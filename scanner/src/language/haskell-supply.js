// Haskell supply-chain orchestration for a project (HS-009): manifests -> components -> advisories + policy.
// The pure logic lives in haskell-sca.js; this module only gathers inputs and shapes supply-chain entries.

import { resolveOperatorSnapshot, IGNORED_NOTE } from './trusted-inputs.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeHaskellManifests } from './haskell-manifests.js';
import { buildHaskellIR } from './haskell-ir.js';
import { getLastRefresh, refreshHackageAdvisories, liveFeedEnabled, FEED_ENV } from './haskell-advisory-feed.js';
import { AdvisoryDb, loadAdvisorySnapshot, evaluateComponents, reachability, nearNameCandidates, sourceIntegrity, lifecycle, licensePolicy, hackagePurl, GHC_BOOT_PACKAGES } from './haskell-sca.js';

const MANIFEST = /(?:^|\/)(?:[^/]+\.cabal|cabal\.project(?:\.[a-z]+)?|package\.yaml|stack\.yaml|stack\.yaml\.lock)$/;
const SCOPE = { runtime: 'required', test: 'optional', benchmark: 'optional', setup: 'optional', 'build-tool': 'optional' };

export function manifestFiles(files) {
  return Object.entries(files).filter(([p, t]) => MANIFEST.test(p) && typeof t === 'string').map(([path, text]) => ({ path, text }));
}

/** Components from declared dependencies, each with its RESOLVED version when a freeze file or an exact pin gives one. */
export function hackageComponents(files) {
  const mf = manifestFiles(files);
  if (!mf.length) return { components: [], manifests: null };
  const manifests = analyzeHaskellManifests(mf);
  // A freeze or lock file resolves the manifests at or below its own directory (that is what a Cabal project or Stack project root means), and the
  // nearest enclosing one wins. Applying one repository-wide made a release builder's freeze (builders/linux.armv6hf/) the "resolved" version of
  // the root package: found by the live Hackage feed bench.
  const dirOf = (p) => (typeof p === 'string' && p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const covers = (lockFile, manifest) => { const base = dirOf(lockFile); const m = dirOf(manifest); return base === '' || m === base || m.startsWith(`${base}/`); };
  const lockedFor = (name, manifest) => {
    let best = null;
    for (const l of manifests.lockedPackages || []) {
      if (l.name !== name || !l.version || !l.file || !covers(l.file, manifest)) continue;
      if (!best || dirOf(l.file).length >= dirOf(best.file).length) best = l;
    }
    return best;
  };
  // Packages this project DEFINES (a .cabal file or an hpack package.yaml in the scanned tree). A `build-depends` on one of them resolves to the
  // workspace package, not to Hackage; reporting it would raise advisories about the project's own (usually fixed) version as if it were a
  // dependency. Found by the live Hackage feed bench (aeson's own test suite depends on aeson).
  const defined = new Set([...(manifests.packages || []), ...(manifests.hpack || [])].map((p) => p.name).filter(Boolean));
  const seen = new Map();
  for (const d of manifests.dependencies || []) {
    if (defined.has(d.name)) continue;
    const lock = lockedFor(d.name, d.manifest);
    const resolved = (lock && lock.version) || d.exactPin || null;
    const key = `${d.name}@${d.scope || 'runtime'}@${resolved || ''}`;   // a covered (resolved) use is not merged into an uncovered one
    if (seen.has(key)) continue;
    seen.set(key, {
      ecosystem: 'hackage', name: d.name, version: resolved, declaredRange: d.declaredRange || null, unbounded: !resolved && !d.declaredRange && d.rangeKind === 'unbounded',
      resolution: lock ? 'freeze' : (d.exactPin ? 'exact-pin' : 'unresolved'),
      scope: d.scope || 'runtime', engineScope: SCOPE[d.scope] || 'required', target: d.component || null, componentKind: d.componentKind || null,
      manifest: d.manifest, line: d.line, ghcComponent: GHC_BOOT_PACKAGES.has(d.name),
      versionSource: lock ? { file: lock.file, line: lock.line || null } : null,
    });
  }
  return { components: [...seen.values()], manifests };
}

/**
 * Folds an explicit resolved graph (a fresh cabal plan or Stack export) into the declared inventory: a declared dependency gets the
 * exact version the plan chose, and a transitive package nobody declared is added with its own scope. Nothing is guessed: when the
 * graph is stale or absent the caller passes none and the declared inventory stands.
 */
function mergeResolved(declared, resolved) {
  if (!resolved || !resolved.components || !resolved.components.length) return declared;
  const byName = new Map(declared.map((c) => [c.name, c]));
  const out = declared.map((c) => {
    const r = resolved.components.find((x) => x.name === c.name);
    return r && r.version ? { ...c, version: r.version, resolution: 'plan', versionSource: r.versionSource, unitId: r.unitId } : c;
  });
  const seen = new Set(out.map((c) => `${c.name}@${c.version || ''}`));
  for (const r of resolved.components) {
    if (byName.has(r.name) || seen.has(`${r.name}@${r.version}`)) continue;
    seen.add(`${r.name}@${r.version}`);
    out.push({ ...r, transitive: true });
  }
  return out;
}

/** Advisory data configured for this scan: a hash-pinned snapshot from the environment or the project's state dir. */
/** The live-feed sentence appended to a "no advisory data" reason: what the refresh did, or how to turn it on. */
function liveFeedNote(env) {
  const r = getLastRefresh();
  if (r && r.status !== 'disabled') return ` Live feed: ${r.status}, ${r.detail}.`;
  return env[FEED_ENV] === '1' ? '' : ` To fetch advisories from the OSV Hackage feed instead, set ${FEED_ENV}=1 (network, opt-in).`;
}

export function configuredAdvisoryDb(root, env = process.env) {
  const c = _configuredAdvisoryDb(root, env);
  return c.db ? c : { ...c, reason: `${c.reason}${liveFeedNote(env)}` };
}
function _configuredAdvisoryDb(root, env = process.env) {
  const sel = resolveOperatorSnapshot({ envVar: 'AGENTIC_SECURITY_HACKAGE_ADVISORIES', fileName: 'hackage-advisories.json', root, env });
  if (!sel.path) return { db: null, reason: `no advisory snapshot configured (set AGENTIC_SECURITY_HACKAGE_ADVISORIES, or place hackage-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME)${sel.projectLocalIgnored ? IGNORED_NOTE('hackage-advisories.json') : ''}`, projectLocalIgnored: !!sel.projectLocalIgnored };
  let snap;
  try { snap = JSON.parse(readFileSync(sel.path, 'utf8')); } catch (e) { return { db: null, reason: `advisory snapshot unreadable: ${e.code || e.message}` }; }
  const r = loadAdvisorySnapshot(snap, { pinnedSha256: env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_SHA256 || null });
  return r.ok ? { db: r.db, reason: null, source: sel.source } : { db: null, reason: `advisory snapshot refused: ${r.reason}` };
}

/**
 * The async step before a scan's synchronous passes: when the live feed is enabled, make sure the operator snapshot covers every
 * Hackage package this scan will evaluate (declared, frozen, transitive when a plan is present, and Haskell packages inside an imported Nix closure). Does nothing, and costs nothing
 * (no manifest parsing), unless the feed is enabled. Never throws.
 */
export async function prefetchHackageFeed(files, { env = process.env, resolvedComponents = [], extraNames = [], ...opts } = {}) {
  if (!liveFeedEnabled(env)) return null;
  try {
    const names = [...hackageComponents(files).components, ...resolvedComponents].map((c) => c.name).concat(extraNames);
    if (!names.length) return null;
    return await refreshHackageAdvisories(names, { env, ...opts });
  } catch (e) { return { status: 'failed', detail: `the feed step failed: ${String((e && e.message) || e).slice(0, 120)}` }; }
}

/** Imports and import-qualified callees across the project's Haskell sources. */
export function collectUsage(files) {
  const hs = {};
  for (const [f, t] of Object.entries(files)) if (/\.hs$/i.test(f) && typeof t === 'string') hs[f] = t;
  if (!Object.keys(hs).length) return { imports: [], callees: new Set() };
  const ir = buildHaskellIR(hs);
  const imports = [];
  const callees = new Set();
  for (const f of Object.values(ir.perFile)) {
    for (const i of f.imports || []) imports.push({ module: i.module, items: i.names && i.names.length ? i.names : null, file: f.file, line: i.line });
    for (const fn of f.functions) for (const c of fn.calls || []) if (typeof c.callee === 'string') callees.add(c.callee);
  }
  return { imports, callees };
}

/**
 * @returns {{supplyChain:object[], statuses:object[], feed:object, policy:object, gaps:object[], components:object[]}}
 */
export function analyzeHaskellSupply(files, { db = undefined, root = null, env = process.env, kev = null, epss = null, metadata = null, registry = null, symbols = {}, resolved = null } = {}) {
  const hc = hackageComponents(files);
  const { manifests } = hc;
  const components = mergeResolved(hc.components, resolved);
  const out = { supplyChain: [], statuses: [], feed: null, policy: {}, gaps: [...((resolved && resolved.gaps) || []).map((g) => ({ ...g, source: 'haskell' }))], components, resolved: resolved ? resolved.summary : null };
  if (!components.length) return out;
  let feedReason = null;
  if (db === undefined) { const c = configuredAdvisoryDb(root, env); db = c.db; feedReason = c.reason; }
  const ev = evaluateComponents(components, db, { kev, epss });
  out.statuses = ev.statuses;
  out.feed = ev.feed;
  if (!db) out.gaps.push({ kind: 'advisory-feed-unavailable', detail: `${feedReason || ev.feed.detail}. ${components.length} Hackage dependencies were NOT checked against any advisory: the absence of findings is not a clean result.` });
  else if (ev.feed.status === 'stale-cache') out.gaps.push({ kind: 'advisory-feed-stale', detail: ev.feed.detail });
  const notCovered = ev.statuses.filter((x) => x.status === 'feed-incomplete' || x.status === 'feed-stale');
  if (db && notCovered.length) out.gaps.push({ kind: 'advisory-feed-incomplete', detail: `${notCovered.length} Hackage package(s) were not covered by the advisory feed (${[...new Set(notCovered.map((x) => x.name))].slice(0, 5).join(', ')}${notCovered.length > 5 ? ', ...' : ''}): their status is unknown, and the absence of findings for them is not a clean result.` });
  const unresolved = components.filter((c) => !c.version);
  if (unresolved.length) out.gaps.push({ kind: 'unresolved-dependency-versions', detail: `${unresolved.length} dependency version(s) are only declared ranges (${unresolved.slice(0, 5).map((c) => c.name).join(', ')}${unresolved.length > 5 ? ', ...' : ''}); generate a Cabal plan or a Stack export to resolve them` });

  // reachability, per finding
  const usage = collectUsage(files);
  for (const f of ev.findings) {
    const r = reachability(f.name, usage.imports, usage.callees, (symbols && symbols[f.osvId]) || null);
    f.reachability = r;
    f.functionReachable = r.function === 'reachable' ? 'reachable' : (r.function === 'not-imported' ? 'unreachable' : 'unknown');
    f.reachabilityTier = r.import === 'imported' ? (r.function === 'reachable' ? 'function-reachable' : 'import-reachable') : (r.import === 'not-imported' ? 'not-imported' : 'unknown');
    out.supplyChain.push({ ...f, file: f.file, line: f.line });
  }
  // policy
  const si = sourceIntegrity(manifests || {});
  for (const s of si.filter((x) => x.finding)) {
    out.supplyChain.push({
      type: 'source_integrity', ecosystem: 'hackage', name: s.location, version: s.tag || null, severity: s.severity, file: s.file, line: s.line,
      vuln: 'Source repository dependency is not pinned to a commit', cwe: 'CWE-829', description: `source-repository-package ${s.location}: ${s.reason}`,
      remediation: 'Pin `tag:` to a full commit hash (and add `--sha256` where supported).', parser: 'HS-SUPPLY', family: 'source-integrity',
      language: 'haskell', capability: 'sca', analysisKind: 'application', evidenceKind: 'manifest', dataSource: { manifest: s.file },
    });
  }
  out.policy.sourceIntegrity = si;
  out.policy.nearName = nearNameCandidates(components, { registry });
  out.policy.lifecycle = lifecycle(components, metadata);
  out.policy.license = licensePolicy(components, metadata);
  for (const n of out.policy.nearName) {
    out.supplyChain.push({
      type: 'dep_confusion_candidate', ecosystem: 'hackage', name: n.name, version: null, severity: 'info', file: components.find((c) => c.name === n.name).manifest, line: components.find((c) => c.name === n.name).line,
      vuln: 'Dependency name resembles a popular package', cwe: 'CWE-1357', description: `${n.name} is one edit from ${n.similarTo}. ${n.note}; registry evidence: ${n.status}.`,
      remediation: 'Confirm the package name is intended.', parser: 'HS-SUPPLY', family: 'dependency-confusion', verdict: 'candidate', malicious: false,
      language: 'haskell', capability: 'sca', analysisKind: 'application', evidenceKind: 'manifest', confidence: 0.2,
    });
  }
  void hackagePurl; void AdvisoryDb;
  return out;
}
