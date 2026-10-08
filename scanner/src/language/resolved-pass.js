// Resolved dependency data in the scan path (QA-005.AC04): explicit exports a user or tool wrote on purpose become part of a normal scan,
// instead of being reachable only from a unit test.
//
//   Haskell   dist-newstyle/cache/plan.json and .stack-work/dependencies.json   -> a resolved graph (transitive packages, exact
//             versions, scopes) joined to the declared manifests; stale data is used for nothing and disclosed.
//   Nix       nix-export.json (and .direnv/nix-export.json)                       -> an imported closure, matched against an advisory
//             snapshot with upstream-identity and patch-evidence rules; no feed means "unknown", never "clean".
//   Eval      AGENTIC_SECURITY_NIX_EVAL=1 + AGENTIC_SECURITY_NIX_TARGET=<attr>   -> an isolated, opt-in evaluation whose state is its
//             own scan-health field. A scan that did not select it never runs a Nix evaluator.
//
// Nothing here fetches, builds, evaluates or runs a project's code unless the evaluation is selected AND the sandbox proves its isolation.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolveOperatorSnapshot, IGNORED_NOTE } from './trusted-inputs.js';
import { analyzeHaskellManifests } from './haskell-manifests.js';
import { buildResolvedGraph } from './haskell-resolved-graph.js';
import { importNixClosure } from './nix-closure.js';
import { NixAdvisoryData, matchNixVulnerabilities, overlayEvidence, closureIdentities, HASKELL_ENV_HINTS } from './nix-sca.js';
import { loadLiveSnapshot, SNAPSHOT_SCHEMA as NIX_LIVE_SCHEMA, refreshNixAdvisories, liveFeedEnabled as nixLiveEnabled, getLastRefresh as nixLastRefresh, FEED_ENV as NIX_FEED_ENV } from './nix-advisory-feed.js';
import { configuredAdvisoryDb, collectUsage, manifestFiles } from './haskell-supply.js';
import { runIsolatedEval, mergeEvaluationHealth, _which } from './nix-eval-isolation.js';

export const RESOLVED_PASS_VERSION = 'resolved-pass/1';

const PLAN = /(?:^|\/)dist-newstyle\/cache\/plan\.json$/;
const STACK_EXPORT = /(?:^|\/)\.stack-work\/dependencies\.json$/;
const NIX_EXPORT = /(?:^|\/)nix-export\.json$/;
const ACTIONABLE = new Set(['affected', 'possibly-affected', 'candidate', 'backported-verified']);

const memo = new WeakMap();
const memoized = (files, key, make) => { let m = memo.get(files); if (!m) { m = new Map(); memo.set(files, m); } if (!m.has(key)) m.set(key, make()); return m.get(key); };

function parseJson(text) { try { return { ok: true, value: JSON.parse(text) }; } catch (e) { return { ok: false, reason: String((e && e.message) || e).slice(0, 120) }; } }

/** The resolved Haskell graph for a file set, or null when no explicit export is present. Cached per file set. */
export function resolvedHaskellGraph(files) {
  return memoized(files, 'hs-graph', () => {
    const planFile = Object.keys(files).find((p) => PLAN.test(p));
    const stackFile = !planFile ? Object.keys(files).find((p) => STACK_EXPORT.test(p)) : null;
    const src = planFile || stackFile;
    if (!src) return null;
    const mf = manifestFiles(files);
    const manifests = mf.length ? analyzeHaskellManifests(mf) : null;
    const parsed = parseJson(files[src]);
    if (!parsed.ok) return { file: src, graph: { source: planFile ? 'cabal-plan' : 'stack-export', graphAvailable: false, units: null, edges: null, freshness: { status: 'unverified', reasons: [] }, closure: { complete: false, reason: 'malformed_resolved_data' }, gaps: [{ kind: planFile ? 'malformed_plan' : 'malformed_stack_export', detail: `${src} is not valid JSON: ${parsed.reason}` }], declared: [] }, manifests };
    const graph = buildResolvedGraph({ manifests, ...(planFile ? { plan: parsed.value } : { stackExport: parsed.value }), expected: {} });
    return { file: src, graph, manifests };
  });
}

/**
 * Components for the resolved graph: every Hackage unit with an exact version, its scope and where it came from. Only a graph that is
 * not stale contributes; a stale one is returned as a gap (never as components), and a partial one says it is partial.
 */
export function resolvedHackageComponents(files) {
  const r = resolvedHaskellGraph(files);
  if (!r) return { components: [], gaps: [], summary: null };
  const g = r.graph;
  const gaps = (g.gaps || []).map((x) => ({ kind: `resolved-${x.kind}`, detail: x.detail || x.message || x.kind, file: r.file }));
  const summary = { file: r.file, source: g.source, graphAvailable: g.graphAvailable, freshness: g.freshness, closure: g.closure, units: g.units ? g.units.length : null, edges: g.edges ? g.edges.length : null };
  if (!g.graphAvailable || g.freshness.status === 'stale') return { components: [], gaps, summary };
  // The plan is a file in the scanned project. Where the project's own freeze file also pins a package, the two must agree: a plan that
  // contradicts the freeze is stale or forged, and contributes no versions.
  const frozen = new Map(((r.manifests && r.manifests.lockedPackages) || []).filter((l) => l.name && l.version).map((l) => [l.name, l.version]));
  const clashes = (g.units || []).filter((u) => u.name && u.version && frozen.has(u.name) && frozen.get(u.name) !== u.version).map((u) => `${u.name} ${u.version} (plan) vs ${frozen.get(u.name)} (freeze)`);
  if (clashes.length) { gaps.push({ kind: 'resolved-stale-plan-contradicts-freeze', detail: `the plan contradicts the freeze file (${clashes.slice(0, 3).join('; ')}): it is stale or forged, so no version was taken from it`, file: r.file }); return { components: [], gaps, summary }; }
  gaps.push({ kind: 'resolved-project-supplied-plan', detail: 'the plan is a file in the scanned project: it is checked against the declared bounds and the freeze file, but whoever controls the project controls its contents', file: r.file });
  const SCOPE = { runtime: 'required', test: 'optional', benchmark: 'optional', setup: 'optional', 'build-tool': 'optional' };
  const direct = new Set((g.declared || []).map((d) => d.name));
  const components = [];
  for (const u of g.units) {
    if (u.origin === 'local' || u.origin === 'compiler' || !u.name || !u.version) continue;   // the project itself and boot libraries are not dependencies to match
    const scopes = Array.isArray(u.scopes) && u.scopes.length ? u.scopes : ['runtime'];
    const scope = scopes.includes('runtime') ? 'runtime' : scopes[0];
    components.push({ ecosystem: 'hackage', name: u.name, version: u.version, declaredRange: null, resolution: 'plan', scope, engineScope: SCOPE[scope] || 'required', target: null, componentKind: u.componentKind || null, manifest: r.file, line: null, ghcComponent: false, direct: direct.has(u.name), unitId: u.id, origin: u.origin, versionSource: { file: r.file, line: null } });
  }
  return { components, gaps, summary };
}

// ── Nix closure ──────────────────────────────────────────────────────────────────
function loadNixExports(files, env = process.env) {
  const exports = []; const sources = []; const problems = []; const trust = new Set();
  const take = (label, text, origin) => {
    sources.push(label);
    const parsed = parseJson(text);
    if (!parsed.ok) { problems.push({ kind: 'malformed-export', file: label, detail: parsed.reason }); return; }
    const j = parsed.value;
    trust.add(origin);
    // NOTE: an `expected` block inside the file is IGNORED. The file is the thing under test, so it cannot also say what it should be
    // checked against; what an export must match is derived by the scanner (below) or comes from the operator.
    if (j && Array.isArray(j.exports)) exports.push(...j.exports.filter((e) => e && typeof e === 'object'));
    else if (j && typeof j === 'object' && j.schema && (j.data !== undefined || j.text !== undefined)) exports.push(j);
    else exports.push({ text });
  };
  if (env.AGENTIC_SECURITY_NIX_EXPORT) {
    try { take(env.AGENTIC_SECURITY_NIX_EXPORT, readFileSync(env.AGENTIC_SECURITY_NIX_EXPORT, 'utf8'), 'operator'); }
    catch (e) { sources.push(env.AGENTIC_SECURITY_NIX_EXPORT); problems.push({ kind: 'malformed-export', file: env.AGENTIC_SECURITY_NIX_EXPORT, detail: `unreadable: ${e.code || e.message}` }); }
  }
  for (const p of Object.keys(files).filter((x) => NIX_EXPORT.test(x)).sort()) take(p, files[p], 'project-supplied');
  // What the export must have been made against: the real flake.lock of this project (a forged export cannot also forge that file's hash
  // without the lock it claims to describe being the lock that is here).
  const expected = {};
  const lockPath = Object.keys(files).filter((p) => /(^|\/)flake\.lock$/.test(p)).sort((a, b) => a.length - b.length)[0];
  if (lockPath) expected.flakeLockSha256 = createHash('sha256').update(files[lockPath]).digest('hex');
  else if (sources.length) problems.push({ kind: 'export-unverified', detail: 'there is no flake.lock to bind the export to, so it cannot be shown to describe this project' });
  if (env.AGENTIC_SECURITY_NIX_EXPORT_PUBKEY) { try { expected.publicKeyPem = readFileSync(env.AGENTIC_SECURITY_NIX_EXPORT_PUBKEY, 'utf8'); expected.requireSigned = true; } catch { problems.push({ kind: 'malformed-export', detail: 'the configured export public key is unreadable' }); } }
  return { exports, sources, problems, expected, trust: [...trust] };
}

/** Names of the Haskell packages inside an imported Nix closure (derivations whose env carries Haskell build attributes). */
export function nixHaskellPackageNames(files, opts = {}) {
  const c = nixClosureOf(files, opts);
  if (!c || (c.refused && c.refused.length)) return [];
  const nodes = (c.closure && c.closure.nodes) || [];
  return [...new Set(nodes.filter((n) => n.pname && n.deriver && c.drvEnv[n.deriver] && HASKELL_ENV_HINTS.some((k) => k in c.drvEnv[n.deriver])).map((n) => n.pname))];
}

/** The imported closure (and each derivation's env block) for a file set, or null when there is no export. Cached per file set. */
export function nixClosureOf(files, { now = Date.now() } = {}) {
  return memoized(files, 'nix-closure', () => {
    const { exports, sources, problems, expected, trust } = loadNixExports(files);
    if (!sources.length) return null;
    const closure = importNixClosure({ exports, expected, now });
    const drvEnv = {};
    for (const ex of exports) {
      if (ex.schema !== 'nix-derivation-show-json') continue;
      let data = ex.data; if (data === undefined && typeof ex.text === 'string') { const p = parseJson(ex.text); data = p.ok ? p.value : null; }
      for (const [k, v] of Object.entries(data || {})) if (v && v.env) drvEnv[k] = v.env;
    }
    // A disclosure that says the export does not describe THIS project (another lock, another target, a bad or missing required
    // signature) means its contents are not evidence about this build: it is refused, not merely labelled.
    const REFUSE = new Set(['stale-export', 'foreign-target', 'foreign-revision', 'invalid-signature', 'unsigned']);
    const refused = (closure.disclosures || []).filter((d) => REFUSE.has(d.kind));
    return { closure, drvEnv, sources, problems, trust, refused };
  });
}

/** Advisory records for Nix: a snapshot named by AGENTIC_SECURITY_NIX_ADVISORIES or kept in the project state directory. */
export function configuredNixAdvisories(root, env = process.env, hackageDb = null) {
  const sel = resolveOperatorSnapshot({ envVar: 'AGENTIC_SECURITY_NIX_ADVISORIES', fileName: 'nix-advisories.json', root, env });
  if (!sel.path) return { data: null, reason: `no Nix advisory snapshot is configured (set AGENTIC_SECURITY_NIX_ADVISORIES, or place nix-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME)${sel.projectLocalIgnored ? IGNORED_NOTE('nix-advisories.json') : ''}` };
  let snap; try { snap = JSON.parse(readFileSync(sel.path, 'utf8')); } catch (e) { return { data: null, reason: `the Nix advisory snapshot is unreadable: ${e.code || e.message}` }; }
  if (snap && snap.schema === NIX_LIVE_SCHEMA) {
    // A snapshot the live feed wrote: its records must match their hashes, and it carries which CPE identities it actually read.
    const live = loadLiveSnapshot(snap);
    if (!live.ok) return { data: null, reason: `the live Nix advisory snapshot was refused: ${live.reason}` };
    return { data: new NixAdvisoryData({ records: live.records, hackage: hackageDb, source: sel.source === 'env' ? 'pinned-snapshot' : 'nvd-live-feed', generatedAt: live.generatedAt, covered: live.covered }), reason: null };
  }
  const records = Array.isArray(snap) ? snap : (Array.isArray(snap.records) ? snap.records : []);
  return { data: new NixAdvisoryData({ records, hackage: hackageDb, source: 'pinned-snapshot', generatedAt: (snap && snap.generatedAt) || null }), reason: null };
}

/**
 * Package metadata for the closure (meta.identifiers, knownVulnerabilities, license), from a file the OPERATOR names in
 * AGENTIC_SECURITY_NIX_META: either `{pname: meta}` or the `nix-env -qa --meta --json` shape (`{attr: {pname, meta}}`). It is never
 * read from the scanned project, because metadata decides which upstream identity a component is matched under.
 */
export function configuredNixMeta(env = process.env) {
  const p = env.AGENTIC_SECURITY_NIX_META;
  if (!p) return { meta: {}, reason: null };
  let raw;
  try { const text = readFileSync(p, 'utf8'); if (text.length > (32 << 20)) return { meta: {}, reason: 'the Nix metadata file is larger than 32 MB and was not read' }; raw = JSON.parse(text); } catch (e) { return { meta: {}, reason: `the Nix metadata file is unreadable: ${e.code || e.message}` }; }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { meta: {}, reason: 'the Nix metadata file is not a JSON object' };
  const meta = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!v || typeof v !== 'object') continue;
    const m = v.meta && typeof v.meta === 'object' ? v.meta : v;
    const name = typeof v.pname === 'string' && v.pname ? v.pname : k.split('.').pop();
    if (/^[\w.+-]{1,100}$/.test(name) && !Object.prototype.hasOwnProperty.call(meta, name)) meta[name] = m;
  }
  return { meta, reason: null };
}

/**
 * The async step before a scan's synchronous passes: when the live Nix feed is enabled, make sure the operator snapshot covers every
 * CPE identity the imported closure declares. Does nothing, and costs nothing, unless the feed is enabled. Never throws.
 */
export async function prefetchNixAdvisoryFeed(files, { env = process.env, ...opts } = {}) {
  if (!nixLiveEnabled(env)) return null;
  try {
    const c = nixClosureOf(files, opts.now ? { now: opts.now } : {});
    if (!c || (c.refused && c.refused.length)) return null;
    const { cpes } = closureIdentities({ closure: c.closure, drvEnv: c.drvEnv, meta: configuredNixMeta(env).meta, overlays: overlayEvidence(files) });
    if (!cpes.length) return null;
    return await refreshNixAdvisories(cpes, { env, ...opts });
  } catch (e) { return { status: 'failed', detail: `the feed step failed: ${String((e && e.message) || e).slice(0, 120)}` }; }
}

function nixLiveFeedNote(env) {
  const r = nixLastRefresh();
  if (r && r.status !== 'disabled') return ` Live feed: ${r.status}, ${r.detail}.`;
  return env[NIX_FEED_ENV] === '1' ? '' : ` To fetch advisories for the closure's upstream software from the NVD instead, set ${NIX_FEED_ENV}=1 (network, opt-in).`;
}

/** Closure statuses and findings, with every disclosure the import and the feed produced. */
export function analyzeNixClosure(files, opts = {}) {
  return memoized(files, 'nix-analysis', () => _analyzeNixClosure(files, opts));
}
function _analyzeNixClosure(files, { scanRoot = null, env = process.env, now = Date.now() } = {}) {
  const c = nixClosureOf(files, { now });
  if (!c) return null;
  const hackage = configuredAdvisoryDb(scanRoot, env).db;
  const adv = configuredNixAdvisories(scanRoot, env, hackage);
  if (!adv.data) adv.reason = `${adv.reason}${nixLiveFeedNote(env)}`;
  const nm = configuredNixMeta(env);
  let usage = null; try { usage = collectUsage(files); } catch { usage = null; }
  let matched = null;
  if (!c.refused.length) try { matched = matchNixVulnerabilities({ closure: c.closure, drvEnv: c.drvEnv, data: adv.data, meta: nm.meta, overlays: overlayEvidence(files), haskellUsage: usage }); } catch (e) { matched = null; c.problems.push({ kind: 'match-failed', detail: String((e && e.message) || e).slice(0, 160) }); }
  const gaps = [];
  if (c.trust.includes('project-supplied') && !c.trust.includes('operator')) gaps.push({ kind: 'closure-project-supplied', detail: 'the closure export is a file in the scanned project, bound to its flake.lock but not signed: whoever controls the project controls its contents, so the ABSENCE of a finding for a component it lists is not evidence the real build is free of it (provide the export through AGENTIC_SECURITY_NIX_EXPORT, signed with AGENTIC_SECURITY_NIX_EXPORT_PUBKEY, to have it treated as operator evidence)' });
  for (const d of c.closure.disclosures || []) gaps.push({ kind: `closure-${d.kind}`, detail: d.detail });
  for (const d of c.refused) gaps.push({ kind: `closure-refused-${d.kind}`, detail: `${d.detail}; the export was REFUSED and contributes nothing` });
  for (const p of c.problems) gaps.push({ kind: `closure-${p.kind}`, detail: p.detail, file: p.file });
  if (!adv.data) gaps.push({ kind: 'closure-advisory-feed-unavailable', detail: `${adv.reason}. The closure's components were NOT checked against any advisory: the absence of findings is not a clean result.` });
  if (nm.reason) gaps.push({ kind: 'closure-meta-unreadable', detail: nm.reason });
  const notCovered = ((matched && matched.statuses) || []).filter((x) => x.feedCoverage === 'incomplete');
  if (adv.data && notCovered.length) gaps.push({ kind: 'closure-advisory-feed-incomplete', detail: `${notCovered.length} component(s) were not covered by the live advisory feed (${[...new Set(notCovered.map((x) => x.name))].slice(0, 5).join(', ')}${notCovered.length > 5 ? ', ...' : ''}): their status is unknown, and the absence of findings for them is not a clean result.` });
  if (!adv.data) { /* reported above */ } else if (adv.data.stale) gaps.push({ kind: 'closure-advisory-feed-stale', detail: `the Nix advisory snapshot is stale or undated (${adv.data.ageDays == null ? 'age unknown' : `${Math.floor(adv.data.ageDays)} day(s) old`})` });
  const findings = ((matched && matched.findings) || []).filter((f) => ACTIONABLE.has(f.status)).map((f) => ({ ...f, file: c.sources[0], line: 1 }));
  return { status: c.closure.status, claims: c.closure.claims, sources: c.sources, summary: matched ? matched.summary : null, feed: matched ? matched.feed : null, statuses: matched ? matched.statuses : [], findings, gaps, licenses: matched ? matched.licenses : null, closure: c.closure };
}

// ── isolated evaluation (opt in) ─────────────────────────────────────────────────
/** Runs the isolated evaluation when AGENTIC_SECURITY_NIX_EVAL=1; otherwise null. Never throws; a failure is a recorded state. */
export async function runSelectedNixEval(root, env = process.env, overrides = {}) {
  if (env.AGENTIC_SECURITY_NIX_EVAL !== '1') return null;
  const attribute = env.AGENTIC_SECURITY_NIX_TARGET || '';
  const nixBin = overrides.nix || (_which ? _which('nix') : null);
  if (!attribute) return { status: 'blocked', reason: 'no evaluation target: set AGENTIC_SECURITY_NIX_TARGET to a flake output attribute (for example nixosConfigurations.host.config.system.build.toplevel.drvPath)', projectCodeEvaluated: false };
  if (!nixBin) return { status: 'unsupported', reason: 'the nix binary was not found on PATH; the project\'s Nix code was NOT evaluated', projectCodeEvaluated: false };
  try { return await runIsolatedEval({ nix: typeof nixBin === 'string' ? { file: nixBin } : nixBin, root, attribute, system: env.AGENTIC_SECURITY_NIX_SYSTEM || null, ...overrides }); }
  catch (e) { return { status: 'failed', reason: `the evaluation harness failed: ${String((e && e.message) || e).slice(0, 160)}`, projectCodeEvaluated: false }; }
}

export { mergeEvaluationHealth };
