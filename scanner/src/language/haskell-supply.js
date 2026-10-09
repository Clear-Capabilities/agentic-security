// Haskell supply-chain orchestration for a project (HS-009): manifests -> components -> advisories + policy.
// The pure logic lives in haskell-sca.js; this module only gathers inputs and shapes supply-chain entries.

import { resolveOperatorSnapshot, IGNORED_NOTE } from './trusted-inputs.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeHaskellManifests } from './haskell-manifests.js';
import { buildHaskellIR } from './haskell-ir.js';
import { getLastRefresh, refreshHackageAdvisories, liveFeedEnabled, FEED_ENV } from './haskell-advisory-feed.js';
import { AdvisoryDb, loadAdvisorySnapshot, evaluateComponents, reachability, nearNameCandidates, sourceIntegrity, lifecycle, licensePolicy, hackagePurl, GHC_BOOT_PACKAGES, rangeToIntervals, intervalsContain, baseRangeForGhc } from './haskell-sca.js';
import { deriveCppContext } from './haskell-cpp.js';

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
  // Every distinct DECLARED USE is kept (not just the first per package and scope): a second manifest or component with a different range was
  // never evaluated, so a worse status could hide behind a milder kept one. The evaluator reports the worst per package, scope and advisory
  // and lists the components that carry it; `components` below keeps the old one-per-package-and-scope shape for inventories.
  const seen = new Map();
  for (const d of manifests.dependencies || []) {
    if (defined.has(d.name)) continue;
    const lock = lockedFor(d.name, d.manifest);
    const resolved = (lock && lock.version) || d.exactPin || null;
    // a covered (resolved) use is not merged into an uncovered one; an uncovered use is distinguished by where and how it is declared
    const key = `${d.name}@${d.scope || 'runtime'}@${resolved || ''}@${resolved ? '' : `${d.manifest}|${d.component || ''}|${d.declaredRange || ''}|${d.rangeKind || ''}`}`;
    if (seen.has(key)) continue;
    seen.set(key, {
      ecosystem: 'hackage', name: d.name, version: resolved, declaredRange: d.declaredRange || null, unbounded: !resolved && !d.declaredRange && d.rangeKind === 'unbounded',
      resolution: lock ? 'freeze' : (d.exactPin ? 'exact-pin' : 'unresolved'),
      scope: d.scope || 'runtime', engineScope: SCOPE[d.scope] || 'required', target: d.component || null, componentKind: d.componentKind || null,
      manifest: d.manifest, line: d.line, ghcComponent: GHC_BOOT_PACKAGES.has(d.name),
      versionSource: lock ? { file: lock.file, line: lock.line || null } : null,
    });
  }
  // Cabal chooses ONE version of a package for every component of a .cabal file, so a use with no bound inherits the unconditional bounds the
  // same manifest declares for that package elsewhere (a library that pins `aeson >=2.2.5.1` next to a test suite that just says `aeson`).
  // Conditional bounds (flags, os, compiler) are not in force everywhere and are not inherited; neither is a bound from another manifest.
  const boundsIn = new Map();
  for (const d of manifests.dependencies || []) {
    if (!d.declaredRange || (d.conditions && d.conditions.length) || defined.has(d.name)) continue;
    const k = `${d.manifest}\u0000${d.name}`;
    if (!boundsIn.has(k)) boundsIn.set(k, []);
    if (!boundsIn.get(k).includes(d.declaredRange)) boundsIn.get(k).push(d.declaredRange);
  }
  for (const c of seen.values()) {
    if (!c.unbounded) continue;
    const rs = boundsIn.get(`${c.manifest}\u0000${c.name}`);
    if (!rs) continue;
    c.declaredRange = rs.length === 1 ? rs[0] : rs.map((r) => `(${r})`).join(' && ');
    c.unbounded = false;
    c.rangeInheritedFromSibling = true;
  }
  // Project-level bounds from cabal.project: `constraints:` narrow a declared range (the solver must satisfy both) and `allow-newer` /
  // `allow-older` widen it. Both apply only to a use with no resolved version, from a project file that actually governs the manifest.
  const bounds = projectBounds(manifests);
  for (const c of seen.values()) {
    if (c.version) continue;
    const gov = bounds.governing(c.manifest);
    if (!gov.length) continue;
    const cons = bounds.constraintsFor(c.name, gov);
    const relax = bounds.relaxationsFor(c.name, gov);
    if (relax.length) c.relaxation = relax;
    if (!cons.length) continue;
    // an exact pin inside the declared range IS the resolved version; anything else is an interval to intersect
    const pins = cons.filter((x) => x.pin);
    const distinctPins = [...new Set(pins.map((x) => x.pin))];
    const declaredIv = c.declaredRange ? rangeToIntervals(c.declaredRange) : [{ lo: null, loInc: false, hi: null, hiInc: false }];
    if (distinctPins.length === 1 && declaredIv && (!c.declaredRange || intervalsContain(declaredIv, distinctPins[0])) && cons.every((x) => x.pin || (rangeToIntervals(x.text) && intervalsContain(rangeToIntervals(x.text), distinctPins[0])))) {
      const p = pins[0];
      c.version = distinctPins[0]; c.resolution = 'constraint-pin'; c.versionSource = { file: p.file, line: p.line || null }; c.unbounded = false;
      c.projectConstraints = cons.map(({ text, file, line }) => ({ text, file, line }));
    } else {
      c.projectConstraints = cons.map(({ text, file, line }) => ({ text, file, line }));
    }
  }
  // Collapse uses that ended up identical (same package, scope, version, bounds): one entry, every declaring component kept in `carriers`.
  const merged = new Map();
  for (const c of seen.values()) {
    const key = `${c.name}@${c.scope}@${c.version || ''}@${c.version ? '' : `${c.declaredRange || ''}|${c.unbounded}|${(c.projectConstraints || []).map((x) => x.text).join(',')}|${(c.relaxation || []).map((x) => x.direction).join(',')}`}`;
    const carrier = { file: c.manifest, line: c.line, target: c.target, componentKind: c.componentKind, declaredRange: c.declaredRange };
    if (merged.has(key)) { merged.get(key).carriers.push(carrier); continue; }
    merged.set(key, { ...c, carriers: [carrier] });
  }
  const uses = [...merged.values()];
  const first = new Map();
  for (const c of uses) { const k = `${c.name}@${c.scope}@${c.version || ''}`; if (!first.has(k)) first.set(k, c); }
  return { components: [...first.values()], uses, manifests, bounds: { conditionalConstraintsSkipped: bounds.conditionalSkipped } };
}

const isRemotePattern = (p) => /^[a-z][a-z0-9+.-]*:\/\//i.test(p);
/** Does a cabal.project `packages:` pattern name this manifest (a .cabal, or a package.yaml whose cabal file is generated beside it)? */
function patternNames(pattern, relManifest) {
  let pat = String(pattern).trim().replace(/^\.\//, '');
  if (pat === '' || pat === '.') pat = '*.cabal';
  else if (pat.endsWith('/')) pat = `${pat}*.cabal`;
  else if (!pat.endsWith('.cabal')) pat = `${pat}/*.cabal`;
  const rel = /(?:^|\/)package\.yaml$/.test(relManifest) ? relManifest.replace(/package\.yaml$/, 'package.cabal') : relManifest;
  const re = new RegExp(`^${pat.split('**').map((seg) => seg.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')).join('.*')}$`);
  return re.test(rel);
}

/**
 * cabal.project constraints and relaxations, scoped to the manifests a project file governs. A project governs a manifest only when the
 * manifest sits at or below the project's directory AND matches one of its `packages:` patterns (a project with no `packages:` governs
 * the .cabal file in its own directory, which is cabal's default). A constraint under an `if` is not in force everywhere and is not applied
 * (counted in `conditionalSkipped` and disclosed). A freeze file is handled as a resolution, not here.
 */
function projectBounds(manifests) {
  const dirOf = (p) => (typeof p === 'string' && p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const isFreeze = (f) => /\.freeze$|(?:^|\/)cabal\.config$/.test(f || '');
  const projects = (manifests.projects || []).filter((p) => p.kind === 'cabal-project' && !isFreeze(p.file));
  const constraints = [];
  let conditionalSkipped = 0;
  for (const c of manifests.constraints || []) {
    if (c.kind !== 'range' || !c.range || isFreeze(c.manifest)) continue;
    if (c.qualifier && c.qualifier !== 'any') continue;
    if (c.conditions && c.conditions.length) { conditionalSkipped += 1; continue; }
    constraints.push({ name: c.name, text: c.rangeText, file: c.file, line: c.line, project: c.manifest, pin: c.range.t === 'cmp' && c.range.op === '==' && !c.range.wildcard ? c.range.text : null });
  }
  const governs = (project, manifest) => {
    const base = dirOf(project.file);
    let rel;
    if (base === '') rel = manifest;
    else if (manifest.startsWith(`${base}/`)) rel = manifest.slice(base.length + 1);
    else return false;
    const pats = (project.packages || []).map((x) => x.pattern).filter((x) => typeof x === 'string' && !isRemotePattern(x));
    return (pats.length ? pats : ['.']).some((pat) => patternNames(pat, rel));
  };
  const relaxMatches = (target, dep) => {
    const t = String(target || '').trim().replace(/^\^/, '');
    if (t === '' || t === 'all' || t === '*' || t === '*:*') return true;
    const parts = t.split(':');
    const last = parts[parts.length - 1];
    return last === dep || last === '*';
  };
  return {
    conditionalSkipped,
    governing: (manifest) => projects.filter((p) => typeof manifest === 'string' && governs(p, manifest)),
    constraintsFor: (name, gov) => constraints.filter((c) => c.name === name && gov.some((p) => p.file === c.project)),
    // A relaxation naming package `a:dep` is applied to `dep` wherever it is used: widening more than the cabal semantics is the safe direction.
    relaxationsFor: (name, gov) => gov.flatMap((p) => (p.allowRelaxations || []).filter((r) => relaxMatches(r.target, name)).map((r) => ({ direction: r.direction, target: r.target, file: r.file, line: r.line }))),
  };
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

/**
 * The compiler this project is built with, only when it is stated: `with-compiler`, a Stack `compiler:`, a plan's compiler-id, or a
 * `tested-with` whose every item is the same exact version (a claim by the project, weaker than a pin). Sources that disagree, or a
 * `tested-with` listing several versions, leave it UNKNOWN, never a guess.
 * @returns {{version: string|null, label: string, basis: string|null, reason: string|null}}
 */
export function projectCompiler(files, manifests, resolved) {
  const pins = [];
  const take = (v, basis) => { if (typeof v === 'string') { const m = /(?:^|[\\/])ghc-(\d+(?:\.\d+)+)$/.exec(v.trim()); if (m) pins.push({ version: m[1], basis }); } };
  for (const p of (manifests && manifests.projects) || []) take(p.withCompiler, 'with-compiler');
  for (const s of (manifests && manifests.stack) || []) take(s.compiler, 'stack compiler');
  const pc = resolved && resolved.compiler;
  if (pc && /^ghc$/i.test(pc.name || 'ghc') && pc.version) pins.push({ version: pc.version, basis: 'plan compiler-id' });
  const distinct = [...new Set(pins.map((p) => p.version))];
  if (distinct.length > 1) return { version: null, label: 'unknown compiler', basis: null, reason: `the project states conflicting compilers: ${pins.map((p) => `${p.basis} ${p.version}`).join(', ')}` };
  if (distinct.length === 1) return { version: distinct[0], label: `GHC ${distinct[0]}`, basis: [...new Set(pins.map((p) => p.basis))].join(' + '), reason: null };
  let tested = null;
  try { tested = deriveCppContext(files).ghc; } catch { /* unreadable manifests state nothing */ }
  if (tested && tested.basis === 'tested-with') {
    const vs = [...new Set(tested.versions.map((v) => v.join('.')))];
    if (vs.length === 1) return { version: vs[0], label: `GHC ${vs[0]}`, basis: 'tested-with (the project\'s own claim, not a pin)', reason: null };
    return { version: null, label: 'unknown compiler', basis: null, reason: `tested-with lists several GHC versions: ${vs.join(', ')}; none is pinned` };
  }
  return { version: null, label: 'unknown compiler', basis: null, reason: 'no compiler is pinned by with-compiler, a Stack compiler or a plan, and no tested-with names exactly one version' };
}

/** A compiler-provided package takes its version from the plan's boot unit, else (for base) the compiler's base series; otherwise it stays as declared. */
function resolveBootComponent(c, compiler, resolved) {
  if (!c.ghcComponent || c.version) return c;
  const boot = resolved && resolved.bootLibraries && resolved.bootLibraries.find((b) => b.name === c.name && b.version);
  if (boot) return { ...c, version: boot.version, resolution: 'plan-compiler', versionSource: boot.versionSource || null, compilerDerived: { compiler: compiler.label, basis: 'plan boot library' } };
  if (compiler.version && c.name === 'base') {
    const range = baseRangeForGhc(compiler.version);
    if (range) return { ...c, declaredRange: range, unbounded: false, declaredRangeAsWritten: c.declaredRange || null, compilerDerived: { compiler: compiler.label, basis: compiler.basis, rule: `base ${range} is the base series of ${compiler.label}` } };
  }
  return c;
}

const GHC_RANK = { affected: 3, 'possibly-affected': 2, unknown: 1 };
/** One finding per advisory for the project's compiler: members, the worst status, and a remediation that names the compiler. */
function groupCompilerFindings(findings, compiler) {
  const byAdvisory = new Map();
  for (const f of findings) { const k = `${f.osvId}\u0000${(f.ids && f.ids[0]) || ''}`; if (!byAdvisory.has(k)) byAdvisory.set(k, []); byAdvisory.get(k).push(f); }
  const out = [];
  for (const members of byAdvisory.values()) {
    const rank = (f) => GHC_RANK[f.matchStatus] || 0;
    const lead = members.slice().sort((a, b) => rank(b) - rank(a))[0];
    const packages = [...new Set(members.map((m) => m.name))].sort();
    const fixed = [...new Set(members.flatMap((m) => m.fixedIn || []))];
    const list = packages.join(', ');
    const fixText = fixed.length ? `a release that ships ${list} ${fixed.join(' or ')} or later` : `a release with a fixed ${list} (none is published yet)`;
    const remediation = compiler.version
      ? `${list} ${packages.length > 1 ? 'are' : 'is'} provided by the compiler, and this project builds with ${compiler.label} (${compiler.basis}). Upgrade GHC to ${fixText}; a Cabal bound does not change the compiler's own library.`
      : `${list} ${packages.length > 1 ? 'are' : 'is'} provided by the compiler, and this project's compiler is unknown (${compiler.reason}), so which ${list} version applies cannot be decided. Pin one with with-compiler in cabal.project, or supply a Cabal plan, to decide it. The fix is a compiler upgrade: upgrade GHC to ${fixText}.`;
    out.push({
      ...lead, name: list, packages, grouped: 'compiler', ghcComponent: true, compiler: { version: compiler.version, label: compiler.label, basis: compiler.basis, reason: compiler.reason },
      matchStatus: lead.matchStatus, remediation,
      members: members.map((m) => ({ name: m.name, scope: m.scope, version: m.version, declaredRange: m.declaredRange, matchStatus: m.matchStatus, matchReason: m.matchReason, resolution: m.resolution, carriedBy: m.carriedBy, ...(m.compilerDerived ? { compilerDerived: m.compilerDerived } : {}) })),
      memberCount: members.length,
    });
  }
  return out;
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
  const compiler = projectCompiler(files, manifests, resolved);
  out.compiler = compiler;
  // Evaluate every distinct declared use (the evaluator reports the worst per package, scope and advisory), with compiler-provided packages
  // resolved against the project's compiler where that can be decided.
  const evalComponents = mergeResolved(hc.uses, resolved).map((c) => resolveBootComponent(c, compiler, resolved));
  const ev = evaluateComponents(evalComponents, db, { kev, epss });
  out.statuses = ev.statuses.map((s) => (s.ghcComponent ? { ...s, compiler: compiler.label } : s));
  out.feed = ev.feed;
  if (hc.bounds && hc.bounds.conditionalConstraintsSkipped) out.gaps.push({ kind: 'conditional-constraints-not-applied', detail: `${hc.bounds.conditionalConstraintsSkipped} cabal.project constraint(s) sit under a condition (if os(...), flag, compiler) and were NOT applied to declared ranges; they are not in force everywhere, so a declared range they would narrow is judged as written` });
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
  }
  // Compiler-provided packages (GHC boot libraries) are one finding per advisory for the project's compiler, not one per package and scope:
  // the fix is a compiler upgrade whatever the Cabal bounds say. Every member stays listed in the group and every use keeps its status row.
  const ordinary = ev.findings.filter((f) => !f.ghcComponent);
  const groups = groupCompilerFindings(ev.findings.filter((f) => f.ghcComponent), compiler);
  for (const f of [...ordinary, ...groups]) out.supplyChain.push({ ...f, file: f.file, line: f.line });
  out.counts = { dependencyFindings: ordinary.length, compilerAdvisories: groups.length, compilerMemberRows: groups.reduce((n, g) => n + g.memberCount, 0), statusRows: out.statuses.length };
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
