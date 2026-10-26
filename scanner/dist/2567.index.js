export const id = 2567;
export const ids = [2567];
export const modules = {

/***/ 92567:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   xU: () => (/* binding */ buildResolvedGraph)
/* harmony export */ });
/* unused harmony exports RESOLVED_SCHEMA_VERSION, RESOLVED_BUDGETS, linkModulesToPackages, analyzeResolvedHaskell */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _haskell_manifests_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(95402);
// Resolved Haskell dependency graph (HS-008).
//
// Reads an EXPLICIT cabal install plan (dist-newstyle/cache/plan.json) or a Stack
// resolved export (`stack ls dependencies json`) and joins it with the declared
// manifest inventory from haskell-manifests.js. Static only: no solver, no
// `cabal`/`stack` process, no network, no snapshot fetch.
//
// The rules this module exists to enforce:
//
//   * a resolved graph is a CLAIM about one input state. It is checked against the
//     manifests, compiler, flags and targets it is meant to describe; a mismatch
//     marks it `stale` and DOWNGRADES it (no versions are copied into the declared
//     inventory, no complete closure is claimed);
//   * a freeze file or a stack.yaml.lock is a set of pins, not a closure. Alone, it
//     never yields `closure.complete`;
//   * missing resolved data leaves `units`/`edges` as null (unknown), never [] (none),
//     and every declared dependency keeps `resolvedVersion: null` with a reason;
//   * a local package is labelled `local`, never `hackage`; compiler-shipped packages
//     are `compiler` with `boot:true`; units are keyed by unit id so two builds of one
//     package under different flags stay distinct.




const RESOLVED_SCHEMA_VERSION = 1;
const RESOLVED_BUDGETS = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxUnits: 100000, maxEdges: 1000000 });

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const gap = (kind, message, extra = {}) => ({ kind, message, ...extra });

// Packages that ship with GHC. Used ONLY as a labelled fallback when a Stack export
// carries no location data; a cabal plan states `pre-existing` itself.
const BOOT_FALLBACK = new Set(['base', 'ghc-prim', 'ghc-bignum', 'integer-gmp', 'template-haskell', 'ghc', 'rts', 'ghc-boot', 'ghc-boot-th', 'ghc-heap', 'ghci', 'array', 'bytestring', 'containers', 'deepseq', 'directory', 'exceptions', 'filepath', 'haskeline', 'hpc', 'mtl', 'parsec', 'pretty', 'process', 'stm', 'text', 'time', 'transformers', 'unix', 'Win32', 'binary', 'Cabal', 'Cabal-syntax', 'terminfo', 'xhtml', 'semaphore-compat', 'system-cxx-std-lib']);

function componentScope(componentName) {
  const c = typeof componentName === 'string' ? componentName : 'lib';
  const kind = c.split(':')[0];
  const name = c.includes(':') ? c.slice(c.indexOf(':') + 1) : null;
  const scope = { lib: 'runtime', exe: 'runtime', flib: 'runtime', test: 'test', bench: 'benchmark', setup: 'setup' }[kind] || 'runtime';
  return { kind, name, scope, sublibrary: kind === 'lib' && name ? name : null };
}

function planOrigin(u, localNames) {
  if (u.type === 'pre-existing') return { origin: 'compiler', boot: true, evidence: 'plan-type:pre-existing' };
  const src = isObj(u['pkg-src']) ? u['pkg-src'] : null;
  const st = src && typeof src.type === 'string' ? src.type : null;
  if (u.style === 'local' || st === 'local') return { origin: 'local', boot: false, evidence: u.style === 'local' ? 'style:local' : 'pkg-src:local' };
  if (st === 'repo-tar') return { origin: 'hackage', boot: false, evidence: `pkg-src:repo-tar${src.repo && src.repo.type ? `/${src.repo.type}` : ''}` };
  if (st === 'source-repo') return { origin: 'vcs', boot: false, evidence: 'pkg-src:source-repo' };
  if (st === 'remote-tarball') return { origin: 'url', boot: false, evidence: 'pkg-src:remote-tarball' };
  if (localNames.has(u['pkg-name']) && !st) return { origin: 'unknown', boot: false, evidence: 'name matches a local package but plan does not say local' };
  return { origin: 'unknown', boot: false, evidence: st ? `pkg-src:${st}` : 'no pkg-src' };
}

function depIds(u) {
  const dep = []; const exe = [];
  const take = (arr, into) => { if (Array.isArray(arr)) for (const x of arr) if (typeof x === 'string') into.push(x); };
  take(u.depends, dep); take(u['exe-depends'], exe);
  if (isObj(u.components)) for (const c of Object.values(u.components)) if (isObj(c)) { take(c.depends, dep); take(c['exe-depends'], exe); }
  return { dep: [...new Set(dep)], exe: [...new Set(exe)] };
}

/** Local package facts derived from the declared manifest analysis. */
function manifestFacts(manifests) {
  const m = manifests || {};
  const locals = new Map(); // name -> {version}
  for (const p of m.packages || []) if (p.name) locals.set(p.name, { version: p.version || null });
  for (const p of m.hpack || []) if (p.name && !locals.has(p.name)) locals.set(p.name, { version: p.version || null });
  const withCompiler = (m.projects || []).map((p) => p.withCompiler).find((c) => typeof c === 'string' && /^ghc-\d/.test(c)) || null;
  const stackFile = (m.stack || [])[0] || null;
  let stackCompiler = null;
  if (stackFile) {
    if (typeof stackFile.compiler === 'string') stackCompiler = stackFile.compiler;
    else if (stackFile.snapshot && stackFile.snapshot.kind === 'compiler') stackCompiler = stackFile.snapshot.selector;
  }
  return {
    locals, compiler: withCompiler || stackCompiler, stackFile,
    flagSettings: m.flagSettings || [], flags: m.flags || [], dependencies: m.dependencies || [],
    relaxed: (m.projects || []).some((p) => (p.allowRelaxations || []).length > 0),
  };
}

// ---------------------------------------------------------------------------
// Cabal plan.json
// ---------------------------------------------------------------------------

function propagateScopes(units, edges) {
  const byId = new Map(units.map((u) => [u.id, u]));
  const out = new Map();
  for (const e of edges) { if (!out.has(e.from)) out.set(e.from, []); out.get(e.from).push(e); }
  const seen = new Map(units.map((u) => [u.id, new Set()]));
  const queue = [];
  for (const u of units) if (u.origin === 'local') { seen.get(u.id).add(u.ownScope); queue.push([u.id, u.ownScope]); }
  while (queue.length) {
    const [id, scope] = queue.shift();
    for (const e of out.get(id) || []) {
      const s = e.kind === 'exe-depends' ? 'build-tool' : scope;
      const set = seen.get(e.to);
      if (set && !set.has(s)) { set.add(s); queue.push([e.to, s]); }
    }
  }
  for (const [id, set] of seen) byId.get(id).scopes = [...set].sort();
}

function parsePlan(plan, facts, budgets) {
  const gaps = [];
  if (!isObj(plan) || !Array.isArray(plan['install-plan'])) {
    return { units: null, edges: null, gaps: [gap('malformed_plan', 'plan.json has no `install-plan` array; no graph could be read')], compiler: null, platform: null, malformed: true };
  }
  const raw = plan['install-plan'];
  let truncated = false;
  const list = raw.length > budgets.maxUnits ? (truncated = true, raw.slice(0, budgets.maxUnits)) : raw;
  if (truncated) gaps.push(gap('budget_exceeded', `plan has ${raw.length} units; only ${budgets.maxUnits} were read`));
  const localNames = new Set(facts.locals.keys());
  const units = [];
  const ids = new Set();
  for (const [i, u] of list.entries()) {
    if (!isObj(u) || typeof u.id !== 'string' || typeof u['pkg-name'] !== 'string') {
      gaps.push(gap('malformed_unit', `install-plan entry ${i} lacks id or pkg-name; skipped`, { index: i }));
      continue;
    }
    if (ids.has(u.id)) { gaps.push(gap('duplicate_unit_id', `unit id ${u.id} appears twice; first kept`, { unit: u.id })); continue; }
    ids.add(u.id);
    const o = planOrigin(u, localNames);
    const comp = componentScope(u['component-name']);
    units.push({
      id: u.id, name: u['pkg-name'], version: typeof u['pkg-version'] === 'string' ? u['pkg-version'] : null,
      origin: o.origin, boot: o.boot, originEvidence: o.evidence, planType: u.type || null, style: u.style || null,
      component: { kind: comp.kind, name: comp.name }, sublibrary: comp.sublibrary, ownScope: comp.scope, scopes: [],
      flags: isObj(u.flags) ? { ...u.flags } : {},
      sha256: typeof u['pkg-src-sha256'] === 'string' ? u['pkg-src-sha256'] : null,
      repo: isObj(u['pkg-src']) && isObj(u['pkg-src'].repo) ? { type: u['pkg-src'].repo.type || null, uri: u['pkg-src'].repo.uri || null } : null,
      _deps: depIds(u),
    });
  }
  const edges = [];
  for (const u of units) {
    for (const [kind, arr] of [['depends', u._deps.dep], ['exe-depends', u._deps.exe]]) {
      for (const to of arr) {
        if (!ids.has(to)) { gaps.push(gap('dangling_edge', `unit ${u.id} depends on ${to}, which the plan does not contain`, { from: u.id, to })); continue; }
        if (edges.length >= budgets.maxEdges) { gaps.push(gap('budget_exceeded', 'edge budget reached')); break; }
        edges.push({ from: u.id, to, kind });
      }
    }
    delete u._deps;
  }
  propagateScopes(units, edges);
  for (const u of units) delete u.ownScope;
  const cid = typeof plan['compiler-id'] === 'string' ? plan['compiler-id'] : null;
  return {
    units, edges, gaps, malformed: false,
    compiler: cid ? { id: cid, name: cid.replace(/-\d.*$/, ''), version: (/-(\d+(?:\.\d+)*)$/.exec(cid) || [])[1] || null } : null,
    platform: { os: plan.os || null, arch: plan.arch || null },
  };
}

function flagMap(manifestFlagSettings, flagDecls, pkgName) {
  // expected explicit settings for one local package, plus manual-flag defaults
  const exp = new Map();
  for (const f of flagDecls) if (f.package === pkgName && f.manual && typeof f.default === 'boolean') exp.set(f.name, { value: f.default, from: 'manual-default' });
  for (const s of manifestFlagSettings) {
    if (s.scope === 'stack' || typeof s.value !== 'boolean') continue;
    if (s.package === pkgName || s.package === null) exp.set(s.name, { value: s.value, from: `${s.scope}-setting` });
  }
  return exp;
}

function checkPlanFreshness(parsed, facts, expected) {
  const reasons = [];
  const stale = (kind, message, extra = {}) => reasons.push({ kind, message, ...extra });
  const wantCompiler = expected.compiler || facts.compiler;
  if (wantCompiler && /^ghc-\d/.test(wantCompiler)) {
    if (!parsed.compiler) stale('compiler_unknown', 'plan records no compiler-id; compiler match cannot be shown', { severity: 'unverified' });
    else if (parsed.compiler.id !== wantCompiler) stale('compiler_mismatch', `plan was generated for ${parsed.compiler.id} but the project targets ${wantCompiler}`);
  }
  if (expected.os && parsed.platform && parsed.platform.os && parsed.platform.os !== expected.os) stale('platform_mismatch', `plan os ${parsed.platform.os} differs from expected ${expected.os}`);
  if (expected.arch && parsed.platform && parsed.platform.arch && parsed.platform.arch !== expected.arch) stale('platform_mismatch', `plan arch ${parsed.platform.arch} differs from expected ${expected.arch}`);
  if (Number.isFinite(expected.planMtimeMs) && Number.isFinite(expected.manifestMtimeMs) && expected.planMtimeMs < expected.manifestMtimeMs) stale('plan_older_than_manifest', 'plan.json is older than the newest manifest; it predates the current declarations');

  const units = parsed.units || [];
  const localUnits = units.filter((u) => u.origin === 'local');
  const planLocalNames = new Set(localUnits.map((u) => u.name));
  for (const [name, info] of facts.locals) {
    if (!planLocalNames.has(name)) stale('local_package_missing', `manifest declares local package ${name} but the plan has no local unit for it`, { package: name });
    else if (info.version) {
      const vs = localUnits.filter((u) => u.name === name).map((u) => u.version);
      if (!vs.includes(info.version)) stale('local_version_mismatch', `manifest says ${name} ${info.version} but the plan built ${vs.join(', ')}`, { package: name });
    }
  }
  if (facts.locals.size) for (const n of planLocalNames) if (!facts.locals.has(n)) stale('unknown_local_package', `plan builds local package ${n} that no manifest declares`, { package: n });

  for (const u of localUnits) {
    for (const [flag, e] of flagMap(facts.flagSettings, facts.flags, u.name)) {
      if (flag in u.flags && u.flags[flag] !== e.value) stale('flags_mismatch', `plan built ${u.name} with ${flag}=${u.flags[flag]} but the manifest/project sets ${e.value} (${e.from})`, { package: u.name, flag });
    }
  }
  if (Array.isArray(expected.targets)) {
    const have = new Set(units.map((u) => (u.origin === 'local' ? `${u.name}:${u.component.kind}${u.component.name ? `:${u.component.name}` : ''}` : null)).filter(Boolean));
    for (const t of expected.targets) if (!have.has(t)) stale('target_missing', `expected target ${t} is not in the plan`, { target: t });
  }
  // Declared, unconditional runtime dependencies must be explainable by the plan.
  const names = new Set(units.map((u) => u.name));
  const byName = new Map();
  for (const u of units) { if (!byName.has(u.name)) byName.set(u.name, []); byName.get(u.name).push(u); }
  for (const d of facts.dependencies) {
    if (d.sublibrary || !d.package || !facts.locals.has(d.package) || (d.conditions || []).length) continue;
    if (d.manifestType === 'cabal' && d.shadowedBy) continue;
    if (d.scope !== 'runtime') continue;
    if (!names.has(d.name)) { stale('declared_dependency_missing', `${d.package} declares ${d.name} but the plan contains no such package`, { package: d.package, dependency: d.name }); continue; }
    if (!facts.relaxed && d.rangeKind !== 'unparsed' && d.declaredRange && d.rangeError == null) {
      const ok = byName.get(d.name).some((u) => { try { return u.version && (0,_haskell_manifests_js__WEBPACK_IMPORTED_MODULE_2__/* .versionSatisfies */ .Kw)(d.declaredRange, u.version); } catch { return true; } });
      if (!ok) stale('bounds_violated', `plan has ${d.name} ${byName.get(d.name).map((u) => u.version).join(', ')}, outside declared bound ${d.declaredRange} of ${d.package}`, { package: d.package, dependency: d.name });
    }
  }
  return reasons;
}

// ---------------------------------------------------------------------------
// Stack export
// ---------------------------------------------------------------------------

function parseStackExport(doc, facts, budgets) {
  const envelope = isObj(doc) && Array.isArray(doc.packages) ? doc : null;
  const list = Array.isArray(doc) ? doc : (envelope ? envelope.packages : null);
  if (!Array.isArray(list)) return { units: null, edges: null, gaps: [gap('malformed_stack_export', 'stack export is neither an array nor an object with `packages`; no graph could be read')], malformed: true, envelope: null };
  const gaps = [];
  const scope = envelope && typeof envelope.scope === 'string' ? envelope.scope : null;
  const units = [];
  const idOf = new Map();
  for (const [i, e] of list.slice(0, budgets.maxUnits).entries()) {
    if (!isObj(e) || typeof e.name !== 'string') { gaps.push(gap('malformed_unit', `stack export entry ${i} has no name; skipped`, { index: i })); continue; }
    const version = typeof e.version === 'string' ? e.version : null;
    const id = `${e.name}-${version || '?'}`;
    if (idOf.has(e.name)) { gaps.push(gap('duplicate_unit_id', `package ${e.name} appears twice; first kept`, { unit: id })); continue; }
    idOf.set(e.name, id);
    const loc = isObj(e.location) ? e.location : null;
    let origin; let boot = false; let evidence;
    if (facts.locals.has(e.name)) { origin = 'local'; evidence = 'name matches a local manifest package'; }
    else if (loc && loc.type === 'hackage') { origin = 'hackage'; evidence = 'location:hackage'; }
    else if (loc && typeof loc.type === 'string') { origin = ['git', 'hg', 'github'].includes(loc.type) ? 'vcs' : (loc.type === 'archive' || loc.type === 'url' ? 'url' : 'unknown'); evidence = `location:${loc.type}`; }
    else if (BOOT_FALLBACK.has(e.name)) { origin = 'compiler'; boot = true; evidence = 'boot-name-fallback (export carries no location)'; }
    else { origin = 'unknown'; evidence = 'export carries no location'; }
    units.push({
      id, name: e.name, version, origin, boot, originEvidence: evidence, planType: null, style: null,
      component: { kind: null, name: null }, sublibrary: null, scopes: [scope || 'unspecified'], flags: {}, sha256: null, repo: null,
      _names: Array.isArray(e.dependencies) ? e.dependencies.filter((x) => typeof x === 'string') : [],
    });
  }
  const edges = [];
  for (const u of units) {
    for (const n of u._names) {
      const to = idOf.get(n);
      if (!to) { gaps.push(gap('dangling_edge', `${u.id} depends on ${n}, which the stack export does not contain`, { from: u.id, to: n })); continue; }
      if (edges.length < budgets.maxEdges) edges.push({ from: u.id, to, kind: 'depends' });
    }
    delete u._names;
  }
  return { units, edges, gaps, malformed: false, envelope };
}

function checkStackFreshness(parsed, facts, expected) {
  const reasons = [];
  const env = parsed.envelope;
  const stale = (kind, message, extra = {}) => reasons.push({ kind, message, ...extra });
  if (!env) { stale('stack_export_unlabelled', 'a bare stack export carries no snapshot or compiler, so it cannot be matched to stack.yaml', { severity: 'unverified' }); }
  else {
    const sf = facts.stackFile;
    const snap = typeof env.snapshot === 'string' ? env.snapshot : (typeof env.resolver === 'string' ? env.resolver : null);
    const wantSnap = expected.snapshot || (sf && sf.snapshot ? sf.snapshot.selector : null);
    if (wantSnap) { if (!snap) stale('snapshot_unknown', 'export records no snapshot', { severity: 'unverified' }); else if (snap !== wantSnap) stale('snapshot_mismatch', `export was made for snapshot ${snap} but stack.yaml selects ${wantSnap}`); }
    const wantCompiler = expected.compiler || facts.compiler;
    const comp = typeof env.compiler === 'string' ? env.compiler : null;
    if (wantCompiler && /^ghc-\d/.test(wantCompiler) && comp && comp !== wantCompiler) stale('compiler_mismatch', `export compiler ${comp} differs from ${wantCompiler}`);
    if (!snap && !comp) stale('stack_export_unlabelled', 'export envelope carries neither snapshot nor compiler', { severity: 'unverified' });
  }
  const units = parsed.units || [];
  const names = new Set(units.map((u) => u.name));
  for (const n of facts.locals.keys()) if (!names.has(n)) stale('local_package_missing', `manifest declares local package ${n} but the stack export lacks it`, { package: n });
  const extra = facts.stackFile ? (facts.stackFile.extraDeps || []).filter((e) => e.kind === 'hackage' && e.version) : [];
  for (const e of extra) {
    const u = units.find((x) => x.name === e.name);
    if (u && u.version && u.version !== e.version) stale('extra_dep_mismatch', `stack.yaml pins ${e.name}-${e.version} but the export has ${u.version}`, { package: e.name });
  }
  return reasons;
}

// ---------------------------------------------------------------------------
// Declared inventory join
// ---------------------------------------------------------------------------

function joinDeclared(manifests, graph) {
  const byName = new Map();
  for (const u of graph.units || []) { if (!byName.has(u.name)) byName.set(u.name, []); byName.get(u.name).push(u); }
  const locked = new Map();
  for (const l of (manifests && manifests.lockedPackages) || []) if (l.version && !locked.has(l.name)) locked.set(l.name, l.version);
  const usable = graph.graphAvailable && graph.freshness.status === 'fresh';
  const why = !graph.graphAvailable ? 'no_resolved_data' : (graph.freshness.status === 'stale' ? 'stale_resolved_data' : 'unverified_resolved_data');
  return ((manifests && manifests.dependencies) || []).map((d) => {
    const base = { ...d, resolvedVersion: null, resolution: { status: 'unresolved', reason: why, unitIds: [] } };
    if (locked.has(d.name)) base.lockedVersion = locked.get(d.name);
    if (!usable) return base;
    const cands = (byName.get(d.name) || []).filter((u) => !d.sublibrary || u.sublibrary === d.sublibrary || u.sublibrary === null);
    if (!cands.length) return { ...base, resolution: { status: 'unresolved', reason: 'not_in_resolved_graph', unitIds: [] } };
    const versions = [...new Set(cands.map((u) => u.version))];
    if (versions.length > 1) return { ...base, resolution: { status: 'ambiguous', reason: 'multiple_versions_in_graph', unitIds: cands.map((u) => u.id) } };
    return { ...base, resolvedVersion: versions[0], resolution: { status: 'resolved', reason: null, unitIds: cands.map((u) => u.id), origin: cands[0].origin } };
  });
}

/**
 * Build the resolved graph.
 * input: { manifests (analyzeHaskellManifests output), plan (parsed plan.json),
 *          stackExport (parsed JSON), expected: {compiler, os, arch, targets, snapshot,
 *          planMtimeMs, manifestMtimeMs}, rejectStale, budgets }
 */
function buildResolvedGraph(input = {}) {
  const budgets = { ...RESOLVED_BUDGETS, ...(input.budgets || {}) };
  const expected = input.expected || {};
  const facts = manifestFacts(input.manifests);
  const result = {
    schemaVersion: RESOLVED_SCHEMA_VERSION, source: 'none', graphAvailable: false,
    freshness: { status: 'unverified', reasons: [] }, compiler: null,
    units: null, edges: null, gaps: [], closure: { complete: false, reason: 'no_resolved_data' }, declared: [],
  };
  let parsed = null;
  let reasons = [];
  if (input.plan !== undefined && input.plan !== null) {
    result.source = 'cabal-plan';
    parsed = parsePlan(input.plan, facts, budgets);
    result.compiler = parsed.compiler || null;
    if (!parsed.malformed) reasons = checkPlanFreshness(parsed, facts, expected);
  } else if (input.stackExport !== undefined && input.stackExport !== null) {
    result.source = 'stack-export';
    parsed = parseStackExport(input.stackExport, facts, budgets);
    if (!parsed.malformed) reasons = checkStackFreshness(parsed, facts, expected);
  }

  const lockOnly = !parsed && (((input.manifests || {}).lockedPackages || []).length > 0);
  if (!parsed) {
    result.gaps.push(gap('no_resolved_data', 'no plan.json or stack export was supplied; the dependency graph is unknown (not empty). Nothing was fetched.'));
    if (lockOnly) {
      result.closure = { complete: false, reason: 'lock_only' };
      result.gaps.push(gap('lock_is_not_closure', 'freeze/lock pins name versions but not edges or the full transitive set; a closure is not claimed'));
    }
  } else {
    result.gaps.push(...parsed.gaps);
    if (parsed.malformed) result.closure = { complete: false, reason: 'malformed_resolved_data' };
    else {
      const hardStale = reasons.filter((r) => r.severity !== 'unverified');
      result.freshness = { status: hardStale.length ? 'stale' : (reasons.length ? 'unverified' : 'fresh'), reasons };
      for (const r of reasons) result.gaps.push(gap(r.severity === 'unverified' ? 'freshness_unverified' : 'stale_resolved_data', r.message, { reason: r.kind }));
      if (result.freshness.status === 'stale' && input.rejectStale) {
        result.closure = { complete: false, reason: 'rejected_stale' };
      } else {
        result.graphAvailable = true;
        result.units = parsed.units.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
        result.edges = parsed.edges.sort((a, b) => `${a.from}\0${a.to}\0${a.kind}`.localeCompare(`${b.from}\0${b.to}\0${b.kind}`));
        const dangling = parsed.gaps.some((g) => ['dangling_edge', 'malformed_unit', 'budget_exceeded', 'duplicate_unit_id'].includes(g.kind));
        if (result.freshness.status === 'fresh' && !dangling) result.closure = { complete: true, reason: null };
        else result.closure = { complete: false, reason: result.freshness.status === 'fresh' ? 'graph_gaps' : `${result.freshness.status}_resolved_data` };
      }
    }
  }
  result.declared = joinDeclared(input.manifests, result);
  return result;
}

/**
 * Link imported module names to packages. A link is `verified` only when `moduleIndex`
 * (unit id or package name -> exposed modules, from package metadata) lists the module
 * AND that package is in the graph. Anything else is reported unlinked, never guessed.
 */
function linkModulesToPackages(graph, moduleIndex, imports) {
  const idx = isObj(moduleIndex) ? moduleIndex : {};
  return (imports || []).map((mod) => {
    if (!graph || !graph.graphAvailable) return { module: mod, status: 'unlinked', reason: 'no_resolved_graph' };
    const hits = graph.units.filter((u) => (idx[u.id] || idx[u.name] || []).includes(mod));
    if (!hits.length) return { module: mod, status: 'unlinked', reason: 'no_metadata_for_module' };
    return { module: mod, status: hits.length === 1 ? 'verified' : 'ambiguous', units: hits.map((u) => u.id), packages: [...new Set(hits.map((u) => u.name))] };
  });
}

function readBounded(root, rel, budgets) {
  const abs = path.resolve(root, rel);
  const base = path.resolve(root);
  if (abs !== base && !abs.startsWith(base + path.sep)) return { error: gap('path_outside_root', `${rel} escapes the project root; not read`) };
  let st;
  try { st = fs.statSync(abs); } catch { return { error: gap('resolved_file_missing', `${rel} does not exist`) }; }
  if (!st.isFile()) return { error: gap('resolved_file_missing', `${rel} is not a regular file`) };
  if (st.size > budgets.maxBytes) return { error: gap('budget_exceeded', `${rel} exceeds ${budgets.maxBytes} bytes; not read`) };
  try { return { text: fs.readFileSync(abs, 'utf8'), mtimeMs: st.mtimeMs }; } catch (e) { return { error: gap('read_failed', String(e && e.message).slice(0, 120)) }; }
}

/**
 * Directory entry point. Plan and stack export are read ONLY from the explicit
 * relative paths given (`planPath`, `stackExportPath`); nothing is discovered or run.
 */
function analyzeResolvedHaskell(root, opts = {}) {
  const budgets = { ...RESOLVED_BUDGETS, ...(opts.budgets || {}) };
  const manifests = analyzeHaskellManifestsInDir(root, opts);
  const extraGaps = [];
  const input = { manifests, expected: { ...(opts.expected || {}) }, rejectStale: opts.rejectStale, budgets };
  const load = (rel, key) => {
    const r = readBounded(root, rel, budgets);
    if (r.error) { extraGaps.push(r.error); return null; }
    try { input[key] = JSON.parse(r.text); } catch (e) { extraGaps.push(gap(key === 'plan' ? 'malformed_plan' : 'malformed_stack_export', `${rel} is not valid JSON: ${String(e && e.message).slice(0, 100)}`)); return null; }
    return r;
  };
  if (opts.planPath) { const r = load(opts.planPath, 'plan'); if (r && input.expected.planMtimeMs === undefined) input.expected.planMtimeMs = r.mtimeMs; }
  if (opts.stackExportPath && input.plan === undefined) load(opts.stackExportPath, 'stackExport');
  const g = buildResolvedGraph(input);
  g.gaps.unshift(...extraGaps);
  return { manifests, graph: g };
}


/***/ })

};
