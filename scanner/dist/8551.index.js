export const id = 8551;
export const ids = [8551];
export const modules = {

/***/ 38551:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  analyzeNixClosure: () => (/* binding */ analyzeNixClosure),
  nixClosureOf: () => (/* binding */ nixClosureOf),
  resolvedHackageComponents: () => (/* binding */ resolvedHackageComponents),
  resolvedHaskellGraph: () => (/* binding */ resolvedHaskellGraph),
  runSelectedNixEval: () => (/* binding */ runSelectedNixEval)
});

// UNUSED EXPORTS: RESOLVED_PASS_VERSION, configuredNixAdvisories, mergeEvaluationHealth

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/language/haskell-manifests.js
var haskell_manifests = __webpack_require__(16522);
// EXTERNAL MODULE: ./src/language/haskell-resolved-graph.js
var haskell_resolved_graph = __webpack_require__(86359);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/language/nix-closure.js
// Resolved derivation and closure inventory (NIX-008).
//
// Reads EXPLICITLY SUPPLIED, target-specific exports produced by supported Nix tools; it never runs nix,
// never discovers an executable and never touches the filesystem (this module imports no fs): store-looking
// paths are only strings to be validated and related to each other.
//
// Supported schemas (all documented in docs/guides/nix.md):
//   nix-path-info-json       `nix path-info --json --recursive <installable>`: the object form (keys are store
//                            paths, Nix >= 2.19) and the older array form ([{path, references, deriver, ...}])
//   nix-derivation-show-json `nix derivation show --recursive <installable>`: object keyed by .drv path with
//                            outputs, inputSrcs, inputDrvs, env; also the wrapped {derivations, version} form
//                            whose inputs live under inputs.drvs / inputs.srcs and whose paths omit /nix/store/
//   nix-store-query-text     `nix-store --query --requisites <path>`: one store path per line (OUTPUT-ONLY
//                            identity: no deriver, hash or version, so it can never support an exact claim)
//
// Two different graphs come out and are never conflated: the RUNTIME closure (references of the target's
// output paths) and the BUILD graph (inputDrvs of its derivation). A node's scopes say which it is in.
// An exact claim is made only when every condition holds; each failed condition is a disclosure.



const NIX_CLOSURE_VERSION = 'nix-closure/1';
const CLOSURE_BUDGETS = Object.freeze({ maxBytes: 64 * 1024 * 1024, maxNodes: 200_000, maxEdges: 1_000_000, maxEnvBytes: 1 << 20, maxExports: 16 });
const SUPPORTED_TOOLS = new Set(['nix', 'nix-store']);
const SCHEMA_COMMANDS = {
  'nix-path-info-json': /^nix(?:\s+--\S+)*\s+path-info\b.*--json\b|^nix(?:\s+--\S+)*\s+path-info\b.*--recursive\b/,
  'nix-derivation-show-json': /^nix(?:\s+--\S+)*\s+(?:derivation\s+show|show-derivation)\b/,
  'nix-store-query-text': /^nix-store\b.*(?:--query|-q)\b.*(?:--requisites|-R|--references|--tree)\b|^nix-store\s+-qR\b/,
};
const STORE = '/nix/store/';
const BASE32 = '0123456789abcdfghijklmnpqrsvwxyz';
const STORE_PATH = new RegExp(`^/nix/store/([${BASE32}]{32})-([^/\\x00\\s]+)$`);
const OUTPUT_SUFFIX = /-(?:dev|bin|lib|out|man|doc|info|devdoc|debug|static|dist|fakeroot|headers|include|terminfo)$/;
const ROLE_OF_ENV = [
  ['nativeCheckInputs', 'test'], ['checkInputs', 'test'], ['installCheckInputs', 'test'],
  ['nativeBuildInputs', 'build'], ['depsBuildBuild', 'build'], ['depsBuildTarget', 'build'], ['depsBuildBuildPropagated', 'build'], ['propagatedNativeBuildInputs', 'build'],
  ['buildInputs', 'build+runtime'], ['propagatedBuildInputs', 'build+runtime'], ['depsHostHost', 'build+runtime'], ['depsTargetTarget', 'build+runtime'], ['depsHostHostPropagated', 'build+runtime'],
];

/** Validate and split a store path. Returns null for anything that is not exactly /nix/store/<hash>-<name>. */
function parseStorePath(p) {
  if (typeof p !== 'string' || p.length > 1024) return null;
  const m = STORE_PATH.exec(p);
  if (!m || m[2] === '.' || m[2] === '..' || m[2].includes('..')) return null;
  return { path: p, hash: m[1], name: m[2] };
}
const normalizePath = (p) => (typeof p === 'string' && /^[0-9a-df-np-sv-z]{32}-/.test(p) ? STORE + p : p);

/** Heuristic only: nixpkgs naming is pname-version where the version starts at the first "-<digit>". */
function inferNameVersion(name, drvEnv) {
  if (drvEnv && typeof drvEnv.pname === 'string' && typeof drvEnv.version === 'string') return { pname: drvEnv.pname, version: drvEnv.version, authority: 'derivation-env' };
  if (drvEnv && typeof drvEnv.name === 'string') { const m = /^(.+?)-(\d.*)$/.exec(drvEnv.name); if (m) return { pname: m[1], version: m[2], authority: 'derivation-env' }; }
  const base = String(name || '').replace(/\.drv$/, '').replace(OUTPUT_SUFFIX, '');
  const m = /^(.+?)-(\d.*)$/.exec(base);
  return m ? { pname: m[1], version: m[2], authority: 'inferred-from-store-path' } : { pname: base || null, version: null, authority: 'inferred-from-store-path' };
}

function detectSchema(parsed, text) {
  if (typeof text === 'string' && parsed === undefined) {
    const lines = text.split(/\r?\n/).filter(Boolean);
    return lines.length && lines.every((l) => l.startsWith('/')) ? 'nix-store-query-text' : null;
  }
  if (Array.isArray(parsed)) return parsed.every((x) => x && typeof x === 'object' && typeof x.path === 'string') ? 'nix-path-info-json' : null;
  if (parsed && typeof parsed === 'object') {
    if (parsed.derivations && typeof parsed.derivations === 'object') return 'nix-derivation-show-json';
    const ks = Object.keys(parsed);
    if (!ks.length) return null;
    if (ks.every((k) => /\.drv$/.test(k))) return 'nix-derivation-show-json';
    if (ks.every((k) => /^(?:\/nix\/store\/)?[0-9a-df-np-sv-z]{32}-/.test(k))) return 'nix-path-info-json';
  }
  return null;
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/**
 * @param {{exports: Array<{schema?:string, text?:string, data?:any, provenance?:object, signature?:string}>,
 *          expected?: {system?:string, installable?:string, revision?:object, flakeLockSha256?:string, maxAgeDays?:number, inputsChangedAtMs?:number, roots?:string[], requireSigned?:boolean, publicKeyPem?:string},
 *          now?: number, budgets?: object}} opts
 */
function importNixClosure(opts = {}) {
  const b = { ...CLOSURE_BUDGETS, ...(opts.budgets || {}) };
  const now = opts.now ?? Date.now();
  const expected = opts.expected || {};
  const dis = []; const diag = [];
  const add = (kind, detail, extra = {}) => dis.push({ kind, detail, ...extra });
  const out = { version: NIX_CLOSURE_VERSION, status: 'ok', nodes: [], edges: [], disclosures: dis, diagnostics: diag, claims: null, provenance: [], roots: [], coverage: {} };
  const exps = (opts.exports || []).slice(0, b.maxExports);
  if ((opts.exports || []).length > b.maxExports) add('truncated', `only the first ${b.maxExports} exports were read`);
  if (!exps.length) { add('no-export', 'no export was supplied: nothing about the closure is known'); out.status = 'empty'; out.claims = claims(false, false, dis); return out; }

  // ── parse each export ──
  const pathInfo = new Map();    // path -> {references[], deriver, narHash, narSize, valid}
  const drvs = new Map();        // drv path -> entry
  const queryPaths = new Set();
  const provenance = [];
  let truncated = false; let malformed = 0;

  for (const [idx, ex] of exps.entries()) {
    const label = `export[${idx}]`;
    let parsed; let text = typeof ex.text === 'string' ? ex.text : null;
    if (text !== null && text.length > b.maxBytes) { add('truncated', `${label} is ${text.length} bytes (limit ${b.maxBytes}); not read`); truncated = true; continue; }
    if (ex.data !== undefined) parsed = ex.data;
    else if (text !== null) { try { parsed = JSON.parse(text); } catch { parsed = undefined; } }
    let schema = ex.schema || detectSchema(parsed, text);
    if (!schema || !(schema in SCHEMA_COMMANDS)) { diag.push({ export: label, kind: 'unsupported-schema', detail: ex.schema ? `schema ${ex.schema} is not supported` : 'could not recognise the export format' }); malformed++; continue; }
    const prov = assessProvenance(ex, schema, expected, now, label, add);
    provenance.push({ export: label, schema, ...prov.summary });
    if (schema === 'nix-store-query-text') {
      const lines = String(text !== null ? text : '').split(/\r?\n/).filter(Boolean);
      for (const l of lines) { const sp = parseStorePath(l.trim()); if (!sp) { diag.push({ export: label, kind: 'invalid-store-path', detail: `not a store path: ${l.slice(0, 80)}` }); malformed++; continue; } if (queryPaths.size < b.maxNodes) queryPaths.add(sp.path); else truncated = true; }
      continue;
    }
    if (schema === 'nix-path-info-json') {
      const entries = Array.isArray(parsed) ? parsed.map((e) => [e && e.path, e]) : Object.entries(parsed || {});
      for (const [p, e] of entries) {
        const sp = parseStorePath(normalizePath(p));
        if (!sp) { diag.push({ export: label, kind: 'invalid-store-path', detail: `not a store path: ${String(p).slice(0, 80)}` }); malformed++; continue; }
        if (e === null) { pathInfo.set(sp.path, { references: null, valid: false }); continue; }       // invalid path in the store
        if (!e || typeof e !== 'object') { diag.push({ export: label, kind: 'malformed-entry', detail: sp.path }); malformed++; continue; }
        if (pathInfo.size >= b.maxNodes) { truncated = true; break; }
        const refs = Array.isArray(e.references) ? e.references.map((r) => parseStorePath(normalizePath(r))).filter(Boolean).map((r) => r.path) : null;
        if (Array.isArray(e.references) && refs.length !== e.references.length) { diag.push({ export: label, kind: 'invalid-store-path', detail: `${sp.path} has reference(s) that are not store paths` }); malformed++; }
        pathInfo.set(sp.path, { references: refs, deriver: typeof e.deriver === 'string' && e.deriver ? normalizePath(e.deriver) : null, narHash: typeof e.narHash === 'string' ? e.narHash : null, narSize: Number.isFinite(e.narSize) ? e.narSize : null, valid: e.valid !== false, signatures: Array.isArray(e.signatures) ? e.signatures.length : 0 });
      }
      continue;
    }
    // derivation show
    const wrapped = parsed && parsed.derivations && typeof parsed.derivations === 'object';
    const table = wrapped ? parsed.derivations : parsed;
    for (const [dp0, e] of Object.entries(table || {})) {
      const dp = normalizePath(dp0);
      const sp = parseStorePath(dp);
      if (!sp || !/\.drv$/.test(sp.name)) { diag.push({ export: label, kind: 'invalid-store-path', detail: `not a derivation path: ${String(dp0).slice(0, 80)}` }); malformed++; continue; }
      if (!e || typeof e !== 'object') { diag.push({ export: label, kind: 'malformed-entry', detail: sp.path }); malformed++; continue; }
      if (drvs.size >= b.maxNodes) { truncated = true; break; }
      const outputs = {};
      if (e.outputs && typeof e.outputs === 'object') for (const [n, o] of Object.entries(e.outputs)) { const p = o && o.path ? parseStorePath(normalizePath(o.path)) : null; outputs[n] = p ? p.path : null; }
      const inputDrvs = {};
      const rawIn = wrapped && e.inputs ? (e.inputs.drvs || {}) : (e.inputDrvs || {});
      for (const [k, v] of Object.entries(rawIn)) { const p = parseStorePath(normalizePath(k)); if (!p) { diag.push({ export: label, kind: 'invalid-store-path', detail: `inputDrv key in ${sp.name}` }); malformed++; continue; } inputDrvs[p.path] = Array.isArray(v) ? v : (v && Array.isArray(v.outputs) ? v.outputs : []); }
      const rawSrcs = wrapped && e.inputs ? (e.inputs.srcs || []) : (e.inputSrcs || []);
      const inputSrcs = (Array.isArray(rawSrcs) ? rawSrcs : []).map((s) => parseStorePath(normalizePath(s))).filter(Boolean).map((s) => s.path);
      let env = e.env && typeof e.env === 'object' ? e.env : null;
      if (env && JSON.stringify(env).length > b.maxEnvBytes) { env = null; diag.push({ export: label, kind: 'env-too-large', detail: sp.name }); }
      drvs.set(sp.path, { outputs, inputDrvs, inputSrcs, system: typeof e.system === 'string' ? e.system : null, builder: typeof e.builder === 'string' ? e.builder : null, env });
    }
  }
  out.provenance = provenance;
  if (truncated) { add('truncated', `an export exceeded the node budget (${b.maxNodes}) or size limit; the inventory is partial`); }
  if (malformed) add('malformed', `${malformed} entr${malformed === 1 ? 'y' : 'ies'} could not be used (see diagnostics)`);

  // ── node table ──
  const nodes = new Map();
  const node = (id, kind) => { if (!nodes.has(id)) { const sp = parseStorePath(id); nodes.set(id, { id, kind, hash: sp ? sp.hash : null, storeName: sp ? sp.name : null, scopes: new Set(), outputs: [], system: null, identity: null, pname: null, version: null, versionAuthority: null, deriver: null, narHash: null, patches: [], sources: [], missing: [], roles: new Set(), group: null }); } return nodes.get(id); };
  const outputOwner = new Map();   // output path -> {drv, outputName}
  for (const [dp, d] of drvs) { for (const [n, p] of Object.entries(d.outputs)) if (p) outputOwner.set(p, { drv: dp, output: n }); }
  const edges = [];
  const edgeKeys = new Set();
  const addEdge = (from, to, kind, role) => { const k = `${from}\u0000${to}\u0000${kind}`; if (edgeKeys.has(k)) return; if (edges.length >= b.maxEdges) { truncated = true; return; } edgeKeys.add(k); edges.push({ from, to, kind, ...(role ? { role } : {}) }); };

  for (const [p, info] of pathInfo) {
    const n = node(p, 'output');
    n.narHash = info.narHash || null; n.deriver = info.deriver || null;
    if (info.references === null && info.valid !== false) n.missing.push('references');
    if (!info.narHash) n.missing.push('narHash');
    if (!info.deriver) n.missing.push('deriver');
    if (info.references) for (const r of info.references) if (r !== p) addEdge(p, r, 'reference', null);
  }
  for (const p of queryPaths) { const n = node(p, 'output'); n.queryOnly = !pathInfo.has(p); }
  for (const [dp, d] of drvs) {
    const n = node(dp, 'derivation');
    n.system = d.system; n.outputs = Object.entries(d.outputs).map(([name, path]) => ({ name, path })); n.sources = d.inputSrcs;
    const nv = inferNameVersion(n.storeName, d.env);
    n.pname = nv.pname; n.version = nv.version; n.versionAuthority = nv.authority; n.identity = d.env ? 'derivation-env' : 'drv-path-only';
    if (!d.env) n.missing.push('env');
    if (d.env && typeof d.env.patches === 'string') n.patches = d.env.patches.split(/\s+/).filter(Boolean).map((x) => { const sp = parseStorePath(x); return sp ? { path: sp.path, name: sp.name } : null; }).filter(Boolean).map((x) => ({ path: x.path, name: x.name || x.path }));
    if (d.env && typeof d.env.urls === 'string') n.upstreamUrls = d.env.urls.split(/\s+/).filter(Boolean).slice(0, 8);
    if (d.env && typeof d.env.rev === 'string') n.upstreamRev = d.env.rev;
    // role of each input derivation, from the environment lists that name its output paths
    const rolesFor = (outPaths) => {
      const roles = new Set();
      if (!d.env) return roles;
      for (const [key, role] of ROLE_OF_ENV) { const v = d.env[key]; if (typeof v !== 'string') continue; const set = new Set(v.split(/\s+/)); if (outPaths.some((p) => set.has(p))) roles.add(role); }
      return roles;
    };
    for (const [ip, outs] of Object.entries(d.inputDrvs)) {
      const callee = drvs.get(ip);
      const outPaths = callee ? Object.values(callee.outputs).filter(Boolean) : [];
      const roles = rolesFor(outPaths);
      const role = roles.size ? [...roles].sort().join('|') : 'build';
      node(ip, 'derivation');
      addEdge(dp, ip, 'input-drv', role);
      const e = edges.find((x) => x.from === dp && x.to === ip && x.kind === 'input-drv'); if (e) e.outputsUsed = outs;
    }
    for (const s of d.inputSrcs) { const sn = node(s, 'source'); addEdge(dp, s, 'input-src', 'source'); sn.scopes.add('source'); }
    // link derivation <-> outputs
    for (const [name, op] of Object.entries(d.outputs)) if (op) { const on = node(op, 'output'); on.deriver = on.deriver || dp; on.outputName = name; addEdge(op, dp, 'deriver', null); }
  }
  for (const n of nodes.values()) {
    if (n.kind === 'output') {
      const owner = outputOwner.get(n.id) || (n.deriver && drvs.has(n.deriver) ? { drv: n.deriver } : null);
      const d = owner ? drvs.get(owner.drv) : null;
      if (d) { const nv = inferNameVersion(n.storeName, d.env); n.pname = nv.pname; n.version = nv.version; n.versionAuthority = nv.authority; n.identity = d.env ? 'derivation-env' : 'drv-path-only'; n.system = d.system; n.outputName = owner.output || n.outputName; n.patches = (nodes.get(owner.drv) || {}).patches || []; n.upstreamUrls = (nodes.get(owner.drv) || {}).upstreamUrls; n.upstreamRev = (nodes.get(owner.drv) || {}).upstreamRev; }
      else { const nv = inferNameVersion(n.storeName, null); n.pname = nv.pname; n.version = nv.version; n.versionAuthority = 'inferred-from-store-path'; n.identity = 'output-only'; }
    }
  }

  // ── roots and scopes ──
  let roots = (expected.roots || []).map((r) => parseStorePath(r)).filter(Boolean).map((r) => r.path);
  const fromExpected = roots.length > 0;
  if (!roots.length && pathInfo.size) {
    const referenced = new Set();
    for (const [p, info] of pathInfo) for (const r of info.references || []) if (r !== p) referenced.add(r);
    roots = [...pathInfo.keys()].filter((p) => !referenced.has(p));
  }
  if (!roots.length && queryPaths.size === 1) roots = [...queryPaths];
  const rootDrvs = [];
  for (const r of roots) { const n = nodes.get(r); if (n && n.deriver && drvs.has(n.deriver)) rootDrvs.push(n.deriver); }
  if (roots.length > 1 && !fromExpected) add('ambiguous-root', `${roots.length} paths are not referenced by any other: the target cannot be identified without expected.roots`);
  if (!roots.length) add('no-root', 'no root path could be determined: scopes are not assigned');
  out.roots = roots;
  // runtime closure
  const runtime = new Set(); const rq = [...roots.filter((r) => nodes.has(r))];
  for (const r of rq) runtime.add(r);
  while (rq.length) { const u = rq.shift(); for (const e of edges) if (e.from === u && e.kind === 'reference' && !runtime.has(e.to)) { runtime.add(e.to); rq.push(e.to); } }
  for (const id of runtime) nodes.get(id).scopes.add('runtime');
  // build graph (from the root derivations)
  const buildSeen = new Map(); const bq = [];
  for (const rd of rootDrvs) { buildSeen.set(rd, new Set(['target'])); bq.push(rd); }
  while (bq.length) {
    const u = bq.shift();
    for (const e of edges) if (e.from === u && e.kind === 'input-drv') {
      const roles = new Set(String(e.role || 'build').split('|'));
      const cur = buildSeen.get(e.to) || new Set();
      const before = cur.size;
      for (const r of roles) cur.add(r);
      // roles propagate: a build-only tool's own inputs are build inputs of the target
      if (!buildSeen.has(e.to) || cur.size !== before) { buildSeen.set(e.to, cur); bq.push(e.to); }
    }
  }
  for (const [id, roles] of buildSeen) {
    const n = nodes.get(id); if (!n) continue;
    n.scopes.add('build');
    if ([...roles].every((r) => r === 'test' || r === 'target')) { if (roles.has('test')) n.scopes.add('test'); }
    for (const r of roles) if (r !== 'target') n.roles.add(r);
  }
  // output nodes inherit the build/test scope of their derivation when they were not found in the runtime closure
  for (const n of nodes.values()) if (n.kind === 'output') { const owner = outputOwner.get(n.id); if (owner && buildSeen.has(owner.drv)) { const roles = buildSeen.get(owner.drv); n.scopes.add('build'); if (!n.scopes.has('runtime')) for (const r of roles) if (r !== 'target') n.roles.add(r); if ([...roles].every((r) => r === 'test' || r === 'target') && roles.has('test')) n.scopes.add('test'); } }

  // same-name different-build groups
  // distinct BUILDS: outputs of one derivation (out, dev, ...) are one build; different derivations are different builds
  const groups = new Map();
  for (const n of nodes.values()) if (n.kind === 'output' && n.pname) { const k = `${n.pname}@${n.version || '?'}`; if (!groups.has(k)) groups.set(k, new Set()); groups.get(k).add((outputOwner.get(n.id) || {}).drv || n.deriver || n.hash); }
  for (const n of nodes.values()) if (n.kind === 'output' && n.pname) { const k = `${n.pname}@${n.version || '?'}`; const g = groups.get(k); n.group = k; n.sameNameDifferentBuild = g.size > 1; }

  // dangling references / inputDrvs make a graph open
  let openRuntime = false; let openBuild = false;
  for (const [p, info] of pathInfo) for (const r of info.references || []) if (!pathInfo.has(r) && r !== p) { openRuntime = true; }
  for (const d of drvs.values()) for (const ip of Object.keys(d.inputDrvs)) if (!drvs.has(ip)) openBuild = true;
  if (pathInfo.size && openRuntime) add('open-closure', 'some references point at paths that are not in the export: the runtime closure is not closed');
  if (drvs.size && openBuild) add('open-build-graph', 'some inputDrvs are not described in the export: the build graph is not closed');
  for (const n of nodes.values()) if (n.kind === 'output' && n.identity === 'output-only') { if (!dis.some((x) => x.kind === 'output-only-identity')) add('output-only-identity', 'some components are known only by their store path: name and version are inferred from the path, not authoritative', { count: 0 }); dis.find((x) => x.kind === 'output-only-identity').count++; }
  const missingMeta = [...nodes.values()].filter((n) => n.missing.length && n.kind !== 'source');
  if (missingMeta.length) add('missing-metadata', `${missingMeta.length} node(s) lack metadata (${[...new Set(missingMeta.flatMap((n) => n.missing))].join(', ')})`, { count: missingMeta.length });

  for (const n of nodes.values()) {
    out.nodes.push({ id: n.id, kind: n.kind, componentClass: n.kind === 'source' ? 'source-dependency' : 'resolved-package', hash: n.hash, storeName: n.storeName, pname: n.pname, version: n.version, versionAuthority: n.versionAuthority, identity: n.identity, outputName: n.outputName || null, outputs: n.outputs, system: n.system, scopes: [...n.scopes].sort(), roles: [...n.roles].sort(), deriver: n.deriver, narHash: n.narHash, patches: n.patches, upstream: n.upstreamUrls || n.upstreamRev ? { urls: n.upstreamUrls || [], rev: n.upstreamRev || null } : null, sameNameDifferentBuild: !!n.sameNameDifferentBuild, group: n.group, missing: n.missing });
  }
  out.nodes.sort((a, b) => a.id.localeCompare(b.id));
  out.edges = edges.sort((a, b) => `${a.from}${a.to}${a.kind}`.localeCompare(`${b.from}${b.to}${b.kind}`));
  out.coverage = { outputs: out.nodes.filter((n) => n.kind === 'output').length, derivations: out.nodes.filter((n) => n.kind === 'derivation').length, sources: out.nodes.filter((n) => n.kind === 'source').length, edges: out.edges.length, runtimeClosure: runtime.size, buildGraph: buildSeen.size };
  if (truncated) out.status = 'partial';
  else if (malformed) out.status = 'partial';

  // ── claims ──
  const blocking = (kinds) => dis.some((d) => kinds.includes(d.kind));
  const common = ['foreign-target', 'foreign-revision', 'stale-export', 'unverified-provenance', 'truncated', 'malformed', 'ambiguous-root', 'no-root', 'invalid-signature', 'unsigned'];
  const exactRuntime = pathInfo.size > 0 && !openRuntime && !blocking([...common, 'output-only-identity']) && [...nodes.values()].filter((n) => n.kind === 'output' && runtime.has(n.id)).every((n) => !n.missing.includes('references'));
  const exactBuild = drvs.size > 0 && !openBuild && !blocking(common) && [...nodes.values()].filter((n) => n.kind === 'derivation').every((n) => !n.missing.includes('env'));
  out.claims = claims(exactBuild, exactRuntime, dis);
  return out;
}

function claims(exactBuildGraph, exactRuntimeClosure, dis) {
  return {
    exactBuildGraph, exactRuntimeClosure, exactInventory: exactBuildGraph && exactRuntimeClosure,
    completeness: exactBuildGraph || exactRuntimeClosure ? 'complete-for-supplied-target' : 'not-claimed',
    reasons: dis.filter((d) => !['no-export'].includes(d.kind)).map((d) => d.kind),
  };
}

function assessProvenance(ex, schema, expected, now, label, add) {
  const p = ex.provenance && typeof ex.provenance === 'object' ? ex.provenance : null;
  const summary = { level: 'none', tool: null, command: null, target: null };
  if (!p) { add('unverified-provenance', `${label}: no provenance envelope (tool, command, target, flake.lock hash): the export cannot be tied to a target`); return { summary }; }
  summary.tool = p.tool || null; summary.command = p.command || null; summary.target = p.target || null; summary.toolVersion = p.toolVersion || null; summary.generatedAt = p.generatedAt || null;
  let level = 'declared';
  if (!SUPPORTED_TOOLS.has(p.tool)) { add('unverified-provenance', `${label}: tool ${p.tool || '(none)'} is not a supported source for ${schema}`); level = 'none'; }
  else if (typeof p.command !== 'string' || !SCHEMA_COMMANDS[schema].test(p.command)) { add('unverified-provenance', `${label}: the recorded command does not produce ${schema}`); level = 'none'; }
  else if (!p.target || typeof p.target !== 'object' || !p.target.system) { add('unverified-provenance', `${label}: provenance names no target system`); level = 'none'; }
  if (level !== 'none') {
    const t = p.target || {};
    if (expected.system && t.system !== expected.system) add('foreign-target', `${label}: export is for system ${t.system}, expected ${expected.system}`);
    if (expected.installable && t.installable !== expected.installable) add('foreign-target', `${label}: export is for ${t.installable || '(unnamed)'}, expected ${expected.installable}`);
    for (const [k, v] of Object.entries(expected.revision || {})) { const got = (p.revision || {})[k]; if (got !== v) add('foreign-revision', `${label}: ${k} revision ${got || '(none)'} differs from the expected ${v}`); }
    if (expected.flakeLockSha256 && p.flakeLockSha256 !== expected.flakeLockSha256) add('stale-export', `${label}: made against a different flake.lock (${String(p.flakeLockSha256 || 'none').slice(0, 12)} vs ${expected.flakeLockSha256.slice(0, 12)})`);
    const at = Date.parse(p.generatedAt);
    if (!Number.isFinite(at)) add('stale-export', `${label}: no usable generation time`);
    else {
      const maxMs = (expected.maxAgeDays ?? 30) * 86400000;
      if (now - at > maxMs) add('stale-export', `${label}: generated ${Math.round((now - at) / 86400000)} days ago (limit ${expected.maxAgeDays ?? 30})`);
      if (Number.isFinite(expected.inputsChangedAtMs) && expected.inputsChangedAtMs > at) add('stale-export', `${label}: the flake inputs changed after this export was generated`);
    }
  }
  // optional attestation
  if (ex.signature) {
    try {
      const body = JSON.stringify({ schema: ex.schema ?? schema, provenance: p, data: ex.data !== undefined ? ex.data : null, text: ex.text !== undefined ? ex.text : null });
      const v = (0,external_node_crypto_.createVerify)('sha256'); v.update(body);
      if (expected.publicKeyPem && v.verify(expected.publicKeyPem, Buffer.from(ex.signature, 'base64'))) { if (level !== 'none') level = 'signed'; }
      else add('invalid-signature', `${label}: the signature does not verify`);
    } catch (e) { add('invalid-signature', `${label}: signature check failed (${e.message})`); }
  } else if (expected.requireSigned) add('unsigned', `${label}: a signed export is required`);
  summary.level = level;
  return { summary };
}

/** Canonical body that a producer signs (exported so tests and producers agree on it). */
function signedBody(ex) { return JSON.stringify({ schema: ex.schema, provenance: ex.provenance, data: ex.data !== undefined ? ex.data : null, text: ex.text !== undefined ? ex.text : null }); }


// EXTERNAL MODULE: ./src/language/haskell-sca.js
var haskell_sca = __webpack_require__(2437);
// EXTERNAL MODULE: ./src/language/nix-parser.js
var nix_parser = __webpack_require__(54352);
;// CONCATENATED MODULE: ./src/language/nix-sca.js
// Patch-aware Nix vulnerability matching and reachability (NIX-009).
//
// Input is a resolved closure (nix-closure.js), pinned advisory records, optional nixpkgs metadata
// (`knownVulnerabilities`, license, identifiers) and optional overlay/patch evidence from the Nix source.
// The outcome for each component is one of:
//
//   affected             the upstream version is inside an affected range and nothing excuses it
//   fixed                the version/revision is at or past the fix (or the overlay moves it there)
//   backported-verified  in range, BUT a patch whose content hash is in the advisory's fix-patch list is applied
//   possibly-affected    in range with an UNVERIFIED patch claim (a CVE-named patch file proves nothing),
//                        or only a range overlap, or an ambiguous identity with a plausible match
//   candidate            the upstream identity is ambiguous or name-only: matches are leads, never verdicts
//   unknown              no usable version/identity/feed: this is NEVER reported as "not affected"
//   not-affected         mapped, version outside every affected range
//
// A nixpkgs commit, a store hash or a derivation hash is never an upstream software version and is never
// put in a query. Wrapped Haskell packages reuse the Hackage matcher (PVP ordering). Inclusion in the
// runtime closure and Haskell import/API reachability are separate evidence tiers: a store path or a build
// input can establish the first and never the second.





const NIX_SCA_VERSION = 'nix-sca/1';
const HEX40 = /^[0-9a-f]{40}$/i;
const STORE_HASH = /^[0-9a-df-np-sv-z]{32}$/;
const UPSTREAM_NOISE = /^(?:git|unstable|master|main|HEAD|latest|unstable-\d{4}-\d{2}-\d{2})$/i;

/** A nixpkgs revision, a store-path hash or a date stamp is not an upstream version. */
function isNotAnUpstreamVersion(v) {
  if (typeof v !== 'string' || !v) return 'no version';
  if (HEX40.test(v)) return 'a 40-hex string is a git revision (for example a nixpkgs commit), not a software version';
  if (STORE_HASH.test(v)) return 'a 32-character base32 string is a store-path hash, not a software version';
  if (/^[0-9a-f]{7,12}$/i.test(v) && /[a-f]/i.test(v)) return 'a short hexadecimal string is a revision, not a software version';
  if (UPSTREAM_NOISE.test(v)) return `"${v}" is a moving ref, not a software version`;
  if (!/\d/.test(v)) return `"${v}" has no numeric component`;
  return null;
}

// ── generic version ordering for upstream software ───────────────────────────
const PRE = /^(?:alpha|beta|rc|pre|dev|snapshot|a|b)$/i;
function tokens(v) { return String(v).toLowerCase().replace(/^v(?=\d)/, '').split(/[^a-z0-9]+/).filter(Boolean).flatMap((t) => t.match(/\d+|[a-z]+/g) || []); }
function compareUpstream(a, b) {
  const x = tokens(a), y = tokens(b);
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i], q = y[i];
    if (p === undefined) return PRE.test(q) ? 1 : (/^\d+$/.test(q) && Number(q) === 0 ? 0 : -1);
    if (q === undefined) return PRE.test(p) ? -1 : (/^\d+$/.test(p) && Number(p) === 0 ? 0 : 1);
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) { const d = Number(p) - Number(q); if (d) return d < 0 ? -1 : 1; continue; }
    if (pn !== qn) { if (!pn && PRE.test(p)) return -1; if (!qn && PRE.test(q)) return 1; return pn ? 1 : -1; }
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

// ── advisories ───────────────────────────────────────────────────────────────
const sha = (s) => String(s || '').toLowerCase().replace(/^sha256[-:]/, '');
function eventsToRanges(events) {
  const out = []; let lo = null;
  for (const e of events || []) {
    if ('introduced' in e) lo = e.introduced === '0' ? null : e.introduced;
    else if ('fixed' in e) { out.push({ lo, hi: e.fixed, hiInc: false }); lo = null; }
    else if ('last_affected' in e) { out.push({ lo, hi: e.last_affected, hiInc: true }); lo = null; }
  }
  if (events && events.some((e) => 'introduced' in e) && (lo !== null || !out.length || !events.some((e) => 'fixed' in e || 'last_affected' in e))) out.push({ lo, hi: null, hiInc: false });
  return out;
}
const inRange = (v, r) => (r.lo === null || compareUpstream(v, r.lo) >= 0) && (r.hi === null || (r.hiInc ? compareUpstream(v, r.hi) <= 0 : compareUpstream(v, r.hi) < 0));

/** Normalize a non-Hackage OSV-style record into what Nix matching needs. */
function normalizeGenericAdvisory(rec) {
  if (!rec || typeof rec.id !== 'string') return null;
  const aliases = [...new Set((rec.aliases || []).filter((x) => typeof x === 'string'))];
  const affected = [];
  for (const a of rec.affected || []) {
    if (!a || !a.package) continue;
    const ranges = (a.ranges || []).filter((r) => r.type !== 'GIT').flatMap((r) => eventsToRanges(r.events));
    const git = (a.ranges || []).filter((r) => r.type === 'GIT').map((r) => ({ repo: r.repo || null, events: r.events || [] }));
    affected.push({
      ecosystem: a.package.ecosystem || null, name: a.package.name || null, purl: a.package.purl || null, cpe: a.package.cpe || null,
      ranges, versions: Array.isArray(a.versions) ? a.versions : [], git,
      fixedIn: [...new Set((a.ranges || []).flatMap((r) => (r.events || []).filter((e) => 'fixed' in e).map((e) => e.fixed)))],
      fixPatches: ((a.database_specific && a.database_specific.fix_patches) || (rec.database_specific && rec.database_specific.fix_patches) || []).map((p) => ({ name: p.name || null, sha256: p.sha256 ? sha(p.sha256) : null })),
    });
  }
  return { id: rec.id, ids: [rec.id, ...aliases], cves: [rec.id, ...aliases].filter((x) => /^CVE-/.test(x)), summary: rec.summary || '', withdrawn: rec.withdrawn || null, published: rec.published || null, modified: rec.modified || null, references: (rec.references || []).map((r) => r.url).filter(Boolean), affected };
}

class NixAdvisoryData {
  constructor({ records = [], hackage = null, source = 'records', generatedAt = null, now = Date.now(), maxAgeDays = 30 } = {}) {
    this.source = source; this.generatedAt = generatedAt; this.maxAgeDays = maxAgeDays;
    this.records = records.map(normalizeGenericAdvisory).filter(Boolean);
    this.hackage = hackage;                      // an AdvisoryDb (HS-009) for wrapped Haskell packages
    const gen = generatedAt ? Date.parse(generatedAt) : NaN;
    this.ageDays = Number.isFinite(gen) ? (now - gen) / 86400000 : null;
    this.stale = this.ageDays === null ? true : this.ageDays > maxAgeDays;
    this.feed = { source, generatedAt, status: this.stale ? 'stale-cache' : 'current', records: this.records.length };
  }
}

// ── upstream identity ────────────────────────────────────────────────────────
const HASKELL_ENV_HINTS = ['libraryHaskellDepends', 'setupHaskellDepends', 'executableHaskellDepends', 'isLibrary', 'isExecutable', 'enableSeparateDataOutput', 'compilerName', 'enableLibraryProfiling'];
function purlFromUrl(u) {
  const m = /^https?:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:\/|$)/.exec(u || '');
  if (m) return { purl: `pkg:github/${m[1].toLowerCase()}/${m[2].toLowerCase()}`, host: 'github' };
  const g = /^https?:\/\/gitlab\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:\/|$)/.exec(u || '');
  if (g) return { purl: `pkg:gitlab/${g[1].toLowerCase()}/${g[2].toLowerCase()}`, host: 'gitlab' };
  return null;
}

/**
 * The identity a component can be matched under. Never invents authority: `explicit` needs the package
 * metadata to say so, `src-derived` needs a recognised source host, anything else is `name-only`.
 */
function upstreamIdentity(node, drvEnv, meta, overlay) {
  const cands = [];
  const version = (overlay && overlay.version) || node.version;
  const vguard = isNotAnUpstreamVersion(version);
  const base = { pname: node.pname, version: vguard ? null : version, versionRejected: vguard || null, versionSource: overlay && overlay.version ? 'overlay' : node.versionAuthority };
  const isHs = drvEnv && HASKELL_ENV_HINTS.some((k) => k in drvEnv);
  if (isHs && node.pname) cands.push({ ecosystem: 'Hackage', name: node.pname, purl: (0,haskell_sca/* hackagePurl */.Gf)(node.pname, base.version), authority: 'explicit', basis: 'Haskell build attributes in the derivation' });
  const ids = meta && meta.identifiers ? meta.identifiers : null;
  if (ids && typeof ids.purl === 'string') cands.push({ purl: ids.purl, authority: 'explicit', basis: 'meta.identifiers.purl' });
  const cpes = ids ? [].concat(ids.cpe || [], ids.possibleCPEs || [], ids.v1 && ids.v1.cpeParts ? [ids.v1.cpeParts] : []).filter(Boolean) : [];
  const cpeStrings = cpes.map((c) => (typeof c === 'string' ? c : (c.vendor && c.product ? `${c.vendor}:${c.product}` : null))).filter(Boolean);
  const uniqueCpe = [...new Set(cpeStrings)];
  if (uniqueCpe.length === 1 && ids && ids.cpe && !ids.possibleCPEs) cands.push({ cpe: uniqueCpe[0], authority: 'explicit', basis: 'meta.identifiers.cpe' });
  else for (const c of uniqueCpe) cands.push({ cpe: c, authority: 'candidate', basis: uniqueCpe.length > 1 ? 'one of several possible CPEs' : 'possible CPE' });
  for (const u of (node.upstream && node.upstream.urls) || []) { const p = purlFromUrl(u); if (p) cands.push({ purl: p.purl, authority: 'src-derived', basis: `source URL host ${p.host}` }); }
  if (meta && meta.homepage) { const p = purlFromUrl(meta.homepage); if (p) cands.push({ purl: p.purl, authority: 'src-derived', basis: 'meta.homepage' }); }
  if (!cands.some((c) => c.authority === 'explicit' || c.authority === 'src-derived') && node.pname) cands.push({ name: node.pname, authority: 'name-only', basis: 'store/derivation name only' });
  const uniq = []; const seen = new Set();
  for (const c of cands) { const k = JSON.stringify([c.ecosystem, c.name, c.purl, c.cpe, c.authority]); if (!seen.has(k)) { seen.add(k); uniq.push(c); } }
  const strong = uniq.filter((c) => c.authority === 'explicit' || c.authority === 'src-derived');
  const distinctTargets = new Set(strong.map((c) => c.purl || c.cpe || `${c.ecosystem}:${c.name}`));
  return { ...base, candidates: uniq, ambiguous: distinctTargets.size > 1 || (strong.length === 0 && uniq.length > 1) || uniq.some((c) => c.authority === 'candidate'), authority: strong.length && distinctTargets.size === 1 && !uniq.some((c) => c.authority === 'candidate') ? strong[0].authority : (uniq[0] ? 'name-only' : 'none'), haskell: !!isHs };
}

// ── overlays and patches ─────────────────────────────────────────────────────
const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

/** pname -> {version?, patches:[{name,source,sha256?,url?}], file, line} from overlay `overrideAttrs` calls. */
function overlayEvidence(files) {
  const out = {};
  for (const [file, text] of Object.entries(files || {})) {
    if (!/\.nix$/i.test(file) || typeof text !== 'string') continue;
    const parse = (0,nix_parser/* parseNix */.Z$)(text, { file });
    if (!parse.ast) continue;
    const stack = [parse.ast];
    while (stack.length) {
      const n = stack.pop();
      if (!n || typeof n !== 'object') continue;
      if (n.type === 'attrset') {
        for (const b of n.bindings || []) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = (b.path || []).map(segName);
          if (key.length !== 1 || !key[0]) continue;
          const call = unparen(b.value);
          if (!call || call.type !== 'app') continue;
          const fn = unparen(call.fn);
          const last = fn && fn.type === 'select' ? segName(fn.attrpath[fn.attrpath.length - 1]) : null;
          if (last !== 'overrideAttrs') continue;
          const rec = out[key[0]] || (out[key[0]] = { patches: [], file, line: b.span ? b.span.startLine : null, mechanism: 'overlay-overrideAttrs' });
          let body = unparen(call.arg);
          while (body && body.type === 'lambda') body = unparen(body.body);
          if (body && body.type === 'attrset') {
            for (const ob of body.bindings) {
              if (ob.kind !== 'attr') continue;
              const k = (ob.path || []).map(segName).join('.');
              if (k === 'version') { const v = unparen(ob.value); if (v && v.literal !== undefined) rec.version = v.literal; }
              if (k === 'patches') collectPatches(ob.value, rec.patches);
            }
          }
        }
      }
      for (const k of Object.keys(n)) { const c = n[k]; if (c && typeof c === 'object') { if (Array.isArray(c)) stack.push(...c); else stack.push(c); } }
    }
  }
  return out;
}
function collectPatches(node, acc) {
  const n = unparen(node);
  if (!n) return;
  if (n.type === 'list') for (const it of n.items) collectPatches(it, acc);
  else if (n.type === 'binop') { collectPatches(n.left, acc); collectPatches(n.right, acc); }
  else if (n.type === 'path' && n.literal) acc.push({ name: String(n.literal).replace(/^.*\//, ''), source: 'path', sha256: null });
  else if (n.type === 'app') {
    const flat = []; let f = n; while (f && f.type === 'app') { flat.unshift(f.arg); f = unparen(f.fn); }
    const nm = f && f.type === 'select' ? segName(f.attrpath[f.attrpath.length - 1]) : (f && f.type === 'ident' ? f.name : null);
    if (nm === 'fetchpatch' || nm === 'fetchpatch2') {
      const a = unparen(flat[0]); let url = null; let hash = null;
      if (a && a.type === 'attrset') for (const b of a.bindings) { if (b.kind !== 'attr') continue; const k = (b.path || []).map(segName).join('.'); const v = unparen(b.value); if (k === 'url' && v) url = v.literal ?? null; if ((k === 'sha256' || k === 'hash') && v) hash = v.literal ?? null; }
      acc.push({ name: url ? url.replace(/[?#].*$/, '').replace(/^.*\//, '') : 'fetchpatch', source: 'fetchpatch', url, sha256: hash ? sha(hash) : null });
    }
  }
}

// ── matching ─────────────────────────────────────────────────────────────────
const CVE_IN_NAME = /CVE-\d{4}-\d{4,}/i;
function patchEvidence(patches, advisory, aff) {
  const claims = []; let verified = null;
  const fixHashes = new Set((aff.fixPatches || []).map((p) => p.sha256).filter(Boolean));
  const fixNames = new Set((aff.fixPatches || []).map((p) => p.name).filter(Boolean));
  for (const p of patches || []) {
    const cveInName = (CVE_IN_NAME.exec(p.name || '') || [])[0];
    const namesThis = cveInName && advisory.ids.some((i) => i.toUpperCase() === cveInName.toUpperCase());
    if (p.sha256 && fixHashes.has(sha(p.sha256))) { verified = verified || { patch: p.name, by: 'content hash matches an advisory fix patch' }; continue; }
    if (namesThis || (p.name && fixNames.has(p.name))) claims.push({ patch: p.name, claim: namesThis ? `named after ${cveInName}` : 'name matches an advisory fix patch', verified: false, why: p.sha256 ? 'its content hash is not one the advisory lists' : 'no content hash: a file name proves nothing about what the patch does' });
  }
  return { verified, claims };
}

function genericMatch(adv, aff, ident, node, patches) {
  const v = ident.version;
  const out = { status: 'unknown', reason: '' };
  if (aff.git.length && node.upstream && node.upstream.rev) {
    const rev = node.upstream.rev.toLowerCase();
    const fixed = aff.git.flatMap((g) => g.events.filter((e) => 'fixed' in e).map((e) => String(e.fixed).toLowerCase()));
    const listed = new Set([...(aff.versions || []).map((x) => String(x).toLowerCase()), ...aff.git.flatMap((g) => g.events.filter((e) => 'introduced' in e || 'last_affected' in e).map((e) => String(e.introduced ?? e.last_affected).toLowerCase()))]);
    if (fixed.includes(rev)) return { status: 'fixed', reason: 'the source revision is the advisory fix commit' };
    if ([...listed].includes(rev)) return { status: 'affected', reason: 'the source revision is an affected commit listed by the advisory' };
    out.reason = 'the source revision is neither the fix nor a listed affected commit; commit ordering is not available, so no verdict';
    if (!v) return out;
  }
  if (!v) return { status: 'unknown', reason: ident.versionRejected || 'no upstream version' };
  let inside = aff.ranges.some((r) => inRange(v, r));
  if (!inside && aff.versions.some((x) => compareUpstream(v, x) === 0)) inside = true;
  if (!aff.ranges.length && !aff.versions.length) return { status: 'unknown', reason: 'the advisory has no version information for this package' };
  if (inside) return { status: 'affected', reason: 'the version is inside an affected range' };
  if ((aff.fixedIn || []).some((f) => compareUpstream(v, f) >= 0)) return { status: 'fixed', reason: `the version is at or past the fix (${aff.fixedIn.join(', ')})` };
  return { status: 'not-affected', reason: 'the version is outside every affected range' };
}

/**
 * @param {{closure: object, data: NixAdvisoryData|null, meta?: Record<string,object>, overlays?: object,
 *          haskellUsage?: {imports: object[], callees: Set<string>}, services?: Array<{service:string, packages:string[]}>,
 *          symbols?: Record<string,string[]>, kev?: Set<string>|null, epss?: Record<string,number>|null,
 *          licensePolicy?: object, drvEnv?: Record<string,object>}} opts
 *   meta is keyed by derivation name or pname; drvEnv by derivation path (the env block of the drv show export).
 */
function matchNixVulnerabilities(opts = {}) {
  const { closure, data = null, meta = {}, overlays = {}, haskellUsage = null, services = [], symbols = {}, kev = null, epss = null } = opts;
  const findings = []; const statuses = [];
  const feed = data ? data.feed : { source: null, generatedAt: null, status: 'feed-unavailable', records: 0 };
  const nodes = (closure && closure.nodes) || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  // one subject per derivation: its outputs are one build
  const subjects = new Map();
  const roots = new Set((closure && closure.roots) || []);
  for (const n of nodes) {
    if (n.kind !== 'output' || roots.has(n.id)) continue;      // the target itself is not a dependency of itself
    const key = n.deriver || n.id;
    if (!subjects.has(key)) subjects.set(key, { drv: n.deriver || null, outputs: [], node: n });
    const s = subjects.get(key); s.outputs.push(n);
    if (n.outputName === 'out' || (s.node.outputName !== 'out' && n.scopes.includes('runtime'))) s.node = n;
  }
  const summary = { components: 0, matched: 0, mappedNoMatch: 0, unmapped: 0, candidates: 0 };
  for (const s of subjects.values()) {
    const node = s.node;
    const env = (opts.drvEnv && s.drv && opts.drvEnv[s.drv]) || null;
    const m = meta[node.pname] || meta[node.storeName] || null;
    const ov = overlays[node.pname] || null;
    const patches = [...(node.patches || []), ...((ov && ov.patches) || [])];
    const ident = upstreamIdentity(node, env, m, ov);
    summary.components++;
    const nixBuild = { derivation: s.drv, outputs: s.outputs.map((o) => ({ name: o.outputName, path: o.id })), system: node.system, storeHash: node.hash, patches: patches.map((p) => ({ name: p.name, source: p.source || 'derivation', sha256: p.sha256 || null })), overlay: ov ? { file: ov.file, line: ov.line, versionOverride: ov.version || null } : null, scopes: node.scopes };
    const inclusion = node.scopes.includes('runtime') ? 'runtime-closure' : (node.scopes.length ? 'build-only' : 'unknown');
    const svc = services.filter((x) => x.packages.some((p) => p === node.pname || p === node.storeName)).map((x) => x.service);
    const tiers = { inclusion, services: svc, reachability: { import: 'unknown', function: 'unknown', basis: 'a store path or a build input proves inclusion only, never that code is called' } };
    const base = { name: node.pname, version: ident.version, nixBuild, identity: { authority: ident.authority, candidates: ident.candidates, versionSource: ident.versionSource, versionRejected: ident.versionRejected }, tiers, feed };
    const push = (st, extra = {}) => statuses.push({ ...base, status: st.status, reason: st.reason, ...extra });

    // knownVulnerabilities marked by nixpkgs themselves
    const kvs = (m && Array.isArray(m.knownVulnerabilities) ? m.knownVulnerabilities : []).filter((x) => typeof x === 'string');
    for (const kv of kvs) findings.push(finding(base, { id: `nixpkgs:knownVulnerabilities:${node.pname}`, ids: [kv.match(CVE_IN_NAME) ? kv.match(CVE_IN_NAME)[0] : `nixpkgs-known-vulnerable:${node.pname}`], summary: kv }, 'affected', 'nixpkgs marks this package with knownVulnerabilities', { source: 'nixpkgs-meta', ghc: false }, { kev, epss }));
    if (!data) { push({ status: 'unknown', reason: 'no advisory feed was supplied: absence of a match is not a clean result' }); summary.unmapped++; continue; }
    if (ident.versionRejected && !ident.haskell && !(node.upstream && node.upstream.rev)) { push({ status: 'unknown', reason: `the version cannot be queried: ${ident.versionRejected}` }); summary.unmapped++; continue; }

    let matched = false; let mapped = false;
    // Hackage (wrapped Haskell packages): reuse the PVP matcher
    if (ident.haskell && data.hackage && ident.version && (0,haskell_manifests/* parseVersion */.ot)(ident.version)) {
      mapped = true;
      for (const { adv, aff } of data.hackage.forPackage(node.pname)) {
        if (adv.withdrawn) continue;
        const r = (0,haskell_sca/* matchComponent */.nZ)(aff, { name: node.pname, version: ident.version });
        if (r.status === 'not-affected') continue;
        const pe = patchEvidence(patches, { ids: adv.ids }, { fixPatches: [] });
        const st = decide(r, pe, ident);
        matched = true;
        if (haskellUsage) { const rr = (0,haskell_sca/* reachability */.oY)(node.pname, haskellUsage.imports, haskellUsage.callees, symbols[adv.id] || null); tiers.reachability = { import: rr.import, function: rr.function, basis: rr.reason }; }
        findings.push(finding({ ...base, tiers: { ...tiers } }, { id: adv.canonicalId, ids: adv.ids, summary: adv.summary, cves: adv.cveAliases }, st.status, st.reason, { source: data.hackage.source, ecosystem: 'Hackage', fixedIn: aff.fixedIn, patchEvidence: pe }, { kev, epss }));
      }
    }
    // generic records by PURL / CPE; only authoritative identities are matched, candidates are leads
    for (const adv of data.records) {
      for (const aff of adv.affected) {
        const target = ident.candidates.find((c) => (c.purl && aff.purl && c.purl === aff.purl) || (c.cpe && aff.cpe && c.cpe === aff.cpe) || (c.name && aff.name && !aff.purl && !aff.cpe && c.name === aff.name && c.authority === 'name-only') || (c.ecosystem === 'Hackage' && aff.ecosystem === 'Hackage' && c.name === aff.name));
        if (!target) continue;
        if (aff.ecosystem === 'Hackage') continue;                   // handled above
        mapped = mapped || target.authority === 'explicit' || target.authority === 'src-derived';
        const gm = genericMatch(adv, aff, ident, node, patches);
        if (gm.status === 'not-affected' && target.authority !== 'candidate' && target.authority !== 'name-only') continue;
        const pe = patchEvidence(patches, adv, aff);
        let st = gm.status === 'affected' ? decide(gm, pe, ident) : gm;
        // identity gate: only an authoritative, unambiguous identity may produce a firm verdict
        if (target.authority === 'candidate' || target.authority === 'name-only' || ident.ambiguous) {
          st = { status: gm.status === 'affected' || gm.status === 'possibly-affected' ? 'candidate' : (gm.status === 'fixed' ? 'candidate' : gm.status === 'not-affected' ? 'unknown' : gm.status), reason: `${gm.reason}; the upstream identity is ${target.authority === 'candidate' ? 'ambiguous (several possible CPEs)' : 'name-only'}, so this is a lead, not a verdict` };
          summary.candidates++;
        }
        matched = true;
        findings.push(finding({ ...base, tiers: { ...tiers } }, adv, st.status, st.reason, { source: data.source, ecosystem: aff.ecosystem, fixedIn: aff.fixedIn, patchEvidence: pe, identityBasis: target.basis, identityAuthority: target.authority }, { kev, epss }));
      }
    }
    if (matched) summary.matched++;
    else if (mapped) { summary.mappedNoMatch++; push({ status: 'not-affected', reason: 'mapped to an upstream identity and no advisory in the supplied feed matches this version' }, { identityMapped: true }); }
    else { summary.unmapped++; push({ status: 'unknown', reason: ident.ambiguous ? 'the upstream identity is ambiguous: no verdict' : 'the upstream identity could not be mapped to anything an advisory is keyed by' }, { identityMapped: false }); }
  }
  return { version: NIX_SCA_VERSION, findings, statuses, feed, summary, licenses: licenseReport(nodes.filter((n) => !roots.has(n.id)), meta, opts.licensePolicy) };
}

function decide(r, pe, ident) {
  if (r.status === 'possibly-affected') return { status: 'possibly-affected', reason: r.reason };
  if (pe.verified) return { status: 'backported-verified', reason: `in the affected range, but ${pe.verified.by} (${pe.verified.patch})` };
  if (pe.claims.length) return { status: 'possibly-affected', reason: `in the affected range with an UNVERIFIED patch claim (${pe.claims[0].patch}: ${pe.claims[0].why})` };
  return { status: 'affected', reason: r.reason };
}

function finding(base, adv, status, reason, extra, { kev, epss }) {
  const cves = adv.cves || (adv.ids || []).filter((x) => /^CVE-/.test(x));
  const kevHit = cves.length ? (kev ? cves.some((c) => kev.has(c)) : 'unknown') : 'not-applicable';
  const ep = cves.map((c) => epss && epss[c]).filter((x) => typeof x === 'number');
  const level = { affected: 'high', 'possibly-affected': 'medium', candidate: 'low', 'backported-verified': 'info', fixed: 'info', unknown: 'low', 'not-affected': 'info' }[status] || 'low';
  return {
    type: 'vulnerable_dep', ecosystem: 'nix', language: 'nix', capability: 'sca', analysisKind: 'application', evidenceKind: 'closure',
    name: base.name, version: base.version, osvId: adv.id, ids: adv.ids || [adv.id], cveAliases: cves, summary: adv.summary || '',
    status, matchStatus: status, matchReason: reason, severity: level, severityBasis: 'the advisory carries no severity rating',
    nixBuild: base.nixBuild, identity: base.identity, tiers: base.tiers, feed: base.feed,
    kev: kevHit, epss: ep.length ? Math.max(...ep) : 'unknown',
    fixedIn: extra.fixedIn || [], patchEvidence: extra.patchEvidence || { verified: null, claims: [] }, dataSource: { feed: extra.source || base.feed.source, ecosystem: extra.ecosystem || null, identityBasis: extra.identityBasis || null, identityAuthority: extra.identityAuthority || null, feedStatus: base.feed.status },
    file: null, line: null, vuln: `Vulnerable package in the Nix closure (${status})`, cwe: 'CWE-1104', parser: 'NIX-SCA', family: 'sca',
    description: `${base.name}${base.version ? ` ${base.version}` : ''} (${adv.id}): ${reason}.`,
    remediation: (extra.fixedIn && extra.fixedIn.length) ? `Update ${base.name} to ${extra.fixedIn.join(' or ')} (override the input or overlay), then regenerate the closure export.` : 'No fixed version is recorded in the advisory data.',
    confidence: status === 'affected' ? 0.85 : status === 'possibly-affected' ? 0.5 : 0.3,
  };
}

function licenseReport(nodes, meta, policy) {
  const comps = nodes.filter((n) => n.kind === 'output' && (n.outputName === 'out' || !n.outputName)).map((n) => ({ name: n.pname, version: n.version }));
  const md = {};
  for (const c of comps) { const m = meta[c.name]; if (m && m.license) md[c.name] = { license: typeof m.license === 'string' ? m.license : (m.license.spdxId || m.license.shortName || null) }; }
  return (0,haskell_sca/* licensePolicy */.ez)(comps, md, policy);
}



// EXTERNAL MODULE: ./src/language/haskell-supply.js
var haskell_supply = __webpack_require__(86349);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
// EXTERNAL MODULE: external "node:net"
var external_node_net_ = __webpack_require__(77030);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
;// CONCATENATED MODULE: ./src/language/nix-eval-isolation.js
// Isolated, opt-in Nix evaluation (NIX-011).
//
// Ordinary scanning NEVER evaluates customer Nix: nothing imports this module on the default path. An
// operator who explicitly asks for evaluation gets it only inside an OS sandbox whose isolation this module
// has just proved with a probe, and only through an evaluator whose required safety flags were
// feature-detected. The order is fixed and every step before the last is "before project code runs":
//
//   1. detectSandbox      which backend exists on this host (macOS sandbox-exec, Linux bubblewrap), or none
//   2. probeSandbox       run a probe INSIDE the sandbox that tries to read outside the allowlist, write
//                         outside it, reach the network, reach a daemon socket, spawn a process and see a
//                         credential variable; the sandbox is accepted only if every attempt is refused
//   3. detectEvaluator    run `--version` / `eval --help` and require every safety flag to exist
//   4. runIsolatedEval    run the target-scoped evaluation with a clean environment, a read-only allowlist,
//                         a wall-clock deadline, an output cap and a memory ceiling; kill the whole process group
//
// Anything that fails earlier returns `unsupported` or `blocked` with `projectCodeEvaluated:false`; the
// static findings of the scan are never touched (`staticFindingsRetained:true`) and the result says how to
// import a supplied export instead. Flags are NOT the boundary: the filesystem/network/process boundary is
// the sandbox, and the probe tests it independently of any flag. Nix's own build sandbox and restricted
// evaluation are additional controls, not substitutes. Nothing here runs `nixos-rebuild`, activates a
// configuration, builds anything or edits a host setting.








const NIX_EVAL_VERSION = 'nix-eval-isolation/1';
const DEFAULT_LIMITS = Object.freeze({ deadlineMs: 20_000, maxOutputBytes: 1 << 20, maxRssMb: 512, killGraceMs: 1500, probeDeadlineMs: 15_000 });
/** Flags the evaluator must support; a missing one means `unsupported`, never "run without it". */
const REQUIRED_EVAL_FLAGS = Object.freeze(['--offline', '--no-update-lock-file', '--no-write-lock-file', '--pure-eval', '--json', '--option']);
/** `--option name value` settings that are always passed. */
const SAFETY_OPTIONS = Object.freeze({
  'allow-import-from-derivation': 'false',
  'allow-unsafe-native-code-during-evaluation': 'false',
  'accept-flake-config': 'false',
  'restrict-eval': 'true',
  'allowed-uris': '',
  'substituters': '',
  'max-jobs': '0',
});
const CLEAN_PATH = '/usr/bin:/bin';
const ATTR_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+'-]*(?:\.(?:[A-Za-z0-9_][A-Za-z0-9_+'-]*|"[A-Za-z0-9_.+-]+"))*$/;

// ── 1. sandbox backend ───────────────────────────────────────────────────────
const which = (bin) => { const r = (0,external_node_child_process_.spawnSync)('/usr/bin/which', [bin], { encoding: 'utf8', timeout: 5000 }); return r.status === 0 ? r.stdout.trim() : null; };

function detectSandbox(opts = {}) {
  const plat = opts.platform || (0,external_node_os_.platform)();
  const find = opts.which || which;
  if (opts.forceBackend === 'none') return { available: false, backend: 'none', platform: plat, reason: 'isolation disabled by the caller' };
  if (plat === 'darwin') {
    const p = find('sandbox-exec');
    return p ? { available: true, backend: 'sandbox-exec', path: p, platform: plat, reason: null } : { available: false, backend: 'none', platform: plat, reason: 'sandbox-exec is not installed' };
  }
  if (plat === 'linux') {
    const p = find('bwrap');
    return p ? { available: true, backend: 'bwrap', path: p, platform: plat, reason: null } : { available: false, backend: 'none', platform: plat, reason: 'bubblewrap (bwrap) is not installed: no tested unprivileged filesystem/network namespace is available' };
  }
  return { available: false, backend: 'none', platform: plat, reason: `no sandbox backend is implemented for ${plat}` };
}

const sbq = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const real = (p) => { try { return (0,external_node_fs_.realpathSync)(p); } catch { return (0,external_node_path_.resolve)(p); } };

/**
 * The sandboxed command for a backend. Reads are an ALLOWLIST (the listed roots, system library paths and the
 * evaluator); writes are an allowlist of one scratch directory; network and process creation are denied.
 * @param {{backend:string, path?:string}} sb
 * @param {{execFile:string, args:string[], readOnly:string[], readFiles?:string[], writable:string[], cwd:string}} spec
 */
function sandboxCommand(sb, spec) {
  const ro = [...new Set(spec.readOnly.map(real))];
  const files = [...new Set((spec.readFiles || []).map(real))];
  const rw = [...new Set(spec.writable.map(real))];
  const exec = real(spec.execFile);
  if (sb.backend === 'sandbox-exec') {
    const profile = [
      '(version 1)', '(allow default)', '(deny network*)',
      '(deny file-write*)', `(allow file-write* ${rw.map((p) => `(subpath ${sbq(p)})`).join(' ')} (subpath "/dev"))`,
      '(deny file-read-data (subpath "/"))',
      `(allow file-read-data (literal "/") ${[spec.cwd, ...rw].map((p) => `(literal ${sbq(real(p))})`).join(' ')} (subpath "/usr") (subpath "/System") (subpath "/Library") (subpath "/private/var/db") (subpath "/dev") (subpath "/nix/store") ${ro.map((p) => `(subpath ${sbq(p)})`).join(' ')} ${files.map((p) => `(literal ${sbq(p)})`).join(' ')} ${rw.map((p) => `(subpath ${sbq(p)})`).join(' ')})`,
      '(deny process-exec*)', `(allow process-exec (literal ${sbq(exec)}) (subpath "/nix/store"))`,
    ].join('\n');
    return { file: sb.path, args: ['-p', profile, exec, ...spec.args], profile };
  }
  if (sb.backend === 'bwrap') {
    const a = ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp'];
    for (const p of ['/usr', '/lib', '/lib64', '/bin', '/etc/ssl', '/nix/store']) a.push('--ro-bind-try', p, p);
    for (const p of ro) a.push('--ro-bind', p, p);
    for (const p of files) a.push('--ro-bind', p, p);
    for (const p of rw) a.push('--bind', p, p);
    a.push('--chdir', spec.cwd, exec, ...spec.args);
    return { file: sb.path, args: a, profile: null };
  }
  return null;
}

// ── process supervisor ───────────────────────────────────────────────────────
function rssOfGroup(pgid) {
  const r = (0,external_node_child_process_.spawnSync)('/bin/ps', ['-o', 'rss=', '-g', String(pgid)], { encoding: 'utf8', timeout: 2000 });
  if (r.status !== 0) return 0;
  return r.stdout.split('\n').map((x) => parseInt(x, 10)).filter(Number.isFinite).reduce((a, b) => a + b, 0) / 1024;
}
function killGroup(pid, sig) { try { process.kill(-pid, sig); } catch { try { process.kill(pid, sig); } catch { /* gone */ } } }

/** Run a command to completion under a deadline, an output cap and a memory ceiling. Never throws. */
function supervise(file, args, { env, cwd, deadlineMs, maxOutputBytes, maxRssMb, killGraceMs = 1500 }) {
  return new Promise((resolveP) => {
    const t0 = Date.now();
    let child;
    try { child = (0,external_node_child_process_.spawn)(file, args, { env, cwd, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { return resolveP({ status: 'failed', reason: `could not start: ${e.message}`, stdout: '', stderr: '', exitCode: null, signal: null, ms: 0 }); }
    let out = ''; let err = ''; let bytes = 0; let state = null; let done = false;
    const finish = (extra = {}) => { if (done) return; done = true; clearInterval(poll); clearTimeout(dl); resolveP({ stdout: out, stderr: err.slice(0, 4000), ms: Date.now() - t0, ...extra }); };
    const stop = (why) => { if (state) return; state = why; killGroup(child.pid, 'SIGTERM'); setTimeout(() => killGroup(child.pid, 'SIGKILL'), killGraceMs).unref(); };
    child.stdout.on('data', (d) => { bytes += d.length; if (bytes > maxOutputBytes) { stop('output-limit'); return; } out += d.toString('utf8'); });
    child.stderr.on('data', (d) => { if (err.length < 8000) err += d.toString('utf8'); });
    const dl = setTimeout(() => stop('timed-out'), deadlineMs);
    const poll = setInterval(() => { if (!state && maxRssMb && rssOfGroup(child.pid) > maxRssMb) stop('resource-limit'); }, 250);
    child.on('error', (e) => finish({ status: 'failed', reason: e.message, exitCode: null, signal: null }));
    child.on('close', (code, signal) => {
      killGroup(child.pid, 'SIGKILL');                                          // reap any descendants
      finish({ status: state || (code === 0 ? 'ok' : 'failed'), exitCode: code, signal, reason: state ? `${state}${state === 'timed-out' ? ` after ${deadlineMs} ms` : ''}` : (code === 0 ? null : `exit ${code}`) });
    });
  });
}

const cleanEnv = (work, extra = {}) => ({ PATH: CLEAN_PATH, HOME: work, TMPDIR: work, LANG: 'C', LC_ALL: 'C', ...extra });

// ── 2. probe ─────────────────────────────────────────────────────────────────
const PROBE_SOURCE = `
const fs=require('fs'),net=require('net'),cp=require('child_process');
const [allowedFile,outsideFile,outsideWrite,okWrite,port,sock]=process.argv.slice(2);
const r={};const t=(k,f)=>{try{r[k]=f()}catch(e){r[k]='refused:'+(e.code||'error')}};
t('readAllowed',()=>fs.readFileSync(allowedFile,'utf8').trim());
t('readOutside',()=>{fs.readFileSync(outsideFile,'utf8');return 'READ'});
t('readHostFile',()=>{fs.readFileSync('/etc/hosts','utf8');return 'READ'});
t('writeOutside',()=>{fs.writeFileSync(outsideWrite,'x');return 'WROTE'});
t('writeScratch',()=>{fs.writeFileSync(okWrite,'x');return 'wrote'});
t('spawn',()=>{cp.execFileSync('/bin/echo',['x']);return 'SPAWNED'});
t('credentialEnv',()=>process.env.PROBE_CREDENTIAL||'absent');
let pending=2;const fin=()=>{if(--pending===0){console.log(JSON.stringify(r));process.exit(0)}};
const tcp=net.connect(Number(port),'127.0.0.1');tcp.on('connect',()=>{r.network='CONNECTED';tcp.destroy();fin()});tcp.on('error',(e)=>{r.network='refused:'+e.code;fin()});
const un=net.connect(sock);un.on('connect',()=>{r.daemonSocket='CONNECTED';un.destroy();fin()});un.on('error',(e)=>{r.daemonSocket='refused:'+e.code;fin()});
setTimeout(()=>{r.timeout=true;console.log(JSON.stringify(r));process.exit(0)},8000);
`;

/**
 * Prove the isolation of a backend with real attempts, independent of any evaluator flag. The result is
 * `verified` only if the one permitted read worked, the scratch write worked and every other attempt was refused.
 */
async function probeSandbox(sb, opts = {}) {
  if (!sb || !sb.available) return { verified: false, backend: sb ? sb.backend : 'none', reason: (sb && sb.reason) || 'no sandbox', attempts: {} };
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits || {}) };
  const base = (0,external_node_fs_.mkdtempSync)((0,external_node_path_.join)((0,external_node_os_.tmpdir)(), 'nix-eval-probe-'));
  const allowed = (0,external_node_path_.join)(base, 'ro'); const scratch = (0,external_node_path_.join)(base, 'rw'); const outside = (0,external_node_path_.join)(base, 'outside');
  for (const d of [allowed, scratch, outside]) (0,external_node_fs_.mkdirSync)(d);
  (0,external_node_fs_.writeFileSync)((0,external_node_path_.join)(allowed, 'a.txt'), 'allowed'); (0,external_node_fs_.writeFileSync)((0,external_node_path_.join)(outside, 'secret.txt'), 'secret');
  const script = (0,external_node_path_.join)(base, 'probe.cjs'); (0,external_node_fs_.writeFileSync)(script, PROBE_SOURCE);
  const sockPath = (0,external_node_path_.join)(base, 'daemon.sock');
  let connections = 0;
  const tcp = (0,external_node_net_.createServer)((s) => { connections++; s.destroy(); });
  const uds = (0,external_node_net_.createServer)((s) => { connections++; s.destroy(); });
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r));
  await new Promise((r) => uds.listen(sockPath, r));
  const port = tcp.address().port;
  try {
    const exe = opts.nodePath || process.execPath;
    const cmd = sandboxCommand(sb, { execFile: exe, args: [script, (0,external_node_path_.join)(allowed, 'a.txt'), (0,external_node_path_.join)(outside, 'secret.txt'), (0,external_node_path_.join)(outside, 'w.txt'), (0,external_node_path_.join)(scratch, 'w.txt'), String(port), sockPath], readOnly: [allowed, (0,external_node_path_.dirname)((0,external_node_path_.dirname)(real(exe)))], readFiles: [script], writable: [scratch], cwd: scratch });
    const r = await supervise(cmd.file, cmd.args, { env: cleanEnv(scratch), cwd: scratch, deadlineMs: limits.probeDeadlineMs, maxOutputBytes: 64 * 1024, maxRssMb: limits.maxRssMb, killGraceMs: limits.killGraceMs });
    let attempts = null;
    try { attempts = JSON.parse(r.stdout.trim()); } catch { /* unparseable: not verified */ }
    if (!attempts) return { verified: false, backend: sb.backend, reason: `the probe did not complete inside the sandbox (${r.reason || r.stderr.slice(0, 120) || 'no output'})`, attempts: {} };
    const insufficient = [];
    if (attempts.readAllowed !== 'allowed') insufficient.push('the allowlisted read failed: the sandbox is unusable');
    if (attempts.writeScratch !== 'wrote') insufficient.push('the scratch write failed: the sandbox is unusable');
    if (attempts.readOutside === 'READ') insufficient.push('a file outside the allowlist could be read');
    if (attempts.readHostFile === 'READ') insufficient.push('a host file (/etc/hosts) could be read');
    if (attempts.writeOutside === 'WROTE') insufficient.push('a file outside the scratch directory could be written');
    if (attempts.network === 'CONNECTED') insufficient.push('a network connection succeeded');
    if (attempts.daemonSocket === 'CONNECTED') insufficient.push('a unix daemon socket could be reached');
    if (attempts.spawn === 'SPAWNED') insufficient.push('a native process could be spawned');
    if (attempts.credentialEnv && attempts.credentialEnv !== 'absent') insufficient.push('a credential environment variable was visible');
    if (attempts.timeout) insufficient.push('the probe timed out');
    return { verified: insufficient.length === 0 && connections === 0, backend: sb.backend, reason: insufficient.length ? insufficient.join('; ') : (connections ? 'the probe listeners saw a connection' : null), attempts, listenerConnections: connections, insufficient };
  } finally { tcp.close(); uds.close(); (0,external_node_fs_.rmSync)(base, { recursive: true, force: true }); }
}

// ── 3. evaluator feature detection ───────────────────────────────────────────
/** @param {{file:string, prefixArgs?:string[]}} nix  the evaluator command (a stand-in in tests) */
async function detectEvaluator(nix, sb, ctx) {
  const run = async (args) => {
    const cmd = sandboxCommand(sb, { execFile: nix.file, args: [...(nix.prefixArgs || []), ...args], readOnly: ctx.readOnly, readFiles: [...(ctx.readFiles || []), ...(nix.prefixArgs || []).filter((a) => !a.startsWith('-'))], writable: [ctx.work], cwd: ctx.work });
    return supervise(cmd.file, cmd.args, { env: cleanEnv(ctx.work), cwd: ctx.work, deadlineMs: 10_000, maxOutputBytes: 64 * 1024, maxRssMb: ctx.limits.maxRssMb, killGraceMs: ctx.limits.killGraceMs });
  };
  const v = await run(['--version']);
  const ver = (/(\d+\.\d+(?:\.\d+)?)/.exec(v.stdout) || [])[1] || null;
  if (v.status !== 'ok' || !ver) return { ok: false, reason: `the evaluator did not report a version (${v.reason || 'no output'})`, version: null, missing: REQUIRED_EVAL_FLAGS.slice() };
  const h = await run(['eval', '--help']);
  const text = `${h.stdout}\n${h.stderr}`;
  const missing = REQUIRED_EVAL_FLAGS.filter((f) => !text.includes(f));
  return { ok: missing.length === 0, version: ver, missing, reason: missing.length ? `the evaluator lacks required safety flag(s): ${missing.join(', ')}` : null };
}

// ── target selection and argv ────────────────────────────────────────────────
/** A flake output attribute, validated. Anything outside a plain attribute path is refused. */
function selectTarget({ root, attribute, system = null } = {}) {
  if (typeof root !== 'string' || !root.startsWith('/')) return { ok: false, reason: 'the project root must be an absolute path' };
  if (typeof attribute !== 'string' || !ATTR_RE.test(attribute) || attribute.length > 200) return { ok: false, reason: `"${String(attribute).slice(0, 40)}" is not a plain flake attribute path` };
  if (/\.\./.test(attribute)) return { ok: false, reason: 'attribute paths may not contain ..' };
  return { ok: true, installable: `path:${root}#${attribute}`, root, attribute, system };
}
function buildEvalArgs(target) {
  const opts = Object.entries(SAFETY_OPTIONS).flatMap(([k, v]) => ['--option', k, v]);
  return ['eval', '--offline', '--no-update-lock-file', '--no-write-lock-file', '--pure-eval', '--json', ...opts, target.installable];
}

// ── 4. run ───────────────────────────────────────────────────────────────────
const IMPORT_FALLBACK = Object.freeze({
  summary: 'Evaluation did not run or did not finish. Static findings are unaffected. To supply the data yourself, generate an export on a trusted machine and pass it in:',
  steps: ['nix path-info --json --recursive <installable>  >  pathinfo.json', 'nix derivation show --recursive <installable>  >  drvshow.json', 'Provide both with a provenance envelope (tool, command, target system and installable, flake.lock sha256, generation time); see docs/guides/nix.md'],
  schemas: ['nix-path-info-json', 'nix-derivation-show-json', 'nix-store-query-text'],
});

/**
 * @param {{nix:{file:string,prefixArgs?:string[]}, root:string, attribute:string, system?:string, limits?:object,
 *          sandbox?:object, extraReadOnly?:string[], probe?:Function, env?:object}} o
 * @returns {Promise<{status:'ok'|'unsupported'|'blocked'|'timed-out'|'output-limit'|'resource-limit'|'failed', projectCodeEvaluated:boolean, ...}>}
 */
async function runIsolatedEval(o) {
  const limits = { ...DEFAULT_LIMITS, ...(o.limits || {}) };
  const keep = { staticFindingsRetained: true, fallback: IMPORT_FALLBACK, evaluation: 'opt-in' };
  const stopBefore = (status, reason, extra = {}) => ({ status, reason, projectCodeEvaluated: false, ...keep, ...extra });
  const target = selectTarget({ root: o.root, attribute: o.attribute, system: o.system });
  if (!target.ok) return stopBefore('blocked', target.reason);
  const sb = o.sandbox || detectSandbox();
  if (!sb.available) return stopBefore('unsupported', `no isolation is available (${sb.reason}); the project's Nix code was NOT evaluated`, { sandbox: sb });
  const probe = await (o.probe || probeSandbox)(sb, { limits });
  if (!probe.verified) return stopBefore('blocked', `the sandbox did not prove its isolation, so the project's Nix code was NOT evaluated: ${probe.reason}`, { sandbox: sb, probe });
  const work = (0,external_node_fs_.mkdtempSync)((0,external_node_path_.join)((0,external_node_os_.tmpdir)(), 'nix-eval-work-'));
  try {
    const root = real(o.root);
    const nixFiles = [nix_file(o.nix), ...(o.nix.prefixArgs || []).filter((a) => a && !a.startsWith('-')).map(real)];
    const ctx = { work: real(work), readOnly: [root, (0,external_node_path_.dirname)((0,external_node_path_.dirname)(real(o.nix.file))), ...(o.extraReadOnly || [])], readFiles: nixFiles, limits };
    const feat = await detectEvaluator(o.nix, sb, ctx);
    if (!feat.ok) return stopBefore('unsupported', `${feat.reason}; the project's Nix code was NOT evaluated`, { sandbox: sb, probe: { verified: true }, evaluator: feat });
    const args = [...(o.nix.prefixArgs || []), ...buildEvalArgs(target)];
    const cmd = sandboxCommand(sb, { execFile: o.nix.file, args, readOnly: ctx.readOnly, readFiles: nixFiles, writable: [ctx.work], cwd: ctx.work });
    const r = await supervise(cmd.file, cmd.args, { env: cleanEnv(ctx.work, o.env || {}), cwd: ctx.work, deadlineMs: limits.deadlineMs, maxOutputBytes: limits.maxOutputBytes, maxRssMb: limits.maxRssMb, killGraceMs: limits.killGraceMs });
    const base = { ...keep, projectCodeEvaluated: true, sandbox: { backend: sb.backend }, evaluator: { version: feat.version }, ms: r.ms, target: { attribute: target.attribute, system: target.system, installable: target.installable } };
    if (r.status !== 'ok') return { ...base, status: r.status === 'failed' ? 'failed' : r.status, reason: r.reason || r.stderr.slice(0, 200) };
    let data;
    try { data = JSON.parse(r.stdout); } catch { return { ...base, status: 'failed', reason: 'the evaluator output was not JSON' }; }
    const digest = (0,external_node_crypto_.createHash)('sha256').update(r.stdout).digest('hex');
    return { ...base, status: 'ok', reason: null, export: { schema: 'nix-eval-attrs-json', provenance: { tool: 'nix', toolVersion: feat.version, command: `nix ${buildEvalArgs(target).join(' ')}`, target: { system: target.system, installable: target.installable, attribute: target.attribute }, generatedAt: new Date().toISOString(), isolation: sb.backend, outputSha256: digest }, data }, outputSha256: digest };
  } finally { (0,external_node_fs_.rmSync)(work, { recursive: true, force: true }); }
}
const nix_file = (n) => real(n.file);

/** Evaluation health is its OWN state: it never replaces, empties or downgrades the static scan. */
function mergeEvaluationHealth(scanHealth, result) {
  const h = scanHealth && typeof scanHealth === 'object' ? { ...scanHealth } : {};
  const requested = !!result;
  h.evaluation = requested
    ? { requested: true, status: result.status, ran: result.projectCodeEvaluated === true, reason: result.reason || null, ms: result.ms ?? null, fallback: result.status === 'ok' ? null : result.fallback || IMPORT_FALLBACK }
    : { requested: false, status: 'not-requested', ran: false, reason: 'evaluation is opt-in; the scan is static', fallback: null };
  h.staticFindingsRetained = true;
  return h;
}



;// CONCATENATED MODULE: ./src/language/resolved-pass.js
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










const RESOLVED_PASS_VERSION = 'resolved-pass/1';

const PLAN = /(?:^|\/)dist-newstyle\/cache\/plan\.json$/;
const STACK_EXPORT = /(?:^|\/)\.stack-work\/dependencies\.json$/;
const NIX_EXPORT = /(?:^|\/)nix-export\.json$/;
const ACTIONABLE = new Set(['affected', 'possibly-affected', 'candidate', 'backported-verified']);

const memo = new WeakMap();
const memoized = (files, key, make) => { let m = memo.get(files); if (!m) { m = new Map(); memo.set(files, m); } if (!m.has(key)) m.set(key, make()); return m.get(key); };

function parseJson(text) { try { return { ok: true, value: JSON.parse(text) }; } catch (e) { return { ok: false, reason: String((e && e.message) || e).slice(0, 120) }; } }

/** The resolved Haskell graph for a file set, or null when no explicit export is present. Cached per file set. */
function resolvedHaskellGraph(files) {
  return memoized(files, 'hs-graph', () => {
    const planFile = Object.keys(files).find((p) => PLAN.test(p));
    const stackFile = !planFile ? Object.keys(files).find((p) => STACK_EXPORT.test(p)) : null;
    const src = planFile || stackFile;
    if (!src) return null;
    const mf = (0,haskell_supply/* manifestFiles */.TY)(files);
    const manifests = mf.length ? (0,haskell_manifests/* analyzeHaskellManifests */.JS)(mf) : null;
    const parsed = parseJson(files[src]);
    if (!parsed.ok) return { file: src, graph: { source: planFile ? 'cabal-plan' : 'stack-export', graphAvailable: false, units: null, edges: null, freshness: { status: 'unverified', reasons: [] }, closure: { complete: false, reason: 'malformed_resolved_data' }, gaps: [{ kind: planFile ? 'malformed_plan' : 'malformed_stack_export', detail: `${src} is not valid JSON: ${parsed.reason}` }], declared: [] }, manifests };
    const graph = (0,haskell_resolved_graph/* buildResolvedGraph */.xU)({ manifests, ...(planFile ? { plan: parsed.value } : { stackExport: parsed.value }), expected: {} });
    return { file: src, graph, manifests };
  });
}

/**
 * Components for the resolved graph: every Hackage unit with an exact version, its scope and where it came from. Only a graph that is
 * not stale contributes; a stale one is returned as a gap (never as components), and a partial one says it is partial.
 */
function resolvedHackageComponents(files) {
  const r = resolvedHaskellGraph(files);
  if (!r) return { components: [], gaps: [], summary: null };
  const g = r.graph;
  const gaps = (g.gaps || []).map((x) => ({ kind: `resolved-${x.kind}`, detail: x.detail || x.message || x.kind, file: r.file }));
  const summary = { file: r.file, source: g.source, graphAvailable: g.graphAvailable, freshness: g.freshness, closure: g.closure, units: g.units ? g.units.length : null, edges: g.edges ? g.edges.length : null };
  if (!g.graphAvailable || g.freshness.status === 'stale') return { components: [], gaps, summary };
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
function loadNixExports(files) {
  const exports = []; const sources = []; const problems = []; let expected = {};
  for (const p of Object.keys(files).filter((x) => NIX_EXPORT.test(x)).sort()) {
    const parsed = parseJson(files[p]);
    sources.push(p);
    if (!parsed.ok) { problems.push({ kind: 'malformed-export', file: p, detail: parsed.reason }); continue; }
    const j = parsed.value;
    if (j && Array.isArray(j.exports)) { exports.push(...j.exports.filter((e) => e && typeof e === 'object')); if (j.expected && typeof j.expected === 'object') expected = { ...expected, ...j.expected }; }
    else if (j && typeof j === 'object' && j.schema && (j.data !== undefined || j.text !== undefined)) exports.push(j);
    else exports.push({ text: files[p] });
  }
  return { exports, sources, problems, expected };
}

/** The imported closure (and each derivation's env block) for a file set, or null when there is no export. Cached per file set. */
function nixClosureOf(files, { now = Date.now() } = {}) {
  return memoized(files, 'nix-closure', () => {
    const { exports, sources, problems, expected } = loadNixExports(files);
    if (!sources.length) return null;
    const closure = importNixClosure({ exports, expected, now });
    const drvEnv = {};
    for (const ex of exports) {
      if (ex.schema !== 'nix-derivation-show-json') continue;
      let data = ex.data; if (data === undefined && typeof ex.text === 'string') { const p = parseJson(ex.text); data = p.ok ? p.value : null; }
      for (const [k, v] of Object.entries(data || {})) if (v && v.env) drvEnv[k] = v.env;
    }
    return { closure, drvEnv, sources, problems };
  });
}

/** Advisory records for Nix: a snapshot named by AGENTIC_SECURITY_NIX_ADVISORIES or kept in the project state directory. */
function configuredNixAdvisories(root, env = process.env, hackageDb = null) {
  const path = env.AGENTIC_SECURITY_NIX_ADVISORIES || (root && (0,external_node_fs_.existsSync)((0,state_dir.statePath)(root, 'nix-advisories.json')) ? (0,state_dir.statePath)(root, 'nix-advisories.json') : null);
  if (!path) return { data: null, reason: 'no Nix advisory snapshot is configured (set AGENTIC_SECURITY_NIX_ADVISORIES or provide nix-advisories.json in the project state directory)' };
  let snap; try { snap = JSON.parse((0,external_node_fs_.readFileSync)(path, 'utf8')); } catch (e) { return { data: null, reason: `the Nix advisory snapshot is unreadable: ${e.code || e.message}` }; }
  const records = Array.isArray(snap) ? snap : (Array.isArray(snap.records) ? snap.records : []);
  return { data: new NixAdvisoryData({ records, hackage: hackageDb, source: 'pinned-snapshot', generatedAt: (snap && snap.generatedAt) || null }), reason: null };
}

/** Closure statuses and findings, with every disclosure the import and the feed produced. */
function analyzeNixClosure(files, opts = {}) {
  return memoized(files, 'nix-analysis', () => _analyzeNixClosure(files, opts));
}
function _analyzeNixClosure(files, { scanRoot = null, env = process.env, now = Date.now() } = {}) {
  const c = nixClosureOf(files, { now });
  if (!c) return null;
  const hackage = (0,haskell_supply.configuredAdvisoryDb)(scanRoot, env).db;
  const adv = configuredNixAdvisories(scanRoot, env, hackage);
  let usage = null; try { usage = (0,haskell_supply/* collectUsage */.c$)(files); } catch { usage = null; }
  let matched = null;
  try { matched = matchNixVulnerabilities({ closure: c.closure, drvEnv: c.drvEnv, data: adv.data, overlays: overlayEvidence(files), haskellUsage: usage }); } catch (e) { matched = null; c.problems.push({ kind: 'match-failed', detail: String((e && e.message) || e).slice(0, 160) }); }
  const gaps = [];
  for (const d of c.closure.disclosures || []) gaps.push({ kind: `closure-${d.kind}`, detail: d.detail });
  for (const p of c.problems) gaps.push({ kind: `closure-${p.kind}`, detail: p.detail, file: p.file });
  if (!adv.data) gaps.push({ kind: 'closure-advisory-feed-unavailable', detail: `${adv.reason}. The closure's components were NOT checked against any advisory: the absence of findings is not a clean result.` });
  else if (adv.data.stale) gaps.push({ kind: 'closure-advisory-feed-stale', detail: `the Nix advisory snapshot is stale or undated (${adv.data.ageDays == null ? 'age unknown' : `${Math.floor(adv.data.ageDays)} day(s) old`})` });
  const findings = ((matched && matched.findings) || []).filter((f) => ACTIONABLE.has(f.status)).map((f) => ({ ...f, file: c.sources[0], line: 1 }));
  return { status: c.closure.status, claims: c.closure.claims, sources: c.sources, summary: matched ? matched.summary : null, feed: matched ? matched.feed : null, statuses: matched ? matched.statuses : [], findings, gaps, licenses: matched ? matched.licenses : null, closure: c.closure };
}

// ── isolated evaluation (opt in) ─────────────────────────────────────────────────
/** Runs the isolated evaluation when AGENTIC_SECURITY_NIX_EVAL=1; otherwise null. Never throws; a failure is a recorded state. */
async function runSelectedNixEval(root, env = process.env, overrides = {}) {
  if (env.AGENTIC_SECURITY_NIX_EVAL !== '1') return null;
  const attribute = env.AGENTIC_SECURITY_NIX_TARGET || '';
  const nixBin = overrides.nix || (which ? which('nix') : null);
  if (!attribute) return { status: 'blocked', reason: 'no evaluation target: set AGENTIC_SECURITY_NIX_TARGET to a flake output attribute (for example nixosConfigurations.host.config.system.build.toplevel.drvPath)', projectCodeEvaluated: false };
  if (!nixBin) return { status: 'unsupported', reason: 'the nix binary was not found on PATH; the project\'s Nix code was NOT evaluated', projectCodeEvaluated: false };
  try { return await runIsolatedEval({ nix: typeof nixBin === 'string' ? { file: nixBin } : nixBin, root, attribute, system: env.AGENTIC_SECURITY_NIX_SYSTEM || null, ...overrides }); }
  catch (e) { return { status: 'failed', reason: `the evaluation harness failed: ${String((e && e.message) || e).slice(0, 160)}`, projectCodeEvaluated: false }; }
}




/***/ })

};
