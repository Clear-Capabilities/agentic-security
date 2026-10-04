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

import { createHash, createVerify } from 'node:crypto';

export const NIX_CLOSURE_VERSION = 'nix-closure/1';
export const CLOSURE_BUDGETS = Object.freeze({ maxBytes: 64 * 1024 * 1024, maxNodes: 200_000, maxEdges: 1_000_000, maxEnvBytes: 1 << 20, maxExports: 16 });
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
export function parseStorePath(p) {
  if (typeof p !== 'string' || p.length > 1024) return null;
  const m = STORE_PATH.exec(p);
  if (!m || m[2] === '.' || m[2] === '..' || m[2].includes('..')) return null;
  return { path: p, hash: m[1], name: m[2] };
}
const normalizePath = (p) => (typeof p === 'string' && /^[0-9a-df-np-sv-z]{32}-/.test(p) ? STORE + p : p);

/** Heuristic only: nixpkgs naming is pname-version where the version starts at the first "-<digit>". */
export function inferNameVersion(name, drvEnv) {
  if (drvEnv && typeof drvEnv.pname === 'string' && typeof drvEnv.version === 'string') return { pname: drvEnv.pname, version: drvEnv.version, authority: 'derivation-env' };
  if (drvEnv && typeof drvEnv.name === 'string') { const m = /^(.+?)-(\d.*)$/.exec(drvEnv.name); if (m) return { pname: m[1], version: m[2], authority: 'derivation-env' }; }
  const base = String(name || '').replace(/\.drv$/, '').replace(OUTPUT_SUFFIX, '');
  const m = /^(.+?)-(\d.*)$/.exec(base);
  return m ? { pname: m[1], version: m[2], authority: 'inferred-from-store-path' } : { pname: base || null, version: null, authority: 'inferred-from-store-path' };
}

export function detectSchema(parsed, text) {
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
export function importNixClosure(opts = {}) {
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
      const v = createVerify('sha256'); v.update(body);
      if (expected.publicKeyPem && v.verify(expected.publicKeyPem, Buffer.from(ex.signature, 'base64'))) { if (level !== 'none') level = 'signed'; }
      else add('invalid-signature', `${label}: the signature does not verify`);
    } catch (e) { add('invalid-signature', `${label}: signature check failed (${e.message})`); }
  } else if (expected.requireSigned) add('unsigned', `${label}: a signed export is required`);
  summary.level = level;
  return { summary };
}

/** Canonical body that a producer signs (exported so tests and producers agree on it). */
export function signedBody(ex) { return JSON.stringify({ schema: ex.schema, provenance: ex.provenance, data: ex.data !== undefined ? ex.data : null, text: ex.text !== undefined ? ex.text : null }); }
export { sha256 as _sha256 };
