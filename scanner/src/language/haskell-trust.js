// Trust-boundary adjudication of Haskell taint findings.
//
// A taint finding says "data from a SOURCE reaches a SINK". Whether that is a vulnerability depends on whether the party that controls the
// source is a different party from the one the program runs for. This module reads the origins the taint engine recorded for each finding
// (`sourceRoots`, or the evidence chain) and decides, from code facts only, which side of that line they sit on:
//
//   attacker-reachable    a request, a socket, a header, a cookie, a remote response: the peer is not the operator
//   operator-controlled   command-line arguments and environment variables (the person who starts the process chooses them), and, in a
//                         command-line program, standard input and the files it is pointed at: no boundary is crossed. The finding
//                         is lowered to `info`, never dropped
//   api-contract          the value is a parameter of an exported function that nothing in the analysed code calls, and the function
//                         hands it WHOLE (or as the root it appends fixed text to) to a path or command operation: a thin wrapper.
//                         The caller chose what to read or run, and the wrapper has no fixed part to escape from. Lowered to `info`.
//                         Path operations joined this way since 0.195.9: `renderFile path = responseFile .. path` and
//                         `store path = readFile (cs path)` were 2 of the 29 flagged path sites on the real-code sets and no true
//                         positive had that shape; a parameter spliced UNDER a fixed directory (`"/srv/" ++ name`) is still kept,
//                         because the function chose the directory and lets the caller leave it
//   entry-parameter       a parameter of such a function used inside a larger value the function builds: its own construction, kept
//   data-input            standard input or a file's content in a service or a library: data the program processes, kept. When every
//                         origin is a read of a file at a literal path (`readFile "config/schema.dhall"`) the finding is lowered to `low`
//                         with the reason, since the location is the program's own; other file reads keep their severity
//   unattributed          the engine recorded no origin: kept
//
// A command-line program is one reached only from `main`s whose reachable modules import no server framework or socket library
// (`entryRole` in haskell-ir.js). The role is a fact about the call graph, not about a name or a path.
//
// Nothing here reads a comment, a name or a path: the inputs are the recorded origins, the lowered expression at the sink and the
// parameter annotations the IR derived from the signature.

import { findSites, identNames } from './haskell-guards.js';
import { testComponentIndex } from './haskell-manifests.js';
import { UPLOAD_CONTENT_LABEL } from './haskell-models.js';

export const TRUST_VERDICTS = Object.freeze(['attacker-reachable', 'operator-controlled', 'framework-controlled', 'api-contract', 'entry-parameter', 'data-input', 'unattributed']);

const OPERATOR = new Set(['cli', 'env']);
const EXTERNAL = new Set(['http-body', 'url-param', 'path-param', 'header', 'cookie', 'network', 'upload']);
const DATA = new Set(['stdin', 'file-read']);
const WEAK_PARAM_LABEL = /\(caller-controlled\)$/;
// CWE-918 is deliberately NOT a wrapper family: `fetch url = parseRequest url >>= httpNoBody` is pinned as a finding in
// test/haskell/haskell-generalization.test.js (a URL the caller chooses is the SSRF shape of the development sets). unseen-v4 labels
// that shape safe when the URL is configuration; that disagreement is recorded, not decided here. CWE-22 joined the set in 0.195.9
// (see the header): the synthetic development sets label `load name = readFile name` vulnerable, the real-code sets label every such
// site a false positive, and the real code won; a parameter under a fixed directory is still `entry-parameter`.
const WRAPPER_FAMILIES = new Set(['CWE-78', 'CWE-88', 'CWE-22']);
// `cs`/`convertString` (string-conversions) and `toS` (protolude) change the type of a text value and nothing else
const CONVERSIONS = /(?:^|\.)(?:pack|unpack|fromString|toString|show|encodeUtf8|decodeUtf8|toStrict|fromStrict|toText|unpackFS|fromText|cs|convertString|toS|toSL|toST)$/;
const PATH_JOIN = /(?:^|\.)(?:<\/>|combine|joinPath|<\.>)$/;
// list plumbing that only lays the parameters out as text (`unwords args`, `concatMap (' ':) args`): no fixed words are added
const LIST_LAYOUT = /(?:^|\.)(?:unwords|unlines|intercalate|concatMap|concat|map|fmap)$/;
const SPEC_CTORS = new Set(['System.Process.shell', 'System.Process.proc', 'System.Process.Typed.shell', 'System.Process.Typed.proc']);
const hasAlnum = (v) => /[A-Za-z0-9]/.test(String(v));

function rootsOf(f) {
  // A hop through a function's return that names no origin behind it (`interproc`, `param`) is not an origin.
  if (Array.isArray(f.sourceRoots) && f.sourceRoots.length) return f.sourceRoots.filter((r) => r && r.provenance !== 'interproc' && r.provenance !== 'param').map((r) => ({ label: r.label, provenance: r.provenance || null, ...(r.file ? { file: r.file } : {}), ...(Number.isInteger(r.line) ? { line: r.line } : {}) }));
  const out = [];
  for (const c of f.chain || []) {
    if (!c || !c.label || c.kind === 'sink') continue;
    if (c.provenance === 'interproc' || c.provenance === 'param') continue;
    out.push({ label: c.label, provenance: c.provenance || null });
  }
  if (!out.length && f.source && f.source.label && !/^(?:interproc-return:|parameter )/.test(f.source.label)) out.push({ label: f.source.label, provenance: f.sourceProvenance || null });
  return out;
}

const classOf = (r) => {
  if (r.provenance && OPERATOR.has(r.provenance)) return 'operator';
  if (r.provenance && EXTERNAL.has(r.provenance)) return 'external';
  if (r.provenance && DATA.has(r.provenance)) return 'data';
  if (WEAK_PARAM_LABEL.test(String(r.label || ''))) return 'weak-param';
  return 'other';
};

// The expression a sink was handed, with the conversions that only change its type (`unpack`, `fromString`, `show`) peeled off.
function peel(e, depth = 0) {
  while (e && e.kind === 'call' && depth++ < 8 && typeof e.callee === 'string' && CONVERSIONS.test(e.callee) && (e.args || []).length === 1) e = e.args[0];
  return e;
}

// Flatten a concatenation / path join into its operands, left to right.
function operandsOf(e, out = [], depth = 0, resolve = null) {
  e = peel(e);
  if (!e || depth > 12) { out.push(e); return out; }
  if (resolve && e.kind === 'ident') { const r = resolve(e); if (r && r !== e) return operandsOf(r, out, depth + 1, resolve); }
  if (e.kind === 'binary' && e.hs && e.hs.concat) { operandsOf(e.left, out, depth + 1, resolve); operandsOf(e.right, out, depth + 1, resolve); return out; }
  if (e.kind === 'binary' && (e.op === '</>' || e.op === '<>' || e.op === '++')) { operandsOf(e.left, out, depth + 1, resolve); operandsOf(e.right, out, depth + 1, resolve); return out; }
  if (e.kind === 'call' && typeof e.callee === 'string' && PATH_JOIN.test(e.callee) && (e.args || []).length === 2) { operandsOf(e.args[0], out, depth + 1, resolve); operandsOf(e.args[1], out, depth + 1, resolve); return out; }
  out.push(e);
  return out;
}

/**
 * Is the sink argument a value the function merely passes on? True when every non-literal operand is one of `params` (or list plumbing over
 * them) and either (a) nothing in the value is fixed text that names something (only separators), or (b) for a path, the parameter is the
 * LEFTMOST operand, so it chooses the whole location and the fixed tail is only a file name inside it.
 */
export function isPassThrough(arg, params, family, resolve = null) {
  // a path join whose FIRST component is the parameter (`base </> name`, `joinPath (base : pieces)`) hands the parameter on as the directory the
  // whole location lies in, whatever the tail is (a literal index name, a destructured list element, a request path the caller checked)
  const r0 = resolve ? resolve(arg) : arg;
  if (family === 'path' && r0 && r0.kind === 'call' && typeof r0.callee === 'string' && PATH_JOIN.test(r0.callee) && (r0.args || []).length) {
    const first = r0.args[0];
    const head = first && first.kind === 'array' && Array.isArray(first.elements) && first.elements.length ? first.elements[0] : first;
    if (head && head.kind === 'ident' && params.has(head.name)) return true;
  }
  const ops = operandsOf(arg, [], 0, resolve);
  if (!ops.length || ops.some((o) => !o)) return false;
  const dyn = ops.filter((o) => o.kind !== 'literal');
  if (!dyn.length) return false;
  // a dynamic operand is acceptable when it is made only of parameters and separators (a list laid out as text, a member of a parameter)
  const ok = (o, depth = 0) => {
    if (!o || depth > 10) return false;
    if (o.kind === 'literal') return !hasAlnum(o.value);
    if (o.kind === 'ident') return params.has(o.name);
    if (o.kind === 'member') return ok(o.object, depth + 1);
    if (o.kind === 'array') return o.elements.length > 0 && o.elements.every((x) => ok(x, depth + 1));
    if (o.kind === 'call' && typeof o.callee === 'string' && LIST_LAYOUT.test(o.callee)) return (o.args || []).length > 0 && o.args.every((x) => ok(x, depth + 1));
    // a path join whose FIRST component is the parameter (`joinPath (base : pieces)`, `base </> rest`): the parameter chooses the directory the
    // whole location lies in; the tail picks a file inside it and has its own origin (happstack's `fileServe' .. localPath`)
    if (family === 'path' && o.kind === 'call' && typeof o.callee === 'string' && PATH_JOIN.test(o.callee) && (o.args || []).length) {
      const first = o.args[0];
      const head = first && first.kind === 'array' && Array.isArray(first.elements) && first.elements.length ? first.elements[0] : first;
      return !!head && head.kind === 'ident' && params.has(head.name);
    }
    return false;
  };
  if (!dyn.every((o) => ok(o))) return false;
  const namedLiteral = ops.some((o) => o.kind === 'literal' && hasAlnum(o.value));
  if (!namedLiteral) return true;
  return family === 'path' && ops[0].kind === 'ident' && params.has(ops[0].name);
}

function weakParamsOf(fn) {
  const out = new Set();
  for (const a of fn.paramAnnotations || []) if (a && a.decorator === 'hs:caller-controlled' && a.name) out.add(a.name);
  return out;
}

// A local name bound exactly once (`let cmd = exe <> " " <> args`) stands for its definition when the sink argument is judged.
function localResolver(fn) {
  const defs = new Map();
  for (const n of Object.values(fn.cfg.nodes)) if (n.kind === 'assign' && typeof n.target === 'string' && n.source) defs.set(n.target, [...(defs.get(n.target) || []), n.source]);
  const params = new Set(Array.isArray(fn.params) ? fn.params : []);
  return (e) => (e && e.kind === 'ident' && !params.has(e.name) && defs.has(e.name) && defs.get(e.name).length === 1 ? defs.get(e.name)[0] : e);
}

const fnByQid = (perFile, qid) => {
  if (!qid) return null;
  const file = String(qid).split('::')[0];
  const ir = perFile && perFile[file];
  return ir ? ir.functions.find((x) => x.qid === qid) || null : null;
};

// The role the IR gave the function the finding was found in: `cli` (reached only from mains that import no server framework), `service`, or
// `library` (no main reaches it, or the walk could not).
function roleOf(f, perFile) {
  const fn = fnByQid(perFile, f._funcQid);
  return (fn && fn.hs && fn.hs.entryRole) || 'library';
}

// The function that holds the sink call, and the sink's argument expressions there. A finding found while analysing a CALLER (its `_funcQid`) is
// located at the callee's line; the sink function is the one in the finding's file that has the call at that line.
function locateSink(perFile, f) {
  const ir = perFile && perFile[f.file];
  if (!ir || !f.callee) return null;
  const direct = fnByQid(perFile, f._funcQid);
  const candidates = direct && direct.file === f.file ? [direct, ...ir.functions.filter((x) => x !== direct)] : ir.functions;
  for (const fn of candidates) {
    const sites = findSites(fn, f.callee, f.line);
    if (sites.length) return { fn, sites };
  }
  return null;
}

/**
 * Is this finding a thin wrapper's pass-through? `weakParams` are the caller-controlled parameters of the function the engine analysed. When the
 * sink sits in a callee, the callee must itself hand its own parameter on whole, and every call of it from the analysed function must pass
 * values built only from that function's caller-controlled parameters (one hop; a longer chain is not judged).
 */
function passThroughVerdict(perFile, f) {
  if (!WRAPPER_FAMILIES.has(f.cwe)) return null;
  const family = f.cwe === 'CWE-22' ? 'path' : 'cmd';
  const sink = locateSink(perFile, f);
  if (!sink) return null;
  const argIdx = Number.isInteger(f.argIndex) ? f.argIndex : 0;
  let args = sink.sites.map((s) => (s.call.args || [])[argIdx]).filter(Boolean);
  // A process is started from a SPEC value (`createProcess ((shell cmd) { cwd = d })`): what decides the verdict is what the spec constructor
  // was handed, so the constructor's own arguments are judged instead of the record update around it.
  const specArgs = [];
  const findSpecs = (e, d = 0) => {
    if (!e || typeof e !== 'object' || d > 20) return;
    if (e.kind === 'call' && typeof e.callee === 'string' && SPEC_CTORS.has(e.callee)) { for (const a of (e.args || []).slice(0, 2)) if (a) specArgs.push(a); return; }
    for (const k of ['left', 'right', 'object', 'value']) if (e[k] && typeof e[k] === 'object') findSpecs(e[k], d + 1);
    for (const k of ['args', 'elements', 'branches']) if (Array.isArray(e[k])) e[k].forEach((x) => findSpecs(x, d + 1));
    if (Array.isArray(e.props)) for (const p of e.props) findSpecs(p && p.value, d + 1);
  };
  for (const a of args) findSpecs(a);
  if (specArgs.length) args = specArgs;
  if (!args.length) return null;
  let analysed = fnByQid(perFile, f._funcQid);
  if (!analysed) return null;
  // The finding may have been collected under an intermediate or a recursive callee (happstack's `tryIndex`), whose own parameters carry no
  // weak label; the function that HOLDS the parameter is the one at the root of the evidence chain, found by its file and line.
  if (!weakParamsOf(analysed).size) {
    const root = Array.isArray(f.chain) && f.chain.length ? f.chain[0] : null;
    const rootFile = root && root.file ? root.file : f.file;
    const ir = perFile && perFile[rootFile];
    if (ir && root && Number.isInteger(root.line)) {
      const holder = ir.functions.filter((x) => Number.isInteger(x.line) && x.line <= root.line && weakParamsOf(x).size).sort((a, b) => b.line - a.line)[0];
      if (holder) analysed = holder;
    }
  }
  if (sink.fn.qid === analysed.qid) {
    const weak = weakParamsOf(analysed);
    if (!weak.size) return null;
    const own = new Set(Array.isArray(analysed.params) ? analysed.params : []);
    const res = localResolver(analysed);
    // (a name bound once in the function stands for its definition here too, so `req <- parseRequest url; httpLbs req m` reaches `url`; a record update is a union of base and update)
    return args.every((a) => isPassThrough(a, own, family, res)) && args.some((a) => { const seen = new Set(); const walkIds = (e, d = 0) => { if (!e || d > 12) return; if (e.kind === 'ident') { seen.add(e.name); const r = res(e); if (r && r !== e) walkIds(r, d + 1); } for (const k of ['left', 'right', 'object', 'value']) if (e[k] && typeof e[k] === 'object') walkIds(e[k], d + 1); for (const k of ['args', 'elements', 'branches']) if (Array.isArray(e[k])) e[k].forEach((x) => walkIds(x, d + 1)); }; let x = a; for (let i = 0; i < 4; i++) { const r = res(x); if (r === x) break; x = r; } walkIds(x); return [...seen].some((n) => weak.has(n)); }) ? 'direct' : null;
  }
  // the sink is in a callee
  const own = new Set(Array.isArray(sink.fn.params) ? sink.fn.params : []);
  // a local bound once in the callee stands for its definition (`let fp = joinPath (localPath : rqPaths rq)`, `let path = fp </> index`); the
  // names tracked back to the caller are the parameters the (resolved) argument hands on: for a path join with a parameter head, the head alone
  // (the tail picks a file inside the directory the parameter chose and has its own origin)
  const sinkRes = localResolver(sink.fn);
  // A pattern-bound parameter (`tryIndex (index:rest) fp`) is `$argN` in the IR with `fp` a local assigned from it: the aliases stand for the
  // parameter when the argument is judged, and are mapped back to the positional parameter when the caller's call is read.
  const paramAliases = (g) => {
    const map = new Map((Array.isArray(g.params) ? g.params : []).map((p) => [p, p]));
    const defs = new Map();
    for (const n of Object.values(g.cfg.nodes)) if (n.kind === 'assign' && typeof n.target === 'string' && n.source) defs.set(n.target, [...(defs.get(n.target) || []), n.source]);
    for (let grew = true; grew;) { grew = false; for (const [t, ds] of defs) if (!map.has(t) && ds.length === 1 && ds[0].kind === 'ident' && map.has(ds[0].name)) { map.set(t, map.get(ds[0].name)); grew = true; } }
    return map;
  };
  const sinkAliases = paramAliases(sink.fn);
  const trackedOf = (a, res, params) => {
    const r = res(a);
    if (r && r.kind === 'call' && typeof r.callee === 'string' && PATH_JOIN.test(r.callee) && (r.args || []).length && family === 'path') {
      const first = r.args[0];
      const head = first && first.kind === 'array' && Array.isArray(first.elements) && first.elements.length ? first.elements[0] : first;
      if (head && head.kind === 'ident' && params.has(head.name)) return [head.name];
    }
    return [...identNames(r)];
  };
  const ownAll = new Set(sinkAliases.keys());
  const ownVars = [...new Set(args.flatMap((a) => trackedOf(a, sinkRes, ownAll)))];
  if (!own.size || !ownVars.length || !ownVars.every((v) => ownAll.has(v)) || !args.every((a) => isPassThrough(a, ownAll, family, sinkRes))) return null;
  const weak = weakParamsOf(analysed);
  if (!weak.size) return null;
  // The handoff may run through intermediate project functions of the file (snap's `initJsonFileAuthManager fp` to `mkJsonAuthMgr fp` to
  // `loadUserCache fp`): each hop must pass the tracked parameters on whole, from the caller's own parameters, up to three hops.
  const fileFns = (perFile[f.file] && perFile[f.file].functions) || [];
  // `used` holds the callee's POSITIONAL parameter names; the caller's arguments are judged against the caller's parameters and their aliases
  const handsOn = (caller, callee, used, callerParams, depth) => {
    const calls = findCallsTo(caller, callee);
    if (!calls.length) return null;
    const res = localResolver(caller);
    const aliases = paramAliases(caller);
    const callerAll = new Set([...aliases.keys()].filter((k) => callerParams.has(aliases.get(k))));
    const reached = new Set();   // the caller's parameters (positional names) that feed the callee's tracked parameters
    for (const call of calls) {
      for (let i = 0; i < (call.args || []).length; i++) {
        const p = callee.params[i];
        if (!p || !used.has(p)) continue;
        const a = call.args[i];
        if (!a) return null;
        if (a.kind === 'literal') continue;
        if (!isPassThrough(a, callerAll, family, res)) return null;
        for (const nm of trackedOf(a, res, callerAll)) if (callerAll.has(nm)) reached.add(aliases.get(nm));
      }
    }
    return reached;
  };
  const usedParams = new Set(ownVars.map((v) => sinkAliases.get(v)).filter(Boolean));
  const direct = handsOn(analysed, sink.fn, usedParams, weak, 0);
  if (direct) return 'chain';
  // through intermediaries: a function of the file that calls the sink's function with its own parameters, and is itself handed to by the analysed one
  const search = (callee, used, depth) => {
    if (depth > 2) return false;
    for (const mid of fileFns) {
      if (mid === callee || mid === analysed || !Array.isArray(mid.params) || !mid.params.length) continue;
      const midParams = new Set(mid.params);
      const reached = handsOn(mid, callee, used, midParams, depth);
      if (!reached || !reached.size) continue;
      if (handsOn(analysed, mid, reached, weak, depth)) return true;
      if (search(mid, reached, depth + 1)) return true;
    }
    return false;
  };
  return search(sink.fn, usedParams, 0) ? 'chain' : null;
}

function findCallsTo(fn, target) {
  const out = [];
  const visit = (e, d) => {
    if (!e || typeof e !== 'object' || d > 50) return;
    if (e.kind === 'call' && e.callee === target.name) out.push(e);
    for (const k of ['left', 'right', 'object', 'value', 'callee']) if (e[k] && typeof e[k] === 'object') visit(e[k], d + 1);
    for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) for (const x of e[k]) visit(x, d + 1);
    if (Array.isArray(e.props)) for (const p of e.props) visit(p && p.value, d + 1);
  };
  for (const n of Object.values(fn.cfg.nodes)) {
    if (n.kind === 'call' && n.callee === target.name) out.push({ kind: 'call', callee: n.callee, args: n.args || [] });
    for (const k of ['source', 'value', 'cond']) if (n[k]) visit(n[k], 0);
    if (Array.isArray(n.args)) for (const a of n.args) visit(a, 0);
  }
  return out;
}

/**
 * Lower a finding to `info` and say why, without dropping it: the severity it would have had is kept (`originalSeverity`), a control records the
 * reason (`controls`), and `guardNote` is set (with `keepNote`, only when no earlier pass set one). Idempotent per `guard` (a finding is lowered once by each reason), and two
 * reasons compose: the second finds the severity already `info`, keeps the original severity the first recorded, and adds its own control.
 * Used by the trust-boundary pass (`_trustLowered`) and the reachability pass (`_reachLowered`).
 */
export function lowerFinding(f, { kind, reason, controlKind, guard, keepNote = false }) {
  if (!f || !guard || f[guard]) return false;
  f[guard] = true;
  f.originalSeverity = f.originalSeverity || f.severity;
  f.severity = 'info';
  f.controls = [...(f.controls || []), { kind: controlKind, evidenceKind: 'source' }];
  if (!keepNote || !f.guardNote) f.guardNote = { kind, reason };
  return true;
}

/**
 * Lowers to `info` every Haskell finding in a file the package manifests assign ONLY to a test-suite or benchmark component
 * (`testComponentIndex`): an hspec suite's in-process application echoes a request on purpose, and nothing a client reaches runs it. The
 * finding is kept (test code can hold a real secret, or an injection the author will copy into the program), with `originalSeverity`,
 * a `test-component` control and a `guardNote` naming the stanza and the manifest, and `componentScope` on the finding. Decided from the
 * manifest's `hs-source-dirs`, never from a path name. Applies to every parser (a rule finding in test code is test code too). Idempotent.
 */
export function applyTestComponentScope(findings, manifests) {
  const stats = { lowered: 0, inTestComponent: 0, reason: null };
  if (!Array.isArray(findings) || !findings.length) return stats;
  const idx = testComponentIndex(manifests || {});
  stats.reason = idx.reason;
  if (!idx.dirs.length) return stats;
  for (const f of findings) {
    if (!f || !/\.(?:l?hs|hsc)$/i.test(String(f.file || ''))) continue;
    const owner = idx.ownerOf(f.file);
    if (!owner) continue;
    stats.inTestComponent++;
    if (!f.componentScope) f.componentScope = { kind: owner.kind, component: owner.component, manifest: owner.manifest, dir: owner.dir };
    if (f.severity === 'info') continue;
    const reason = `the file is under '${owner.dir}', which ${owner.manifest} lists as hs-source-dirs of the ${owner.kind} '${owner.component}' and of no library or executable: test code exercises the program, it is not the program a request reaches`;
    if (lowerFinding(f, { kind: 'test-component', reason, controlKind: 'test-component', guard: '_testScopeLowered' })) stats.lowered++;
  }
  return stats;
}

/** The classes of origin a finding's recorded roots fall in (`operator`, `external`, `data`, `weak-param`, `other`), and the roots themselves. */
export function originClasses(f) {
  const roots = rootsOf(f);
  return { roots, classes: new Set(roots.map(classOf)) };
}

const FILE_READ_CALL = /(?:^|\.)(?:readFile|readFile'|readFileUtf8|readBinaryFile|decodeFileThrow|decodeFileEither|decodeFile)$/;
const isFixedPath = (e) => !!e && e.kind === 'literal' && typeof e.value === 'string' && e.value.length > 0 && !/^[a-z][a-z0-9+.-]*:\/\//i.test(e.value);

/** A top-level definition with no parameters whose whole body is one literal (`schemaFilePath = "Application/Schema.sql"`): that literal. */
function constantLiteral(fn) {
  if (!fn || (Array.isArray(fn.params) && fn.params.length) || !fn.cfg || !fn.cfg.nodes) return null;
  const nodes = Object.values(fn.cfg.nodes).filter((n) => n && n.kind !== 'entry' && n.kind !== 'exit');
  if (nodes.length !== 1 || nodes[0].kind !== 'return' || !isFixedPath(nodes[0].value)) return null;
  return nodes[0].value;
}

/**
 * Is this path expression fixed by the program text? A string literal; a name bound once in the function to one (`let fp = ..`); a reference to a
 * project constant that is one (`Paths.schemaFilePath`, followed through the IR's `functionRef`); any of those under a type conversion
 * (`decodeUtf`, `cs`, `pack`). IHP's schema compiler reads `Application/Schema.sql` through a constant two modules away. Anything else (a parameter,
 * a computed value) is not judged.
 */
function fixedPathExpr(e, fn, perFile, depth = 0) {
  if (!e || depth > 6) return false;
  if (isFixedPath(e)) return true;
  if (e.kind === 'call' && typeof e.callee === 'string' && (CONVERSIONS.test(e.callee) || /(?:^|\.)decodeUtf$/.test(e.callee)) && (e.args || []).length === 1) return fixedPathExpr(e.args[0], fn, perFile, depth + 1);
  if (e.kind !== 'ident') return false;
  if (e.hs && e.hs.functionRef) return isFixedPath(constantLiteral(fnByQid(perFile, e.hs.functionRef)));
  const r = fn ? localResolver(fn)(e) : e;
  return r !== e && fixedPathExpr(r, fn, perFile, depth + 1);
}

/**
 * Is every file-read origin of this finding a read of a file whose location the program text fixes (`readFile "config/schema.dhall"`)? Judged from
 * the call at the origin's recorded line: its first argument must be a string literal. A path held in a name, built from parts or taken from
 * a parameter is not judged (the read stays as reported). Content at a fixed project location is the program's own data, not something a
 * request chose; it can still be written by another part of the program, so the finding is lowered to `low`, never to `info`.
 */
function fixedFileReads(perFile, f, roots) {
  const reads = roots.filter((r) => r.provenance === 'file-read');
  // every root is a file read, or the operator's own argument or environment beside one (the schema compiler's `IHP_RELATION_SUPPORT`)
  if (!reads.length || roots.some((r) => r.provenance !== 'file-read' && classOf(r) !== 'operator')) return false;
  const chain = (f.chain || []).filter((c) => c && c.provenance === 'file-read');
  const where = reads.map((r, i) => ({ file: r.file || (chain[i] && chain[i].file) || (f.source && f.source.file), line: Number.isInteger(r.line) ? r.line : (chain[i] && chain[i].line) || (f.source && f.source.line) }));
  return where.every((w) => {
    const ir = perFile && perFile[w.file];
    if (!ir || !Number.isInteger(w.line)) return false;
    let seen = false;
    for (const fn of ir.functions) for (const s of findSites(fn, FILE_READ_CALL, w.line)) { seen = true; if (!fixedPathExpr((s.call.args || [])[0], fn, perFile)) return false; }
    return seen;
  });
}

/**
 * Stamps `trustBoundary` on every Haskell IR-TAINT finding and lowers to `info` the verdicts that name no boundary crossed
 * (`operator-controlled`, `api-contract`). Mutates the findings; returns counts.
 */
export function applyTrustBoundary(findings, perFile) {
  const stats = { attackerReachable: 0, operatorControlled: 0, frameworkControlled: 0, apiContract: 0, entryParameter: 0, dataInput: 0, unattributed: 0 };
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT' || !/\.(?:l?hs|hsc)$/i.test(String(f.file || ''))) continue;
    const roots = rootsOf(f);
    const classes = new Set(roots.map(classOf));
    const role = roleOf(f, perFile);
    let verdict;
    let reason;
    let inferred = false;
    let lowToLow = false;
    if (f.cwe === 'CWE-22' && roots.length && roots.every((r) => r.label === UPLOAD_CONTENT_LABEL)) {
      // wai-extra: `fileContent` is a FilePath only under `tempFileBackEnd`, where the framework wrote the part to a temporary file of its own
      // choosing and the application reads it back; the client chose the bytes, never the path. (`fileName` is the client's text and stays a source.)
      verdict = 'framework-controlled';
      reason = 'the path is the content field of an uploaded part, which is a FilePath only under tempFileBackEnd: the framework chose the temporary file, the client chose only its bytes';
    } else if (classes.has('external')) { verdict = 'attacker-reachable'; reason = 'a request, socket, header, cookie or remote response supplies the value'; }
    else if (roots.length && [...classes].every((c) => c === 'operator')) {
      verdict = 'operator-controlled';
      reason = 'only command-line arguments or environment variables supply the value; whoever starts the program chooses them, so no trust boundary is crossed';
    } else if (roots.length && role === 'cli' && roots.every((r) => r.provenance === 'file-read' || OPERATOR.has(r.provenance) || (f.cwe === 'CWE-22' && r.provenance === 'stdin'))) {
      // Standard input counts here for a PATH operation only: a command-line program reading a file name from its own standard input
      // is the person at the keyboard naming a file (14 of the 29 flagged path sites on the real-code sets, every one a false positive).
      // A command built from standard input stays reported (`getLine >>= callCommand`, pinned in test/haskell/haskell-trust-boundary.test.js).
      verdict = 'operator-controlled';
      reason = f.cwe === 'CWE-22' && roots.some((r) => r.provenance === 'stdin')
        ? 'the function belongs to a command-line program (reached from a main that imports no server framework) and the file it works on is named by the person running it: on its standard input, in files it was pointed at, or in its arguments and environment'
        : 'the function belongs to a command-line program (reached from a main that imports no server framework) and the value comes from files the person running it pointed the program at, or from its arguments and environment; standard input is covered by this rule only for a path operation';
    } else if (classes.has('data')) {
      verdict = 'data-input'; reason = 'standard input or file content supplies the value';
      if (!classes.has('weak-param') && !classes.has('other') && fixedFileReads(perFile, f, roots)) {
        reason = 'the value is the content of a file at a location the program text fixes (a literal path, or a project constant holding one), not a request or a caller-supplied name; another part of the program could still write that file, so the finding is lowered to low and kept';
        lowToLow = true;
      }
    }
    else if (classes.has('weak-param')) {
      verdict = 'entry-parameter';
      reason = 'a parameter of an exported function that nothing in the analysed code calls';
      const pt = passThroughVerdict(perFile, f);
      if (pt) { verdict = 'api-contract'; reason = 'the function hands its parameter on whole (or as the root of a fixed tail) to a path or command operation: a thin wrapper, whose caller chose what to read or run'; }
    } else if (!roots.length && role === 'cli') {
      // No origin was recorded. Every external origin the model knows (a request, a socket, a remote response) is recorded when it is read, so
      // an empty record in a command-line program means the value came from the operator's side: its arguments, environment, files or
      // configuration reached the sink through a path the engine could not attribute. Stated as an inference on the finding.
      verdict = 'operator-controlled';
      reason = 'no origin was recorded for the tainted value and the function belongs to a command-line program; no request, socket or remote-response read feeds it (inferred, not proven)';
      inferred = true;
    } else { verdict = 'unattributed'; reason = roots.length ? 'the recorded origins are not classified' : 'the engine recorded no origin for the value'; }

    f.trustBoundary = { verdict, reason, role, ...(inferred ? { inferred: true } : {}), roots: roots.slice(0, 5) };
    const key = verdict.replace(/-(\w)/g, (_, c) => c.toUpperCase());
    stats[key] = (stats[key] || 0) + 1;
    if (lowToLow && f.severity !== 'info' && f.severity !== 'low' && !f._trustLowered) {
      f._trustLowered = true;
      f.originalSeverity = f.originalSeverity || f.severity;
      f.severity = 'low';
      f.controls = [...(f.controls || []), { kind: 'fixed-file-source', evidenceKind: 'source' }];
      f.guardNote = { kind: 'data-input', reason };
    }
    if (verdict === 'operator-controlled' || verdict === 'api-contract' || verdict === 'framework-controlled') {
      const controlKind = verdict === 'operator-controlled' ? 'operator-controlled-input' : verdict === 'framework-controlled' ? 'framework-temp-file' : 'api-contract-wrapper';
      lowerFinding(f, { kind: verdict, reason, controlKind, guard: '_trustLowered' });
    }
  }
  return stats;
}
