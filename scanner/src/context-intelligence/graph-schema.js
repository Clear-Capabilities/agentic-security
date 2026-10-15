//
// Versioned, typed declaration/reference graph (symbol-graph/1).
//
// This is an ADAPTER-FED CONTRACT, not a second analyzer: symbols and calls come from the shared IR (or, additively,
// from imported compiler metadata). What this module adds is the part the context packer needs and the IR does not
// carry: stable ids, hash-verifiable source spans, per-edge provenance and conditionality, and an explicit,
// classified record of every call that could not be resolved. An unresolved call is data, never a leaf that looks
// like fully analysed code.
import { hashOf, sha256, sliceLines } from './canonical.js';
import { spanFor } from './spans.js';
import { buildImportMap, resolveViaImports } from './imports.js';

export const GRAPH_SCHEMA_VERSION = 'symbol-graph/1';

export const CONTINUATIONS = /^(?:next|done|cb|callback|resolve|reject|reply|fn_next)$/;

/** Unresolved-call reasons that could be hiding first-party code (and so block a `complete` claim). */
export const MATERIAL_REASONS = Object.freeze(new Set([
  'name-matches-first-party-declaration', 'dynamic-callee', 'call-through-local-or-parameter',
  'ambiguous-import-target', 'import-target-not-declared-in-module', 'unresolved-relative-import',
]));

export const EDGE_KINDS = Object.freeze(['call', 'dynamic_possible', 'external_unknown']);
export const RESOLVERS = Object.freeze(['source-static', 'compiler-enriched']);

/** Calls that cannot carry security meaning and are never first-party code. Classified, not dropped. */
const INERT_CALL = /^(?:console\.\w+|Math\.\w+|JSON\.\w+|Object\.(?:keys|values|entries|assign|freeze)|Array\.\w+|Number\.\w+|String\.\w+|Promise\.\w+|parseInt|parseFloat|isNaN|String|Number|Boolean|next|require|print|len|str|int|float|bool|list|dict|tuple|range|isinstance|enumerate|zip|sorted|min|max|sum|abs|round|type|super|pure|fromMaybe|maybe|fmap|show|fst|snd|not|\w+\.(?:json|send|status|sendStatus|end|render|redirect|setHeader|header|then|catch|finally|push|pop|shift|unshift|slice|splice|join|split|map|filter|reduce|forEach|includes|indexOf|toString|trim|replace|toLowerCase|toUpperCase|keys|values|entries|startswith|endswith|lower|upper|items|strip))$/;
const DYNAMIC_CALL = /(?:\[|\bapply\b|\bcall\b|\beval\b|\bFunction\b|__import__|getattr|dynamic|<dynamic>|\bsend\()/;

function lastSegment(name) {
  const s = String(name || '');
  const parts = s.split(/[.:]|::/);
  return parts[parts.length - 1] || s;
}

/** Largest CFG line of a function (0 when it has no CFG). Used only as a lower bound for a span end. */
function cfgMaxLine(fn) {
  let m = 0;
  const nodes = fn && fn.cfg && fn.cfg.nodes;
  if (nodes) for (const n of Object.values(nodes)) if (Number.isInteger(n.line) && n.line > m) m = n.line;
  return m;
}

/** Names a function binds locally: its parameters and every assignment target in its CFG. */
function localNamesOf(fn) {
  const set = new Set((fn && Array.isArray(fn.params) ? fn.params : []).map(String));
  const nodes = fn && fn.cfg && fn.cfg.nodes;
  if (nodes) for (const n of Object.values(nodes)) if (n.kind === 'assign' && typeof n.target === 'string') set.add(n.target);
  return set;
}

/**
 * Is `nodeId` on every modelled path from entry to exit? (CFG dominance, by removal.) Bounded: a CFG larger than
 * the cap reports 'unknown' rather than paying a quadratic cost on a generated file.
 */
export function conditionalityOf(fn, nodeId) {
  const cfg = fn && fn.cfg;
  if (!cfg || !cfg.nodes || !nodeId || !cfg.nodes[nodeId]) return 'unknown';
  if (Object.keys(cfg.nodes).length > 600) return 'unknown';
  if (nodeId === cfg.entry || nodeId === cfg.exit) return 'unconditional';
  const seen = new Set([cfg.entry]);
  const stack = [cfg.entry];
  while (stack.length) {
    const cur = stack.pop();
    for (const s of cfg.nodes[cur]?.succ || []) {
      if (s === nodeId || seen.has(s)) continue;
      seen.add(s);
      stack.push(s);
    }
  }
  return seen.has(cfg.exit) ? 'conditional' : 'unconditional';
}

/**
 * Build the graph from IR facts.
 *   fileContents  { path: normalised text }
 *   functions     Map<qid, fn>  (the IR call graph's `functions`)
 *   edges         [{caller, callee|null, calleeName, line, site}]
 *   provenance    'source-static' | 'compiler-enriched'
 */
export function buildSymbolGraph({ fileContents, functions, edges }) {
  const linesOf = new Map();
  const lines = (f) => {
    if (!linesOf.has(f)) linesOf.set(f, (fileContents[f] || '').split('\n'));
    return linesOf.get(f);
  };

  // Stable ids: file + declared name + ordinal among same-named declarations in that file, ordered by line. An edit
  // ABOVE a function therefore does not rename it; only adding a same-named sibling above it does.
  const rows = [...functions.values()]
    .filter(fn => fn && fn.file && fileContents[fn.file] !== undefined)
    .sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line - b.line) || (a.qid < b.qid ? -1 : 1));
  const ordinal = new Map();
  const idByQid = new Map();
  const symbols = [];
  for (const fn of rows) {
    const anon = /^(?:anon|anonymous|<anonymous>|lambda)\b/.test(fn.name || '') || !fn.name;
    const base = anon ? `${fn.file}::<anon>@${fn.line}` : `${fn.file}::${fn.name}`;
    const k = ordinal.get(base) || 0;
    ordinal.set(base, k + 1);
    const id = !anon && k === 0 ? base : (anon ? base : `${base}#${k + 1}`);
    idByQid.set(fn.qid, id);
    const span = spanFor(fn.file, lines(fn.file), fn.line, cfgMaxLine(fn));
    const text = sliceLines(fileContents[fn.file], span.startLine, span.endLine);
    symbols.push({
      id,
      name: fn.name || '<anon>',
      kind: fn.name === '<module>' ? 'module-top-level' : 'function',
      file: fn.file,
      startLine: span.startLine,
      endLine: span.endLine,
      declLine: fn.line,
      spanPrecision: span.precision,
      spanHash: sha256(text),
      params: Array.isArray(fn.params) ? fn.params.map(String) : [],
      resolver: 'source-static',
    });
  }
  symbols.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

  const byLastName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.name.startsWith('<')) continue;
    const key = lastSegment(s.name);
    if (!byLastName.has(key)) byLastName.set(key, []);
    byLastName.get(key).push(s.id);
  }

  const imports = buildImportMap(fileContents);
  const symbolsByFileName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    for (const key of new Set([s.name, lastSegment(s.name)])) {
      const k = `${s.file}\0${key}`;
      if (!symbolsByFileName.has(k)) symbolsByFileName.set(k, []);
      symbolsByFileName.get(k).push(s.id);
    }
  }

  const byFullName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    if (!byFullName.has(s.name)) byFullName.set(s.name, []);
    byFullName.get(s.name).push(s.id);
  }

  const graphEdges = [];
  for (const e of edges || []) {
    const from = idByQid.get(e.caller);
    if (!from) continue;
    const callerFn = functions.get(e.caller);
    const callerFile = callerFn.file;
    const base = {
      from,
      line: Number.isInteger(e.line) ? e.line : 0,
      calleeName: String(e.calleeName || ''),
      resolver: 'source-static',
      conditionality: conditionalityOf(callerFn, e.site),
      resolution: 'ir',
    };
    const to = e.callee ? idByQid.get(e.callee) : null;
    if (to) {
      graphEdges.push({ ...base, to, kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [] });
      continue;
    }
    const name = base.calleeName;
    const push = (kind, confidence, unresolvedReason, candidates = [], extra = {}) => graphEdges.push({ ...base, ...extra, to: null, kind, confidence, unresolvedReason, candidates });

    if (INERT_CALL.test(name) || CONTINUATIONS.test(name)) { push('external_unknown', 'high', 'inert-builtin'); continue; }

    // a fully qualified name (`Auth.requireUser`, `Class.method`) that matches exactly one declaration IS that declaration
    if (/[.:]/.test(name)) {
      const q = (byFullName.get(name) || []).filter(id => id !== from);
      if (q.length === 1) { graphEdges.push({ ...base, to: q[0], kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [], resolution: 'qualified-name' }); continue; }
    }

    const imp = resolveViaImports(imports, callerFile, name);
    if (imp && imp.kind === 'exact-import') {
      const ids = (symbolsByFileName.get(`${imp.targetFile}\0${imp.member}`) || []).filter(id => id !== from);
      if (ids.length === 1) { graphEdges.push({ ...base, to: ids[0], kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [], resolution: 'import' }); continue; }
      push('external_unknown', 'low', ids.length ? 'ambiguous-import-target' : 'import-target-not-declared-in-module', ids.slice(0, 5));
      continue;
    }
    if (imp && imp.kind === 'third-party') { push('external_unknown', 'high', 'third-party-import'); continue; }
    if (imp && imp.kind === 'unresolved-import') { push('external_unknown', 'low', 'unresolved-relative-import'); continue; }

    // a bare identifier that is a parameter or a local assignment is a call through a value: the target is data
    if (/^[A-Za-z_$][\w$]*$/.test(name) && !imp && localNamesOf(callerFn).has(name)) { push('dynamic_possible', 'low', 'call-through-local-or-parameter'); continue; }
    if (DYNAMIC_CALL.test(name) || name === '') { push('dynamic_possible', 'low', 'dynamic-callee'); continue; }

    const cand = (byLastName.get(lastSegment(name)) || []).filter(id => id !== from).slice(0, 5);
    if (cand.length) push('external_unknown', 'low', 'name-matches-first-party-declaration', cand);
    else push('external_unknown', 'high', 'external-boundary');
  }
  graphEdges.sort((a, b) =>
    (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));

  const snapshotHash = hashOf(Object.keys(fileContents).sort().map(f => [f, sha256(fileContents[f])]));
  const body = { schemaVersion: GRAPH_SCHEMA_VERSION, snapshotHash, symbols, edges: graphEdges, imports: imports.map(i => ({ file: i.file, local: i.local, source: i.source, member: i.member, kind: i.kind, target: i.target })) };
  return { ...body, hash: hashOf(body) };
}

/**
 * Structural validation. Returns a list of problems (empty = valid): dangling ids, spans outside the file, a span
 * hash that no longer matches the text, an edge that names a symbol that is not in the graph.
 */
export function validateGraph(graph, fileContents) {
  const problems = [];
  if (!graph || graph.schemaVersion !== GRAPH_SCHEMA_VERSION) return ['unsupported-schema-version'];
  const ids = new Set(graph.symbols.map(s => s.id));
  if (ids.size !== graph.symbols.length) problems.push('duplicate-symbol-id');
  for (const s of graph.symbols) {
    const text = fileContents[s.file];
    if (typeof text !== 'string') { problems.push(`missing-file:${s.file}`); continue; }
    const n = text.split('\n').length;
    if (!(s.startLine >= 1 && s.endLine >= s.startLine && s.endLine <= n)) { problems.push(`span-out-of-range:${s.id}`); continue; }
    if (sha256(sliceLines(text, s.startLine, s.endLine)) !== s.spanHash) problems.push(`stale-span-hash:${s.id}`);
  }
  for (const e of graph.edges) {
    if (!ids.has(e.from)) problems.push(`dangling-from:${e.from}`);
    if (e.to && !ids.has(e.to)) problems.push(`dangling-to:${e.to}`);
    for (const c of e.candidates || []) if (!ids.has(c)) problems.push(`dangling-candidate:${c}`);
  }
  const { hash, ...rest } = graph;
  if (hashOf(rest) !== hash) problems.push('graph-hash-mismatch');
  return problems;
}
