// SemanticGraph v1: a typed, versioned, additive view over the Layer-1 IR (E2-01).
//
// WHY. The IR (`buildProjectIR`) is a bag of per-function records consumed by the taint engine. It has no stable identifiers, no shared
// entity types and no serialization contract, so every analysis that needs "the call at this place" or "where did this value come from"
// re-derives it with its own conventions, and nothing can be compared across runs. This module names the entities once, gives each a
// STABLE id, and fixes a versioned wire format.
//
// ADDITIVE. Building the graph reads the IR and never modifies it; it is not wired into findings, `chain[]` or last-scan.json. Existing
// output is unchanged by construction (a test pins that). A consumer opts in by calling `buildSemanticGraph`.
//
// HONEST. An entity type the IR cannot yet supply (Sanitizer, Guard, ServiceBoundary, StorageEdge) is declared in the schema, emitted as an
// empty list, and reported `schema-only` in `coverage` with the reason. A location the IR does not carry (column) is `null` and the entity
// says `locationPrecision: 'line'`. Nothing is guessed to fill a field.
//
// STABLE IDS. An id is the first 16 hex of SHA-256 over the entity's kind and its identity fields, which never include a line number: adding
// a blank line above a function does not change any id in it. Ties between otherwise identical entities (two `exec(x)` in one function) are
// broken by their order of appearance in that function.
import { createHash } from 'node:crypto';
import { analysisLimits } from '../dataflow/analysis-limits.js';

export const SEMANTIC_GRAPH_SCHEMA = 'agentic-security/semantic-graph';
export const SEMANTIC_GRAPH_VERSION = '1.0.0';
export const SUPPORTED_MAJOR = 1;

export const ENTITY_LISTS = Object.freeze(['symbols', 'callSites', 'allocations', 'fieldAccesses', 'valueOrigins', 'serviceBoundaries', 'storageEdges', 'sanitizers', 'guards']);
export const CONFIDENCE_TIERS = Object.freeze(['observed', 'inferred', 'unresolved']);
const SYMBOL_KINDS = Object.freeze(['module', 'function', 'class', 'variable', 'parameter']);
const ORIGIN_KINDS = Object.freeze(['parameter', 'call-result', 'literal', 'member', 'concat', 'object', 'array', 'function', 'identifier', 'unknown']);

const ID_PREFIX = Object.freeze({ symbols: 'sym', callSites: 'call', allocations: 'alloc', fieldAccesses: 'field', valueOrigins: 'orig', serviceBoundaries: 'svc', storageEdges: 'store', sanitizers: 'san', guards: 'guard' });

const h16 = (parts) => createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 16);
const stripLine = (qid) => String(qid).replace(/@\d+$/, '');

// ---- canonical serialization ------------------------------------------------------------------------------------------------

function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}
export function serializeGraph(graph) {
  const g = { ...graph };
  for (const k of ENTITY_LISTS) g[k] = [...(graph[k] || [])].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return JSON.stringify(canon(g));
}

// ---- validation -------------------------------------------------------------------------------------------------------------

/** @returns {{ok:boolean, errors:{code:string,path:string,message:string}[]}} Never throws on hostile input. */
export function validateGraph(g) {
  const errors = [];
  const err = (code, path, message) => errors.push({ code, path, message });
  if (!g || typeof g !== 'object' || Array.isArray(g)) return { ok: false, errors: [{ code: 'NOT_AN_OBJECT', path: '', message: 'a graph is an object' }] };
  if (g.schema !== SEMANTIC_GRAPH_SCHEMA) { err('SCHEMA_MISMATCH', 'schema', `expected ${SEMANTIC_GRAPH_SCHEMA}`); return { ok: false, errors }; }
  const m = typeof g.schemaVersion === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(g.schemaVersion) : null;
  if (!m) { err('BAD_VERSION', 'schemaVersion', 'must be a semantic version'); return { ok: false, errors }; }
  if (Number(m[1]) !== SUPPORTED_MAJOR) { err('UNSUPPORTED_MAJOR', 'schemaVersion', `major ${m[1]} is not supported (supported: ${SUPPORTED_MAJOR}); migrate it first`); return { ok: false, errors }; }
  const ids = new Map();
  for (const list of ENTITY_LISTS) {
    if (!Array.isArray(g[list])) { err('MISSING_FIELD', list, 'must be a list (empty when none)'); continue; }
    g[list].forEach((e, i) => {
      const p = `${list}[${i}]`;
      if (!e || typeof e !== 'object' || Array.isArray(e)) { err('BAD_TYPE', p, 'must be an object'); return; }
      if (typeof e.id !== 'string' || !new RegExp(`^${ID_PREFIX[list]}:[0-9a-f]{16}$`).test(e.id)) err('BAD_ID', `${p}.id`, `must look like ${ID_PREFIX[list]}:<16 hex>`);
      else if (ids.has(e.id)) err('DUPLICATE_ID', `${p}.id`, `duplicate id ${e.id}`); else ids.set(e.id, list);
      if (typeof e.file !== 'string' || !e.file || e.file.startsWith('/') || e.file.split('/').includes('..')) err('BAD_TYPE', `${p}.file`, 'must be a repository-relative path');
      if (!(Number.isInteger(e.line) && e.line >= 0)) err('BAD_TYPE', `${p}.line`, 'line must be a non-negative integer');
      if (!(e.column === null || (Number.isInteger(e.column) && e.column >= 0))) err('BAD_TYPE', `${p}.column`, 'column must be null or a non-negative integer');
      if (e.column === null && e.locationPrecision !== 'line') err('RULE_VIOLATION', `${p}.locationPrecision`, "a null column requires locationPrecision 'line'");
      const c = e.confidence;
      if (!c || typeof c !== 'object' || !CONFIDENCE_TIERS.includes(c.tier) || typeof c.basis !== 'string' || !c.basis) err('BAD_TYPE', `${p}.confidence`, 'needs { tier, basis }');
    });
  }
  if (errors.length) return { ok: false, errors };
  const need = (e, p, field, list) => { if (e[field] !== null && e[field] !== undefined && ids.get(e[field]) !== list) err('DANGLING_REF', `${p}.${field}`, `${e[field]} is not a ${list} id`); };
  g.symbols.forEach((e, i) => { if (!SYMBOL_KINDS.includes(e.kind)) err('UNKNOWN_ENUM', `symbols[${i}].kind`, `unknown symbol kind ${e.kind}`); need(e, `symbols[${i}]`, 'parent', 'symbols'); });
  g.callSites.forEach((e, i) => { need(e, `callSites[${i}]`, 'caller', 'symbols'); need(e, `callSites[${i}]`, 'callee', 'symbols'); if (e.callee && e.resolution !== 'resolved') err('RULE_VIOLATION', `callSites[${i}].resolution`, 'a call with a callee must be resolved'); if (!e.callee && e.resolution === 'resolved') err('RULE_VIOLATION', `callSites[${i}].resolution`, 'a resolved call needs a callee'); (e.args || []).forEach((a, j) => need(a, `callSites[${i}].args[${j}]`, 'origin', 'valueOrigins')); });
  g.valueOrigins.forEach((e, i) => { if (!ORIGIN_KINDS.includes(e.kind)) err('UNKNOWN_ENUM', `valueOrigins[${i}].kind`, `unknown origin kind ${e.kind}`); need(e, `valueOrigins[${i}]`, 'symbol', 'symbols'); });
  g.fieldAccesses.forEach((e, i) => { need(e, `fieldAccesses[${i}]`, 'symbol', 'symbols'); if (!['read', 'write'].includes(e.mode)) err('UNKNOWN_ENUM', `fieldAccesses[${i}].mode`, 'mode must be read or write'); });
  g.allocations.forEach((e, i) => need(e, `allocations[${i}]`, 'symbol', 'symbols'));
  if (!g.coverage || typeof g.coverage !== 'object') err('MISSING_FIELD', 'coverage', 'coverage is required');
  else for (const list of ENTITY_LISTS) { const c = g.coverage[list]; if (!c || !['populated', 'schema-only'].includes(c.state) || !c.reason) err('BAD_TYPE', `coverage.${list}`, 'needs { state, reason }'); else if (c.state === 'schema-only' && g[list].length) err('RULE_VIOLATION', `coverage.${list}`, 'schema-only but not empty'); else if (c.state === 'populated' && !g[list].length) err('RULE_VIOLATION', `coverage.${list}`, 'populated but empty'); }
  return { ok: errors.length === 0, errors };
}

/** Parse and validate a serialized graph. Returns { ok, graph?, errors }. */
export function parseGraph(text) {
  let g; try { g = JSON.parse(text); } catch (e) { return { ok: false, errors: [{ code: 'BAD_JSON', path: '', message: e.message }] }; }
  const v = validateGraph(g);
  return v.ok ? { ok: true, graph: g, errors: [] } : { ok: false, errors: v.errors };
}

/** Bring an older-minor graph to this version. A different major is refused: there is no silent best-effort. */
export function migrateGraph(g) {
  const m = typeof g?.schemaVersion === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(g.schemaVersion) : null;
  if (!m || g.schema !== SEMANTIC_GRAPH_SCHEMA) return { ok: false, reason: 'not a semantic graph' };
  if (Number(m[1]) !== SUPPORTED_MAJOR) return { ok: false, reason: `major ${m[1]} has no migration path to ${SEMANTIC_GRAPH_VERSION}` };
  return { ok: true, graph: { ...g, schemaVersion: SEMANTIC_GRAPH_VERSION }, migrated: g.schemaVersion !== SEMANTIC_GRAPH_VERSION };
}

// ---- builder ----------------------------------------------------------------------------------------------------------------

const exprText = (e) => {
  if (!e || typeof e !== 'object') return '';
  switch (e.kind) {
    case 'ident': return e.name;
    case 'member': return `${exprText(e.object)}.${e.prop ?? '[]'}`;
    case 'call': return `${exprText(e.callee)}(...)`;
    case 'literal': return JSON.stringify(e.value);
    default: return `<${e.kind || 'unknown'}>`;
  }
};
const originKindOf = (e, params) => {
  if (!e) return 'unknown';
  if (e.kind === 'ident') return params.includes(e.name) ? 'parameter' : 'identifier';
  if (e.kind === 'call') return 'call-result';
  if (e.kind === 'literal') return 'literal';
  if (e.kind === 'member') return 'member';
  if (e.kind === 'binary' || e.kind === 'tpl') return 'concat';
  if (e.kind === 'object') return 'object';
  if (e.kind === 'array') return 'array';
  if (e.kind === 'function-value') return 'function';
  return 'unknown';
};
const loc = (file, line) => ({ file, line: Number.isInteger(line) ? line : 0, column: null, locationPrecision: 'line' });
const OBSERVED = { tier: 'observed', basis: 'read directly from the Layer-1 IR' };
const UNRESOLVED = { tier: 'unresolved', basis: 'the IR holds no resolved target for this call' };

function memberChain(e) {
  const path = [];
  let cur = e;
  while (cur && cur.kind === 'member') { path.unshift(cur.prop ?? '[]'); cur = cur.object; }
  return cur && cur.kind === 'ident' ? { base: cur.name, path } : null;
}
function walkExprs(e, visit) {
  if (!e || typeof e !== 'object') return;
  visit(e);
  for (const k of ['object', 'callee', 'left', 'right', 'test', 'cons', 'alt']) if (e[k]) walkExprs(e[k], visit);
  for (const k of ['args', 'parts', 'elements', 'values']) if (Array.isArray(e[k])) e[k].forEach((x) => walkExprs(x, visit));
  if (Array.isArray(e.props)) e.props.forEach((p) => walkExprs(p?.value ?? p, visit));
}

/**
 * @param {{perFile:object, callGraph?:object}} projectIR the object `buildProjectIR` returns
 * @param {{engineVersion?:string}} [meta]
 */
export function buildSemanticGraph(projectIR, meta = {}) {
  const g = Object.fromEntries(ENTITY_LISTS.map((k) => [k, []]));
  const ordinal = new Map();
  const next = (key) => { const n = ordinal.get(key) ?? 0; ordinal.set(key, n + 1); return n; };
  const symByQid = new Map();
  const files = Object.keys(projectIR?.perFile || {}).sort();

  // pass 1: symbols
  for (const file of files) {
    const pf = projectIR.perFile[file];
    for (const fn of pf.functions || []) {
      const isModule = fn.name === '<module>';
      const key = `${file}|${stripLine(fn.qid)}`;
      const id = `sym:${h16(['symbol', file, stripLine(fn.qid), next(`sym|${key}`)])}`;
      symByQid.set(fn.qid, id);
      g.symbols.push({ id, kind: isModule ? 'module' : 'function', name: fn.name, qid: stripLine(fn.qid), parent: null, params: [...(fn.params || [])], ...loc(file, fn.line), confidence: OBSERVED });
    }
  }
  // function-by-name index for DIRECT same-file resolution only; anything else stays unresolved (cross-file resolution is E2-02)
  const byFileName = new Map();
  for (const file of files) for (const fn of projectIR.perFile[file].functions || []) if (fn.name !== '<module>') { const k = `${file}|${fn.name}`; byFileName.set(k, byFileName.has(k) ? null : symByQid.get(fn.qid)); }

  // pass 2: call sites, origins, field accesses, allocations
  for (const file of files) {
    for (const fn of projectIR.perFile[file].functions || []) {
      const symId = symByQid.get(fn.qid);
      const params = fn.params || [];
      const originFor = (expr, variable, line) => {
        const kind = originKindOf(expr, params);
        const o = { id: `orig:${h16(['origin', symId, variable, kind, exprText(expr), next(`orig|${symId}|${variable}|${kind}|${exprText(expr)}`)])}`, symbol: symId, variable, kind, text: exprText(expr), ...loc(file, line), confidence: kind === 'unknown' ? { tier: 'unresolved', basis: 'the IR could not model this expression' } : OBSERVED };
        g.valueOrigins.push(o);
        return o.id;
      };
      const field = (expr, mode, line) => {
        const mc = memberChain(expr);
        if (!mc || !mc.path.length) return;
        g.fieldAccesses.push({ id: `field:${h16(['field', symId, mc.base, mc.path, mode, next(`field|${symId}|${mc.base}|${mc.path.join('.')}|${mode}`)])}`, symbol: symId, base: mc.base, path: mc.path, mode, ...loc(file, line), confidence: OBSERVED });
      };
      const alloc = (expr, line) => {
        const kind = expr.kind === 'object' ? 'object' : expr.kind === 'array' ? 'array' : expr.kind === 'function-value' ? 'function' : null;
        if (!kind) return;
        g.allocations.push({ id: `alloc:${h16(['alloc', symId, kind, next(`alloc|${symId}|${kind}`)])}`, symbol: symId, kind, ...loc(file, line), confidence: OBSERVED });
      };
      for (const c of fn.calls || []) {
        const calleeText = c.callee;
        const direct = byFileName.get(`${file}|${calleeText}`) || null;
        const args = (c.args || []).map((a, index) => { walkExprs(a, (x) => { if (x.kind === 'member') field(x, 'read', c.line); alloc(x, c.line); }); return { index, origin: originFor(a, `arg:${calleeText}:${index}`, c.line) }; });
        g.callSites.push({ id: `call:${h16(['call', symId, calleeText, next(`call|${symId}|${calleeText}`)])}`, caller: symId, calleeText, callee: direct, resolution: direct ? 'resolved' : 'unresolved', args, ...loc(file, c.line), confidence: direct ? { tier: 'inferred', basis: 'a function of this name exists in the same file' } : UNRESOLVED });
      }
      const callFromExpr = (x, line) => {
        const calleeText = exprText(x.callee).replace(/\(\.\.\.\)$/, '');
        const direct = x.callee?.kind === 'ident' ? (byFileName.get(`${file}|${calleeText}`) || null) : null;
        const args = (x.args || []).map((a, index) => ({ index, origin: originFor(a, `arg:${calleeText}:${index}`, line) }));
        g.callSites.push({ id: `call:${h16(['call', symId, calleeText, next(`call|${symId}|${calleeText}`)])}`, caller: symId, calleeText, callee: direct, resolution: direct ? 'resolved' : 'unresolved', args, ...loc(file, line), confidence: direct ? { tier: 'inferred', basis: 'a function of this name exists in the same file' } : UNRESOLVED });
      };
      // The CFG is the one structure every language's IR shares (`writes` exists for JavaScript only): assignment nodes carry { target, source, line }.
      const assigns = Object.values(fn.cfg?.nodes || {}).filter((n) => n.kind === 'assign' && n.target).sort((x, y) => (x.line ?? 0) - (y.line ?? 0) || String(x.id ?? '').localeCompare(String(y.id ?? '')));
      for (const d of assigns) {
        const variable = String(d.target);
        const line = d.line ?? fn.line;
        originFor(d.source, variable, line);
        // calls that appear INSIDE an assignment source (`const cmd = h.build(x)`) are not in fn.calls; they are call sites all the same
        walkExprs(d.source, (x) => { if (x.kind === 'member') field(x, 'read', line); alloc(x, line); if (x.kind === 'call' && x.callee) callFromExpr(x, line); });
        const mc = variable.includes('.') ? variable.split('.') : null;
        if (mc) g.fieldAccesses.push({ id: `field:${h16(['field', symId, mc[0], mc.slice(1), 'write', next(`field|${symId}|${mc[0]}|${mc.slice(1).join('.')}|write`)])}`, symbol: symId, base: mc[0], path: mc.slice(1), mode: 'write', ...loc(file, line), confidence: OBSERVED });
      }
    }
  }

  // E2-07: service relationships are opt-in. A caller that ran dataflow/service-edges.js passes the result as `meta.serviceEdges`; HTTP and
  // messaging relationships become `serviceBoundaries`, persistence relationships become `storageEdges`, and relationships with no counterpart
  // are kept as boundaries with `to: null` and unresolved confidence. Without it both lists stay schema-only, as before.
  const se = meta.serviceEdges && meta.serviceEdges.optedIn ? meta.serviceEdges : null;
  if (se) {
    const tier = (e) => (e === 'observed' ? 'observed' : e === 'inferred' ? 'inferred' : 'unresolved');
    for (const e of se.edges) {
      const list = e.kind === 'persistence' ? g.storageEdges : g.serviceBoundaries;
      list.push({ id: `${e.kind === 'persistence' ? 'store' : 'svc'}:${e.id.slice('svcedge:'.length)}`, kind: e.kind, from: e.from, to: e.to, via: e.via, ...loc(e.from.file, e.from.line), evidence: e.evidence, confidence: { tier: tier(e.evidence), basis: e.basis } });
    }
    for (const u of se.unknown) g.serviceBoundaries.push({ id: `svc:${h16(['unknown', u.service, u.file, u.kind, u.reason])}`, kind: u.kind, from: { service: u.service, file: u.file, line: u.line }, to: null, via: null, ...loc(u.file, u.line), evidence: 'unknown', confidence: { tier: 'unresolved', basis: u.reason } });
  }
  const SCHEMA_ONLY = {
    ...(se ? {} : { serviceBoundaries: 'opt-in: pass meta.serviceEdges (dataflow/service-edges.js) with two or more declared services; the IR itself carries no service-boundary facts', storageEdges: 'opt-in: pass meta.serviceEdges (dataflow/service-edges.js); the IR itself carries no persistence facts' }),
    sanitizers: 'sanitizer decisions are made by the dataflow layer (sanitizer-gate.js), not recorded in the IR; they are folded in by E2-08',
    guards: 'guard dominance is computed by dataflow/guard-dominance.js, not recorded in the IR; it is folded in by E2-08',
  };
  const REASON_POP = { serviceBoundaries: 'HTTP and messaging relationships between declared services, and the ones with no counterpart', storageEdges: 'tables one declared service writes and another reads', symbols: 'one per IR function and per file top level', callSites: 'every call recorded in an IR function, plus calls nested inside assignment sources', allocations: 'object, array and function-valued expressions in call arguments and assignments', fieldAccesses: 'member reads in arguments and assignments, and dotted writes', valueOrigins: 'every call argument and every assignment node in the CFG of a function' };
  const coverage = {};
  for (const k of ENTITY_LISTS) coverage[k] = SCHEMA_ONLY[k] ? { state: 'schema-only', reason: SCHEMA_ONLY[k] } : g[k].length ? { state: 'populated', reason: REASON_POP[k] } : { state: 'schema-only', reason: `no ${k} in this input` };
  const limits = [
    'columns are null: the IR carries line numbers only',
    'a call resolves only to a same-file function of the same name; imports, re-exports and methods are unresolved until E2-02',
    'heap, alias and closure facts are not in the IR, so field accesses are syntactic, not points-to results',
  ];
  // Dynamic constructs the analysis cannot resolve, per function (E2-03): the graph says where precision was given up, instead of leaving it implicit.
  const dynamicFeatures = analysisLimits(projectIR).map((l) => ({ symbol: symByQid.get(`${l.qid}@${(projectIR.perFile[l.file].functions.find((f) => stripLine(f.qid) === l.qid) || {}).line}`) ?? null, file: l.file, line: l.line, kind: l.kind, detail: l.detail, effect: l.effect }));
  return { schema: SEMANTIC_GRAPH_SCHEMA, schemaVersion: SEMANTIC_GRAPH_VERSION, producer: { layer: 'ir-v1', engineVersion: meta.engineVersion ?? null }, ...g, coverage, limits, dynamicFeatures };
}
