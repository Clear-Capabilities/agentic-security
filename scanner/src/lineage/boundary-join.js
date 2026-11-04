//
// boundary-join.js: cross-service handoffs in the lineage graph (GA plan,
// GA-03.3: "integrate existing cross-service boundary joins into the
// documented opt-in scan path; validate producer/consumer schemas, argument
// mapping and field protection; unknown dynamic edges must remain unknown").
//
// A HANDOFF is a value leaving one function through a queue publish or a
// storage write and re-entering another function through a queue receive or
// a storage read. The field-identity engine sees the two halves as an escape
// and an unrelated call result; nothing in the hop stream connects them, so
// before this module the multi-service fixture's queue consumer and its
// reporting handlers reported no flow at all (3 of 8 labelled positives).
//
// What a join IS, and what it is not:
//   * A join is a MODELED connection: the producer and the consumer name the
//     SAME identity by a literal the parser can read (the same string literal
//     or the same `process.env` name for a queue, the same collection literal
//     for a store), or an operator declared the edge in a boundary contract
//     (boundary-contract.js, DAG-08). Nothing here observes a message on the
//     wire or a row in a table: every seed carries `modeledInput: true,
//     observed: false`, exactly the vocabulary DAG-08 fixed.
//   * Two sites that share only a FIELD NAME are never joined. Two sites whose
//     identity is computed (`QueueUrl: makeUrl(env)`, `collection(name)`) are
//     reported as `unjoined` with the reason `dynamic-identity`; an identity
//     with no partner in the scanned tree is `no-producer-in-scope`.
//   * The fields that cross are the fields that REACHED the producer site in
//     the analysis: the record expression's object-literal keys are mapped to
//     the data-element ids whose contributing state keys the key's value
//     expression references (`{note: body.note, total: body.qty * PRICE}`
//     hands `note` to the key `note` and `qty` to the key `total`). A record
//     that is not an object literal hands every reaching id to the record as
//     a whole, disclosed as `basis: 'whole-record'`.
//   * The consumer is seeded on the parsed record's FIELDS, after the call
//     that received it (`source-seeding.js`'s `after-node` placement), under
//     the consumer-side record path the receive shape implies (an SQS
//     `ReceiveMessageCommand` result is `Messages[].Body`; a Mongo `find()`
//     result is the record itself). A declared contract seeds the handler
//     parameter the contract binds, in the function's entry state.
//
// The join needs the producer's analysis before the consumer can be seeded,
// and a chain (HTTP to queue to store to HTTP response) needs the store
// writer analysed WITH its queue seeds before the store reader can be
// joined. graph-builder.js therefore re-runs the field analysis in bounded
// rounds (`MAX_BOUNDARY_ROUNDS`) while a round mints new seeds, and reports
// `truncated` when the last round still would.
//
// Pure: no file access, no engine import. graph-builder.js owns the rounds;
// index.js loads the contracts file; engine.js reads the opt-in variable.

import { createHash } from 'node:crypto';
import { accessPathOf } from '../dataflow/access-paths.js';
import { exprRoots, walkExpr } from './source-seeding.js';
import { bindBoundaryContracts } from './boundary-contract.js';
import { classifyDataElementName } from './classification.js';

export const MAX_BOUNDARY_ROUNDS = 4;
export const BOUNDARY_JOIN_KINDS = Object.freeze(['queue', 'storage']);

// AWS SDK v3 command classes: `client.send(new <Command>(input))`. The input
// object carries the identity (`QueueUrl`/`TopicArn`) and the record.
export const QUEUE_SEND_COMMANDS = Object.freeze({
  SendMessageCommand: { provider: 'sqs', record: 'MessageBody', entry: 'privacy-js-queue-sendMessage' },
  SendMessageBatchCommand: { provider: 'sqs', record: 'Entries', entry: 'privacy-js-queue-sendMessage' },
  PublishCommand: { provider: 'sns', record: 'Message', entry: 'privacy-js-queue-publish' },
});
export const QUEUE_RECEIVE_COMMANDS = Object.freeze({
  ReceiveMessageCommand: { provider: 'sqs', recordPath: 'Messages.Body', encoding: 'json' },
});
const QUEUE_IDENTITY_KEYS = Object.freeze(['QueueUrl', 'TopicArn', 'topic', 'queueName']);
// Record-bearing keys for the v2 shapes `sqs.sendMessage({...})` / `sns.publish({...})`.
const QUEUE_RECORD_KEYS = Object.freeze(['MessageBody', 'Message']);

// MongoDB driver shapes on a `collection('<literal>')` handle.
const STORAGE_WRITE_METHODS = Object.freeze({ insertOne: 0, replaceOne: 1, insertMany: 0 });
const STORAGE_READ_METHODS = Object.freeze({ find: 'many', findOne: 'one', findMany: 'many' });
const STORAGE_READ_CHAIN_TAIL = Object.freeze(['toArray']);

const isObj = (v) => v !== null && typeof v === 'object';
const propOf = (objExpr, key) => (objExpr && objExpr.kind === 'object' ? (objExpr.props || []).find((p) => !p.spread && p.key === key) : null);

/** The file's module-scope function (`<file>::top::<module>@N`), when the call graph has one. */
function moduleFunctionOf(callGraph, file) {
  for (const fn of callGraph.functions.values()) {
    if (fn.file === file && /::top::<module>@/.test(String(fn.qid))) return fn;
  }
  return null;
}

/** The single module-scope assignment to `name` in `file`, or null (none, or more than one). */
function moduleConstant(callGraph, file, name) {
  const fn = moduleFunctionOf(callGraph, file);
  if (!fn) return null;
  let found = null; let count = 0;
  for (const node of Object.values(fn.cfg?.nodes ?? {})) {
    if (node.kind === 'assign' && node.target === name && node.source) { found = node.source; count += 1; }
  }
  return count === 1 ? found : null;
}

/**
 * Resolve an identity-bearing expression to a literal the parser can read:
 * `{kind: 'literal', value}` for a string/number literal, `{kind: 'env',
 * value: NAME}` for `process.env.NAME`, following a module-scope constant up
 * to three hops. Anything else is null: a computed identity is unknown.
 */
export function resolveIdentityExpr(expr, callGraph, file, depth = 0) {
  if (!isObj(expr) || depth > 3) return null;
  if (expr.kind === 'literal' && (typeof expr.value === 'string' || typeof expr.value === 'number')) return { kind: 'literal', value: String(expr.value) };
  if (expr.kind === 'member' && typeof expr.prop === 'string' && expr.object?.kind === 'member'
    && expr.object.prop === 'env' && expr.object.object?.kind === 'ident' && expr.object.object.name === 'process') {
    return { kind: 'env', value: expr.prop };
  }
  if (expr.kind === 'ident' && callGraph) {
    const c = moduleConstant(callGraph, file, expr.name);
    return c ? resolveIdentityExpr(c, callGraph, file, depth + 1) : null;
  }
  return null;
}

const identityKey = (kind, r) => (r ? `${kind}:${r.kind}:${r.value}` : null);

/** `client.send(new SendMessageCommand({...}))` and friends: the command descriptor, or null. */
export function queueCommandOf(calleeExpr, args) {
  if (!isObj(calleeExpr) || calleeExpr.kind !== 'member' || calleeExpr.prop !== 'send') return null;
  const a0 = Array.isArray(args) ? args[0] : null;
  if (!isObj(a0) || a0.kind !== 'call' || !a0.isNew || a0.callee?.kind !== 'ident') return null;
  const name = a0.callee.name;
  if (QUEUE_SEND_COMMANDS[name]) return { role: 'send', command: name, ...QUEUE_SEND_COMMANDS[name], input: a0.args?.[0] ?? null };
  if (QUEUE_RECEIVE_COMMANDS[name]) return { role: 'receive', command: name, ...QUEUE_RECEIVE_COMMANDS[name], input: a0.args?.[0] ?? null };
  return null;
}

function queueIdentityOf(inputExpr, callGraph, file) {
  if (!isObj(inputExpr) || inputExpr.kind !== 'object') return { identity: null, reason: 'no-literal-input' };
  for (const key of QUEUE_IDENTITY_KEYS) {
    const p = propOf(inputExpr, key);
    if (!p) continue;
    const r = resolveIdentityExpr(p.value, callGraph, file);
    return r ? { identity: identityKey('queue', r), detail: { key, ...r } } : { identity: null, reason: 'dynamic-identity', detail: { key } };
  }
  return { identity: null, reason: 'no-identity-key' };
}

/** `JSON.stringify(x)` → x; anything else unchanged. */
function unwrapSerialization(e) {
  if (isObj(e) && e.kind === 'call' && e.callee?.kind === 'member' && e.callee.prop === 'stringify'
    && e.callee.object?.kind === 'ident' && e.callee.object.name === 'JSON' && e.args?.length) return e.args[0];
  return e;
}

/** `<handle>.collection('<literal>')` → `{table, handleExpr}`, or null. */
function collectionCallOf(e) {
  if (!isObj(e) || e.kind !== 'call' || e.callee?.kind !== 'member' || e.callee.prop !== 'collection') return null;
  const a0 = e.args?.[0];
  if (!isObj(a0)) return { table: null, handleExpr: e.callee.object, reason: 'dynamic-identity' };
  if (a0.kind !== 'literal' || typeof a0.value !== 'string') return { table: null, handleExpr: e.callee.object, reason: 'dynamic-identity' };
  return { table: a0.value, handleExpr: e.callee.object };
}

/** The database name behind a collection handle when it is `x.db('<literal>')` reachable through module constants. */
function databaseOf(handleExpr, callGraph, file) {
  let cur = handleExpr; let depth = 0;
  while (isObj(cur) && depth++ < 4) {
    if (cur.kind === 'ident') { cur = moduleConstant(callGraph, file, cur.name); continue; }
    if (cur.kind === 'call' && cur.callee?.kind === 'member' && cur.callee.prop === 'db') {
      const a0 = cur.args?.[0];
      return isObj(a0) && a0.kind === 'literal' && typeof a0.value === 'string' ? a0.value : null;
    }
    return null;
  }
  return null;
}

function storageIdentity(coll, callGraph, file) {
  if (!coll || !coll.table) return { identity: null, reason: coll ? coll.reason : 'no-collection', detail: null };
  const database = databaseOf(coll.handleExpr, callGraph, file);
  return { identity: `storage:collection:${coll.table}`, detail: { table: coll.table, database } };
}

/** A storage WRITE site: `<handle>.collection('<lit>').insertOne(record)` and friends. */
function storageWriteOf(calleeExpr, args) {
  if (!isObj(calleeExpr) || calleeExpr.kind !== 'member') return null;
  const argIndex = STORAGE_WRITE_METHODS[calleeExpr.prop];
  if (argIndex === undefined) return null;
  const coll = collectionCallOf(calleeExpr.object);
  if (!coll) return null;
  return { method: calleeExpr.prop, coll, recordExpr: Array.isArray(args) ? args[argIndex] ?? null : null };
}

/** A storage READ expression: `<handle>.collection('<lit>').find(q).toArray()` / `.findOne(q)`. */
export function storageReadOf(expr) {
  if (!isObj(expr) || expr.kind !== 'call' || expr.callee?.kind !== 'member') return null;
  let e = expr;
  if (STORAGE_READ_CHAIN_TAIL.includes(e.callee.prop)) e = e.callee.object;
  if (!isObj(e) || e.kind !== 'call' || e.callee?.kind !== 'member') return null;
  const cardinality = STORAGE_READ_METHODS[e.callee.prop];
  if (!cardinality) return null;
  const coll = collectionCallOf(e.callee.object);
  if (!coll) return null;
  return { method: e.callee.prop, cardinality, coll };
}

/**
 * Every producer (a sink site that publishes to a queue or writes a store)
 * and every consumer (an assignment whose source receives from a queue or
 * reads a store) in the call graph. `sites` is graph-builder.js's
 * `enumerateSinkSites(callGraph).sites`. Endpoints whose identity cannot be
 * read are listed in `unjoined` with the reason, never silently dropped.
 */
export function collectBoundaryEndpoints(callGraph, sites) {
  const producers = []; const consumers = []; const unjoined = [];
  for (const site of sites || []) {
    const cat = site.decision?.category;
    if (cat === 'queue') {
      const cmd = queueCommandOf(site.calleeExpr, site.args);
      let input = cmd ? cmd.input : (site.args?.[0] ?? null);
      let recordExpr = null;
      if (cmd && cmd.role === 'send') recordExpr = propOf(input, cmd.record)?.value ?? null;
      else for (const k of QUEUE_RECORD_KEYS) { const p = propOf(input, k); if (p) { recordExpr = p.value; break; } }
      const id = queueIdentityOf(input, callGraph, site.file);
      // A producer is kept whether or not its identity resolved: a declared
      // contract names its producer by site, not by identity. Only a
      // discovered join needs the identity, and only an identified
      // producer takes part in one.
      producers.push({ kind: 'queue', site, identity: id.identity, detail: id.detail ?? null, recordExpr: unwrapSerialization(recordExpr), provider: cmd?.provider ?? null });
      if (!id.identity) unjoined.push({ side: 'producer', kind: 'queue', file: site.file, line: site.line, reason: id.reason });
    } else if (cat === 'database') {
      const w = storageWriteOf(site.calleeExpr, site.args);
      if (!w) continue;
      const id = storageIdentity(w.coll, callGraph, site.file);
      producers.push({ kind: 'storage', site, identity: id.identity, detail: id.detail, recordExpr: w.recordExpr, method: w.method });
      if (!id.identity) unjoined.push({ side: 'producer', kind: 'storage', file: site.file, line: site.line, reason: id.reason });
    }
  }
  for (const fn of callGraph.functions.values()) {
    for (const [nid, node] of Object.entries(fn.cfg?.nodes ?? {})) {
      if (node.kind !== 'assign' || typeof node.target !== 'string' || node.target.includes('.') || !isObj(node.source) || node.source.kind !== 'call') continue;
      const base = { file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, target: node.target };
      const cmd = queueCommandOf(node.source.callee, node.source.args);
      if (cmd && cmd.role === 'receive') {
        const id = queueIdentityOf(cmd.input, callGraph, fn.file);
        const ep = { ...base, kind: 'queue', identity: id.identity, detail: id.detail ?? null, recordPath: cmd.recordPath, encoding: cmd.encoding, provider: cmd.provider };
        if (id.identity) consumers.push(ep); else unjoined.push({ side: 'consumer', kind: 'queue', file: fn.file, line: base.line, reason: id.reason });
        continue;
      }
      const r = storageReadOf(node.source);
      if (r) {
        const id = storageIdentity(r.coll, callGraph, fn.file);
        const ep = { ...base, kind: 'storage', identity: id.identity, detail: id.detail, recordPath: '', cardinality: r.cardinality, method: r.method };
        if (id.identity) consumers.push(ep); else unjoined.push({ side: 'consumer', kind: 'storage', file: fn.file, line: base.line, reason: id.reason });
      }
    }
  }
  return { producers, consumers, unjoined };
}

const pathCovers = (a, b) => a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`);

/**
 * Which data-element ids crossed at a producer site, per record key.
 * `siteHops` are the hops stamped with the site's scope and node id: the
 * `write-out/call-arg` hops say which ids reached the call at all, the
 * `production`/`selection` hops say which state key each id came from. A
 * key's ids are the reaching ids whose contributing key its value expression
 * references.
 */
export function recordShape(recordExpr, siteHops) {
  const reached = new Set();
  const byKey = new Map();
  const contributions = [];
  for (const h of siteHops || []) {
    if (h.kind === 'write-out' && h.subKind === 'call-arg') reached.add(h.dataElementId);
    // An identifier read is a `production/ident` hop, a field read a
    // `selection/member` hop; both carry the contributing state key.
    if ((h.kind === 'production' || h.kind === 'selection') && typeof h.fromPath === 'string') contributions.push({ path: h.fromPath, id: h.dataElementId });
  }
  if (!reached.size) return { basis: 'none', byKey, whole: new Set() };
  const props = isObj(recordExpr) && recordExpr.kind === 'object' ? recordExpr.props || [] : null;
  if (!props || props.some((p) => p.spread) || !props.length) return { basis: 'whole-record', byKey, whole: new Set(reached) };
  for (const p of props) {
    if (typeof p.key !== 'string' || p.key === '*') continue;
    const refs = new Set();
    // Outermost access paths only: `body.note` references `body.note`, not
    // `body`, or every sibling field the record carries would be joined too.
    walkExpr(p.value, (e, parent) => {
      if (e.kind !== 'ident' && e.kind !== 'member') return;
      if (parent && parent.kind === 'member' && parent.object === e) return;
      const ap = accessPathOf(e);
      if (ap && !ap.includes('*')) refs.add(ap);
    });
    const ids = new Set();
    for (const c of contributions) if (reached.has(c.id) && [...refs].some((r) => pathCovers(r, c.path))) ids.add(c.id);
    if (ids.size) byKey.set(p.key, ids);
  }
  return { basis: 'object-literal', byKey, whole: new Set() };
}

const joinIdOf = (parts) => `join:${createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 12)}`;

function mintSeed({ consumer, placement, seedPath, id, join }) {
  const canonicalName = seedPath.slice(seedPath.lastIndexOf('.') + 1);
  return {
    file: consumer.file, qid: consumer.qid, nodeId: consumer.nodeId, line: consumer.line,
    entryId: `boundary:${join.kind}`, seedPath, canonicalName, seedKind: placement,
    category: join.kind === 'queue' ? 'queue-message' : 'database-read', coverageStatus: 'modeled', externality: 'unknown',
    reason: `${join.kind} handoff ${join.provenance === 'manual' ? 'declared by contract ' + join.contractId : 'discovered from the literal identity ' + join.identity}; modeled, not observed`,
    dataElementId: id, dataClasses: classifyDataElementName(canonicalName).classes,
    boundary: {
      joinId: join.joinId, kind: join.kind, identity: join.identity, provenance: join.provenance, contractId: join.contractId ?? null,
      basis: join.basis, producer: join.producer, modeledInput: true, observed: false, exploited: false,
    },
  };
}

/**
 * Plan the consumer seeds for every join the current hop stream supports.
 * `minted` is the cross-round set of seed keys already handed out, so a
 * round only reports what is new. Returns `{seeds, joins, unjoined, gaps}`.
 */
export function planBoundaryJoins({ endpoints, hops, contracts = [], callGraph, minted = new Set() }) {
  const hopsBySite = new Map();
  for (const h of hops || []) {
    const k = `${h.scope}|${h.nodeId}`;
    if (!hopsBySite.has(k)) hopsBySite.set(k, []);
    hopsBySite.get(k).push(h);
  }
  const seeds = []; const joins = []; const unjoined = [...(endpoints.unjoined || [])]; const gaps = [];
  const siteKey = (s) => `${s.qid}|${s.nodeId}`;
  const shapeOf = (p) => recordShape(p.recordExpr, hopsBySite.get(siteKey(p.site)) ?? []);
  const emit = (consumer, producer, placement, basePath, fieldMappings, join) => {
    const shape = shapeOf(producer);
    const fields = [];
    const add = (path, id, from, to) => {
      const key = `${consumer.qid}|${consumer.nodeId}|${path}|${id}`;
      if (minted.has(key)) return;
      minted.add(key);
      seeds.push(mintSeed({ consumer, placement, seedPath: path, id, join: { ...join, basis: shape.basis } }));
      fields.push({ from, to, dataElementId: id });
    };
    if (fieldMappings) {
      for (const m of fieldMappings) {
        const ids = shape.byKey.get(m.from) ?? (shape.basis === 'whole-record' ? shape.whole : new Set());
        for (const id of ids) add([basePath, m.to].filter(Boolean).join('.'), id, m.from, m.to);
      }
    } else {
      for (const [key, ids] of shape.byKey) for (const id of ids) add([basePath, key].filter(Boolean).join('.'), id, key, key);
      for (const id of shape.whole) add(basePath, id, null, null);
    }
    joins.push({ ...join, basis: shape.basis, fields, consumer: { file: consumer.file, line: consumer.line, qid: consumer.qid, nodeId: consumer.nodeId }, reached: shape.whole.size + [...shape.byKey.values()].reduce((n, s) => n + s.size, 0) });
  };

  // Discovered joins: the same literal identity on both sides.
  for (const c of endpoints.consumers) {
    const partners = endpoints.producers.filter((p) => p.kind === c.kind && p.identity && p.identity === c.identity
      && !(p.kind === 'storage' && p.detail?.database && c.detail?.database && p.detail.database !== c.detail.database));
    if (!partners.length) { unjoined.push({ side: 'consumer', kind: c.kind, file: c.file, line: c.line, identity: c.identity, reason: 'no-producer-in-scope' }); continue; }
    for (const p of partners) {
      const producer = { file: p.site.file, line: p.site.line, qid: p.site.qid, nodeId: p.site.nodeId };
      const join = { joinId: joinIdOf([c.kind, c.identity, siteKey(p.site), `${c.qid}|${c.nodeId}`]), kind: c.kind, identity: c.identity, provenance: 'code', contractId: null, producer };
      emit(c, p, 'after-node', [c.target, c.recordPath].filter(Boolean).join('.'), null, join);
    }
  }
  // Declared joins: a DAG-08 contract bound to a consumer parameter; the
  // producer is the contract's producer site, matched by file and function.
  const bound = contracts.length ? bindBoundaryContracts(contracts, callGraph) : { bindings: [], gaps: [], rejected: [] };
  gaps.push(...bound.gaps.map((g) => ({ ...g, source: 'contract' })), ...bound.rejected.map((r) => ({ contractId: r.contractId, kind: 'rejected-contract', errors: r.errors, source: 'contract' })));
  for (const b of bound.bindings) {
    const contract = contracts.find((c) => c.id === b.contractId);
    const psite = contract?.producer?.site;
    if (!psite) { gaps.push({ contractId: b.contractId, kind: 'unbound-boundary', side: 'producer', reason: 'producer-site-required', detail: 'a lineage join needs the producer site to read which fields reached it', source: 'contract' }); continue; }
    const norm = (f) => String(f || '').replace(/^\.\//, '').replace(/\\/g, '/');
    const partners = endpoints.producers.filter((p) => p.kind === b.kind && norm(p.site.file) === norm(psite.file)
      && (() => { const fn = callGraph.functions.get(p.site.qid) ?? [...callGraph.functions.values()].find((f) => f.qid === p.site.qid); return fn && (fn.name === psite.function || String(fn.name).endsWith(`.${psite.function}`)); })());
    if (!partners.length) { gaps.push({ contractId: b.contractId, kind: 'unbound-boundary', side: 'producer', reason: 'producer-site-not-a-' + b.kind + '-site', detail: `${psite.function} in ${psite.file}`, source: 'contract' }); continue; }
    const consumer = { file: b.file, qid: b.qid, nodeId: null, line: b.line, target: b.param };
    const recordPath = contract.consumer.site.recordPath || '';
    for (const p of partners) {
      const producer = { file: p.site.file, line: p.site.line, qid: p.site.qid, nodeId: p.site.nodeId };
      const join = { joinId: joinIdOf([b.kind, b.contractId, siteKey(p.site), b.qid]), kind: b.kind, identity: b.channel, provenance: 'manual', contractId: b.contractId, producer };
      emit(consumer, p, 'entry', [b.param, recordPath].filter(Boolean).join('.'), b.mappedFields, join);
    }
  }
  return { seeds, joins, unjoined, gaps };
}
