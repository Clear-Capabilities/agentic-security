// boundary-contract.js: DAG-08. Versioned, field-aware contracts for the HTTP, queue and storage edges between services.
//
// A contract is an OPERATOR DECLARATION that a producer site hands named fields to a consumer site across a trust boundary.
// What it can establish, and what it cannot:
//   * It establishes a MODELED untrusted input at the consumer: the declared consumer parameter/record fields are treated as
//     attacker-influenced when the taint engine runs. It does not establish that any value was observed on the wire, nor that a
//     sink in the consumer is exploited. Every attribution carries `modeledInput: true, observed: false`.
//   * It is bound to a parser-resolved local site (a function in the call graph and one of its parameters). A declaration that
//     cannot be bound (no such file/function/parameter, an ambiguous name, a field the Haskell record does not have) becomes an
//     explicit COVERAGE GAP. It never becomes a finding at a guessed function.
//   * Field mappings carry renames (`customer_id` -> `customerId`). The consumer is seeded only at the mapped consumer fields
//     (consumer projection), so a sibling field such as `displayName` is not attributed to the boundary.
//   * `persistence` separates an immediate call edge (http) from a handoff that outlives the request (storage, durable queue).
//     A storage write and a later read correlate only under a declared storage contract that names the same store, table and
//     key/schema version. Two sites that merely share a field name are never joined.
//   * Evidence kinds stay separately attributable: foreign graph validation, digest check, manual assertion, code mapping and
//     observed connection. Only an `observed-connection` item can make `observed` true, and this module never creates one.
//
// Pure: no file access, no dependency on the taint engine. The seeding step that needs the engine lives in
// dataflow/cross-service-taint.js and consumes the bindings built here.

import { createHash } from 'node:crypto';
import { EDGE_PROVENANCE_VALUES } from './schema.js';
import { computeScc } from '../graph/scc.js';

export const BOUNDARY_CONTRACT_VERSION = '1.0.0';
export const BOUNDARY_CONTRACTS_FILENAME = 'boundary-contracts.json';
export const BOUNDARY_KINDS = Object.freeze(['http', 'queue', 'storage']);
export const PERSISTENCE_VALUES = Object.freeze(['immediate', 'persisted']);
export const EVIDENCE_KINDS = Object.freeze(['foreign-graph-validation', 'digest-check', 'manual-assertion', 'code-mapping', 'observed-connection']);

const isStr = (v) => typeof v === 'string' && v.length > 0;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const sorted = (a) => [...a].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));

function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v === undefined ? null : v);
}

/** Digest of everything that defines what the contract says (not who declared it or when). */
export function contractDigest(c) {
  const basis = {
    version: c.version, kind: c.kind, persistence: c.persistence, channel: c.channel, schema: c.schema,
    producer: { service: c.producer && c.producer.service, site: (c.producer && c.producer.site) || null, untrustedFields: sorted((c.producer && c.producer.untrustedFields) || []) },
    consumer: { service: c.consumer && c.consumer.service, site: (c.consumer && c.consumer.site) || null },
    fieldMappings: (c.fieldMappings || []).map((m) => ({ from: m.from, to: m.to })).sort((a, b) => (a.from + a.to < b.from + b.to ? -1 : 1)),
  };
  return `sha256:${createHash('sha256').update(canonical(basis)).digest('hex')}`;
}

function channelKey(c) {
  const ch = c.channel || {};
  if (c.kind === 'http') return `http:${String(ch.method || '*').toUpperCase()} ${ch.route || ''}`;
  if (c.kind === 'queue') return `queue:${ch.topic || ''}`;
  return `storage:${ch.store || ''}/${ch.table || ''}#${ch.key || ''}`;
}

/** Structural validation. Never throws, never touches a graph. */
export function validateBoundaryContract(c) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });
  if (!isObj(c)) return { valid: false, errors: [{ path: '$', message: 'contract must be an object' }] };
  if (!isStr(c.id) || !c.id.startsWith('boundary:')) err('$.id', 'id is required and must start with "boundary:"');
  if (c.version !== BOUNDARY_CONTRACT_VERSION) err('$.version', `unsupported contract version "${c.version}" (supported: ${BOUNDARY_CONTRACT_VERSION})`);
  if (!BOUNDARY_KINDS.includes(c.kind)) err('$.kind', `kind must be one of ${BOUNDARY_KINDS.join('|')}`);
  if (!PERSISTENCE_VALUES.includes(c.persistence)) err('$.persistence', `persistence must be one of ${PERSISTENCE_VALUES.join('|')}`);
  else if (c.kind === 'storage' && c.persistence !== 'persisted') err('$.persistence', 'a storage contract is persisted: the value outlives the request');
  else if (c.kind === 'http' && c.persistence !== 'immediate') err('$.persistence', 'an http contract is an immediate call edge');
  if (!isObj(c.channel)) err('$.channel', 'channel is required');
  else if (c.kind === 'http' && !isStr(c.channel.route)) err('$.channel.route', 'http channel needs a route');
  else if (c.kind === 'queue' && !isStr(c.channel.topic)) err('$.channel.topic', 'queue channel needs a topic');
  else if (c.kind === 'storage') {
    if (!isStr(c.channel.store)) err('$.channel.store', 'storage channel needs a store');
    if (!isStr(c.channel.table)) err('$.channel.table', 'storage channel needs a table');
    if (!isStr(c.channel.key)) err('$.channel.key', 'storage channel needs a key contract');
  }
  if (!isObj(c.schema) || !isStr(c.schema.name) || !isStr(c.schema.version)) err('$.schema', 'schema {name, version} is required');
  for (const side of ['producer', 'consumer']) {
    const s = c[side];
    if (!isObj(s) || !isStr(s.service)) { err(`$.${side}.service`, `${side}.service is required`); continue; }
    if (s.site !== undefined && s.site !== null) {
      if (!isObj(s.site) || !isStr(s.site.file) || !isStr(s.site.function)) err(`$.${side}.site`, `${side}.site needs file and function`);
      else if (side === 'consumer' && !isStr(s.site.param)) err('$.consumer.site.param', 'consumer.site needs the handler parameter that receives the record');
    } else if (side === 'consumer') err('$.consumer.site', 'consumer.site is required to seed taint');
  }
  if (!Array.isArray(c.fieldMappings)) err('$.fieldMappings', 'fieldMappings must be an array');
  else c.fieldMappings.forEach((m, i) => { if (!isObj(m) || !isStr(m.from) || !isStr(m.to)) err(`$.fieldMappings[${i}]`, 'mapping needs from and to'); });
  if (!EDGE_PROVENANCE_VALUES.includes(c.provenance)) err('$.provenance', `provenance must be one of ${EDGE_PROVENANCE_VALUES.join('|')}`);
  if (!isObj(c.evidence) || c.evidence.declared !== true || c.evidence.observed !== false) err('$.evidence', 'evidence must be {declared: true, observed: false}: a contract is never an observed flow');
  if (c.configDigest !== undefined && !isStr(c.configDigest)) err('$.configDigest', 'configDigest must be a string');
  if (!isStr(c.declaredBy)) err('$.declaredBy', 'declaredBy is required');
  return { valid: errors.length === 0, errors };
}

/** Build a well-formed contract (the digest is computed, never trusted from input). */
export function createBoundaryContract(spec) {
  const c = {
    version: BOUNDARY_CONTRACT_VERSION, provenance: 'manual', evidence: { declared: true, observed: false }, ...spec,
  };
  if (!c.persistence) c.persistence = c.kind === 'storage' ? 'persisted' : c.kind === 'http' ? 'immediate' : 'persisted';
  c.configDigest = contractDigest(c);
  return c;
}

/** Evidence items; each keeps its own kind and basis. `observed` is true only for an observed-connection item. */
export function evidenceItem(kind, detail = {}) {
  if (!EVIDENCE_KINDS.includes(kind)) throw new TypeError(`unknown evidence kind "${kind}"`);
  return { kind, observed: kind === 'observed-connection', ...detail };
}

export function attributeEvidence(items) {
  const byKind = Object.fromEntries(EVIDENCE_KINDS.map((k) => [k, []]));
  for (const it of items || []) if (it && byKind[it.kind]) byKind[it.kind].push(it);
  return { byKind, observed: byKind['observed-connection'].length > 0 && byKind['observed-connection'].every((i) => i.observed === true), declaredOnly: byKind['observed-connection'].length === 0 };
}

/** Evidence available for one contract. A passed digest check is a digest check, not an observation. */
export function contractEvidence(c, { binding = null, foreignValidation = null } = {}) {
  const items = [];
  if (c.provenance === 'manual' || c.provenance === 'schema') items.push(evidenceItem('manual-assertion', { declaredBy: c.declaredBy, provenance: c.provenance }));
  if (c.configDigest) items.push(evidenceItem('digest-check', { expected: c.configDigest, actual: contractDigest(c), ok: c.configDigest === contractDigest(c) }));
  if (binding) items.push(evidenceItem('code-mapping', { file: binding.file, line: binding.line, qid: binding.qid }));
  if (foreignValidation) items.push(evidenceItem('foreign-graph-validation', { ok: foreignValidation.ok === true, graphDigest: foreignValidation.graphDigest || null }));
  return items;
}

const paramNameOf = (p) => (typeof p === 'string' ? p : p && p.name);
const norm = (f) => String(f || '').replace(/^\.\//, '').replace(/\\/g, '/');

function resolveSite(site, callGraph) {
  const fns = [...(callGraph && callGraph.functions && callGraph.functions.values ? callGraph.functions.values() : [])];
  const file = norm(site.file);
  const hits = fns.filter((f) => norm(f.file) === file && (f.name === site.function || String(f.name).endsWith(`.${site.function}`)));
  if (hits.length === 1) return { fn: hits[0] };
  if (hits.length > 1) return { gap: 'ambiguous-site', detail: `${hits.length} functions named ${site.function} in ${site.file}` };
  return { gap: fns.some((f) => norm(f.file) === file) ? 'function-not-found' : 'file-not-found', detail: `${site.function} in ${site.file}` };
}

/**
 * Bind consumer (and, when given, producer) sites to parser-resolved functions.
 * Returns `{bindings, gaps, rejected}`; nothing is guessed. A consumer binding carries the access paths to seed.
 */
export function bindBoundaryContracts(contracts, callGraph, { language = null } = {}) {
  const bindings = []; const gaps = []; const rejected = [];
  for (const c of contracts || []) {
    const v = validateBoundaryContract(c);
    if (!v.valid) { rejected.push({ contractId: c && c.id, errors: v.errors }); continue; }
    const gap = (side, reason, detail, extra = {}) => gaps.push({ contractId: c.id, kind: 'unbound-boundary', side, reason, detail, service: c[side].service, site: c[side].site || null, ...extra });
    if (c.producer.site) {
      const r = resolveSite(c.producer.site, callGraph);
      if (r.gap) gap('producer', r.gap, r.detail);
    }
    const site = c.consumer.site;
    const r = resolveSite(site, callGraph);
    if (r.gap) { gap('consumer', r.gap, r.detail); continue; }
    const fn = r.fn;
    const rec = ((fn.hs && fn.hs.recordParams) || []).find((p) => p.name === site.param) || null;
    if (!(fn.params || []).map(paramNameOf).includes(site.param)) { gap('consumer', 'param-not-found', `${site.param} is not a parameter of ${fn.name}`); continue; }
    if (!c.fieldMappings.length) { gap('consumer', 'no-field-mappings', 'a contract with no field mappings seeds nothing'); continue; }
    const seeds = []; const mapped = [];
    for (const m of c.fieldMappings) {
      if (rec && !(rec.fields || []).includes(m.to)) { gap('consumer', 'field-not-in-record', `${m.to} is not a field of ${rec.type}`, { field: m.to }); continue; }
      seeds.push([site.param, site.recordPath, m.to].filter(Boolean).join('.'));
      mapped.push({ from: m.from, to: m.to, renamed: m.from !== m.to });
    }
    if (!seeds.length) continue;
    bindings.push({
      contractId: c.id, kind: c.kind, persistence: c.persistence, digest: contractDigest(c), schema: c.schema,
      channel: channelKey(c), upstream: { service: c.producer.service, site: c.producer.site || null },
      consumerService: c.consumer.service, qid: fn.qid, file: fn.file, line: fn.line, param: site.param,
      language: language || (/\.l?hs$/i.test(fn.file) ? 'haskell' : null), record: rec ? { type: rec.type, fields: rec.fields } : null,
      originalLocation: { file: fn.file, line: fn.line }, seeds, mappedFields: mapped,
      evidence: contractEvidence(c, { binding: { file: fn.file, line: fn.line, qid: fn.qid } }),
    });
  }
  return { bindings, gaps, rejected };
}

/** The attribution stamped on a finding that came from a bound boundary seed. A declaration is a modeled input only. */
export function boundaryAttribution(binding) {
  return {
    contractId: binding.contractId, contractVersion: BOUNDARY_CONTRACT_VERSION, digest: binding.digest, kind: binding.kind,
    persistence: binding.persistence, channel: binding.channel, schema: binding.schema, upstream: binding.upstream,
    consumerService: binding.consumerService, param: binding.param, mappedFields: binding.mappedFields,
    modeledInput: true, observed: false, exploited: false, evidence: binding.evidence,
    attribution: attributeEvidence(binding.evidence),
  };
}

/**
 * Storage correlation. A write and a later read join only under a declared storage contract that names the same store and
 * table, and (when both sites state it) the same key and schema version. Field names alone never join two sites.
 * @param {object[]} contracts
 * @param {Array<{store,table,key?,schemaVersion?,fields:string[],site?:any}>} writes
 * @param {Array<{store,table,key?,schemaVersion?,fields:string[],site?:any}>} reads
 */
export function correlateStorage(contracts, writes, reads) {
  const storage = (contracts || []).filter((c) => c.kind === 'storage' && validateBoundaryContract(c).valid);
  const joins = []; const unjoined = [];
  const matches = (c, s) => c.channel.store === s.store && c.channel.table === s.table
    && (!s.key || s.key === c.channel.key) && (!s.schemaVersion || s.schemaVersion === c.schema.version);
  const used = new Set();
  for (const w of writes || []) {
    const c = storage.find((x) => matches(x, w));
    if (!c) { unjoined.push({ side: 'write', site: w.site || null, reason: 'no-storage-contract', store: w.store, table: w.table }); continue; }
    for (const r of reads || []) {
      if (!matches(c, r)) continue;
      used.add(r);
      const map = new Map(c.fieldMappings.map((m) => [m.from, m.to]));
      const fields = (w.fields || []).filter((f) => map.has(f) && (r.fields || []).includes(map.get(f))).map((f) => ({ from: f, to: map.get(f) }));
      joins.push({ contractId: c.id, persistence: 'persisted', immediate: false, store: w.store, table: w.table, key: c.channel.key, schemaVersion: c.schema.version, write: w.site || null, read: r.site || null, fields });
    }
  }
  for (const r of reads || []) if (!used.has(r)) unjoined.push({ side: 'read', site: r.site || null, reason: 'no-storage-contract', store: r.store, table: r.table });
  return { joins, unjoined };
}

export const DEFAULT_SERVICE_ROUNDS = 16;
export const DEFAULT_SERVICE_FACTS = 2000;

/**
 * Which fields are modeled-tainted in which service, through contract edges. The service graph may contain cycles: it is
 * condensed with SCC (graph/scc.js) and each recursive component is solved by a worklist under a round and fact budget.
 * A budget hit is reported (`truncated`), never silently treated as convergence.
 */
export function analyzeServiceBoundaries(contracts, { entry = {}, maxRounds = DEFAULT_SERVICE_ROUNDS, maxFacts = DEFAULT_SERVICE_FACTS } = {}) {
  const valid = (contracts || []).filter((c) => validateBoundaryContract(c).valid);
  const nodes = sorted([...new Set(valid.flatMap((c) => [c.producer.service, c.consumer.service]))]);
  const edges = valid.map((c) => [c.producer.service, c.consumer.service]);
  const scc = computeScc({ nodes, edges });
  const tainted = new Map(nodes.map((n) => [n, new Set(entry[n] || [])]));
  const origins = new Map();                  // service\0field -> {contractId, from}
  let facts = nodes.reduce((a, n) => a + tainted.get(n).size, 0);
  let truncated = false; let rounds = 0; let converged = true;
  const out = new Map();
  for (const c of valid) { if (!out.has(c.producer.service)) out.set(c.producer.service, []); out.get(c.producer.service).push(c); }

  const step = (svc) => {
    let changed = false;
    for (const c of out.get(svc) || []) {
      const have = tainted.get(svc);
      const dst = tainted.get(c.consumer.service);
      for (const m of c.fieldMappings) {
        if (!(have.has(m.from) || (c.producer.untrustedFields || []).includes(m.from))) continue;
        if (dst.has(m.to)) continue;
        if (facts >= maxFacts) { truncated = true; continue; }
        dst.add(m.to); facts++; changed = true;
        origins.set(`${c.consumer.service}\0${m.to}`, { contractId: c.id, from: `${svc}.${m.from}` });
      }
    }
    return changed;
  };

  for (const id of scc.order) {
    const comp = scc.components[id];
    if (!comp.recursive) { for (const s of comp.members) step(s); continue; }
    let r = 0; let again = true;
    while (again && r < maxRounds && !truncated) { again = false; r++; for (const s of comp.members) if (step(s)) again = true; }
    rounds = Math.max(rounds, r);
    if (again) { converged = false; }
  }
  if (truncated) converged = false;
  return {
    services: nodes,
    cycles: scc.components.filter((c) => c.recursive).map((c) => c.members),
    taintedFields: Object.fromEntries(nodes.map((n) => [n, sorted([...tainted.get(n)])])),
    origins: Object.fromEntries([...origins].map(([k, v]) => [k.replace('\0', '.'), v])),
    rounds, converged, truncated,
    note: 'Fields are modeled from declarations; none is an observed runtime flow.',
  };
}
