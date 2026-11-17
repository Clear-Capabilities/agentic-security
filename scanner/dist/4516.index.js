export const id = 4516;
export const ids = [4516];
export const modules = {

/***/ 64516:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  renderBoundariesText: () => (/* binding */ renderBoundariesText),
  runBoundaries: () => (/* binding */ runBoundaries)
});

// UNUSED EXPORTS: BINDINGS_FILE, BOUNDARIES_REPORT_SCHEMA, BOUNDARIES_REPORT_VERSION, IDENTITIES_FILE, MAX_FINDINGS, TRACE_FILES, listConfigFiles, readScanFindings

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/posture/assurance/bounded-io.js
var bounded_io = __webpack_require__(49447);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/lineage/deployment/ingest.js + 4 modules
var ingest = __webpack_require__(18876);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/lineage/runtime-observation.js
var runtime_observation = __webpack_require__(61995);
// EXTERNAL MODULE: ./src/lineage/deployment/boundary-graph.js
var boundary_graph = __webpack_require__(8283);
;// CONCATENATED MODULE: ./src/lineage/deployment/trace-correlation.js
// trace-correlation.js: sanitize runtime traces and correlate them with the
// static deployment boundary graph (X-303).
//
// The import side:
//  - A trace line is a JSON object. Only an allowlist of topology metadata is
//    kept (timestamp, environment, tenant, source and destination service,
//    host and port, request method, route host and path, outcome, sampled
//    flag, repeat count). Every other field is removed, never stored, and only
//    counted, split into credential-shaped, payload-shaped and other. A field
//    name is never kept, so a header or a body cannot reach the artifact even
//    as a key.
//  - Values that are kept are held to an identifier grammar. A request path
//    loses its query string and fragment, and any segment that looks like a
//    number, a uuid, a hash, a token or a long opaque string becomes `:id`.
//    A record whose kept value is not identifier-shaped is rejected whole,
//    never partially kept.
//  - A record for another environment is not relabelled and not stored: the
//    import is for one environment and counts the rest as rejected. A record
//    with no environment cannot be placed and is rejected too.
//  - Storage is bounded: input bytes, line length, line count, distinct
//    observations. Duplicates (same normalized key) merge into one observation
//    with a summed count and a widened interval. Past the observation cap the
//    oldest are evicted and the eviction is reported.
//
// The correlation side matches observations to graph nodes by explicit,
// numbered rules (R1 exact service pair, R2 route, R3 identity, R4 naming
// convention). R1-R3 produce `runtime-observation` edges; R4 produces an
// `inferred` edge because a naming convention is a guess about identity, not
// an observation of it. A static edge is never edited: observed and inferred
// edges are separate edges, so the three kinds of evidence stay separate.
//
// What coverage means here: an observed edge is evidence that the path
// carried traffic during the window. It is never evidence that the window held
// all traffic. `trafficCoverage` is therefore always 'not-established'; sampled,
// stale and missing observations are listed separately; and a static edge with
// no matching observation stays `possible`, never `blocked` (absence in a
// sampled or unknown-completeness trace cannot establish a block).





const OBSERVATION_SET_SCHEMA = 'agentic-security/deployment-observations';
const OBSERVATION_SET_VERSION = '1.0.0';

const TRACE_LIMITS = Object.freeze({
  maxInputBytes: 4 * 1024 * 1024,
  maxLineBytes: 8 * 1024,
  maxLines: 50_000,
  maxObservations: 2_000,
  maxCount: 1_000_000_000,
});
const DEFAULT_STALE_AFTER_MS = 7 * 24 * 3600 * 1000;

const CORRELATION_RULES = Object.freeze({
  R1: 'exact service pair: source and destination service names match service nodes of the same environment and tenant',
  R2: 'route: request host and path fall under a route node reached from the destination service',
  R3: 'identity: the source identity matches the identity the source service is configured to assume',
  R4: 'naming convention: a DNS style host or an unqualified service name resolves to exactly one service (inferred, never observed)',
});

const OUTCOMES = ['ok', 'denied', 'error'];
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const TOP_KEYS = ['ts', 'environment', 'tenant', 'source', 'destination', 'route', 'outcome', 'sampled', 'count'];
const SOURCE_KEYS = ['service', 'identity', 'tenant'];
const DEST_KEYS = ['service', 'host', 'port', 'tenant'];
const ROUTE_KEYS = ['method', 'host', 'path'];

const SVC = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,127}$/;
const HOST = /^[A-Za-z0-9*]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const ENV = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const CREDENTIAL_KEY = /auth|token|secret|passw|cookie|bearer|credential|session|api[-_]?key|signature|jwt/i;
const PAYLOAD_KEY = /body|payload|request|response|header|query|param|message|data|content|text|input|output|record|prompt/i;

function emptySanitization() {
  return { recordsWithRemovedFields: 0, removedFieldCount: 0, credentialShaped: 0, payloadShaped: 0, other: 0 };
}

function classifyRemoved(key, s) {
  s.removedFieldCount += 1;
  if (CREDENTIAL_KEY.test(key)) s.credentialShaped += 1;
  else if (PAYLOAD_KEY.test(key)) s.payloadShaped += 1;
  else s.other += 1;
}

/** Strip a path to its route shape: no query, no fragment, opaque segments become ':id'. Returns null if nothing usable remains. */
function normalizePath(raw) {
  if (typeof raw !== 'string') return null;
  const cut = raw.split(/[?#]/)[0];
  if (!cut.startsWith('/')) return null;
  const segs = cut.split('/').slice(1, 13);
  // Keep only plain words and versions; numbers, ids, hashes and tokens all carry digits or length.
  const out = segs.map((seg) => {
    if (seg === '') return '';
    if (/^[A-Za-z]+([_-][A-Za-z]+)*$/.test(seg) && seg.length <= 32) return seg;
    if (/^v\d{1,3}$/.test(seg)) return seg;
    return ':id';
  });
  const p = out.join('/');
  const rebuilt = `/${p.startsWith('/') ? p.slice(1) : p}`.replace(/\/{2,}/g, '/');
  return rebuilt.length <= 200 ? rebuilt : null;
}

function sanitizeObject(obj, allowed, stats) {
  const kept = {};
  let removed = 0;
  for (const k of Object.keys(obj)) {
    if (allowed.includes(k)) kept[k] = obj[k]; else { classifyRemoved(k, stats); removed += 1; }
  }
  return { kept, removed };
}

/** Normalize one parsed line. Returns `{ obs }` or `{ reject }`. */
function normalizeRecord(rec, stats) {
  if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) return { reject: 'not-an-object' };
  let removedTotal = 0;
  const top = sanitizeObject(rec, TOP_KEYS, stats); removedTotal += top.removed;
  const r = top.kept;
  const sub = (v, keys) => { if (v === undefined) return {}; if (v === null || typeof v !== 'object' || Array.isArray(v)) return null; const s = sanitizeObject(v, keys, stats); removedTotal += s.removed; return s.kept; };
  const src = sub(r.source, SOURCE_KEYS), dst = sub(r.destination, DEST_KEYS), rt = sub(r.route, ROUTE_KEYS);
  if (removedTotal > 0) stats.recordsWithRemovedFields += 1;
  if (src === null || dst === null || rt === null) return { reject: 'bad-structure' };

  if (typeof r.ts !== 'string' || !ISO.test(r.ts) || !Number.isFinite(Date.parse(r.ts))) return { reject: 'bad-timestamp' };
  if (typeof r.environment !== 'string' || !ENV.test(r.environment)) return { reject: 'missing-environment' };
  if (r.tenant !== undefined && r.tenant !== null && (typeof r.tenant !== 'string' || !ENV.test(r.tenant))) return { reject: 'bad-tenant' };
  for (const t of [src.tenant, dst.tenant]) if (t !== undefined && t !== null && (typeof t !== 'string' || !ENV.test(t))) return { reject: 'bad-tenant' };
  if (src.service !== undefined && (typeof src.service !== 'string' || !SVC.test(src.service))) return { reject: 'bad-source-service' };
  if (src.identity !== undefined && (typeof src.identity !== 'string' || !SVC.test(src.identity))) return { reject: 'bad-identity' };
  if (dst.service !== undefined && (typeof dst.service !== 'string' || !SVC.test(dst.service))) return { reject: 'bad-destination-service' };
  if (dst.host !== undefined && (typeof dst.host !== 'string' || !HOST.test(dst.host))) return { reject: 'bad-destination-host' };
  if (dst.port !== undefined && !(Number.isInteger(dst.port) && dst.port >= 1 && dst.port <= 65535)) return { reject: 'bad-destination-port' };
  if (rt.method !== undefined && !METHODS.includes(rt.method)) return { reject: 'bad-method' };
  if (rt.host !== undefined && (typeof rt.host !== 'string' || !HOST.test(rt.host))) return { reject: 'bad-route-host' };
  let path = null;
  if (rt.path !== undefined) { path = normalizePath(rt.path); if (path === null) return { reject: 'bad-route-path' }; }
  if (r.outcome !== undefined && !OUTCOMES.includes(r.outcome)) return { reject: 'bad-outcome' };
  if (r.sampled !== undefined && typeof r.sampled !== 'boolean') return { reject: 'bad-sampled' };
  if (r.count !== undefined && !(Number.isInteger(r.count) && r.count >= 1 && r.count <= TRACE_LIMITS.maxCount)) return { reject: 'bad-count' };
  if (!src.service && !src.identity && !dst.service && !dst.host && !(rt.host || path)) return { reject: 'no-topology-fields' };

  const o = {
    environment: r.environment,
    tenant: r.tenant ?? null,
    from: { service: src.service ?? null, identity: src.identity ?? null, tenant: src.tenant ?? r.tenant ?? null },
    to: { service: dst.service ?? null, host: dst.host ?? null, port: dst.port ?? null, tenant: dst.tenant ?? r.tenant ?? null },
    route: (rt.method || rt.host || path) ? { method: rt.method ?? null, host: rt.host ?? null, path } : null,
    outcome: r.outcome ?? 'ok',
    sampled: r.sampled === true,
    eventCount: r.count ?? 1,
    firstObservedAt: r.ts,
    lastObservedAt: r.ts,
  };
  o.id = observationIdOf(o);
  return { obs: o };
}

const OBS_ID_FIELDS = ['environment', 'tenant', 'from', 'to', 'route', 'outcome', 'sampled'];
function observationIdOf(o) { return (0,identity/* semanticId */.YN)('bobs', o, OBS_ID_FIELDS); }

function mergeInto(a, b) {
  a.eventCount = Math.min(TRACE_LIMITS.maxCount, a.eventCount + b.eventCount);
  if (Date.parse(b.firstObservedAt) < Date.parse(a.firstObservedAt)) a.firstObservedAt = b.firstObservedAt;
  if (Date.parse(b.lastObservedAt) > Date.parse(a.lastObservedAt)) a.lastObservedAt = b.lastObservedAt;
}

function eventCountBand(n) {
  if (n <= 1) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[0];
  if (n <= 10) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[1];
  if (n <= 100) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[2];
  if (n <= 1000) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[3];
  return runtime_observation/* EVENT_COUNT_BANDS */.Ws[4];
}

function computeSetDigest(set) { return (0,identity/* digestOf */.ol)({ ...set, digest: null }); }

function finalizeSet(environment, byId, stats, sanitization, limits) {
  let list = [...byId.values()];
  let evicted = 0;
  if (list.length > limits.maxObservations) {
    list.sort((a, b) => Date.parse(b.lastObservedAt) - Date.parse(a.lastObservedAt) || (a.id < b.id ? -1 : 1));
    evicted = list.length - limits.maxObservations;
    list = list.slice(0, limits.maxObservations);
  }
  list.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const times = list.flatMap(o => [Date.parse(o.firstObservedAt), Date.parse(o.lastObservedAt)]);
  const set = {
    schema: OBSERVATION_SET_SCHEMA,
    schemaVersion: OBSERVATION_SET_VERSION,
    environment,
    window: times.length ? { start: new Date(Math.min(...times)).toISOString(), end: new Date(Math.max(...times)).toISOString() } : null,
    observations: list,
    sanitization,
    stats: { ...stats, evicted },
    digest: '',
  };
  set.digest = computeSetDigest(set);
  return set;
}

/**
 * Import runtime trace lines for ONE environment. Never throws, never reads a
 * file, never stores a removed field or a rejected record.
 *
 * @param {string} text  JSON Lines
 * @param {object} p
 * @param {string} p.environment  the only environment this import accepts
 */
function importTraceLines(text, { environment, limits: overrides = {} } = {}) {
  const limits = { ...TRACE_LIMITS, ...overrides };
  if (typeof environment !== 'string' || !ENV.test(environment)) return { status: 'invalid-input', reason: 'environment must be a name such as prod', set: null };
  if (typeof text !== 'string') return { status: 'invalid-input', reason: 'trace input must be text', set: null };
  if (Buffer.byteLength(text, 'utf8') > limits.maxInputBytes) return { status: 'limit-exceeded', reason: `trace input is over the ${limits.maxInputBytes} byte limit; nothing was imported`, set: null };

  const sanitization = emptySanitization();
  const stats = { linesRead: 0, accepted: 0, duplicates: 0, rejected: 0, rejectedEnvironment: 0, truncatedLines: false, rejectReasons: {} };
  const byId = new Map();
  const lines = text.split('\n');
  for (const raw of lines) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line.trim() === '') continue;
    if (stats.linesRead >= limits.maxLines) { stats.truncatedLines = true; break; }
    stats.linesRead += 1;
    const reject = (why) => { stats.rejected += 1; stats.rejectReasons[why] = (stats.rejectReasons[why] ?? 0) + 1; };
    if (Buffer.byteLength(line, 'utf8') > limits.maxLineBytes) { reject('line-too-long'); continue; }
    let rec;
    try { rec = JSON.parse(line); } catch { reject('not-json'); continue; }
    const n = normalizeRecord(rec, sanitization);
    if (n.reject) { reject(n.reject); continue; }
    if (n.obs.environment !== environment) { stats.rejectedEnvironment += 1; stats.rejected += 1; stats.rejectReasons['other-environment'] = (stats.rejectReasons['other-environment'] ?? 0) + 1; continue; }
    const prev = byId.get(n.obs.id);
    if (prev) { mergeInto(prev, n.obs); stats.duplicates += 1; } else byId.set(n.obs.id, n.obs);
    stats.accepted += 1;
  }
  const set = finalizeSet(environment, byId, stats, sanitization, limits);
  return { status: 'ok', reason: null, set };
}

/**
 * Merge a newer import into stored observations of the SAME environment,
 * bounded. Different environments are refused (never merged). Returns a new set.
 */
function mergeObservationSets(existing, incoming, { maxObservations = TRACE_LIMITS.maxObservations } = {}) {
  if (!existing || !incoming) return { status: 'invalid-input', reason: 'two observation sets are required', set: null };
  if (existing.environment !== incoming.environment) return { status: 'environment-mismatch', reason: `refusing to merge '${incoming.environment}' observations into '${existing.environment}'`, set: null };
  const byId = new Map(existing.observations.map(o => [o.id, { ...o }]));
  let duplicates = 0;
  for (const o of incoming.observations) {
    const prev = byId.get(o.id);
    if (prev) { mergeInto(prev, o); duplicates += 1; } else byId.set(o.id, { ...o });
  }
  const stats = { linesRead: 0, accepted: byId.size, duplicates, rejected: 0, rejectedEnvironment: 0, truncatedLines: false, rejectReasons: {} };
  const sanitization = {
    recordsWithRemovedFields: existing.sanitization.recordsWithRemovedFields + incoming.sanitization.recordsWithRemovedFields,
    removedFieldCount: existing.sanitization.removedFieldCount + incoming.sanitization.removedFieldCount,
    credentialShaped: existing.sanitization.credentialShaped + incoming.sanitization.credentialShaped,
    payloadShaped: existing.sanitization.payloadShaped + incoming.sanitization.payloadShaped,
    other: existing.sanitization.other + incoming.sanitization.other,
  };
  return { status: 'ok', reason: null, set: finalizeSet(existing.environment, byId, stats, sanitization, { maxObservations }) };
}

// ------------------------------------------------------------ persistence

const SET_FIELDS = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'environment', 'window', 'observations', 'sanitization', 'stats', 'digest']));
const OBS_FIELDS = (/* unused pure expression or super */ null && (['id', 'environment', 'tenant', 'from', 'to', 'route', 'outcome', 'sampled', 'eventCount', 'firstObservedAt', 'lastObservedAt']));

/** Deterministic text form of an observation set (for the caller to store). */
function exportObservationSet(set) { return `${canonicalize(set)}\n`; }

/**
 * Read a stored observation set back. Closed world, bounded, digest-checked:
 * a set that was edited, padded with extra fields, or grown past the cap is
 * refused, never partially accepted.
 */
function parseObservationSet(text, { maxObservations = TRACE_LIMITS.maxObservations, maxBytes = 2 * TRACE_LIMITS.maxInputBytes } = {}) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > maxBytes) return { status: 'malformed', reason: 'not text, or over the size limit', set: null };
  let set;
  try { set = JSON.parse(text); } catch { return { status: 'malformed', reason: 'not valid JSON', set: null }; }
  const bad = (reason) => ({ status: 'invalid', reason, set: null });
  if (!set || typeof set !== 'object' || Array.isArray(set)) return bad('not an object');
  for (const k of Object.keys(set)) if (!SET_FIELDS.includes(k)) return bad(`unknown field '${k}'`);
  if (set.schema !== OBSERVATION_SET_SCHEMA) return bad('wrong schema');
  if (typeof set.environment !== 'string' || !ENV.test(set.environment)) return bad('bad environment');
  if (!Array.isArray(set.observations) || set.observations.length > maxObservations) return bad(`observations must be an array of at most ${maxObservations}`);
  const ids = new Set();
  for (const o of set.observations) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return bad('observation is not an object');
    for (const k of Object.keys(o)) if (!OBS_FIELDS.includes(k)) return bad(`observation has unknown field '${k}'`);
    if (o.environment !== set.environment) return bad('observation environment differs from the set environment');
    if (!ISO.test(o.firstObservedAt ?? '') || !ISO.test(o.lastObservedAt ?? '') || Date.parse(o.firstObservedAt) > Date.parse(o.lastObservedAt)) return bad('observation interval is invalid');
    if (!OUTCOMES.includes(o.outcome) || typeof o.sampled !== 'boolean') return bad('observation outcome or sampled flag is invalid');
    if (!Number.isInteger(o.eventCount) || o.eventCount < 1 || o.eventCount > TRACE_LIMITS.maxCount) return bad('observation count is invalid');
    for (const [f, keys] of [['from', SOURCE_KEYS], ['to', DEST_KEYS]]) {
      if (!o[f] || typeof o[f] !== 'object') return bad(`observation.${f} is missing`);
      for (const k of Object.keys(o[f])) if (!keys.includes(k)) return bad(`observation.${f} has unknown field '${k}'`);
    }
    for (const v of [o.from?.service, o.from?.identity, o.to?.service]) if (v !== null && v !== undefined && !SVC.test(v)) return bad('observation has a non identifier-shaped name');
    for (const v of [o.tenant, o.from?.tenant, o.to?.tenant]) if (v !== null && v !== undefined && !ENV.test(v)) return bad('observation has a bad tenant');
    if (o.to.host !== null && o.to.host !== undefined && !HOST.test(o.to.host)) return bad('observation has a bad host');
    if (o.route !== null) {
      if (typeof o.route !== 'object') return bad('observation.route is invalid');
      for (const k of Object.keys(o.route)) if (!ROUTE_KEYS.includes(k)) return bad(`observation.route has unknown field '${k}'`);
      if (o.route.path !== null && o.route.path !== undefined && (typeof o.route.path !== 'string' || !/^\/[A-Za-z0-9._:\/-]*$/.test(o.route.path) || o.route.path.length > 200)) return bad('observation has a bad route path');
    }
    if (observationIdOf(o) !== o.id) return bad('observation id does not match its content');
    if (ids.has(o.id)) return bad('duplicate observation id');
    ids.add(o.id);
  }
  if (set.digest !== computeSetDigest(set)) return bad('digest does not match the content');
  return { status: 'ok', reason: null, set };
}

// ------------------------------------------------------------ correlation

const COMM_RELATIONS = new Set(['calls', 'depends-on', 'network-allows', 'routes-to']);

function serviceIndex(graph, environment) {
  const exact = new Map(), bySuffix = new Map();
  for (const n of graph.nodes) {
    if (n.kind !== 'service' || n.environment !== environment) continue;
    exact.set(`${n.tenant ?? ''}\n${n.name}`, n);
    const base = n.name.includes('/') ? n.name.slice(n.name.lastIndexOf('/') + 1) : n.name;
    const k = `${n.tenant ?? ''}\n${base}`;
    if (!bySuffix.has(k)) bySuffix.set(k, []);
    bySuffix.get(k).push(n);
  }
  return { exact, bySuffix };
}

function dnsToService(host) {
  const m = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?)\.([a-z0-9]([a-z0-9-]*[a-z0-9])?)(\.svc(\.cluster\.local)?)?$/.exec(host ?? '');
  return m ? `${m[3]}/${m[1]}` : null;
}

function resolveService(idx, tenant, name, host) {
  const t = tenant ?? '';
  if (name) {
    const hit = idx.exact.get(`${t}\n${name}`);
    if (hit) return { node: hit, rule: 'R1', basis: 'exact-name' };
    if (!name.includes('/')) {
      const c = idx.bySuffix.get(`${t}\n${name}`) ?? [];
      if (c.length === 1) return { node: c[0], rule: 'R4', basis: 'unqualified-name' };
      if (c.length > 1) return { node: null, reason: 'ambiguous-service-name' };
    }
    return { node: null, reason: 'no-service-node' };
  }
  if (host) {
    const dns = dnsToService(host);
    if (dns) {
      const hit = idx.exact.get(`${t}\n${dns}`);
      if (hit) return { node: hit, rule: 'R4', basis: 'dns-name' };
    }
    const c = idx.bySuffix.get(`${t}\n${host}`) ?? [];
    if (c.length === 1) return { node: c[0], rule: 'R4', basis: 'host-as-service-name' };
    return { node: null, reason: c.length > 1 ? 'ambiguous-service-name' : 'no-service-node' };
  }
  return { node: null, reason: 'no-destination' };
}

function pathUnder(prefix, path) {
  if (typeof prefix !== 'string' || typeof path !== 'string') return false;
  if (prefix === '/') return true;
  return path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

/**
 * Correlate an observation set with a static graph. Pure: the clock is the
 * explicit `now` argument. Returns the correlation record; use
 * `applyCorrelation` to fold its edges into a graph.
 *
 * @param {object} graph  a valid boundary graph
 * @param {object} set    an observation set from importTraceLines
 * @param {object} p
 * @param {string} p.now  ISO timestamp the freshness test uses
 * @param {number} [p.staleAfterMs]
 * @param {boolean} [p.createObservedOnlyNodes]  default true
 */
function correlateObservations(graph, set, { now, staleAfterMs = DEFAULT_STALE_AFTER_MS, createObservedOnlyNodes = true } = {}) {
  if (!graph || !set || set.schema !== OBSERVATION_SET_SCHEMA) return { status: 'invalid-input', reason: 'a boundary graph and an observation set are required' };
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) return { status: 'invalid-input', reason: 'now must be an ISO timestamp' };
  const env = set.environment;
  const idx = serviceIndex(graph, env);
  const nodesById = new Map(graph.nodes.map(n => [n.id, n]));
  const outStatic = new Map();
  for (const e of graph.edges) {
    if (e.provenance !== 'static-config') continue;
    if (!outStatic.has(e.from)) outStatic.set(e.from, []);
    outStatic.get(e.from).push(e);
  }
  const staticBetween = (a, b) => graph.edges.filter(e => e.provenance === 'static-config' && e.from === a && e.to === b && COMM_RELATIONS.has(e.relation));

  const newNodes = new Map();
  const unmatched = [];
  const conflicts = [];
  const acc = new Map(); // observed/inferred edge key -> accumulator
  const touchedStatic = new Set();
  const outcomes = { ok: 0, denied: 0, error: 0 };
  const deniedStatic = new Set();

  const observedOnly = (name, tenant) => {
    if (!createObservedOnlyNodes || !name) return null;
    const n = { kind: 'service', name, environment: env, tenant: tenant ?? null, repository: null, trustZone: 'unknown', resolved: false, unresolvedReason: 'observed at runtime, not present in the static configuration', attrs: {}, declaredBy: [] };
    newNodes.set(`${n.tenant ?? ''}\n${n.name}`, n);
    return n;
  };
  const idOf = (n) => n.id ?? (0,boundary_graph/* nodeIdOf */.$z)(n);

  const bump = (key, init, o) => {
    let a = acc.get(key);
    if (!a) { a = { ...init, first: o.firstObservedAt, last: o.lastObservedAt, allSampled: true, count: 0 }; acc.set(key, a); }
    if (Date.parse(o.firstObservedAt) < Date.parse(a.first)) a.first = o.firstObservedAt;
    if (Date.parse(o.lastObservedAt) > Date.parse(a.last)) a.last = o.lastObservedAt;
    a.allSampled = a.allSampled && o.sampled;
    a.count = Math.min(TRACE_LIMITS.maxCount, a.count + o.eventCount);
    return a;
  };

  for (const o of set.observations) {
    outcomes[o.outcome] += 1;
    const srcR = o.from.service ? resolveService(idx, o.from.tenant, o.from.service, null) : { node: null, reason: 'no-source' };
    const dstR = (o.to.service || o.to.host) ? resolveService(idx, o.to.tenant, o.to.service, o.to.host) : { node: null, reason: 'no-destination' };
    let srcNode = srcR.node, dstNode = dstR.node;
    let matchedAny = false;

    // R1/R4: service pair
    if (o.from.service && (o.to.service || o.to.host)) {
      if (!srcNode && srcR.reason === 'no-service-node') srcNode = observedOnly(o.from.service, o.from.tenant);
      if (!dstNode && dstR.reason === 'no-service-node') dstNode = observedOnly(o.to.service ?? o.to.host, o.to.tenant);
      if (srcNode && dstNode) {
        const srcId = idOf(srcNode), dstId = idOf(dstNode);
        const inferred = srcR.rule === 'R4' || dstR.rule === 'R4';
        const stat = staticBetween(srcId, dstId);
        if (o.outcome === 'ok') {
          const basis = inferred ? (srcR.rule === 'R4' ? srcR.basis : dstR.basis) : null;
          const key = `${inferred ? `I:${basis}` : 'O'}\n${srcId}\n${dstId}`;
          const a = bump(key, { kind: inferred ? 'inferred' : 'runtime', relation: 'calls', from: srcId, to: dstId, rule: inferred ? 'R4' : 'R1', basis, corroborates: new Set(), contradicts: new Set() }, o);
          for (const e of stat) { if (e.pathState !== 'blocked') { a.corroborates.add(e.id); touchedStatic.add(e.id); } }
          for (const e of graph.edges.filter(x => x.provenance === 'static-config' && x.from === srcId && x.to === dstId && x.pathState === 'blocked')) { a.contradicts.add(e.id); conflicts.push({ code: 'observed-over-blocked-path', edgeId: e.id, observationId: o.id }); }
        } else {
          for (const e of stat) deniedStatic.add(e.id);
        }
        matchedAny = true;
      }
    }

    // R3: identity
    if (o.from.identity && srcNode && o.outcome === 'ok') {
      const srcId = idOf(srcNode);
      const assumes = (outStatic.get(srcId) ?? []).filter(e => e.relation === 'assumes');
      const named = assumes.find(e => { const n = nodesById.get(e.to); return n && (n.name === o.from.identity || n.name.endsWith(`/${o.from.identity}`)); });
      if (named) {
        const a = bump(`O\n${srcId}\n${named.to}\nassumes`, { kind: 'runtime', relation: 'assumes', from: srcId, to: named.to, rule: 'R3', basis: null, corroborates: new Set(), contradicts: new Set() }, o);
        a.corroborates.add(named.id); touchedStatic.add(named.id);
        matchedAny = true;
      } else if (assumes.length) {
        conflicts.push({ code: 'identity-mismatch', service: srcNode.name, observedIdentity: o.from.identity, configured: assumes.map(e => nodesById.get(e.to)?.name).sort(), observationId: o.id });
        matchedAny = true;
      }
    }

    // R2: route
    if (o.route && (o.route.host || o.route.path) && dstNode && o.outcome === 'ok') {
      const dstId = idOf(dstNode);
      const routes = graph.nodes.filter(n => n.kind === 'route' && n.environment === env && (n.tenant === null || n.tenant === (o.to.tenant ?? null)) && (!o.route.host || n.attrs.host === o.route.host || n.attrs.host === '*') && (o.route.path === null || pathUnder(n.attrs.path, o.route.path)));
      for (const r of routes) {
        const chain = (0,boundary_graph/* findPath */.Hh)(outStatic, r.id, dstId, { accept: (e) => e.relation === 'routes-to' && e.pathState !== 'blocked', maxHops: 4 });
        if (chain) {
          for (const e of chain) {
            const a = bump(`O\n${e.from}\n${e.to}\nroutes-to`, { kind: 'runtime', relation: 'routes-to', from: e.from, to: e.to, rule: 'R2', basis: null, corroborates: new Set(), contradicts: new Set() }, o);
            a.corroborates.add(e.id); touchedStatic.add(e.id);
          }
          matchedAny = true;
        }
      }
    }
    if (!matchedAny) {
      const reason = !o.to.service && !o.to.host && !o.route ? 'no-destination' : (srcR.reason && !srcNode ? srcR.reason : dstR.reason) ?? 'no-rule-matched';
      unmatched.push({ observationId: o.id, reason });
    }
  }

  // Build observed / inferred edges
  const edges = [];
  for (const [key, a] of [...acc.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    const stale = nowMs - Date.parse(a.last) > staleAfterMs;
    const e = {
      relation: a.relation, from: a.from, to: a.to, environment: env, tenant: null, effect: 'none',
      provenance: a.kind === 'runtime' ? 'runtime-observation' : 'inferred',
      confidence: a.kind === 'inferred' ? 'low' : (a.allSampled || stale ? 'medium' : 'high'),
      pathState: 'possible', observationInterval: null, completeness: null, sourceRevision: null, source: null,
      discriminator: a.kind === 'inferred' ? `R4:${a.basis}` : a.rule, crossRepo: null,
      attrs: { rule: a.rule, countBand: eventCountBand(a.count), ...(a.basis ? { basis: a.basis } : {}), ...(a.kind === 'runtime' && stale ? { stale: true } : {}) },
    };
    if (a.kind === 'runtime') {
      e.pathState = 'runtime-supported';
      e.observationInterval = { start: a.first, end: a.last };
      e.completeness = a.allSampled ? 'sampled' : 'unknown'; // never 'complete'
    }
    e.id = (0,boundary_graph/* edgeIdOf */.aI)(e);
    edges.push({ edge: e, acc: a, stale });
  }

  const staticCandidates = graph.edges.filter(e => e.provenance === 'static-config' && e.environment === env && COMM_RELATIONS.has(e.relation) && e.pathState !== 'blocked' && e.effect !== 'deny');
  const missingEdgeIds = staticCandidates.filter(e => !touchedStatic.has(e.id)).map(e => e.id).sort();

  return {
    status: 'ok',
    environment: env,
    rules: CORRELATION_RULES,
    window: set.window,
    evaluatedAt: new Date(nowMs).toISOString(),
    staleAfterMs,
    observedNodes: [...newNodes.values()],
    edges: edges.map(x => x.edge),
    corroboration: Object.fromEntries(edges.map(x => [x.edge.id, { corroborates: [...x.acc.corroborates].sort(), contradicts: [...x.acc.contradicts].sort() }])),
    conflicts,
    unmatched,
    outcomes,
    coverage: {
      // Observation is evidence of traffic, never proof that the window held all traffic.
      trafficCoverage: 'not-established',
      observed: edges.filter(x => x.edge.provenance === 'runtime-observation' && !x.acc.allSampled && !x.stale).map(x => x.edge.id).sort(),
      sampled: edges.filter(x => x.acc.allSampled && x.edge.provenance === 'runtime-observation').map(x => x.edge.id).sort(),
      stale: edges.filter(x => x.stale && x.edge.provenance === 'runtime-observation').map(x => x.edge.id).sort(),
      missingStaticEdgeIds: missingEdgeIds,
      deniedObservedStaticEdgeIds: [...deniedStatic].sort(),
    },
  };
}

/** Fold a correlation into a graph as a new validated graph. Static edges are untouched. */
function applyCorrelation(graph, correlation) {
  if (!correlation || correlation.status !== 'ok') return { ok: false, graph: null, errors: [{ code: 'RULE_VIOLATION', path: '', message: 'correlation is not usable' }] };
  const nodes = [...graph.nodes, ...correlation.observedNodes];
  const edges = [...graph.edges, ...correlation.edges];
  return (0,boundary_graph/* buildBoundaryGraph */.v4)({ repository: graph.repository, revision: graph.revision, nodes, edges, gaps: graph.gaps, sources: graph.sources });
}

// EXTERNAL MODULE: ./src/lineage/deployment/projection.js + 2 modules
var projection = __webpack_require__(83929);
;// CONCATENATED MODULE: ./src/lineage/deployment/boundaries-run.js
// boundaries-run.js: the operator entry point that builds a boundary context for scanned findings (X-308 wiring).
//
// Nothing in the default scan builds a boundary context. This is the one place that does, and it runs only when an operator
// asks for it (`agentic-security boundaries`) AND the `deployment-boundaries` feature is on (off by default). Rules it keeps:
//   - Local files only. It reads the directory it is pointed at, bounded, with no symlink followed, and optionally one scan
//     result file. It opens no socket, spawns no process, reads no credential and executes no configuration.
//   - Read-only with respect to the project. The only write is the report file the operator names with `out`, refused when the
//     target is a symlink.
//   - Off means off. With the feature off nothing is read: the result is a typed `disabled` and no file is opened.
//   - Everything that was not established is carried through: ingest gaps, unsupported syntax, files not read, trace sampling
//     and staleness, findings with no service binding. A result never says safe.
//
// Reserved names inside the directory: `service-bindings.json` (finding path prefix to service), `identities.json` (policy file
// to the identity it belongs to) and `traces.jsonl` / `traces.ndjson` (sanitized runtime trace lines). They are inputs, never
// ingested as configuration.










const BOUNDARIES_REPORT_SCHEMA = 'agentic-security/boundaries-report';
const BOUNDARIES_REPORT_VERSION = '1.0.0';
const BINDINGS_FILE = 'service-bindings.json';
const IDENTITIES_FILE = 'identities.json';
const TRACE_FILES = Object.freeze(['traces.jsonl', 'traces.ndjson']);
const MAX_FINDINGS = 5000;

const RESERVED = new Set([BINDINGS_FILE, IDENTITIES_FILE, ...TRACE_FILES]);
const CONFIG_EXTENSIONS = new Set(['.yaml', '.yml', '.json', '.tf', '.hcl', '.tfvars', '.conf', '.toml', '.xml']);
const SKIP_DIRS = new Set(['.git', 'node_modules', state_dir/* STATE_DIR_NAME */.Ky]);
const MAX_WALK_ENTRIES = 5000;

/** List candidate configuration files under `dir`, relative and sorted. Symlinks are never followed or listed. */
function listConfigFiles(dir) {
  const found = [];
  const skipped = { symlinks: 0, overLimit: false };
  let seen = 0;
  const walk = (d, rel) => {
    let entries;
    try { entries = external_node_fs_.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (++seen > MAX_WALK_ENTRIES) { skipped.overLimit = true; return; }
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.symlinks += 1; continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(external_node_path_.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (!rel && RESERVED.has(e.name)) continue;
      if (CONFIG_EXTENSIONS.has(external_node_path_.extname(e.name).toLowerCase())) found.push(r);
    }
  };
  walk(dir, '');
  return { files: found.sort(), skipped };
}

function readJsonFile(file, maxBytes, what) {
  const r = (0,bounded_io/* readFileBounded */.Y1)(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `${what}: ${r.reason}` };
  try { return { ok: true, value: JSON.parse(r.text) }; } catch (e) { return { ok: false, reason: `${what} is not valid JSON (${String(e.message).split('\n')[0]})` }; }
}

/**
 * Read the findings of a scan result file. A sibling `.sig` that exists must verify; a result with no signature is read and
 * labelled unverified.
 */
function readScanFindings(file, { maxBytes, verify } = {}) {
  const r = (0,bounded_io/* readFileBounded */.Y1)(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `scan result: ${r.reason}`, findings: [], integrity: 'unreadable' };
  let integrity = 'unsigned';
  if (typeof verify === 'function') {
    const v = verify(r.text, `${file}.sig`);
    if (v === false) return { ok: false, reason: 'the scan result has a signature that does not verify; it is not used', findings: [], integrity: 'signature-mismatch' };
    if (v === true) integrity = 'verified';
  }
  let doc;
  try { doc = JSON.parse(r.text); } catch (e) { return { ok: false, reason: `scan result is not valid JSON (${String(e.message).split('\n')[0]})`, findings: [], integrity }; }
  const list = Array.isArray(doc) ? doc : doc?.findings;
  if (!Array.isArray(list)) return { ok: false, reason: 'scan result has no findings array', findings: [], integrity };
  return { ok: true, reason: null, findings: list.filter((f) => f && typeof f === 'object' && !Array.isArray(f)), integrity };
}

/**
 * Build a boundary graph from a directory of deployment sources and attach a context to each finding.
 *
 * @param {object} o
 * @param {object} o.config        resolveAssuranceConfig() result (the feature gate)
 * @param {string} o.from          directory with configuration, optional traces, bindings and identities
 * @param {string} [o.environment] default 'prod'
 * @param {string|null} [o.repository]
 * @param {string|null} [o.revision]  exact 40/64 hex commit the files were read at
 * @param {string|null} [o.findingsFile]  a scan result (last-scan.json)
 * @param {object[]|null} [o.findings]     findings already in memory (an evaluation passes these instead of a file)
 * @param {Function} [o.verifySignature]  (body, sigFile) => true | false | null
 * @param {string} [o.now]         ISO time used to judge trace staleness; defaults to the current time
 * @returns {object} typed result; `status` is ok | disabled | blocked | unsupported | error. Never throws.
 */
function runBoundaries({ config, from, environment = 'prod', repository = null, revision = null, findingsFile = null, findings: suppliedFindings = null, verifySignature, now, action = null } = {}) {
  const gate = (0,assurance_config/* featureStatus */.FX)(config, ingest/* DEPLOYMENT_FEATURE */.H2);
  if (gate.status !== 'ok') return { ...gate, report: null };
  const limits = (0,assurance_config/* limitValues */.OH)(config);
  const fail = (code, reason) => (0,assurance_config/* typed */.nE)('error', code, reason, { feature: ingest/* DEPLOYMENT_FEATURE */.H2, report: null });

  if (typeof from !== 'string' || !from) return fail('invalid-input', '--from names the directory with deployment configuration');
  let root;
  try { root = external_node_fs_.realpathSync(from); if (!external_node_fs_.statSync(root).isDirectory()) throw new Error('not a directory'); } catch { return fail('invalid-input', `--from '${from}' is not a readable directory`); }

  const clock = now ?? new Date().toISOString();
  const notes = [];
  const listing = listConfigFiles(root);
  if (listing.skipped.symlinks) notes.push(`${listing.skipped.symlinks} symbolic link(s) were not followed`);
  if (listing.skipped.overLimit) notes.push(`the directory walk stopped at ${MAX_WALK_ENTRIES} entries; later files were not listed`);
  let paths = listing.files;
  if (paths.length > ingest/* MAX_INGEST_FILES */.qz) { notes.push(`${paths.length - ingest/* MAX_INGEST_FILES */.qz} configuration file(s) beyond the ${ingest/* MAX_INGEST_FILES */.qz} file limit were not read`); paths = paths.slice(0, ingest/* MAX_INGEST_FILES */.qz); }
  if (!paths.length) return fail('invalid-input', `no configuration files (${[...CONFIG_EXTENSIONS].join(', ')}) were found under '${from}'`);

  let identities = {};
  const idFile = external_node_path_.join(root, IDENTITIES_FILE);
  if (external_node_fs_.existsSync(idFile)) {
    const j = readJsonFile(idFile, limits.maxFileBytes, IDENTITIES_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!j.value || typeof j.value !== 'object' || Array.isArray(j.value)) return fail('invalid-input', `${IDENTITIES_FILE} must be an object mapping a file path to an identity`);
    identities = Object.fromEntries(Object.entries(j.value).filter(([, v]) => typeof v === 'string'));
  }
  let bindings = [];
  const bindFile = external_node_path_.join(root, BINDINGS_FILE);
  if (external_node_fs_.existsSync(bindFile)) {
    const j = readJsonFile(bindFile, limits.maxFileBytes, BINDINGS_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!Array.isArray(j.value)) return fail('invalid-input', `${BINDINGS_FILE} must be an array of { pathPrefix, service } objects`);
    bindings = j.value;
  } else notes.push(`no ${BINDINGS_FILE}: no finding can be tied to a service, so every finding reports exposure as not assessed`);

  const ingested = (0,ingest/* ingestDeploymentFiles */.Bi)({ config, root, paths, environment, repository, revision, identities });
  if (ingested.status !== 'ok') return fail(ingested.code ?? 'invalid-config', ingested.reason ?? 'ingest failed');
  let graph = ingested.graph;

  const observation = { supplied: false, accepted: 0, rejected: 0, status: 'not-supplied', coverage: null };
  const traceName = TRACE_FILES.find((n) => external_node_fs_.existsSync(external_node_path_.join(root, n)));
  if (traceName) {
    observation.supplied = true;
    const t = (0,bounded_io/* readFileBounded */.Y1)(external_node_path_.join(root, traceName), limits.maxFileBytes);
    if (t.status !== 'ok') { observation.status = 'unreadable'; notes.push(`${traceName} was not read: ${t.reason}`); }
    else {
      const imp = importTraceLines(t.text, { environment });
      if (imp.status !== 'ok') { observation.status = imp.status; notes.push(`${traceName} was not imported: ${imp.reason}`); }
      else {
        observation.accepted = imp.set.stats.accepted; observation.rejected = imp.set.stats.rejected;
        const corr = correlateObservations(graph, imp.set, { now: clock });
        if (corr.status !== 'ok') { observation.status = corr.status; notes.push(`traces were not correlated: ${corr.reason}`); }
        else {
          const applied = applyCorrelation(graph, corr);
          if (applied.ok) { graph = applied.graph; observation.status = 'correlated'; observation.coverage = corr.coverage; }
          else { observation.status = 'invalid-graph'; notes.push('correlated traces produced an invalid graph and were not applied'); }
        }
      }
    }
  }

  let findings = [];
  let integrity = 'not-supplied';
  if (Array.isArray(suppliedFindings)) {
    integrity = 'in-memory';
    findings = suppliedFindings.filter((f) => f && typeof f === 'object' && !Array.isArray(f));
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
  } else if (findingsFile) {
    const s = readScanFindings(findingsFile, { maxBytes: limits.maxFileBytes, verify: verifySignature });
    if (!s.ok) return fail('invalid-input', s.reason);
    integrity = s.integrity;
    findings = s.findings;
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
    if (integrity === 'unsigned') notes.push('the scan result carries no signature, so its integrity was not verified');
  }

  const attached = (0,projection/* attachBoundaryContext */.Nu)({ config, findings, graph, bindings, now: clock, action });
  if (attached.status !== 'ok') return { ...attached, report: null };
  const contexts = attached.findings.map((f) => f.boundaryContext).filter(Boolean);
  const rows = attached.findings.map((f) => ({
    id: f.id ?? null, stableId: f.stableId ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, vuln: f.vuln ?? null,
    ...(f.boundaryContext ? (0,projection/* boundaryFields */.Q)(f.boundaryContext) : { boundaryContext: null, boundaryView: null, notAnalyzed: 'the context could not be computed for this finding' }),
  }));
  const report = {
    schema: BOUNDARIES_REPORT_SCHEMA, schemaVersion: BOUNDARIES_REPORT_VERSION,
    feature: ingest/* DEPLOYMENT_FEATURE */.H2, environment, repository, revision,
    graph: {
      digest: graph.digest, nodeCount: graph.nodes.length, edgeCount: graph.edges.length, gapCount: graph.gaps.length,
      unresolvedNodeCount: graph.nodes.filter((n) => !n.resolved).length,
      gaps: graph.gaps.map((g) => ({ code: g.code, subject: g.subject, file: g.file ?? null, message: g.message })),
      files: ingested.files, sourceCount: graph.sources.length,
    },
    observation,
    scanResult: { supplied: Boolean(findingsFile) || integrity === 'in-memory', integrity, findingCount: findings.length },
    coverage: (0,projection/* boundaryCoverage */.V2)(contexts),
    findings: rows,
    errors: attached.errors,
    notes,
    statement: 'Configured relationships were not exercised and runtime traffic coverage is not established; a path that is not listed has not been shown to be absent.',
  };
  return (0,assurance_config/* typed */.nE)('ok', null, 'boundary contexts built from local files', { feature: ingest/* DEPLOYMENT_FEATURE */.H2, report, graph });
}

/** Text form of a report. Reuses each context's own projected text; adds nothing about safety. */
function renderBoundariesText(report) {
  const L = [];
  L.push(`Deployment boundaries (environment ${report.environment}${report.repository ? `, repository ${report.repository}` : ''})`);
  L.push(`  Graph: ${report.graph.nodeCount} node(s), ${report.graph.edgeCount} edge(s), ${report.graph.gapCount} gap(s), ${report.graph.unresolvedNodeCount} unresolved; digest ${report.graph.digest.slice(0, 12)}`);
  for (const f of report.graph.files) L.push(`    ${f.file}: ${f.adapter ?? 'not read'} (${f.status})`);
  for (const g of report.graph.gaps.slice(0, 20)) L.push(`    gap ${g.code}: ${g.subject}`);
  if (report.graph.gaps.length > 20) L.push(`    and ${report.graph.gaps.length - 20} more gap(s)`);
  L.push(`  Traces: ${report.observation.status}${report.observation.supplied ? ` (${report.observation.accepted} accepted, ${report.observation.rejected} rejected)` : ''}`);
  L.push(`  Scan result: ${report.scanResult.supplied ? `${report.scanResult.findingCount} finding(s), integrity ${report.scanResult.integrity}` : 'not supplied, so no finding was analyzed'}`);
  for (const f of report.findings) {
    L.push(`  ${f.id ?? f.stableId ?? 'finding'} ${f.file ?? ''}${f.line ? `:${f.line}` : ''} ${f.vuln ?? ''}`.trimEnd());
    for (const t of f.boundaryView?.text ?? [f.notAnalyzed ?? 'not analyzed']) L.push(`    ${t}`);
  }
  for (const line of report.coverage.lines) L.push(line);
  for (const n of report.notes) L.push(`  Note: ${n}`);
  L.push(`  ${report.statement}`);
  return `${L.join('\n')}\n`;
}


/***/ })

};
