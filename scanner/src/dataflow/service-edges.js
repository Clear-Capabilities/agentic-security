// Static service relationships (E2-07): which service calls, publishes to, or stores for which other service, read from the code.
//
// OPT-IN. Nothing here runs unless a caller passes the service roots; a single-service repository gets nothing, and no relationship is invented
// from a naming coincidence alone.
//
// WHAT AN EDGE CARRIES. Each edge says how it is known:
//   observed  both ends are literal in the code and agree (an HTTP client calling `http://orders/api/items` and an `orders` route `POST /api/items`;
//             a producer and a consumer naming the same literal topic; two services naming the same table AND the project declaring one shared database)
//   inferred  the ends match but one rests on a weaker fact (two services name the same table with no declaration that they share a database;
//             a client URL whose host comes from a configured base URL)
//   unknown   one end is dynamic (a computed topic, a URL assembled from user data) or has no counterpart: it is recorded and never connected
//
// WHAT IT NEVER SAYS. A chain is `static-observed` only when every hop is observed, `static-inferred` when the weakest hop is inferred, and
// `unproven` is reserved for a caller that supplies its own edges: this module never connects across an unknown one. No label is ever `proven`: this module reads text, it does not run the services, so ambiguity across
// a service boundary cannot be described as a demonstrated exploit chain. Traversal is bounded by hop count and a visited set, so a cycle ends.
//
// SCOPE. JavaScript, TypeScript and Python sources. HTTP (Express/Koa/Fastify-style routes, Flask/FastAPI decorators; fetch/axios/requests/got
// clients), messaging (Kafka/AMQP/Redis/NATS style publish and subscribe with a literal topic), persistence (SQL text and common collection calls).
// Serializer contracts (protobuf/JSON-schema sharing) are not read: recorded as a limit.
import { createHash } from 'node:crypto';

const EDGE_KINDS = Object.freeze(['http', 'messaging', 'persistence']);
const EVIDENCE = Object.freeze(['observed', 'inferred', 'unknown']);
export const MAX_HOPS = 6;
const RANK = { observed: 0, inferred: 1, unknown: 2 };
const id = (parts) => `svcedge:${createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 16)}`;
const posix = (p) => String(p).replace(/\\/g, '/');
const lineOf = (code, index) => code.slice(0, index).split('\n').length;

function serviceOf(file, services) {
  const f = posix(file);
  let best = null;
  for (const s of services) { const root = posix(s.root).replace(/\/$/, ''); if ((f === root || f.startsWith(`${root}/`)) && (!best || root.length > posix(best.root).length)) best = s; }
  return best;
}

const norm = (p) => `/${String(p).replace(/^https?:\/\/[^/]+/, '').replace(/[?#].*$/, '').split('/').filter(Boolean).join('/')}`;
// `/items/:id`, `/items/{id}`, `/items/<id>`, `/items/${id}` all name the same shape
// a concrete segment (`/items/42`) matches a parameter segment of a route; two concrete segments must be equal
const matchesShape = (routePath, clientPath) => { const r = shape(routePath).split('/'); const c = shape(clientPath).split('/'); return r.length === c.length && r.every((seg, i) => seg === ':p' || seg === c[i]); };
const shape = (p) => norm(p).split('/').map((seg) => (/^(?::|\{|<|\$\{)/.test(seg) ? ':p' : seg)).join('/');

// ---- extraction -------------------------------------------------------------------------------------------------------------

const ROUTE_JS = /\b(?:app|router|server|fastify|api)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['"`])(\/[^'"`]*)\2/g;
const ROUTE_PY = /@\s*(?:app|router|bp|blueprint)\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*(['"])(\/[^'"]*)\2([^)]*)\)/g;
const CLIENT_JS = /\b(fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete))?|got(?:\s*\.\s*(?:get|post|put|patch|delete))?)\s*\(\s*([`'"])([^`'"]*)\2/g;
const CLIENT_PY = /\brequests\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['"])([^'"]*)\2/g;
const CLIENT_DYN = /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete))?|requests\s*\.\s*(?:get|post|put|patch|delete)|got)\s*\(\s*([A-Za-z_$][\w$.]*)\s*[,)]/g;
const PRODUCE = /\b(?:producer|channel|publisher|pubsub|nats|client|redis|bus|queue)\s*\.\s*(?:send|publish|emit|produce|sendToQueue|xadd|lpush)\s*\(\s*(?:\{\s*topic\s*:\s*)?(['"`])([^'"`]+)\1/g;
const PRODUCE_DYN = /\b(?:producer|channel|publisher|pubsub|nats|bus|queue)\s*\.\s*(?:send|publish|emit|produce|sendToQueue)\s*\(\s*(?:\{\s*topic\s*:\s*)?([A-Za-z_$][\w$.]*)\s*[,})]/g;
const CONSUME = /\b(?:consumer|channel|subscriber|pubsub|nats|bus|queue|client)\s*\.\s*(?:subscribe|consume|on|psubscribe|xread|brpop)\s*\(\s*(?:\{\s*topic\s*:\s*)?(['"`])([^'"`]+)\1/g;
const SQL_WRITE = /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?([A-Za-z_][\w.]*)/gi;
const SQL_READ = /\bSELECT\b[^;]{0,300}?\bFROM\s+[`"']?([A-Za-z_][\w.]*)/gi;
const COLL_WRITE = /\b(?:db|database|mongo)\s*\.\s*(?:collection\s*\(\s*['"`]([\w.-]+)['"`]\s*\)|([A-Za-z_]\w*))\s*\.\s*(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|save|create|insert|update|remove)\s*\(/g;
const COLL_READ = /\b(?:db|database|mongo)\s*\.\s*(?:collection\s*\(\s*['"`]([\w.-]+)['"`]\s*\)|([A-Za-z_]\w*))\s*\.\s*(?:find|findOne|findMany|findById|get|select|aggregate|count)\s*\(/g;
const DB_URL = /\b(DATABASE_URL|DB_URL|MONGO_URL|MONGODB_URI|POSTGRES_URL|REDIS_URL)\b/g;

function* matches(re, code) { re.lastIndex = 0; let m; while ((m = re.exec(code))) yield m; }

/** @returns {{routes:object[], clients:object[], produces:object[], consumes:object[], writes:object[], reads:object[], dbRefs:string[], unknown:object[]}} */
export function extractFacts(file, code) {
  const out = { routes: [], clients: [], produces: [], consumes: [], writes: [], reads: [], dbRefs: [], unknown: [] };
  const py = /\.py$/.test(file);
  const at = (m) => lineOf(code, m.index);
  for (const m of matches(py ? ROUTE_PY : ROUTE_JS, code)) {
    let method = m[1].toUpperCase();
    if (py && method === 'ROUTE') { const mm = /methods\s*=\s*\[\s*['"](\w+)['"]/.exec(m[4] || ''); method = mm ? mm[1].toUpperCase() : 'GET'; }
    out.routes.push({ method, path: m[3], file, line: at(m) });
  }
  for (const m of matches(py ? CLIENT_PY : CLIENT_JS, code)) {
    const target = py ? m[3] : m[3];
    // `fetch(url, { method: 'POST' })` names its verb in the options object; `axios.post` and `requests.post` in the callee
    const optionVerb = /\bmethod\s*:\s*['"`](\w+)['"`]/.exec(code.slice(m.index, m.index + 300));
    const verb = py ? m[1].toUpperCase() : ((/\.\s*(get|post|put|patch|delete)/.exec(m[1]) || [null, optionVerb ? optionVerb[1] : 'GET'])[1]).toUpperCase();
    if (/^https?:\/\//.test(target) || /^\$\{[^}]+\}\//.test(target)) out.clients.push({ method: verb, url: target, file, line: at(m), literalHost: /^https?:\/\/[^/${]+/.test(target) });
  }
  for (const m of matches(CLIENT_DYN, code)) out.unknown.push({ kind: 'http', file, line: at(m), reason: `client URL comes from \`${m[1]}\`, not a literal` });
  for (const m of matches(PRODUCE, code)) out.produces.push({ topic: m[2], file, line: at(m) });
  for (const m of matches(PRODUCE_DYN, code)) out.unknown.push({ kind: 'messaging', file, line: at(m), reason: `topic comes from \`${m[1]}\`, not a literal` });
  for (const m of matches(CONSUME, code)) out.consumes.push({ topic: m[2], file, line: at(m) });
  for (const m of matches(SQL_WRITE, code)) out.writes.push({ table: m[1].toLowerCase(), file, line: at(m) });
  for (const m of matches(SQL_READ, code)) out.reads.push({ table: m[1].toLowerCase(), file, line: at(m) });
  for (const m of matches(COLL_WRITE, code)) out.writes.push({ table: String(m[1] || m[2]).toLowerCase(), file, line: at(m) });
  for (const m of matches(COLL_READ, code)) out.reads.push({ table: String(m[1] || m[2]).toLowerCase(), file, line: at(m) });
  for (const m of matches(DB_URL, code)) out.dbRefs.push(m[1]);
  return out;
}

/**
 * @param {Record<string,string>} fileContents repository-relative path -> source
 * @param {{services:{name:string, root:string, hosts?:string[]}[], sharedDatabases?:{name?:string, services:string[], tables?:string[]}[]}} opts
 *   `services` is REQUIRED: without it nothing is inferred. `hosts` are the names other services use to reach this one.
 *   `sharedDatabases` is the declaration that makes a persistence edge observed rather than inferred.
 */
export function buildServiceEdges(fileContents, opts = {}) {
  const services = (opts.services || []).filter((s) => s && s.name && s.root);
  if (services.length < 2) return { edges: [], unknown: [], services: services.map((s) => s.name), limits: LIMITS, optedIn: false, note: 'fewer than two services declared: no service relationships are inferred' };
  const facts = new Map(services.map((s) => [s.name, { routes: [], clients: [], produces: [], consumes: [], writes: [], reads: [], dbRefs: new Set(), unknown: [] }]));
  for (const [file, code] of Object.entries(fileContents || {}).sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (typeof code !== 'string' || !/\.(?:[cm]?[jt]sx?|py)$/.test(file)) continue;
    const svc = serviceOf(file, services);
    if (!svc) continue;
    const f = extractFacts(posix(file), code);
    const acc = facts.get(svc.name);
    for (const k of ['routes', 'clients', 'produces', 'consumes', 'writes', 'reads', 'unknown']) acc[k].push(...f[k].map((x) => ({ ...x, service: svc.name })));
    for (const d of f.dbRefs) acc.dbRefs.add(d);
  }
  const hostsOf = (s) => new Set([s.name, ...(s.hosts || [])].map((h) => h.toLowerCase()));
  const edges = []; const unknown = [];
  for (const [name, f] of facts) for (const u of f.unknown) unknown.push({ service: name, ...u, evidence: 'unknown' });

  // HTTP: a client URL names a host and a path; the host picks the service, the method and path shape pick the route
  for (const [from, f] of facts) for (const c of f.clients) {
    const hm = /^https?:\/\/([^/:${]+)/.exec(c.url);
    const host = hm ? hm[1].toLowerCase() : null;
    const target = host ? services.find((s) => s.name !== from && hostsOf(s).has(host)) : null;
    if (!target) { unknown.push({ service: from, kind: 'http', file: c.file, line: c.line, reason: host ? `host ${host} is not a declared service` : 'the host is configured at run time', evidence: 'unknown' }); continue; }
    const route = facts.get(target.name).routes.find((r) => (r.method === c.method || r.method === 'ALL') && matchesShape(r.path, c.url));
    if (!route) { unknown.push({ service: from, kind: 'http', file: c.file, line: c.line, reason: `${target.name} has no ${c.method} route matching ${norm(c.url)}`, evidence: 'unknown' }); continue; }
    edges.push({ id: id(['http', from, c.file, c.method, shape(c.url), target.name, route.file]), kind: 'http', from: { service: from, file: c.file, line: c.line }, to: { service: target.name, file: route.file, line: route.line }, via: { method: c.method, path: shape(route.path) }, evidence: 'observed', basis: 'a literal client URL and a route with the same method and path shape' });
  }
  // Messaging: the same literal topic on a producer and a consumer in different services
  for (const [from, f] of facts) for (const p of f.produces) {
    const consumers = [...facts].filter(([n]) => n !== from).flatMap(([n, g]) => g.consumes.filter((c) => c.topic === p.topic).map((c) => ({ ...c, service: n })));
    if (!consumers.length) { unknown.push({ service: from, kind: 'messaging', file: p.file, line: p.line, reason: `no other service consumes topic "${p.topic}"`, evidence: 'unknown' }); continue; }
    for (const c of consumers) edges.push({ id: id(['messaging', from, p.file, p.topic, c.service, c.file]), kind: 'messaging', from: { service: from, file: p.file, line: p.line }, to: { service: c.service, file: c.file, line: c.line }, via: { topic: p.topic }, evidence: 'observed', basis: 'the same literal topic is produced and consumed' });
  }
  // Persistence: one service writes a table another reads
  const shared = (opts.sharedDatabases || []).map((d) => ({ services: new Set(d.services), tables: d.tables ? new Set(d.tables.map((t) => t.toLowerCase())) : null }));
  for (const [from, f] of facts) for (const w of f.writes) for (const [to, g] of facts) {
    if (to === from) continue;
    for (const r of g.reads.filter((x) => x.table === w.table)) {
      const declared = shared.some((d) => d.services.has(from) && d.services.has(to) && (!d.tables || d.tables.has(w.table)));
      edges.push({ id: id(['persistence', from, w.file, w.table, to, r.file]), kind: 'persistence', from: { service: from, file: w.file, line: w.line }, to: { service: to, file: r.file, line: r.line }, via: { table: w.table }, evidence: declared ? 'observed' : 'inferred', basis: declared ? 'both services use the table and the project declares them as sharing a database' : 'both services name the table, but nothing declares that they share a database' });
    }
  }
  edges.sort((a, b) => (a.id < b.id ? -1 : 1));
  unknown.sort((a, b) => (a.service + a.file + a.line < b.service + b.file + b.line ? -1 : 1));
  return { edges, unknown, services: services.map((s) => s.name), limits: LIMITS, optedIn: true };
}

const LIMITS = Object.freeze([
  'only JavaScript, TypeScript and Python sources are read',
  'a topic, URL host or table assembled at run time is recorded as unknown and never connected',
  'serializer contracts (protobuf, JSON schema) are not read, so a shared message shape is not an edge',
  'an edge says two services are related in the code; it does not say attacker data crosses it. That needs a finding on each side',
  'no chain is ever labelled proven: this module reads text and does not run the services',
]);

/**
 * Bounded breadth-first trace from a service. Each path carries the weakest evidence on it. A path through an inferred edge is
 * `static-inferred`; the label `static-observed` needs every hop observed; nothing is `proven`.
 */
export function traceFrom(graph, start, { maxHops = MAX_HOPS, maxPaths = 200 } = {}) {
  const hops = Math.max(1, Math.min(MAX_HOPS, maxHops));
  const byFrom = new Map();
  for (const e of graph.edges) { if (!byFrom.has(e.from.service)) byFrom.set(e.from.service, []); byFrom.get(e.from.service).push(e); }
  const out = []; let truncated = false;
  const queue = [{ at: start, path: [], seen: new Set([start]) }];
  while (queue.length) {
    const cur = queue.shift();
    if (cur.path.length >= hops) { if ((byFrom.get(cur.at) || []).length) truncated = true; continue; }
    for (const e of byFrom.get(cur.at) || []) {
      if (cur.seen.has(e.to.service)) continue;
      const path = [...cur.path, e];
      if (out.length >= maxPaths) { truncated = true; break; }
      const weakest = path.reduce((w, x) => (RANK[x.evidence] > RANK[w] ? x.evidence : w), 'observed');
      out.push({ services: [start, ...path.map((x) => x.to.service)], edges: path.map((x) => x.id), kinds: path.map((x) => x.kind), evidence: weakest, label: weakest === 'observed' ? 'static-observed' : weakest === 'inferred' ? 'static-inferred' : 'unproven' });
      queue.push({ at: e.to.service, path, seen: new Set([...cur.seen, e.to.service]) });
    }
  }
  return { start, paths: out, truncated, maxHops: hops };
}
