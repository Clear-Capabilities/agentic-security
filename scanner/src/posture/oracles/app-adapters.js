// Application-level oracle adapters (verified-remediation PRD FR-05, FR-06, FR-12): a REAL HTTP application over REAL persistent state.
//
// The two earlier routes to an application verdict were a decision function called in isolation (`authorization-decision`) and an
// in-memory store the harness owns (`business-state`). Neither starts the application or touches its database. These adapters do:
//
//   - the application's own module is imported and its factory called with an open node:sqlite database (a real SQLite engine, built
//     into Node 24) on a file in the run's workspace, created fresh from the declared schema and seed for every run;
//   - every declared request is a real HTTP/1.1 request, serialised by Node's HTTP client and parsed by Node's HTTP server, carried over
//     an in-memory duplex pair. No socket is opened, so the boundary's network denial stays in force and nothing can be reached;
//   - after the whole process tree is dead, the VERIFIER opens the database file read-only and evaluates the declared state checks
//     itself. A status code never decides: a 403 that still wrote another tenant's row is a violation.
//   - optional `network` (version 2): every outbound connection the application opens is recorded at the connection layer with the
//     request that caused it, resolved by the declared DNS answers (a host may rebind), and served by a declared host or refused. A
//     connection the declared policy forbids is a violation (`forbid.connections`), whatever the response; a destination the
//     declaration does not model makes the run inconclusive. No socket is opened.
//   - optional `files` (version 2): a real directory tree with planted files outside an allowed root and real symbolic links; the
//     factory receives `{ db, filesRoot }`. A planted file's secret in a response is the violation.
//   - optional `credential` on a state check (version 3): the verifier judges a stored password value itself (plaintext, fast digest,
//     an approved KDF recomputed from the password, salting). See the section on stored credentials below.
//   - optional `env` and route `requireHeaders` (version 4): declared environment values set before the application loads (a credential
//     wired from the environment), and a declared host that serves a route only to a request presenting exact headers (401 otherwise),
//     so a control can show the application uses the replacement credential and not a hardcoded one.
//
//   application-security   hypothesis: an attack request reaches an effect it must not (a planted per-run secret appears in its
//                          response, or a state check guarding it does not hold). Confirmed when any attack violates; refuted when
//                          none does AND every control request met its expectation (the application demonstrably worked);
//                          otherwise inconclusive. A deny-everything patch therefore cannot refute: its controls fail.
//   application-behaviour  hypothesis: legitimate behaviour regressed. Confirmed when a control request's expectation or a control
//                          state check fails; refuted when all hold.
//
// Secrets: a seed value or an expectation may contain `{{secret:<name>}}`; prepare() replaces it with a value derived from the per-run
// token, which the target cannot know in advance. Expectations and checks are DECLARATIVE (a closed set of operators); a state check is
// one read-only SELECT executed by the verifier, never code supplied by the target or the contract.
//
// Limits, stated: the application must be importable from the workspace with no packages outside Node's standard library (the
// workspace holds only the declared files); the factory receives the database (dependency injection) rather than opening its own; one
// process, requests sent in the declared order (no concurrency is claimed); Express itself is not executed in this repository (an
// Express application is a request listener with this same signature, but no Express fixture runs here).
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { defineOracle } from './oracle.js';

const SECRET_RE = /\{\{secret:([a-z][a-z0-9-]{0,31})\}\}/g;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const isId = (s) => typeof s === 'string' && /^[A-Za-z_$][\w$-]{0,63}$/.test(s);
const isStr = (s, max = 2000) => typeof s === 'string' && s.length <= max;

const secretValue = (token, name) => `S-${crypto.createHash('sha256').update(`${token}:${name}`).digest('hex').slice(0, 24)}`;
const subst = (v, token) => (typeof v === 'string' ? v.replace(SECRET_RE, (_, n) => secretValue(token, n)) : v);
const deep = (v, token) => (Array.isArray(v) ? v.map((x) => deep(x, token)) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x, token)])) : subst(v, token));

// The verifier-authored WSGI driver for the Python runtime. Part of the harness text, so the harness digest covers it.
const PY_DRIVER_SRC = "import io, json, os, sqlite3, sys, urllib.parse, importlib.util\ncfg = json.loads(sys.stdin.read())\nout = {\"responses\": {}}\ndef done():\n    with open(\"__oracle_py_out.json\", \"w\") as f:\n        json.dump(out, f)\n    sys.exit(0)\ntry:\n    sys.path.insert(0, os.getcwd())\n    spec = importlib.util.spec_from_file_location(\"app_under_test\", os.path.join(os.getcwd(), cfg[\"entry\"]))\n    mod = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(mod)\n    factory = getattr(mod, cfg[\"export\"])\n    db = sqlite3.connect(\"__oracle_app.db\", isolation_level=None)\n    app = factory(db)\n    if not callable(app):\n        raise TypeError(\"the factory did not return a WSGI application\")\nexcept SystemExit:\n    raise\nexcept BaseException as e:\n    out[\"loadFailed\"] = True\n    out[\"loadError\"] = str(e)[:160]\n    done()\nfor r in cfg[\"requests\"]:\n    path, _, qs = r[\"path\"].partition(\"?\")\n    b = r.get(\"body\")\n    body = b\"\" if b is None else (b if isinstance(b, str) else json.dumps(b)).encode()\n    env = {\"REQUEST_METHOD\": r[\"method\"], \"PATH_INFO\": urllib.parse.unquote(path), \"QUERY_STRING\": qs, \"SERVER_NAME\": \"app.local\", \"SERVER_PORT\": \"80\",\n           \"SERVER_PROTOCOL\": \"HTTP/1.1\", \"SCRIPT_NAME\": \"\", \"CONTENT_LENGTH\": str(len(body)), \"wsgi.version\": (1, 0), \"wsgi.url_scheme\": \"http\",\n           \"wsgi.input\": io.BytesIO(body), \"wsgi.errors\": sys.stderr, \"wsgi.multithread\": False, \"wsgi.multiprocess\": False, \"wsgi.run_once\": False}\n    if body:\n        env[\"CONTENT_TYPE\"] = \"application/json\"\n    for k, v in (r.get(\"headers\") or {}).items():\n        key = k.upper().replace(\"-\", \"_\")\n        env[key if key in (\"CONTENT_TYPE\", \"CONTENT_LENGTH\") else \"HTTP_\" + key] = str(v)\n    st = {}\n    def start_response(status, headers, exc_info=None):\n        st[\"status\"] = int(str(status).split(\" \", 1)[0])\n        st[\"headers\"] = headers\n    try:\n        chunks = app(env, start_response)\n        data = b\"\".join(chunks)[:8192]\n        if hasattr(chunks, \"close\"):\n            chunks.close()\n        ct = {str(k).lower(): str(v) for k, v in st.get(\"headers\", [])}.get(\"content-type\", \"\")\n        out[\"responses\"][r[\"id\"]] = {\"status\": st.get(\"status\"), \"contentType\": ct, \"body\": data.decode(\"utf-8\", \"replace\")}\n    except BaseException as e:\n        out[\"responses\"][r[\"id\"]] = {\"error\": str(e)[:160]}\ntry:\n    db.close()\nexcept BaseException:\n    pass\nout[\"completed\"] = True\ndone()\n";

const APP_HARNESS = `import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { duplexPair } from 'node:stream';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
const INPUT = __INPUT__;
const ENTRY = __ENTRY__;
const PY_DRIVER = ${JSON.stringify(PY_DRIVER_SRC)};
const out = { responses: {} };
const text = (e) => String((e && e.message) || e).slice(0, 160);
function finish(extra) { Object.assign(out, extra); try { fs.writeFileSync('__oracle_result.json', JSON.stringify(out)); } catch {} process.exit(0); }
let db;
try {
  db = new DatabaseSync('__oracle_app.db');
  db.exec(INPUT.schemaSql);
  for (const s of INPUT.seed) db.prepare(s.sql).run(...s.params);
} catch (e) { finish({ setupFailed: true, setupError: text(e) }); }
// Python runtime: the verifier-authored driver below runs the application's WSGI callable for every declared request (a real WSGI
// environ, no HTTP server), over the same database file, under an isolated interpreter (-I: no user site, no PYTHONPATH).
if (INPUT.runtime === 'python') {
  try { db.close(); } catch {}
  if (!INPUT.python) finish({ runtimeMissing: true, loadFailed: true, loadError: 'no python3 interpreter was found by the verifier' });
  const { spawnSync } = await import('node:child_process');
  fs.writeFileSync('__oracle_py_driver.py', PY_DRIVER);
  const r = spawnSync(INPUT.python, ['-I', '__oracle_py_driver.py'], { input: JSON.stringify({ entry: ENTRY, export: INPUT.export, requests: INPUT.requests }), encoding: 'utf8', timeout: INPUT.requestTimeoutMs * (INPUT.requests.length + 2), maxBuffer: 1 << 20, env: {} });
  let got = null;
  try { got = JSON.parse(fs.readFileSync('__oracle_py_out.json', 'utf8')); } catch {}
  if (!got) finish({ loadFailed: true, loadError: r.error ? text(r.error) : 'the python driver reported nothing (exit ' + r.status + ')' });
  if (got.loadFailed) finish({ loadFailed: true, loadError: String(got.loadError || '').slice(0, 160) });
  out.responses = got.responses && typeof got.responses === 'object' ? got.responses : {};
  finish({ completed: got.completed === true });
}
// Filesystem: a real directory tree in the workspace, built before the application loads. The application is told its allowed root;
// files outside it hold planted secrets, and declared symbolic links are real links.
const FS_DIR = path.resolve('__oracle_fs');
let filesRoot = null;
if (INPUT.files) {
  try {
    for (const [rel, content] of Object.entries(INPUT.files.tree)) { const abs = path.join(FS_DIR, rel); fs.mkdirSync(path.dirname(abs), { recursive: true }); fs.writeFileSync(abs, content); }
    for (const [rel, target] of Object.entries(INPUT.files.links || {})) { const abs = path.join(FS_DIR, rel); fs.mkdirSync(path.dirname(abs), { recursive: true }); fs.symlinkSync(target, abs); }
    filesRoot = path.join(FS_DIR, INPUT.files.root);
    fs.mkdirSync(filesRoot, { recursive: true });
  } catch (e) { finish({ setupFailed: true, setupError: text(e) }); }
}
// Network: every outbound connection the application opens is recorded at the connection layer (net, tls, the HTTP agents and raw
// sockets) with the request that caused it. A declared host resolves by the declared DNS answers (one per resolution, the last
// repeating, so a host can rebind); a connection to a declared host with routes is served by a verifier-declared HTTP server over an
// in-memory duplex; anything else is refused. No socket is opened, so the boundary's network denial stays in force.
let current = null;
const connections = []; const lookups = [];
if (INPUT.network) {
  const N = INPUT.network;
  const hostsByName = new Map(N.hosts.map((h) => [h.name.toLowerCase(), h]));
  const resolved = new Map();
  const mapped = (a) => { if (!a) return a; const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(a); if (m) { const x = parseInt(m[1], 16); const y = parseInt(m[2], 16); return [x >> 8, x & 255, y >> 8, y & 255].join('.'); } return a.toLowerCase().startsWith('::ffff:') && net.isIPv4(a.slice(7)) ? a.slice(7) : a; };
  const resolveName = (name) => {
    const n = String(name || 'localhost').toLowerCase().replace(/^\\[|\\]$/g, '').replace(/\\.$/, '');
    if (net.isIP(n)) return mapped(n);
    const h = hostsByName.get(n); if (!h) return null;
    const i = resolved.get(n) || 0; resolved.set(n, i + 1);
    return mapped(h.addresses[Math.min(i, h.addresses.length - 1)]);
  };
  const servers = N.hosts.filter((h) => h.routes && h.routes.length).map((h) => ({ h, addrs: h.addresses.map(mapped), port: h.port || 80, server: http.createServer((req, res) => {
    const route = h.routes.find((r) => r.path === req.url);
    if (!route) { res.writeHead(404); res.end('not found'); return; }
    // a route may require exact request headers (a credential the application must present); anything else is refused with 401
    if (route.requireHeaders && Object.entries(route.requireHeaders).some(([k, v]) => String(req.headers[k.toLowerCase()] || '') !== v)) { res.writeHead(401); res.end('unauthorized'); return; }
    res.writeHead(route.status || 200, route.headers || {}); res.end(route.body || '');
  }) }));
  const record = (host, port, isTls, given) => { const address = given !== undefined ? mapped(given) : resolveName(host); const e = { request: current, host: String(host || '').slice(0, 253), port: Number(port) || null, address, tls: !!isTls }; if (connections.length < 200) connections.push(e); return e; };
  const sockLike = (s, e) => { s.setNoDelay = () => s; s.setKeepAlive = () => s; s.setTimeout = () => s; s.ref = () => s; s.unref = () => s; s.remoteAddress = e.address || undefined; s.remotePort = e.port || undefined; s.connecting = true; return s; };
  const refuse = (e, cb) => {
    const [client] = duplexPair(); sockLike(client, e);
    process.nextTick(() => { const err = Object.assign(new Error(e.address ? 'connect ECONNREFUSED ' + e.address : 'getaddrinfo ENOTFOUND ' + e.host), { code: e.address ? 'ECONNREFUSED' : 'ENOTFOUND' }); client.destroy(err); });
    return client;
  };
  const opts = (args) => { const a = args[0]; if (a && typeof a === 'object') return { o: a, cb: typeof args[1] === 'function' ? args[1] : null }; const o = { port: a }; if (typeof args[1] === 'string') o.host = args[1]; return { o, cb: args.find((x) => typeof x === 'function') || null }; };
  const fakeConnect = (...args) => {
    const { o, cb } = opts(args);
    if (o.path) { if (connections.length < 200) connections.push({ request: current, host: 'unix:' + String(o.path).slice(0, 200), port: null, address: null, tls: false }); return refuse({ address: null, host: 'unix socket' }, cb); }
    const port = Number(o.port) || 80;
    const host = o.host || o.hostname;
    const [client, srv] = duplexPair();
    sockLike(client, { address: null, port });
    const wire = (e) => {
      client.remoteAddress = e.address || undefined;
      const up = e.address && servers.find((s) => s.port === port && s.addrs.includes(e.address));
      if (!up) { const err = Object.assign(new Error(e.address ? 'connect ECONNREFUSED ' + e.address : 'getaddrinfo ENOTFOUND ' + e.host), { code: e.address ? 'ECONNREFUSED' : 'ENOTFOUND' }); client.destroy(err); return; }
      up.server.emit('connection', srv);
      client.connecting = false; client.emit('connect'); client.emit('ready'); if (cb) cb();
    };
    // An application-supplied lookup (address pinning against DNS rebinding) decides the address, as it would on a real socket.
    if (typeof o.lookup === 'function' && !net.isIP(String(host || '').replace(/^\\[|\\]$/g, ''))) {
      try { o.lookup(host, { family: o.family || 0, all: false }, (err, address) => wire(record(host, port, false, err ? null : (Array.isArray(address) ? address[0] && address[0].address : address) || null))); }
      catch { process.nextTick(() => wire(record(host, port, false, null))); }
    } else { const e = record(host, port, false); process.nextTick(() => wire(e)); }
    return client;
  };
  const fakeTls = (...args) => { const { o, cb } = opts(args); return refuse(record(o.host || o.servername, Number(o.port) || 443, true), cb); };
  net.connect = fakeConnect; net.createConnection = fakeConnect;
  net.Socket.prototype.connect = function (...args) { const { o } = opts(args); const e = record(o.host, o.port, false); process.nextTick(() => this.destroy(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))); void e; return this; };
  tls.connect = fakeTls;
  // The agents' callback is (err, socket), not a connect listener: return the socket and let the agent take it from there.
  http.Agent.prototype.createConnection = function (o) { return fakeConnect(o); };
  https.Agent.prototype.createConnection = function (o) { return fakeTls(o); };
  const lookupOne = (host) => { const a = resolveName(host); if (lookups.length < 200) lookups.push({ request: current, host: String(host).slice(0, 253), address: a }); return a; };
  const nf = (host) => Object.assign(new Error('getaddrinfo ENOTFOUND ' + host), { code: 'ENOTFOUND' });
  dns.lookup = (host, o, cb) => { if (typeof o === 'function') { cb = o; o = {}; } const a = lookupOne(host); process.nextTick(() => { if (!a) return cb(nf(host)); const fam = net.isIP(a); if (o && o.all) cb(null, [{ address: a, family: fam }]); else cb(null, a, fam); }); };
  dns.promises.lookup = async (host, o) => { const a = lookupOne(host); if (!a) throw nf(host); const fam = net.isIP(a); return o && o.all ? [{ address: a, family: fam }] : { address: a, family: fam }; };
  const res4 = (host) => { const a = lookupOne(host); return a && net.isIPv4(a) ? [a] : null; };
  dns.resolve4 = (host, o, cb) => { if (typeof o === 'function') cb = o; const r = res4(host); process.nextTick(() => (r ? cb(null, r) : cb(nf(host)))); };
  dns.promises.resolve4 = async (host) => { const r = res4(host); if (!r) throw nf(host); return r; };
  // Named ESM imports of built-in modules (import { lookup } from 'node:dns') are bindings, not property reads: sync them.
  syncBuiltinESMExports();
}
// Declared environment values (version 4): set before the application loads, so a credential wired from the environment is present.
for (const [k, v] of Object.entries(INPUT.env || {})) process.env[k] = v;
let mod;
try { mod = await import('./' + ENTRY); } catch (e) { finish({ loadFailed: true, loadError: text(e) }); }
const factory = mod && (mod[INPUT.export] || (mod.default && mod.default[INPUT.export]));
if (typeof factory !== 'function') finish({ loadFailed: true, loadError: 'the factory export is not a function' });
let handler;
try { handler = await factory(filesRoot ? { db, filesRoot } : { db }); } catch (e) { finish({ loadFailed: true, loadError: text(e) }); }
if (typeof handler !== 'function') finish({ loadFailed: true, loadError: 'the factory did not return a request listener' });
const server = http.createServer(handler);
function send(r) {
  return new Promise((resolve) => {
    const [client, srv] = duplexPair();
    server.emit('connection', srv);
    const ENC_ABS = '%7B%7Bfs%3Aabs%7D%7D';
    if (INPUT.files) r = { ...r, path: r.path.split(ENC_ABS).join(encodeURIComponent(FS_DIR)).split('{{fs:abs}}').join(FS_DIR), ...(r.body !== undefined ? { body: JSON.parse(JSON.stringify(r.body).split('{{fs:abs}}').join(FS_DIR.replace(/\\\\/g, '\\\\\\\\'))) } : {}) };
    const body = r.body === undefined ? null : (typeof r.body === 'string' ? r.body : JSON.stringify(r.body));
    const headers = { ...(r.headers || {}) };
    if (body !== null && !Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json';
    if (body !== null) headers['content-length'] = Buffer.byteLength(body);
    let done = false;
    const end = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => end({ error: 'timeout' }), INPUT.requestTimeoutMs);
    const req = http.request({ method: r.method, path: r.path, headers, createConnection: () => client }, (res) => {
      let t = ''; res.setEncoding('utf8');
      res.on('data', (d) => { if (t.length < 8192) t += d; });
      res.on('end', () => end({ status: res.statusCode, contentType: String(res.headers['content-type'] || ''), body: t.slice(0, 8192) }));
      res.on('error', (e) => end({ error: text(e) }));
    });
    req.on('error', (e) => end({ error: text(e) }));
    if (body !== null) req.write(body);
    req.end();
  });
}
for (const r of INPUT.requests) { current = r.id; out.responses[r.id] = await send(r); }
try { db.close(); } catch {}
finish({ completed: true, ...(INPUT.network ? { connections, lookups } : {}) });
`;

/** Validation shared by both adapters. Returns a problem string or null. */
function validateAppInputs(i, { requireAttack }) {
  if (!isId(i.export)) return 'export must be an identifier';
  if (i.runtime !== undefined && !['node', 'python'].includes(i.runtime)) return "runtime must be 'node' or 'python'";
  if (!isStr(i.schemaSql, 20000) || !i.schemaSql.trim()) return 'schemaSql must be a non-empty string';
  if (!Array.isArray(i.seed) || i.seed.length > 200) return 'seed must be an array of at most 200 statements';
  for (const s of i.seed) if (!s || !isStr(s.sql, 2000) || !/^\s*INSERT\b/i.test(s.sql) || !Array.isArray(s.params) || s.params.length > 32) return 'every seed entry is one INSERT with a params array';
  if (!Array.isArray(i.requests) || i.requests.length < 1 || i.requests.length > 128) return 'requests must hold 1 to 128 entries';
  const ids = new Set();
  for (const r of i.requests) {
    if (!r || !isId(r.id) || ids.has(r.id)) return 'every request needs a unique identifier id';
    ids.add(r.id);
    if (!['control', 'attack'].includes(r.role)) return `request ${r.id}: role must be control or attack`;
    if (!METHODS.has(r.method)) return `request ${r.id}: unsupported method`;
    if (!isStr(r.path, 2000) || !r.path.startsWith('/')) return `request ${r.id}: path must start with /`;
    if (r.headers !== undefined && (typeof r.headers !== 'object' || Array.isArray(r.headers) || Object.keys(r.headers).length > 16)) return `request ${r.id}: headers must be an object of at most 16 entries`;
    if (r.role === 'control') {
      const e = r.expect || {};
      for (const k of Object.keys(e)) if (!['status', 'bodyIncludes', 'bodyExcludes'].includes(k)) return `request ${r.id}: unknown expectation '${k}'`;
      if (e.status !== undefined && (!Array.isArray(e.status) || !e.status.every((n) => Number.isInteger(n) && n >= 100 && n < 600))) return `request ${r.id}: expect.status must list status codes`;
      for (const k of ['bodyIncludes', 'bodyExcludes']) if (e[k] !== undefined && (!Array.isArray(e[k]) || !e[k].every((s) => isStr(s, 500) && s.length))) return `request ${r.id}: expect.${k} must list strings`;
    } else {
      const f = r.forbid || {};
      for (const k of Object.keys(f)) if (k !== 'secrets' && k !== 'connections') return `request ${r.id}: unknown forbidden effect '${k}'`;
      if (f.secrets !== undefined && (!Array.isArray(f.secrets) || !f.secrets.every((s) => /^[a-z][a-z0-9-]{0,31}$/.test(s)))) return `request ${r.id}: forbid.secrets must list secret names`;
      if (f.connections !== undefined && (f.connections !== true || !i.network)) return `request ${r.id}: forbid.connections must be true and needs a network declaration`;
    }
  }
  const checks = i.stateChecks || [];
  if (!Array.isArray(checks) || checks.length > 64) return 'stateChecks must be an array of at most 64';
  const cids = new Set();
  for (const c of checks) {
    if (!c || !isId(c.id) || cids.has(c.id)) return 'every state check needs a unique identifier id';
    cids.add(c.id);
    if (!['control', 'attack'].includes(c.role)) return `state check ${c.id}: role must be control or attack`;
    // one read-only SELECT, executed by the verifier on its own read-only connection
    if (!isStr(c.sql, 2000) || !/^\s*SELECT\b/i.test(c.sql) || /;\s*\S/.test(c.sql) || /\b(?:ATTACH|PRAGMA|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|VACUUM)\b/i.test(c.sql)) return `state check ${c.id}: sql must be one read-only SELECT`;
    if (!Array.isArray(c.params || []) || (c.params || []).length > 16) return `state check ${c.id}: params must be an array`;
    if (c.credential !== undefined) { const p = validateCredential(c.credential, c.id); if (p) return p; }
    else if (!('expect' in c)) return `state check ${c.id}: expect is required`;
  }
  for (const c of checks) if (c.credential?.distinctFrom !== undefined && !checks.some((x) => x.id === c.credential.distinctFrom && x.credential)) return `state check ${c.id}: credential.distinctFrom must name another credential check`;
  if ((i.network !== undefined || i.files !== undefined || i.env !== undefined) && i.runtime === 'python') return 'network, files and env declarations are supported for the node runtime only';
  if (i.env !== undefined && (!isPlain(i.env) || Object.keys(i.env).length > 16 || !Object.entries(i.env).every(([k, v]) => /^[A-Z_][A-Z0-9_]{0,63}$/.test(k) && !/^(?:NODE_|PATH$|HOME$|LD_|DYLD_)/.test(k) && isStr(v, 500)))) return 'env must map at most 16 upper-case names (not NODE_*, PATH, HOME, LD_*, DYLD_*) to strings';
  if (i.network !== undefined) { const p = validateNetwork(i.network); if (p) return p; }
  if (i.files !== undefined) { const p = validateFiles(i.files); if (p) return p; }
  if (requireAttack && !i.requests.some((r) => r.role === 'attack') && !checks.some((c) => c.role === 'attack')) return 'at least one attack request or attack state check is required';
  if (!i.requests.some((r) => r.role === 'control')) return 'at least one control request is required (it shows the application worked)';
  if (!requireAttack && i.requests.some((r) => r.role === 'attack')) return 'the behaviour oracle takes control requests only';
  return null;
}

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isHostname = (s) => typeof s === 'string' && s.length >= 1 && s.length <= 253 && s.split('.').every((l) => LABEL.test(l));
const isPlain = (o) => o && typeof o === 'object' && !Array.isArray(o);

/** A declared network: hosts with their DNS answers and served routes, a destination policy and the approved hosts. */
export function validateNetwork(n) {
  if (!isPlain(n)) return 'network must be an object';
  for (const k of Object.keys(n)) if (!['hosts', 'policy', 'approved'].includes(k)) return `network: unknown field '${k}'`;
  if (!['allowlist', 'public-only'].includes(n.policy)) return "network.policy must be 'allowlist' or 'public-only'";
  if (!Array.isArray(n.hosts) || !n.hosts.length || n.hosts.length > 16) return 'network.hosts must hold 1 to 16 hosts';
  const names = new Set();
  for (const h of n.hosts) {
    if (!isPlain(h)) return 'every network host must be an object';
    for (const k of Object.keys(h)) if (!['name', 'addresses', 'port', 'routes'].includes(k)) return `network host: unknown field '${k}'`;
    if (!isHostname(h.name) || net.isIP(h.name) || names.has(h.name)) return 'every network host needs a unique lower-case host name';
    names.add(h.name);
    if (!Array.isArray(h.addresses) || !h.addresses.length || h.addresses.length > 4 || !h.addresses.every((a) => typeof a === 'string' && net.isIP(a))) return `network host ${h.name}: addresses must list 1 to 4 IP addresses (one per successive resolution)`;
    if (h.port !== undefined && !(Number.isInteger(h.port) && h.port > 0 && h.port < 65536)) return `network host ${h.name}: port must be a port number`;
    if (h.routes !== undefined) {
      if (!Array.isArray(h.routes) || h.routes.length > 16) return `network host ${h.name}: routes must be an array of at most 16`;
      for (const r of h.routes) {
        if (!isPlain(r) || !isStr(r.path, 500) || !r.path.startsWith('/')) return `network host ${h.name}: every route needs a path starting with /`;
        for (const k of Object.keys(r)) if (!['path', 'status', 'headers', 'body', 'requireHeaders'].includes(k)) return `network host ${h.name}: unknown route field '${k}'`;
        if (r.requireHeaders !== undefined && (!isPlain(r.requireHeaders) || Object.keys(r.requireHeaders).length > 4 || !Object.entries(r.requireHeaders).every(([k, v]) => /^[a-z][a-z0-9-]{0,63}$/.test(k) && isStr(v, 500)))) return `network host ${h.name}: route requireHeaders must map at most 4 lower-case header names to strings`;
        if (r.status !== undefined && !(Number.isInteger(r.status) && r.status >= 100 && r.status < 600)) return `network host ${h.name}: route status must be a status code`;
        if (r.headers !== undefined && (!isPlain(r.headers) || Object.keys(r.headers).length > 8 || !Object.values(r.headers).every((v) => isStr(v, 500)))) return `network host ${h.name}: route headers must be at most 8 strings`;
        if (r.body !== undefined && !isStr(r.body, 2000)) return `network host ${h.name}: route body must be a string`;
      }
    }
  }
  if (!Array.isArray(n.approved) || !n.approved.every((a) => names.has(a))) return 'network.approved must list declared host names';
  if (n.policy === 'allowlist' && !n.approved.length) return 'an allowlist policy needs at least one approved host';
  return null;
}

const relOk = (r) => typeof r === 'string' && r.length > 0 && r.length <= 200 && !r.startsWith('/') && !r.includes('\0') && !r.includes('\\') && path.posix.normalize(r) === r && !r.split('/').some((s) => s === '..' || s === '.' || s.startsWith('__oracle'));

/** A declared file tree: the allowed root, the files (inside and outside it) and the symbolic links. Every path stays in the tree. */
export function validateFiles(f) {
  if (!isPlain(f)) return 'files must be an object';
  for (const k of Object.keys(f)) if (!['root', 'tree', 'links'].includes(k)) return `files: unknown field '${k}'`;
  if (!relOk(f.root)) return 'files.root must be a relative directory inside the tree';
  if (!isPlain(f.tree) || !Object.keys(f.tree).length || Object.keys(f.tree).length > 64) return 'files.tree must map 1 to 64 relative paths to their content';
  for (const [rel, c] of Object.entries(f.tree)) if (!relOk(rel) || !isStr(c, 4000)) return `files.tree: '${String(rel).slice(0, 60)}' needs a confined relative path and text content`;
  const links = f.links || {};
  if (!isPlain(links) || Object.keys(links).length > 16) return 'files.links must map at most 16 link paths to their targets';
  for (const [rel, target] of Object.entries(links)) {
    if (!relOk(rel) || typeof target !== 'string' || target.startsWith('/') || target.length > 200) return `files.links: '${String(rel).slice(0, 60)}' needs a confined path and a relative target`;
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(rel), target));
    if (resolved.startsWith('..') || resolved.startsWith('/')) return `files.links: '${rel}' must point inside the tree`;
  }
  return null;
}

// ---------------------------------------------------------------- stored credentials (version 3)
//
// A credential check reads one stored value (the first column of the first row of its SELECT) and judges it against the password the
// run used, VERIFIER-SIDE: `not-plaintext` (the password does not appear in it), `not-fast-digest` (no MD5, SHA-1 or SHA-2 digest of
// the password appears in it, hex or base64), `approved-format` (it parses as the approved format and RECOMPUTES from the password
// with at least the approved parameters: a known-vector check, not a pattern match), `distinct-from` (it differs from another check's
// stored value for the same password: salted). The only approved format in this release is scrypt as
// `scrypt$N$r$p$<salt hex>$<key hex>`, the format the deterministic password repair writes. The verifier bounds its own work: a
// stored value whose parameters exceed N 2^20, r 32 or p 16 cannot be recomputed here and does not hold.
const CREDENTIAL_PROPERTIES = Object.freeze(['not-plaintext', 'not-fast-digest', 'approved-format', 'distinct-from']);
const FAST_DIGESTS = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

function validateCredential(k, id) {
  if (!isPlain(k)) return `state check ${id}: credential must be an object`;
  for (const f of Object.keys(k)) if (!['password', 'properties', 'distinctFrom', 'approved'].includes(f)) return `state check ${id}: unknown credential field '${f}'`;
  if (!isStr(k.password, 200) || !k.password.length) return `state check ${id}: credential.password must be a string`;
  if (!Array.isArray(k.properties) || !k.properties.length || !k.properties.every((p) => CREDENTIAL_PROPERTIES.includes(p))) return `state check ${id}: credential.properties must list ${CREDENTIAL_PROPERTIES.join(', ')}`;
  if (k.properties.includes('distinct-from') !== (k.distinctFrom !== undefined)) return `state check ${id}: distinct-from and distinctFrom go together`;
  if (k.properties.includes('approved-format')) {
    const a = k.approved;
    if (!isPlain(a) || a.format !== 'scrypt') return `state check ${id}: credential.approved.format must be 'scrypt'`;
    for (const f of Object.keys(a)) if (!['format', 'minN', 'minR', 'minSaltBytes', 'minKeyBytes'].includes(f)) return `state check ${id}: unknown approved field '${f}'`;
    for (const f of ['minN', 'minR', 'minSaltBytes', 'minKeyBytes']) if (!Number.isInteger(a[f]) || a[f] < 1) return `state check ${id}: credential.approved.${f} must be a positive integer`;
  }
  return null;
}

function judgeCredential(stored, k, others) {
  const failed = [];
  const value = typeof stored === 'string' ? stored : stored == null ? null : String(stored);
  if (value === null) return ['no-stored-value'];
  const pw = k.password;
  if (k.properties.includes('not-plaintext') && value.includes(pw)) failed.push('not-plaintext');
  if (k.properties.includes('not-fast-digest')) {
    const low = value.toLowerCase();
    const hit = FAST_DIGESTS.some((a) => { const d = crypto.createHash(a).update(pw, 'utf8').digest(); return low.includes(d.toString('hex')) || value.includes(d.toString('base64').replace(/=+$/, '')); });
    if (hit) failed.push('not-fast-digest');
  }
  if (k.properties.includes('approved-format')) {
    const a = k.approved;
    const m = /^scrypt\$(\d{1,8})\$(\d{1,3})\$(\d{1,3})\$([0-9a-f]{2,256})\$([0-9a-f]{2,512})$/i.exec(value);
    let ok = false;
    if (m) {
      const [N, r, p] = [Number(m[1]), Number(m[2]), Number(m[3])];
      const salt = Buffer.from(m[4], 'hex'); const key = Buffer.from(m[5], 'hex');
      const pow2 = N > 1 && (N & (N - 1)) === 0;
      if (pow2 && N >= a.minN && r >= a.minR && p >= 1 && salt.length >= a.minSaltBytes && key.length >= a.minKeyBytes && N <= 1 << 20 && r <= 32 && p <= 16) {
        try { ok = crypto.timingSafeEqual(crypto.scryptSync(pw, salt, key.length, { N, r, p, maxmem: 256 * N * r + (1 << 20) }), key); } catch { ok = false; }
      }
    }
    if (!ok) failed.push('approved-format');
  }
  if (k.properties.includes('distinct-from') && (others[k.distinctFrom] === undefined || others[k.distinctFrom] === value)) failed.push('distinct-from');
  return failed;
}

// The interpreter is resolved by the VERIFIER from fixed locations; a request or a profile cannot name one.
const PYTHONS = ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3'];
function findPython() {
  for (const p of PYTHONS) { try { if (fs.statSync(p).isFile()) return p; } catch { /* next */ } }
  return null;
}

function prepareAppInputs(i, token) {
  return {
    export: i.export, schemaSql: i.schemaSql, runtime: i.runtime || 'node', python: i.runtime === 'python' ? findPython() : null, requestTimeoutMs: Math.min(Number(i.requestTimeoutMs) || 2000, 5000),
    seed: i.seed.map((s) => ({ sql: s.sql, params: deep(s.params, token) })),
    requests: i.requests.map((r) => ({ id: r.id, method: r.method, path: subst(r.path, token), headers: deep(r.headers || {}, token), ...(r.body !== undefined ? { body: deep(r.body, token) } : {}) })),
    ...(i.network ? { network: deep(i.network, token) } : {}),
    ...(i.files ? { files: { root: i.files.root, tree: deep(i.files.tree, token), links: i.files.links || {} } } : {}),
    ...(i.env ? { env: deep(i.env, token) } : {}),
  };
}

// Address classes a `public-only` policy forbids: loopback, private, link-local (cloud metadata), carrier-grade NAT, unspecified,
// unique-local and the IPv4-mapped forms of all of them.
const PRIVATE = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15]]) PRIVATE.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10]]) PRIVATE.addSubnet(a, p, 'ipv6');
export const isPrivateAddress = (a) => { const v = net.isIP(a); return v === 4 ? PRIVATE.check(a, 'ipv4') : v === 6 ? PRIVATE.check(a, 'ipv6') : false; };

/** Is this recorded connection permitted by the declared policy? null when the destination is not modelled (an undeclared name). */
function connectionPermitted(network, c) {
  if (!c.address) return network.policy === 'allowlist' ? false : null;
  if (network.policy === 'public-only') return !isPrivateAddress(c.address);
  return network.hosts.some((h) => network.approved.includes(h.name) && h.addresses.includes(c.address) && (h.port || 80) === c.port);
}

const canon = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? Number(x) : x));

/** The verifier's own read of the database the run left behind. Read-only connection; a missing or unreadable file is no evidence. */
function readState(dbPath, checks, token) {
  if (!dbPath) return { ok: false, reason: 'the run left no database file', results: {} };
  let db;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
  } catch (e) { return { ok: false, reason: `the database could not be opened read-only: ${String(e.message).slice(0, 120)}`, results: {} }; }
  const results = {}; const stored = {}; const pendingCredentials = [];
  try {
    for (const c of checks) {
      let rows;
      try { rows = db.prepare(c.sql).all(...deep(c.params || [], token)); } catch (e) { results[c.id] = { held: false, error: String(e.message).slice(0, 120) }; continue; }
      if (c.credential) {
        const first = rows[0] ? Object.values(rows[0])[0] : null;
        stored[c.id] = first == null ? undefined : String(first);
        pendingCredentials.push([c, first]);
        continue;
      }
      const want = deep(c.expect, token);
      const got = JSON.parse(canon(rows));
      results[c.id] = { held: canon(got) === canon(want), rows: got.slice(0, 20) };
    }
    // credential checks last: distinct-from needs every stored value read first. The stored value itself never enters the result.
    for (const [c, first] of pendingCredentials) {
      const failed = judgeCredential(first, deep(c.credential, token), stored);
      results[c.id] = { held: failed.length === 0, failedProperties: failed };
    }
  } finally { try { db.close(); } catch { /* ignore */ } }
  return { ok: true, results };
}

/** Did each control request meet its declared expectation? */
function judgeControls(inputs, responses, token) {
  const failed = [];
  for (const r of inputs.requests.filter((x) => x.role === 'control')) {
    const got = responses?.[r.id];
    const e = deep(r.expect || {}, token);
    if (!got || got.error || typeof got.status !== 'number') { failed.push({ id: r.id, reason: got?.error ? `no response (${got.error})` : 'no response' }); continue; }
    if (e.status && !e.status.includes(got.status)) { failed.push({ id: r.id, reason: `status ${got.status}, expected ${e.status.join('/')}` }); continue; }
    const body = String(got.body || '');
    const miss = (e.bodyIncludes || []).find((s) => !body.includes(s));
    if (miss) { failed.push({ id: r.id, reason: 'the response lacks an expected value' }); continue; }
    const bad = (e.bodyExcludes || []).find((s) => body.includes(s));
    if (bad) failed.push({ id: r.id, reason: 'the response contains a value it must not' });
  }
  return failed;
}

/** Which attack requests reached a forbidden effect: a planted secret in the response. */
function judgeAttacks(inputs, responses, token, connections = []) {
  const connectionsOf = (id) => connections.filter((c) => c && typeof c === 'object' && c.request === id);
  const violated = [];
  for (const r of inputs.requests.filter((x) => x.role === 'attack')) {
    const got = responses?.[r.id];
    const body = String(got?.body || '');
    const leaked = (r.forbid?.secrets || []).filter((n) => body.includes(secretValue(token, n)));
    const forbidden = r.forbid?.connections && inputs.network ? connectionsOf(r.id).filter((c) => connectionPermitted(inputs.network, c) === false) : [];
    const destinations = forbidden.slice(0, 8).map((c) => ({ host: c.host, address: c.address, port: c.port, tls: c.tls }));
    if (leaked.length) violated.push({ id: r.id, effect: 'secret-disclosed', secrets: leaked, status: got?.status ?? null, ...(destinations.length ? { destinations } : {}) });
    else if (destinations.length) violated.push({ id: r.id, effect: 'forbidden-connection', secrets: [], destinations, status: got?.status ?? null });
  }
  return violated;
}

// ---------------------------------------------------------------- the two adapter specs

const APP_PLATFORMS = Object.freeze({
  darwin: { status: 'supported', note: 'executed by this repository\'s tests on the macOS development host (userspace confinement backend)' },
  linux: { status: 'unverified', note: 'no Linux outcome is claimed: the boundary refuses to run on the namespace backend until read denial and supervised tree termination are implemented and executed there; the run reports unsupported' },
  win32: { status: 'unsupported', note: 'no confinement backend exists for Windows' },
});
const APP_BUDGETS = Object.freeze({ timeoutMs: 20000, graceMs: 1000, maxOutputBytes: 65536, maxFileBytes: 1048576, maxFiles: 64 });
const APP_LIMITS = [
  'the application must load from the workspace with Node\'s standard library only; its factory receives an open node:sqlite database',
  'requests run one at a time in the declared order over an in-memory HTTP connection: no concurrency and no network are exercised',
  'only the declared requests, secrets and state checks are judged; behaviour outside them is not verified',
  'Express itself is not executed in this repository; an Express application has this request-listener signature but no Express fixture runs',
  'outbound connections (a declared network) are observed at the Node connection layer (net, tls, the HTTP agents, raw sockets) and served by verifier-declared hosts with the declared DNS answers; https destinations are recorded and refused, never served; a connection opened below that layer is not observed (the repair scope gate refuses a candidate that introduces one); node runtime only',
  'a declared file tree is real (files and symbolic links in the workspace) and the factory receives its allowed root; only a planted file disclosed in a response is judged: writes outside the root and time-of-check races are not exercised; node runtime only',
  'a stored credential is judged by recomputation for one approved format (scrypt, `scrypt$N$r$p$<salt hex>$<key hex>`); a different but sound format does not hold; KDF parameters above N 2^20, r 32 or p 16 are beyond the verifier bound and do not hold; timing and memory hardness are not measured',
];

function loadedOrOpen(result) {
  if (!result) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false, benignCompleted: false }, reason: 'the application run left no result' };
  if (result.setupFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false, setupFailed: true, benignCompleted: false }, reason: 'the declared schema or seed could not be created' };
  if (result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false, benignCompleted: false }, reason: 'the application did not load or its factory did not return a request listener' };
  if (!result.completed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: true, benignCompleted: false }, reason: 'the application run did not complete every request' };
  return null;
}

function stateOf(inputs, token, pathOf) {
  const checks = inputs.stateChecks || [];
  const st = readState(pathOf ? pathOf('__oracle_app.db') : null, checks, token);
  if (!st.ok) return { ok: false, reason: st.reason };
  const failed = (role) => checks.filter((c) => c.role === role && !st.results[c.id]?.held).map((c) => ({ id: c.id, reason: st.results[c.id]?.error ? 'the check could not run' : c.credential ? `the stored credential fails: ${(st.results[c.id]?.failedProperties || []).join(', ')}` : 'the durable state differs from the declared expectation', ...(c.credential ? { failedProperties: st.results[c.id]?.failedProperties || [] } : {}) }));
  return { ok: true, controlFailed: failed('control'), attackFailed: failed('attack') };
}

function interpretSecurity({ inputs, token, result, pathOf }) {
  const open = loadedOrOpen(result); if (open) return open;
  const st = stateOf(inputs, token, pathOf);
  if (!st.ok) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: true, benignCompleted: false }, reason: st.reason };
  const controlFailures = [...judgeControls(inputs, result.responses, token), ...st.controlFailed];
  const violations = [...judgeAttacks(inputs, result.responses, token, Array.isArray(result.connections) ? result.connections.slice(0, 200) : []), ...st.attackFailed.map((c) => (c.failedProperties ? { id: c.id, effect: 'credential-storage', properties: c.failedProperties } : { id: c.id, effect: 'durable-state' }))];
  const observed = { targetLoaded: true, benignCompleted: controlFailures.length === 0, controlFailures, attackViolations: violations };
  let unmodelledAttacks = [];
  if (inputs.network) {
    const conns = Array.isArray(result.connections) ? result.connections.filter((c) => c && typeof c === 'object') : [];
    observed.connections = conns.length;
    // AC-12.2: a destination the declaration does not model (an undeclared name, connected to or looked up) is an explicit gap, never a
    // pass or a violation. An attack that reached one cannot be counted as blocked, so the run cannot refute.
    // A lookup the declared DNS cannot answer is the same gap: on a real network the name would resolve somewhere.
    const lookups = Array.isArray(result.lookups) ? result.lookups.filter((l) => l && typeof l === 'object' && !l.address) : [];
    const unmodelled = [...conns.filter((c) => connectionPermitted(inputs.network, c) === null), ...lookups];
    if (unmodelled.length) observed.unmodelledDestinations = [...new Set(unmodelled.map((c) => c.host))].slice(0, 8);
    const attackIds = new Set(inputs.requests.filter((r) => r.role === 'attack').map((r) => r.id));
    unmodelledAttacks = [...new Set(unmodelled.filter((c) => attackIds.has(c.request)).map((c) => c.request))];
  }
  if (violations.length) return { satisfied: true, preconditionsHeld: controlFailures.length === 0, observed, reason: `an attack reached a forbidden effect: ${violations.map((v) => `${v.id} (${v.effect})`).join(', ')}` };
  if (unmodelledAttacks.length) return { satisfied: null, preconditionsHeld: false, observed, reason: `attack request(s) reached a destination the declared network does not model, so they cannot be judged blocked: ${unmodelledAttacks.join(', ')}` };
  if (!controlFailures.length) return { satisfied: false, preconditionsHeld: true, observed, reason: 'no attack reached a forbidden effect and every control request met its expectation' };
  return { satisfied: null, preconditionsHeld: false, observed, reason: `no attack reached a forbidden effect, but control request(s) failed, so the application was not shown to work: ${controlFailures.map((c) => c.id).join(', ')}` };
}

function interpretBehaviour({ inputs, token, result, pathOf }) {
  const open = loadedOrOpen(result); if (open) return open;
  const st = stateOf(inputs, token, pathOf);
  if (!st.ok) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: true, benignCompleted: false }, reason: st.reason };
  const controlFailures = [...judgeControls(inputs, result.responses, token), ...st.controlFailed];
  const observed = { targetLoaded: true, benignCompleted: true, controlFailures, casesChecked: inputs.requests.length + (inputs.stateChecks || []).length };
  if (controlFailures.length) return { satisfied: true, preconditionsHeld: true, observed, reason: `legitimate behaviour regressed: ${controlFailures.map((c) => `${c.id} (${c.reason})`).join('; ')}` };
  return { satisfied: false, preconditionsHeld: true, observed, reason: 'every declared legitimate request and state check held' };
}

const securitySpec = {
  id: 'application-security', class: 'application-security', version: '4',
  description: 'Does an attack request reach a forbidden effect in a running application? The application is started over a fresh SQLite file, every declared request is sent as real HTTP, and the verifier judges the responses and its own read-only read of the database. Refuted only when no attack violates AND every legitimate control request met its expectation.',
  prerequisites: ['node-runtime', 'node-sqlite', 'confinement-backend'],
  platforms: APP_PLATFORMS, budgets: APP_BUDGETS,
  negativeControls: [{ id: 'parameterised-and-scoped', description: 'the same application binding the request value as a parameter and scoping by owner must leak no planted secret while every control request still succeeds', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/application-security', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: APP_LIMITS,
  harnessSource: APP_HARNESS,
  validateInputs: (i) => validateAppInputs(i, { requireAttack: true }),
  prepare: prepareAppInputs,
  interpret: interpretSecurity,
};

const behaviourSpec = {
  id: 'application-behaviour', class: 'application-behaviour', version: '4',
  description: 'Does a revision of a running application still serve its legitimate requests? Control requests only; the hypothesis is that legitimate behaviour REGRESSED, so a revision is clean when this is refuted. A deny-everything or feature-removing patch confirms it.',
  prerequisites: ['node-runtime', 'node-sqlite', 'confinement-backend'],
  platforms: APP_PLATFORMS, budgets: APP_BUDGETS,
  negativeControls: [{ id: 'behaviour-preserved', description: 'an application answering every declared control request as expected, with the declared durable state, must show no regression', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/application-behaviour', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: APP_LIMITS,
  harnessSource: APP_HARNESS,
  validateInputs: (i) => validateAppInputs(i, { requireAttack: false }),
  prepare: prepareAppInputs,
  interpret: interpretBehaviour,
};

export const applicationSecurity = defineOracle(securitySpec);
export const applicationBehaviour = defineOracle(behaviourSpec);
