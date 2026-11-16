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
import { DatabaseSync } from 'node:sqlite';
import { defineOracle } from './oracle.js';

const SECRET_RE = /\{\{secret:([a-z][a-z0-9-]{0,31})\}\}/g;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const isId = (s) => typeof s === 'string' && /^[A-Za-z_$][\w$-]{0,63}$/.test(s);
const isStr = (s, max = 2000) => typeof s === 'string' && s.length <= max;

export const secretValue = (token, name) => `S-${crypto.createHash('sha256').update(`${token}:${name}`).digest('hex').slice(0, 24)}`;
const subst = (v, token) => (typeof v === 'string' ? v.replace(SECRET_RE, (_, n) => secretValue(token, n)) : v);
const deep = (v, token) => (Array.isArray(v) ? v.map((x) => deep(x, token)) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x, token)])) : subst(v, token));

export const APP_HARNESS = `import fs from 'node:fs';
import http from 'node:http';
import { duplexPair } from 'node:stream';
import { DatabaseSync } from 'node:sqlite';
const INPUT = __INPUT__;
const ENTRY = __ENTRY__;
const out = { responses: {} };
const text = (e) => String((e && e.message) || e).slice(0, 160);
function finish(extra) { Object.assign(out, extra); try { fs.writeFileSync('__oracle_result.json', JSON.stringify(out)); } catch {} process.exit(0); }
let db;
try {
  db = new DatabaseSync('__oracle_app.db');
  db.exec(INPUT.schemaSql);
  for (const s of INPUT.seed) db.prepare(s.sql).run(...s.params);
} catch (e) { finish({ setupFailed: true, setupError: text(e) }); }
let mod;
try { mod = await import('./' + ENTRY); } catch (e) { finish({ loadFailed: true, loadError: text(e) }); }
const factory = mod && (mod[INPUT.export] || (mod.default && mod.default[INPUT.export]));
if (typeof factory !== 'function') finish({ loadFailed: true, loadError: 'the factory export is not a function' });
let handler;
try { handler = await factory({ db }); } catch (e) { finish({ loadFailed: true, loadError: text(e) }); }
if (typeof handler !== 'function') finish({ loadFailed: true, loadError: 'the factory did not return a request listener' });
const server = http.createServer(handler);
function send(r) {
  return new Promise((resolve) => {
    const [client, srv] = duplexPair();
    server.emit('connection', srv);
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
for (const r of INPUT.requests) out.responses[r.id] = await send(r);
try { db.close(); } catch {}
finish({ completed: true });
`;

/** Validation shared by both adapters. Returns a problem string or null. */
export function validateAppInputs(i, { requireAttack }) {
  if (!isId(i.export)) return 'export must be an identifier';
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
      for (const k of Object.keys(f)) if (k !== 'secrets') return `request ${r.id}: unknown forbidden effect '${k}'`;
      if (f.secrets !== undefined && (!Array.isArray(f.secrets) || !f.secrets.every((s) => /^[a-z][a-z0-9-]{0,31}$/.test(s)))) return `request ${r.id}: forbid.secrets must list secret names`;
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
    if (!('expect' in c)) return `state check ${c.id}: expect is required`;
  }
  if (requireAttack && !i.requests.some((r) => r.role === 'attack')) return 'at least one attack request is required';
  if (!i.requests.some((r) => r.role === 'control')) return 'at least one control request is required (it shows the application worked)';
  if (!requireAttack && i.requests.some((r) => r.role === 'attack')) return 'the behaviour oracle takes control requests only';
  return null;
}

export function prepareAppInputs(i, token) {
  return {
    export: i.export, schemaSql: i.schemaSql, requestTimeoutMs: Math.min(Number(i.requestTimeoutMs) || 2000, 5000),
    seed: i.seed.map((s) => ({ sql: s.sql, params: deep(s.params, token) })),
    requests: i.requests.map((r) => ({ id: r.id, method: r.method, path: subst(r.path, token), headers: deep(r.headers || {}, token), ...(r.body !== undefined ? { body: deep(r.body, token) } : {}) })),
  };
}

const canon = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? Number(x) : x));

/** The verifier's own read of the database the run left behind. Read-only connection; a missing or unreadable file is no evidence. */
export function readState(dbPath, checks, token) {
  if (!dbPath) return { ok: false, reason: 'the run left no database file', results: {} };
  let db;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
  } catch (e) { return { ok: false, reason: `the database could not be opened read-only: ${String(e.message).slice(0, 120)}`, results: {} }; }
  const results = {};
  try {
    for (const c of checks) {
      let rows;
      try { rows = db.prepare(c.sql).all(...deep(c.params || [], token)); } catch (e) { results[c.id] = { held: false, error: String(e.message).slice(0, 120) }; continue; }
      const want = deep(c.expect, token);
      const got = JSON.parse(canon(rows));
      results[c.id] = { held: canon(got) === canon(want), rows: got.slice(0, 20) };
    }
  } finally { try { db.close(); } catch { /* ignore */ } }
  return { ok: true, results };
}

/** Did each control request meet its declared expectation? */
export function judgeControls(inputs, responses, token) {
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
export function judgeAttacks(inputs, responses, token) {
  const violated = [];
  for (const r of inputs.requests.filter((x) => x.role === 'attack')) {
    const got = responses?.[r.id];
    const body = String(got?.body || '');
    const leaked = (r.forbid?.secrets || []).filter((n) => body.includes(secretValue(token, n)));
    if (leaked.length) violated.push({ id: r.id, effect: 'secret-disclosed', secrets: leaked, status: got?.status ?? null });
  }
  return violated;
}

// ---------------------------------------------------------------- the two adapter specs

export const APP_PLATFORMS = Object.freeze({
  darwin: { status: 'supported', note: 'executed by this repository\'s tests on the macOS development host (userspace confinement backend)' },
  linux: { status: 'unverified', note: 'the namespace backend runs these tests in the hosted sandbox-linux job; no Linux outcome is claimed here until that job records them' },
  win32: { status: 'unsupported', note: 'no confinement backend exists for Windows' },
});
export const APP_BUDGETS = Object.freeze({ timeoutMs: 20000, graceMs: 1000, maxOutputBytes: 65536, maxFileBytes: 1048576, maxFiles: 64 });
const APP_LIMITS = [
  'the application must load from the workspace with Node\'s standard library only; its factory receives an open node:sqlite database',
  'requests run one at a time in the declared order over an in-memory HTTP connection: no concurrency and no network are exercised',
  'only the declared requests, secrets and state checks are judged; behaviour outside them is not verified',
  'Express itself is not executed in this repository; an Express application has this request-listener signature but no Express fixture runs',
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
  const failed = (role) => checks.filter((c) => c.role === role && !st.results[c.id]?.held).map((c) => ({ id: c.id, reason: st.results[c.id]?.error ? 'the check could not run' : 'the durable state differs from the declared expectation' }));
  return { ok: true, controlFailed: failed('control'), attackFailed: failed('attack') };
}

export function interpretSecurity({ inputs, token, result, pathOf }) {
  const open = loadedOrOpen(result); if (open) return open;
  const st = stateOf(inputs, token, pathOf);
  if (!st.ok) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: true, benignCompleted: false }, reason: st.reason };
  const controlFailures = [...judgeControls(inputs, result.responses, token), ...st.controlFailed];
  const violations = [...judgeAttacks(inputs, result.responses, token), ...st.attackFailed.map((c) => ({ id: c.id, effect: 'durable-state' }))];
  const observed = { targetLoaded: true, benignCompleted: controlFailures.length === 0, controlFailures, attackViolations: violations };
  if (violations.length) return { satisfied: true, preconditionsHeld: controlFailures.length === 0, observed, reason: `an attack reached a forbidden effect: ${violations.map((v) => `${v.id} (${v.effect})`).join(', ')}` };
  if (!controlFailures.length) return { satisfied: false, preconditionsHeld: true, observed, reason: 'no attack reached a forbidden effect and every control request met its expectation' };
  return { satisfied: null, preconditionsHeld: false, observed, reason: `no attack reached a forbidden effect, but control request(s) failed, so the application was not shown to work: ${controlFailures.map((c) => c.id).join(', ')}` };
}

export function interpretBehaviour({ inputs, token, result, pathOf }) {
  const open = loadedOrOpen(result); if (open) return open;
  const st = stateOf(inputs, token, pathOf);
  if (!st.ok) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: true, benignCompleted: false }, reason: st.reason };
  const controlFailures = [...judgeControls(inputs, result.responses, token), ...st.controlFailed];
  const observed = { targetLoaded: true, benignCompleted: true, controlFailures, casesChecked: inputs.requests.length + (inputs.stateChecks || []).length };
  if (controlFailures.length) return { satisfied: true, preconditionsHeld: true, observed, reason: `legitimate behaviour regressed: ${controlFailures.map((c) => `${c.id} (${c.reason})`).join('; ')}` };
  return { satisfied: false, preconditionsHeld: true, observed, reason: 'every declared legitimate request and state check held' };
}

const securitySpec = {
  id: 'application-security', class: 'application-security', version: '1',
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
  id: 'application-behaviour', class: 'application-behaviour', version: '1',
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
