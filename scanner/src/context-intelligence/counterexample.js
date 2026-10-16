// Deterministic counterexample validation for a candidate invariant violation (E4-04).
//
// A candidate (for example a cross-route inconsistency from E4-03) says "this route looks weaker than its sibling". This module tries to settle it
// WITHOUT a model, in layers, and reports where it got to as one of four states that are never blended:
//
//   refuted     the claim is contradicted: the control IS on the path, the route is declared public by policy, there is no sensitive operation
//               on the resource, or an executed attempt by the attacker was denied
//   unresolved  the analysis cannot say: an unresolved call or a traversal limit could hide the control, or the fixture could not run
//   plausible   every edge is resolved and the path reaches the resource's sensitive operation with no control of that kind before it, but nothing
//               was executed. This is static evidence only
//   proven      an authorized LOCAL request fixture ran the real handler code and the attacker, who does not own the object, read or changed the
//               victim's object. Only an execution can produce this state
//
// MODEL OUTPUT NEVER ENTERS. This file imports nothing from the review or model paths and reads no prose: facts come from the code analysis, which
// skips comments, docstrings and string contents, so a comment that claims a check exists, or tells a reviewer to ignore the finding, cannot move a
// state. The evidence trace is a list of steps each naming its kind (`static` or `executed`), so a reader can see which layer decided.
//
// THE FIXTURE RUNNER executes handler code, so it is confined: a child process under Node's permission model with NO file access (the fixture's sources are loaded from memory), no
// child processes and no workers, a driver that removes `fetch` and refuses every builtin and package, a scrubbed environment, a wall-clock
// limit and capped output. Network is not part of Node's permission model, so it is blocked by the driver, not by the runtime: lower assurance. Express-style
// apps are supported through a small in-process shim for `express`, and `db` is a recording in-memory store the fixture supplies. Code that needs
// anything else (a real database, another module system, a missing dependency) ends as `unresolved`, never as `proven`.
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';

export const STATES = Object.freeze(['proven', 'plausible', 'refuted', 'unresolved']);
const FIXTURE_TIMEOUT_MS = 8000;
const MAX_OUTPUT = 200_000;
const MAX_FIXTURE_BYTES = 100_000;

// ---- the fixture runner -----------------------------------------------------------------------------------------------------

const DRIVER = String.raw`
'use strict';
const path = require('node:path');
const spec = JSON.parse(process.env.FIXTURE_SPEC);
const ops = [];
const store = JSON.parse(JSON.stringify(spec.store || {}));
const match = (doc, q) => Object.entries(q || {}).every(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v)) ? true : doc[k] === v);
const coll = (name) => ({
  async findOne(q) { ops.push({ op: 'findOne', c: name, q }); return (store[name] || []).find((d) => match(d, q)) || null; },
  async find(q) { ops.push({ op: 'find', c: name, q }); return (store[name] || []).filter((d) => match(d, q)); },
  async updateOne(q, u) { ops.push({ op: 'updateOne', c: name, q }); const d = (store[name] || []).find((x) => match(x, q)); if (d) Object.assign(d, (u && u.$set) || u); return { matchedCount: d ? 1 : 0 }; },
  async deleteOne(q) { ops.push({ op: 'deleteOne', c: name, q }); const i = (store[name] || []).findIndex((x) => match(x, q)); if (i >= 0) store[name].splice(i, 1); return { deletedCount: i >= 0 ? 1 : 0 }; },
  async insertOne(d) { ops.push({ op: 'insertOne', c: name }); (store[name] ||= []).push(d); return { insertedId: d.id }; },
});
global.db = new Proxy({}, { get: (_, name) => coll(String(name)) });
const routes = []; const mw = [];
const app = {};
for (const m of ['get', 'post', 'put', 'patch', 'delete']) app[m] = (p, ...hs) => { routes.push({ method: m.toUpperCase(), path: p, handlers: hs.flat() }); return app; };
app.use = (...a) => { const fn = a.find((x) => typeof x === 'function'); if (fn) mw.push(fn); return app; };
app.listen = () => app; app.set = () => app; app.disable = () => app;
const express = () => app; express.json = () => (q, s, n) => n(); express.urlencoded = () => (q, s, n) => n(); express.Router = () => app;
// The fixture's files are loaded from memory: nothing is read from disk, so the process needs no file permission at all, and require can only
// reach the shim for express and the fixture's own relative modules. Everything else, builtins included, is refused.
delete globalThis.fetch; delete globalThis.WebSocket;
const vm = require('node:vm');
const cache = new Map();
const norm = (p) => path.posix.normalize(p).replace(/^\.\//, '');
const fileFor = (from, request) => {
  const base = path.posix.join(path.posix.dirname(from), request);
  for (const c of [base, base + '.js', base + '.cjs', base + '/index.js']) if (Object.hasOwn(spec.files, norm(c))) return norm(c);
  return null;
};
const load = (file) => {
  if (cache.has(file)) return cache.get(file).exports;
  const mod = { exports: {} }; cache.set(file, mod);
  const req = (request) => {
    if (request === 'express') return express;
    if (request.startsWith('.')) { const f = fileFor(file, request); if (f) return load(f); throw Object.assign(new Error('no such fixture module ' + request), { code: 'FIXTURE_UNSUPPORTED' }); }
    throw Object.assign(new Error('fixture runner does not provide module ' + request), { code: 'FIXTURE_UNSUPPORTED' });
  };
  const wrapper = '(function (exports, require, module, __filename, __dirname) {' + spec.files[file] + '\n})';
  vm.runInThisContext(wrapper, { filename: file })(mod.exports, req, mod, file, path.posix.dirname(file));
  return mod.exports;
};
const matchRoute = (r, method, url) => {
  if (r.method !== method) return null;
  const a = r.path.split('/'); const b = url.split('/');
  if (a.length !== b.length) return null;
  const params = {};
  for (let i = 0; i < a.length; i++) { if (a[i].startsWith(':')) params[a[i].slice(1)] = b[i]; else if (a[i] !== b[i]) return null; }
  return params;
};
(async () => {
  let result;
  try {
    load(norm(spec.entry));
    const req0 = spec.request;
    const hit = routes.map((r) => ({ r, params: matchRoute(r, req0.method, req0.path) })).find((x) => x.params);
    if (!hit) { result = { error: 'no-route', detail: req0.method + ' ' + req0.path }; }
    else {
      const user = spec.user ? JSON.parse(JSON.stringify(spec.user)) : undefined;
      const req = { method: req0.method, params: hit.params, query: req0.query || {}, body: req0.body || {}, headers: {}, user, get: () => undefined };
      let done; const finished = new Promise((r) => { done = r; });
      const res = { statusCode: 200, body: undefined, sent: false,
        status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; this.sent = true; done(); return this; }, send(b) { this.body = b; this.sent = true; done(); return this; },
        sendStatus(c) { this.statusCode = c; this.sent = true; done(); return this; }, set() { return this; }, end() { this.sent = true; done(); return this; }, type() { return this; }, locals: {} };
      const chain = [...mw, ...hit.r.handlers];
      let i = 0;
      const next = (err) => { if (err) { res.statusCode = 500; res.sent = true; done(); return; } const h = chain[i++]; if (!h) { done(); return; } try { const p = h(req, res, next); if (p && typeof p.then === 'function') p.catch((e) => { res.statusCode = 500; res.body = String(e && e.message); res.sent = true; done(); }); } catch (e) { res.statusCode = 500; res.body = String(e && e.message); res.sent = true; done(); } };
      next();
      await Promise.race([finished, new Promise((r) => setTimeout(r, 2000))]);
      result = { status: res.statusCode, body: res.body, sent: res.sent, ops, store };
    }
  } catch (e) { result = { error: e && e.code === 'FIXTURE_UNSUPPORTED' ? 'unsupported' : 'load-failed', detail: String(e && e.message).slice(0, 300) }; }
  process.stdout.write('@@RESULT@@' + JSON.stringify(result));
})();
`;

/**
 * Run one request against the real handler code under confinement.
 * @param {{files:Record<string,string>, entry:string, request:{method:string,path:string,body?:object,query?:object}, user?:object, store?:object}} f
 * @returns {{ok:boolean, status?:number, body?:any, ops?:object[], store?:object, error?:string, detail?:string}}
 */
export function runFixture(f) {
  const total = Object.values(f.files || {}).reduce((n, t) => n + String(t).length, 0);
  if (total > MAX_FIXTURE_BYTES) return { ok: false, error: 'too-large', detail: `${total} bytes of fixture source` };
  for (const rel of Object.keys(f.files || {})) if (path.isAbsolute(rel) || rel.split('/').includes('..')) return { ok: false, error: 'bad-path', detail: rel };
  // `--permission` with no allow flags: no file reads or writes, no child processes, no workers. The driver comes in through -e and the fixture's
  // files through the environment, so nothing needs the disk. Network is not covered by the permission model; the driver removes `fetch` and
  // refuses every builtin and package, which is the whole of its network reach.
  const r = spawnSync(process.execPath, ['--permission', '-e', DRIVER], {
    encoding: 'utf8', timeout: FIXTURE_TIMEOUT_MS, maxBuffer: MAX_OUTPUT,
    env: { PATH: '/usr/bin:/bin', FIXTURE_SPEC: JSON.stringify({ files: f.files, entry: f.entry, request: f.request, user: f.user, store: f.store }) },
  });
  if (r.error) return { ok: false, error: r.error.code === 'ETIMEDOUT' ? 'timeout' : 'spawn-failed', detail: String(r.error.message).slice(0, 200) };
  const out = String(r.stdout || ''); const i = out.indexOf('@@RESULT@@');
  if (i < 0) return { ok: false, error: 'no-result', detail: String(r.stderr || '').slice(0, 300) };
  let parsed; try { parsed = JSON.parse(out.slice(i + 10)); } catch { return { ok: false, error: 'bad-result' }; }
  return parsed.error ? { ok: false, error: parsed.error, detail: parsed.detail } : { ok: true, ...parsed };
}

/**
 * Make the attacker's request against the real handler code and say what happened to the victim's object. Used by assessCandidate and, after a patch,
 * by the final verification of a fix (which must execute even when a static look already says the control is present).
 * @returns {{state:'proven'|'refuted'|'unresolved', trace:object[], reasons:string[], reason?:string, status?:number}}
 */
export function executeAttempt(candidate, fx) {
  const trace = [];
  const method = fx.method || (candidate.operations?.includes('delete') ? 'DELETE' : candidate.operations?.includes('update') ? 'PUT' : 'GET');
  const attack = runFixture({ files: fx.files, entry: fx.entry, request: { method, path: fx.path, body: fx.body }, user: fx.attacker.user, store: fx.store });
  if (!attack.ok) { trace.push(step('executed', 'attacker request', `${attack.error}: ${attack.detail || ''}`)); return { state: 'unresolved', trace, reasons: [`the fixture could not run (${attack.error}); the claim stays unproven`], reason: `the fixture could not run (${attack.error}); the claim stays unproven` }; }
  trace.push(step('executed', 'attacker request', `${method} ${fx.path} as ${JSON.stringify(fx.attacker.user)} -> ${attack.status}`));
  const marker = fx.victim.marker;
  const leaked = marker ? JSON.stringify(attack.body ?? '').includes(marker) : attack.status >= 200 && attack.status < 300 && attack.body != null;
  const changed = JSON.stringify(attack.store?.[fx.victim.collection] || []) !== JSON.stringify(fx.store[fx.victim.collection] || []);
  if (leaked || changed) {
    trace.push(step('executed', 'effect on the victim\'s object', leaked ? 'the attacker received the victim\'s data' : 'the victim\'s object was modified by the attacker'));
    if (fx.siblingPath) {
      const sib = runFixture({ files: fx.files, entry: fx.entry, request: { method: fx.siblingMethod || 'GET', path: fx.siblingPath }, user: fx.attacker.user, store: fx.store });
      if (sib.ok) trace.push(step('executed', 'the enforcing sibling, same attacker', `${fx.siblingMethod || 'GET'} ${fx.siblingPath} -> ${sib.status}${marker && !JSON.stringify(sib.body ?? '').includes(marker) ? ' (victim data withheld)' : ''}`));
    }
    return { state: 'proven', trace, reasons: ['an executed local request let a principal who does not own the object ' + (leaked ? 'read' : 'change') + ' it'], status: attack.status };
  }
  trace.push(step('executed', 'effect on the victim\'s object', 'none: the attacker was denied or got nothing'));
  return { state: 'refuted', trace, reasons: [`an executed attempt by the attacker was denied (status ${attack.status})`], status: attack.status };
}

// ---- the assessment ---------------------------------------------------------------------------------------------------------

const step = (kind, what, detail = null) => ({ kind, what, ...(detail ? { detail } : {}) });
const sameBundle = (b, route) => b.entrypoint && b.entrypoint.label === route;

/**
 * @param {{route:string, resource:string, dimension:string, operations?:string[], enforcedAt?:object[], waivedBy?:string[]}} candidate  e.g. a finding from findCrossRouteInconsistencies
 * @param {{bundles:object[], fixture?:{files:Record<string,string>, entry:string, victim:{user:object, ownsId:string, collection:string, marker?:string}, attacker:{user:object}, store:object, path:string, method?:string, body?:object, siblingPath?:string, siblingMethod?:string}}} ctx
 * @returns {{state:'proven'|'plausible'|'refuted'|'unresolved', trace:object[], reasons:string[]}}
 */
export function assessCandidate(candidate, ctx) {
  const trace = [];
  const fail = (state, reason) => ({ state, trace, reasons: [reason] });
  const bundle = (ctx.bundles || []).find((b) => sameBundle(b, candidate.route));
  if (!bundle || !bundle.manifest) { trace.push(step('static', 'locate the route bundle', 'no bundle for this route')); return fail('unresolved', `no analysed bundle for ${candidate.route}`); }
  trace.push(step('static', 'locate the route bundle', bundle.entrypoint.id));

  if (candidate.waivedBy && candidate.waivedBy.length) { trace.push(step('static', 'check policy', `public-by-design: ${candidate.waivedBy.join(', ')}`)); return fail('refuted', `declared public by ${candidate.waivedBy.join(', ')}`); }

  const facts = bundle.reach?.facts || [];
  const sens = facts.filter((f) => f.category === 'sensitive');
  if (!sens.length) { trace.push(step('static', 'find a sensitive operation', 'none on the path')); return fail('refuted', 'no sensitive operation is reachable from this route, so there is nothing to protect'); }
  const first = Math.min(...sens.map((f) => f.effLine));
  const kinds = candidate.dimension === 'ownership' ? ['ownership'] : [candidate.dimension];
  const before = facts.filter((f) => f.category === 'control' && kinds.includes(f.kind) && (f.effLine < first || (f.basis === 'query-filter' && f.effLine <= first)));
  if (before.length) { trace.push(step('static', `look for ${candidate.dimension} before the first sensitive operation`, `found at ${before[0].file}:${before[0].line}`)); return fail('refuted', `${candidate.dimension} is enforced at ${before[0].file}:${before[0].line} before the sensitive operation`); }
  trace.push(step('static', `look for ${candidate.dimension} before the first sensitive operation`, 'none'));

  const hidden = (bundle.manifest.unknowns || []).some((u) => u.material) || bundle.reach?.capped;
  if (hidden) { trace.push(step('static', 'check for unresolved calls', 'a material unresolved call or a traversal limit')); return fail('unresolved', 'an unresolved call or a traversal limit could hide the control'); }
  trace.push(step('static', 'check for unresolved calls', 'none'));

  const fx = ctx.fixture;
  if (!fx) return { state: 'plausible', trace, reasons: ['every edge on the path is resolved and no control precedes the sensitive operation; nothing was executed'] };

  const ex = executeAttempt(candidate, fx);
  trace.push(...ex.trace);
  if (ex.state === 'unresolved') return fail('unresolved', ex.reason);
  if (ex.state === 'proven') return { state: 'proven', trace, reasons: ex.reasons };
  return { state: 'refuted', trace, reasons: ex.reasons };
}
