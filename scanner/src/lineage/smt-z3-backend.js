//
// smt-z3-backend.js: a real solver for the SMT orchestrator (DAG-04, R04.3 / R04.4).
//
// The orchestrator (smt-orchestrator.js) is built against an injectable backend object
//   { name, version?, available?, check(problem, { signal }) -> Promise<{ result, reason? }> }.
// This module is that backend, on top of the optional `z3-solver` package. Rules it keeps:
//
//   * LAZY and OPTIONAL. `z3-solver` is imported on the first query, never at module load, and never by a
//     default scan (the whole path is behind `pathEvidence` and `AGENTIC_SECURITY_LINEAGE_SMT=z3`). A package
//     that is not installed, fails to load or fails to initialise makes the backend `unsupported`
//     (`available === false`): never a crash and never an `unsat`.
//   * ONLY A VERIFIED ENCODING MAY SAY `unsat`. `encodeProblem` refuses (result `unknown`, with a reason) any
//     problem it cannot translate faithfully: a variable used with two sorts, a number SMT-LIB cannot write
//     exactly, an unknown literal or operator. An opaque (unmodeled) predicate is encoded as `true`, which can
//     only make the formula LARGER, so `unsat` stays sound; for the same reason a `sat` that leaned on an opaque
//     predicate is reported `unknown`, not as a model.
//   * Numbers are Real, not Int, so a comparison such as `0.5 < x < 1` is not wrongly called infeasible.
//   * BOUNDED. A per-query timeout (`timeoutMs`), a process memory cap (`memoryMb`, Z3's `memory_max_size`),
//     and the orchestrator's own deadline racing the query. A timeout is `timeout`, memory exhaustion and any
//     other solver failure is `unknown`. None of them ever reduces anything.
//   * DETERMINISTIC. Variables are renamed v0..vN in sorted order, assertions keep their order, the solver
//     random seed is fixed, and the SMT-LIB text is the cache key. Only definitive answers (`sat`, `unsat`)
//     are cached; a timeout depends on the machine and is not.
//
// `unsat` here means "the encoded conditions cannot hold together", relative to the model stated in
// path-predicates.js. It is not a proof about the running program, and `sat` never implies exploitability.

import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export const Z3_BACKEND_VERSION = 'smt-z3/1';
export const Z3_DEFAULT_TIMEOUT_MS = 1000;
export const Z3_DEFAULT_MEMORY_MB = 256;
const CACHE_MAX = 256;
const HARD_GRACE_MS = 500;
// 1e21 and 1e-7 are where String(number) switches to exponent form, which SMT-LIB has no literal for.
const MAX_PLAIN = 1e15;

// ---- encoding ------------------------------------------------------------------------------------------

const OPS = { '<': '<', '<=': '<=', '>': '>', '>=': '>=', '==': '=', '===': '=', '!=': 'distinct', '!==': 'distinct' };

/** A finite JS number as an SMT-LIB Real literal, or null when it cannot be written exactly in plain decimal. */
function realLiteral(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || Math.abs(n) >= MAX_PLAIN) return null;
  const s = String(n);
  if (/e/i.test(s)) return null;
  const abs = Math.abs(n);
  const body = Number.isInteger(abs) ? `${abs}.0` : String(abs);
  return n < 0 ? `(- ${body})` : body;
}

/** A JS string as an SMT-LIB 2.6 string literal: only printable ASCII is written raw. */
function stringLiteral(s) {
  let out = '';
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '""';
    else if (cp >= 0x20 && cp <= 0x7e && ch !== '\\') out += ch;
    else out += `\\u{${cp.toString(16)}}`;
  }
  return `"${out}"`;
}

/**
 * Translate the solver-neutral problem (path-predicates.js `toSolverProblem`) into SMT-LIB 2 text.
 *
 * @returns {{ok:true, text:string, digest:string, unmodeled:number, sorts:object, literals:number, assertions:number}
 *   | {ok:false, reason:string}}
 */
export function encodeProblem(problem) {
  if (!problem || typeof problem !== 'object' || !Array.isArray(problem.assertions) || !Array.isArray(problem.vars)) {
    return { ok: false, reason: 'encoding-unverified:malformed-problem' };
  }
  const sorts = new Map();
  const claim = (v, sort) => {
    if (typeof v !== 'string') return false;
    if (sorts.has(v) && sorts.get(v) !== sort) return false;
    sorts.set(v, sort);
    return true;
  };
  const constants = problem.constants && typeof problem.constants === 'object' ? problem.constants : {};
  let literals = 0; let unmodeled = 0;
  const alt = [];
  for (const a of problem.assertions) {
    if (!a || !Array.isArray(a.alternatives)) return { ok: false, reason: 'encoding-unverified:malformed-assertion' };
    for (const conj of a.alternatives) {
      if (!Array.isArray(conj)) return { ok: false, reason: 'encoding-unverified:malformed-assertion' };
      for (const l of conj) {
        literals += 1;
        if (!l || typeof l !== 'object') return { ok: false, reason: 'encoding-unverified:malformed-literal' };
        if (l.t === 'num') {
          if (!OPS[l.op]) return { ok: false, reason: 'encoding-unverified:unknown-operator' };
          for (const s of [l.left, l.right]) {
            if (!s || typeof s !== 'object') return { ok: false, reason: 'encoding-unverified:malformed-literal' };
            if ('var' in s) { if (!claim(s.var, 'Real')) return { ok: false, reason: 'encoding-unverified:sort-conflict' }; }
            else if (realLiteral(s.const) === null) return { ok: false, reason: 'encoding-unverified:number-not-encodable' };
          }
        } else if (l.t === 'eq') {
          if (typeof l.value !== 'string') return { ok: false, reason: 'encoding-unverified:non-string-equality' };
          if (!claim(l.var, 'String')) return { ok: false, reason: 'encoding-unverified:sort-conflict' };
        } else if (l.t === 'bool') {
          if (!claim(l.var, 'Bool')) return { ok: false, reason: 'encoding-unverified:sort-conflict' };
        } else if (l.t === 'opaque') {
          unmodeled += 1;
        } else {
          return { ok: false, reason: 'encoding-unverified:unknown-literal' };
        }
      }
    }
  }
  const constEntries = [];
  for (const [k, v] of Object.entries(constants)) {
    if (!sorts.has(k)) continue; // a constant for a variable no condition reads constrains nothing
    if (typeof v === 'number') {
      if (!claim(k, 'Real')) return { ok: false, reason: 'encoding-unverified:sort-conflict' };
      if (realLiteral(v) === null) return { ok: false, reason: 'encoding-unverified:number-not-encodable' };
    } else if (typeof v === 'string') {
      if (!claim(k, 'String')) return { ok: false, reason: 'encoding-unverified:sort-conflict' };
    } else return { ok: false, reason: 'encoding-unverified:constant-type' };
    constEntries.push([k, v]);
  }
  // Rename to v0..vN in sorted order: no escaping hazard, and two distinct names can never merge.
  const names = [...sorts.keys()].sort();
  const id = new Map(names.map((n, i) => [n, `v${i}`]));
  const lines = ['(set-logic ALL)'];
  for (const n of names) lines.push(`(declare-const ${id.get(n)} ${sorts.get(n)})`);
  const side = (s) => ('var' in s ? id.get(s.var) : realLiteral(s.const));
  let asserted = 0;
  for (const a of problem.assertions) {
    const alts = a.alternatives.map((conj) => {
      const parts = conj.map((l) => {
        if (l.t === 'num') return `(${OPS[l.op]} ${side(l.left)} ${side(l.right)})`;
        if (l.t === 'eq') return l.equal ? `(= ${id.get(l.var)} ${stringLiteral(l.value)})` : `(distinct ${id.get(l.var)} ${stringLiteral(l.value)})`;
        if (l.t === 'bool') return l.truth ? id.get(l.var) : `(not ${id.get(l.var)})`;
        return 'true'; // opaque: no constraint
      });
      return parts.length === 0 ? 'true' : parts.length === 1 ? parts[0] : `(and ${parts.join(' ')})`;
    });
    lines.push(`(assert ${alts.length === 0 ? 'false' : alts.length === 1 ? alts[0] : `(or ${alts.join(' ')})`})`);
    asserted += 1;
  }
  for (const [k, v] of constEntries.sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    lines.push(`(assert (= ${id.get(k)} ${typeof v === 'number' ? realLiteral(v) : stringLiteral(v)}))`);
    asserted += 1;
  }
  lines.push('(check-sat)');
  const text = lines.join('\n');
  // Structural self-check of the translation: every assertion of the problem became exactly one assert.
  const emitted = lines.filter((l) => l.startsWith('(assert ')).length;
  if (emitted !== problem.assertions.length + constEntries.length || asserted !== emitted) {
    return { ok: false, reason: 'encoding-unverified:assertion-count' };
  }
  return {
    ok: true, text, unmodeled, literals, assertions: emitted,
    sorts: Object.fromEntries(names.map((n) => [n, sorts.get(n)])),
    digest: crypto.createHash('sha256').update(text).digest('hex').slice(0, 16),
  };
}

// ---- the backend ---------------------------------------------------------------------------------------

/**
 * The default loader. Loaded through a createRequire call at first use, the way the optional tree-sitter
 * runtime is: a bundler keeps it external, and a build without the package fails here (reported as
 * unsupported by the caller), never at start-up.
 */
async function defaultLoader() {
  return require('z3-solver');
}

/**
 * Build a z3 backend.
 *
 * @param {object} [o]
 * @param {number} [o.timeoutMs]   per-query solver timeout (Z3 `timeout`)
 * @param {number} [o.memoryMb]    process memory cap handed to Z3 (`memory_max_size`)
 * @param {()=>Promise<object>} [o.loader]  returns the `z3-solver` module; injected by tests
 */
export function createZ3Solver({ timeoutMs = Z3_DEFAULT_TIMEOUT_MS, memoryMb = Z3_DEFAULT_MEMORY_MB, loader = defaultLoader } = {}) {
  const state = { initP: null, failed: null, api: null, ctx: null, version: null, queue: Promise.resolve() };
  const cache = new Map();
  const stats = { queries: 0, cacheHits: 0, loads: 0 };

  function init() {
    if (state.initP) return state.initP;
    state.initP = (async () => {
      stats.loads += 1;
      const mod = await loader();
      const initFn = mod?.init ?? mod?.default?.init;
      if (typeof initFn !== 'function') throw new Error('z3-solver has no init()');
      const api = await initFn();
      try { api.Z3.global_param_set('memory_max_size', String(memoryMb)); } catch { /* an older build without the knob */ }
      state.api = api;
      state.ctx = api.Context('lineage-smt');
      try { state.version = api.getVersionString?.() ?? null; } catch { state.version = null; }
      return state;
    })().catch((e) => {
      state.failed = String(e?.code || e?.name || 'load-error');
      state.initP = null;
      return null;
    });
    return state.initP;
  }

  async function run(enc, signal) {
    const ctx = state.ctx;
    const solver = new ctx.Solver();
    let abortHook;
    try {
      solver.set('timeout', timeoutMs);
      try { solver.set('random_seed', 0); } catch { /* not a parameter of this build */ }
      solver.fromString(enc.text);
      if (signal) {
        abortHook = () => { try { state.api.Z3.interrupt(ctx.ptr); } catch { /* best effort */ } };
        signal.addEventListener('abort', abortHook, { once: true });
      }
      // Z3 honours `timeout`, but a wedged wasm call must not hold the queue forever: past a grace period the
      // backend gives up on this context and reports itself unavailable from then on.
      let hardTimer;
      const hung = new Promise((resolve) => { hardTimer = setTimeout(() => resolve('hung'), timeoutMs + HARD_GRACE_MS); });
      const verdict = await Promise.race([solver.check(), hung]).finally(() => clearTimeout(hardTimer));
      if (verdict === 'hung') {
        try { state.api.Z3.interrupt(ctx.ptr); } catch { /* best effort */ }
        state.failed = 'hung';
        return { result: 'timeout', reason: 'z3-hung' };
      }
      if (verdict === 'unsat') return { result: 'unsat' };
      if (verdict === 'sat') return { result: 'sat' };
      const why = String(solver.reasonUnknown?.() ?? '');
      if (/timeout/i.test(why)) return { result: 'timeout', reason: 'z3-timeout' };
      if (/memout|memory/i.test(why)) return { result: 'unknown', reason: 'z3-memory' };
      if (/cancel/i.test(why)) return { result: 'unknown', reason: 'z3-cancelled' };
      return { result: 'unknown', reason: 'z3-unknown' };
    } finally {
      if (abortHook && signal) signal.removeEventListener('abort', abortHook);
    }
  }

  const backend = {
    name: 'z3',
    get version() { return state.version ? `${state.version}+${Z3_BACKEND_VERSION}` : Z3_BACKEND_VERSION; },
    /** False only after a load/initialisation failure; true (unknown yet) before the first query. */
    get available() { return state.failed === null; },
    get loadFailure() { return state.failed; },
    stats() { return { ...stats, cacheSize: cache.size }; },
    /** Never throws. `unsupported` when z3 is missing, `unknown` when the encoding cannot be verified. */
    async check(problem, { signal } = {}) {
      stats.queries += 1;
      const enc = encodeProblem(problem);
      if (!enc.ok) return { result: 'unknown', reason: enc.reason };
      const key = `${timeoutMs}|${enc.text}`;
      const hit = cache.get(key);
      if (hit) { stats.cacheHits += 1; cache.delete(key); cache.set(key, hit); return finish(hit, enc, true); }
      const ready = await init();
      if (!ready || state.failed) return { result: 'unsupported', reason: `z3-unavailable:${state.failed}` };
      // One query at a time: the wasm context is single-threaded.
      const turn = state.queue.then(() => run(enc, signal)).catch(() => ({ result: 'unknown', reason: 'z3-error' }));
      state.queue = turn.then(() => {}, () => {});
      const raw = await turn;
      if (raw.result === 'sat' || raw.result === 'unsat') {
        cache.set(key, raw);
        if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
      }
      return finish(raw, enc, false);
    },
    /** Release the wasm worker threads. The next query re-initialises. */
    async shutdown() {
      const api = state.api;
      state.initP = null; state.api = null; state.ctx = null;
      if (!api) return;
      try { const kt = (await loader())?.killThreads ?? null; if (kt && api.em) kt(api.em); } catch { /* nothing to release */ }
    },
  };
  return backend;
}

function finish(raw, enc, cached) {
  // A model that leaned on an unmodeled predicate says nothing about the real conditions.
  if (raw.result === 'sat' && enc.unmodeled > 0) return { result: 'unknown', reason: 'sat-with-unmodeled-predicates', encodingDigest: enc.digest, cached };
  return { ...raw, encodingDigest: enc.digest, cached };
}

let _shared = null;
/** The process-wide backend used when AGENTIC_SECURITY_LINEAGE_SMT=z3. */
export function sharedZ3Solver() {
  if (!_shared) _shared = createZ3Solver();
  return _shared;
}
export function smtBackendEnabled(env = process.env) {
  return env.AGENTIC_SECURITY_LINEAGE_SMT === 'z3';
}
