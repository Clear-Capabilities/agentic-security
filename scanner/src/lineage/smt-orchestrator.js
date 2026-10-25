//
// smt-orchestrator.js: the optional solver path for witness conditions (DAG-04, R04.3 / R04.4).
//
// The bounded abstract domains in path-predicates.js decide first. A solver is consulted only when they
// say `unknown`, and only through this module, which makes the call:
//   * awaited: the caller gets one settled result, never a dangling promise;
//   * time-bounded: a deadline races the solver, and a solver that ignores it is still released;
//   * cancellable: an AbortSignal from the caller and the module's own deadline both abort the solver's
//     signal, and a late settlement from an abandoned solver is swallowed;
//   * honest: no solver reports `unsupported`, a deadline reports `timeout`, a malformed or failing solver
//     reports `unknown`. None of these ever drops or downgrades the finding. The abstract result is kept.
//
// No solver ships here and no dependency is added. `noSolver` is the default stub. A real solver is an
// object with `{ name, version?, available?, check(problem, { signal }) -> Promise<{ result }> }` where
// `result` is 'sat' | 'unsat' | 'unknown'. `problem` is the solver-neutral view from `toSolverProblem`.
// Satisfiability never implies exploitability.

import { evaluateWitnessConditions, toSolverProblem, PATH_PREDICATE_VERSION, SATISFIABILITY_NOTE } from './path-predicates.js';

export const SOLVER_DEFAULT_TIMEOUT_MS = 1000;
export const SOLVER_TIMEOUT_MAX_MS = 60_000;

/** The default: a solver that is not there. */
export const noSolver = Object.freeze({
  name: 'none', version: null, available: false,
  async check() { return { result: 'unsupported' }; },
});

const MAP = Object.freeze({ sat: 'feasible-model', unsat: 'infeasible-under-model', unknown: 'unknown' });

/** Render the problem as SMT-LIB 2 text for a solver adapter that wants text. Opaque predicates become comments. */
export function toSmtLib(problem) {
  const lines = ['(set-logic ALL)'];
  const sym = (s) => `|${String(s).replace(/\|/g, '_')}|`;
  const num = (side) => (side.var ? sym(side.var) : String(side.const));
  for (const v of problem.vars) lines.push(`(declare-const ${sym(v)} Int)`);
  for (const a of problem.assertions) {
    const alts = a.alternatives.map((alt) => {
      const parts = alt.map((l) => {
        if (l.t === 'num') {
          const op = { '<': '<', '<=': '<=', '>': '>', '>=': '>=', '==': '=', '===': '=', '!=': 'distinct', '!==': 'distinct' }[l.op];
          return `(${op} ${num(l.left)} ${num(l.right)})`;
        }
        if (l.t === 'eq') return `(${l.equal ? '=' : 'distinct'} ${sym(l.var)} ${JSON.stringify(l.value)})`;
        if (l.t === 'bool') return l.truth ? 'true' : 'false';
        return 'true';
      });
      return parts.length === 1 ? parts[0] : `(and ${parts.join(' ') || 'true'})`;
    });
    lines.push(`; ${a.ref}`);
    lines.push(`(assert ${alts.length === 0 ? 'false' : alts.length === 1 ? alts[0] : `(or ${alts.join(' ')})`})`);
  }
  lines.push('(check-sat)');
  return lines.join('\n');
}

function boundedTimeout(ms) {
  if (ms === undefined) return SOLVER_DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(ms) || ms < 0 || ms > SOLVER_TIMEOUT_MAX_MS) return null;
  return Math.floor(ms);
}

/**
 * Ask a solver about the collected conditions. Always resolves; never throws.
 *
 * @returns {Promise<{status:string, reasons:string[], solver:object, elapsedMs:number, semanticsVersion:string, limitations:string[]}>}
 */
export async function checkWithSolver(collected, { solver = noSolver, timeoutMs, signal, now = Date.now } = {}) {
  const started = now();
  const info = { name: solver?.name ?? 'unknown', version: solver?.version ?? null };
  const out = (status, reasons, extra = {}) => ({
    status, reasons, solver: info, elapsedMs: now() - started, semanticsVersion: PATH_PREDICATE_VERSION,
    satisfiabilityNote: SATISFIABILITY_NOTE,
    limitations: ['A solver result is relative to the encoded conditions, not to the running program.', ...(extra.limitations ?? [])],
    ...(extra.model ? { model: extra.model } : {}),
  });
  const tmo = boundedTimeout(timeoutMs);
  if (tmo === null) return out('unknown', ['invalid-timeout']);
  if (!solver || solver.available === false || typeof solver.check !== 'function') return out('unsupported', ['no-solver']);
  if (signal?.aborted) return out('unknown', ['cancelled']);

  const ac = new AbortController();
  let timer; let onAbort;
  const timeoutP = new Promise((resolve) => { timer = setTimeout(() => resolve({ __timeout: true }), tmo); });
  const cancelP = new Promise((resolve) => {
    if (!signal) return;
    onAbort = () => resolve({ __cancelled: true });
    signal.addEventListener('abort', onAbort, { once: true });
  });
  let solverP;
  try {
    solverP = Promise.resolve(solver.check(toSolverProblem(collected), { signal: ac.signal }));
  } catch {
    clearTimeout(timer);
    return out('unknown', ['solver-error']);
  }
  // A solver that settles after we gave up must not become an unhandled rejection.
  solverP.catch(() => {});
  try {
    const r = await Promise.race([solverP, timeoutP, cancelP]);
    if (r && r.__timeout) { ac.abort(); return out('timeout', ['solver-deadline']); }
    if (r && r.__cancelled) { ac.abort(); return out('unknown', ['cancelled']); }
    const status = isObjectWithResult(r) ? MAP[r.result] : undefined;
    if (r?.result === 'unsupported') return out('unsupported', ['solver-declined']);
    if (!status) return out('unknown', ['solver-malformed']);
    return out(status, [`solver-${r.result}`], r.result === 'sat' && r.model && typeof r.model === 'object' ? { model: r.model } : {});
  } catch {
    return out('unknown', ['solver-error']);
  } finally {
    clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener('abort', onAbort);
  }
}

function isObjectWithResult(r) { return typeof r === 'object' && r !== null && typeof r.result === 'string'; }

/**
 * The full decision: abstract domains first, then the solver only when the abstract answer is `unknown`.
 * The abstract answer stays on the result, so a timeout or an unsupported solver never erases what the
 * cheap model already established, and the finding stays visible as unknown/partial.
 */
export async function evaluateWitnessConditionsAsync(collected, o = {}) {
  const abstract = evaluateWitnessConditions(collected, o);
  if (abstract.status !== 'unknown') return { ...abstract, abstractStatus: abstract.status, solverConsulted: false };
  const s = await checkWithSolver(collected, o);
  if (s.status === 'unsupported') return { ...abstract, abstractStatus: abstract.status, solverConsulted: false, solver: s.solver, solverStatus: 'unsupported' };
  if (s.status === 'timeout') {
    return { ...abstract, status: 'timeout', reasons: [...abstract.reasons, 'solver-deadline'], abstractStatus: abstract.status, solverConsulted: true, solver: s.solver, solverStatus: 'timeout', elapsedMs: s.elapsedMs };
  }
  if (s.status === 'unknown') {
    return { ...abstract, abstractStatus: abstract.status, solverConsulted: true, solver: s.solver, solverStatus: 'unknown', reasons: [...abstract.reasons, ...s.reasons], elapsedMs: s.elapsedMs };
  }
  return {
    ...abstract, status: s.status, reasons: s.reasons, abstractStatus: abstract.status, solverConsulted: true, solver: s.solver, solverStatus: s.status,
    limitations: [...abstract.limitations, ...s.limitations], elapsedMs: s.elapsedMs,
    contradiction: s.status === 'infeasible-under-model' ? { kind: 'solver-unsat', refs: abstract.clauseRefs } : null,
  };
}
