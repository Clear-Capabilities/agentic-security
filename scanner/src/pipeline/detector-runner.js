// Detector runner (assurance-hardening PRD, E2 decomposition — D-0028 step
// (a): "build a small `_runDetector(errs, file, name, thunk)` isolation
// helper first (low-risk, no call sites touched yet)").
//
// FR-201: "Execute detectors in isolated units with per-analyzer error
// capture | One detector exception does not prevent subsequent independent
// analyzers from running."
//
// Modeled directly on `annotator-runner.js`'s own runAnnotatorAsync (FR-106,
// already shipped) — same isolation contract, same "extract into its own
// file so the capture path can be fault-injection tested directly" rationale
// (this codebase's own detectors are built never to throw in practice, so
// there is no natural way to prove the isolation works end-to-end without
// synthetic throwing callbacks). The one real difference: every one of
// `engine.js`'s ~128 per-file detector call sites is SYNCHRONOUS — none
// return a Promise — so this helper is deliberately sync-only, not a
// generic sync-or-async wrapper. Wrapping ~128 calls per file in an async
// function across every scanned file would add real Promise-microtask
// overhead to the hottest loop in the engine for no benefit any detector
// actually needs.
//
// THIS MODULE HAS NO CALLER YET, BY DESIGN. D-0028's own decomposition is
// explicit that step (a) — this helper — must exist and be proven correct
// BEFORE step (b) (migrating the ~128 heterogeneous call sites in small,
// git-diffable, gate-verified batches) begins. Wiring it into engine.js
// is intentionally out of scope for this step.

/**
 * Run one detector (`fn`), isolating any exception it throws so it cannot
 * abort the caller's per-file loop. On success, returns `fn()`'s value
 * unchanged. On a thrown exception, appends a structured entry to
 * `detectorErrors` and returns `undefined` — the SAME "undefined means it
 * failed, check the errors array" contract `runAnnotatorAsync` already
 * establishes, so a caller spreading the result into an array must guard
 * with `...(runDetector(...) || [])`, exactly as existing `_runAnnotator`
 * call sites already do for their own non-array return values.
 *
 * @param {Array<{file:string, analyzer:string, err:string}>} detectorErrors - mutated in place (push only)
 * @param {string} file - the file being analyzed when `fn` was invoked
 * @param {string} analyzer - the detector's name, for FR-203's future per-analyzer coverage ledger
 * @param {() => any} fn - the detector call itself, e.g. `() => scanXxx(file, cc)`
 * @returns {any} fn()'s return value, or undefined if it threw
 */
export function runDetector(detectorErrors, file, analyzer, fn) {
  try {
    return fn();
  } catch (e) {
    detectorErrors.push({ file, analyzer, err: String((e && e.message) || e) });
    return undefined;
  }
}
