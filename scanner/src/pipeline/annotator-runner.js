// Annotator runner (assurance-hardening PRD, Milestone 0/1, FR-106).
//
// Extracted from engine.js's local `_runAnnotator` closure so the Promise-
// aware error-capture contract can be fault-injection tested directly,
// without needing a real annotator to actually throw (this codebase's
// annotators are deliberately built never to — see posture/CLAUDE.md's "no
// throwing" convention — which is good for production but means there was
// no natural way to prove the capture path works end-to-end before this
// module existed). engine.js's `_runAnnotator` is now a thin wrapper that
// closes over its local `_annotatorErrors` array and delegates here; this
// module has no engine.js-specific state, so it takes the errors array as a
// parameter instead of a closure.
//
// Contract: a rejection or thrown error from `fn()` — sync or async — is
// captured as a structured entry, never left to become an unhandled
// rejection or to race ahead of the caller. The caller MUST `await` this
// function for the second half of that contract (capture-before-return) to
// hold; see engine.js's call sites, all of which now do.

/**
 * @param {Array<{phase:string, err:string}>} annotatorErrors - mutated in place (push only)
 * @param {string} phase - name recorded on a captured error
 * @param {() => any} fn - sync or async callback
 * @returns {Promise<any>} fn()'s resolved value, or undefined if it threw/rejected
 */
export async function runAnnotatorAsync(annotatorErrors, phase, fn) {
  try {
    return await fn();
  } catch (e) {
    annotatorErrors.push({ phase, err: String((e && e.message) || e) });
    return undefined;
  }
}
