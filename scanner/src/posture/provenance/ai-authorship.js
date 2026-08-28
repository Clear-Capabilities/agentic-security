// AI-authorship verification hook (Finding Provenance PRD, M4 §4.3).
//
// No concrete external signed-commit-metadata standard exists yet to target
// (the spec's own words) — so this is an extensible REGISTRY a future
// verifier plugs into, not a hardcoded vendor integration. With nothing
// registered (today's real state, and likely for some time), every
// finding's aiAuthorship stays `unknown` — matching the PRD's explicit
// default: "Unknown unless signed, verifiable generation metadata exists."
//
// Scoped to SAST findingOrigin only (see this plan's own scope-correction
// note) — a transitive/direct SCA origin is a manifest edit, not source
// authorship in the sense this hook asks about.
//
// KNOWN LIMITATION: `commitMeta` (git-evidence.js) is the only shape any
// verifier registered here ever receives — `{commit, authorName,
// authorEmail, authorDate, committerDate, summary}`, where `summary` is
// `%s` (the subject line only), NOT the full commit message body (`%B`).
// A future verifier that needs to inspect a trailer buried in the body
// (e.g. a "Co-Authored-By" line that isn't also the subject) cannot see it
// through this shape today. `commitMeta` is a widely-used shared primitive
// elsewhere in this directory, so widening it is a bigger, more careful
// change than this task's budget — deliberately left as a known limitation
// rather than silently expanding it here.

const _verifiers = new Map();

/**
 * Register a verifier. `verifyFn(commitMeta) -> {status, verifier} | null`.
 * A later registration under the SAME name replaces the earlier one (a
 * re-register, not a stack) — matches this codebase's own precedent
 * elsewhere (verification-separation.js's "one verifier, one vote per lens,
 * a re-vote replaces rather than stuffs").
 */
export function registerAIAuthorshipVerifier(name, verifyFn) {
  if (typeof name !== 'string' || !name || typeof verifyFn !== 'function') return false;
  _verifiers.set(name, verifyFn);
  return true;
}

/** Test/reset helper — never called from production code. */
export function _clearAIAuthorshipVerifiers() {
  _verifiers.clear();
}

/**
 * Consults every registered verifier in registration order; the first one
 * to return a non-null result wins (first-registered-first-consulted, not
 * "last wins" — an explicit choice: a more specific verifier should be
 * registered first if precedence matters, rather than this function
 * guessing which of several opinions to prefer). Defaults to
 * {status:'unknown', verifier:null} with nothing registered or every
 * verifier declining to answer.
 *
 * NEVER THROWS: a verifier that throws is treated as "no opinion", exactly
 * like predicate-replay.js and missing-control-resolver.js already treat a
 * throwing caller-supplied function elsewhere in this directory.
 */
export function resolveAIAuthorship(commitMeta) {
  if (!commitMeta) return { status: 'unknown', verifier: null };
  for (const [name, verifyFn] of _verifiers) {
    let result;
    try { result = verifyFn(commitMeta); } catch { continue; }
    if (result && typeof result === 'object' && result.status) {
      return { status: result.status, verifier: result.verifier || name };
    }
  }
  return { status: 'unknown', verifier: null };
}
