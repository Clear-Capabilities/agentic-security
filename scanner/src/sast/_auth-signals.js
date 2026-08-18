// Shared cross-framework "is this handler actually protected?" resolver.
//
// WHY THIS EXISTS (PRD Theme 1, T1.2). Every authz-adjacent detector used to
// hand-roll its own list of blessed middleware/dependency names, and each list
// was a closed enumeration. Real codebases name their auth helpers whatever
// they like, so the enumerations missed, and the detectors emitted findings
// asserting an ABSENCE that the same file visibly contradicts.
//
// The measured cost of that, from the 2026-08-17 independent-population audit:
// GHSA-3cg5-48j3-v4gv scored as a TRUE POSITIVE for "FastAPI mutating endpoint
// create_folder() has no Security() / Depends() auth dependency" against a
// function whose signature reads `user=Depends(get_verified_user)` and whose
// first statement is `await check_folders_permission(request, user, db=db)`.
// The claim was false about the code; it scored only because the CWE and file
// happened to line up with an unrelated fix 200 lines away. Two more entries in
// the same population failed the same way.
//
// The rule this module encodes: an absence-claim must be checked against BOTH
// the handler's injected dependencies AND its body. A detector that looks only
// at a signature cannot see `check_folders_permission(...)`, and one that looks
// only for known names cannot see a project's own convention.
//
// Deliberately biased toward RECOGNISING auth. A false "this is protected"
// costs one missed finding; a false "this is unprotected" is a wrong statement
// about code the reader can see, which is what destroys trust in every other
// finding the tool emits.

/**
 * Security NOUNS — the concepts that make an identifier about authentication
 * or authorization. Matched against a CALLEE or PARAMETER name, never against
 * free text, so a comment or string literal cannot satisfy it.
 *
 * Deliberately nouns, not action verbs. An earlier draft included bare
 * `session`, `access`, `verify` and `require`, and its own test immediately
 * caught the consequence: `Depends(get_async_session)` — a DATABASE session —
 * read as authentication evidence and would have silently suppressed real
 * missing-auth findings. Over-suppression is the dangerous direction for this
 * module (it hides vulnerabilities), so ambiguous stems are excluded and only
 * their unambiguous compounds are listed. Verbs are handled separately in
 * hasAuthInBody, where they must co-occur with one of these nouns.
 */
const AUTH_NAME_RE = new RegExp([
  'auth', 'authn', 'authz', 'authoriz', 'authoris',
  'login', 'logged_?in', 'jwt', 'oauth', 'oidc', 'saml',
  'principal', 'identity', 'credential', 'password',
  'user',                          // covers current_/verified_/active_/request_user
  'permission', 'privilege', 'role', 'scope',
  'admin', 'superuser', 'staff',
  'api_?key', 'apikey', 'bearer', 'access_?token', 'access_?control',
  '(?:user|auth|login|web|http)_?session', 'session_?(?:user|token|id)',
].join('|'), 'i');

/**
 * A dependency-injection wrapper: FastAPI Depends()/Security(), NestJS, etc.
 * Group 1 is the wrapper, group 2 the injected callee (absent for `Security()`).
 */
const DI_CALL_RE = /\b(Depends|Security)\s{0,8}\(\s{0,8}([A-Za-z_$][\w$.]{0,128})?/g;

/**
 * Does a handler's PARAMETER LIST carry injected auth?
 *
 * Recognises the DI shape first (`Depends(x)` / `Security(x)` with an
 * auth-shaped callee), then falls back to an auth-shaped parameter NAME —
 * `user`, `current_user`, `principal` — which is how most frameworks surface
 * an already-resolved identity.
 */
export function hasAuthInParams(paramsText) {
  const params = String(paramsText || '');
  if (!params.trim()) return null;

  DI_CALL_RE.lastIndex = 0;
  let m;
  while ((m = DI_CALL_RE.exec(params))) {
    const wrapper = m[1];
    const callee = m[2] || '';
    // `Security(...)` is an auth construct by definition, whatever it wraps —
    // FastAPI has no non-security use for it. `Depends(...)` is generic
    // dependency injection (DB sessions, config, pagination), so it only
    // counts when the injected callee itself names a security concept.
    if (wrapper === 'Security' || AUTH_NAME_RE.test(callee)) {
      return { authenticated: true, reason: `dependency-injected auth: ${wrapper}(${callee || '…'})` };
    }
  }

  // Parameter name shapes: `user: User`, `user=Depends(...)`, `current_user`.
  for (const p of params.split(',')) {
    const name = (p.split(/[:=]/)[0] || '').trim().replace(/^\*+/, '');
    if (!name) continue;
    if (/^(?:user|current_user|principal|identity|viewer|actor|me)$/i.test(name)) {
      return { authenticated: true, reason: `auth-shaped handler parameter: ${name}` };
    }
  }
  return null;
}

/**
 * Does a handler BODY perform an explicit authorization check?
 *
 * This is the half the FastAPI detector was missing entirely. A project's own
 * `check_folders_permission(...)` is not in anyone's enumeration of blessed
 * names, but it is unmistakably an authorization call at the call site.
 */
export function hasAuthInBody(bodyText) {
  const body = String(bodyText || '');
  if (!body.trim()) return null;
  // Call shape: <name>(...) where the callee name is auth-shaped AND reads as
  // an action (check/require/verify/ensure/assert/validate/has/can/enforce).
  // Bounded repetition throughout: this walks third-party source, so a
  // pathological identifier chain must not become a scanner-side ReDoS.
  // Only the FINAL segment is used, so the dotted qualifier is not matched at
  // all — which also keeps this free of the nested quantifier the project's own
  // redos-nfa.js correctly flags on `(?:\w+\.)*` shapes.
  const callRe = /\b([A-Za-z_$][\w$]{0,63})\s{0,8}\(/g;
  let m;
  while ((m = callRe.exec(body))) {
    const callee = m[1];
    const actiony = /^(?:check|require|ensure|verify|assert|validate|enforce|has|can|is|get|authorize|authorise|guard)/i.test(callee);
    if (actiony && AUTH_NAME_RE.test(callee)) {
      return { authenticated: true, reason: `explicit authorization call in body: ${callee}()` };
    }
  }
  // Raise-on-forbidden shape: an explicit 401/403 the handler itself emits.
  if (/\b(?:HTTP_401_UNAUTHORIZED|HTTP_403_FORBIDDEN|UnauthorizedError|ForbiddenError|status_code\s*=\s*40[13]|\b40[13]\b\s*,)/.test(body)) {
    return { authenticated: true, reason: 'handler raises an explicit 401/403' };
  }
  return null;
}

/**
 * The single question every authz detector should ask before asserting that a
 * handler is unprotected. Returns null when there is no evidence (i.e. the
 * detector may fire), or {authenticated:true, reason} when it must not.
 *
 * `reason` exists so the finding — or its absence — is explainable, per the
 * PRD's T2.2 requirement that an absence-claim record what it looked for.
 */
export function routeAuthEvidence({ params = '', body = '' } = {}) {
  return hasAuthInParams(params) || hasAuthInBody(body) || null;
}

export const _internals = { AUTH_NAME_RE, hasAuthInParams, hasAuthInBody };
