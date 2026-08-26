// Privacy sink policy (assurance-hardening PRD FR-404).
//
// `annotatePrivacyTaint` treats every SINK_PATTERNS match as unconditionally
// prohibited — any regulated-data class reaching log/response/outboundHttp/
// etc. always produces a finding, with no way to say "PII flowing to
// emailSend is expected here (password-reset emails), don't flag it." FR-404
// asks specifically for a POLICY-gated version of that emission: a finding
// still fires by default (nothing changes for a repo with no policy file —
// this is what keeps the PRD's own worked example, "email from request
// input to logging produces a mapped privacy finding", true unmodified), but
// an operator can mark a specific (data class, sink) pair — or a sink
// entirely, for every class — as policy-permitted, which suppresses the
// finding.
//
// Extended for FR-408 ("repository privacy policy defining prohibited and
// conditionally permitted flows... environment- and destination-specific
// decisions") with two additional, OPTIONAL rule axes: `environment` (this
// scan's deployment environment — resolved from AGENTIC_SECURITY_ENVIRONMENT,
// never from NODE_ENV, which this codebase's own env-hygiene detector
// already flags as "unreliable as a security boundary" for application
// code, and the same reasoning applies to a scanner's own policy decisions)
// and `destination` (a regex matched against the actual sink expression
// text — "stripe.track", not just the broader "thirdPartySdk" category).
// Both axes are ADDITIVE constraints and FAIL CLOSED: a rule naming an
// environment or destination the caller did not supply context for does
// NOT match — an unknown environment must never silently satisfy an
// environment-scoped permission, which is the entire point of adding the
// axis. A rule with neither field set behaves exactly as it did under
// FR-404 (unconstrained by environment/destination), so every FR-404 rule
// written before this extension keeps working unmodified.
//
// Suppression must be VISIBLE, not silent — same principle the root
// CLAUDE.md states for ignore-pragma suppressions ("a suppression nobody can
// see is indistinguishable from a finding that never fired"). A permitted
// flow is recorded on the annotator's `policyExemptions` array (see
// privacy-taint.js), never just dropped.

import * as fs from 'node:fs';
import { statePath } from '../posture/state-dir.js';

function _policyStatePath(scanRoot) {
  return statePath(scanRoot, 'privacy-policy.json');
}

/**
 * Load the operator's privacy sink policy. Never throws — a missing file
 * (ENOENT) is the common "no policy configured" case; a malformed one logs
 * a warning and degrades to the empty policy (everything prohibited, the
 * pre-FR-404 default). Returns { allow: [{sink, class?, reason?}] }.
 */
export function loadPrivacySinkPolicy(scanRoot) {
  const EMPTY = { allow: [] };
  if (!scanRoot) return EMPTY;
  const fp = _policyStatePath(scanRoot);
  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`agentic-security: bad JSON in privacy-policy.json — falling back to no policy (${e.message})`);
    }
    return EMPTY;
  }
  const allow = Array.isArray(raw?.allow)
    ? raw.allow.filter(r => r && typeof r.sink === 'string' && r.sink)
    : [];
  return { allow };
}

// FR-408: does `ruleEnv` (unset | string | string[]) cover `currentEnv`?
// Unset is unconstrained (matches anything, including an unknown
// environment — preserves FR-404 rules verbatim). Set-but-unknown-current
// fails closed: a rule scoped to an environment the caller never told us
// about must not match by accident.
function _matchesEnvironment(ruleEnv, currentEnv) {
  if (ruleEnv == null) return true;
  if (!currentEnv) return false;
  const allowed = Array.isArray(ruleEnv) ? ruleEnv : [ruleEnv];
  return allowed.some(e => typeof e === 'string' && e.toLowerCase() === String(currentEnv).toLowerCase());
}

// FR-408: does `rulePattern` (unset | regex source string) match `destText`
// (the raw sink expression, e.g. "stripe.track")? Same fail-closed shape as
// environment — an invalid operator-supplied regex never silently matches
// everything, and an unset destText for a destination-scoped rule doesn't
// match either.
function _matchesDestination(rulePattern, destText) {
  if (rulePattern == null) return true;
  if (!destText) return false;
  try { return new RegExp(rulePattern, 'i').test(destText); } catch { return false; }
}

function _rulesForSink(policy, sinkKind, ctx) {
  const allow = Array.isArray(policy?.allow) ? policy.allow : [];
  return allow.filter(r => r.sink === sinkKind
    && _matchesEnvironment(r.environment, ctx?.environment)
    && _matchesDestination(r.destination, ctx?.destination));
}

/**
 * Is `sinkKind` policy-permitted for every class in `classes`, in the
 * given context (`{environment?, destination?}`, both optional)? A rule
 * matches a class either explicitly (`rule.class === cls`) or by covering
 * the sink for ANY class (`rule.class` unset), AND must satisfy any
 * environment/destination constraint the rule itself declares (FR-408).
 * Returns true only when every matched class has a covering rule — a
 * finding combining a permitted class with an unpermitted one (e.g.
 * "PII+CREDENTIALS both flow to log, but only PII→log was allowed") must
 * still fire, not be silently swept away by a partial allow rule.
 */
export function isSinkPermitted(classes, sinkKind, policy, ctx = {}) {
  if (!Array.isArray(classes) || !classes.length) return false;
  const rulesForSink = _rulesForSink(policy, sinkKind, ctx);
  if (!rulesForSink.length) return false;
  return classes.every(cls => rulesForSink.some(r => !r.class || r.class === cls));
}

/**
 * The specific rule(s) that permitted a class for a sink in the given
 * context, for exemption disclosure (reason strings, when the operator
 * supplied one).
 */
export function permittingRules(classes, sinkKind, policy, ctx = {}) {
  return _rulesForSink(policy, sinkKind, ctx).filter(r => !r.class || classes.includes(r.class));
}
