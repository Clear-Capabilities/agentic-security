// The one assurance decision every user-facing surface states (the GA plan, GA-11.7): the CLI ship verdict, the Slack, Discord and
// Teams digests and the pull-request comment all call `assuranceDecision` and print its wording, so a surface can no longer decide
// from severity counts alone. The decision vocabulary is the release verdict's (`release-verdict.js`): `deployable`, `needs_review`,
// `not_deployable`, plus `unknown` when no scan health was recorded, because a result that cannot say whether the scan completed
// cannot say anything about deployability.
//
// Rules, in order:
//   - actionable findings (critical or high)                               -> not_deployable (an incomplete or missing scan health is noted)
//   - no scan health at all (a findings file with no health record)        -> unknown: zero findings with no record of completion prove nothing
//   - scan health not `complete`, no actionable findings                   -> needs_review (the first condition is the reason)
//   - complete, no actionable findings                                     -> deployable
//
// Wording: the default strings are the ones the CLI, the docs and the brand assets have carried since the ship verdict existed, kept
// so that existing output stays recognisable; the bounded wording of the `portfolio-assurance` feature (`portfolio/wording.js`) is the
// opt-in alternative and the surfaces still choose it the way they did. What is new is the `unknown` state and that every surface
// derives its wording from the same decision.
// the four decisions: deployable, needs_review, not_deployable, unknown

const WORDING = Object.freeze({
  deployable: { icon: '✅', headline: 'Safe to deploy' },
  not_deployable: { icon: '❌', headline: 'Not safe to deploy' },
  needs_review: { icon: '⚠️', headline: 'Scan incomplete — cannot confirm safe to deploy' },
  unknown: { icon: '⚠️', headline: 'Cannot confirm safe to deploy — no scan health recorded' },
});

/**
 * @param {object} p
 * @param {number|Array} p.actionable   the critical and high findings (a count or the array)
 * @param {object|null} p.scanHealth    scan.scanHealth, or null when none was recorded
 * @returns {{decision:string, icon:string, headline:string, reason:string, actionable:number, scanStatus:string|null, condition:string|null}}
 */
export function assuranceDecision({ actionable = 0, scanHealth = null } = {}) {
  const n = Array.isArray(actionable) ? actionable.length : Number(actionable) || 0;
  const health = scanHealth && typeof scanHealth === 'object' && typeof scanHealth.status === 'string' ? scanHealth : null;
  const conditions = health && Array.isArray(health.conditions) ? health.conditions : [];
  const condition = conditions[0] || (health && health.status !== 'complete' ? 'analysis did not complete cleanly' : null);
  let decision;
  let reason;
  if (n > 0) { decision = 'not_deployable'; reason = `${n} actionable finding(s)${!health ? ' (no scan health recorded)' : health.status !== 'complete' ? `, and the scan is ${health.status}: ${condition}` : ''}`; }
  else if (!health) { decision = 'unknown'; reason = 'no scan health was recorded with this result, so whether the scan completed is unknown'; }
  else if (health.status !== 'complete') { decision = 'needs_review'; reason = `no actionable finding, but the scan is ${health.status}: ${condition}${conditions.length > 1 ? ` (+${conditions.length - 1} more)` : ''}`; }
  else { decision = 'deployable'; reason = 'no critical or high finding and every analyzer finished'; }
  return { decision, ...WORDING[decision], reason, actionable: n, scanStatus: health ? health.status : null, condition };
}

