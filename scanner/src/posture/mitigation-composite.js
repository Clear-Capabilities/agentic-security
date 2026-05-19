// FR-PROD-7 — Mitigation-aware composite verdict.
//
// Composite the per-control mitigation signals (WAF, telemetry, auth posture,
// network policy, feature flags, reachability) into ONE verdict per finding:
//
//   exposed-in-prod      — at least one control path leaves this finding reachable
//   mitigated-in-prod    — at least one production control would block this attack
//   unreachable-in-prod  — the code path is not reachable from any prod entry
//
// Rules:
//   1. If `unreachable` flag is set by reachability-filter AND no production
//      entry signal contradicts it → unreachable-in-prod.
//   2. If any of (waf, auth, network, flag-gated-off) blocks → mitigated-in-prod.
//      Note: PROD-1 deliberately under-approximates; we only set this verdict
//      when the control unambiguously blocks the attack.
//   3. Otherwise → exposed-in-prod.
//
// Distinct from f.exploitability (an ordinal priority): this verdict is a
// hard label used by `--firehose` filtering and the PR-comment bot.

export function annotateMitigationComposite(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const mitigations = [];
    if (f.mitigatedByWaf) mitigations.push('waf:' + (f.wafRuleId || 'present'));
    if (f.mitigatedByAuth) mitigations.push('auth:' + (f.authMechanism || 'present'));
    if (f.mitigatedByNetwork) mitigations.push('network:' + (f.networkPolicyName || 'present'));
    if (f.featureFlagState === 'gated-off') mitigations.push('flag-off:' + (f.featureFlag || 'unknown'));

    const unreachable = f.unreachable === true || f.reachable === false;
    // A finding can be both `unreachable` (static) and `mitigated` (runtime).
    // Prefer the more informative production-aware label when both apply.
    if (mitigations.length > 0) {
      f.mitigatedInProd = true;
      f.exposedInProd = false;
      f.unreachableInProd = false;
      f.mitigationVerdict = 'mitigated-in-prod';
      f.mitigationsApplied = mitigations;
    } else if (unreachable) {
      f.mitigatedInProd = false;
      f.exposedInProd = false;
      f.unreachableInProd = true;
      f.mitigationVerdict = 'unreachable-in-prod';
      f.mitigationsApplied = [];
    } else {
      f.mitigatedInProd = false;
      f.exposedInProd = true;
      f.unreachableInProd = false;
      f.mitigationVerdict = 'exposed-in-prod';
      f.mitigationsApplied = [];
    }
  }
  return findings;
}
