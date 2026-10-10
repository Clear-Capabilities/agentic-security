// Bounded assurance wording (X-703.AC03).
//
// A scan that found nothing blocking has said something narrow: the checks that ran, on the code and policy it names, found nothing the
// policy blocks. It has not said the software is safe, secure or free of vulnerabilities, and a signature on the result does not turn
// it into independent certification. Unconditional "Safe to deploy" wording over-claims in exactly the case where a check did not
// run, so with the `portfolio-assurance` feature on the verdict becomes the headline below followed by the scope and the gaps.
//
// The old wording stays the default. Existing fixtures and docs pin it; the change is additive behind the feature flag
// (assurance/config.js, `portfolio-assurance`, default off), so a flag-off run is byte-identical to before.

import { resolveAssuranceConfig, featureStatus } from '../assurance/config.js';

export const FEATURE_ID = 'portfolio-assurance';
export const HEADLINE = 'No blocking findings in completed supported checks';
export const BLOCKED_HEADLINE = 'Blocking findings present in completed supported checks';
const INCOMPLETE_HEADLINE = 'Blocking-finding checks did not complete';
export const NOT_A_GUARANTEE = 'This does not mean the software is safe or free of vulnerabilities, and a signature on it is not independent certification.';

/** Is the bounded wording on? An explicit boolean option wins; otherwise the assurance configuration (kill switch, environment, project file) decides. */
export function portfolioAssuranceEnabled({ option, env = process.env, scanRoot } = {}) {
  if (typeof option === 'boolean') return option;
  try {
    return featureStatus(resolveAssuranceConfig({ scanRoot, env }), FEATURE_ID).status === 'ok';
  } catch { return false; }
}

/**
 * The bounded statement for a validated manifest: headline, scope and gaps, in that order. `signature` is the optional result of
 * `verifyAssuranceClaim`; it can only ADD the trust-basis disclosure, never soften the headline.
 */
export function assuranceStatement(manifest, { signature = null } = {}) {
  const cov = manifest.coverage;
  const blocking = manifest.findings.blocking;
  let headline = HEADLINE;
  if (blocking > 0) headline = `${BLOCKED_HEADLINE}: ${blocking}`;
  else if (!cov.complete) headline = `${HEADLINE}, but the mandatory scope is not fully covered`;
  const scope = `Scope: ${cov.completed} of ${cov.mandatory} mandatory checks completed, ${cov.waived} waived, ${cov.incomplete} incomplete, ${cov.unsupported} unsupported. ${manifest.scope.description}`;
  const gaps = [];
  for (const c of manifest.checks.incomplete) gaps.push(`incomplete: ${c.id} (${c.gaps.join('; ')})`);
  for (const c of manifest.checks.unsupported) gaps.push(`unsupported: ${c.id} (${c.gaps.join('; ')})`);
  for (const c of manifest.checks.waived) gaps.push(`waived: ${c.id} (${c.reason}; approved by ${c.approvedBy})`);
  for (const r of manifest.residualRisks) gaps.push(`residual risk: ${r.id} (${r.statement})`);
  const lines = [headline, scope, gaps.length ? `Gaps: ${gaps.join(' | ')}` : 'Gaps: none recorded in the manifest', `Policy: ${manifest.policy.id} (blocking severity ${manifest.policy.blockingSeverity} and above)`];
  if (manifest.synthetic === true) lines.push('Synthetic fixture: this describes no real release.');
  if (signature) {
    lines.push(signature.ok
      ? `Signature: valid under trust basis ${signature.trustBasis} (self-issued, signer ${signature.signer}). It shows the manifest is unmodified; it is not independent certification.`
      : `Signature: NOT valid (${signature.reason}). Treat this statement as unverified.`);
  }
  lines.push(NOT_A_GUARANTEE);
  return { headline, scope, gaps, blocking, complete: cov.complete, text: lines.join('\n') };
}

/** Headline for the one-screen scan verdict, from what a plain scan knows (no manifest). */
export function scanVerdictWording({ clean, scanIncomplete, actionableCount }) {
  if (clean) return { icon: '✅', headline: HEADLINE, tier: 'ok' };
  if (actionableCount === 0 && scanIncomplete) return { icon: '⚠️', headline: INCOMPLETE_HEADLINE, tier: 'incomplete' };
  return { icon: '❌', headline: `${BLOCKED_HEADLINE}: ${actionableCount}`, tier: 'blocked' };
}
