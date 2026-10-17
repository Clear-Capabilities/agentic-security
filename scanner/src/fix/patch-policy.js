// Risk-tiered patch policy (E3-06): given a verified-patch record, may it be applied without a person, proposed for a person, or refused?
//
// Two modes. `requested` is a person (or an agent acting for one) who asked for the write: it proceeds on any tier that is not
// unverified or blocked, and the result carries the degraded legs as warnings so nothing about the pass is hidden. `automatic` is
// anything that would write with nobody asking: it is OFF unless the policy enables it, and even then it applies only a configured
// low-risk patch whose every REQUIRED check passed. Absent tests, a replay that did not run, an unobservable footprint, or any other
// degraded leg make an automatic write a proposal, never a silent write. Preview and undo are never removed by this module.
//
// Pure: no fs, no clock.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const AUTH_CATEGORIES = /auth|crypto|permission|access|privilege|session|tenant/i;

export const DEFAULT_POLICY = Object.freeze({
  automatic: Object.freeze({ enabled: false, maxSeverity: 'medium', allowedMaterialRisk: Object.freeze(['low']), requireExploitProof: false, maxResidualRisk: 'low' }),
});
const RESIDUAL_RANK = { none: 0, low: 1, medium: 2, high: 3, unknown: 4 };

export { deriveResidualRiskOf as deriveResidualRisk } from './verification-record.js';

const decide = (decision, record, reasons, extra = {}) => ({ decision, tier: record.fixCompleteness, verifiedFull: record.verifiedFull, residualRisk: record.residualRisk, reasons, warnings: record.degradedLegs, preview: true, undo: true, ...extra });

/**
 * @param {{record:object, finding?:{severity?:string}, materialClassification?:{highImpactCategories?:string[], risk?:string}, mode?:'requested'|'automatic', policy?:object}} o
 */
export function decidePatchApplication({ record, finding = {}, materialClassification = {}, mode = 'requested', policy = DEFAULT_POLICY }) {
  const tier = record.fixCompleteness;
  if (tier === 'blocked') return decide('refuse', record, ['a required check was blocked or a failure was recorded, so the patch cannot be applied']);
  if (tier === 'unverified') return decide('refuse', record, ['the weakness is not shown to be gone, or a check failed']);
  if (mode === 'requested') return decide('apply', record, [`${tier}: applied at the request of a person`]);

  const a = { ...DEFAULT_POLICY.automatic, ...(policy?.automatic || {}) };
  if (!a.enabled) return decide('propose', record, ['automatic application is not enabled by policy; the patch is proposed for a person to apply']);
  const reasons = [];
  if (tier !== 'FULL') reasons.push(`completeness is ${tier}, automatic application needs FULL`);
  if (!record.verifiedFull) reasons.push('not every required check passed');
  for (const d of record.degradedLegs) reasons.push(`degraded: ${d}`);
  if (a.requireExploitProof && record.exploitProofAfter.status !== 'passed') reasons.push('policy requires an exploit replay and none confirmed the fix');
  for (const leg of ['behaviorTests', 'behaviorPreservation']) if (record[leg].status !== 'passed') reasons.push(`${leg} did not pass (${record[leg].status})`);
  const sev = SEVERITY_RANK[String(finding.severity || '').toLowerCase()];
  if (sev === undefined) reasons.push('the finding severity is unknown');
  else if (sev > SEVERITY_RANK[a.maxSeverity]) reasons.push(`severity ${finding.severity} is above the automatic limit (${a.maxSeverity})`);
  const cats = materialClassification.highImpactCategories || [];
  if (cats.length) reasons.push(`high-impact change (${cats.join(', ')}) needs a person`);
  if (cats.some((c) => AUTH_CATEGORIES.test(c))) reasons.push('the change alters authentication, authorization or cryptography');
  if (materialClassification.risk && !a.allowedMaterialRisk.includes(materialClassification.risk)) reasons.push(`material risk ${materialClassification.risk} is not in the allowed set`);
  if ((RESIDUAL_RANK[record.residualRisk.level] ?? 4) > RESIDUAL_RANK[a.maxResidualRisk]) reasons.push(`residual risk ${record.residualRisk.level} is above ${a.maxResidualRisk}`);
  if (reasons.length) return decide('propose', record, reasons);
  return decide('apply', record, ['FULL, low risk, every required check passed']);
}
