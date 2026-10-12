// X-eligibility (PRD 3 "Eligibility"): a finding may enter synthesis only with a stable id, a vulnerable span, a
// CWE/family, code-flow evidence, and deterministic corroboration OR exploit proof. Reuses the existing
// vocabularies rather than inventing a third: proof-fabric's evidence-state ladder when present, else the older
// proof-tier (`taint-proven`/`execution-proven`), else the finding's own `parser` (an IR-TAINT/MULTI-SINK parser
// origin is code-flow evidence even with no execution).
import { stateRank } from '../proof-fabric/states.js';

const ANALYSED_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);

export function checkEligibility(finding, { proofState = null } = {}) {
  const reasons = [];
  if (!finding?.stableId && !finding?.id) reasons.push('no stable id');
  if (finding?.file == null || finding?.line == null) reasons.push('no vulnerable span (file:line)');
  if (!finding?.cwe && !finding?.family) reasons.push('no CWE or family');
  const hasFlowEvidence = ANALYSED_PARSERS.has(finding?.parser) || !!finding?.snippet;
  if (!hasFlowEvidence) reasons.push('no code-flow evidence (parser not IR-TAINT/MULTI-SINK, no snippet)');

  let evidenceState = 'none';
  if (proofState && stateRank(proofState) >= stateRank('EXPLOIT_CONFIRMED')) evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'execution-proven') evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'taint-proven' || ANALYSED_PARSERS.has(finding?.parser)) evidenceState = 'taint-proven';
  if (evidenceState === 'none') reasons.push('no deterministic corroboration or exploit proof');

  return { eligible: reasons.length === 0, reasons, evidenceState };
}
