import { CONFIDENCE_LEVEL } from './schema.js';

export function assessConfidence({
  parentBoundaryVerified = false, historyComplete = false, detectorCompatible = true,
  renameAmbiguous = false, shallow = false, budgetExhausted = false,
} = {}) {
  const reasons = [];
  if (budgetExhausted) return { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons: ['budget_exhausted'] };

  if (parentBoundaryVerified && historyComplete && detectorCompatible && !renameAmbiguous) {
    reasons.push('parent_absence_verified', 'complete_history');
    return { level: CONFIDENCE_LEVEL.HIGH, score: 0.95, reasons };
  }
  if (detectorCompatible && (!historyComplete || !parentBoundaryVerified) && !shallow) {
    if (!historyComplete) reasons.push('partial_history');
    if (!parentBoundaryVerified) reasons.push('no_parent_to_test');
    return { level: CONFIDENCE_LEVEL.MEDIUM, score: 0.65, reasons };
  }
  if (shallow || renameAmbiguous || !detectorCompatible) {
    if (shallow) reasons.push('shallow_history');
    if (renameAmbiguous) reasons.push('rename_ambiguous');
    if (!detectorCompatible) reasons.push('detector_incompatible');
    return { level: CONFIDENCE_LEVEL.LOW, score: 0.35, reasons };
  }
  reasons.push('no_defensible_origin');
  return { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons };
}
