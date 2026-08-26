// Enrichment completion pass (assurance-hardening PRD, Milestone 1, FR-103).
//
// engine.js's primary enrichment chain (stableId -> defaults -> confidence
// -> calibration -> exploitability -> proof-gate -> ...) runs once, early,
// over whatever is in `finalFindings` at that moment. At least 19 separate
// call sites append MORE findings after that chain already ran (A-03) —
// cross-language taint, IAM/container/business-logic/spec-drift/concurrency
// producers, privacy-taint, plus several opt-in "world-class artifact"
// emitters (API contract, SBOM diff, license graph, multi-sink synthesis).
// Moving all 19 call sites earlier in that ~900-line function was
// considered and rejected as the fix here: several depend on state (aR,
// annotatedComponents, supplyChain dedup results) not yet computed at an
// earlier point, and relocating them carries real regression risk against
// this project's own 500+-entry accuracy corpus for a single engineering
// cycle's blast radius.
//
// Instead: this is a GAP-FILLING pass, run once, late, right before the
// finding collection is frozen (FR-104). It finds every finding still
// missing a stableId — the reliable marker of "never went through the
// primary chain," since annotateStableIds is the first stage in that chain
// and runs unconditionally — and runs the same core stages on exactly that
// subset. This covers every late producer's output equally, whether or not
// that producer has been converted to go through producer-collector.js
// (see that module's header for which ones have).
//
// Two of the four stages (backfillFindingDefaults, annotateConfidence)
// already skip a finding that has the field set, so calling them here is
// pure gap-filling by construction. The other two (annotateCalibratedConfidence,
// annotateExploitability) always recompute unconditionally, which is why
// this scopes to the late subset rather than the whole array — cheap and
// correct, not "cheap because deduped by luck."

import { annotateStableIds } from '../posture/stable-id.js';
import { backfillFindingDefaults } from '../posture/finding-defaults.js';
import { annotateConfidence } from '../posture/confidence.js';
import { annotateCalibratedConfidence } from '../posture/calibration.js';
import { annotateExploitability } from '../posture/exploitability.js';

/**
 * @param {object[]} finalFindings
 * @param {object} ctx
 * @param {string} ctx.scanRoot
 * @param {object} ctx.projectCtx - same shape engine.js's own annotateExploitability call already builds
 * @returns {{gapFilledCount:number}}
 */
export function completeEnrichment(finalFindings, { scanRoot, projectCtx } = {}) {
  if (!Array.isArray(finalFindings)) return { gapFilledCount: 0 };
  const late = finalFindings.filter(f => f && typeof f === 'object' && !f.stableId);
  if (!late.length) return { gapFilledCount: 0 };

  annotateStableIds(late);
  backfillFindingDefaults(late);
  annotateConfidence(late);
  try { annotateCalibratedConfidence(late, { scanRoot }); } catch { /* calibration table load is best-effort */ }
  try { annotateExploitability(late, projectCtx || {}); } catch { /* scoring is best-effort */ }

  return { gapFilledCount: late.length };
}
