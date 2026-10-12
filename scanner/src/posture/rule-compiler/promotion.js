// Promotion gate (PRD 3 "Promotion Gate"): precision/recall thresholds, zero protected-negative failures, zero
// benchmark leakage. A candidate rule does NOT automatically become a production rule — `evaluateRule` only
// scores; `gatePromotion` only judges; the lifecycle ledger (`lifecycle.js`) is the one place a PROMOTED state is
// actually recorded, and nothing in this module writes to it.
import { scoreRule } from './corpus.js';

export const PROMOTION_DEFAULTS = Object.freeze({ minPrecision: 0.95, minRecall: 0.80, maxProtectedFailures: 0 });

// Deliberately independent of posture/evaluation/custody.js: that module's term list and guard are reserved for
// the evaluation custodian's sealed-label boundary (QA-002.AC03), and a test enforces that nothing outside
// posture/evaluation/ may import it. The anti-cheating need here is smaller and different in kind — a rule
// synthesis prompt/corpus must not embed a benchmark name or an advisory id — so it gets its own small, independent
// checker rather than reaching across that isolation boundary.
const ADVISORY_ID = /\b(?:CVE|GHSA|CWE)-[A-Za-z0-9-]+\b/i;

/** Anti-cheating: the synthesis agent must never see benchmark answer keys, hidden labels, CWE-bearing hidden
 * filenames or vulnerability-comment metadata. */
export function checkLeakage(promptText, { benchmarkNames = [] } = {}) {
  const hay = String(promptText ?? '');
  const offending = [];
  for (const name of benchmarkNames) if (name && hay.toLowerCase().includes(String(name).toLowerCase())) offending.push(name);
  const m = ADVISORY_ID.exec(hay);
  if (m) offending.push(m[0]);
  return { ok: offending.length === 0, offendingTerms: offending };
}

export function evaluateRule(ir, corpus, thresholds = PROMOTION_DEFAULTS) {
  const score = scoreRule(ir, corpus);
  const t = { ...PROMOTION_DEFAULTS, ...thresholds };
  const reasons = [];
  if (score.precision === null) reasons.push('precision unmeasured (no positive or negative corpus fired)');
  else if (score.precision < t.minPrecision) reasons.push(`precision ${(score.precision * 100).toFixed(1)}% below ${(t.minPrecision * 100).toFixed(0)}%`);
  if (score.recall === null) reasons.push('recall unmeasured (empty positive corpus)');
  else if (score.recall < t.minRecall) reasons.push(`recall ${(score.recall * 100).toFixed(1)}% below ${(t.minRecall * 100).toFixed(0)}%`);
  if (score.protectedFailures > t.maxProtectedFailures) reasons.push(`${score.protectedFailures} protected-negative failure(s) (max ${t.maxProtectedFailures})`);
  return { pass: reasons.length === 0, reasons, score, thresholds: t };
}

/** The one promotion decision. Never auto-applied: a caller still has to act on `pass:true` by recording a
 * lifecycle transition. Localization ("acceptable") is a human/caller judgment this function cannot make from
 * line/column alone; it is surfaced for review, never silently assumed. */
export function gatePromotion({ ir, corpus, leakageCheck, thresholds } = {}) {
  const evalResult = evaluateRule(ir, corpus, thresholds);
  const reasons = [...evalResult.reasons];
  if (!leakageCheck || leakageCheck.ok !== true) reasons.push(leakageCheck ? `leakage check failed: ${leakageCheck.offendingTerms.join(', ')}` : 'leakage check was not run');
  return { pass: reasons.length === 0, reasons, evaluation: evalResult };
}
