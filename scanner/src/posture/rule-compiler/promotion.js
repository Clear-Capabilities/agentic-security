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

// What a synthesis agent must never see (PRD 3, anti-cheating): benchmark answer keys, hidden test labels, CWE-bearing hidden file
// names, vulnerability comments and protected test metadata. These defaults are always applied; a caller adds its own benchmark names.
const DEFAULT_BENCHMARK_NAMES = Object.freeze(['owasp benchmark', 'juliet', 'sard test', 'cve-replay', 'corpus-baseline', 'answer key', 'ground truth', 'adjudicated', 'hidden test', 'expectedresults']);
const CWE_FILENAME = /(^|[\\/])[^\\/]*cwe[-_]?\d+[^\\/]*$/i;
const ANSWER_KEY_FILENAME = /(^|[\\/])(?:labels?|answers?|expected|ground[-_]?truth|answer[-_]?key|oracle|result)[^\\/]*\.(?:json|jsonl|ya?ml|csv|txt)$/i;
const VULNERABILITY_COMMENT = /(?:\/\/|#|\/\*|^\s*\*)\s*(?:POTENTIAL FLAW|FLAW\b|INCIDENTAL|BAD\b|GOOD\b|vulnerab\w*|insecure|exploit\w*)/im;

/**
 * Anti-cheating gate. Fails closed: any hit makes `ok` false, and the synthesis loop will not report a pass.
 * @param {string} promptText everything the synthesis agent would be shown (corpus code, spec text)
 * @param {{benchmarkNames?: string[], fileNames?: string[]}} opts
 */
export function checkLeakage(promptText, { benchmarkNames = [], fileNames = [] } = {}) {
  const hay = String(promptText ?? '');
  const lower = hay.toLowerCase();
  const offending = [];
  for (const name of [...DEFAULT_BENCHMARK_NAMES, ...benchmarkNames]) if (name && lower.includes(String(name).toLowerCase())) offending.push(`benchmark name: ${name}`);
  const m = ADVISORY_ID.exec(hay);
  if (m) offending.push(`identifier: ${m[0]}`);
  if (VULNERABILITY_COMMENT.test(hay)) offending.push('a comment that describes the vulnerability');
  for (const f of fileNames) {
    if (CWE_FILENAME.test(String(f))) offending.push(`weakness-bearing file name: ${f}`);
    if (ANSWER_KEY_FILENAME.test(String(f))) offending.push(`answer-key file name: ${f}`);
  }
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
