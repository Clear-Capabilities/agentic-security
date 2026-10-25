// Label loading and scoring for bench/dag.
//
// A label is a hand-written judgement about one site in a pinned project (or
// a controlled fixture). Scoring asks one question per label: did the scanner
// report a finding of the label's class at that site? Positive+reported is a
// TP, positive+silent an FN, negative+reported an FP, negative+silent a TN.
// Ambiguous labels are carried through for transparency and never scored.
//
// WHAT THIS DOES NOT MEASURE (also stated in every summary.md):
//   * It is a sample, not a census. Recall is recall over the positives the
//     labeller found by reading sink sites, not over every vulnerability in the
//     project. Precision is precision over the sites that were labelled, and
//     negatives were chosen from sites the labeller read, most of them because
//     the scanner had reported on them. That makes precision a lower-bound
//     style estimate on flagged sites, not a population rate.
//   * A finding with no integer line (some structural detectors) is credited at
//     FILE granularity: it matches every label of its class in the same file.
//     The count of such credits is reported as `fileLevelCredits`.
import * as crypto from 'node:crypto';

export const CLASS_CWE = Object.freeze({
  'xss': ['CWE-79'],
  'open-redirect': ['CWE-601'],
  'path-traversal': ['CWE-22'],
  'sync-io': ['CWE-400'],
  'privacy-log': ['CWE-359', 'CWE-532'],
  'csrf': ['CWE-352'],
  'weak-rng': ['CWE-338'],
  'unbounded-body': ['CWE-770'],
  'cookie-flags': ['CWE-1004', 'CWE-614'],
  'weak-hash': ['CWE-916'],
  'unsafe-boundary': ['CWE-676'],
  'nix-secret': ['CWE-312', 'CWE-798', 'CWE-532'],
  'pam-empty-password': ['CWE-258'],
  'nix-script': ['CWE-78'],
  'root-service': ['CWE-250'],
});

/**
 * Held-out assignment. A label is held out when the first byte of
 * sha256(label.id) is divisible by 3 (about one third). It depends on the id
 * only, so adding labels never moves an existing label across the split.
 * Nothing in this benchmark tunes the scanner; the split exists so that anyone
 * who does tune against it has a subset they must not look at.
 */
export function isHeldOut(id) {
  return crypto.createHash('sha256').update(id).digest()[0] % 3 === 0;
}

export function labelMatchesFinding(label, finding, tolerance = 0) {
  if (finding.file !== label.file) return false;
  const cwes = CLASS_CWE[label.class];
  if (!cwes || !cwes.includes(finding.cwe)) return false;
  if (!Number.isInteger(finding.line)) return 'file';
  return Math.abs(finding.line - label.line) <= tolerance ? 'line' : false;
}

export function scoreSiteLabel(label, findings, tolerance = 0) {
  let hit = false;
  let fileLevel = false;
  for (const f of findings) {
    const m = labelMatchesFinding(label, f, tolerance);
    if (m === 'line') { hit = true; fileLevel = false; break; }
    if (m === 'file') { hit = true; fileLevel = true; }
  }
  return { reported: hit, fileLevel: hit && fileLevel };
}

export function outcome(verdict, reported) {
  if (verdict === 'positive') return reported ? 'TP' : 'FN';
  if (verdict === 'negative') return reported ? 'FP' : 'TN';
  return 'excluded';
}

export function ratio(num, den) {
  return den === 0 ? null : Math.round((num / den) * 10000) / 10000;
}

/** Aggregate per-label outcomes into precision/recall with explicit denominators. */
export function aggregate(rows) {
  const c = { TP: 0, FP: 0, FN: 0, TN: 0, excluded: 0, fileLevelCredits: 0 };
  for (const r of rows) {
    c[r.outcome]++;
    if (r.fileLevel) c.fileLevelCredits++;
  }
  return {
    ...c,
    labeled: c.TP + c.FP + c.FN + c.TN,
    precision: ratio(c.TP, c.TP + c.FP),
    precisionDenominator: c.TP + c.FP,
    recall: ratio(c.TP, c.TP + c.FN),
    recallDenominator: c.TP + c.FN,
  };
}

// ---- flow labels (fixture) -------------------------------------------------

/** Match a flow label against the compact flow records a unit produced. */
export function scoreFlowLabel(label, flows) {
  let reached = false;
  let sinkMatch = false;
  for (const f of flows) {
    if (!f.fields.includes(label.field)) continue;
    if (label.sourceKind && f.sourceKind !== label.sourceKind) continue;
    if (label.sourceFile && !f.files.some((x) => x === label.sourceFile)) continue;
    reached = true;
    if (!label.sinkKind || f.sinkKind === label.sinkKind || f.sinkSub === label.sinkKind) sinkMatch = true;
  }
  return { reported: reached, sinkMatch: reached && sinkMatch };
}
