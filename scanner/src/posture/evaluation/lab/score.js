// Scoring for the Eval Lab (PRD 6): detection, falsification, exploit proof, remediation, economics. Pure functions over
// recorded attempts and the dataset's labels; no fs, no clock, no process.
//
// Principles carried over from the rest of the evaluation code:
//   * a figure never appears without the counts behind it;
//   * an attempt that timed out, errored or was blocked is a recorded NO-RESULT. For a known positive it is a miss; for a
//     negative it is neither a true negative nor a false positive (it is `unscored`), so a model cannot look precise by crashing;
//   * a quantity that could not be measured is `null` with a reason, never 0;
//   * detection is scored on LOCATION. A finding of the right class in the right file but outside the labelled span is a
//     file-level hit and a localization miss, and only a localized hit is a true positive.
import { normalizeCwe } from './dataset.js';
import { ratio, f1 } from './stats.js';

const DEFAULT_LINE_TOLERANCE = 3;

const resultOf = (a) => a && a.status === 'completed';

/** @param {object[]} entries dataset entries @param {Map<string, object>} attempts entryId -> attempt @param {Map<string,string>} fileMaps `${entryId}\0${path}` -> staged path */
export function scoreDetect({ entries, attempts, mapFile = (entryId, f) => f, tolerance = DEFAULT_LINE_TOLERANCE, targetCwes = null }) {
  const cweSet = targetCwes ? new Set(targetCwes.map(normalizeCwe)) : null;
  const perCwe = new Map();
  const slot = (c) => { if (!perCwe.has(c)) perCwe.set(c, { tp: 0, fn: 0, fp: 0, fileHits: 0 }); return perCwe.get(c); };
  const byCategory = {};
  const c = { tp: 0, fn: 0, fp: 0, tn: 0, unscoredNegatives: 0, noResultPositives: 0, fileHits: 0, positives: 0, negatives: 0, attempted: 0, completed: 0 };
  const misses = [];
  for (const e of entries) {
    const a = attempts.get(e.id);
    if (!a) continue;
    c.attempted++;
    if (resultOf(a)) c.completed++;
    const found = resultOf(a) ? (a.output?.findings ?? []) : [];
    if (e.kind === 'vulnerable') {
      c.positives++;
      const cwe = normalizeCwe(e.cwe); const s = slot(cwe);
      if (!resultOf(a)) { c.fn++; s.fn++; c.noResultPositives++; misses.push({ entryId: e.id, reason: `no-result:${a.status}` }); continue; }
      const file = mapFile(e.id, e.expectedSpan.file);
      const sameFile = found.filter((f) => f.file === file && normalizeCwe(f.cwe) === cwe);
      const loc = sameFile.some((f) => Number.isInteger(f.line) && f.line >= e.expectedSpan.startLine - tolerance && f.line <= e.expectedSpan.endLine + tolerance);
      if (sameFile.length) { c.fileHits++; s.fileHits++; }
      if (loc) { c.tp++; s.tp++; } else { c.fn++; s.fn++; misses.push({ entryId: e.id, reason: sameFile.length ? 'wrong-location' : found.some((f) => f.file === file) ? 'wrong-class' : 'not-found' }); }
    } else {
      c.negatives++;
      const cat = e.kind === 'hard-negative' ? e.category : 'fixed';
      byCategory[cat] ??= { entries: 0, falsePositives: 0, unscored: 0 };
      byCategory[cat].entries++;
      if (!resultOf(a)) { c.unscoredNegatives++; byCategory[cat].unscored++; continue; }
      const relevant = found.filter((f) => !cweSet || f.cwe == null || cweSet.has(normalizeCwe(f.cwe)));
      if (relevant.length) {
        c.fp++; byCategory[cat].falsePositives++;
        for (const k of new Set(relevant.map((f) => normalizeCwe(f.cwe) ?? 'unclassified'))) slot(k).fp++;
      } else c.tn++;
    }
  }
  const precision = ratio(c.tp, c.tp + c.fp); const recall = ratio(c.tp, c.tp + c.fn);
  const per = {};
  for (const [k, v] of [...perCwe.entries()].sort()) { const p = ratio(v.tp, v.tp + v.fp); const r = ratio(v.tp, v.tp + v.fn); per[k] = { ...v, precision: p, recall: r, f1: v.tp + v.fn > 0 ? f1(p ?? (v.tp + v.fn > 0 ? 0 : null), r) : null }; }
  const f1s = Object.values(per).filter((p) => p.tp + p.fn > 0 && p.f1 != null).map((p) => p.f1);
  return {
    counts: c, precision, recall, f1: c.positives > 0 && c.tp === 0 ? 0 : f1(precision, recall),
    macroF1: f1s.length ? f1s.reduce((a, b) => a + b, 0) / f1s.length : null, perCwe: per,
    fileLevelRecall: ratio(c.fileHits, c.positives), localizationAccuracy: ratio(c.tp, c.fileHits),
    hardNegativeFalsePositiveRate: Object.fromEntries(Object.entries(byCategory).map(([k, v]) => [k, { ...v, rate: ratio(v.falsePositives, v.entries - v.unscored) }])),
    completion: ratio(c.completed, c.attempted), misses, tolerance,
  };
}

/** truth: Map candidateId -> 'vulnerable' | 'not-vulnerable'. verdicts: Map candidateId -> attempt-level verdict or null (no result). */
export function scoreFalsify({ truth, verdicts }) {
  const c = { vulnerable: 0, negative: 0, confirmedVuln: 0, refutedVuln: 0, abstainedVuln: 0, refutedNeg: 0, confirmedNeg: 0, abstainedNeg: 0, noResult: 0 };
  for (const [id, t] of truth) {
    const v = verdicts.get(id) ?? null;
    if (t === 'vulnerable') c.vulnerable++; else c.negative++;
    if (v == null) { c.noResult++; continue; }
    if (t === 'vulnerable') { if (v === 'confirmed') c.confirmedVuln++; else if (v === 'refuted') c.refutedVuln++; else c.abstainedVuln++; }
    else if (v === 'refuted') c.refutedNeg++; else if (v === 'confirmed') c.confirmedNeg++; else c.abstainedNeg++;
  }
  const tpr = ratio(c.confirmedVuln, c.vulnerable); const tnr = ratio(c.refutedNeg, c.negative);
  return { counts: c, truePositiveRate: tpr, trueNegativeRate: tnr, balancedAccuracy: tpr == null || tnr == null ? null : (tpr + tnr) / 2, falseRefutationRate: ratio(c.refutedVuln, c.vulnerable), falseConfirmationRate: ratio(c.confirmedNeg, c.negative) };
}

/** proofs: array of {entryKind, reproducerValid, state, successes, runs, status}. */
export function scoreExploit({ proofs }) {
  const vuln = proofs.filter((p) => p.entryKind === 'vulnerable');
  const neg = proofs.filter((p) => p.entryKind !== 'vulnerable');
  const valid = proofs.filter((p) => p.reproducerValid);
  const executed = valid.filter((p) => p.executed);
  // reproduction is a property of the VULNERABLE code: a reproducer that (rightly) does nothing to fixed code is not a failure to reproduce
  const executedVuln = executed.filter((p) => p.entryKind === 'vulnerable');
  const reproduced = executedVuln.filter((p) => (p.successes ?? 0) > 0);
  const confirmedVuln = vuln.filter((p) => p.state === 'EXPLOIT_CONFIRMED').length;
  const confirmedNeg = neg.filter((p) => p.state === 'EXPLOIT_CONFIRMED').length;
  return {
    counts: { attempted: proofs.length, vulnerable: vuln.length, negative: neg.length, reproducerValid: valid.length, executed: executed.length, notExecuted: valid.length - executed.length, reproduced: reproduced.length, confirmedVuln, confirmedNeg },
    pocGenerationSuccess: ratio(valid.length, proofs.length),
    reproductionRate: ratio(reproduced.length, executedVuln.length),
    confirmationRate: ratio(confirmedVuln, vuln.length),
    falseConfirmationRate: ratio(confirmedNeg, neg.length),
    unmeasured: valid.length > executed.length ? `${valid.length - executed.length} reproducer(s) could not be executed here (no execution environment); they are not counted as failures` : null,
  };
}

/** patches: array of {applicable, patchProvided, exploitBlocked: true|false|null, testsPass: true|false|null, completeness, state}. */
export function scorePatch({ patches }) {
  const app = patches.filter((p) => p.applicable);
  const provided = app.filter((p) => p.patchProvided);
  const verified = provided.filter((p) => p.exploitBlocked !== null);
  const blocked = verified.filter((p) => p.exploitBlocked === true);
  const testable = provided.filter((p) => p.testsPass !== null);
  const strict = provided.filter((p) => p.exploitBlocked === true && p.testsPass === true);
  const tiers = { FULL: 0, DEGRADED: 0, INCOMPLETE: 0 };
  for (const p of provided) if (tiers[p.completeness] !== undefined) tiers[p.completeness]++;
  return {
    counts: { applicable: app.length, patchProvided: provided.length, verifiable: verified.length, exploitBlocked: blocked.length, testsMeasured: testable.length, testsPassed: testable.filter((p) => p.testsPass).length, validStrict: strict.length },
    patchRate: ratio(provided.length, app.length),
    validPatchRate: ratio(strict.length, app.length),
    exploitBlockedRate: ratio(blocked.length, app.length),
    testPreservationRate: ratio(testable.filter((p) => p.testsPass).length, testable.length),
    regressionRate: ratio(testable.filter((p) => !p.testsPass).length, testable.length),
    completenessTier: tiers,
    unmeasured: testable.length < provided.length ? `${provided.length - testable.length} patch(es) had no runnable test command, so test preservation is unmeasured for them` : null,
  };
}

/** Sum what the attempts cost. Unknown usage is counted, never read as zero. */
export function scoreEconomics(attempts) {
  const known = attempts.filter((a) => a.usage?.usd != null);
  const lat = attempts.map((a) => a.usage?.latencyMs).filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  const sum = (k) => attempts.reduce((s, a) => s + (a.usage?.[k] ?? 0), 0);
  return {
    attempts: attempts.length, usdMeasured: known.reduce((s, a) => s + a.usage.usd, 0), attemptsWithUnknownCost: attempts.length - known.length,
    inputTokens: sum('inputTokens'), outputTokens: sum('outputTokens'), tokensUnknownAttempts: attempts.filter((a) => a.usage?.inputTokens == null || a.usage?.outputTokens == null).length,
    latencyMs: { median: lat.length ? (lat.length % 2 ? lat[lat.length >> 1] : (lat[(lat.length >> 1) - 1] + lat[lat.length >> 1]) / 2) : null, p95: lat.length ? lat[Math.min(lat.length - 1, Math.ceil(lat.length * 0.95) - 1)] : null, total: lat.reduce((a, b) => a + b, 0) },
    timeouts: attempts.filter((a) => a.status === 'timeout').length, failures: attempts.filter((a) => ['error', 'blocked', 'unavailable'].includes(a.status)).length,
  };
}
