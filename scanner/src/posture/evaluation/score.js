// End-to-end scoring of an evaluation run (QA-003.AC03).
//
// The rule that makes this a measurement and not a flattering one: a known
// positive that sat behind a timeout, an error, an unavailable tree or a
// quarantine is a MISS. The end-to-end metrics keep every such case in the
// denominator. A second set, "conditional on completion", is reported beside
// them and is labelled as such; it never replaces them.
//
// What is NOT scored, and is counted with its reason instead of vanishing:
//   - targets with no adjudicated label            (unlabeled-target)
//   - labels that are only candidates / disputed   (label-not-adjudicated)
//   - findings no adjudicated label accounts for   (no-adjudicated-label), which
//     go to a review queue: they may be genuine, so they are never auto-FPs.
//
// False positives are counted ONLY on adjudicated negatives (patched code, safe
// real code, near-misses), one per ROOT CAUSE: repeated alerts for the same flaw
// (`clusterAlerts`) score once and are reported in `alertsCollapsed`; the operational
// alert burden is report.js's job and is never hidden by this. The score also carries
// `perTarget` tallies, which is what the grouped bootstrap resamples. Pure: no fs, no clock.

import { SCHEMA_VERSION } from '../assurance/schema-kit.js';
import { digestOf } from '../assurance/identity.js';
import { isScoreable, matchFinding, matchNegative, reviewQueue, populationCounts } from './labels.js';

const SCORE_SCHEMA = 'agentic-security/evaluation-score';

const rate = (n, d) => (d > 0 ? n / d : null);

function countsOf(tp, fn, fp, tn) {
  const precision = rate(tp, tp + fp);
  const recall = rate(tp, tp + fn);
  const f1 = tp + fp + fn === 0 ? null : (2 * tp) / (2 * tp + fp + fn);
  return { tp, fn, fp, tn, precision, recall, f1 };
}

function bump(map, key, field) {
  if (!map[key]) map[key] = { tp: 0, fn: 0, fp: 0, tn: 0 };
  map[key][field]++;
}

const finalize = (m) => Object.fromEntries(Object.keys(m).sort().map((k) => [k, countsOf(m[k].tp, m[k].fn, m[k].fp, m[k].tn)]));

/** Micro (pooled counts) and macro (mean of per-group F1 over groups where F1 is defined). */
export function aggregate(byGroup) {
  const rows = Object.values(byGroup);
  const sum = rows.reduce((s, r) => ({ tp: s.tp + r.tp, fn: s.fn + r.fn, fp: s.fp + r.fp, tn: s.tn + r.tn }), { tp: 0, fn: 0, fp: 0, tn: 0 });
  const defined = rows.filter((r) => r.f1 !== null);
  return { micro: countsOf(sum.tp, sum.fn, sum.fp, sum.tn), macroF1: defined.length ? defined.reduce((s, r) => s + r.f1, 0) / defined.length : null, groups: rows.length };
}

const findingKey = (f) => `${f.file}|${f.line}|${f.family}|${f.cwe}`;

/**
 * Collapse repeated alerts to root causes (QA-004.AC02). Findings in the same file and family whose lines chain within
 * `lineWindow` of one another are one root cause: the same sink reported by two detectors, or a single flaw reported on its
 * source line and its sink line, is one defect, not several. A finding with no line cannot be placed and stays alone. Returns
 * clusters in a stable order; each carries every member so the operational alert count is still available.
 */
export function clusterAlerts(findings, lineWindow = 3) {
  const sorted = [...findings].sort((a, b) => String(a.file).localeCompare(String(b.file)) || String(a.family).localeCompare(String(b.family)) || (a.line ?? -1) - (b.line ?? -1));
  const clusters = [];
  for (const f of sorted) {
    const last = clusters[clusters.length - 1];
    const prev = last && last.members[last.members.length - 1];
    const joins = prev && prev.file === f.file && prev.family === f.family && Number.isInteger(prev.line) && Number.isInteger(f.line) && f.line - prev.line <= lineWindow;
    if (joins) last.members.push(f); else clusters.push({ file: f.file, family: f.family, line: f.line, members: [f] });
  }
  return clusters;
}

/**
 * @param {object} o
 * @param {object} o.run         a run record (runner.js)
 * @param {object} o.protocol    the protocol the run is bound to (matching policy comes from it)
 * @param {object[]} o.defects   defect labels
 * @param {object[]} o.negatives negative labels
 */
export function scoreRun({ run, protocol, defects = [], negatives = [] }) {
  const policy = protocol.matching;
  const outcomeOf = new Map(run.outcomes.map((o) => [`${o.targetId}|${o.variant}`, o]));
  const inRun = new Set(run.outcomes.map((o) => o.targetId));

  const e2e = { lang: {}, family: {} }; const cond = { lang: {}, family: {} };
  const misses = []; const falsePositives = []; const negativeFailures = []; const matchedFinding = new Set();
  const unscored = { unlabeledTargets: [], nonAdjudicatedLabels: 0, unlabeledFindings: { count: 0, byReason: {} }, positivesOutsideRun: 0 };
  const queue = [];

  const labelledTargets = new Set();
  // Per-target tallies (end to end), so an interval can resample whole targets/groups instead of pretending cases are independent.
  const perTarget = {};
  const tally = (targetId, language, field, n = 1) => {
    if (!perTarget[targetId]) perTarget[targetId] = { language, tp: 0, fn: 0, fp: 0, tn: 0 };
    perTarget[targetId][field] += n;
  };
  const scoreable = (l) => {
    if (isScoreable(l)) return true;
    unscored.nonAdjudicatedLabels++;
    return false;
  };

  for (const l of defects.filter(scoreable)) {
    if (!inRun.has(l.targetId)) { unscored.positivesOutsideRun++; continue; }
    labelledTargets.add(l.targetId);
    const o = outcomeOf.get(`${l.targetId}|pre`);
    const completed = o?.status === 'completed';
    const hit = completed ? o.findings.find((f) => matchFinding(f, l, policy).matched) : null;
    if (hit) {
      matchedFinding.add(`${l.targetId}|pre|${findingKey(hit)}`);
      for (const [m, k] of [[e2e.lang, l.language], [e2e.family, l.family], [cond.lang, l.language], [cond.family, l.family]]) bump(m, k, 'tp');
      tally(l.targetId, l.language, 'tp');
    } else {
      const reason = !o ? 'no-outcome' : completed ? 'not-detected' : o.status;
      misses.push({ labelId: l.id, targetId: l.targetId, reason, detail: o?.failureReason || null });
      for (const [m, k] of [[e2e.lang, l.language], [e2e.family, l.family]]) bump(m, k, 'fn');
      tally(l.targetId, l.language, 'fn');
      if (completed) for (const [m, k] of [[cond.lang, l.language], [cond.family, l.family]]) bump(m, k, 'fn');
    }
  }

  for (const n of negatives.filter(scoreable)) {
    if (!inRun.has(n.targetId)) continue;
    labelledTargets.add(n.targetId);
    const o = outcomeOf.get(`${n.targetId}|${n.variant}`);
    if (o?.status !== 'completed') {
      negativeFailures.push({ labelId: n.id, targetId: n.targetId, variant: n.variant, reason: o?.status || 'no-outcome', detail: o?.failureReason || null });
      continue;
    }
    const hits = new Map();
    for (const f of o.findings) {
      if (matchNegative(f, n).matched) hits.set(findingKey(f), f);
      else if ((n.scope.files || []).includes(f.file)) queue.push({ targetId: n.targetId, variant: n.variant, finding: f, reason: 'finding-in-negative-scope-other-family' });
    }
    for (const f of hits.values()) matchedFinding.add(`${n.targetId}|${n.variant}|${findingKey(f)}`);
    if (hits.size) {
      // One false positive per ROOT CAUSE, not per alert: repeated alerts for the same flaw are reported in `alertsCollapsed` and
      // in the operational burden, never silently hidden and never multiplied into the precision denominator.
      const clusters = clusterAlerts([...hits.values()], policy.lineWindow);
      for (const c of clusters) falsePositives.push({ labelId: n.id, targetId: n.targetId, kind: n.kind, finding: { file: c.members[0].file, line: c.members[0].line, family: c.family }, alertsCollapsed: c.members.length });
      for (const [m, k] of [[e2e.lang, n.language], [e2e.family, n.family], [cond.lang, n.language], [cond.family, n.family]]) { for (let i = 0; i < clusters.length; i++) bump(m, k, 'fp'); }
      tally(n.targetId, n.language, 'fp', clusters.length);
    } else {
      for (const [m, k] of [[e2e.lang, n.language], [e2e.family, n.family], [cond.lang, n.language], [cond.family, n.family]]) bump(m, k, 'tn');
      tally(n.targetId, n.language, 'tn');
    }
  }

  // Findings no adjudicated label accounts for: unscored, queued for review, never auto-FP.
  for (const o of run.outcomes) {
    if (o.status !== 'completed') continue;
    for (const f of o.findings) {
      if (matchedFinding.has(`${o.targetId}|${o.variant}|${findingKey(f)}`)) continue;
      if (queue.some((q) => q.targetId === o.targetId && q.variant === o.variant && q.finding === f)) continue;
      unscored.unlabeledFindings.count++;
      unscored.unlabeledFindings.byReason['no-adjudicated-label'] = (unscored.unlabeledFindings.byReason['no-adjudicated-label'] || 0) + 1;
      queue.push({ targetId: o.targetId, variant: o.variant, finding: f, reason: 'no-adjudicated-label' });
    }
  }
  for (const id of [...inRun].sort()) if (!labelledTargets.has(id)) unscored.unlabeledTargets.push({ targetId: id, reason: 'unlabeled-target' });

  const endToEnd = { byLanguage: finalize(e2e.lang), byFamily: finalize(e2e.family) };
  const conditional = { byLanguage: finalize(cond.lang), byFamily: finalize(cond.family) };
  const completed = run.outcomes.filter((o) => o.status === 'completed').length;
  const score = {
    schema: SCORE_SCHEMA, schemaVersion: SCHEMA_VERSION, runId: run.runId, protocolHash: run.protocolHash, split: run.split,
    endToEnd: { ...endToEnd, ...aggregate(endToEnd.byLanguage), label: 'end-to-end: failures on known positives are misses' },
    conditional: { ...conditional, ...aggregate(conditional.byLanguage), label: 'conditional on completion: additional, never a replacement' },
    completion: { outcomes: run.outcomes.length, completed, rate: rate(completed, run.outcomes.length), totals: run.totals },
    misses, falsePositives, negativeFailures, unscored, perTarget,
    reviewQueue: reviewQueue(queue),
    population: populationCounts(defects, negatives),
  };
  score.scoreHash = digestOf({ ...score, reviewQueue: undefined });
  return score;
}
