// Honest accuracy reporting (QA-004.AC01, QA-004.AC02).
//
// Turns a score (score.js) into the figures a reader can check: raw TP/FP/FN/TN counts first, then precision, recall and F1 by
// language and by family, micro and macro aggregates, 95% intervals by the registered method, completion with its own interval,
// and every count of what was NOT scored and why. Two rules shape the whole file:
//
//   1. A figure never appears without the counts that produced it, and a stratum too small to support a figure is reported
//      `unmeasured` with its raw counts, not dropped and not given a flattering point estimate. The per-family floor comes from
//      the protocol's own thresholds.
//   2. Deduplication changes what is SCORED, never what is HIDDEN. Repeated alerts for one root cause score once; the operational
//      alert burden (every alert a reviewer would actually have to read) is reported beside it, in its own section.
//
// The four populations (regression, adjudicated development, sealed, operational) stay separate: a report carries exactly one
// population label, there is no function here that merges two, and `checkPopulationsDisjoint` refuses overlapping membership.
//
// Pure: no fs, no clock.

import { SCHEMA_VERSION } from '../assurance/schema-kit.js';
import { digestOf } from '../assurance/identity.js';
import { groupTargets } from './grouping.js';
import { clusterAlerts } from './score.js';
import { groupedBootstrap, wilsonInterval, f1Of, precisionOf, recallOf, INTERVAL_METHODS } from './interval.js';

const REPORT_SCHEMA = 'agentic-security/evaluation-report';
const POPULATIONS = Object.freeze(['regression', 'development', 'sealed', 'operational']);

const interval = (iv) => ({ method: iv.method, level: iv.level, status: iv.status, low: iv.low, high: iv.high, groups: iv.groups ?? null, replicates: iv.replicates ?? null, ...(iv.reason ? { reason: iv.reason } : {}) });

function stratum(counts, intervals, { minPositives, label }) {
  const positives = counts.tp + counts.fn;
  const metrics = { precision: precisionOf(counts), recall: recallOf(counts), f1: f1Of(counts) };
  if (positives < minPositives) {
    return {
      raw: { tp: counts.tp, fp: counts.fp, fn: counts.fn, tn: counts.tn }, status: 'unmeasured',
      reason: `${positives} positive${positives === 1 ? '' : 's'} in ${label}, fewer than the ${minPositives} the protocol requires for a measured figure`,
      descriptive: metrics, intervals: null,
    };
  }
  return { raw: { tp: counts.tp, fp: counts.fp, fn: counts.fn, tn: counts.tn }, status: 'measured', metrics, intervals };
}

/**
 * @param {object} o
 * @param {object} o.score      a score (score.js); its `perTarget` tallies drive the intervals
 * @param {object} o.protocol   the frozen protocol the score is bound to (thresholds, targets and grouping come from it)
 * @param {'regression'|'development'|'sealed'|'operational'} o.population
 * @param {object} [o.run]      the run record the score came from, for status counts and the operational alert burden
 * @param {number} [o.replicates]
 */
export function buildAccuracyReport({ score, protocol, population, run = null, replicates }) {
  if (!POPULATIONS.includes(population)) throw new Error(`population must be one of ${POPULATIONS.join(', ')}`);
  if (score.protocolHash !== protocol.protocolHash) throw new Error('the score was produced under a different protocol');
  const t = protocol.thresholds;
  const { groupOf } = groupTargets(protocol.targets);
  const units = Object.entries(score.perTarget || {}).map(([id, c]) => ({ id, ...c })).sort((a, b) => a.id.localeCompare(b.id));
  const boot = (name, statistic, filter) => groupedBootstrap({
    units: filter ? units.filter(filter) : units, groupOf, statistic, name, protocolHash: protocol.protocolHash, ...(replicates ? { replicates } : {}),
  });
  const triple = (prefix, pick) => ({
    f1: interval(boot(`${prefix}:f1`, (a) => f1Of(pick(a)), null)),
    precision: interval(boot(`${prefix}:precision`, (a) => precisionOf(pick(a)), null)),
    recall: interval(boot(`${prefix}:recall`, (a) => recallOf(pick(a)), null)),
  });
  const forLang = (lang) => {
    const sub = (name, stat) => interval(groupedBootstrap({ units: units.filter((u) => u.language === lang), groupOf, statistic: stat, name: `lang:${lang}:${name}`, protocolHash: protocol.protocolHash, ...(replicates ? { replicates } : {}) }));
    return { f1: sub('f1', (a) => f1Of(a.total)), precision: sub('precision', (a) => precisionOf(a.total)), recall: sub('recall', (a) => recallOf(a.total)) };
  };

  const e2e = score.endToEnd;
  const byLanguage = {};
  for (const [lang, c] of Object.entries(e2e.byLanguage)) byLanguage[lang] = stratum(c, forLang(lang), { minPositives: t.minPositivesPerCoreLanguage, label: `${lang}` });
  // Family strata: no per-family interval is attempted below the floor; above it, the per-target tallies are not family-split, so
  // the interval is reported as unavailable rather than borrowed from the language level.
  const byFamily = {};
  for (const [fam, c] of Object.entries(e2e.byFamily)) {
    byFamily[fam] = stratum(c, { note: 'per-family intervals need family-split tallies; not computed in this build' }, { minPositives: t.minPositivesPerFamily, label: `family ${fam}` });
  }

  const macroStat = (a) => {
    const f = Object.values(a.byLanguage).map(f1Of).filter((x) => x !== null);
    return f.length ? f.reduce((s, x) => s + x, 0) / f.length : null;
  };
  const completion = score.completion;
  const statusCounts = run ? { ...run.totals } : completion.totals || {};
  const alertBurdenSection = run ? alertBurden(run, protocol.matching?.lineWindow) : null;

  const report = {
    schema: REPORT_SCHEMA, schemaVersion: SCHEMA_VERSION, population, synthetic: !!protocol.synthetic,
    protocolHash: protocol.protocolHash, scoreHash: score.scoreHash, runId: score.runId, split: score.split,
    definitions: {
      truePositive: 'an adjudicated defect label matched by a completed scan finding (location range plus family or CWE)',
      falsePositive: 'a root-cause cluster of findings inside an adjudicated negative, in its family (repeated alerts for one flaw score once)',
      falseNegative: 'an adjudicated defect label with no match, INCLUDING one behind a timeout, error, unavailable or quarantined scan',
      trueNegative: 'an adjudicated negative with no finding in its family',
      precision: 'TP / (TP + FP)', recall: 'TP / (TP + FN)', f1: '2TP / (2TP + FP + FN)',
      micro: 'counts pooled across languages, then the ratio', macro: 'mean of per-language F1 over languages where F1 is defined',
    },
    counts: { endToEnd: { micro: { tp: e2e.micro.tp, fp: e2e.micro.fp, fn: e2e.micro.fn, tn: e2e.micro.tn } }, conditionalOnCompletion: { micro: { tp: score.conditional.micro.tp, fp: score.conditional.micro.fp, fn: score.conditional.micro.fn, tn: score.conditional.micro.tn } } },
    aggregate: {
      micro: { precision: e2e.micro.precision, recall: e2e.micro.recall, f1: e2e.micro.f1, intervals: triple('micro', (a) => a.total) },
      macro: { f1: e2e.macroF1, languages: e2e.groups, interval: interval(boot('macro:f1', macroStat, null)) },
      note: 'end to end: failures on known positives are misses. Conditional-on-completion figures are additional and live under counts.conditionalOnCompletion.',
    },
    byLanguage, byFamily,
    completion: { ...completion, interval: wilsonInterval(completion.completed, completion.outcomes), statusCounts },
    disclosed: {
      unsupported: { outcomesUnavailable: statusCounts.unavailable ?? 0, outcomesQuarantined: statusCounts.quarantined ?? 0 },
      unscored: {
        unlabeledTargets: score.unscored.unlabeledTargets.length, nonAdjudicatedLabels: score.unscored.nonAdjudicatedLabels,
        unlabeledFindings: score.unscored.unlabeledFindings.count, positivesOutsideRun: score.unscored.positivesOutsideRun,
      },
      unknownLabels: { count: score.unscored.nonAdjudicatedLabels, note: 'candidate, disputed or rejected labels are never scored' },
      trueNegativeFailures: { count: score.negativeFailures.length, note: 'a negative whose scan did not complete is neither a true negative nor a false positive', items: score.negativeFailures },
      reviewQueue: { count: score.reviewQueue.length, note: 'findings no adjudicated label accounts for; they may be genuine and are not counted as false positives' },
    },
    operationalAlertBurden: alertBurdenSection,
    intervalMethods: { registered: t.intervalMethod, definitions: INTERVAL_METHODS },
  };
  report.reportHash = digestOf({ ...report, reportHash: undefined });
  return report;
}

/**
 * The operational burden: how many alerts a reviewer would actually face, reported SEPARATELY from the deduplicated scoring.
 * `rawAlerts` counts every finding on every completed outcome; `rootCauses` collapses repeats. Neither number replaces the other.
 */
export function alertBurden(run, lineWindow = 3) {
  let raw = 0; let roots = 0; let completedTargets = 0;
  const byTarget = {};
  for (const o of run.outcomes || []) {
    if (o.status !== 'completed') continue;
    completedTargets++;
    const n = (o.findings || []).length;
    const c = clusterAlerts(o.findings || [], lineWindow).length;
    raw += n; roots += c;
    const key = o.targetId;
    byTarget[key] = { rawAlerts: (byTarget[key]?.rawAlerts || 0) + n, rootCauses: (byTarget[key]?.rootCauses || 0) + c };
  }
  return {
    rawAlerts: raw, rootCauses: roots, duplicatesCollapsed: raw - roots, completedOutcomes: completedTargets,
    alertsPerCompletedOutcome: completedTargets ? raw / completedTargets : null,
    rootCausesPerCompletedOutcome: completedTargets ? roots / completedTargets : null,
    byTarget,
    note: 'rawAlerts is what a reviewer reads; rootCauses is what scoring counts. Deduplication never hides burden.',
  };
}

/** The four populations must not share a target. Returns the overlaps; empty means disjoint. */
export function checkPopulationsDisjoint(populations) {
  const seen = new Map(); const overlaps = [];
  for (const name of POPULATIONS) {
    for (const id of populations?.[name] || []) {
      if (seen.has(id) && seen.get(id) !== name) overlaps.push({ targetId: id, populations: [seen.get(id), name] });
      else seen.set(id, name);
    }
  }
  return overlaps;
}
