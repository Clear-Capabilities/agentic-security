// QA-004: honest accuracy, uncertainty and security-economics reporting.
// GENERATED data only (test/helpers/evaluation-generated.js): the figures exercise the arithmetic, they describe no real code.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generatedPopulation, generatedScore, unitOf } from '../helpers/evaluation-generated.js';
import { buildAccuracyReport, alertBurden, checkPopulationsDisjoint } from '../../src/posture/evaluation/report.js';
import { groupedBootstrap, wilsonInterval, seededRng, seedFor, f1Of, INTERVAL_METHODS } from '../../src/posture/evaluation/interval.js';
import { accountCosts } from '../../src/posture/evaluation/economics.js';
import { clusterAlerts } from '../../src/posture/evaluation/score.js';
import { CORE_LANGUAGES } from '../../src/posture/evaluation/protocol.js';

const pop = generatedPopulation({ per: 100 });
// ~90% detection and ~5% false alarms, chosen by target id so the run is reproducible.
const { run, score } = generatedScore(pop, { detect: (t) => unitOf(t.id, 'd') < 0.9, falseAlarm: (t) => unitOf(t.id, 'f') < 0.05 });
const report = () => buildAccuracyReport({ score, protocol: pop.protocol, population: 'sealed', run });

describe('[QA-004.AC01] reports publish raw counts, per-language and per-family metrics, aggregates, completion and documented intervals', () => {
  test('raw TP/FP/FN/TN come before any ratio, by language and by family, and the ratios follow from them', () => {
    const r = report();
    for (const lang of CORE_LANGUAGES) {
      const s = r.byLanguage[lang];
      assert.deepEqual(Object.keys(s.raw).sort(), ['fn', 'fp', 'tn', 'tp']);
      assert.equal(s.raw.tp + s.raw.fn, 100, `${lang}: every positive is a TP or an FN`);
      assert.equal(s.raw.fp + s.raw.tn, 100, `${lang}: every negative is an FP or a TN`);
      assert.equal(s.status, 'measured');
      assert.equal(s.metrics.recall, s.raw.tp / (s.raw.tp + s.raw.fn));
      assert.equal(s.metrics.precision, s.raw.tp / (s.raw.tp + s.raw.fp));
      assert.equal(s.metrics.f1, (2 * s.raw.tp) / (2 * s.raw.tp + s.raw.fp + s.raw.fn));
    }
    assert.ok(r.byFamily['sql-injection'], 'a family row exists');
    assert.equal(r.byFamily['sql-injection'].raw.tp + r.byFamily['sql-injection'].raw.fn, 900);
  });

  test('micro pools the counts and macro averages per-language F1; they are different numbers and both are stated', () => {
    const r = report();
    const sum = (k) => CORE_LANGUAGES.reduce((s, l) => s + r.byLanguage[l].raw[k], 0);
    assert.equal(r.counts.endToEnd.micro.tp, sum('tp'));
    assert.equal(r.aggregate.micro.f1, (2 * sum('tp')) / (2 * sum('tp') + sum('fp') + sum('fn')));
    const macro = CORE_LANGUAGES.map((l) => r.byLanguage[l].metrics.f1).reduce((a, b) => a + b, 0) / CORE_LANGUAGES.length;
    assert.ok(Math.abs(r.aggregate.macro.f1 - macro) < 1e-12);
    assert.match(r.definitions.micro, /pooled/);
    assert.match(r.definitions.macro, /mean of per-language F1/);
  });

  test('completion has a rate, its raw counts and its own interval; unsupported and unscored counts are disclosed, not dropped', () => {
    const g = generatedScore(pop, { status: (t, v) => (t.id === 'gen-go-3' && v === 'pre' ? 'timeout' : t.id === 'gen-go-4' && v === 'post' ? 'unavailable' : 'completed') });
    const r = buildAccuracyReport({ score: g.score, protocol: pop.protocol, population: 'sealed', run: g.run });
    assert.equal(r.completion.outcomes, 1800);
    assert.equal(r.completion.completed, 1798);
    assert.equal(r.completion.interval.method, 'wilson-95');
    assert.ok(r.completion.interval.low < r.completion.rate && r.completion.rate < r.completion.interval.high + 1e-9);
    assert.equal(r.completion.statusCounts.timeout, 1);
    assert.equal(r.disclosed.unsupported.outcomesUnavailable, 1);
    assert.ok('unlabeledTargets' in r.disclosed.unscored && 'nonAdjudicatedLabels' in r.disclosed.unscored && 'unlabeledFindings' in r.disclosed.unscored);
    // the timeout on a known positive is a MISS in the end-to-end figures
    assert.equal(g.score.misses.find((m) => m.targetId === 'gen-go-3').reason, 'timeout');
  });

  test('every interval names its method and level; the registered method is the one implemented', () => {
    const r = report();
    assert.equal(r.intervalMethods.registered, 'grouped-bootstrap-95');
    assert.ok(INTERVAL_METHODS['grouped-bootstrap-95'] && INTERVAL_METHODS['wilson-95']);
    for (const iv of [r.aggregate.micro.intervals.f1, r.aggregate.macro.interval, r.byLanguage.go.intervals.f1, r.byLanguage.go.intervals.precision, r.byLanguage.go.intervals.recall]) {
      assert.equal(iv.method, 'grouped-bootstrap-95');
      assert.equal(iv.level, 0.95);
      assert.equal(iv.status, 'measured');
      assert.ok(iv.low <= iv.high);
    }
    const f1 = r.byLanguage.go.metrics.f1;
    assert.ok(r.byLanguage.go.intervals.f1.low <= f1 && f1 <= r.byLanguage.go.intervals.f1.high, 'the point estimate sits inside its own interval');
  });

  test('the bootstrap is reproducible: the same score and protocol give the same interval; a different protocol seeds differently', () => {
    const a = report().byLanguage.rust.intervals.f1; const b = report().byLanguage.rust.intervals.f1;
    assert.deepEqual(a, b);
    assert.notEqual(seedFor('sha256:aaa', 'x'), seedFor('sha256:bbb', 'x'));
    assert.notEqual(seedFor('sha256:aaa', 'x'), seedFor('sha256:aaa', 'y'));
    const r1 = seededRng(7); const r2 = seededRng(7);
    assert.deepEqual([r1(), r1(), r1()], [r2(), r2(), r2()]);
  });

  test('the bootstrap resamples GROUPS: near-duplicate targets make the interval wider than treating them as independent', () => {
    // 40 targets, half missed. As 40 independent groups the interval is narrow; as 4 groups of 10 (one group all-hit, one all-miss...) it is wide.
    const units = Array.from({ length: 40 }, (_, i) => ({ id: `t${i}`, language: 'go', tp: i < 20 ? 1 : 0, fn: i < 20 ? 0 : 1, fp: 0, tn: 0 }));
    const stat = (a) => f1Of(a.total);
    const independent = groupedBootstrap({ units, groupOf: {}, statistic: stat, name: 'x', protocolHash: 'sha256:p' });
    const grouped = groupedBootstrap({ units, groupOf: Object.fromEntries(units.map((u, i) => [u.id, `g${Math.floor(i / 10)}`])), statistic: stat, name: 'x', protocolHash: 'sha256:p', minGroups: 4 });
    assert.equal(independent.status, 'measured');
    assert.equal(grouped.status, 'measured');
    assert.ok(grouped.high - grouped.low > independent.high - independent.low, `grouped ${grouped.high - grouped.low} should exceed independent ${independent.high - independent.low}`);
  });

  test('too few independent groups: the interval is unmeasured with the reason, never a degenerate range', () => {
    const units = Array.from({ length: 30 }, (_, i) => ({ id: `t${i}`, language: 'go', tp: 1, fn: 0, fp: 0, tn: 0 }));
    const oneGroup = groupedBootstrap({ units, groupOf: Object.fromEntries(units.map((u) => [u.id, 'only'])), statistic: (a) => f1Of(a.total), name: 'x', protocolHash: 'sha256:p' });
    assert.equal(oneGroup.status, 'unmeasured');
    assert.equal(oneGroup.low, null);
    assert.match(oneGroup.reason, /1 independent group/);
  });

  test('wilson interval: known value, and zero cases is unmeasured', () => {
    const w = wilsonInterval(95, 100);
    assert.ok(Math.abs(w.low - 0.8882) < 0.001 && Math.abs(w.high - 0.9784) < 0.001, `${w.low} ${w.high}`);
    assert.equal(wilsonInterval(0, 0).status, 'unmeasured');
    assert.equal(wilsonInterval(5, 4).status, 'unmeasured');
  });

  test('a stratum below the protocol floor is reported UNMEASURED with its raw counts and no flattering interval (control: at the floor it is measured)', () => {
    const small = generatedPopulation({ per: 100 });
    // Make 'ruby' a thin stratum by labelling only 20 of its positives into the run: drop the rest from the score by marking them outside the run.
    const g = generatedScore(small, {});
    const cut = JSON.parse(JSON.stringify(g.score));
    const rubyTotal = cut.endToEnd.byLanguage.ruby; rubyTotal.tp = 20; rubyTotal.fn = 0; rubyTotal.fp = 0; rubyTotal.tn = 20;
    const r = buildAccuracyReport({ score: cut, protocol: small.protocol, population: 'sealed', run: g.run });
    assert.equal(r.byLanguage.ruby.status, 'unmeasured');
    assert.match(r.byLanguage.ruby.reason, /20 positives in ruby, fewer than the 100/);
    assert.equal(r.byLanguage.ruby.intervals, null);
    assert.deepEqual(r.byLanguage.ruby.raw, { tp: 20, fp: 0, fn: 0, tn: 20 }, 'raw counts are still published');
    assert.ok(r.byLanguage.ruby.descriptive, 'a descriptive figure is kept apart from the measured ones');
    assert.equal(r.byLanguage.go.status, 'measured', 'control');
    assert.equal(r.byFamily['sql-injection'].status, 'measured', 'control: the family has 900 positives');
  });
});

describe('[QA-004.AC02] unknown labels and true-negative failures are disclosed; repeated alerts dedupe for scoring and the burden is reported separately', () => {
  test('a non-adjudicated label and a negative whose scan failed are disclosed with counts, and neither inflates a rate', () => {
    const p = generatedPopulation({ per: 100 });
    const candidate = { ...p.defects[0], adjudication: { status: 'candidate', reviewers: [] } };
    const defects = [candidate, ...p.defects.slice(1)];
    const g = generatedScore({ ...p, defects }, { status: (t, v) => (t.id === 'gen-ruby-1' && v === 'post' ? 'error' : 'completed') });
    const r = buildAccuracyReport({ score: g.score, protocol: p.protocol, population: 'sealed', run: g.run });
    assert.equal(r.disclosed.unknownLabels.count, 1);
    assert.equal(r.disclosed.trueNegativeFailures.count, 1);
    assert.equal(r.disclosed.trueNegativeFailures.items[0].reason, 'error');
    assert.equal(r.counts.endToEnd.micro.tp + r.counts.endToEnd.micro.fn, 899, 'the candidate is not scored');
    assert.equal(r.counts.endToEnd.micro.tn + r.counts.endToEnd.micro.fp, 899, 'the failed negative is neither a TN nor an FP');
  });

  test('five alerts for ONE flaw inside a negative score as one false positive, while the operational burden still counts all five', () => {
    const p = generatedPopulation({ per: 100 });
    const g = generatedScore(p, { falseAlarm: (t) => t.id === 'gen-java-0', extraAlerts: (t, v) => (t.id === 'gen-java-0' && v === 'post' ? 4 : 0) });
    assert.equal(g.score.endToEnd.byLanguage.java.fp, 1, 'one root cause, one false positive');
    assert.equal(g.score.falsePositives[0].alertsCollapsed, 5);
    const r = buildAccuracyReport({ score: g.score, protocol: p.protocol, population: 'sealed', run: g.run });
    const burden = r.operationalAlertBurden;
    assert.equal(burden.rawAlerts, 900 + 5, 'every alert a reviewer would read');
    assert.equal(burden.rootCauses, 900 + 1);
    assert.equal(burden.duplicatesCollapsed, 4);
    assert.equal(burden.byTarget['gen-java-0'].rawAlerts, 5 + 1, 'the target also carries its genuine detection on the pre variant');
    assert.match(burden.note, /never hides burden/);
  });

  test('alerts far apart, in other files or in other families are different root causes (control: adjacent ones merge)', () => {
    const f = (o) => ({ file: 'a.x', family: 'sql-injection', line: 10, ...o });
    assert.equal(clusterAlerts([f({ line: 10 }), f({ line: 12 })]).length, 1, 'within the window');
    assert.equal(clusterAlerts([f({ line: 10 }), f({ line: 40 })]).length, 2, 'far apart');
    assert.equal(clusterAlerts([f({}), f({ file: 'b.x' })]).length, 2, 'other file');
    assert.equal(clusterAlerts([f({}), f({ family: 'command-injection' })]).length, 2, 'other family');
    assert.equal(clusterAlerts([f({ line: null }), f({ line: null })]).length, 2, 'a finding with no line cannot be placed, so it never merges');
    assert.equal(alertBurden({ outcomes: [{ targetId: 't', status: 'timeout', findings: [f({})] }] }).rawAlerts, 0, 'only completed outcomes produce alerts');
  });

  test('the four populations must not share a target', () => {
    assert.deepEqual(checkPopulationsDisjoint({ regression: ['a'], development: ['b'], sealed: ['c'], operational: ['d'] }), []);
    const overlaps = checkPopulationsDisjoint({ development: ['b', 'x'], sealed: ['x'], regression: ['x'] });
    assert.ok(overlaps.length >= 1 && overlaps.every((o) => o.targetId === 'x'));
    assert.throws(() => buildAccuracyReport({ score, protocol: pop.protocol, population: 'everything', run }), /population must be one of/);
    assert.throws(() => buildAccuracyReport({ score: { ...score, protocolHash: 'sha256:' + '0'.repeat(64) }, protocol: pop.protocol, population: 'sealed', run }), /different protocol/);
  });
});

describe('[QA-004.AC03] cost accounting keeps the kinds apart, charges failures, and never double-counts a duplicated finding', () => {
  const E = (o) => ({ id: `e${Math.random()}`, targetId: 't', ...o });
  const ledger = () => [
    E({ kind: 'model', amountUsd: 2.0, outcome: 'confirmed', rootCauseId: 'rc-1', attemptId: 'a1' }),
    E({ kind: 'model', amountUsd: 1.0, outcome: 'failed', attemptId: 'a2' }),
    E({ kind: 'model', amountUsd: 0.5, outcome: 'duplicate', rootCauseId: 'rc-1', attemptId: 'a3' }),
    E({ kind: 'tool', amountUsd: 0.4, outcome: 'validated-fix', rootCauseId: 'rc-1', attemptId: 'a4' }),
    E({ kind: 'cache', amountUsd: 0.1, outcome: 'confirmed', rootCauseId: 'rc-2' }),
    E({ kind: 'human-review', minutes: 30, outcome: 'confirmed', rootCauseId: 'rc-2' }),
  ];

  test('model, tool, cache and human minutes are separate totals; minutes are never added to dollars', () => {
    const r = accountCosts(ledger());
    assert.equal(r.ok, true);
    assert.equal(r.totals.model.usd, 3.5);
    assert.equal(r.totals.tool.usd, 0.4);
    assert.equal(r.totals.cache.usd, 0.1);
    assert.equal(r.totals.humanReview.minutes, 30);
    assert.equal(r.machineSpendUsd, 4.0);
    assert.match(r.separation, /never combined/);
  });

  test('cost per confirmed defect includes failed and duplicate attempts and divides by DISTINCT root causes', () => {
    const r = accountCosts(ledger());
    assert.equal(r.confirmedDefects, 2, 'rc-1 was found three times and counts once');
    assert.equal(r.validatedFixes, 1);
    assert.equal(r.costPerConfirmedDefectUsd, 4.0 / 2);
    assert.equal(r.costPerValidatedFixUsd, 4.0 / 1);
    assert.equal(r.humanMinutesPerConfirmedDefect, 15);
    // control: dropping the failed attempt lowers the price, so it was being charged
    const withoutFailed = accountCosts(ledger().filter((e) => e.outcome !== 'failed'));
    assert.ok(withoutFailed.costPerConfirmedDefectUsd < r.costPerConfirmedDefectUsd);
  });

  test('a duplicate finding of an already confirmed root cause never raises the defect count', () => {
    const base = accountCosts(ledger());
    const dup = accountCosts([...ledger(), E({ kind: 'model', amountUsd: 0.0, outcome: 'confirmed', rootCauseId: 'rc-1' }), E({ kind: 'tool', amountUsd: 0, outcome: 'validated-fix', rootCauseId: 'rc-1' })]);
    assert.equal(dup.confirmedDefects, base.confirmedDefects);
    assert.equal(dup.validatedFixes, base.validatedFixes);
  });

  test('an entry with no amount is unmeasured, not zero, and the ratio is flagged a lower bound', () => {
    const r = accountCosts([E({ kind: 'model', outcome: 'confirmed', rootCauseId: 'rc-1' }), E({ kind: 'tool', amountUsd: 1, outcome: 'failed' })]);
    assert.equal(r.totals.model.unmeasured, 1);
    assert.equal(r.unmeasuredMachineEntries, 1);
    assert.equal(r.lowerBound, true);
    assert.equal(accountCosts([E({ kind: 'tool', amountUsd: 1, outcome: 'confirmed', rootCauseId: 'r' })]).lowerBound, false);
  });

  test('no confirmed defect: the ratio is undefined (null), not zero and not the total', () => {
    const r = accountCosts([E({ kind: 'model', amountUsd: 5, outcome: 'failed' })]);
    assert.equal(r.costPerConfirmedDefectUsd, null);
    assert.equal(r.costPerValidatedFixUsd, null);
    assert.equal(r.machineSpendUsd, 5);
  });

  test('malformed entries are refused: mixed units, an unknown kind, a negative amount, a confirmation with no root cause', () => {
    for (const bad of [
      E({ kind: 'human-review', minutes: 5, amountUsd: 2 }),
      E({ kind: 'tool', amountUsd: 1, minutes: 3 }),
      E({ kind: 'telepathy', amountUsd: 1 }),
      E({ kind: 'model', amountUsd: -1 }),
      E({ kind: 'model', amountUsd: 1, outcome: 'confirmed' }),
      E({ kind: 'model', amountUsd: 1, outcome: 'victory' }),
    ]) assert.equal(accountCosts([bad]).ok, false, JSON.stringify(bad));
  });
});
