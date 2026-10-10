// X-603: calibration by supported strata. SYNTHETIC outcomes only (test/helpers/routing-fixtures.js): the arithmetic is real, the
// populations are not. A population built with `synthetic: false` here is a GENERATED stand-in used to reach the `reliable` branch of
// the logic; it is not evidence about any model.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCalibration, verifyCalibration, routingPopulationGate, validateCalibrationConfig, ROUTING_MINIMUMS, ROUTING_PROMOTION_TARGETS, CALIBRATION_LABELS,
} from '../../src/posture/routing/calibration.js';
import { syntheticPopulation, outcomeOf, taskOf, BASE_CONFIG, HELD_OUT_FROM, HELD_DATE, DEV_DATE, ADJUDICATION } from '../helpers/routing-fixtures.js';
import { buildRoutingOutcome } from '../../src/posture/routing/outcomes.js';

const MODELS = [{ id: 'model-a', acc: 0.9, costUsd: 0.05 }, { id: 'model-b', acc: 0.88, costUsd: 0.01 }];
const build = (outcomes, config = BASE_CONFIG) => { const r = buildCalibration({ outcomes, config }); assert.equal(r.ok, true, JSON.stringify(r.errors)); return r.artifact; };
const stratumEst = (a, model, stratum = 'repair|javascript|CWE-89|xs', version = '1') => a.estimates.find((e) => e.model === model && e.stratum === stratum && (e.modelVersion ?? null) === version);
const real = (o) => syntheticPopulation({ ...o, synthetic: false });

describe('[X-603.AC01] calibration uses held-out grouped outcomes with model-version and time splits and gives estimates with uncertainty', () => {
  test('the estimate is computed on held-out outcomes only; development outcomes do not enter it', () => {
    // development: model-b is always wrong. Held-out: it is right about 88 percent of the time.
    const dev = []; const held = syntheticPopulation({ dev: 0, held: 240, models: MODELS, startIndex: 1000 }).outcomes;
    for (let i = 0; i < 60; i++) dev.push(outcomeOf({ task: taskOf(i), model: 'model-b', correct: false, observedAt: DEV_DATE, group: `grp-d-${i}` }), outcomeOf({ task: taskOf(i), model: 'model-a', correct: true, observedAt: DEV_DATE, group: `grp-d-${i}` }));
    const a = build([...dev, ...held]);
    const heldB = held.filter((o) => o.model === 'model-b');
    const expected = heldB.filter((o) => o.outcome === 'correct').length / heldB.length;
    const e = stratumEst(a, 'model-b');
    assert.equal(e.n, heldB.length);
    assert.ok(Math.abs(e.accuracy - expected) < 1e-8, `${e.accuracy} vs ${expected}`);
    assert.equal(e.development.n, 60);
    assert.equal(e.development.accuracy, 0);
    assert.equal(a.counts.development, 120); assert.equal(a.counts.heldOut, 480);
  });

  test('the time split is at the cutoff: an outcome at the cutoff is held out, one a second earlier is development', () => {
    const t = taskOf(1);
    const at = outcomeOf({ task: t, model: 'model-a', observedAt: HELD_OUT_FROM, group: 'g-at' });
    const before = outcomeOf({ task: taskOf(2), model: 'model-a', observedAt: '2026-03-31T23:59:59Z', group: 'g-before' });
    const a = build([at, before]);
    assert.equal(a.counts.heldOut, 1); assert.equal(a.counts.development, 1);
  });

  test('a group on both sides of the split is removed from the held-out side and counted, so near-duplicates cannot look like generalisation', () => {
    const dev = outcomeOf({ task: taskOf(1), model: 'model-a', observedAt: DEV_DATE, group: 'shared-upstream' });
    const leaky = outcomeOf({ task: taskOf(2), model: 'model-a', observedAt: HELD_DATE, group: 'shared-upstream' });
    const clean = outcomeOf({ task: taskOf(3), model: 'model-a', observedAt: HELD_DATE, group: 'other-upstream' });
    const a = build([dev, leaky, clean]);
    assert.equal(a.counts.heldOut, 1);
    assert.equal(a.exclusions.counts['group-straddles-split'], 1);
    assert.deepEqual(a.exclusions.ids['group-straddles-split'], [leaky.id]);
  });

  test('a model version listed as held out is held out entirely, and versions are never pooled', () => {
    const v1 = syntheticPopulation({ dev: 0, held: 60, models: [{ id: 'model-a', version: '1', acc: 0.95 }], startIndex: 0 }).outcomes;
    // version 2 is observed BEFORE the time cutoff but is held out by version, and it is worse
    const v2 = [];
    for (let i = 0; i < 60; i++) v2.push(outcomeOf({ task: taskOf(5000 + i), model: 'model-a', version: '2', correct: i % 2 === 0, observedAt: DEV_DATE, group: `grp-v2-${i}` }));
    const a = build([...v1, ...v2], { ...BASE_CONFIG, heldOutModelVersions: [{ model: 'model-a', modelVersion: '2' }] });
    const e1 = stratumEst(a, 'model-a', undefined, '1'); const e2 = stratumEst(a, 'model-a', undefined, '2');
    assert.equal(e1.n, 60); assert.equal(e2.n, 60, 'the version-2 outcomes are held out even though they precede the cutoff');
    assert.ok(e1.accuracy > e2.accuracy);
    assert.equal(e2.accuracy, 0.5);
    assert.equal(a.counts.development, 0);
  });

  test('a measured estimate carries a grouped-bootstrap interval around the point value, with its method and group count', () => {
    const a = build(real({ dev: 60, held: 240, models: MODELS }).outcomes);
    const e = stratumEst(a, 'model-a');
    assert.equal(e.interval.method, 'grouped-bootstrap-95');
    assert.equal(e.interval.status, 'measured');
    assert.ok(e.interval.low < e.accuracy && e.accuracy < e.interval.high, JSON.stringify(e.interval));
    assert.equal(e.interval.groups, 240);
    assert.ok(a.config.replicates >= 100);
  });

  test('too few independent groups leaves the interval unmeasured, with the reason, and the stratum cannot be reliable', () => {
    const a = build(real({ dev: 60, held: 240, models: MODELS, groupSize: 60 }).outcomes);
    const e = stratumEst(a, 'model-a');
    assert.equal(e.interval.status, 'unmeasured');
    assert.equal(e.interval.low, null);
    assert.match(e.interval.reason, /independent group/);
    assert.notEqual(e.label, 'reliable');
    assert.ok(e.reasons.some((r) => /uncertainty interval is unmeasured/.test(r)));
  });

  test('operational failures are counted beside the rate, and the conservative rate treats unlabelled failures as misses', () => {
    const base = real({ dev: 0, held: 40, models: [{ id: 'model-a', acc: 1 }] }).outcomes;
    const failures = [];
    for (let i = 0; i < 10; i++) {
      const r = buildRoutingOutcome({ runId: `f${i}`, task: taskOf(900 + i), model: 'model-a', modelVersion: '1', status: i % 2 ? 'timeout' : 'provider-error', outcome: 'unknown', group: `grp-f-${i}`, observedAt: HELD_DATE, synthetic: false });
      failures.push(r.outcome);
    }
    const a = build([...base, ...failures]);
    const e = stratumEst(a, 'model-a');
    assert.equal(e.n, 40); assert.equal(e.accuracy, 1);
    assert.equal(e.operational.timeout + e.operational.providerError, 10);
    assert.equal(e.operational.unlabelled, 10);
    assert.ok(Math.abs(e.conservativeAccuracy - 40 / 50) < 1e-8);
  });
});

describe('[X-603.AC02] under-sampled or shifted strata use an explicit fallback; no reliable label below the preregistered minimum', () => {
  test('the preregistered minimums are the PRD section 5 numbers and a config cannot lower them', () => {
    assert.equal(ROUTING_MINIMUMS.pairedTasksOverall, 200);
    assert.equal(ROUTING_MINIMUMS.pairedTasksPerStratum, 30);
    assert.equal(ROUTING_PROMOTION_TARGETS.qualityDifferenceLowerBound, -0.02);
    assert.equal(ROUTING_PROMOTION_TARGETS.medianCostReduction, 0.20);
    assert.equal(ROUTING_PROMOTION_TARGETS.qualityGain, 0.05);
    assert.equal(ROUTING_PROMOTION_TARGETS.p95LatencyRatio, 1.2);
    assert.throws(() => { ROUTING_MINIMUMS.pairedTasksOverall = 1; });
    for (const [k, v] of [['pairedTasksOverall', 199], ['pairedTasksPerStratum', 29], ['developmentPerStratum', 9]]) {
      const r = buildCalibration({ outcomes: [], config: { ...BASE_CONFIG, minimums: { [k]: v } } });
      assert.equal(r.ok, false, k);
      assert.equal(r.errors[0].code, 'BAD_CALIBRATION_CONFIG');
    }
    assert.equal(validateCalibrationConfig({ ...BASE_CONFIG, minimums: { pairedTasksOverall: 500 } }).ok, true, 'stricter is allowed');
  });

  test('overall boundary: 199 paired tasks never earns reliable, 200 does', () => {
    const at = (n) => build(real({ dev: 60, held: n, models: MODELS }).outcomes);
    const short = at(199); const enough = at(200);
    assert.equal(short.pairing.overallPairedHeldOut, 199); assert.equal(short.pairing.overallMet, false);
    assert.ok(short.estimates.every((e) => e.label !== 'reliable' && e.label !== 'reliable-synthetic'), 'no reliable label at 199');
    assert.ok(short.estimates.some((e) => e.reasons.some((r) => /199 paired adjudicated task/.test(r))));
    assert.equal(enough.pairing.overallMet, true);
    assert.equal(stratumEst(enough, 'model-a').label, 'reliable');
    assert.equal(stratumEst(enough, 'model-b').label, 'reliable');
  });

  test('per-stratum boundary: 29 paired tasks in a stratum is not reliable, 30 is, even when the overall minimum is met', () => {
    const big = real({ dev: 40, held: 200, models: MODELS, strata: [{ vulnClass: 'CWE-22' }] });
    const s29 = real({ dev: 15, held: 29, models: MODELS, strata: [{ vulnClass: 'CWE-79' }], startIndex: 5000 });
    const s30 = real({ dev: 15, held: 30, models: MODELS, strata: [{ vulnClass: 'CWE-89' }], startIndex: 9000 });
    const a = build([...big.outcomes, ...s29.outcomes, ...s30.outcomes]);
    assert.equal(a.pairing.overallMet, true);
    const e29 = stratumEst(a, 'model-b', 'repair|javascript|CWE-79|xs'); const e30 = stratumEst(a, 'model-b', 'repair|javascript|CWE-89|xs');
    assert.equal(e29.pairedWithBaseline, 29); assert.notEqual(e29.label, 'reliable');
    assert.equal(e30.pairedWithBaseline, 30);
    assert.equal(e30.label, 'reliable');
    assert.equal(e29.label, 'fallback-parent', 'the 29-task stratum borrows a coarser reliable stratum, explicitly');
    assert.equal(e29.fallback.from, 'repair|javascript');
    assert.ok(e29.reasons.some((r) => /29 paired adjudicated task/.test(r)));
  });

  test('an under-sampled stratum falls back to a reliable parent, explicitly, and is labelled fallback-parent, never reliable', () => {
    const big = real({ dev: 40, held: 240, models: MODELS, strata: [{ contextTokens: 3000 }] });
    const thin = real({ dev: 10, held: 8, models: MODELS, strata: [{ contextTokens: 60_000 }], startIndex: 7000 });
    const a = build([...big.outcomes, ...thin.outcomes]);
    const e = stratumEst(a, 'model-b', 'repair|javascript|CWE-89|m');
    assert.equal(e.label, 'fallback-parent');
    assert.equal(e.fallback.policy, 'parent-stratum');
    assert.equal(e.fallback.from, 'repair|javascript|CWE-89');
    assert.ok(e.fallback.parentInterval.low !== null);
    assert.ok(e.reasons.length > 0);
    assert.ok(CALIBRATION_LABELS.includes(e.label));
  });

  test('with no reliable parent either, the fallback is the baseline model, stated in the artifact', () => {
    const a = build(real({ dev: 5, held: 12, models: MODELS }).outcomes);
    for (const e of a.estimates) {
      assert.equal(e.label, 'insufficient-evidence');
      assert.equal(e.fallback.policy, 'baseline-model');
      assert.equal(e.fallback.model, 'model-a');
    }
  });

  test('a shifted stratum is labelled shifted, gets no parent fallback, and falls back to the baseline model', () => {
    const dev = []; for (let i = 0; i < 40; i++) dev.push(outcomeOf({ task: taskOf(i, { synthetic: false }), model: 'model-b', correct: true, observedAt: DEV_DATE, group: `grp-d-${i}`, synthetic: false }), outcomeOf({ task: taskOf(i, { synthetic: false }), model: 'model-a', correct: true, observedAt: DEV_DATE, group: `grp-d-${i}`, synthetic: false }));
    const held = []; for (let i = 0; i < 240; i++) held.push(outcomeOf({ task: taskOf(1000 + i, { synthetic: false }), model: 'model-b', correct: i % 2 === 0, observedAt: HELD_DATE, group: `grp-h-${i}`, synthetic: false }), outcomeOf({ task: taskOf(1000 + i, { synthetic: false }), model: 'model-a', correct: true, observedAt: HELD_DATE, group: `grp-h-${i}`, synthetic: false }));
    const a = build([...dev, ...held]);
    const e = stratumEst(a, 'model-b');
    assert.equal(e.shift, 'shifted');
    assert.equal(e.label, 'shifted');
    assert.equal(e.fallback.policy, 'baseline-model');
    assert.equal(stratumEst(a, 'model-a').shift, 'stable');
    assert.equal(stratumEst(a, 'model-a').label, 'reliable');
  });

  test('a stratum with no development baseline cannot be called stable, so it is not reliable', () => {
    const a = build(real({ dev: 0, held: 240, models: MODELS }).outcomes);
    const e = stratumEst(a, 'model-a');
    assert.equal(e.shift, 'untested');
    assert.equal(e.label, 'insufficient-evidence');
    assert.ok(e.reasons.some((r) => /development baseline/.test(r)));
  });

  test('unknown and delayed outcomes are never imputed: they are excluded from the rate and counted by reason', () => {
    const base = real({ dev: 0, held: 40, models: [{ id: 'model-a', acc: 1 }] }).outcomes;
    const extra = [outcomeOf({ task: taskOf(800), model: 'model-a', correct: null, group: 'g-u', synthetic: false }), outcomeOf({ task: taskOf(801), model: 'model-a', correct: null, delayed: true, group: 'g-d', synthetic: false })];
    const a = build([...base, ...extra]);
    assert.equal(a.exclusions.counts['unlabelled-unknown'], 1); assert.equal(a.exclusions.counts['unlabelled-delayed'], 1);
    assert.equal(stratumEst(a, 'model-a').n, 40);
  });

  test('a synthetic population never produces a reliable label; only reliable-synthetic', () => {
    const a = build(syntheticPopulation({ dev: 60, held: 240, models: MODELS }).outcomes);
    assert.equal(a.synthetic, true);
    assert.ok(a.estimates.every((e) => e.label !== 'reliable'));
    assert.equal(stratumEst(a, 'model-a').label, 'reliable-synthetic');
  });

  test('the section 5 routing population gate reads unmeasured on synthetic data, insufficient-population when small, and never pass', () => {
    const synth = routingPopulationGate(build(syntheticPopulation({ dev: 60, held: 240, models: MODELS }).outcomes));
    assert.equal(synth.status, 'unmeasured'); assert.match(synth.reason, /synthetic/);
    const small = routingPopulationGate(build(real({ dev: 20, held: 50, models: MODELS }).outcomes));
    assert.equal(small.status, 'insufficient-population');
    const enough = routingPopulationGate(build(real({ dev: 60, held: 240, models: MODELS }).outcomes));
    assert.equal(enough.status, 'population-sufficient');
    assert.equal(enough.promotion, 'not-evaluated');
    for (const g of [synth, small, enough, routingPopulationGate(null)]) assert.notEqual(g.status, 'pass');
    assert.equal(routingPopulationGate(null).status, 'unmeasured');
  });
});

describe('[X-603.AC03] calibration artifacts record dataset hashes, adjudication versions, sample counts and exclusions and rebuild deterministically', () => {
  const pop = syntheticPopulation({ dev: 40, held: 100, models: MODELS });

  test('the artifact records the dataset hash, adjudication versions, counts and every exclusion with its reason', () => {
    const extra = [
      outcomeOf({ task: taskOf(700), model: 'model-a', correct: null, group: 'g-x' }),
      { ...pop.outcomes[0], runId: 'tampered' }, // fails id validation
      pop.outcomes[1], // duplicate
    ];
    const a = build([...pop.outcomes, ...extra]);
    assert.match(a.dataset.hash, /^sha256:[0-9a-f]{64}$/);
    assert.match(a.calibrationHash, /^sha256:[0-9a-f]{64}$/);
    assert.match(a.configHash, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(a.adjudicationVersions, ['synthetic-protocol-1']);
    assert.equal(a.counts.input, pop.outcomes.length + 3);
    assert.equal(a.exclusions.counts['invalid-record'], 1); assert.equal(a.exclusions.counts.duplicate, 1); assert.equal(a.exclusions.counts['unlabelled-unknown'], 1);
    assert.equal(a.counts.usable + a.exclusions.counts['unlabelled-unknown'], a.counts.valid);
    assert.ok(a.exclusions.ids.duplicate.includes(pop.outcomes[1].id));
    assert.equal(a.synthetic, true);
  });

  test('the same outcomes in any order rebuild the identical artifact', () => {
    const a1 = build(pop.outcomes); const a2 = build([...pop.outcomes].reverse()); const a3 = build([...pop.outcomes].sort(() => 0));
    assert.equal(a1.calibrationHash, a2.calibrationHash);
    assert.equal(a1.calibrationHash, a3.calibrationHash);
    assert.deepEqual(JSON.parse(JSON.stringify(a1)), JSON.parse(JSON.stringify(a2)));
    assert.equal(verifyCalibration(a1, { outcomes: [...pop.outcomes].reverse(), config: BASE_CONFIG }).ok, true);
  });

  test('a changed outcome, a changed configuration or an edited artifact all fail verification', () => {
    const a = build(pop.outcomes);
    const flipped = pop.outcomes.map((o, i) => (i === 3 ? outcomeOf({ task: taskOf(0), model: 'model-a', correct: false, observedAt: DEV_DATE, group: 'grp-flip' }) : o));
    assert.equal(verifyCalibration(a, { outcomes: flipped, config: BASE_CONFIG }).ok, false);
    assert.equal(verifyCalibration(a, { outcomes: pop.outcomes, config: { ...BASE_CONFIG, timeSplit: { heldOutFrom: '2026-03-01T00:00:00Z' } } }).ok, false);
    const edited = JSON.parse(JSON.stringify(a)); edited.estimates[0].label = 'reliable';
    const v = verifyCalibration(edited, { outcomes: pop.outcomes, config: BASE_CONFIG });
    assert.equal(v.ok, false); assert.match(v.reason, /own hash/);
    assert.equal(verifyCalibration(null, { outcomes: [], config: BASE_CONFIG }).ok, false);
  });

  test('the dataset hash moves with a label change and the config hash moves with the time split', () => {
    const a = build(pop.outcomes);
    const other = build(pop.outcomes, { ...BASE_CONFIG, timeSplit: { heldOutFrom: '2026-03-01T00:00:00Z' } });
    assert.notEqual(a.configHash, other.configHash);
    assert.equal(a.dataset.hash, other.dataset.hash);
    const relabelled = pop.outcomes.map((o, i) => (i === 0 ? { ...o, outcome: 'delayed', labelSource: 'none', labelId: undefined } : o));
    const r = buildCalibration({ outcomes: relabelled, config: BASE_CONFIG });
    assert.equal(r.ok, true);
    assert.notEqual(r.artifact.dataset.hash, a.dataset.hash);
  });
});
