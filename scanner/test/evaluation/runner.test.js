// QA-003: reproducible runs, ablations and end-to-end scoring. SYNTHETIC data only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  runEvaluation, runReplicates, runAblations, assertAblationComparable, runIdentity, runIdentityMaterial, defaultScanFn, ABLATION_LAYERS, digestTree,
} from '../../src/posture/evaluation/runner.js';
import { scoreRun } from '../../src/posture/evaluation/score.js';
import { suite, resolver, clone, stubScan, timeoutError, SYN_FINDING, FIXTURES } from '../helpers/evaluation-suite.js';

const P = () => suite().protocol;
const score = (run) => scoreRun({ run, protocol: P(), defects: suite().defects, negatives: suite().negatives });
const CMD = SYN_FINDING({ id: 'c1', file: 'tool.py', line: 11, family: 'command-injection', cwe: 'CWE-78' });
const GOOD = { 'syn-sqli-js-pre': [SYN_FINDING()], 'syn-cmd-py-pre': [CMD] };
const base = (over = {}) => ({ protocol: P(), config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: stubScan(GOOD), split: 'dev', ...over });

describe('[QA-003.AC01] every run records each target outcome with findings, timing, cost, failure reason and hashes', () => {
  test('a run record carries a full outcome per target and variant, bound to the protocol', async () => {
    const { ok, run } = await runEvaluation(base());
    assert.equal(ok, true);
    assert.equal(run.protocolHash, P().protocolHash);
    assert.equal(run.outcomes.length, 4);
    for (const o of run.outcomes) {
      for (const k of ['targetId', 'variant', 'status', 'findings', 'durationMs', 'costUsd', 'costSource', 'failureReason', 'inputHash', 'outputHash']) assert.ok(k in o, `${o.targetId}/${o.variant} lacks ${k}`);
      assert.match(o.inputHash, /^sha256:[0-9a-f]{64}$/);
      assert.match(o.outputHash, /^sha256:[0-9a-f]{64}$/);
    }
    assert.equal(run.outcomes.find((o) => o.targetId === 'syn-cmd-py' && o.variant === 'pre').findings[0].family, 'command-injection');
    assert.deepEqual(Object.keys(run.totals).sort(), ['completed', 'error', 'quarantined', 'timeout', 'unavailable']);
    assert.match(run.runId, /^erun:/);
  });

  test('cost is reported only when measured; an unmeasured cost is not zero', async () => {
    const { run } = await runEvaluation(base());
    assert.ok(run.outcomes.every((o) => o.costUsd === null && o.costSource === 'unmeasured'));
    const priced = await runEvaluation(base({ scanFn: async () => ({ findings: [], costUsd: 0.25 }) }));
    assert.ok(priced.run.outcomes.every((o) => o.costUsd === 0.25 && o.costSource === 'reported-by-scan'));
    assert.equal(priced.run.totalCostUsd, 1);
  });

  test('a failed scan records its reason and stays in the record', async () => {
    const { run } = await runEvaluation(base({ scanFn: stubScan({ 'syn-sqli-js-pre': new Error('parser exploded'), 'syn-cmd-py-pre': timeoutError() }) }));
    const err = run.outcomes.find((o) => o.targetId === 'syn-sqli-js' && o.variant === 'pre');
    const to = run.outcomes.find((o) => o.targetId === 'syn-cmd-py' && o.variant === 'pre');
    assert.equal(err.status, 'error'); assert.match(err.failureReason, /parser exploded/);
    assert.equal(to.status, 'timeout'); assert.match(to.failureReason, /no result within/);
    assert.equal(run.totals.error, 1); assert.equal(run.totals.timeout, 1);
  });

  test('deterministic repeats reproduce output hashes exactly (stub), and a nondeterministic deterministic-layer is flagged', async () => {
    const r = await runReplicates({ n: 2, ...base() });
    assert.equal(r.valid, true);
    assert.deepEqual(r.determinism, { checked: true, identical: true, differing: [] });
    assert.notEqual(r.runs[0].runId, r.runs[1].runId, 'replicates are distinct runs of one experiment');
    assert.equal(r.runs[0].experimentId, r.runs[1].experimentId);
    let n = 0;
    const flaky = async () => ({ findings: [SYN_FINDING({ id: `f${n++}` })] });
    const bad = await runReplicates({ n: 2, ...base({ scanFn: flaky }) });
    assert.equal(bad.valid, false);
    assert.equal(bad.determinism.identical, false);
    assert.match(bad.reasons.join(' '), /different output across replicates/);
  });

  test('deterministic repeats on the REAL engine reproduce (deterministic-only and deep-taint, one target each side)', async () => {
    for (const layer of ['deterministic-only', 'deep-taint']) {
      const r = await runReplicates({ n: 2, protocol: P(), config: { layer }, resolveTarget: resolver(), split: 'dev' });
      assert.equal(r.ok, true, JSON.stringify(r.errors));
      assert.equal(r.runs[0].totals.completed, 4, `${layer}: ${JSON.stringify(r.runs[0].outcomes.map((o) => o.failureReason))}`);
      assert.equal(r.determinism.identical, true, `${layer} differed: ${r.determinism.differing}`);
      assert.equal(r.runs[0].rawHash, r.runs[1].rawHash);
    }
  });

  test('a stochastic (model-assisted) configuration needs at least three replicates with recorded seeds', async () => {
    const cfg = { layer: 'model-assisted', provider: 'stub-provider', model: 'stub-model', seed: 100 };
    const two = await runReplicates({ n: 2, seedSupported: true, ...base({ config: cfg }) });
    assert.equal(two.valid, false);
    assert.match(two.reasons.join(' '), /at least 3 measured replicates/);
    const three = await runReplicates({ n: 3, seedSupported: true, ...base({ config: cfg }) });
    assert.equal(three.valid, true);
    assert.deepEqual(three.runs.map((r) => r.config.seed), [100, 101, 102]);
    assert.equal(new Set(three.runs.map((r) => r.runId)).size, 3);
    const noSeed = await runReplicates({ n: 3, seedSupported: false, ...base({ config: cfg }) });
    assert.match(noSeed.reasons.join(' '), /seeds are not supported/);
    assert.deepEqual(noSeed.runs.map((r) => r.config.seed), [100, 100, 100]);
  });

  test('the model-assisted layer on the real engine is UNAVAILABLE without an endpoint, recorded as such and never as a clean result', async () => {
    const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
    delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
    try {
      const { run } = await runEvaluation({ protocol: P(), config: { layer: 'model-assisted' }, resolveTarget: resolver(), split: 'dev' });
      assert.equal(run.totals.completed, 0);
      assert.equal(run.totals.unavailable, 4);
      assert.match(run.outcomes[0].failureReason, /AGENTIC_SECURITY_LLM_ENDPOINT/);
    } finally { if (prev !== undefined) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev; }
  });
});

describe('[QA-003.AC02] ablations share targets, matching policy, resources and ceilings; any input change is a distinct run', () => {
  test('three layers over identical pinned targets are comparable and have distinct identities', async () => {
    const ab = await runAblations({ ...base(), layers: ABLATION_LAYERS, config: {} });
    assert.equal(ab.ok, true, JSON.stringify(ab.errors));
    assert.equal(ab.runs.length, 3);
    assert.equal(new Set(ab.runs.map((r) => r.runId)).size, 3);
    assert.equal(new Set(ab.runs.map((r) => r.targetSetDigest)).size, 1);
    assert.equal(new Set(ab.runs.map((r) => JSON.stringify(r.budget))).size, 1);
    assert.deepEqual(ab.runs.map((r) => r.config.layer), ABLATION_LAYERS);
  });

  test('ablations that differ in budget, target set, provider, model, settings, cache or protocol are refused', async () => {
    const { runs } = await runAblations({ ...base(), layers: ['deterministic-only', 'deep-taint'], config: {} });
    assert.equal(assertAblationComparable(runs).ok, true, 'control');
    const tweaks = {
      budget: (r) => { r.budget = { ...r.budget, perTargetTimeoutMs: 1 }; },
      targets: (r) => { r.targetSetDigest = 'sha256:' + '1'.repeat(64); },
      provider: (r) => { r.config = { ...r.config, provider: 'other' }; },
      model: (r) => { r.config = { ...r.config, model: 'other' }; },
      settings: (r) => { r.config = { ...r.config, settings: { temperature: 1 } }; },
      cache: (r) => { r.config = { ...r.config, cache: { mode: 'enabled' } }; },
      protocol: (r) => { r.protocolHash = 'sha256:' + '2'.repeat(64); },
      split: (r) => { r.split = 'all'; },
    };
    for (const [name, tweak] of Object.entries(tweaks)) {
      const copy = clone(runs);
      tweak(copy[1]);
      const c = assertAblationComparable(copy);
      assert.equal(c.ok, false, `${name} must make ablations incomparable`);
      assert.equal(c.errors[0].code, 'ABLATION_MISMATCH');
    }
    const dup = [runs[0], { ...runs[0] }];
    assert.ok(assertAblationComparable(dup).errors.some((e) => e.code === 'DUPLICATE_ID'));
  });

  test('changing the cache, provider, model, settings, seed, budget, split or a target digest changes the run identity', () => {
    const m = () => ({ protocol: P(), config: { layer: 'deep-taint', provider: 'p', model: 'm', settings: { t: 0 }, cache: { mode: 'none' }, seed: 1 }, budget: { perTargetTimeoutMs: 1000, spendCeilingUsd: 0 }, split: 'dev', replicate: 0, targetDigests: { a: 'sha256:' + 'a'.repeat(64) } });
    const id0 = runIdentity(m());
    assert.equal(runIdentity(m()), id0, 'control: identical inputs give the same identity');
    const variants = {
      cache: (x) => { x.config.cache = { mode: 'enabled' }; },
      provider: (x) => { x.config.provider = 'q'; },
      model: (x) => { x.config.model = 'n'; },
      settings: (x) => { x.config.settings = { t: 1 }; },
      seed: (x) => { x.config.seed = 2; },
      layer: (x) => { x.config.layer = 'deterministic-only'; },
      budget: (x) => { x.budget = { perTargetTimeoutMs: 999, spendCeilingUsd: 0 }; },
      spend: (x) => { x.budget = { perTargetTimeoutMs: 1000, spendCeilingUsd: 5 }; },
      split: (x) => { x.split = 'all'; },
      replicate: (x) => { x.replicate = 1; },
      targetDigest: (x) => { x.targetDigests = { a: 'sha256:' + 'b'.repeat(64) }; },
      extraTarget: (x) => { x.targetDigests = { ...x.targetDigests, b: 'sha256:' + 'c'.repeat(64) }; },
      protocol: (x) => { x.protocol = { ...x.protocol, protocolHash: 'sha256:' + '3'.repeat(64) }; },
      engine: (x) => { x.protocol = { ...x.protocol, engine: { ...x.protocol.engine, version: '9.9.9' } }; },
    };
    for (const [name, mutate] of Object.entries(variants)) {
      const x = m(); mutate(x);
      assert.notEqual(runIdentity(x), id0, `${name} must change the run identity`);
    }
    assert.equal('labels' in runIdentityMaterial(m()), false, 'labels never enter run identity: the engine never sees them');
  });

  test('a target tree that differs from the pinned digest is refused and yields a distinct run identity', async () => {
    const edited = mkTestTmp('eval-edited-');
    fs.cpSync(FIXTURES, edited, { recursive: true });
    fs.appendFileSync(path.join(edited, 'syn-cmd-py', 'pre', 'tool.py'), '# changed\n');
    const calls = [];
    const { run } = await runEvaluation(base({ resolveTarget: (t, v) => ({ dir: path.join(edited, t.id, v) }), scanFn: stubScan(GOOD, calls) }));
    const { run: pristine } = await runEvaluation(base());
    assert.notEqual(run.runId, pristine.runId);
    assert.notEqual(run.targetSetDigest, pristine.targetSetDigest);
    const refused = run.outcomes.filter((o) => o.targetId === 'syn-cmd-py');
    assert.ok(refused.every((o) => o.status === 'unavailable' && /target-digest-mismatch/.test(o.failureReason)));
    assert.equal(calls.some((c) => c.dir.includes('syn-cmd-py')), false, 'a tree that is not the pinned one is never scanned');
    assert.equal(digestTree(path.join(FIXTURES, 'syn-cmd-py', 'pre')) === digestTree(path.join(edited, 'syn-cmd-py', 'pre')), false);
  });

  test('the outcome cache is keyed by every relevant input: a changed model or settings misses, an identical rerun hits', async () => {
    const cache = new Map(); const calls = [];
    const cfg = (over = {}) => ({ layer: 'deep-taint', provider: 'p', model: 'm', settings: {}, cache: { mode: 'enabled' }, ...over });
    const go = (c) => runEvaluation(base({ config: c, cache, scanFn: stubScan(GOOD, calls) }));
    const first = await go(cfg()); const n1 = calls.length;
    const again = await go(cfg());
    assert.equal(calls.length, n1, 'identical inputs hit the cache');
    assert.ok(again.run.outcomes.every((o) => o.cached === true));
    assert.equal(again.run.rawHash, first.run.rawHash);
    await go(cfg({ model: 'm2' })); const n2 = calls.length;
    assert.ok(n2 > n1, 'a different model must miss');
    await go(cfg({ settings: { temperature: 0.7 } }));
    assert.ok(calls.length > n2, 'different settings must miss');
    const off = new Map();
    await runEvaluation(base({ config: cfg({ cache: { mode: 'none' } }), cache: off, scanFn: stubScan(GOOD) }));
    assert.equal(off.size, 0, 'cache mode none never stores');
  });
});

describe('[QA-003.AC03] failures on known positives are end-to-end misses; conditional metrics are separate; unknown labels stay unscored', () => {
  const run = (scanFn) => runEvaluation(base({ scanFn })).then((r) => r.run);

  test('a timeout or an error on a known positive is a MISS in the end-to-end metrics, not an exclusion', async () => {
    const healthy = score(await run(stubScan(GOOD)));
    assert.equal(healthy.endToEnd.micro.tp, 2);
    assert.equal(healthy.endToEnd.micro.recall, 1);
    for (const failure of [timeoutError(), new Error('boom')]) {
      const s = score(await run(stubScan({ ...GOOD, 'syn-sqli-js-pre': failure })));
      assert.equal(s.endToEnd.micro.tp, 1);
      assert.equal(s.endToEnd.micro.fn, 1, 'the positive behind the failure is a false negative');
      assert.equal(s.endToEnd.micro.recall, 0.5);
      assert.deepEqual(s.misses.map((m) => m.reason), [failure.code === 'TIMEOUT' ? 'timeout' : 'error']);
      assert.ok(s.completion.rate < 1);
    }
  });

  test('conditional-on-completion metrics are reported separately and labelled; they never replace the end-to-end ones', async () => {
    const s = score(await run(stubScan({ ...GOOD, 'syn-sqli-js-pre': timeoutError() })));
    assert.equal(s.conditional.micro.fn, 0, 'conditional excludes the case that did not complete');
    assert.equal(s.conditional.micro.recall, 1);
    assert.ok(s.endToEnd.micro.recall < s.conditional.micro.recall, 'the failure only shows in the end-to-end figure');
    assert.match(s.endToEnd.label, /end-to-end/);
    assert.match(s.conditional.label, /conditional on completion/);
    assert.notDeepEqual(s.endToEnd.micro, s.conditional.micro);
  });

  test('quarantined and unavailable positives are misses too (nothing leaves the denominator)', async () => {
    const r = await runEvaluation(base({ resolveTarget: (t, v) => (t.id === 'syn-sqli-js' ? { unavailable: 'fetch failed' } : resolver()(t, v)) }));
    const s = score(r.run);
    assert.equal(s.endToEnd.micro.fn, 1);
    assert.equal(s.misses[0].reason, 'unavailable');
    assert.equal(s.negativeFailures.length, 1, 'a failed negative is disclosed, counted as neither a TN nor a FP');
    assert.equal(s.endToEnd.byLanguage.javascript.tn, 0);
  });

  test('results without an adjudicated label stay unscored, with counts and reasons', async () => {
    const r = await run(stubScan({ ...GOOD, 'syn-sqli-js-pre': [SYN_FINDING(), SYN_FINDING({ id: 'x', line: 2, family: 'xss', cwe: 'CWE-79' })] }));
    const noLabels = scoreRun({ run: r, protocol: P(), defects: [], negatives: [] });
    assert.deepEqual(noLabels.unscored.unlabeledTargets.map((t) => t.reason), ['unlabeled-target', 'unlabeled-target']);
    assert.equal(noLabels.endToEnd.micro.tp + noLabels.endToEnd.micro.fn + noLabels.endToEnd.micro.fp + noLabels.endToEnd.micro.tn, 0);
    assert.ok(noLabels.unscored.unlabeledFindings.count >= 3);
    const candidate = clone(suite().defects[0]); candidate.adjudication = { status: 'candidate', reviewers: [] };
    const withCandidate = scoreRun({ run: r, protocol: P(), defects: [candidate], negatives: [] });
    assert.equal(withCandidate.unscored.nonAdjudicatedLabels, 1, 'a candidate label is counted as unscored, not scored');
    assert.equal(withCandidate.endToEnd.micro.tp, 0);
  });

  test('the same finding is not double counted, and a finding matching two reviewed defects is a TP for each', async () => {
    const dup = await run(stubScan({ ...GOOD, 'syn-sqli-js-pre': [SYN_FINDING(), SYN_FINDING({ id: 'dup' })] }));
    const s = score(dup);
    assert.equal(s.endToEnd.micro.tp, 2, 'two findings at one reviewed defect are still one TP for it');
  });

  test('a REAL engine timeout kills the scan process tree and is reported as a timeout', async () => {
    const dir = mkTestTmp('eval-timeout-');
    fs.cpSync(path.join(FIXTURES, 'syn-sqli-js', 'pre'), dir, { recursive: true });
    const t0 = Date.now();
    await assert.rejects(defaultScanFn(dir, { layer: 'deep-taint', timeoutMs: 1, env: { PATH: process.env.PATH } }), (e) => e.code === 'TIMEOUT');
    assert.ok(Date.now() - t0 < 5000, 'the deadline fires promptly');
    const bad = await runEvaluation({ ...base(), config: { layer: 'deep-taint' }, scanFn: (d, o) => defaultScanFn(d, { ...o, timeoutMs: 1 }) });
    assert.equal(bad.run.totals.timeout, 4);
    const s = score(bad.run);
    assert.equal(s.endToEnd.micro.recall, 0);
    assert.equal(s.completion.rate, 0);
  });

  test('the real-engine ablation exposes a layer difference that the matching policy (not the layer) explains', async () => {
    const ab = await runAblations({ protocol: P(), config: {}, resolveTarget: resolver(), split: 'dev' });
    const [det, deep] = ab.runs.map(score);
    assert.equal(ab.runs[0].totals.completed, 4);
    assert.equal(det.endToEnd.micro.tp, 0, 'pattern findings carry no line, and a finding with no line cannot be localised');
    assert.equal(deep.endToEnd.micro.tp, 2, 'deep taint reports the line');
    assert.ok(deep.endToEnd.micro.f1 > det.endToEnd.micro.f1);
  });
});
