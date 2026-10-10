// QA-001: the frozen evaluation protocol. SYNTHETIC data only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  freezeProtocol, validateProtocol, diffProtocols, amendProtocol, deriveSuccessorProtocol, assertBoundToProtocol,
  PREREGISTERED_THRESHOLDS, protocolHashOf,
} from '../../src/posture/evaluation/protocol.js';
import { runEvaluation } from '../../src/posture/evaluation/runner.js';
import { scoreRun } from '../../src/posture/evaluation/score.js';
import { suite, resolver, clone, stubScan, SYN_FINDING } from '../helpers/evaluation-suite.js';

const codes = (r) => r.errors.map((e) => e.code);
const paths = (r) => r.errors.map((e) => e.path);

function freezeWith(mutate) {
  const d = clone(suite().draft);
  mutate(d);
  return freezeProtocol(d);
}

describe('[QA-001.AC01] a protocol manifest pins every input and is immutable', () => {
  test('the synthetic draft freezes, validates, and its hash is stable', () => {
    const { protocol } = suite();
    assert.ok(protocol, JSON.stringify(suite().freezeErrors));
    assert.equal(validateProtocol(protocol).ok, true);
    assert.equal(protocol.protocolHash, protocolHashOf(protocol));
    assert.equal(protocol.synthetic, true);
    assert.equal(freezeProtocol(clone(suite().draft)).protocol.protocolHash, protocol.protocolHash);
  });

  test('a frozen protocol cannot be mutated in place', () => {
    const { protocol } = suite();
    assert.throws(() => { protocol.thresholds.overallMicroF1 = 0.1; }, TypeError);
    assert.throws(() => { protocol.targets.push({}); }, TypeError);
    assert.throws(() => { protocol.splits.dev.push('x'); }, TypeError);
  });

  test('content edited after freezing fails the hash check (both directions)', () => {
    const edited = clone(suite().protocol);
    assert.equal(validateProtocol(edited).ok, true, 'an untouched copy is valid');
    edited.thresholds.overallMicroF1 = 0.5;
    const v = validateProtocol(edited);
    assert.equal(v.ok, false);
    assert.ok(codes(v).includes('HASH_MISMATCH') || codes(v).includes('RULE_VIOLATION'));
    const moved = clone(suite().protocol);
    moved.splits.dev = [...moved.splits.dev, ...moved.splits.sealed]; moved.splits.sealed = [];
    assert.equal(validateProtocol(moved).ok, false, 'moving a target between splits is a change');
  });

  test('each pinned input is required: version, bundle digest, clean tree, licences, commits, scope, matching, limits', () => {
    const cases = [
      ['engine version', (d) => { delete d.engine.version; }, 'engine.version'],
      ['bundle digest', (d) => { d.engine.bundleDigest = 'not-a-digest'; }, 'engine.bundleDigest'],
      ['measurement commit', (d) => { d.measurement.commit = 'abc'; }, 'measurement.commit'],
      ['clean tree', (d) => { d.measurement.cleanTree = false; }, 'measurement.cleanTree'],
      ['tool versions', (d) => { d.tools = {}; }, 'tools'],
      ['model version', (d) => { d.models = [{ provider: 'p', model: 'm' }]; }, 'models[0]'],
      ['dataset licences', (d) => { d.datasetLicenses = {}; }, 'datasetLicenses'],
      ['target licence declared', (d) => { d.targets[0].license = 'undeclared'; }, 'targets[0].license'],
      ['pre commit', (d) => { d.targets[0].preCommit = 'zzz'; }, 'targets[0].preCommit'],
      ['post commit', (d) => { d.targets[0].postCommit = 'zzz'; }, 'targets[0].postCommit'],
      ['target digest', (d) => { d.targets[0].digest = 'sha256:short'; }, 'targets[0].digest'],
      ['declared scope', (d) => { d.scope = { languages: [], families: [] }; }, 'scope'],
      ['scope covers target language', (d) => { d.scope.languages = ['rust']; }, 'targets[0].language'],
      ['limits', (d) => { d.limits.perTargetTimeoutMs = -1; }, 'limits.perTargetTimeoutMs'],
      ['cwe alone never sufficient', (d) => { d.matching.cweAloneSufficient = true; }, 'matching.cweAloneSufficient'],
    ];
    for (const [name, mutate, path] of cases) {
      const r = freezeWith(mutate);
      assert.equal(r.ok, false, `${name} must be required`);
      assert.ok(paths(r).includes(path), `${name}: expected an error at ${path}, got ${paths(r).join(', ')}`);
    }
  });

  test('thresholds may be stricter than the preregistered floor, never looser or missing', () => {
    assert.equal(freezeWith((d) => { d.thresholds.overallMicroF1 = 0.85; }).ok, true);
    const loose = freezeWith((d) => { d.thresholds.pooledPrecision = 0.5; });
    assert.equal(loose.ok, false);
    assert.ok(paths(loose).includes('thresholds.pooledPrecision'));
    const missing = freezeWith((d) => { delete d.thresholds.minPositivesPerCoreLanguage; });
    assert.equal(missing.ok, false);
    assert.ok(codes(missing).includes('MISSING_FIELD'));
    const smaller = freezeWith((d) => { d.thresholds.minPositivesPerCoreLanguage = 3; });
    assert.equal(smaller.ok, false, 'a tiny curated minimum must not replace the registered one');
    assert.equal(PREREGISTERED_THRESHOLDS.minPositivesPerCoreLanguage, 100);
  });
});

describe('[QA-001.AC02] related samples cannot straddle the development/sealed line', () => {
  test('a protocol whose split separates a vulnerable/fixed pair or an upstream is refused', () => {
    const forkOfFirst = freezeWith((d) => {
      const extra = clone(d.targets[0]);
      extra.id = 'syn-sqli-js-fork'; extra.forkOf = d.targets[0].upstream; extra.upstream = 'example.invalid/synthetic/fork'; extra.pairId = 'pair-fork';
      extra.preCommit = '9'.repeat(40); extra.postCommit = '8'.repeat(40);
      d.targets.push(extra);
      d.splits.sealed.push(extra.id); // related to a dev target
    });
    assert.equal(forkOfFirst.ok, false);
    assert.match(forkOfFirst.errors.map((e) => e.message).join(' '), /straddle/);
    const sameSide = freezeWith((d) => {
      const extra = clone(d.targets[0]);
      extra.id = 'syn-sqli-js-fork'; extra.forkOf = d.targets[0].upstream; extra.upstream = 'example.invalid/synthetic/fork'; extra.pairId = 'pair-fork';
      extra.preCommit = '9'.repeat(40); extra.postCommit = '8'.repeat(40);
      d.targets.push(extra);
      d.splits.dev.push(extra.id);
    });
    assert.equal(sameSide.ok, true, 'the same relation on one side is fine');
  });

  test('a target in both splits, in neither, or unknown is refused', () => {
    assert.equal(freezeWith((d) => { d.splits.sealed.push(d.splits.dev[0]); }).ok, false);
    assert.equal(freezeWith((d) => { d.splits.dev = d.splits.dev.slice(1); }).ok, false);
    assert.equal(freezeWith((d) => { d.splits.dev.push('ghost'); }).ok, false);
  });
});

describe('[QA-001.AC03] protocol and population changes are versioned, invalidate comparability, and cannot shrink the denominator', () => {
  const base = () => suite().protocol;

  test('an amendment before any result is a new version with a diff, and is comparable with nothing earlier', () => {
    const r = amendProtocol(base(), { limits: { ...base().limits, perTargetTimeoutMs: 60000 } }, { reason: 'shorten the per-target ceiling before any run' });
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    assert.equal(r.protocol.protocolVersion, 2);
    assert.equal(r.protocol.supersedes, base().protocolHash);
    assert.notEqual(r.protocol.protocolHash, base().protocolHash);
    assert.deepEqual(r.protocol.comparability.comparableWith, []);
    assert.deepEqual(r.protocol.comparability.invalidates, [base().protocolHash]);
    assert.ok(r.diff.changes.some((c) => c.path === 'limits.perTargetTimeoutMs'));
    assert.equal(diffProtocols(base(), base()).identical, true);
  });

  test('an amendment must state a reason and may only touch measurement-defining fields', () => {
    assert.equal(amendProtocol(base(), { limits: base().limits }).ok, false);
    assert.equal(amendProtocol(base(), { protocolHash: 'x' }, { reason: 'r' }).ok, false);
  });

  test('a threshold, matching rule or denominator change AFTER a result exists is rejected (POST_RESULT_CHANGE)', async () => {
    const stub = stubScan({ 'syn-sqli-js': [SYN_FINDING()] });
    const { run } = await runEvaluation({ protocol: base(), config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: stub });
    assert.ok(run);
    for (const patch of [
      { thresholds: { ...base().thresholds, overallMicroF1: 0.5 } },
      { matching: { ...base().matching, lineWindow: 50 } },
      { targets: base().targets.slice(0, 1) },
    ]) {
      const r = amendProtocol(base(), patch, { reason: 'looks better now', observedResults: [run] });
      assert.equal(r.ok, false);
      assert.equal(r.errors[0].code, 'POST_RESULT_CHANGE');
    }
    // The control: the very same amendment is fine while no result is bound to it.
    assert.equal(amendProtocol(base(), { thresholds: { ...base().thresholds, overallMicroF1: 0.9 } }, { reason: 'stricter, pre-result' }).ok, true);
    // A result bound to some OTHER protocol does not block it.
    assert.equal(amendProtocol(base(), { thresholds: { ...base().thresholds, overallMicroF1: 0.9 } }, { reason: 'stricter', observedResults: [{ protocolHash: 'sha256:' + '0'.repeat(64) }] }).ok, true);
  });

  test('results and runs bound to an old protocol are rejected under the amended one', async () => {
    const stub = stubScan({});
    const { run } = await runEvaluation({ protocol: base(), config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: stub });
    assert.equal(assertBoundToProtocol(run, base()).ok, true);
    const next = amendProtocol(base(), { limits: { ...base().limits, replicates: 5 } }, { reason: 'more replicates' }).protocol;
    const bad = assertBoundToProtocol(run, next);
    assert.equal(bad.ok, false);
    assert.equal(bad.errors[0].code, 'PROTOCOL_MISMATCH');
    // and the engine refuses to score a run against a protocol it was not produced under
    const edited = clone(next); edited.thresholds.overallMicroF1 = 0.01;
    assert.equal(assertBoundToProtocol(run, edited).ok, false);
  });

  test('a removed target is retired with a reason and stays in the original denominator; silent removal is refused', () => {
    const r = amendProtocol(base(), { targets: base().targets.filter((t) => t.id !== 'syn-nearmiss-js'), splits: { dev: base().splits.dev, sealed: [] } }, { reason: 'unlicensed upstream withdrawn' });
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    assert.ok(r.protocol.originalTargetIds.includes('syn-nearmiss-js'));
    assert.equal(r.protocol.retired.find((x) => x.id === 'syn-nearmiss-js').retiredInVersion, 2);
    // Hand-built protocol that just drops the target from `targets` while keeping it in the original list.
    const silent = freezeWith((d) => { d.originalTargetIds = d.targets.map((t) => t.id); d.targets = d.targets.slice(0, 2); d.splits.sealed = []; });
    assert.equal(silent.ok, false);
    assert.match(silent.errors.map((e) => e.message).join(' '), /without a disclosed retirement/);
  });

  test('unavailable targets stay in the run denominator and are scored as misses, not dropped', async () => {
    const unavailable = (t, variant) => (t.id === 'syn-cmd-py' ? { unavailable: 'upstream withdrawn' } : resolver()(t, variant));
    const { run } = await runEvaluation({ protocol: base(), config: { layer: 'deep-taint' }, resolveTarget: unavailable, scanFn: stubScan({ 'syn-sqli-js': [SYN_FINDING()] }), split: 'dev' });
    const un = run.outcomes.filter((o) => o.status === 'unavailable');
    assert.deepEqual(un.map((o) => o.targetId), ['syn-cmd-py', 'syn-cmd-py']);
    assert.equal(run.outcomes.length, 4, 'both variants of both dev targets are present');
    const score = scoreRun({ run, protocol: base(), defects: suite().defects, negatives: suite().negatives });
    assert.ok(score.misses.some((m) => m.targetId === 'syn-cmd-py' && m.reason === 'unavailable'));
    assert.equal(score.endToEnd.micro.fn, 1);
  });

  test('a successor protocol cannot reuse a sealed target a result already consumed', async () => {
    const stub = stubScan({});
    const { run } = await runEvaluation({ protocol: base(), config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: stub, split: 'all', allowSealed: true });
    assert.deepEqual(run.sealedTargetIds, ['syn-nearmiss-js']);
    const reuse = deriveSuccessorProtocol(base(), clone(suite().draft), { observedResults: [run] });
    assert.equal(reuse.ok, false);
    assert.equal(reuse.errors[0].code, 'SEALED_REUSE');
    const fresh = clone(suite().draft);
    const extra = clone(fresh.targets[2]); extra.id = 'syn-nearmiss-2'; extra.upstream = 'example.invalid/synthetic/nearmiss-2'; extra.pairId = 'pair-nm2'; extra.preCommit = '7'.repeat(40);
    fresh.targets = [fresh.targets[0], fresh.targets[1], extra];
    fresh.originalTargetIds = fresh.targets.map((t) => t.id);
    fresh.splits = { dev: [fresh.targets[0].id, fresh.targets[1].id].sort(), sealed: ['syn-nearmiss-2'] };
    const ok = deriveSuccessorProtocol(base(), fresh, { observedResults: [run] });
    assert.equal(ok.ok, true, JSON.stringify(ok.errors));
    assert.equal(ok.protocol.supersedes, base().protocolHash);
    assert.deepEqual(ok.protocol.comparability.comparableWith, []);
  });
});
