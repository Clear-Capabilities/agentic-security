// X-601: routing task kinds and strata, truth-label provenance, and outcome records that keep everything.
// All populations are SYNTHETIC (test/helpers/routing-fixtures.js): no model was called and nobody adjudicated anything.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRoutingTask, validateRoutingTask, ROUTING_TASK_KINDS, CONTEXT_BUCKETS, contextBucketOf, stratumParents, deriveRoutingLabel,
  buildRoutingOutcome, validateRoutingOutcome, createOutcomeLedger, NON_TRUTH_SIGNALS, OUTCOME_STATUSES,
} from '../../src/posture/routing/outcomes.js';
import { validateRoutingLabel } from '../../src/posture/assurance/contracts.js';
import { taskOf, outcomeOf, ADJUDICATION } from '../helpers/routing-fixtures.js';

describe('[X-601.AC01] routing records separate the four task kinds and carry language, class, context size and required capabilities', () => {
  test('all four kinds build, and each lands in a different stratum', () => {
    assert.deepEqual([...ROUTING_TASK_KINDS], ['discovery', 'triage', 'verification-planning', 'repair']);
    const strata = ROUTING_TASK_KINDS.map((k) => taskOf(1, { taskKind: k }).stratum);
    assert.equal(new Set(strata).size, 4);
    for (const k of ROUTING_TASK_KINDS) assert.ok(taskOf(1, { taskKind: k }).stratum.startsWith(`${k}|`));
  });

  test('the record carries language, vulnerability class, context size and bucket, and sorted required capabilities', () => {
    const t = taskOf(7, { language: 'Python', vulnClass: 'CWE-78', contextTokens: 50_000, requiredCapabilities: ['tool-use', 'code-edit', 'tool-use'] });
    assert.equal(t.language, 'python');
    assert.equal(t.vulnClass, 'CWE-78');
    assert.equal(t.contextTokens, 50_000);
    assert.equal(t.contextBucket, 'm');
    assert.deepEqual(t.requiredCapabilities, ['code-edit', 'tool-use']);
    assert.equal(t.stratum, 'repair|python|CWE-78|m');
  });

  test('context buckets are ordered and a bucket change changes the stratum', () => {
    assert.deepEqual(CONTEXT_BUCKETS.map((b) => b.id), ['xs', 's', 'm', 'l', 'xl']);
    assert.equal(contextBucketOf(4000), 'xs'); assert.equal(contextBucketOf(4001), 's'); assert.equal(contextBucketOf(10_000_000), 'xl');
    assert.notEqual(taskOf(1, { contextTokens: 100 }).stratum, taskOf(1, { contextTokens: 100_000 }).stratum);
  });

  test('capability order does not change the identity; a different capability set does', () => {
    const a = taskOf(1, { requiredCapabilities: ['tool-use', 'code-edit'] });
    const b = taskOf(1, { requiredCapabilities: ['code-edit', 'tool-use'] });
    assert.equal(a.id, b.id);
    assert.notEqual(a.id, taskOf(1, { requiredCapabilities: ['tool-use'] }).id);
  });

  test('a record that omits or corrupts any of the four required facts is rejected, never half-built', () => {
    const base = { taskId: 't', taskKind: 'triage', language: 'go', vulnClass: 'CWE-22', contextTokens: 10, requiredCapabilities: [] };
    for (const bad of [{ taskKind: 'summarise' }, { language: '' }, { vulnClass: 'sql injection!' }, { contextTokens: -1 }, { contextTokens: 1.5 }, { requiredCapabilities: ['telepathy'] }, { requiredCapabilities: 'tool-use' }, { dataClass: 'secret-sauce' }]) {
      const r = buildRoutingTask({ ...base, ...bad });
      assert.equal(r.ok, false, JSON.stringify(bad));
      assert.equal(r.task, null);
    }
    assert.equal(buildRoutingTask(base).ok, true);
    const t = { ...taskOf(1) };
    delete t.language;
    assert.equal(validateRoutingTask(t).ok, false);
    assert.equal(validateRoutingTask({ ...taskOf(1), extra: 1 }).ok, false);
  });

  test('parent strata run from fine to coarse', () => {
    assert.deepEqual(stratumParents('repair|go|CWE-22|s'), ['repair|go|CWE-22', 'repair|go', 'repair']);
  });
});

describe('[X-601.AC02] labels come only from independent adjudication or trusted execution; signals are not truth', () => {
  const task = taskOf(1);

  test('independent adjudication by a human or verifier service yields a valid decided label', () => {
    for (const reviewerKind of ['human', 'verifier-service']) {
      const d = deriveRoutingLabel({ task, model: 'model-a', outcome: 'correct', evidence: { ...ADJUDICATION(), reviewerKind } });
      assert.equal(d.accepted, true);
      assert.equal(d.label.labelSource, 'adjudication');
      assert.equal(validateRoutingLabel(d.label).ok, true);
      assert.equal(d.adjudicationVersion, 'synthetic-protocol-1');
    }
  });

  test('trusted execution needs the verification record it came from', () => {
    const ok = deriveRoutingLabel({ task, model: 'model-a', outcome: 'incorrect', evidence: { kind: 'trusted-execution', verificationRecordId: 'vrec:0123456789abcdef' } });
    assert.equal(ok.accepted, true);
    assert.equal(ok.label.labelSource, 'trusted-execution');
    assert.equal(ok.label.verificationRecordId, 'vrec:0123456789abcdef');
    assert.equal(validateRoutingLabel(ok.label).ok, true);
    for (const bad of [{ kind: 'trusted-execution' }, { kind: 'trusted-execution', verificationRecordId: 'not-a-record' }]) {
      const r = deriveRoutingLabel({ task, model: 'model-a', outcome: 'correct', evidence: bad });
      assert.equal(r.accepted, false);
      assert.equal(r.code, 'MISSING_PROVENANCE');
    }
  });

  test('provider agreement, self-reported confidence and accepted suggestions are refused and the outcome becomes unknown', () => {
    for (const kind of ['provider-agreement', 'self-reported-confidence', 'accepted-suggestion', 'model-judgement', 'majority-vote']) {
      assert.ok(NON_TRUTH_SIGNALS.includes(kind));
      const r = deriveRoutingLabel({ task, model: 'model-a', outcome: 'correct', evidence: { ...ADJUDICATION(), verificationRecordId: 'vrec:0123456789abcdef', kind } });
      assert.equal(r.accepted, false, kind);
      assert.equal(r.code, 'NOT_A_TRUTH_LABEL');
      assert.equal(r.downgradedTo, 'unknown');
      assert.equal(r.label.outcome, 'unknown');
      assert.equal(r.label.labelSource, 'none');
    }
  });

  test('no evidence, an unknown evidence kind, and a decided outcome without a source are all refused', () => {
    assert.equal(deriveRoutingLabel({ task, model: 'm', outcome: 'correct' }).accepted, false);
    assert.equal(deriveRoutingLabel({ task, model: 'm', outcome: 'correct', evidence: { kind: 'vibes' } }).accepted, false);
    // the label contract itself still rejects a decided label with no source
    const forged = { ...deriveRoutingLabel({ task, model: 'm', outcome: 'unknown' }).label, outcome: 'correct' };
    assert.equal(validateRoutingLabel(forged).ok, false);
  });

  test('a reviewer that is the model under test or its provider is not independent', () => {
    for (const reviewerId of ['model-a', 'provider-a']) {
      const r = deriveRoutingLabel({ task, model: 'model-a', provider: 'provider-a', outcome: 'correct', evidence: { ...ADJUDICATION(), reviewerId } });
      assert.equal(r.accepted, false);
      assert.equal(r.code, 'NOT_INDEPENDENT');
    }
    assert.equal(deriveRoutingLabel({ task, model: 'model-a', outcome: 'correct', evidence: { ...ADJUDICATION(), reviewerKind: 'model' } }).code, 'NOT_INDEPENDENT');
    assert.equal(deriveRoutingLabel({ task, model: 'model-a', outcome: 'correct', evidence: { ...ADJUDICATION(), adjudicationVersion: '' } }).code, 'MISSING_PROVENANCE');
  });

  test('a decided outcome record cannot be built without a cited label', () => {
    const r = buildRoutingOutcome({ runId: 'r', task, model: 'm', status: 'completed', outcome: 'correct', label: null });
    assert.equal(r.ok, false);
  });
});

describe('[X-601.AC03] outcomes keep unknown and delayed results, actual usage, cost, latency, cache state and version, and drop nothing', () => {
  test('an outcome records tokens, cost, latency, cache state and model version', () => {
    const o = outcomeOf({ task: taskOf(1), model: 'model-a', version: '2026-05', costUsd: 0.0123, latencyMs: 912 });
    assert.equal(o.modelVersion, '2026-05');
    assert.equal(o.usage.inputTokens, 3000); assert.equal(o.usage.outputTokens, 400);
    assert.equal(o.costUsd, 0.0123); assert.equal(o.latencyMs, 912);
    assert.ok(['hit', 'partial', 'miss', 'ineligible', 'unknown'].includes(o.cacheState));
    assert.equal(validateRoutingOutcome(o).ok, true);
  });

  test('unknown and delayed outcomes are valid records, and an unknown count must be null, never 0', () => {
    const delayed = outcomeOf({ task: taskOf(1), model: 'm', correct: null, delayed: true });
    const unknown = outcomeOf({ task: taskOf(2), model: 'm', correct: null });
    assert.equal(delayed.outcome, 'delayed'); assert.equal(unknown.outcome, 'unknown');
    assert.equal(delayed.labelSource, 'none');
    const r = buildRoutingOutcome({ runId: 'r', task: taskOf(3), model: 'm', status: 'failed', usage: {}, outcome: 'unknown' });
    assert.equal(r.ok, true);
    assert.equal(r.outcome.usage.inputTokens, null);
    assert.equal(r.outcome.usage.cachedInputTokens, null);
    assert.equal(r.outcome.costUsd, null);
    assert.equal(r.outcome.costStatus, 'unknown');
    assert.equal(validateRoutingOutcome({ ...r.outcome, usage: { ...r.outcome.usage, inputTokens: -1 } }).ok, false);
    assert.equal(validateRoutingOutcome({ ...r.outcome, costStatus: 'measured' }).ok, false, 'a measured cost needs a value');
  });

  test('the ledger keeps every status, including failures, and its summary counts them all', () => {
    const ledger = createOutcomeLedger();
    let i = 0;
    for (const status of OUTCOME_STATUSES) {
      const r = buildRoutingOutcome({ runId: `r${i}`, task: taskOf(i++), model: 'm', status, outcome: 'unknown' });
      assert.equal(ledger.add(r.outcome).ok, true, status);
    }
    ledger.add(outcomeOf({ task: taskOf(50), model: 'm', correct: true }));
    ledger.add(outcomeOf({ task: taskOf(51), model: 'm', correct: null, delayed: true, runId: 'r-late' }));
    const s = ledger.summary();
    assert.equal(s.total, OUTCOME_STATUSES.length + 2);
    for (const status of OUTCOME_STATUSES) assert.ok(s.byStatus[status] >= 1, `${status} is counted`);
    assert.equal(s.failures, 5);
    assert.equal(s.byOutcome.delayed, 1); assert.equal(s.byOutcome.correct, 1);
    assert.equal(s.labelled, 1); assert.equal(s.unlabelled, OUTCOME_STATUSES.length + 1);
  });

  test('the ledger has no way to remove or overwrite a record, and rejections are retained with a reason', () => {
    const ledger = createOutcomeLedger();
    assert.deepEqual(Object.keys(ledger).sort(), ['add', 'all', 'rejected', 'summary']);
    const o = outcomeOf({ task: taskOf(1), model: 'm', correct: true });
    assert.equal(ledger.add(o).ok, true);
    assert.equal(ledger.add(o).code, 'DUPLICATE_ID');
    assert.equal(ledger.add({ ...o, status: 'imaginary' }).code, 'INVALID');
    assert.equal(ledger.all().length, 1);
    assert.deepEqual(ledger.rejected().map((r) => r.reason).sort(), ['duplicate', 'invalid']);
    assert.equal(ledger.summary().rejectedAtIntake, 2);
  });
});
