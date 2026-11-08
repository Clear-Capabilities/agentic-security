// Threat-model PRD FR-09.2 and AC-09A: synthetic scorer tests. Every enrolled label is reconciled to one status and the original
// denominator survives duplicates, a localization mismatch, findings no label accounts for, skipped or failed inputs and an incomplete
// population. Before this, a negative label whose target the run never reached left the count without a trace. SYNTHETIC data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreRun } from '../../src/posture/evaluation/score.js';
import { suite, clone, SYN_FINDING } from '../helpers/evaluation-suite.js';

const CMD = SYN_FINDING({ id: 'c1', file: 'tool.py', line: 11, family: 'command-injection', cwe: 'CWE-78' });
const out = (targetId, variant, findings = [], status = 'completed', failureReason = null) => ({ targetId, variant, status, findings, failureReason });
const runOf = (outcomes) => ({ runId: 'run-syn', protocolHash: suite().protocol.protocolHash, split: 'dev', outcomes, totals: { outcomes: outcomes.length } });
const FULL = () => [out('syn-sqli-js', 'pre', [SYN_FINDING()]), out('syn-sqli-js', 'post'), out('syn-cmd-py', 'pre', [CMD]), out('syn-cmd-py', 'post'), out('syn-nearmiss-js', 'pre')];
const score = (outcomes, labels = {}) => scoreRun({ run: runOf(outcomes), protocol: suite().protocol, defects: labels.defects ?? suite().defects, negatives: labels.negatives ?? suite().negatives });
const statusOf = (s, id) => s.reconciliation.cases.filter((c) => c.labelId === id).map((c) => c.status);

test('a complete run reconciles every enrolled label to exactly one status', () => {
  const s = score(FULL());
  assert.equal(s.reconciliation.enrolled, suite().defects.length + suite().negatives.length);
  assert.equal(s.reconciliation.reconciled, true);
  assert.deepEqual(s.reconciliation.byStatus, { 'negative:tn': 3, 'positive:tp': 2 });
  assert.equal(s.endToEnd.micro.f1, 1);
});

test('incomplete population: a negative the run never reached is counted as outside-run, never silently dropped', () => {
  const s = score(FULL().filter((o) => o.targetId !== 'syn-nearmiss-js' && o.targetId !== 'syn-cmd-py'));
  assert.equal(s.reconciliation.reconciled, true, 'the statuses still add up to the enrolled count');
  assert.equal(s.unscored.positivesOutsideRun, 1);
  assert.equal(s.unscored.negativesOutsideRun, 2, 'both unreached negatives are disclosed');
  assert.equal(s.reconciliation.byStatus['negative:outside-run'], 2);
  assert.equal(s.reconciliation.byStatus['positive:outside-run'], 1);
});

test('skipped or failed inputs: a positive behind a timeout is a miss with its reason, and a failed negative is neither tn nor fp', () => {
  const outcomes = FULL().map((o) => (o.targetId === 'syn-sqli-js' ? { ...o, status: 'timeout', findings: [], failureReason: 'no result within budget' } : o));
  const s = score(outcomes);
  const [pos] = suite().defects; const neg = suite().negatives.find((n) => n.targetId === 'syn-sqli-js');
  assert.deepEqual(statusOf(s, pos.id), ['fn']);
  assert.equal(s.reconciliation.cases.find((c) => c.labelId === pos.id).reason, 'timeout');
  assert.deepEqual(statusOf(s, neg.id), ['scan-failed']);
  assert.equal(s.endToEnd.micro.fn, 1, 'the miss stays in the end-to-end denominator');
  assert.equal(s.conditional.micro.fn, 0, 'only the conditional figures leave it out, and they are labelled as such');
  assert.ok(s.completion.rate < 1);
  assert.equal(s.reconciliation.reconciled, true);
});

test('localization mismatch: a finding at the wrong line misses the defect and goes to review, not to the false positives', () => {
  const outcomes = FULL().map((o) => (o.targetId === 'syn-sqli-js' && o.variant === 'pre' ? { ...o, findings: [SYN_FINDING({ line: 40 })] } : o));
  const s = score(outcomes);
  assert.deepEqual(statusOf(s, suite().defects[0].id), ['fn']);
  assert.equal(s.reconciliation.cases.find((c) => c.labelId === suite().defects[0].id).reason, 'not-detected');
  assert.equal(s.falsePositives.length, 0);
  assert.ok(s.reviewQueue.length >= 1, 'the unlocalized finding is queued for review');
});

test('unmatched findings: a finding no adjudicated label accounts for is unscored and queued, never an automatic false positive', () => {
  const outcomes = FULL().map((o) => (o.targetId === 'syn-cmd-py' && o.variant === 'pre' ? { ...o, findings: [CMD, SYN_FINDING({ id: 'x', file: 'other.py', line: 3, family: 'xss', cwe: 'CWE-79' })] } : o));
  const s = score(outcomes);
  assert.equal(s.unscored.unlabeledFindings.count, 1);
  assert.equal(s.endToEnd.micro.fp, 0);
  assert.deepEqual(s.reconciliation.byStatus, { 'negative:tn': 3, 'positive:tp': 2 }, 'the labels reconcile as before');
});

test('duplicates: repeated alerts count once per root cause, and a duplicated label is reconciled per enrolment, not merged away', () => {
  const outcomes = FULL().map((o) => (o.targetId === 'syn-sqli-js' && o.variant === 'post' ? { ...o, findings: [SYN_FINDING({ id: 'a' }), SYN_FINDING({ id: 'b', line: 9 })] } : o));
  const s = score(outcomes);
  assert.equal(s.falsePositives.length, 1, 'two alerts at one flaw are one false positive');
  assert.equal(s.falsePositives[0].alertsCollapsed, 2);
  const neg = suite().negatives.find((n) => n.targetId === 'syn-sqli-js');
  assert.deepEqual(statusOf(s, neg.id), ['fp']);
  const twice = score(FULL(), { defects: [...suite().defects, clone(suite().defects[0])] });
  assert.equal(twice.reconciliation.enrolled, 6);
  assert.equal(twice.reconciliation.reconciled, true);
  assert.deepEqual(statusOf(twice, suite().defects[0].id), ['tp', 'tp'], 'the duplicate is visible in the reconciliation, so a custodian can catch it');
});

test('a label that is not adjudicated is reconciled as such and scores nothing', () => {
  const cand = clone(suite().defects[0]); cand.adjudication = { status: 'candidate', reviewers: [] };
  const s = score(FULL(), { defects: [cand, suite().defects[1]] });
  assert.deepEqual(statusOf(s, cand.id), ['not-adjudicated']);
  assert.equal(s.reconciliation.reconciled, true);
  assert.equal(s.endToEnd.micro.tp, 1);
});
