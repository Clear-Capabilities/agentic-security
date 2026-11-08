// Threat-model PRD FR-04.3 and AC-04C (TM-06): corroboration is counted by independent evidence, not by lenses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recordProducer, recordVerdict, consensusOf, refutationRemoves } from '../src/posture/verification-separation.js';

const finding = (severity = 'high') => { const f = { id: 'F', parser: 'SAST', severity }; recordProducer(f, 'detector:SAST'); return f; };

test('TM-06: two refuting lenses from one verifier do not outweigh an upholding vote from another', () => {
  const f = finding();
  recordVerdict(f, { verifierId: 'verifier:a', lens: 'reachability', verdict: 'refuted' });
  recordVerdict(f, { verifierId: 'verifier:a', lens: 'data-shape', verdict: 'refuted' });
  recordVerdict(f, { verifierId: 'verifier:b', lens: 'control-flow', verdict: 'upheld' });
  const c = consensusOf(f);
  assert.equal(c.verdict, 'undecided', 'one independent vote each');
  assert.equal(c.conflict, true);
  assert.deepEqual([c.refuted, c.upheld], [2, 1], 'the lens counts are kept for the reviewer');
  assert.deepEqual(c.lenses, ['control-flow', 'data-shape', 'reachability']);
  assert.equal(refutationRemoves(f, c), false);
});

test('AC-04C: votes sharing one observation are one piece of evidence; repeated submissions are idempotent', () => {
  const f = finding();
  for (const v of ['verifier:a', 'verifier:b', 'verifier:c']) recordVerdict(f, { verifierId: v, lens: 'replay', verdict: 'refuted', evidence: { observationId: 'obs-1', kind: 'effect' } });
  recordVerdict(f, { verifierId: 'verifier:d', lens: 'replay', verdict: 'upheld', evidence: { observationId: 'obs-2', kind: 'effect' } });
  let c = consensusOf(f);
  assert.deepEqual([c.independent.refuted, c.independent.upheld], [1, 1], 'three verifiers on one observation count once');
  assert.equal(c.verdict, 'undecided');
  recordVerdict(f, { verifierId: 'verifier:d', lens: 'replay', verdict: 'upheld', evidence: { observationId: 'obs-2', kind: 'effect' } });
  c = consensusOf(f);
  assert.equal(c.independent.upheld, 1, 'a repeated submission changes nothing');
});

test('AC-04C: separate verified observations count separately and can carry a refutation with sufficient authority', () => {
  const f = finding('critical');
  recordVerdict(f, { verifierId: 'verifier:a', lens: 'replay', verdict: 'refuted', evidence: { observationId: 'obs-1', kind: 'effect' } });
  recordVerdict(f, { verifierId: 'verifier:b', lens: 'replay', verdict: 'refuted', evidence: { observationId: 'obs-2', kind: 'effect' } });
  const c = consensusOf(f);
  assert.equal(c.independent.refuted, 2); assert.equal(c.refutationAuthority, 'sufficient');
  assert.equal(refutationRemoves(f, c), true);
});

test('AC-04C: a critical disagreement stays visible and cannot remove the finding; reasoning alone is advisory', () => {
  const contested = finding('critical');
  recordVerdict(contested, { verifierId: 'verifier:a', lens: 'replay', verdict: 'refuted', evidence: { observationId: 'obs-1', kind: 'effect' } });
  recordVerdict(contested, { verifierId: 'verifier:b', lens: 'replay', verdict: 'refuted', evidence: { observationId: 'obs-2', kind: 'effect' } });
  recordVerdict(contested, { verifierId: 'verifier:c', lens: 'replay', verdict: 'upheld', evidence: { observationId: 'obs-3', kind: 'effect' } });
  const c = consensusOf(contested);
  assert.equal(c.verdict, 'refuted'); assert.equal(c.conflict, true); assert.equal(c.refutationAuthority, 'advisory');
  assert.equal(refutationRemoves(contested, c), false, 'unresolved disagreement keeps a critical finding');
  const opinion = finding('critical');
  recordVerdict(opinion, { verifierId: 'verifier:llm-review', lens: 'reasoning', verdict: 'refuted', evidence: { kind: 'reasoning' } });
  assert.equal(consensusOf(opinion).refutationAuthority, 'advisory');
  assert.equal(refutationRemoves(opinion), false);
  const high = finding('high');
  recordVerdict(high, { verifierId: 'verifier:llm-review', lens: 'reasoning', verdict: 'refuted' });
  assert.equal(refutationRemoves(high), true, 'below critical the existing behaviour is unchanged');
});

test('a verdict whose generator produced the finding is excluded as self-authored', () => {
  const f = finding();
  recordVerdict(f, { verifierId: 'verifier:x', lens: 'replay', verdict: 'upheld', evidence: { generator: 'SAST', kind: 'reasoning' } });
  const c = consensusOf(f);
  assert.equal(c.selfAuthoredExcluded, 1); assert.equal(c.independent.groups, 0); assert.equal(c.verdict, 'undecided');
});
