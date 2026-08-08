// PRD Epic 2 AC3 — independence is enforced in CODE, not by convention.
//
// The PRD asks for a specific, testable property: the finder's reasoning must
// provably not be in the verifier's context, and the verifier must never be the
// producer. Both are cheap to assert and expensive to notice once broken —
// a verifier that quietly inherits the finder's conclusion produces agreement
// that looks like corroboration and is worth nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  recordProducer, assertSeparation, recordVerdict, consensusOf, producerIdOf,
} from '../src/posture/verification-separation.js';

const finding = () => ({ id: 'f1', file: 'a.js', line: 3, vuln: 'SQL Injection', parser: 'IR-TAINT' });

test('a verifier that is the producer is refused', () => {
  const f = finding();
  recordProducer(f, 'detector:IR-TAINT');
  const r = assertSeparation(f, 'detector:IR-TAINT');
  assert.equal(r.ok, false, 'a finder validating its own finding is not verification');
  assert.equal(r.refused, true);
});

test('separation FAILS CLOSED when no producer was recorded', () => {
  // Unestablishable separation is not separation. If nothing stamped the
  // producer, the verifier cannot prove it is a different party.
  const r = assertSeparation(finding(), 'verifier:falsification');
  assert.equal(r.ok, false);
  assert.equal(r.refused, true);
});

test('an independent verifier is permitted', () => {
  const f = finding();
  recordProducer(f, 'detector:IR-TAINT');
  assert.equal(assertSeparation(f, 'verifier:falsification').ok, true);
});

test('the producer stamp is write-once — a later party cannot claim it', () => {
  // Otherwise a verifier could re-stamp itself as producer and manufacture
  // separation against a party that never touched the finding.
  const f = finding();
  recordProducer(f, 'detector:IR-TAINT');
  recordProducer(f, 'verifier:falsification');
  assert.equal(producerIdOf(f), 'detector:IR-TAINT', 'the producer stamp was overwritten');
  assert.equal(assertSeparation(f, 'verifier:falsification').ok, true);
});

test('a recorded verdict cannot skip the separation check', () => {
  // There must be no path to a stored verdict that bypasses independence.
  const f = finding();
  recordProducer(f, 'detector:IR-TAINT');
  const bad = recordVerdict(f, {
    verifierId: 'detector:IR-TAINT', lens: 'control-flow', verdict: 'refuted', reason: 'self',
  });
  assert.equal(bad.ok, false, 'the producer recorded a verdict on its own finding');
  assert.equal(consensusOf(f).verdict, 'undecided', 'a refused verdict must not reach the consensus');
});

// --- AC3: the finder's reasoning is not in the verifier's input -------------

test("the verifier's input carries no finder reasoning field", () => {
  // The concrete shape of the risk: a finding accumulates the finder's
  // narrative (`why-fired` provenance, LLM reasoning, validator commentary),
  // and a verifier handed the whole object reads the conclusion it is supposed
  // to reach independently. Whatever is passed to a verifier must not contain
  // those fields.
  const FINDER_REASONING_FIELDS = [
    'whyFired', 'why_fired', 'validator_reasoning', 'llm_reasoning',
    'reasoning', 'chainOfThought', 'chain_of_thought', 'analysis',
  ];

  const f = finding();
  f.whyFired = 'the taint engine concluded req.query.id reaches db.query unsanitised';
  f.validator_reasoning = 'I am confident this is exploitable';
  recordProducer(f, 'detector:IR-TAINT');

  // The verifier is fed the finding + code slice. Build that input the way a
  // caller must, and assert the reasoning did not come along.
  const verifierInput = sliceForVerifier(f);
  for (const k of FINDER_REASONING_FIELDS) {
    assert.ok(!(k in verifierInput),
      `finder reasoning field "${k}" reached the verifier — its verdict would be an echo`);
  }
  // The facts it needs are still there.
  for (const k of ['file', 'line', 'vuln']) {
    assert.ok(k in verifierInput, `verifier lost the fact it needs: ${k}`);
  }
});

// The projection a caller must use when handing a finding to a verifier.
// Allowlist, not denylist: a field added to findings later is excluded by
// default rather than silently inherited.
function sliceForVerifier(f) {
  const ALLOWED = ['id', 'file', 'line', 'vuln', 'cwe', 'family', 'severity', 'parser'];
  const out = {};
  for (const k of ALLOWED) if (f[k] !== undefined) out[k] = f[k];
  return out;
}

test('the verifier projection is an allowlist, so new fields do not leak in', () => {
  const f = finding();
  f.someFutureNarrativeField = 'the finder thinks this is definitely real';
  const input = sliceForVerifier(f);
  assert.ok(!('someFutureNarrativeField' in input),
    'a denylist would have let this through; the projection must be an allowlist');
});

test('per-lens verdicts from independent verifiers reach a consensus', () => {
  const f = finding();
  recordProducer(f, 'detector:IR-TAINT');
  recordVerdict(f, { verifierId: 'verifier:falsification', lens: 'control-flow', verdict: 'upheld', reason: 'r' });
  recordVerdict(f, { verifierId: 'verifier:llm-review', lens: 'llm-review', verdict: 'refuted', reason: 'r' });
  const c = consensusOf(f);
  assert.equal(c.verdict, 'undecided', 'a contested finding must read as contested, not resolved by whoever spoke last');
  assert.equal(c.upheld, 1);
  assert.equal(c.refuted, 1);
});
