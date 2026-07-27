import { test, describe } from 'node:test';
import assert from 'node:assert';
import { PROOF_TIERS, attachProofTier, proofTierOf } from '../src/posture/proof-tier.js';

describe('proof tier vocabulary', () => {
  test('exposes exactly the four tiers, most-proven first', () => {
    assert.deepEqual([...PROOF_TIERS], ['execution-proven', 'proof-failed', 'taint-proven', 'unproven']);
  });

  test('a finding with no proof attempt reads as taint-proven when the analyser found it', () => {
    assert.equal(proofTierOf({ parser: 'IR-TAINT' }), 'taint-proven');
  });

  test('a finding with no analyser backing reads as unproven', () => {
    assert.equal(proofTierOf({}), 'unproven');
  });

  test('attachProofTier records evidence and sets the tier', () => {
    const f = attachProofTier({ id: 'x' }, {
      tier: 'execution-proven', backend: 'userspace', ran: true,
      observed: 'marker file created', reason: null, exitCode: 0, timedOut: false, at: '2026-07-27T00:00:00.000Z',
    });
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.backend, 'userspace');
    assert.equal(f.proofEvidence.ran, true);
  });

  test('an unrunnable PoC never yields execution-proven', () => {
    const f = attachProofTier({ id: 'x', parser: 'IR-TAINT' }, {
      tier: 'execution-proven', backend: 'disabled', ran: false,
      observed: null, reason: 'no confinement primitive', exitCode: null, timedOut: false, at: '2026-07-27T00:00:00.000Z',
    });
    // ran:false must be demoted — proof requires the PoC to have actually run.
    assert.notEqual(f.proofTier, 'execution-proven');
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /confinement/);
  });

  test('rejects a tier outside the vocabulary', () => {
    assert.throws(() => attachProofTier({}, { tier: 'definitely-exploitable', ran: true }), /unknown proof tier/i);
  });
});
