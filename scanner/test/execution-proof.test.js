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

import { proveFinding } from '../src/posture/execution-proof.js';
import { sandboxAvailable } from '../src/sandbox/index.js';

const noSbx = !sandboxAvailable() ? 'skipped: no confinement primitive on this host' : false;

describe('proveFinding', () => {
  test('a PoC that demonstrates the bug is execution-proven', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'a', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `import fs from 'node:fs'; fs.writeFileSync('PROVEN', 'yes');` },
    });
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.ran, true);
    assert.notEqual(f.proofEvidence.backend, 'disabled');
  });

  test('a PoC that does NOT demonstrate the bug is proof-failed, not dismissed', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'b', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `console.log('nothing to see');` },
    });
    assert.equal(f.proofTier, 'proof-failed');
    // Explicitly NOT a false-positive verdict.
    assert.notEqual(f.proofTier, 'unproven');
  });

  test('a PoC that hangs is timed out and does not become proven', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'c', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `while (true) {}` },
    }, { timeoutMs: 1200 });
    assert.equal(f.proofEvidence.timedOut, true);
    assert.notEqual(f.proofTier, 'execution-proven');
  });

  test('a finding with no PoC is untouched and says why', async () => {
    const f = await proveFinding({ id: 'd', parser: 'IR-TAINT' });
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /no proof-of-concept/i);
  });

  test('a non-JS PoC records that it is unsupported rather than guessing', async () => {
    const f = await proveFinding({ id: 'e', parser: 'IR-TAINT', poc: { lang: 'php', code: '<?php ?>' } });
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /unsupported/i);
  });

  test('the sandbox backend is recorded in the evidence', { skip: noSbx }, async () => {
    const f = await proveFinding({ id: 'f', parser: 'IR-TAINT', poc: { lang: 'js', code: `console.log(1);` } });
    assert.ok(typeof f.proofEvidence.backend === 'string' && f.proofEvidence.backend.length > 0);
  });
});
