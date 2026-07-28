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

// A skip is NOT a pass. `sandboxAvailable()` is now a functional verdict: it is
// false only when a trivial command could not actually be run under
// confinement on this host (binary absent, or present but the host refuses the
// confinement). When that happens the execution-proof feature is DISABLED, not
// degraded — nothing below runs unconfined, and none of these guarantees is
// verified on this host.
const noSbx = !sandboxAvailable()
  ? 'SKIPPED, NOT PASSED: confinement is unavailable on this host (a trivial command could not be run '
    + 'under any backend), so execution proof is disabled and these guarantees are UNVERIFIED here'
  : false;

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

  test('a sandbox that could not start is NOT reported as a failed exploit attempt', { skip: noSbx }, async () => {
    // Force the backend belonging to the OTHER platform family: its confinement
    // binary cannot exist here, so runConfined returns status:'error' WITHOUT
    // ever executing the PoC. A PoC that never ran must not be labelled
    // 'proof-failed' — that tier means "ran and did not demonstrate the bug".
    const unavailable = process.platform === 'darwin' ? 'namespace' : 'userspace';
    const f = await proveFinding({
      id: 'g', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `import fs from 'node:fs'; fs.writeFileSync('PROVEN', 'yes');` },
    }, { force: unavailable });
    assert.equal(f.proofEvidence.ran, false);
    assert.notEqual(f.proofTier, 'proof-failed');
    assert.notEqual(f.proofTier, 'execution-proven');
    // Left at its static standing, with the real cause named.
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /sandbox could not start/i);
  });

  test('the sandbox backend is recorded in the evidence', { skip: noSbx }, async () => {
    const f = await proveFinding({ id: 'f', parser: 'IR-TAINT', poc: { lang: 'js', code: `console.log(1);` } });
    assert.ok(typeof f.proofEvidence.backend === 'string' && f.proofEvidence.backend.length > 0);
  });
});

import { normalizeFindings } from '../src/report/index.js';

describe('report surfacing', () => {
  test('proof tier and evidence survive report normalisation', () => {
    const out = normalizeFindings({ findings: [{
      id: 'z', severity: 'high', file: 'a.js', line: 1, vuln: 'X', cwe: 'CWE-1',
      description: 'd', remediation: 'r', parser: 'IR-TAINT', family: 'f',
      proofTier: 'execution-proven',
      proofEvidence: { tier: 'execution-proven', backend: 'userspace', ran: true, observed: 'marker', reason: null, exitCode: 0, timedOut: false, at: '2026-07-27T00:00:00.000Z' },
    }] });
    const f = out.find(x => x.id === 'z') || out[0];
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.backend, 'userspace');
  });

  test('a finding without proof fields normalises without inventing them', () => {
    const out = normalizeFindings({ findings: [{
      id: 'y', severity: 'low', file: 'b.js', line: 2, vuln: 'Y', cwe: 'CWE-2',
      description: 'd', remediation: 'r', parser: 'REGEX', family: 'f',
    }] });
    const f = out.find(x => x.id === 'y') || out[0];
    assert.ok(f.proofTier === undefined || f.proofTier === 'unproven');
  });
});
