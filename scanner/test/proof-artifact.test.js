// PRD Epic 1.2 / 1.4 / 7.4 — the proof level and its artifact digest.
//
// The schema is the load-bearing part: a report that says PROVEN must mean the
// exploit fired, and a report that says nothing must not be read as PATTERN.
// These tests pin both directions, plus the digest's tamper-evidence property.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  proofLevelOf, proofArtifactDigest, proofBlock, PROOF_LEVELS, _internals,
} from '../src/posture/proof-artifact.js';
import { toSARIF } from '../src/report/index.js';

const proven = (over = {}) => ({
  id: 'x', severity: 'critical', file: 'a.js', line: 2, vuln: 'Command Injection',
  cwe: 'CWE-78', family: 'command-injection', parser: 'IR-TAINT',
  proofTier: 'execution-proven',
  proofEvidence: { ran: true, backend: 'userspace', observed: "marker 'PROVEN' written", at: '2026-01-01T00:00:00Z', exitCode: 0 },
  poc: { marker: 'PROVEN', code: 'import h from "./a.js";' },
  ...over,
});

test('every engine tier maps to a declared proof level', () => {
  for (const [tier, level] of Object.entries(_internals.TIER_TO_LEVEL)) {
    assert.ok(PROOF_LEVELS.includes(level), `${tier} maps to undeclared level ${level}`);
    assert.equal(proofLevelOf({ proofTier: tier }), level);
  }
});

test('a finding with no tier has NO proof level — not PATTERN', () => {
  // The distinction that matters: "the proof stage never ran" is not the same
  // claim as "we tried and this is only a pattern match". Defaulting to PATTERN
  // would assert every finding had been considered.
  assert.equal(proofLevelOf({}), null);
  assert.equal(proofLevelOf({ proofTier: undefined }), null);
  assert.equal(proofBlock({}), null);
});

test('an unknown tier degrades to the weakest level rather than vanishing', () => {
  assert.equal(proofLevelOf({ proofTier: 'something-new' }), 'PATTERN');
});

test('the digest commits to the claim and changes when the claim changes', () => {
  const base = proofArtifactDigest(proven());
  assert.match(base, /^[0-9a-f]{64}$/);

  // Each of these is part of what was claimed.
  assert.notEqual(base, proofArtifactDigest(proven({ proofTier: 'proof-failed' })), 'tier not committed');
  assert.notEqual(base, proofArtifactDigest(proven({
    proofEvidence: { ...proven().proofEvidence, observed: 'something else' },
  })), 'observed effect not committed');
  assert.notEqual(base, proofArtifactDigest(proven({
    poc: { marker: 'PROVEN', code: 'a different exploit' },
  })), 'the PoC itself not committed');
  assert.notEqual(base, proofArtifactDigest(proven({
    proofEvidence: { ...proven().proofEvidence, ran: false },
  })), 'ran-flag not committed');
});

test('the digest is stable across identical proofs run at different times', () => {
  // Otherwise it cannot answer "is this the artifact the PR was reviewed
  // against?", which is the only reason it exists.
  const a = proven();
  const b = proven({ proofEvidence: { ...proven().proofEvidence, at: '2027-09-09T09:09:09Z', exitCode: 1 } });
  assert.equal(proofArtifactDigest(a), proofArtifactDigest(b));
});

test('no evidence means no digest — never a hash over nothing', () => {
  assert.equal(proofArtifactDigest({ proofTier: 'execution-proven' }), null);
  assert.equal(proofArtifactDigest({ proofEvidence: { ran: true } }), null);
  assert.equal(proofArtifactDigest({}), null);
});

test('a failed proof still reports its level and its reason', () => {
  // "The PoC ran and nothing happened" is a triage signal; dropping the reason
  // would make it indistinguishable from "no PoC was attempted".
  const b = proofBlock({
    proofTier: 'proof-failed',
    proofEvidence: { ran: true, backend: 'userspace', reason: 'no predicted effect' },
  });
  assert.equal(b.proofLevel, 'PROBABLE_FP');
  assert.equal(b.proofRan, true);
  assert.equal(b.proofReason, 'no predicted effect');
});

// ---------------------------------------------------------------- SARIF

test('SARIF carries the proof level and artifact digest', () => {
  const r = toSARIF({ findings: [proven()] }, {}).runs[0].results[0];
  assert.equal(r.properties.proofLevel, 'PROVEN');
  assert.equal(r.properties.proofTier, 'execution-proven');
  assert.equal(r.properties.proofBackend, 'userspace');
  assert.match(r.properties.proofArtifactSha256, /^[0-9a-f]{64}$/);
});

test('SARIF omits the proof block entirely when no proof stage ran', () => {
  const f = { ...proven() };
  delete f.proofTier; delete f.proofEvidence; delete f.poc;
  const r = toSARIF({ findings: [f] }, {}).runs[0].results[0];
  for (const k of ['proofLevel', 'proofTier', 'proofRan', 'proofArtifactSha256']) {
    assert.ok(!(k in r.properties), `${k} leaked into a scan with no proof stage`);
  }
});

test('SARIF proof level survives the weaker tiers too', () => {
  for (const [tier, level] of [['taint-proven', 'REACHABLE'], ['unproven', 'PATTERN']]) {
    const r = toSARIF({ findings: [proven({ proofTier: tier })] }, {}).runs[0].results[0];
    assert.equal(r.properties.proofLevel, level);
  }
});
