// Threat-model PRD FR-10 (AC-10A, AC-10B) and the pilot portion of M4: a candidate is qualified only for the cases it passes, every gate
// is recomputed from evidence, and missing scope, an old artifact, a failed legitimate control, an unmeasured stratum or a stale feed
// each keep the gate they belong to open. The positive, negative and legitimate cases come from real runs of the two-tenant pilot.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';
import { startRecordsService, observe, artifactDigest } from './fixtures/pilot/records-service.mjs';
import { evaluateCandidate, signCandidatePacket, verifyCandidatePacket, writeCandidateDecision, packetDigest } from '../src/posture/assurance/candidate-qualification.js';

const NOW = Date.parse('2026-11-08T12:00:00Z');
const FIXED = artifactDigest('fixed');
const POLICY = 'sha256:policy-v1';

async function pilotCase(caseId, variant, token, expected, gate = 'G-03') {
  const svc = await startRecordsService({ variant });
  try {
    const o = await observe(svc, '/records/r-b-1', { token });
    const legit = expected === 'legitimate';
    return {
      caseId, requirement: 'FR-08', gate, expected, verdict: 'recorded', reasonCode: 'pilot-oracle', owner: 'service-owner',
      artifactDigest: variant === 'vulnerable' ? FIXED : svc.artifact.digest, // a positive control runs on the vulnerable twin of the candidate
      vulnerableArtifact: variant === 'vulnerable' ? svc.artifact.digest : undefined,
      policyDigest: POLICY, expires: '2026-12-01T00:00:00Z',
      observed: { status: o.status, forbiddenEffect: !legit && o.markerDelivered, legitimateEffect: legit && o.markerDelivered && o.status === 200 },
    };
  } finally { await svc.close(); }
}

async function packet(over = {}) {
  const cases = [
    await pilotCase('PILOT-03', 'vulnerable', 'token-tenant-a', 'positive'),
    await pilotCase('PILOT-05', 'fixed', 'token-tenant-a', 'negative'),
    await pilotCase('PILOT-06', 'fixed', 'token-tenant-b', 'legitimate'),
    { caseId: 'REG-01', requirement: 'G-01', gate: 'G-01', expected: 'negative', verdict: 'pass', owner: 'release-engineering', artifactDigest: FIXED, policyDigest: POLICY, expires: '2026-12-01T00:00:00Z', observed: { forbiddenEffect: false } },
    { caseId: 'DET-01', requirement: 'FR-07', gate: 'G-05', expected: 'positive', verdict: 'observed', owner: 'detection-engineering', artifactDigest: FIXED, policyDigest: POLICY, expires: '2026-12-01T00:00:00Z', observed: { forbiddenEffect: true } },
    { caseId: 'OPS-01', requirement: 'G-07', gate: 'G-07', expected: 'legitimate', verdict: 'within-budget', owner: 'release-owner', artifactDigest: FIXED, policyDigest: POLICY, expires: '2026-12-01T00:00:00Z', observed: { legitimateEffect: true } },
  ];
  return {
    scanner: { version: '0.195.29', bundleDigest: 'sha256:bundle' },
    target: { repository: 'shop', commit: 'a1'.repeat(20), artifactDigest: FIXED, policyDigest: POLICY, deploymentProfile: 'local-pilot', window: { start: '2026-11-08T00:00:00Z', end: '2026-11-08T12:00:00Z' } },
    scope: { status: 'satisfied' },
    runner: { attested: true },
    evaluation: { status: 'measured', meetsFloors: true },
    telemetry: { feeds: [{ name: 'service-log', lastHeartbeat: '2026-11-08T11:59:00Z' }] },
    cases, ...over,
  };
}

test('AC-10A: a packet with every required piece of valid evidence is qualified for its stated scope, and the signature verifies', async () => {
  const p = await packet();
  const d = evaluateCandidate(p, { now: NOW, requiredCases: ['PILOT-03', 'PILOT-05', 'PILOT-06'] });
  assert.equal(d.status, 'qualified', JSON.stringify(d.blockers));
  assert.deepEqual(d.cases.find((c) => c.caseId === 'PILOT-03').outcome, 'met', 'the vulnerable positive reproduced');
  assert.equal(d.scope.artifactDigest, FIXED);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const signed = signCandidatePacket(p, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  assert.equal(verifyCandidatePacket(signed, publicKey.export({ type: 'spki', format: 'pem' })).ok, true);
  assert.equal(verifyCandidatePacket({ ...signed, target: { ...signed.target, artifactDigest: 'sha256:other' } }, publicKey.export({ type: 'spki', format: 'pem' })).code, 'SIGNATURE', 'an edited packet does not verify');
});

test('AC-10A: missing scope, an old artifact, a failed legitimate control, an unmeasured stratum and a stale feed each keep their gate open', async () => {
  const gateOf = async (over, mutate = (x) => x) => { const p = mutate(await packet(over)); return evaluateCandidate(p, { now: NOW }); };
  let d = await gateOf({ scope: undefined });
  assert.equal(d.status, 'not-qualified'); assert.equal(d.gates['G-02'].outcome, 'unresolved');
  d = await gateOf({}, (p) => ({ ...p, cases: p.cases.map((c) => (c.caseId === 'PILOT-05' ? { ...c, artifactDigest: artifactDigest('vulnerable') } : c)) }));
  assert.equal(d.gates['G-03'].outcome, 'unresolved'); assert.match(d.gates['G-03'].reasons.join(), /another artifact/);
  const denyAll = await pilotCase('PILOT-06', 'deny-all', 'token-tenant-b', 'legitimate');
  d = await gateOf({}, (p) => ({ ...p, target: { ...p.target, artifactDigest: artifactDigest('deny-all') }, cases: p.cases.map((c) => (c.caseId === 'PILOT-06' ? denyAll : { ...c, artifactDigest: c.artifactDigest === FIXED ? artifactDigest('deny-all') : c.artifactDigest })) }));
  assert.equal(d.gates['G-03'].outcome, 'violated', 'a "fix" that denies everyone fails the legitimate control');
  d = await gateOf({ evaluation: { status: 'unmeasured', reason: 'no independent labels for this candidate' } });
  assert.equal(d.gates['G-06'].outcome, 'blocked');
  d = await gateOf({ telemetry: { feeds: [{ name: 'service-log', lastHeartbeat: '2026-11-08T09:00:00Z' }] } });
  assert.equal(d.gates['G-05'].outcome, 'unresolved'); assert.match(d.gates['G-05'].reasons.join(), /stale/);
  d = await gateOf({ runner: { attested: false, reason: 'macOS host: confinement is host-proved, not enforced' } });
  assert.equal(d.gates['G-04'].outcome, 'blocked');
  d = await gateOf({}, (p) => ({ ...p, cases: p.cases.map((c) => (c.caseId === 'PILOT-03' ? { ...c, expires: '2026-11-01T00:00:00Z' } : c)) }));
  assert.match(d.gates['G-03'].reasons.join(), /expired/);
});

test('AC-10A: a gate with no evidence is never met by inheritance, and a required case with no record keeps the candidate open', async () => {
  const p = await packet();
  const d = evaluateCandidate({ ...p, cases: p.cases.filter((c) => c.gate !== 'G-07') }, { now: NOW });
  assert.equal(d.gates['G-07'].outcome, 'unresolved'); assert.match(d.gates['G-07'].reasons.join(), /no evidence/);
  const r = evaluateCandidate(p, { now: NOW, requiredCases: ['PILOT-09'] });
  assert.equal(r.status, 'not-qualified'); assert.ok(r.blockers.some((b) => b.caseId === 'PILOT-09'));
});

test('AC-10B: repeated verification gives the same decision, and an interrupted or retried write leaves a consistent file', async () => {
  const p = await packet();
  const a = evaluateCandidate(p, { now: NOW }); const b = evaluateCandidate(p, { now: NOW });
  assert.deepEqual(a, b);
  assert.equal(packetDigest(p), packetDigest(JSON.parse(JSON.stringify(p))));
  const dir = mkTestTmp('cand-'); const file = path.join(dir, 'decision.json');
  assert.equal(writeCandidateDecision(file, a).written, true);
  assert.equal(writeCandidateDecision(file, b).unchanged, true, 'a retry writes nothing new');
  assert.deepEqual(fs.readdirSync(dir), ['decision.json'], 'no temporary file is left behind');
});
