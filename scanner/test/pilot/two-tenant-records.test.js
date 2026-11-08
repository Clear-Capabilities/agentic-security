// Threat-model PRD FR-08.1 and AC-08A: PILOT-01 to PILOT-08 on a loopback two-tenant service. The application variant, the client
// oracle (did Tenant B's marker come back?) and the detection (a hunt over the service's own sanitized logs) are separate parties; the
// expected outcomes live only in this test, never in anything the detector reads. Every case record is bound to the artifact digest.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { startRecordsService, observe, artifactDigest } from '../fixtures/pilot/records-service.mjs';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { huntLogs } from '../../src/posture/dnr/hunt.js';

const ir = (payloadClass, cwe) => buildDetectionIR({ finding: { id: `pilot-${payloadClass}`, cwe }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'GET', path: '/records/:id', payloadClass } } } }).ir;
const DETECTIONS = { bypass: ir('auth-bypass', 'CWE-306'), object: ir('object-authz', 'CWE-639') };

const CASES = [
  { id: 'PILOT-01', variant: 'vulnerable', token: null, path: '/records/r-b-1', expect: { delivered: true, bypass: 'OBSERVED', object: 'NOT_OBSERVED' } },
  { id: 'PILOT-02', variant: 'vulnerable', token: 'not-a-valid-token', path: '/records/r-b-1', expect: { delivered: true, bypass: 'OBSERVED', object: 'NOT_OBSERVED' } },
  { id: 'PILOT-03', variant: 'vulnerable', token: 'token-tenant-a', path: '/records/r-b-1', expect: { delivered: true, bypass: 'NOT_OBSERVED', object: 'OBSERVED' } },
  { id: 'PILOT-04', variant: 'fixed', token: 'not-a-valid-token', path: '/records/r-b-1', expect: { delivered: false, status: 401, bypass: 'NOT_OBSERVED', object: 'NOT_OBSERVED' } },
  { id: 'PILOT-05', variant: 'fixed', token: 'token-tenant-a', path: '/records/r-b-1', expect: { delivered: false, status: 403, bypass: 'NOT_OBSERVED', object: 'NOT_OBSERVED' } },
  { id: 'PILOT-06', variant: 'fixed', token: 'token-tenant-b', path: '/records/r-b-1', expect: { delivered: true, legitimate: true, status: 200, bypass: 'NOT_OBSERVED', object: 'NOT_OBSERVED' } },
  { id: 'PILOT-07', variant: 'vulnerable', token: 'token-tenant-a', path: '/health', expect: { delivered: false, targetRelevant: 0 } },
  { id: 'PILOT-08', variant: 'vulnerable', token: 'not-a-valid-token', path: '/records/r-b-1', omitAuthFacts: true, expect: { delivered: true, bypass: 'INCONCLUSIVE', object: 'INCONCLUSIVE' } },
];

async function runCase(c) {
  const svc = await startRecordsService({ variant: c.variant, omitAuthFacts: !!c.omitAuthFacts });
  try {
    const obs = await observe(svc, c.path, { token: c.token });
    const dir = mkTestTmp(`pilot-${c.id}-`);
    fs.writeFileSync(path.join(dir, 'service.log'), `${svc.logLines.join('\n')}\n`);
    const hunts = {};
    for (const [k, d] of Object.entries(DETECTIONS)) hunts[k] = await huntLogs({ ir: d, logsPath: dir });
    const logged = svc.logLines.map((l) => JSON.parse(l)).find((l) => l.request_id === obs.requestId);
    return {
      caseId: c.id, artifact: svc.artifact, actor: c.token === null ? 'none' : c.token === 'not-a-valid-token' ? 'rejected-credential' : c.token.replace('token-', ''),
      observed: obs, detection: Object.fromEntries(Object.entries(hunts).map(([k, h]) => [k, { verdict: h.verdict, matches: h.matches.count, target: h.coverage?.target ?? null }])),
      join: { key: obs.requestId, matched: !!logged }, logText: svc.logLines.join('\n'),
    };
  } finally { await svc.close(); }
}

test('AC-08A: PILOT-01 to PILOT-08 produce artifact-bound evidence with the expected effect and detection', async () => {
  for (const c of CASES) {
    const r = await runCase(c);
    const why = `${c.id}: ${JSON.stringify({ observed: r.observed, detection: r.detection })}`;
    assert.equal(r.artifact.digest, artifactDigest(c.variant), `${c.id}: bound to the artifact`);
    assert.equal(r.observed.markerDelivered, c.expect.delivered, why);
    if (c.expect.status) assert.equal(r.observed.status, c.expect.status, why);
    if (c.expect.bypass) assert.equal(r.detection.bypass.verdict, c.expect.bypass, why);
    if (c.expect.object) assert.equal(r.detection.object.verdict, c.expect.object, why);
    if (c.expect.targetRelevant !== undefined) {
      assert.equal(r.detection.bypass.target.relevant, c.expect.targetRelevant, `${c.id}: an unrelated route with the same method counts zero`);
      assert.equal(r.detection.object.target.relevant, c.expect.targetRelevant);
    }
    assert.equal(r.join.matched, true, `${c.id}: the oracle's observation joins the service log by request id`);
    // a detection signal plus an independently observed delivery, joined by key, is a corroborated effect; neither alone is
    const corroborated = r.observed.markerDelivered && (r.detection.bypass.verdict === 'OBSERVED' || r.detection.object.verdict === 'OBSERVED') && r.join.matched;
    assert.equal(corroborated, ['PILOT-01', 'PILOT-02', 'PILOT-03'].includes(c.id), `${c.id}: corroboration`);
    assert.ok(!/token-tenant|not-a-valid-token|Bearer/.test(r.logText), `${c.id}: no credential value is written to the log`);
  }
});

test('PILOT-08: with no trusted outcome or tenant in the logs, the delivery the oracle saw is kept and the detection stays open', async () => {
  const r = await runCase(CASES.find((c) => c.id === 'PILOT-08'));
  assert.equal(r.observed.markerDelivered, true, 'the positive evidence is preserved');
  assert.equal(r.detection.bypass.target.missingRequired, 1);
  assert.notEqual(r.detection.bypass.verdict, 'NOT_OBSERVED', 'an unresolved required field never reads as clean');
});

test('a "fix" that denies everyone fails the legitimate control, so it cannot pass as the patched artifact', async () => {
  const legit = CASES.find((c) => c.id === 'PILOT-06');
  const fixed = await runCase(legit);
  const denyAll = await runCase({ ...legit, variant: 'deny-all' });
  assert.equal(fixed.observed.markerDelivered, true);
  assert.equal(denyAll.observed.markerDelivered, false);
  const patchedControlPasses = (r) => r.observed.status === 200 && r.observed.markerDelivered;
  assert.equal(patchedControlPasses(fixed), true);
  assert.equal(patchedControlPasses(denyAll), false, 'a server that returns the record to no one does not pass the patched control');
  assert.notEqual(artifactDigest('fixed'), artifactDigest('deny-all'), 'the two artifacts are distinguishable');
});
