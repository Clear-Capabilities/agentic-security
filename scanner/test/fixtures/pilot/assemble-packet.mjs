// Assemble candidate packets from real runs of the local pilot fixtures (threat-model PRD FR-08, FR-10.1, section 6).
//
// One packet per deployment identity (FR-08.2): the two-tenant records service (PILOT-01 to PILOT-11), the app-to-cloud export chain and
// the records search over a database (both PILOT-12). Every case is produced by running the fixture now: the client oracle, the
// service's sanitized log and a hunt over it are separate parties, and the case records only the observation, a join key and digests,
// never a credential, a response body or a log line. Every case is `tier: 'local'`. What this host cannot produce is recorded as
// blocked with its reason, never left out: the independently held variant (PILOT-09), the staging sensor-loss drill (PILOT-10) and the
// workflow invariant's execution through the trust boundary (PILOT-11, run by test/invariants/approval-workflow.test.js).
//
// A positive control runs on the vulnerable twin of the candidate and is recorded against the candidate's identity with the twin's
// digest beside it (`vulnerableArtifact`, `vulnerablePolicy`), so the packet shows both that the fixture can reproduce the effect and
// that the candidate does not.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startRecordsService, observe, artifactDigest } from './records-service.mjs';
import { OBJECTS, startCloudChain, runDbSearch, dbArtifactDigest, cloudArtifactDigest, policyDigest } from './cloud-and-db.mjs';
import { buildDetectionIR } from '../../../src/posture/dnr/detection-ir.js';
import { huntLogs } from '../../../src/posture/dnr/hunt.js';

const sha = (s) => `sha256:${crypto.createHash('sha256').update(s).digest('hex')}`;
const ir = (payloadClass, cwe) => buildDetectionIR({ finding: { id: `pilot-${payloadClass}`, cwe }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'GET', path: '/records/:id', payloadClass } } } }).ir;

const RECORDS = [
  { id: 'PILOT-01', variant: 'vulnerable', token: null, path: '/records/r-b-1', expected: 'positive', rule: 'bypass' },
  { id: 'PILOT-02', variant: 'vulnerable', token: 'not-a-valid-token', path: '/records/r-b-1', expected: 'positive', rule: 'bypass' },
  { id: 'PILOT-03', variant: 'vulnerable', token: 'token-tenant-a', path: '/records/r-b-1', expected: 'positive', rule: 'object' },
  { id: 'PILOT-04', variant: 'fixed', token: 'not-a-valid-token', path: '/records/r-b-1', expected: 'negative' },
  { id: 'PILOT-05', variant: 'fixed', token: 'token-tenant-a', path: '/records/r-b-1', expected: 'negative' },
  { id: 'PILOT-06', variant: 'fixed', token: 'token-tenant-b', path: '/records/r-b-1', expected: 'legitimate' },
];

async function runRecords(c, { omitAuthFacts = false } = {}) {
  const svc = await startRecordsService({ variant: c.variant, omitAuthFacts });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pilot-packet-'));
  try {
    const obs = await observe(svc, c.path, { token: c.token });
    const logText = `${svc.logLines.join('\n')}\n`;
    fs.writeFileSync(path.join(dir, 'service.log'), logText);
    const bypass = await huntLogs({ ir: ir('auth-bypass', 'CWE-306'), logsPath: dir });
    const object = await huntLogs({ ir: ir('object-authz', 'CWE-639'), logsPath: dir });
    const joined = svc.logLines.some((l) => JSON.parse(l).request_id === obs.requestId);
    const lastAt = JSON.parse(svc.logLines[svc.logLines.length - 1])['@timestamp'];
    return { obs, hunts: { bypass, object }, joined, logDigest: sha(logText), lastAt, artifact: svc.artifact.digest };
  } finally { await svc.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

const huntView = (h) => ({ verdict: h.verdict, matches: h.matches.count, relevant: h.coverage?.target?.relevant ?? null, missingRequired: h.coverage?.target?.missingRequired ?? null });

/**
 * @param {{now?:number, scannerBundle?:string|null, ttlMs?:number}} o
 * @returns {Promise<Object<string, object>>} packets keyed by deployment identity
 */
export async function assemblePilotPacket({ now = Date.now(), scannerBundle = null, ttlMs = 7 * 24 * 3600 * 1000 } = {}) {
  const expires = new Date(now + ttlMs).toISOString();
  const start = new Date(now).toISOString();
  const base = { tier: 'local', expires, ...(scannerBundle ? { scannerBundle } : {}) };
  const scanner = { bundleDigest: scannerBundle };

  // records service
  const candidate = artifactDigest('fixed');
  const cases = []; let lastAt = start;
  for (const c of RECORDS) {
    const r = await runRecords(c); lastAt = r.lastAt;
    const twin = c.variant === 'vulnerable' ? { vulnerableArtifact: r.artifact } : {};
    const evidence = { requestId: r.obs.requestId, joined: r.joined, logDigest: r.logDigest, status: r.obs.status, hunts: { bypass: huntView(r.hunts.bypass), object: huntView(r.hunts.object) } };
    const legit = c.expected === 'legitimate';
    cases.push({ ...base, caseId: c.id, requirement: 'FR-08.1', gate: 'G-03', expected: c.expected, verdict: 'recorded', reasonCode: 'pilot-oracle', owner: 'service-owner',
      artifactDigest: candidate, ...twin, evidence,
      observed: { status: r.obs.status, forbiddenEffect: !legit && r.obs.markerDelivered, legitimateEffect: legit && r.obs.markerDelivered && r.obs.status === 200 } });
    // the detection half of the same run, judged on the signal: the right rule fires on a reproduced effect and joins the oracle's request
    const fired = c.rule ? r.hunts[c.rule].verdict === 'OBSERVED' && r.joined : r.hunts.bypass.verdict === 'OBSERVED' || r.hunts.object.verdict === 'OBSERVED';
    cases.push({ ...base, caseId: `${c.id}-detect`, requirement: 'FR-07', gate: 'G-05', kind: 'detection', expected: c.rule ? 'positive' : 'negative', verdict: 'recorded', reasonCode: 'pilot-hunt', owner: 'detection-engineering',
      artifactDigest: candidate, ...twin, evidence, observed: { detected: fired } });
  }
  // PILOT-07: an unrelated route with the same method must count zero toward the target route
  const p7 = await runRecords({ variant: 'vulnerable', token: 'token-tenant-a', path: '/health' });
  cases.push({ ...base, caseId: 'PILOT-07', requirement: 'FR-07.3', gate: 'G-05', expected: 'negative', verdict: 'recorded', reasonCode: 'target-counter', owner: 'detection-engineering',
    artifactDigest: candidate, vulnerableArtifact: p7.artifact, evidence: { bypass: huntView(p7.hunts.bypass), object: huntView(p7.hunts.object) },
    observed: { forbiddenEffect: (p7.hunts.bypass.coverage?.target?.relevant ?? 1) > 0 || (p7.hunts.object.coverage?.target?.relevant ?? 1) > 0 } });
  // PILOT-08: without trusted auth facts the delivery is kept and the hunt must not read as clean
  const p8 = await runRecords({ variant: 'vulnerable', token: 'not-a-valid-token', path: '/records/r-b-1' }, { omitAuthFacts: true });
  cases.push({ ...base, caseId: 'PILOT-08', requirement: 'FR-07.1', gate: 'G-05', expected: 'negative', verdict: 'recorded', reasonCode: 'missing-auth-facts', owner: 'detection-engineering',
    artifactDigest: candidate, vulnerableArtifact: p8.artifact, evidence: { delivered: p8.obs.markerDelivered, bypass: huntView(p8.hunts.bypass), object: huntView(p8.hunts.object) },
    observed: { forbiddenEffect: !p8.obs.markerDelivered || p8.hunts.bypass.verdict === 'NOT_OBSERVED' || p8.hunts.object.verdict === 'NOT_OBSERVED' } });
  cases.push({ ...base, caseId: 'PILOT-09', requirement: 'FR-02.3', gate: 'G-03', tier: 'independent', expected: 'negative', verdict: 'blocked', owner: 'label-custodian', artifactDigest: candidate,
    blocked: 'the withheld variant must be held and run by an independent party; none is available to this run' });
  cases.push({ ...base, caseId: 'PILOT-10', requirement: 'FR-08.4', gate: 'G-05', tier: 'staging', expected: 'positive', verdict: 'blocked', owner: 'incident-lead', artifactDigest: candidate,
    blocked: 'the sensor-loss drill needs the owner-authorized staging deployment and alert destination' });
  cases.push({ ...base, caseId: 'PILOT-11', requirement: 'FR-02', gate: 'G-03', expected: 'negative', verdict: 'blocked', owner: 'service-owner', artifactDigest: candidate,
    blocked: 'the workflow invariant executes through the trust boundary (test/invariants/approval-workflow.test.js); this assembler does not run it' });
  const window = { start, end: lastAt };
  const records = { scanner, target: { repository: 'synthetic-pilot', service: 'records-service', artifactDigest: candidate, deploymentProfile: 'local-pilot', window }, telemetry: { feeds: [{ name: 'records-service-log', lastHeartbeat: lastAt }] }, cases };

  // app-to-cloud export chain: the store adjudicates with its own evaluator
  const fetchVia = async (policy, key) => { const s = await startCloudChain({ policy }); try { const res = await fetch(`${s.url}/export?key=${encodeURIComponent(key)}`); return { status: res.status, body: await res.text() }; } finally { await s.close(); } };
  const SENSITIVE = 'arn:aws:s3:::records/tenant-b/report.csv';
  const cloudTarget = { repository: 'synthetic-pilot', service: 'export-chain', artifactDigest: cloudArtifactDigest(), policyDigest: policyDigest('fixed'), deploymentProfile: 'local-pilot', window };
  const cc = (caseId, expected, observed, extra = {}) => ({ ...base, caseId, requirement: 'FR-08.3', gate: 'G-03', expected, verdict: 'recorded', reasonCode: 'store-adjudicated', owner: 'platform-iam',
    artifactDigest: cloudTarget.artifactDigest, policyDigest: cloudTarget.policyDigest, observed, ...extra });
  const v = await fetchVia('vulnerable', 'tenant-b/report.csv'); const f = await fetchVia('fixed', 'tenant-b/report.csv'); const own = await fetchVia('fixed', 'tenant-a/report.csv');
  const chain = { scanner, target: cloudTarget, cases: [
    cc('PILOT-12-cloud-vulnerable', 'positive', { status: v.status, forbiddenEffect: v.body === OBJECTS[SENSITIVE] }, { vulnerablePolicy: policyDigest('vulnerable') }),
    cc('PILOT-12-cloud-fixed', 'negative', { status: f.status, forbiddenEffect: f.body === OBJECTS[SENSITIVE] }),
    cc('PILOT-12-cloud-legitimate', 'legitimate', { status: own.status, legitimateEffect: own.status === 200 && own.body === 'MARKER-A-REPORT' }),
  ] };

  // records search over a database: a fixed tautology, results capped, the database discarded after each run
  const dbTarget = { repository: 'synthetic-pilot', service: 'records-search', artifactDigest: dbArtifactDigest('fixed'), deploymentProfile: 'local-pilot', window };
  const proof = { tenant: 'tenant-a', name: "invoice' OR '1'='1" };
  const dc = (caseId, expected, observed, extra = {}) => ({ ...base, caseId, requirement: 'FR-08.3', gate: 'G-03', expected, verdict: 'recorded', reasonCode: 'db-oracle', owner: 'service-owner', artifactDigest: dbTarget.artifactDigest, observed, ...extra });
  const db = { scanner, target: dbTarget, cases: [
    dc('PILOT-12-db-vulnerable', 'positive', { forbiddenEffect: runDbSearch('vulnerable', proof).otherTenantMarker }, { vulnerableArtifact: dbArtifactDigest('vulnerable') }),
    dc('PILOT-12-db-fixed', 'negative', { forbiddenEffect: runDbSearch('fixed', proof).otherTenantMarker }),
    dc('PILOT-12-db-legitimate', 'legitimate', { legitimateEffect: runDbSearch('fixed', { tenant: 'tenant-a', name: 'invoice' }).ownMarker }),
  ] };

  return { 'records-service': records, 'export-chain': chain, 'records-search': db };
}
