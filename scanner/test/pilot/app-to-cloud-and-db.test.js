// Threat-model PRD FR-08.3, PILOT-12: one app-to-cloud chain and one bounded database-backed injection proof. In each, the vulnerable
// scenario shows the sensitive effect, the fixed control does not, and the allowed workflow still works; the graph's action-specific
// prediction is compared with an effect the object store adjudicates with its own evaluator. Results feed the candidate gate G-03.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { POLICIES, OBJECTS, startCloudChain, runDbSearch, dbArtifactDigest, policyDigest } from '../fixtures/pilot/cloud-and-db.mjs';
import { parseIamPolicy } from '../../src/lineage/deployment/adapter-cloud.js';
import { computeAttackPaths } from '../../src/lineage/deployment/attack-paths.js';
import { resourceMatches } from '../../src/lineage/deployment/iam-eval.js';
import { evaluateCandidate } from '../../src/posture/assurance/candidate-qualification.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { node, edge, graphOf } from '../deployment/path-helpers.js';

const SENSITIVE = 'arn:aws:s3:::records/tenant-b/report.csv';
const CONTEXT = { 'aws:PrincipalTag/tenant': 'tenant-a' };

/** The graph's prediction: can the export route reach, with s3:GetObject, a resource pattern that covers tenant B's object? */
function predict(policyName) {
  const pol = parseIamPolicy(JSON.stringify(POLICIES[policyName]), { file: `iam/${policyName}.json`, identity: 'app', environment: 'prod', digest: digestOf(policyName) });
  const route = node('route', 'edge/export', { trustZone: 'public' }); const svc = node('service', 'shop/export'); const ident = node('identity', 'iam/app');
  const g = graphOf({ nodes: [route, svc, ident, ...pol.nodes], edges: [edge('routes-to', route, svc), edge('assumes', svc, ident), ...pol.edges], gaps: pol.gaps });
  const r = computeAttackPaths(g, { action: 's3:GetObject', context: CONTEXT });
  const covering = r.paths.filter((p) => resourceMatches(p.target.name.replace(/^aws\//, ''), SENSITIVE));
  const states = [...new Set(covering.map((p) => p.state))];
  return { state: states.includes('possible') ? 'possible' : states.includes('unresolved') ? 'unresolved' : states.length ? states[0] : 'no-path', truncated: r.truncated };
}
async function observe(policy, key) {
  const svc = await startCloudChain({ policy });
  try { const res = await fetch(`${svc.url}/export?key=${encodeURIComponent(key)}`); const body = await res.text(); return { status: res.status, body }; } finally { await svc.close(); }
}

test('PILOT-12 cloud: the vulnerable policy reaches tenant B\'s object as predicted, the fixed one does not, and the own-tenant read works', async () => {
  const v = await observe('vulnerable', 'tenant-b/report.csv');
  assert.equal(v.body, OBJECTS[SENSITIVE], 'the forbidden effect is observed under the vulnerable policy');
  assert.equal(predict('vulnerable').state, 'possible', 'and the graph predicted a possible path to it');
  const f = await observe('fixed', 'tenant-b/report.csv');
  assert.equal(f.status, 403); assert.notEqual(f.body, OBJECTS[SENSITIVE]);
  assert.equal(predict('fixed').state, 'no-path', 'the repaired policy grants no pattern covering the object');
  const own = await observe('fixed', 'tenant-a/report.csv');
  assert.equal(own.body, 'MARKER-A-REPORT', 'the allowed workflow still works under the repair');
  assert.equal(predict('vulnerable').truncated, false);
});

test('PILOT-12 cloud: a conditional deny is decided by the store and stays unresolved in the graph without the request context', async () => {
  assert.equal((await observe('conditional', 'tenant-b/report.csv')).status, 403, 'the store applies the condition to the request');
  const pol = parseIamPolicy(JSON.stringify(POLICIES.conditional), { file: 'iam/c.json', identity: 'app', environment: 'prod', digest: digestOf('c') });
  const route = node('route', 'edge/export', { trustZone: 'public' }); const svc = node('service', 'shop/export'); const ident = node('identity', 'iam/app');
  const g = graphOf({ nodes: [route, svc, ident, ...pol.nodes], edges: [edge('routes-to', route, svc), edge('assumes', svc, ident), ...pol.edges] });
  assert.equal(computeAttackPaths(g, { action: 's3:GetObject' }).paths[0].state, 'unresolved', 'no tenant tag in the context: the graph does not guess');
  assert.equal(computeAttackPaths(g, { action: 's3:GetObject', context: CONTEXT }).paths[0].state, 'blocked', 'with the tag it decides the same as the store');
});

test('PILOT-12 database: the concatenated query returns another tenant\'s record, the bound query does not, and the exact search works', () => {
  const proof = { tenant: 'tenant-a', name: "invoice' OR '1'='1" };
  assert.equal(runDbSearch('vulnerable', proof).otherTenantMarker, true, 'the injection reaches tenant B\'s row');
  const fixed = runDbSearch('fixed', proof);
  assert.equal(fixed.otherTenantMarker, false); assert.equal(fixed.rows, 0);
  const legit = runDbSearch('fixed', { tenant: 'tenant-a', name: 'invoice' });
  assert.equal(legit.ownMarker, true); assert.equal(legit.otherTenantMarker, false);
  assert.notEqual(dbArtifactDigest('vulnerable'), dbArtifactDigest('fixed'));
});

test('PILOT-12 feeds the candidate gate: both scenarios meet their positive, negative and legitimate controls for the fixed artifacts', async () => {
  const exp = '2026-12-01T00:00:00Z'; const owner = 'service-owner';
  const v = await observe('vulnerable', 'tenant-b/report.csv'); const f = await observe('fixed', 'tenant-b/report.csv'); const own = await observe('fixed', 'tenant-a/report.csv');
  const proof = { tenant: 'tenant-a', name: "invoice' OR '1'='1" };
  const target = { artifactDigest: dbArtifactDigest('fixed'), policyDigest: policyDigest('fixed') };
  const c = (caseId, expected, observed) => ({ caseId, requirement: 'FR-08.3', gate: 'G-03', expected, verdict: 'recorded', owner, expires: exp, artifactDigest: target.artifactDigest, policyDigest: target.policyDigest, observed });
  const cases = [
    c('PILOT-12-cloud-vulnerable', 'positive', { forbiddenEffect: v.body === OBJECTS[SENSITIVE] }),
    c('PILOT-12-cloud-fixed', 'negative', { forbiddenEffect: f.body === OBJECTS[SENSITIVE] }),
    c('PILOT-12-cloud-legitimate', 'legitimate', { legitimateEffect: own.body === 'MARKER-A-REPORT' }),
    c('PILOT-12-db-vulnerable', 'positive', { forbiddenEffect: runDbSearch('vulnerable', proof).otherTenantMarker }),
    c('PILOT-12-db-fixed', 'negative', { forbiddenEffect: runDbSearch('fixed', proof).otherTenantMarker }),
    c('PILOT-12-db-legitimate', 'legitimate', { legitimateEffect: runDbSearch('fixed', { tenant: 'tenant-a', name: 'invoice' }).ownMarker }),
  ];
  const d = evaluateCandidate({ target, cases }, { requiredGates: ['G-03'], now: Date.parse('2026-11-08T12:00:00Z') });
  assert.equal(d.gates['G-03'].outcome, 'met', JSON.stringify(d.gates['G-03']));
});
