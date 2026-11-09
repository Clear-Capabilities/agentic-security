// GA-10 §3 (0.195.31): exposure windows reconcile commit, image and deployment evidence. Pinned: two records that place different
// commits in one environment at one moment are both refused; a deployment that contains the fix but predates the fix commit is
// refused; a refused record makes the window `partial` with the reason in `unknowns` (it could have been the first vulnerable
// deployment); records spanning environments are flagged; exposure after the telemetry ends is reported, open-ended without a fix
// deployment; and the start and end of the exposure are explicit facts with their evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { computeExposureWindow, reconcileDeployments, formatExposureWindow } from '../../src/posture/dnr/exposure-window.js';

const A = 'a'.repeat(40); const B = 'b'.repeat(40); const FIX = 'f'.repeat(40); const C = 'c'.repeat(40);
// history: A (introduces) -> B -> FIX -> C
const order = [A, B, FIX, C];
const deps = { isAncestor: (anc, desc) => (order.includes(anc) && order.includes(desc) ? order.indexOf(anc) <= order.indexOf(desc) : null), commitDate: (sha) => (sha === FIX ? '2026-03-10T00:00:00.000Z' : null) };
const finding = { stableId: 'F1', findingProvenance: { findingOrigin: { commit: A, authorDate: '2026-03-01T00:00:00.000Z' } } };
const dep = (commit, deployedAt, environment = 'prod') => ({ commit, commitSource: 'deployment-record', deployedAt, environment, artifactDigest: null });

test('conflicting provenance: two records with different commits at the same moment in one environment are both refused, and the window says so', () => {
  const r = reconcileDeployments([dep(A, '2026-03-02T00:00:00.000Z'), dep(B, '2026-03-02T00:00:00.000Z'), dep(C, '2026-03-12T00:00:00.000Z')], { fixCommit: FIX, fixAt: '2026-03-10T00:00:00.000Z', isAncestor: deps.isAncestor });
  assert.deepEqual(r.deployments.map((d) => d.commit), [C]);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /conflicting provenance: 2 records place different commits/);
  const w = computeExposureWindow({ finding, deployments: [dep(A, '2026-03-02T00:00:00.000Z'), dep(B, '2026-03-02T00:00:00.000Z'), dep(C, '2026-03-12T00:00:00.000Z')], fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-20T00:00:00.000Z' }, deps });
  assert.equal(w.status, 'unavailable', 'the refused records were the only vulnerable deployments, so there is no exposure start');
  assert.ok(w.unknowns.some((u) => /1 deployment record\(s\) were refused/.test(u)), w.unknowns.join('; '));
  assert.equal(w.deploymentProblems.length, 1);
  assert.deepEqual(w.exposureStart, { at: null, evidence: 'none' });
});

test('a deployment that contains the fix but predates the fix commit is refused; without it the window is complete', () => {
  const bad = dep(C, '2026-03-05T00:00:00.000Z');
  const good = [dep(A, '2026-03-02T00:00:00.000Z'), dep(C, '2026-03-12T00:00:00.000Z')];
  const r = reconcileDeployments([...good, bad], { fixCommit: FIX, fixAt: '2026-03-10T00:00:00.000Z', isAncestor: deps.isAncestor });
  assert.equal(r.deployments.length, 2);
  assert.match(r.problems[0], /contains the fix but predates the fix commit/);
  const w = computeExposureWindow({ finding, deployments: [...good, bad], fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-20T00:00:00.000Z' }, deps });
  assert.equal(w.status, 'partial');
  assert.ok(w.unknowns.some((u) => /refused/.test(u)));
  const clean = computeExposureWindow({ finding, deployments: good, fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-20T00:00:00.000Z' }, deps });
  assert.equal(clean.status, 'complete', clean.unknowns.join('; '));
  assert.deepEqual(clean.exposureStart, { at: '2026-03-02T00:00:00.000Z', evidence: 'first-vulnerable-deployment' });
  assert.deepEqual(clean.exposureEnd, { at: '2026-03-12T00:00:00.000Z', evidence: 'fix-deployment' });
  assert.equal(clean.unobservableAfter, null);
});

test('records spanning environments are flagged, and a load-time refusal is carried into the unknowns too', () => {
  const w = computeExposureWindow({ finding, deployments: [dep(A, '2026-03-02T00:00:00.000Z', 'prod'), dep(A, '2026-03-02T00:00:00.000Z', 'staging'), dep(C, '2026-03-12T00:00:00.000Z', 'prod')], deploymentProblems: ['deployment 3: commit must be a hex sha'], fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-20T00:00:00.000Z' }, deps });
  assert.equal(w.status, 'partial');
  assert.ok(w.unknowns.some((u) => /span 2 environments \(prod, staging\)/.test(u)), w.unknowns.join('; '));
  assert.ok(w.unknowns.some((u) => /1 deployment record\(s\) were refused/.test(u)));
  assert.equal(w.deploymentProblems.length, 1);
});

test('exposure after the telemetry ends is reported, open-ended when the fix was never deployed', () => {
  const noFix = computeExposureWindow({ finding, deployments: [dep(A, '2026-03-02T00:00:00.000Z')], fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-08T00:00:00.000Z' }, deps });
  assert.deepEqual(noFix.unobservableAfter, { start: '2026-03-08T00:00:00.000Z', end: null, openEnded: true });
  assert.deepEqual(noFix.exposureEnd, { at: null, evidence: 'fix-not-deployed' });
  assert.equal(noFix.stillExposed, true);
  assert.match(formatExposureWindow(noFix), /Exposed but not observable: 2026-03-08 to present \(after telemetry ended\)/);
  const late = computeExposureWindow({ finding, deployments: [dep(A, '2026-03-02T00:00:00.000Z'), dep(C, '2026-03-12T00:00:00.000Z')], fixCommit: FIX, telemetry: { start: '2026-03-01T00:00:00.000Z', end: '2026-03-08T00:00:00.000Z' }, deps });
  assert.deepEqual(late.unobservableAfter, { start: '2026-03-08T00:00:00.000Z', end: '2026-03-12T00:00:00.000Z', openEnded: false });
  assert.deepEqual(late.observableWindow, { start: '2026-03-02T00:00:00.000Z', end: '2026-03-08T00:00:00.000Z', openEnded: false });
  assert.equal(late.status, 'complete', late.unknowns.join('; '));
});
