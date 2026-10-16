// E5-02: a mismatched build can never be labelled as runtime corroborating a static finding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { IDENTITY_FIELDS, STRONG_FIELDS, canCorroborate, linkObservationToSnapshot, normalizeIdentity, observationIdentity } from '../../src/lineage/deployment-identity.js';
import { correlateWithBuild, snapshotIdentityOf } from '../../src/lineage/build-attested-correlation.js';
import { correlateObservations } from '../../src/lineage/observation-correlation.js';
import { annotateRuntimeCorrelation } from '../../src/posture/runtime-correlation.js';

const C1 = 'a'.repeat(40); const C2 = 'b'.repeat(40);
const D1 = 'sha256:' + '1'.repeat(64); const D2 = 'sha256:' + '2'.repeat(64);
const link = (o, s) => linkObservationToSnapshot(o, s);

test('the rules: one disagreement is a mismatch whatever else agrees; a strong field in agreement is a match; no comparable identity is unknown', () => {
  assert.equal(link({ commit: C1 }, { commit: C1 }).state, 'matched');
  assert.equal(link({ commit: C1 }, { commit: C2 }).state, 'mismatched');
  assert.equal(link({ commit: C1, imageDigest: D1 }, { commit: C1, imageDigest: D2 }).state, 'mismatched', 'the commit agrees and the image does not');
  assert.deepEqual(link({ commit: C1, imageDigest: D1 }, { commit: C1, imageDigest: D2 }).disagreed, ['imageDigest']);
  assert.equal(link({ imageDigest: D1 }, { imageDigest: D1 }).state, 'matched');
  assert.equal(link({ buildHash: 'build-42' }, { buildHash: 'build-42' }).state, 'matched');
  assert.equal(link({}, { commit: C1 }).state, 'unknown'); assert.match(link({}, { commit: C1 }).reasons[0], /observation carries no commit/);
  assert.equal(link({ commit: C1 }, {}).state, 'unknown'); assert.match(link({ commit: C1 }, {}).reasons[0], /snapshot carries no commit/);
  assert.equal(link({ commit: C1 }, { imageDigest: D1 }).state, 'unknown', 'different kinds of identity cannot be compared');
  assert.equal(link({ sbomRef: 'urn:sbom:1' }, { sbomRef: 'urn:sbom:1' }).state, 'unknown', 'an SBOM reference alone is not a strong tie');
  assert.deepEqual([...STRONG_FIELDS], ['commit', 'buildHash', 'imageDigest']); assert.deepEqual([...IDENTITY_FIELDS], ['commit', 'buildHash', 'imageDigest', 'sbomRef']);
});

test('commits compare by full sha or a prefix of at least 12; a short prefix, a different environment and a dirty snapshot do not match', () => {
  assert.equal(link({ commit: C1.slice(0, 12) }, { commit: C1 }).state, 'matched');
  assert.equal(link({ commit: C1.slice(0, 11) }, { commit: C1 }).state, 'unknown', 'a prefix under 12 is not a usable identity');
  assert.equal(link({ commit: C1, environment: 'staging' }, { commit: C1, environment: 'production' }).state, 'mismatched');
  assert.equal(link({ commit: C1, environment: 'production' }, { commit: C1, environment: 'production' }).state, 'matched');
  assert.equal(link({ commit: C1 }, { commit: C1, environment: 'production' }).state, 'matched', 'an environment only one side names is not a disagreement');
  const dirty = link({ commit: C1 }, { commit: C1, dirty: true });
  assert.equal(dirty.state, 'unknown'); assert.match(dirty.reasons[0], /uncommitted changes/);
  assert.equal(link({ commit: C1, imageDigest: D1 }, { commit: C1, imageDigest: D1, dirty: true }).state, 'matched', 'an image digest agreeing makes the dirty tree irrelevant');
  assert.equal(canCorroborate(link({ commit: C1 }, { commit: C1 })), true);
  for (const s of [{}, { commit: C2 }]) assert.equal(canCorroborate(link({ commit: C1 }, s)), false);
  assert.equal(canCorroborate(null), false);
});

test('hostile or malformed identity values are treated as absent, never as a match', () => {
  const n = normalizeIdentity({ commit: 'not hex', imageDigest: 'sha256:short', buildHash: 'has spaces', sbomRef: '../x', environment: 'a b' });
  assert.deepEqual(n, { commit: null, buildHash: null, imageDigest: null, sbomRef: null, environment: null, dirty: false });
  assert.equal(link({ commit: 'zzzz' }, { commit: 'zzzz' }).state, 'unknown');
  assert.equal(link(null, null).state, 'unknown');
  assert.deepEqual(observationIdentity(null), normalizeIdentity({}));
});

// ---- the lineage correlation ----------------------------------------------------------------------------------------------

const node = (id) => ({ id, kind: 'external', subtype: 'external-api', label: 'x', aliases: [], location: null, system: { application: 'repo', environment: null }, destination: null, storeDetail: null, queueDetail: null, externality: { value: 'external', evidenceRefs: [] }, lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [], confidence: { score: 0.9, tier: 'high' }, coverageStatus: 'modeled', coverageReason: null });
const graph = { schemaVersion: '1.0.0', graphId: 'dfg:repo:uncommitted:default', nodes: [node('node:n1'), node('node:n2'), node('node:n3')], edges: [], dataElements: [], flows: [{ id: 'flow:1', source: 'node:n3', sink: 'node:n1', edgeIds: [], dataElementIds: [] }, { id: 'flow:2', source: 'node:n3', sink: 'node:n2', edgeIds: [], dataElementIds: [] }], transformations: [], evidence: [] };
const obs = (id, over = {}) => ({ id: `observation:${id}`, version: '1.0.0', adapter: 'native-jsonl', source: 'otel-collector', environment: 'production', windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-01T02:00:00.000Z', matchedNodeIds: ['node:n1'], matchedEdgeIds: [], matchedFlowIds: ['flow:1'], attributes: {}, eventCountBand: '1', firstObservedAt: '2026-01-01T00:30:00.000Z', lastObservedAt: '2026-01-01T00:30:00.000Z', matchMethod: 'destination_literal', matchConfidence: 'high', retention: { expiresAt: null }, importedAt: '2026-01-01T01:00:00.000Z', ...over });
const SNAP = { commit: C1, environment: 'production' };

test('without a snapshot identity the original correlation is returned unchanged', () => {
  const o = [obs('1')];
  assert.deepEqual(correlateWithBuild(graph, o, {}), correlateObservations(graph, o, {}));
  assert.deepEqual(correlateWithBuild(graph, null, { snapshotIdentity: SNAP }), correlateObservations(graph, null, { snapshotIdentity: SNAP }), 'a store that was never consulted stays not_evaluated');
});

test('an observation from a DIFFERENT build is excluded and listed; it cannot make a flow observed, let alone corroborated', () => {
  const r = correlateWithBuild(graph, [obs('1')], { snapshotIdentity: SNAP, observationBuilds: { 'observation:1': { commit: C2 } } });
  assert.deepEqual(r.buildMismatchedObservationIds, ['observation:1']);
  assert.equal(r.byFlow['flow:1'].layer, 'not_observed_in_window');
  assert.equal(r.byFlow['flow:1'].corroboration, 'none');
  assert.deepEqual(r.observedFlowIds, []);
  assert.equal(r.buildLink.requested, true); assert.equal(r.buildLink.snapshot.commit, C1);
});

test('the same build corroborates; an observation with no identity is seen but only unattested; a mix is unattested', () => {
  const ok = correlateWithBuild(graph, [obs('1')], { snapshotIdentity: SNAP, observationBuilds: { 'observation:1': { commit: C1 } } });
  assert.equal(ok.byFlow['flow:1'].layer, 'runtime_observed'); assert.equal(ok.byFlow['flow:1'].corroboration, 'corroborated'); assert.deepEqual(ok.buildMismatchedObservationIds, []);
  const bare = correlateWithBuild(graph, [obs('1')], { snapshotIdentity: SNAP });
  assert.equal(bare.byFlow['flow:1'].layer, 'runtime_observed'); assert.equal(bare.byFlow['flow:1'].corroboration, 'unattested');
  const mix = correlateWithBuild(graph, [obs('1'), obs('2')], { snapshotIdentity: SNAP, observationBuilds: { 'observation:1': { commit: C1 } } });
  assert.equal(mix.byFlow['flow:1'].corroboration, 'unattested', 'one unattested contributor is enough to withhold corroboration');
  assert.equal(mix.byFlow['flow:2'].corroboration, 'none');
  const both = correlateWithBuild(graph, [obs('1'), obs('2')], { snapshotIdentity: SNAP, observationBuilds: { 'observation:1': { commit: C1 }, 'observation:2': { commit: C2 } } });
  assert.equal(both.byFlow['flow:1'].corroboration, 'corroborated', 'the mismatched one is excluded, the matching one stands'); assert.deepEqual(both.buildMismatchedObservationIds, ['observation:2']);
});

test('a snapshot whose tree is dirty cannot corroborate on the commit alone; an image digest still can', () => {
  const dirty = correlateWithBuild(graph, [obs('1')], { snapshotIdentity: { ...SNAP, dirty: true }, observationBuilds: { 'observation:1': { commit: C1 } } });
  assert.equal(dirty.byFlow['flow:1'].corroboration, 'unattested');
  const image = correlateWithBuild(graph, [obs('1')], { snapshotIdentity: { ...SNAP, imageDigest: D1, dirty: true }, observationBuilds: { 'observation:1': { commit: C1, imageDigest: D1 } } });
  assert.equal(image.byFlow['flow:1'].corroboration, 'corroborated');
});

test('the snapshot identity of a real checkout: the commit, and dirty when the tree has changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5b-'));
  try {
    const git = (...a) => execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { cwd: root, stdio: 'pipe' });
    git('init', '-q'); fs.writeFileSync(path.join(root, 'a.txt'), '1'); git('add', '-A'); git('commit', '-qm', 'one');
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    const clean = snapshotIdentityOf(root, { environment: 'production' });
    assert.equal(clean.commit, head); assert.equal(clean.dirty, false); assert.equal(clean.environment, 'production');
    fs.writeFileSync(path.join(root, 'a.txt'), '2');
    assert.equal(snapshotIdentityOf(root).dirty, true);
    assert.equal(snapshotIdentityOf(os.tmpdir() + '/definitely-not-a-repo-xyz').commit, null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ---- the older trace path -------------------------------------------------------------------------------------------------

function trace(lines) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5c-'));
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), lines.map((l) => JSON.stringify({ ts: new Date().toISOString(), kind: 'function-call', qid: 'q', fileRel: 'src/a.js', line: 10, ...l })).join('\n'));
  return root;
}

test('trace records from another build are dropped and counted; matching ones corroborate; unidentified ones leave it unattested', async () => {
  const finding = () => [{ id: 'f', severity: 'high', file: 'src/a.js', line: 10, scope: 'q' }];
  const matching = trace([{ commit: C1 }, { commit: C1 }]);
  const other = trace([{ commit: C2 }]);
  const mixed = trace([{ commit: C1 }, {}]);
  const none = trace([{}]);
  try {
    let f = finding(); const a = await annotateRuntimeCorrelation(matching, f, { snapshotIdentity: SNAP });
    assert.equal(f[0].runtimeObserved, true); assert.equal(f[0].runtimeEvidence.corroboration, 'corroborated');
    f = finding(); await annotateRuntimeCorrelation(other, f, { snapshotIdentity: SNAP });
    assert.equal(f[0].runtimeObserved, 'unknown', 'the only record is from another build: there is no usable trace'); assert.notEqual(f[0].runtimeEvidence.corroboration, 'corroborated');
    f = finding(); await annotateRuntimeCorrelation(mixed, f, { snapshotIdentity: SNAP });
    assert.equal(f[0].runtimeEvidence.corroboration, 'unattested');
    f = finding(); await annotateRuntimeCorrelation(none, f, {});
    assert.equal(f[0].runtimeEvidence.corroboration, 'unattested', 'no snapshot identity: seen, never corroborated');
    assert.equal(a.observed, 1);
  } finally { for (const r of [matching, other, mixed, none]) fs.rmSync(r, { recursive: true, force: true }); }
});
