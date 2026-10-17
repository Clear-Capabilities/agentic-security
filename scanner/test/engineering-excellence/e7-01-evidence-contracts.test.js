// E7-01: every kind of evidence names its schema and identity in a readable way, can be bound to an immutable snapshot, and forms a lineage that is checked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSamples } from '../../../scripts/engineering-excellence/lib/evidence-samples.mjs';
import {
  EVIDENCE_KINDS, EVIDENCE_KIND_NAMES, EVIDENCE_REF_SCHEMA, EVIDENCE_REF_VERSION, buildEvidenceRef, buildSnapshotRef, checkLineage, describeEvidence,
  inspectEvidence, observeSnapshotBinding, verifyEvidenceRef, verifySnapshotRef,
} from '../../src/posture/assurance/evidence-registry.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { migrateRecord, toLegacyVerificationView } from '../../src/posture/assurance/migrations.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const C = 'a'.repeat(40);
const { samples, notExercised, finding } = await buildSamples();
const snap = buildSnapshotRef({ commit: C, engineVersion: 'test', configDigest: digestOf({ k: 1 }) });

test('the inventory covers sixteen kinds, every producer exists, and the one kind without a producer in a scan is named', () => {
  assert.equal(EVIDENCE_KIND_NAMES.length, 16);
  for (const k of EVIDENCE_KIND_NAMES) assert.ok(fs.existsSync(path.join(ROOT, EVIDENCE_KINDS[k].producer)), `${k}: ${EVIDENCE_KINDS[k].producer}`);
  assert.deepEqual(Object.keys(notExercised), ['release-evidence']); assert.match(notExercised['release-evidence'], /validator tests/);
  assert.equal(Object.keys(samples).length, 15); assert.ok(Object.isFrozen(EVIDENCE_KINDS));
});

test('every real record is described, usable, and its declared snapshot binding is what it actually carries', () => {
  for (const [kind, sample] of Object.entries(samples)) {
    const d = describeEvidence(kind, sample); assert.equal(d.ok, true, kind);
    const i = inspectEvidence(kind, sample); assert.deepEqual(i.errors, [], `${kind}: ${i.errors}`);
    assert.equal(observeSnapshotBinding(sample), EVIDENCE_KINDS[kind].snapshot, `${kind}: the producer's declared binding differs from what the record carries`);
    if (EVIDENCE_KINDS[kind].schemaRead.style !== 'none') { assert.ok(d.schema && d.version, `${kind} states its schema and version`); assert.match(d.version, /^\d+\.\d+\.\d+$|^\d+\.\d+$/); }
  }
  // three spellings of a schema are read into one shape
  assert.deepEqual([describeEvidence('finding-evidence', samples['finding-evidence']).version, describeEvidence('fix-verification', samples['fix-verification']).version, describeEvidence('scan-health', samples['scan-health']).version], ['1.0.0', '1.0.0', '1.0.0']);
  assert.equal(describeEvidence('finding', finding).schema, null, 'a finding declares no schema: reported as a gap, not invented');
  assert.ok(inspectEvidence('finding', finding).gaps.some((g) => /declares no schema/.test(g)));
  assert.ok(inspectEvidence('sbom', samples.sbom).gaps.some((g) => /random per run/.test(g)));
});

test('the two finding identities agree across kinds: bundles, provenance and the runtime explanation are keyed by the stable id', () => {
  const ids = ['finding-evidence', 'provenance-evidence', 'runtime-explanation'].map((k) => describeEvidence(k, samples[k]).id);
  assert.equal(new Set(ids).size, 1, ids.join(' vs ')); assert.equal(ids[0], finding.stableId);
  assert.equal(samples['runtime-explanation'].findingStableId, finding.stableId);
});

test('UNKNOWN KIND, NON-OBJECT, MISSING SCHEMA and a FUTURE MAJOR are refused', () => {
  assert.equal(describeEvidence('nonsense', {}).ok, false); assert.match(describeEvidence('nonsense', {}).reason, /unknown evidence kind/);
  assert.equal(inspectEvidence('fix-verification', null).ok, false);
  const noSchema = { ...samples['fix-verification'] }; delete noSchema.schema;
  assert.match(inspectEvidence('fix-verification', noSchema).errors.join(' '), /schema declaration/);
  const future = { ...samples['fix-verification'], schemaVersion: '2.0.0' };
  assert.match(inspectEvidence('fix-verification', future).errors.join(' '), /major version 2 is newer/);
  const noId = { ...samples['fix-verification'] }; delete noId.id;
  assert.match(inspectEvidence('fix-verification', noId).errors.join(' '), /identity fields/);
  assert.throws(() => buildEvidenceRef('nonsense', {}, snap), /unknown evidence kind/);
});

test('SNAPSHOT: a digest over commit, tree, engine, bundle and configuration; a dirty tree or no commit is not immutable; tampering is detected', () => {
  assert.equal(verifySnapshotRef(snap), true); assert.equal(snap.immutable, true);
  assert.equal(buildSnapshotRef({ commit: C, dirty: true }).immutable, false);
  assert.equal(buildSnapshotRef({}).immutable, false);
  assert.notEqual(buildSnapshotRef({ commit: C, engineVersion: 'a' }).digest, buildSnapshotRef({ commit: C, engineVersion: 'b' }).digest);
  assert.notEqual(buildSnapshotRef({ commit: C }).digest, buildSnapshotRef({ commit: 'b'.repeat(40) }).digest);
  assert.equal(verifySnapshotRef({ ...snap, commit: 'b'.repeat(40) }), false); assert.equal(verifySnapshotRef({ ...snap, immutable: false }), false); assert.equal(verifySnapshotRef(null), false);
  assert.equal(buildSnapshotRef({ commit: C, dirty: true }).digest === buildSnapshotRef({ commit: C }).digest, false, 'dirty is part of what the digest covers');
});

test('EVIDENCE REF: every real record gets a reference that verifies, is deterministic, and is bound to the snapshot', () => {
  for (const [kind, sample] of Object.entries(samples)) {
    const ref = buildEvidenceRef(kind, sample, snap);
    assert.equal(ref.schema, EVIDENCE_REF_SCHEMA); assert.equal(ref.schemaVersion, EVIDENCE_REF_VERSION); assert.equal(ref.snapshotDigest, snap.digest); assert.equal(ref.snapshotImmutable, true);
    assert.deepEqual(verifyEvidenceRef(ref, sample, snap), { ok: true, errors: [] }, kind);
    assert.deepEqual(buildEvidenceRef(kind, JSON.parse(JSON.stringify(sample)), snap), ref, `${kind}: same record, same reference`);
  }
  const dirty = buildSnapshotRef({ commit: C, dirty: true });
  assert.equal(buildEvidenceRef('verification', samples.verification, dirty).snapshotImmutable, false, 'evidence about a dirty tree says so');
});

test('TAMPERING: a changed record, a changed reference, a swapped snapshot, a swapped id and a forged digest are each rejected', () => {
  const sample = samples['fix-verification']; const ref = buildEvidenceRef('fix-verification', sample, snap);
  const bad = (r, p, s) => verifyEvidenceRef(r, p, s);
  assert.equal(bad(ref, { ...sample, verifiedFull: !sample.verifiedFull }, snap).ok, false);
  assert.match(bad(ref, { ...sample, patchHash: 'sha256:' + 'e'.repeat(64) }, snap).errors.join(' '), /does not match the digest/);
  assert.match(bad({ ...ref, payloadId: 'fvrec:0000000000000000' }, sample, snap).errors.join(' '), /altered after it was built/);
  assert.match(bad({ ...ref, snapshotImmutable: false }, sample, snap).errors.join(' '), /altered/);
  assert.match(bad(ref, sample, buildSnapshotRef({ commit: 'b'.repeat(40) })).errors.join(' '), /snapshot does not match/);
  assert.match(bad(ref, sample, { ...snap, commit: 'b'.repeat(40) }).errors.join(' '), /snapshot does not match/);
  assert.match(bad({ ...ref, kind: 'verification' }, sample, snap).errors.join(' '), /altered|differs/);
  assert.match(bad({ ...ref, digest: 'sha256:' + 'f'.repeat(64) }, sample, snap).errors.join(' '), /altered/);
  assert.equal(bad(null, sample, snap).ok, false); assert.equal(bad({ ...ref, schemaVersion: '2.0.0' }, sample, snap).ok, false);
  assert.throws(() => buildEvidenceRef('fix-verification', sample, { ...snap, commit: 'x' }), /not a valid snapshot/);
  assert.throws(() => buildEvidenceRef('fix-verification', sample, snap, { restsOn: ['not-a-digest'] }), /not a digest/);
});

test('PROVENANCE: findingProvenance and a bare provenance are carried separately and never merged; changing either is detected', () => {
  const { findingProvenance: _real, ...bare } = finding;
  const f = { ...bare, findingProvenance: { status: 'complete', findingOrigin: { commit: 'b'.repeat(40) } }, provenance: 'ai-generated' };
  const ref = buildEvidenceRef('finding', f, snap);
  assert.equal(ref.findingProvenanceDigest, digestOf(f.findingProvenance)); assert.equal(ref.otherProvenanceDigest, digestOf('ai-generated'));
  assert.notEqual(ref.findingProvenanceDigest, ref.otherProvenanceDigest);
  assert.equal(buildEvidenceRef('finding', { ...bare }, snap).findingProvenanceDigest, null);
  assert.equal(buildEvidenceRef('finding', { ...bare, provenance: 'x' }, snap).findingProvenanceDigest, null, 'a bare provenance is never read as the git origin');
  const tampered = { ...f, findingProvenance: { ...f.findingProvenance, status: 'unknown' } };
  assert.equal(verifyEvidenceRef(ref, tampered, snap).ok, false);
  const onlyOther = { ...f, provenance: 'human-written' };
  assert.equal(verifyEvidenceRef(ref, onlyOther, snap).ok, false, 'the payload digest covers the other provenance too');
});

test('LINEAGE: a chain verifies in dependency order; a dangling reference, a cycle, a different snapshot and a duplicate are each reported', () => {
  const f = buildEvidenceRef('finding', finding, snap);
  const fe = buildEvidenceRef('finding-evidence', samples['finding-evidence'], snap, { restsOn: [f.digest] });
  const fix = buildEvidenceRef('fix-verification', samples['fix-verification'], snap, { restsOn: [f.digest, fe.digest] });
  const ok = checkLineage([fix, f, fe]);
  assert.equal(ok.ok, true, ok.errors.join('; ')); assert.deepEqual(ok.order, [f.digest, fe.digest, fix.digest], 'dependencies come first, whatever order they were given');
  assert.deepEqual(checkLineage([fix, f, fe]).order, checkLineage([f, fe, fix]).order);
  const dangling = checkLineage([fix, fe]); assert.equal(dangling.ok, false); assert.match(dangling.errors.join(' '), /dangling/);
  const other = buildSnapshotRef({ commit: 'c'.repeat(40) });
  const elsewhere = buildEvidenceRef('verification', samples.verification, other, { restsOn: [f.digest] });
  assert.match(checkLineage([f, elsewhere]).errors.join(' '), /different snapshot/);
  assert.match(checkLineage([f, f]).errors.join(' '), /duplicate/);
  // a cycle cannot be built with honest refs (a digest covers restsOn), so forge two refs that point at each other
  const a = { ...f, digest: 'sha256:' + '1'.repeat(64), restsOn: ['sha256:' + '2'.repeat(64)] }; const b = { ...fe, digest: 'sha256:' + '2'.repeat(64), restsOn: ['sha256:' + '1'.repeat(64)] };
  assert.match(checkLineage([a, b]).errors.join(' '), /cycle/);
  assert.deepEqual(checkLineage([]), { ok: true, errors: [], order: [] });
});

test('COMPATIBILITY: legacy shapes migrate into a current record that the registry accepts, and a migration never invents confirmation', () => {
  const ctx = { hypothesisId: 'h1', commit: C, detectorOrigin: { detector: 'IR-TAINT' }, scope: { description: 'app.js', platform: 'node' } };
  const legacy = { proofEvidence: { tier: 'execution-proven', ran: true, observed: 'effect seen' } };
  const m = migrateRecord('verification', legacy, ctx);
  assert.equal(m.ok, true, JSON.stringify(m.errors));
  assert.equal(m.record.outcome, 'inconclusive', 'a legacy execution proof with no trusted runner is not a confirmation');
  assert.equal(describeEvidence('verification', m.record).ok, true); assert.deepEqual(inspectEvidence('verification', m.record).errors, []);
  assert.equal(verifyEvidenceRef(buildEvidenceRef('verification', m.record, snap), m.record, snap).ok, true);
  assert.equal(toLegacyVerificationView(m.record).verified, null, 'and a legacy consumer is not told it was verified');
  const trusted = migrateRecord('verification', legacy, { ...ctx, trustedRunner: true });
  assert.equal(trusted.record.outcome, 'confirmed'); assert.equal(trusted.record.evidence.length, 1);
  assert.equal(migrateRecord('verification', legacy, { commit: C }).ok, false, 'no hypothesis id: refused, not guessed');
  assert.equal(migrateRecord('verification', { proofEvidence: { tier: 'proof-failed', ran: true } }, ctx).record.outcome, 'inconclusive', 'a failed proof is not a refutation');
  assert.equal(migrateRecord('verification', { status: true }, ctx).record.outcome, 'inconclusive', 'a bare true is not a confirmation');
  // a current record passes through untouched; one with a future major is refused
  assert.equal(migrateRecord('verification', m.record, ctx).record.id, m.record.id);
  assert.equal(migrateRecord('verification', { ...m.record, schemaVersion: '2.0.0' }, ctx).ok, false);
  assert.equal(migrateRecord('nonsense', {}, ctx).ok, false);
});

test('the committed inventory is current', async () => {
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'engineering-excellence', 'evidence-inventory.mjs'), '--verify'], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
