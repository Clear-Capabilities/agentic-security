// REL-002.AC02: migration tests preserve old artifacts through adapters and retain the previous
// reader/policy where rollback is supported. Includes the one known hard break: a verifier older than
// CORE-003 rejects newly signed evidence bundles.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  ensureKeyPair, buildEvidenceBundle, signEvidenceBundle, verifyEvidenceBundle, canonicalBytes,
} from '../../src/posture/evidence-bundle.js';
import { migrateRecord, toLegacyVerificationView } from '../../src/posture/assurance/migrations.js';
import {
  READER_POLICY, PRE_CORE_003_BUNDLE_KEYS, verifyWithPreCore003Reader, exportLegacyBundle,
} from '../../src/posture/assurance/rollback.js';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO } from '../helpers/closure-fixtures.js';

const FINDING = { id: 'f1', stableId: 's1', severity: 'high', file: 'app.js', line: 42, vuln: 'SQL Injection', cwe: 'CWE-89', family: 'injection', parser: 'IR-TAINT', proofTier: 'unproven' };
const HEX = 'ab'.repeat(32);
const COMMIT = 'c'.repeat(40);

function keys() { return ensureKeyPair(mkTestTmp('rel-keys-')); }
/** A bundle exactly as the signer worked BEFORE CORE-003: no issuance block. */
function oldStyleBundle(kp) {
  const unsigned = buildEvidenceBundle(FINDING, { engineVersion: '0.100.0' });
  const sig = crypto.sign(null, canonicalBytes(unsigned), kp.privateKeyPem);
  return { ...unsigned, signature: { algorithm: 'ed25519', canonicalisation: unsigned.schema, value: sig.toString('base64') } };
}

// One legacy input per record kind the adapters accept, with what it must NOT become.
const LEGACY = {
  verification: { input: { status: true }, ctx: { hypothesisId: 'hyp-1', commit: COMMIT }, never: ['confirmed', 'refuted'], field: 'outcome' },
  capabilityDecision: { input: { decision: 'allow', provider: 'p', purpose: 'triage', reason: 'ok' }, ctx: {}, field: 'enforced', expect: false },
  routingLabel: { input: { taskId: 't1', model: 'm1', correct: true }, ctx: {}, never: ['correct', 'incorrect'], field: 'outcome' },
  releaseEvidence: { input: { commit: COMMIT, bundleDigest: `sha256:${HEX}`, verified: true, checks: [{ id: 'unit', status: 'pass' }] }, ctx: {}, field: 'complete', expect: false },
  observationBinding: { input: { id: 'obs-1', adapter: 'otel', matchedNodeIds: ['n1'], windowStart: '2026-01-01T00:00:00Z', windowEnd: '2026-01-02T00:00:00Z' }, ctx: { hypothesisId: 'hyp-1' }, field: 'completeness', expect: 'unknown' },
};

test('[REL-002.AC02] every legacy artifact kind still reads through its adapter, and evidence is lost rather than invented', () => {
  for (const [kind, c] of Object.entries(LEGACY)) {
    const r = migrateRecord(kind, c.input, c.ctx);
    assert.equal(r.ok, true, `${kind}: ${JSON.stringify(r.errors)}`);
    assert.ok(r.record.migration, `${kind}: the record says where it came from`);
    if (c.never) assert.equal(c.never.includes(r.record[c.field]), false, `${kind}: legacy "true" must not become ${c.never.join('/')} (got ${r.record[c.field]})`);
    if ('expect' in c) assert.equal(r.record[c.field], c.expect, `${kind}.${c.field}`);
  }
  // a current-format record is validated, never rewritten
  const rec = migrateRecord('verification', LEGACY.verification.input, LEGACY.verification.ctx).record;
  const again = migrateRecord('verification', rec);
  assert.equal(again.ok, true);
  assert.deepEqual(again.record, rec);
  // an unsupported major version is rejected, not coerced
  assert.equal(migrateRecord('verification', { ...rec, schemaVersion: '9.0.0' }).ok, false);
  // and the legacy view never reports a skipped check as passed
  assert.equal(toLegacyVerificationView(rec).verified, null);
});

test('[REL-002.AC02] a reader policy exists for every record kind and says honestly whether a previous reader is retained', () => {
  for (const kind of [...Object.keys(LEGACY), 'evidenceBundle']) {
    const p = READER_POLICY[kind];
    assert.ok(p, `${kind} has a reader policy`);
    assert.equal(typeof p.rollbackSupported, 'boolean');
    assert.ok(p.note.length > 20, `${kind}: the limitation is written down`);
    if (p.rollbackSupported) assert.ok(p.previousReader, `${kind}: rollback is supported, so a previous reader is named`);
    else assert.equal(p.previousReader, null, `${kind}: no previous reader is claimed where none exists`);
  }
  // the two supported kinds really have a working previous reader
  assert.equal(typeof toLegacyVerificationView, 'function');
  assert.equal(typeof verifyWithPreCore003Reader, 'function');
  assert.equal(READER_POLICY.verification.rollbackSupported, true);
  assert.equal(READER_POLICY.evidenceBundle.rollbackSupported, true);
  for (const k of ['observationBinding', 'capabilityDecision', 'routingLabel', 'releaseEvidence']) assert.equal(READER_POLICY[k].rollbackSupported, false, `${k} is declared unsupported, not silently assumed`);
});

test('[REL-002.AC02] KNOWN BREAK: a verifier older than CORE-003 rejects a newly signed bundle (strict unknown-key rule)', () => {
  const kp = keys();
  const fresh = signEvidenceBundle(buildEvidenceBundle(FINDING, { engineVersion: '9.9.9' }), kp.privateKeyPem);
  assert.ok(fresh.issuance, 'new bundles carry the issuance block');
  const old = verifyWithPreCore003Reader(fresh, kp.publicKeyPem);
  assert.equal(old.ok, false, 'the old reader rejects the new bundle');
  assert.match(old.reason, /unrecognised top-level key\(s\).*issuance/);
  const now = verifyEvidenceBundle(fresh, kp.publicKeyPem);
  assert.equal(now.ok, true, now.reason);
  assert.equal(now.trustBasis, 'self-issued-local-key');
  // the break is the key list, nothing else: the old key set is exactly the new one minus issuance
  assert.deepEqual([...PRE_CORE_003_BUNDLE_KEYS].sort(), ['doesNotProve', 'engine', 'evidence', 'finding', 'proves', 'schema', 'signature']);
  // the strict rule is not loosened to make the old reader pass: a stapled field is still rejected by the old reader
  const stapled = { ...oldStyleBundle(kp), verdict: 'safe' };
  assert.equal(verifyWithPreCore003Reader(stapled, kp.publicKeyPem).ok, false);
  assert.equal(verifyEvidenceBundle(stapled, kp.publicKeyPem).ok, false);
});

test('[REL-002.AC02] old artifacts stay readable: a pre-CORE-003 bundle verifies under both readers, reported as having no declared trust basis', () => {
  const kp = keys();
  const old = oldStyleBundle(kp);
  assert.equal(old.issuance, undefined);
  assert.equal(verifyWithPreCore003Reader(old, kp.publicKeyPem).ok, true, 'the old reader still accepts it');
  const v = verifyEvidenceBundle(old, kp.publicKeyPem);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.trustBasis, 'none-declared');
  assert.equal(v.independentlyCertified, false);
  // a tampered old bundle fails under both
  const tampered = { ...old, finding: { ...old.finding, severity: 'low' } };
  assert.equal(verifyWithPreCore003Reader(tampered, kp.publicKeyPem).ok, false);
  assert.equal(verifyEvidenceBundle(tampered, kp.publicKeyPem).ok, false);
});

test('[REL-002.AC02] migration path: a consumer that cannot upgrade gets a legacy export plus a sidecar, never a silent downgrade', () => {
  const kp = keys();
  const fresh = signEvidenceBundle(buildEvidenceBundle(FINDING, { engineVersion: '9.9.9' }), kp.privateKeyPem);
  const ex = exportLegacyBundle(fresh, kp.privateKeyPem);
  assert.equal(ex.ok, true, ex.reason);
  assert.equal(ex.bundle.issuance, undefined, 'the export carries no issuance block');
  assert.equal(verifyWithPreCore003Reader(ex.bundle, kp.publicKeyPem).ok, true, 'the pre-CORE-003 verifier accepts the export');
  const cur = verifyEvidenceBundle(ex.bundle, kp.publicKeyPem);
  assert.equal(cur.ok, true);
  assert.equal(cur.trustBasis, 'none-declared', 'the current verifier reports the lost trust basis, it does not invent one');
  assert.equal(cur.independentlyCertified, false);
  assert.deepEqual(ex.bundle.finding, fresh.finding, 'the content is unchanged');
  // the disclosure that cannot ride inside the bundle is in the sidecar
  assert.equal(ex.sidecar.droppedIssuance.trustBasis, 'self-issued-local-key');
  assert.match(ex.sidecar.note, /no longer inside the signed bytes/);
  assert.match(ex.sidecar.note, /Upgrade the verifier/);
  assert.match(ex.sidecar.originalBundleDigest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(ex.sidecar.originalBundleDigest, ex.sidecar.exportedBundleDigest);
  // the original is untouched
  assert.ok(fresh.issuance);
});

test('[REL-002.AC02] the legacy export refuses a tampered bundle, a bundle signed by another key, and an unusable key', () => {
  const kp = keys();
  const other = keys();
  const fresh = signEvidenceBundle(buildEvidenceBundle(FINDING, { engineVersion: '9.9.9' }), kp.privateKeyPem);
  const tampered = { ...fresh, finding: { ...fresh.finding, severity: 'low' } };
  const a = exportLegacyBundle(tampered, kp.privateKeyPem);
  assert.equal(a.ok, false);
  assert.match(a.reason, /does not verify under this key/);
  const b = exportLegacyBundle(fresh, other.privateKeyPem);
  assert.equal(b.ok, false, 'a bundle this key did not sign is not re-signed');
  assert.equal(exportLegacyBundle(fresh, 'not a key').ok, false);
  assert.equal(exportLegacyBundle(null, kp.privateKeyPem).ok, false);
});

test('[REL-002.AC02] the migration guide documents the break and the path', () => {
  const guide = fs.readFileSync(path.join(REPO, 'docs', 'guides', 'assurance-rollout-and-rollback.md'), 'utf8');
  assert.match(guide, /older than CORE-003/);
  assert.match(guide, /exportLegacyBundle/);
  assert.match(guide, /unrecognised top-level key/);
  assert.match(guide, /none-declared/);
  for (const k of Object.keys(READER_POLICY)) assert.ok(guide.includes(`\`${k}\``), `guide lists reader policy for ${k}`);
});
