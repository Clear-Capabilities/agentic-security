// Signed provenance evidence bundles (Finding Provenance PRD, M4 §4.1).
// Mirrors test/evidence-bundle.test.js's conventions for the sibling module:
// a throwaway Ed25519 keypair per test via ensureKeyPair(tmpKeyDir()) — not
// node:crypto's generateKeyPairSync via a CJS require() shim, which doesn't
// belong in an ESM test file and isn't needed when ensureKeyPair already
// does exactly this.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ensureKeyPair, buildProvenanceEvidenceBundle, signProvenanceEvidenceBundle,
  verifyProvenanceEvidenceBundle, PROVENANCE_BUNDLE_SCHEMA,
} from '../../src/posture/provenance-evidence-bundle.js';

const tmpKeyDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'prov-attest-'));

const SAMPLE_FINDING = {
  id: 'f1', stableId: 'sid-1',
  findingProvenance: {
    status: 'complete',
    findingOrigin: { commit: 'abc123', authorName: 'Alice', authorDate: '2026-01-01T00:00:00Z', summary: 'add sqli' },
    branchIntroduction: { commit: 'def456', branch: 'main' },
    evidenceAttribution: [{ role: 'sink', path: 'a.js', line: 10, commit: 'abc123' }],
    method: 'semantic-history-replay',
    confidence: { level: 'high', score: 0.95, reasons: ['parent_absence_verified'] },
    limitations: [],
    analysisBasis: { head: 'abc123' },
  },
};

function signed(dir) {
  const kp = ensureKeyPair(dir);
  const bundle = signProvenanceEvidenceBundle(buildProvenanceEvidenceBundle(SAMPLE_FINDING, {}), kp.privateKeyPem);
  return { kp, bundle };
}

test('buildProvenanceEvidenceBundle: returns null for a finding with no findingProvenance', () => {
  assert.equal(buildProvenanceEvidenceBundle({ id: 'x' }), null);
  assert.equal(buildProvenanceEvidenceBundle(null), null);
});

test('buildProvenanceEvidenceBundle: copies the allowlisted fields, nothing invented', () => {
  const b = buildProvenanceEvidenceBundle(SAMPLE_FINDING, { engineVersion: '1.0.0', repoIdentity: 'owner/repo', head: 'abc123' });
  assert.equal(b.schema, PROVENANCE_BUNDLE_SCHEMA);
  assert.equal(b.finding.stableId, 'sid-1');
  assert.equal(b.provenance.findingOrigin.commit, 'abc123');
  assert.equal(b.provenance.confidence.level, 'high');
  assert.equal(b.repo.identity, 'owner/repo');
});

test('sign + verify: a genuinely signed bundle verifies with the matching public key', () => {
  const { kp, bundle } = signed(tmpKeyDir());
  const r = verifyProvenanceEvidenceBundle(bundle, kp.publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});

test('verify: a tampered field after signing fails verification', () => {
  const { kp, bundle } = signed(tmpKeyDir());
  bundle.provenance.confidence.level = 'high'; // already high — mutate something else to guarantee a real change
  bundle.provenance.findingOrigin.commit = 'tampered000';
  const r = verifyProvenanceEvidenceBundle(bundle, kp.publicKeyPem);
  assert.equal(r.ok, false);
});

test('verify: an unknown top-level key stapled on after signing is rejected (EA-03 class)', () => {
  const { kp, bundle } = signed(tmpKeyDir());
  bundle.extraClaim = 'verified beyond doubt';
  const r = verifyProvenanceEvidenceBundle(bundle, kp.publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised top-level key/);
});

test('verify: wrong public key fails', () => {
  const { bundle } = signed(tmpKeyDir());
  const stranger = ensureKeyPair(tmpKeyDir());
  const r = verifyProvenanceEvidenceBundle(bundle, stranger.publicKeyPem);
  assert.equal(r.ok, false);
});

test('verify: unsigned bundle is rejected', () => {
  const bundle = buildProvenanceEvidenceBundle(SAMPLE_FINDING, {});
  const r = verifyProvenanceEvidenceBundle(bundle, 'irrelevant');
  assert.equal(r.ok, false);
  assert.match(r.reason, /unsigned/);
});

test('verify: unrecognised schema is rejected before touching the signature', () => {
  const r = verifyProvenanceEvidenceBundle({ schema: 'something-else' }, 'irrelevant');
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised schema/);
});
