// A password migration keeps the legacy digest so existing users still log in once. That line is the original finding's text and keeps
// its stable id, so the central verifier excuses it only with a proof the repair coordinator built from oracle runs on exactly these
// files: new passwords stored under the approved KDF, legacy logins preserved, legacy values rewritten after login. Every missing part
// of the proof leaves the finding "still present".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyPatch, legacyRetainedForMigration, migrationFilesDigest, PASSWORD_MIGRATION_OBLIGATIONS } from '../../src/posture/fix-verify.js';
import { runFullScan } from '../../src/engine.js';

const ORIGINAL = "import crypto from 'node:crypto';\nexport function hashPassword(password) {\n  return crypto.createHash('md5').update(String(password)).digest('hex');\n}\n";
const MIGRATED = "import crypto from 'node:crypto';\nexport function hashPasswordLegacy(password) {\n  return crypto.createHash('md5').update(String(password)).digest('hex');\n}\n"
  + "export function hashPassword(password) {\n  const salt = crypto.randomBytes(16);\n  const key = crypto.scryptSync(String(password), salt, 32, { N: 16384, r: 8, p: 1 });\n  return ['scrypt', 16384, 8, 1, salt.toString('hex'), key.toString('hex')].join('$');\n}\n";
const FILE = 'src/auth.mjs';
const kept = (over = {}) => [{ vuln: 'weak password hash', file: FILE, line: 3, cwe: 'CWE-916', stableId: 's1', ...over }];
const files = { [FILE]: MIGRATED };
const proof = (over = {}) => ({ passed: [...PASSWORD_MIGRATION_OBLIGATIONS], filesDigest: migrationFilesDigest(files), ...over });

test('a complete proof bound to these files excuses a weak password hash kept beside an approved KDF', () => {
  const r = legacyRetainedForMigration(kept(), files, proof());
  assert.equal(r.length, 1);
  assert.match(r[0].reason, /kept for migration/);
});

test('each missing part of the proof refuses the excuse', () => {
  assert.equal(legacyRetainedForMigration(kept(), files, null), null, 'no proof');
  for (const id of PASSWORD_MIGRATION_OBLIGATIONS) {
    assert.equal(legacyRetainedForMigration(kept(), files, proof({ passed: PASSWORD_MIGRATION_OBLIGATIONS.filter((x) => x !== id) })), null, `without ${id}`);
  }
  assert.equal(legacyRetainedForMigration(kept(), files, proof({ filesDigest: migrationFilesDigest({ [FILE]: ORIGINAL }) })), null, 'a proof for other files');
  assert.equal(legacyRetainedForMigration(kept({ cwe: 'CWE-89' }), files, proof()), null, 'not a password hash finding');
  const noKdf = { [FILE]: ORIGINAL };
  assert.equal(legacyRetainedForMigration(kept(), noKdf, proof({ filesDigest: migrationFilesDigest(noKdf) })), null, 'no approved KDF in the file');
  assert.equal(legacyRetainedForMigration([], files, proof()), null, 'nothing kept');
});

test('end to end: the rescan rejects the kept legacy digest without a proof and accepts it with one', async () => {
  const scan = await runFullScan({ fileContents: { [FILE]: ORIGINAL }, scanRoot: process.cwd(), provenance: false }, () => {});
  const f = scan.findings.find((x) => /CWE-(?:916|327|328)/.test(String(x.cwe)));
  assert.ok(f, 'the original reports the digest');
  const without = await verifyPatch({ scanRoot: process.cwd(), originalFindingStableId: f.stableId, files });
  assert.equal(without.reason, 'original-finding-still-present', 'the legacy line keeps its stable id');
  const withProof = await verifyPatch({ scanRoot: process.cwd(), originalFindingStableId: f.stableId, files, migrationProof: proof() });
  assert.notEqual(withProof.reason, 'original-finding-still-present');
  assert.ok(withProof.retainedForMigration?.length >= 1);
});
