// M0-06: a finding the original files already had is not "introduced" by a patch, but only when the baseline rescan reproduces the
// finding being fixed. Otherwise a weakness still present under another id could be that finding, and nothing is excused.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../../src/runScan.js';
import { verifyPatch as rescanPatch } from '../../src/posture/fix-verify.js';

const ORIGINAL = "const jwtSecret = 'a-very-long-hardcoded-jwt-signing-secret-value-123456';\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n";
const FROM_ENV = "const jwtSecret = process.env.JWT_SECRET;\nif (!jwtSecret) throw new Error('JWT_SECRET is not set');\nexports.sign = (jwt, claims) => jwt.sign(claims, jwtSecret);\n";

async function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'preex-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
  fs.writeFileSync(path.join(root, 'app.js'), ORIGINAL);
  const { scan } = await runScan(root);
  return { root, findings: scan.findings.filter((f) => f.file === 'app.js') };
}

test('a pre-existing finding is retained and reported, not counted as introduced', async () => {
  const { root, findings } = await fixture();
  try {
    const target = findings.find((f) => f.cwe === 'CWE-798');
    assert.ok(target, 'the hardcoded secret is found');
    const r = await rescanPatch({ scanRoot: root, originalFindingStableId: target.stableId, files: { 'app.js': FROM_ENV } });
    assert.equal(r.targetReproduced, true);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.preExisting.length >= 1, 'the JWT findings the file already had are listed');
    assert.deepEqual(r.introduced, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('with a target the baseline cannot reproduce, nothing is excused', async () => {
  const { root } = await fixture();
  try {
    const r = await rescanPatch({ scanRoot: root, originalFindingStableId: 'feedfacefeedface', files: { 'app.js': FROM_ENV } });
    assert.equal(r.targetReproduced, false);
    assert.equal(r.ok, false);
    assert.ok(r.introduced.length >= 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
