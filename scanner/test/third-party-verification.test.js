// PRD F7.3 — third-party bundle verification, tested as a third party.
//
// The claim an evidence bundle makes is not "this repo can verify it". It is
// "SOMEONE ELSE, holding only the public key and the bundle, can verify it".
// Every existing test verifies in-repo, importing src/ directly — which proves
// the crypto round-trips, and proves nothing about the claim.
//
// The difference is not pedantic. An in-repo test still passes if verification
// silently depends on the repo: a file read relative to the source tree, a
// module resolved from node_modules, a default key path under the project, a
// bundled artifact that never shipped in `files`. Any of those would make the
// published claim false while the suite stayed green.
//
// So this test packs the package the way npm publishes it, extracts it
// somewhere else, and runs the SHIPPED CLI from a working directory outside the
// repository, given nothing but a bundle and a public key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..');

let stage;        // where the packed package is extracted — NOT the repo
let outside;      // cwd for the verifying process — NOT the repo
let cli;          // the shipped CLI inside `stage`

function run(args, cwd) {
  return spawnSync(process.execPath, args, { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

before(() => {
  stage = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-stage-'));
  outside = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-cwd-'));

  // Pack exactly what npm would publish, then unpack it elsewhere. Anything the
  // package forgot to ship is simply absent here, which is the point.
  const packed = spawnSync('npm', ['pack', '--pack-destination', stage], {
    cwd: SCANNER, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(packed.status, 0, `npm pack failed: ${packed.stderr}`);
  const tgz = fs.readdirSync(stage).find((f) => f.endsWith('.tgz'));
  assert.ok(tgz, 'npm pack produced no tarball');

  const untar = spawnSync('tar', ['-xzf', path.join(stage, tgz), '-C', stage], { encoding: 'utf8' });
  assert.equal(untar.status, 0, `tar failed: ${untar.stderr}`);

  cli = path.join(stage, 'package', 'dist', 'agentic-security.mjs');
  assert.ok(fs.existsSync(cli), 'the packed package does not contain the CLI bundle');
});

after(() => {
  for (const d of [stage, outside]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('the packed package ships a runnable CLI', () => {
  // `version` is a SUBCOMMAND here, not a `--version` flag; the flag form
  // prints usage and exits 1. Using the flag was a bug in this test, not in the
  // CLI, and is recorded so the next reader does not re-file it.
  const r = run([cli, 'version'], outside);
  assert.equal(r.status, 0, `shipped CLI failed to start: ${r.stderr}`);
  assert.match(r.stdout.trim(), /\d+\.\d+\.\d+/);
});

test('a third party with only the bundle and public key verifies it', async () => {
  // Produce a signed bundle and export the PUBLIC key only. The private key
  // never leaves the generating side, exactly as in the real flow.
  const { buildEvidenceBundle, signEvidenceBundle, ensureKeyPair } =
    await import('../src/posture/evidence-bundle.js');

  const keyHome = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-keys-'));
  const { publicKeyPem, privateKeyPem } = ensureKeyPair(keyHome);

  const finding = {
    id: 'sql-injection:app.js:42', stableId: 'abc123', severity: 'critical',
    file: 'app.js', line: 42, vuln: 'SQL Injection', cwe: 'CWE-89',
    family: 'sql-injection', parser: 'JS',
  };
  const bundle = signEvidenceBundle(
    buildEvidenceBundle(finding, { engineVersion: 'test', rulesetVersion: 'test', bundleSha: 'test', commit: 'test' }),
    privateKeyPem,
  );

  const bundlePath = path.join(outside, 'bundle.json');
  const pubPath = path.join(outside, 'signer.pub');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  fs.writeFileSync(pubPath, publicKeyPem);

  // The actual claim: shipped CLI, cwd outside the repo, no repo on any path.
  const r = run([cli, 'verify-attestation', bundlePath, '--public-key', pubPath], outside);
  assert.equal(
    r.status, 0,
    `third-party verification failed — this is the published claim.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`,
  );

  try { fs.rmSync(keyHome, { recursive: true, force: true }); } catch { /* best effort */ }
});

test('a TAMPERED bundle is rejected by the same third party', async () => {
  // Without this, a verifier that returned 0 unconditionally would pass the test
  // above. Proving the failing direction is what makes the passing one mean
  // something.
  const { buildEvidenceBundle, signEvidenceBundle, ensureKeyPair } =
    await import('../src/posture/evidence-bundle.js');

  const keyHome = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-keys-'));
  const { publicKeyPem, privateKeyPem } = ensureKeyPair(keyHome);

  const finding = {
    id: 'sql-injection:app.js:42', stableId: 'abc123', severity: 'critical',
    file: 'app.js', line: 42, vuln: 'SQL Injection', cwe: 'CWE-89',
    family: 'sql-injection', parser: 'JS',
  };
  const bundle = signEvidenceBundle(
    buildEvidenceBundle(finding, { engineVersion: 'test', rulesetVersion: 'test', bundleSha: 'test', commit: 'test' }),
    privateKeyPem,
  );

  // Downgrade the severity — the kind of edit someone would actually make.
  bundle.finding.severity = 'low';

  const bundlePath = path.join(outside, 'tampered.json');
  const pubPath = path.join(outside, 'signer2.pub');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  fs.writeFileSync(pubPath, publicKeyPem);

  const r = run([cli, 'verify-attestation', bundlePath, '--public-key', pubPath], outside);
  assert.notEqual(r.status, 0, 'a tampered bundle must NOT verify');

  try { fs.rmSync(keyHome, { recursive: true, force: true }); } catch { /* best effort */ }
});

test('a bundle does not verify under the WRONG public key', async () => {
  const { buildEvidenceBundle, signEvidenceBundle, ensureKeyPair } =
    await import('../src/posture/evidence-bundle.js');

  const homeA = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-keyA-'));
  const homeB = fs.mkdtempSync(path.join(os.tmpdir(), 'third-party-keyB-'));
  const a = ensureKeyPair(homeA);
  const b = ensureKeyPair(homeB);

  const bundle = signEvidenceBundle(
    buildEvidenceBundle(
      { id: 'x', stableId: 'x', severity: 'high', file: 'a.js', line: 1, vuln: 'v', cwe: 'CWE-1', family: 'f', parser: 'JS' },
      { engineVersion: 'test', rulesetVersion: 'test', bundleSha: 'test', commit: 'test' },
    ),
    a.privateKeyPem,
  );

  const bundlePath = path.join(outside, 'wrongkey.json');
  const pubPath = path.join(outside, 'other.pub');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  fs.writeFileSync(pubPath, b.publicKeyPem);   // someone else's key

  const r = run([cli, 'verify-attestation', bundlePath, '--public-key', pubPath], outside);
  assert.notEqual(r.status, 0, 'a bundle must not verify under an unrelated public key');

  for (const d of [homeA, homeB]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});
