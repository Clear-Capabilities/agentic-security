// artifact-provenance-cli.test.js — PRD 5 (Source-to-Artifact Security &
// Provenance) required-fixture killer scenario, run against the REAL built
// CLI (not a unit-test shortcut). Proves every PRD-named fixture property:
// a vulnerable base package, a clean equivalent, a deleted-but-recoverable
// secret, a valid signature, an invalid signature, incorrect provenance,
// and a stale vulnerable deployment (the PRD's own "Killer Demonstration").
//
// See test/fixtures/artifact-provenance/README.md for the full
// property-by-property mapping.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { buildDockerArchive } from '../helpers/build-tar-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

function run(cwd, args, extraEnv = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd, encoding: 'utf8', timeout: 60000, env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1', ...extraEnv },
  });
}

// Real OSV data (via the project's own disk cache, see
// docs/implementation-status/source-to-artifact-provenance.md's
// verification section): lodash 4.17.4 is vulnerable to 10 advisories;
// 4.17.21 to a 3-advisory subset of those same 10. The 7 difference —
// GHSA-29mw-wpgm-hmr9 among them — is what "vulnerable base package" vs.
// "clean equivalent" proves below.
const VULNERABLE_VERSION = '4.17.4';
const CLEAN_VERSION = '4.17.21';
const AWS_KEY = 'AKIA' + 'QWERTYUIOPASDFGH'; // shaped like a real AWS access key id, never a real one

function dockerArchiveWithLodash(version, labels = {}) {
  return buildDockerArchive({
    config: { labels },
    layers: [{ files: [{ name: 'app/package.json', content: JSON.stringify({ dependencies: { lodash: version } }) }] }],
  });
}

test('PRD 5 killer scenario: vulnerable base package vs. clean equivalent (real OSV correlation)', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'vulnerable.tar'), dockerArchiveWithLodash(VULNERABLE_VERSION));
  fs.writeFileSync(path.join(dir, 'clean.tar'), dockerArchiveWithLodash(CLEAN_VERSION));

  const vuln = run(dir, ['image', 'scan', 'vulnerable.tar']);
  assert.equal(vuln.status, 0, vuln.stderr);
  const vulnReport = JSON.parse(vuln.stdout);
  const vulnIds = vulnReport.vulnerabilities.filter((v) => v.type === 'vulnerable_dep').map((v) => v.osvId);
  assert.ok(vulnIds.length >= 7, `expected the vulnerable base package to carry real OSV advisories, got ${vulnIds.length}`);

  const clean = run(dir, ['image', 'scan', 'clean.tar']);
  assert.equal(clean.status, 0, clean.stderr);
  const cleanReport = JSON.parse(clean.stdout);
  const cleanIds = cleanReport.vulnerabilities.filter((v) => v.type === 'vulnerable_dep').map((v) => v.osvId);
  assert.ok(cleanIds.length < vulnIds.length, 'the clean equivalent must carry strictly fewer real advisories than the vulnerable base package');
  assert.notEqual(vulnReport.inventory.digest, cleanReport.inventory.digest, 'different installed versions must produce different image digests');
});

test('PRD 5 killer scenario: a secret deleted in a later layer is still reported as recoverable from an earlier one', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const archive = buildDockerArchive({
    config: {},
    layers: [
      { files: [{ name: 'secrets/creds.env', content: `AWS_KEY=${AWS_KEY}` }] },
      { files: [{ name: 'secrets/creds.env', whiteout: true }, { name: 'app/package.json', content: '{}' }] },
    ],
  });
  fs.writeFileSync(path.join(dir, 'secret-image.tar'), archive);
  const r = run(dir, ['image', 'scan', 'secret-image.tar']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.secrets.deletedButRecoverable.length, 1);
  assert.ok(!r.stdout.includes(AWS_KEY), 'the raw secret value must never appear in CLI output');
});

test('PRD 5 killer scenario: a valid detached signature verifies, an invalid one does not — never treated as verified', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'image.tar'), dockerArchiveWithLodash(CLEAN_VERSION));

  const scan = run(dir, ['image', 'scan', 'image.tar', '--format', 'json']);
  const digest = JSON.parse(scan.stdout).inventory.digest;

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(dir, 'key.pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  fs.writeFileSync(path.join(dir, 'valid.sig'), crypto.sign(null, Buffer.from(digest, 'utf8'), privateKey));
  fs.writeFileSync(path.join(dir, 'invalid.sig'), crypto.sign(null, Buffer.from('sha256:' + 'f'.repeat(64), 'utf8'), privateKey));

  const validR = run(dir, ['image', 'verify', 'image.tar', '--signature', 'valid.sig', '--public-key', 'key.pub.pem']);
  assert.equal(validR.status, 0, validR.stderr);
  assert.equal(JSON.parse(validR.stdout).signature.state, 'verified');

  const invalidR = run(dir, ['image', 'verify', 'image.tar', '--signature', 'invalid.sig', '--public-key', 'key.pub.pem']);
  assert.equal(invalidR.status, 1, 'an invalid signature must fail the CLI check');
  assert.equal(JSON.parse(invalidR.stdout).signature.state, 'invalid');
});

test('PRD 5 killer scenario: incorrect provenance (subject digest mismatch) is reported invalid, never verified', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'image.tar'), dockerArchiveWithLodash(CLEAN_VERSION));

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(dir, 'key.pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));

  // An attestation that is validly signed, but names a DIFFERENT artifact's
  // digest as its subject — the "incorrect provenance" fixture property.
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'other-image', digest: { sha256: 'f'.repeat(64) } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {},
  };
  const payload = Buffer.from(JSON.stringify(statement), 'utf8');
  const payloadType = 'application/vnd.in-toto+json';
  const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.from(payloadType).length} ${payloadType} ${payload.length} `), payload]);
  const envelope = { payloadType, payload: payload.toString('base64'), signatures: [{ sig: crypto.sign(null, pae, privateKey).toString('base64') }] };
  fs.writeFileSync(path.join(dir, 'attestation.json'), JSON.stringify(envelope));

  const r = run(dir, ['image', 'verify', 'image.tar', '--attestation', 'attestation.json', '--public-key', 'key.pub.pem']);
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).attestation.state, 'invalid');
});

test('PRD 5 killer scenario (THE Killer Demonstration): a stale vulnerable deployment — source fixed Monday, production still runs Friday\'s image', { timeout: 60000 }, (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  // Source is fixed: last-scan.json (hand-written here rather than produced
  // by a live `scan --only sca` run, matching this codebase's own SCA-test
  // convention — see test/sca-batch.test.js — of injecting vulnerable_dep-
  // shaped fixtures directly rather than depending on live OSV/cache state)
  // reports NO lodash advisory at all: the developer upgraded on Monday.
  fx.writeFile('.agentic-security/last-scan.json', JSON.stringify({ supplyChain: [] }));
  fx.commit('fix: upgrade lodash');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // Production is still running Friday's old, vulnerable image.
  fs.writeFileSync(path.join(dir, 'friday.tar'), dockerArchiveWithLodash(VULNERABLE_VERSION));

  const r = run(dir, ['provenance', 'trace', 'friday.tar', '--source', fx.root, '--format', 'cli']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /SOURCE: FIXED/);
  assert.match(r.stdout, /DEPLOYED ARTIFACT: STILL VULNERABLE/);
  assert.match(r.stdout, /PRODUCTION EXPOSURE: PRESENT/);

  // Same scenario via --format json, for a machine-readable assertion.
  const jr = run(dir, ['provenance', 'trace', 'friday.tar', '--source', fx.root, '--format', 'json']);
  const parsed = JSON.parse(jr.stdout);
  assert.ok(parsed.mismatch.scenarioA.length > 0);
  assert.equal(parsed.mismatch.scenarioB.length, 0);
});

test('PRD 5: supply vex reports a real VEX status per advisory against the real built CLI', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'image.tar'), dockerArchiveWithLodash(VULNERABLE_VERSION));
  const r = run(dir, ['supply', 'vex', 'image.tar']);
  assert.equal(r.status, 0, r.stderr);
  const { statements } = JSON.parse(r.stdout);
  assert.ok(statements.length >= 7);
  for (const s of statements) assert.ok(['affected', 'not_affected', 'fixed', 'under_investigation'].includes(s.status));
});

test('PRD 5: a scanned artifact can be re-traced by DIGEST alone (no re-parsing the archive)', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // A project marker is required for the digest-keyed persisted scan to be
  // written at all (src/posture/state-dir.js's isSafeStateDir) — a bare
  // throwaway temp dir with none produces a SILENT no-op write, which is
  // exactly the gap this test exists to catch.
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"artifact-provenance-fixture"}');
  fs.writeFileSync(path.join(dir, 'image.tar'), dockerArchiveWithLodash(CLEAN_VERSION, { 'org.opencontainers.image.revision': 'deadbeef' }));
  const scan = run(dir, ['image', 'scan', 'image.tar']);
  const digest = JSON.parse(scan.stdout).inventory.digest;

  const trace = run(dir, ['provenance', 'trace', digest]);
  assert.equal(trace.status, 0, trace.stderr);
  const { artifactProvenanceGraph } = JSON.parse(trace.stdout);
  assert.ok(artifactProvenanceGraph.nodes.some((n) => n.kind === 'gitCommit' && n.sha === 'deadbeef'));
});

test('PRD 5: safety — a hostile tar entry (path traversal) in an archive is surfaced, never crashes the CLI', { timeout: 60000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-artifact-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const archive = buildDockerArchive({ config: {}, layers: [{ files: [{ name: '../../etc/passwd', content: 'evil' }] }] });
  fs.writeFileSync(path.join(dir, 'hostile.tar'), archive);
  const r = run(dir, ['image', 'scan', 'hostile.tar']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.ok(report.inventory.unsafeEntries.some((e) => e.name === '../../etc/passwd'));
});
