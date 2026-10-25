// Contract test for source-to-artifact provenance (docs/reference/artifact-provenance-contract.md): the real commands over an archive, each
// output held to the page's tables in both directions, plus the signature states, the mismatch detector and the exit codes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildDockerArchive } from '../helpers/build-tar-fixture.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { seedAdvisory } from '../helpers/seed-osv-cache.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/artifact-provenance-contract.md');
const COMMIT = 'a'.repeat(40);

const dir = mkTestTmp('agsec-artifact-contract-');
fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"host","version":"1.0.0"}');
fs.writeFileSync(path.join(dir, 'image.tar'), buildDockerArchive({
  config: { labels: { 'org.opencontainers.image.revision': COMMIT } },
  layers: [
    { files: [{ name: 'app/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.4' } }) }, { name: 'secrets/c.env', content: 'AWS_KEY=AKIA' + 'QWERTYUIOPASDFGH' }] },
    { files: [{ name: 'secrets/c.env', whiteout: true }] },
  ],
}));
// the advisory data is seeded into a private home, so the result is the same on a warm machine and a cold runner
const home = mkTestTmp('agsec-artifact-home-');
seedAdvisory(home, { ecosystem: 'npm', name: 'lodash', version: '4.17.4', id: 'GHSA-contract-0001', description: 'seeded advisory for the contract test', fixedVersions: ['4.17.21'] });
const run = (...a) => spawnSync(process.execPath, [CLI, ...a], { cwd: dir, encoding: 'utf8', timeout: 120000, env: { ...process.env, HOME: home, AGENTIC_SECURITY_OFFLINE: '1' } });

const scan = run('image', 'scan', 'image.tar');
const report = JSON.parse(scan.stdout);
const digest = report.inventory.digest;

test('contract: image scan has exactly the documented fields, and every documented vulnerability field appears', () => {
  assert.equal(scan.status, 0, scan.stderr);
  sameFields(report, fieldsUnder(PAGE, 'Scan output'), 'scan output');
  sameFields(report.inventory, fieldsUnder(PAGE, 'Inventory'), 'inventory');
  sameFields(report.secrets, fieldsUnder(PAGE, 'Secrets'), 'secrets');
  assert.equal(report.source.kind, 'archive');
  const documented = ['type', 'name', 'version', 'ecosystem', 'purl', 'osvId', 'cveAliases', 'description', 'fixedVersions', 'severity', 'cvssVector', 'osvVulnFunctions', 'scope', 'file', 'line', 'depChain', 'advisory', 'range', 'hasKnownAttackRef'];
  const seen = new Set(report.vulnerabilities.flatMap(v => Object.keys(v)));
  for (const k of documented) assert.ok(PAGE.includes(`\`${k}\``), `${k} is on the page`);
  for (const k of seen) assert.ok(documented.includes(k), `${k} is carried and not documented`);
  assert.ok(report.vulnerabilities.length > 0);
});

test('contract: the inventory reads the commit and base image only from labels, and a deleted secret is reported recoverable and masked', () => {
  assert.equal(report.inventory.baseImage, null, 'no base-image label, so none is guessed');
  assert.equal(report.inventory.buildLabels['org.opencontainers.image.revision'], COMMIT);
  assert.equal(report.secrets.deletedButRecoverable.length, 1);
  assert.doesNotMatch(JSON.stringify(report), /QWERTYUIOPASDFGH/, 'the secret value is masked');
});

test('contract: image verify has the documented fields, and an absent signature is missing, never verified', () => {
  const r = run('image', 'verify', digest);
  assert.equal(r.status, 0);
  const v = JSON.parse(r.stdout);
  sameFields(v, fieldsUnder(PAGE, 'Verify output'), 'verify output');
  sameFields(v.signature, ['state', 'reason'], 'signature');
  assert.equal(v.signature.state, 'missing');
  assert.equal(v.attestation.state, 'missing');
});

test('contract: a valid signature verifies, one for another digest is invalid, and the CLI exits 1 on invalid only, and a signature with no key is not verified', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(dir, 'pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  fs.writeFileSync(path.join(dir, 'good.sig'), crypto.sign(null, Buffer.from(digest, 'utf8'), privateKey));
  fs.writeFileSync(path.join(dir, 'bad.sig'), crypto.sign(null, Buffer.from('sha256:' + 'f'.repeat(64), 'utf8'), privateKey));
  const ok = run('image', 'verify', 'image.tar', '--signature', 'good.sig', '--public-key', 'pub.pem');
  assert.equal(ok.status, 0);
  assert.equal(JSON.parse(ok.stdout).signature.state, 'verified');
  const bad = run('image', 'verify', 'image.tar', '--signature', 'bad.sig', '--public-key', 'pub.pem');
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout).signature.state, 'invalid');
  const noKey = run('image', 'verify', 'image.tar', '--signature', 'good.sig');
  assert.equal(JSON.parse(noKey.stdout).signature.state, 'missing', 'a signature with no key to check it is not verified');
  assert.match(JSON.parse(noKey.stdout).signature.reason, /public key/);
  assert.equal(noKey.status, 0);
  for (const s of ['verified', 'invalid', 'missing', 'unavailable']) assert.ok(PAGE.includes(`| \`${s}\` |`), `${s} is on the page`);
});

test('contract: provenance trace has the documented fields and node kinds, and the commit is the label, never inferred', () => {
  const r = run('provenance', 'trace', digest);
  assert.equal(r.status, 0);
  const t = JSON.parse(r.stdout);
  sameFields(t, fieldsUnder(PAGE, 'Trace output'), 'trace output');
  sameFields(t.trace, ['found', 'root', 'reached'], 'trace');
  assert.equal(t.mismatch, null);
  const kinds = new Set(t.artifactProvenanceGraph.nodes.map(n => n.kind));
  for (const k of kinds) assert.ok(PAGE.includes(`\`${k}\``), `node kind ${k} is on the page`);
  const commit = t.artifactProvenanceGraph.nodes.find(n => n.kind === 'gitCommit');
  assert.equal(commit.sha, COMMIT); assert.equal(commit.known, true);
  assert.equal(kinds.has('deployment'), false, 'a deployment appears only when declared');
  const declared = JSON.parse(run('provenance', 'trace', digest, '--deployment-id', 'prod', '--deployment-environment', 'production').stdout);
  assert.equal(declared.artifactProvenanceGraph.nodes.some(n => n.kind === 'deployment'), true);
});

test('contract: the mismatch has the documented fields; fixed-in-source is flagged, the same advisories are not, and no dependency data is refused', () => {
  const src = mkTestTmp('agsec-artifact-src-');
  fs.mkdirSync(path.join(src, '.agentic-security'));
  fs.writeFileSync(path.join(src, 'package.json'), '{"name":"s","version":"1.0.0"}');
  const writeScan = (body) => fs.writeFileSync(path.join(src, '.agentic-security', 'last-scan.json'), JSON.stringify(body));
  writeScan({ supplyChain: [] });
  const fixed = JSON.parse(run('provenance', 'trace', digest, '--source', src).stdout);
  sameFields(fixed.mismatch, fieldsUnder(PAGE, 'Mismatch'), 'mismatch');
  assert.ok(fixed.mismatch.scenarioA.length > 0); assert.equal(fixed.mismatch.hasMismatch, true);
  writeScan({ findings: report.vulnerabilities.filter(v => v.type === 'vulnerable_dep') });
  const same = JSON.parse(run('provenance', 'trace', digest, '--source', src).stdout);
  assert.equal(same.mismatch.scenarioA.length, 0, 'the same advisories on both sides is not "fixed in source"');
  writeScan({ findings: [] });
  const none = run('provenance', 'trace', digest, '--source', src);
  assert.equal(none.status, 1);
  assert.match(none.stderr, /no dependency data/);
});

test('contract: supply vex has the documented fields and only the documented statuses, and does not claim affected without reachability', () => {
  const r = run('supply', 'vex', digest);
  assert.equal(r.status, 0);
  const v = JSON.parse(r.stdout);
  sameFields(v, fieldsUnder(PAGE, 'VEX output'), 'vex output');
  sameFields(v.statements[0], ['purl', 'name', 'ecosystem', 'osvId', 'status', 'justification', 'evidence'], 'vex statement');
  for (const s of v.statements) assert.ok(['not_affected', 'affected', 'fixed', 'under_investigation'].includes(s.status), s.status);
  assert.ok(v.statements.every(s => s.status !== 'affected'), 'no reachability evidence, so nothing is claimed affected');
  assert.ok(v.statements.some(s => s.status === 'under_investigation'));
});

test('contract: the exit codes are the documented ones (2 for usage, 1 for an unreadable input) and the three inputs are documented', () => {
  assert.equal(run('image', 'scan').status, 2);
  assert.equal(run('image', 'scan', 'image.tar', '--format', 'xml').status, 2);
  assert.equal(run('image', 'scan', 'no-such.tar').status, 1);
  for (const code of ['`0`', '`1`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`), `exit ${code} is on the page`);
  for (const input of ['Archive', 'Engine', 'Registry']) assert.ok(PAGE.includes(`| ${input} |`));
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Scan output');
  assert.throws(() => sameFields({ ...report, extra: 1 }, doc, 'scan'));
  const { scannedAt, ...rest } = report;
  assert.throws(() => sameFields(rest, doc, 'scan'));
  assert.ok(scannedAt);
});

test('contract: the page quotes the committed hosted run, and every check in it passed', () => {
  const r = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'bench', 'artifact-real', 'RESULT.json'), 'utf8'));
  assert.ok(r.checks.length >= 14 && r.checks.every(c => c.ok), 'every recorded check passed');
  assert.equal(r.verification.signedWithItsKey.state, 'verified');
  assert.equal(r.verification.signedWithAnotherKey.state, 'invalid');
  assert.equal(r.verification.unsigned.state, 'missing');
  assert.equal(r.mismatch.sameSource.scenarioA, 0);
  assert.ok(r.mismatch.patchedSource.scenarioA > 0);
  assert.ok(PAGE.includes(`All ${r.checks.length} checks passed`));
  assert.ok(PAGE.includes(`${r.advisories.vulnerable} advisories on all three`));
});
