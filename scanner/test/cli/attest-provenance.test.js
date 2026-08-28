import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

test('attest --provenance: signs a real bundle from a real scan, distinct from finding-evidence bundles', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');

  const scanR = spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  // `scan` exit code encodes the deploy-gate verdict, not scan success —
  // 3 is expected here because the fixture's critical sqli finding trips
  // the gate (src/report/index.js#exitCodeFor). "<=3" is the established
  // convention for "the scan itself completed" across this suite (see
  // e.g. test/labs-command.test.js, test/posture-command.test.js).
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const attestR = spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });
  assert.equal(attestR.status, 0, `attest --provenance failed: ${attestR.stderr}`);

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const files = fs.readdirSync(outDir).filter((f) => f.startsWith('provenance-'));
  assert.ok(files.length > 0, 'expected at least one provenance-*.json bundle');

  const bundle = JSON.parse(fs.readFileSync(path.join(outDir, files[0]), 'utf8'));
  assert.equal(bundle.schema, 'agentic-security/provenance-evidence@1');
  assert.ok(bundle.signature?.value);
  assert.ok(bundle.provenance);
});

test('attest --provenance: with no findingProvenance-bearing findings, exits 2 honestly', async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-attest-prov-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  fs.mkdirSync(path.join(tmp, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(tmp, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [] }));
  const r = spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: tmp, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 2);
});

test('verify-attestation: round-trips a real provenance bundle end-to-end', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');

  spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const file = fs.readdirSync(outDir).find((f) => f.startsWith('provenance-'));
  const r = spawnSync(process.execPath, [CLI, 'verify-attestation', path.join(outDir, file)], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(r.status, 0, `verify-attestation failed: ${r.stderr}\n${r.stdout}`);
  assert.match(r.stdout, /VALID/);
  assert.match(r.stdout, /origin:/);
});

test('verify-attestation: a tampered provenance bundle is rejected with exit 1', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
  fx.commit('introduce sqli');
  spawnSync(process.execPath, [CLI, 'scan', '.'], { cwd: fx.root, encoding: 'utf8', timeout: 60000 });
  spawnSync(process.execPath, [CLI, 'attest', '--provenance'], { cwd: fx.root, encoding: 'utf8', timeout: 30000 });

  const outDir = path.join(fx.root, '.agentic-security', 'attestations');
  const file = fs.readdirSync(outDir).find((f) => f.startsWith('provenance-'));
  const p = path.join(outDir, file);
  const bundle = JSON.parse(fs.readFileSync(p, 'utf8'));
  bundle.provenance.confidence.level = 'high';
  bundle.provenance.findingOrigin.commit = 'tampered000000';
  fs.writeFileSync(p, JSON.stringify(bundle, null, 2));

  const r = spawnSync(process.execPath, [CLI, 'verify-attestation', p], { cwd: fx.root, encoding: 'utf8', timeout: 15000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /INVALID/);
});
