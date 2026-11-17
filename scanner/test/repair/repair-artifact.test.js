// Verified remediation M4-06: source-to-artifact verification of a repair (FR-16). A verified dependency repair is looked for in built
// images: the patched files by digest, the resolved packages by version, and the contract's checks re-run on the image's own files.
// Images are synthetic `docker save` archives built by the test helper. A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { materialize } from '../../src/repair/dependencies.js';
import { readImage, compareArtifact, artifactVerdict } from '../../src/repair/artifact.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { npmLock } from '../helpers/npm-lock.js';
import { buildDockerArchive } from '../helpers/build-tar-fixture.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const BIN = path.join(SCANNER, 'bin', 'agentic-security.js');
const FIX = path.join(SCANNER, 'test', 'fixtures', 'repair', 'dep-files');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the artifact execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

function fixed(root, app) {
  const T = (n, v) => `vendor/packages/${n}-${v}.tgz`;
  const deps = { otherlib: `file:${T('otherlib', '2.0.0')}`, vulnlib: `file:${T('vulnlib', '2.0.0')}` };
  return {
    'package.json': `${JSON.stringify({ name: 'dep-files', version: '1.0.0', type: 'module', dependencies: deps }, null, 2)}\n`,
    'package-lock.json': npmLock(root, { name: 'dep-files', version: '1.0.0' }, deps, {
      'node_modules/otherlib': { version: '2.0.0', tarball: T('otherlib', '2.0.0'), dependencies: { vulnlib: '^2.0.0' } },
      'node_modules/vulnlib': { version: '2.0.0', tarball: T('vulnlib', '2.0.0') },
    }),
    'src/app.mjs': app.replace("import { safeJoin } from 'vulnlib';", "import { resolveInside } from 'vulnlib';")
      .replace("    const file = safeJoin(filesRoot, name);\n", "    const file = resolveInside(filesRoot, name);\n    if (!file) { res.writeHead(404); res.end('no such file'); return; }\n"),
  };
}

/** A `docker save` image holding the given application files and their materialized node_modules under app/. */
function image(root, dep, files, labels = {}) {
  const withModules = materialize(root, dep, files);
  return buildDockerArchive({ config: { labels }, layers: [{ files: [{ name: 'etc/os-release', content: 'ID=alpine\n' }] }, { files: Object.entries(withModules).map(([rel, content]) => ({ name: `app/${rel}`, content })) }] });
}

async function verifiedRun() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'art-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'dep:vulnlib', file: 'package.json' }, family: 'dependency', profile, profileOrigin: 'repository-file' });
  const original = Object.fromEntries(['src/app.mjs', 'package.json', 'package-lock.json'].map((f) => [f, fs.readFileSync(path.join(root, f), 'utf8')]));
  const patched = fixed(root, original['src/app.mjs']);
  const r = await runRepair({ root, plan: p.plan, config: ON, proposers: [queueProposer([{ files: patched }])], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 1 } } });
  assert.equal(r.record.disposition, 'verified-for-contract', r.record.reasons.join('; '));
  return { root, plan: p.plan, record: r.record, original, patched, dep: profile.dependency };
}
const cli = (root, ...args) => { const x = spawnSync(process.execPath, [BIN, 'repair', ...args, '--root', root, '--json'], { encoding: 'utf8', timeout: 180000 }); return { status: x.status, json: (() => { try { return JSON.parse(x.stdout); } catch { return null; } })(), stderr: x.stderr }; };

describe('[FR-16] the artifact comparison (no execution)', () => {
  test('[AC-16.1/16.2/16.6] unpatched source, stale packages and a label claiming a revision are each a mismatch; the record cannot say verified without a bound digest', async (t) => {
    if (!ready) return t.skip(whyNot);
    const s = await verifiedRun();
    const cmp = (files, labels) => compareArtifact({ record: s.record, plan: s.plan, image: readImage(image(s.root, s.dep, files, labels)), appDir: '/app/' });
    const good = cmp(s.patched);
    assert.deepEqual(good.problems, []);
    const stale = cmp(s.original, { 'org.opencontainers.image.revision': 'the-fixed-commit', 'dev.sigstore.cosign/signature': 'present' });
    assert.ok(stale.files.some((f) => f.state === 'unpatched'));
    assert.match(stale.problems.join(' '), /built from unpatched source/);
    const oldModules = image(s.root, s.dep, { ...s.patched, 'package-lock.json': s.original['package-lock.json'] });
    const pk = compareArtifact({ record: s.record, plan: s.plan, image: readImage(oldModules), appDir: 'app' });
    assert.match(pk.problems.join(' '), /vulnlib@1\.0\.0 .*vulnerable range/);
    const v = artifactVerdict({ image: readImage(image(s.root, s.dep, s.patched)), appDir: 'app', comparison: good, checks: [] });
    assert.equal(v.artifact, 'unavailable', 'content alone, with no executed checks, is never artifact-verified');
  });
});

describe('[FR-16] repair artifact, executed', () => {
  test('[AC-16.1/16.5] the patched image is artifact-verified with the contract re-run on its files; the unpatched one is a mismatch; an export names the image and verify tells them apart', needs(async () => {
    const s = await verifiedRun();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'art-img-'));
    const goodTar = path.join(dir, 'good.tar'); fs.writeFileSync(goodTar, image(s.root, s.dep, s.patched));
    const badTar = path.join(dir, 'bad.tar'); fs.writeFileSync(badTar, image(s.root, s.dep, s.original));
    const bad = cli(s.root, 'artifact', s.record.runId, '--image', badTar, '--app-dir', 'app', '--allow-execution');
    assert.equal(bad.status, 1, bad.stderr);
    assert.equal(bad.json.artifact, 'artifact-mismatch');
    const noExec = cli(s.root, 'artifact', s.record.runId, '--image', goodTar, '--app-dir', 'app');
    assert.equal(noExec.json.artifact, 'unavailable');
    const good = cli(s.root, 'artifact', s.record.runId, '--image', goodTar, '--app-dir', 'app', '--allow-execution');
    assert.equal(good.status, 0, `${good.stderr} ${JSON.stringify(good.json?.source?.problems)}`);
    assert.equal(good.json.artifact, 'artifact-verified');
    assert.ok(good.json.source.checks.length >= 3 && good.json.source.checks.every((c) => c.status === 'passed'));
    const shown = cli(s.root, 'show', s.record.runId);
    assert.equal(shown.json.record?.artifact ?? shown.json.artifact, 'artifact-verified');
    const out = path.join(dir, 'bundle');
    assert.equal(cli(s.root, 'export', s.record.runId, '--out', out).status, 0);
    const bundle = JSON.parse(fs.readFileSync(path.join(out, 'bundle.json'), 'utf8'));
    assert.equal(bundle.artifactDigest, readImage(fs.readFileSync(goodTar)).digest);
    assert.match(bundle.claim, /in the source and in image sha256:/);
    assert.equal(cli(s.root, 'verify', out, '--image', goodTar).status, 0);
    const other = cli(s.root, 'verify', out, '--image', badTar);
    assert.equal(other.status, 1);
    assert.match(other.json.problems.join(' '), /not the checked artifact/);
  }));
});

describe('[FR-16] staging and operational observations', () => {
  const receiptFor = (digest, environment = 'staging') => ({ schema: 'agentic-security/deployment-receipt', schemaVersion: '1.0.0', environment, artifactDigest: digest, deployedAt: '2026-11-17T10:00:00Z', deployer: 'release-operator' });
  const verifiedRecord = { disposition: 'verified-for-contract', artifact: 'artifact-verified', environment: 'not-checked', source: { artifactDigest: `sha256:${'a'.repeat(64)}` } };

  test('[AC-16.3/16.6] the verdict needs the verified artifact, a statement naming it and checks executed on it; a failure keeps the source verification', async () => {
    const { stagingVerdict, validateReceipt } = await import('../../src/repair/staging.js');
    const D = verifiedRecord.source.artifactDigest;
    const passed = [{ obligation: 'a', status: 'passed' }, { obligation: 'b', status: 'passed' }];
    assert.equal(stagingVerdict({ record: { ...verifiedRecord, artifact: 'source-only', source: null }, receipt: receiptFor(D), imageDigest: D, checks: passed }).staging.status, 'blocked', 'a receipt cannot stand in for the artifact comparison');
    assert.equal(stagingVerdict({ record: verifiedRecord, receipt: receiptFor(D) }).staging.status, 'not-executed', 'a receipt alone upgrades nothing');
    assert.equal(stagingVerdict({ record: verifiedRecord, receipt: receiptFor(D) }).environment, 'not-checked');
    const failed = stagingVerdict({ record: verifiedRecord, receipt: receiptFor(D), imageDigest: D, checks: [passed[0], { obligation: 'b', status: 'failed' }] });
    assert.deepEqual([failed.staging.status, failed.environment], ['failed', 'unavailable']);
    assert.deepEqual([stagingVerdict({ record: verifiedRecord, receipt: receiptFor(D), imageDigest: D, checks: passed }).environment], ['staging-verified']);
    assert.equal(stagingVerdict({ record: verifiedRecord, receipt: receiptFor(D, 'production'), imageDigest: D, checks: passed }).staging.status, 'declared', 'a production receipt file is a declaration');
    assert.equal(stagingVerdict({ record: verifiedRecord, readback: { environment: 'production', artifactDigest: D, connector: 'test-connector', observedAt: '2026-11-17T10:05:00Z' }, imageDigest: D, checks: passed }).environment, 'deployment-observed');
    assert.equal(stagingVerdict({ record: verifiedRecord, receipt: receiptFor(`sha256:${'b'.repeat(64)}`), imageDigest: D, checks: passed }).staging.status, 'mismatch');
    assert.match(validateReceipt({ ...receiptFor(D), verdict: 'verified' }).join(' '), /unknown receipt field 'verdict'/);
  });

  test('[AC-16.3/16.5/16.6] staging through the CLI: blocked before the artifact is verified, a mismatched receipt makes the environment unavailable without touching the disposition, the verified image in staging is staging-verified, and observations stay beside the record', needs(async () => {
    const s = await verifiedRun();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stg-'));
    const goodTar = path.join(dir, 'good.tar'); fs.writeFileSync(goodTar, image(s.root, s.dep, s.patched));
    const D = readImage(fs.readFileSync(goodTar)).digest;
    const write = (name, v) => { const f = path.join(dir, name); fs.writeFileSync(f, JSON.stringify(v)); return f; };
    const early = cli(s.root, 'staging', s.record.runId, '--receipt', write('r0.json', receiptFor(D)), '--image', goodTar, '--app-dir', 'app', '--allow-execution');
    assert.equal(early.status, 3, early.stderr);
    assert.equal(early.json.staging.status, 'blocked');
    assert.equal(cli(s.root, 'artifact', s.record.runId, '--image', goodTar, '--app-dir', 'app', '--allow-execution').status, 0);
    const wrong = cli(s.root, 'staging', s.record.runId, '--receipt', write('r1.json', receiptFor(`sha256:${'c'.repeat(64)}`)), '--image', goodTar, '--app-dir', 'app', '--allow-execution');
    assert.equal(wrong.status, 1);
    assert.equal(wrong.json.environment, 'unavailable');
    const rec1 = JSON.parse(fs.readFileSync(path.join(s.root, '.agentic-security', 'repair', 'runs', s.record.runId, 'record.json'), 'utf8'));
    assert.deepEqual([rec1.disposition, rec1.artifact, rec1.environment], ['verified-for-contract', 'artifact-verified', 'unavailable']);
    const ok = cli(s.root, 'staging', s.record.runId, '--receipt', write('r2.json', receiptFor(D)), '--image', goodTar, '--app-dir', 'app', '--allow-execution');
    assert.equal(ok.status, 0, `${ok.stderr} ${JSON.stringify(ok.json?.staging?.problems)}`);
    assert.equal(ok.json.environment, 'staging-verified');
    assert.ok(ok.json.staging.checks.length >= 3 && ok.json.staging.checks.every((c) => c.status === 'passed'));
    const out = path.join(dir, 'bundle');
    assert.equal(cli(s.root, 'export', s.record.runId, '--out', out).status, 0);
    const bundle = JSON.parse(fs.readFileSync(path.join(out, 'bundle.json'), 'utf8'));
    assert.equal(bundle.staging.artifactDigest, D);
    assert.match(bundle.claim, /places in staging .* live staging service was not exercised/);
    const before = cli(s.root, 'observe', s.record.runId);
    assert.equal(before.json.presence.state, 'not-applied');
    for (const [rel, t] of Object.entries(s.patched)) fs.writeFileSync(path.join(s.root, rel), t);
    assert.equal(cli(s.root, 'observe', s.record.runId).json.presence.state, 'present');
    fs.writeFileSync(path.join(s.root, 'src', 'app.mjs'), s.original['src/app.mjs']);
    const later = cli(s.root, 'observe', s.record.runId, '--report', 'regression', '--note', 'reported by a user after merge');
    assert.equal(later.json.presence.state, 'changed');
    assert.ok(later.json.history.some((h) => h.kind === 'regression' && h.source === 'operator-report'));
    const rec2 = JSON.parse(fs.readFileSync(path.join(s.root, '.agentic-security', 'repair', 'runs', s.record.runId, 'record.json'), 'utf8'));
    assert.equal(rec2.disposition, 'verified-for-contract', 'an observation never rewrites the verification');
  }));
});
