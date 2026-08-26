// `agentic-security ci` subcommand tests — verify artifacts + exit policy.
import { test } from 'node:test';
import * as assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, '..', 'dist', 'agentic-security.mjs');
const fixture = path.resolve(here, 'fixtures', 'vulnerable-js');

async function copyFixture() {
  const dst = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-ci-'));
  // shallow copy of all files in the fixture (no nested dirs expected here)
  for (const entry of await fsp.readdir(fixture, { withFileTypes: true })) {
    if (entry.isFile()) await fsp.copyFile(path.join(fixture, entry.name), path.join(dst, entry.name));
  }
  return dst;
}

function runCi(cwd, args) {
  // Spawn the bundled CLI; clear baseline-detection env so tests are deterministic.
  const r = spawnSync('node', [cli, 'ci', cwd, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_BASE_REF: '',
      CI_MERGE_REQUEST_TARGET_BRANCH_NAME: '',
      BUILDKITE_PULL_REQUEST_BASE_BRANCH: '',
      BITBUCKET_PR_DESTINATION_BRANCH: '',
    },
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('ci writes findings.{json,sarif,junit.xml} to .agentic-security/', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = runCi(dir, ['--fail-on', 'none']);
  assert.equal(r.code, 0, `--fail-on none should exit 0; stderr=${r.stderr}`);
  const stateDir = path.join(dir, '.agentic-security');
  assert.ok(fs.existsSync(path.join(stateDir, 'findings.json')), 'findings.json written');
  assert.ok(fs.existsSync(path.join(stateDir, 'findings.sarif')), 'findings.sarif written');
  assert.ok(fs.existsSync(path.join(stateDir, 'findings.junit.xml')), 'findings.junit.xml written');
  // sarif is valid JSON
  JSON.parse(await fsp.readFile(path.join(stateDir, 'findings.sarif'), 'utf8'));
  // junit.xml starts with XML prolog
  const xml = await fsp.readFile(path.join(stateDir, 'findings.junit.xml'), 'utf8');
  assert.match(xml, /^<\?xml version="1\.0"/);
});

// Stage 5 correctness audit: cmdScan computes and attaches scan.attestation
// (the R4 tamper-evidence digest — "attests what actually ships") right
// before writing its own artifacts, but cmdCi duplicates cmdScan's
// suppression/override/pack pipeline and artifact-writing without ever
// computing an attestation. `agentic-security ci` is the documented
// single-shot CI entry point — the pipeline most likely to be used as the
// actual evidence/audit trail — yet findings.json, its real CI artifact,
// always carries attestation: null.
test('ci writes an attestation into findings.json, same as scan does', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = runCi(dir, ['--fail-on', 'none']);
  assert.equal(r.code, 0, `--fail-on none should exit 0; stderr=${r.stderr}`);
  const findings = JSON.parse(await fsp.readFile(path.join(dir, '.agentic-security', 'findings.json'), 'utf8'));
  assert.ok(findings.attestation, `expected findings.json to carry a run attestation, same as 'agentic-security scan'; got ${JSON.stringify(findings.attestation)}`);
  assert.match(findings.attestation.digest, /^[0-9a-f]{64}$/);
});

test('ci --fail-on critical exits 1 when critical findings exist', async () => {
  if (!fs.existsSync(cli)) return;
  const dir = await copyFixture();
  const r = runCi(dir, ['--fail-on', 'critical']);
  assert.equal(r.code, 1, `--fail-on critical should exit 1 on vulnerable fixture; stderr=${r.stderr}`);
});

test('ci --fail-on none always exits 0', async () => {
  if (!fs.existsSync(cli)) return;
  const dir = await copyFixture();
  const r = runCi(dir, ['--fail-on', 'none']);
  assert.equal(r.code, 0);
});

// S1 (Stage-0 capability audit, 2026). cmdCi's state-dir-write guard executed
// a bare `return;` with no value, so `process.exit(await cmdCi(args))` became
// `process.exit(undefined)` — exit 0 — regardless of what --fail-on demanded,
// because the fail-on evaluation lived AFTER the guard and never ran. Verified
// via direct code read + `node -e "process.exit(undefined)"` -> exit 0 before
// this fix. A CI pipeline reading only the exit code would see a passing
// build with unevaluated critical findings.
test('ci --fail-on critical still exits 1 when state writes are refused (AGENTIC_SECURITY_NO_STATE=1)', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'critical'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AGENTIC_SECURITY_NO_STATE: '1',
      GITHUB_BASE_REF: '', CI_MERGE_REQUEST_TARGET_BRANCH_NAME: '',
      BUILDKITE_PULL_REQUEST_BASE_BRANCH: '', BITBUCKET_PR_DESTINATION_BRANCH: '',
    },
  });
  assert.equal(r.status, 1,
    `state-write refusal must not skip the fail-on evaluation; stderr=${r.stderr}`);
  // And artifacts genuinely were not written — the refusal itself is still honoured.
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security', 'findings.json')),
    'AGENTIC_SECURITY_NO_STATE=1 must still block the artifact write');
});

test('ci --fail-on none exits 0 even when state writes are refused (both directions)', async () => {
  if (!fs.existsSync(cli)) return;
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none'], {
    encoding: 'utf8',
    env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
  });
  assert.equal(r.status, 0);
});

// ── FR-204: assurance modes, real end-to-end through the actual bundled CLI ──

test('ci --assurance bogus is rejected immediately with a clear error, exit 1', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none', '--assurance', 'bogus'], {
    encoding: 'utf8',
    env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--assurance must be one of/);
});

test('ci --assurance strict on a genuinely clean/complete scan still exits 0 (per --fail-on none)', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  // FR-207: this assertion is about the SAST/detector dimension of
  // "genuinely complete," not the (now real) feed-freshness dimension --
  // a developer machine or CI runner with a genuinely aged local
  // KEV/EPSS disk cache would otherwise make this test's outcome depend
  // on real, ambient host state instead of this codebase. See the
  // identical rationale in test/scan-health.test.js's "reports complete"
  // test.
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none', '--assurance', 'strict'], {
    encoding: 'utf8',
    env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1', AGENTIC_SECURITY_OFFLINE: '1' },
  });
  assert.equal(r.status, 0, `a genuinely complete scan must pass strict mode too; stderr=${r.stderr}`);
  assert.match(r.stderr, /assurance gate PASSED \(mode=strict\)/);
});

// The real, unmocked FR-202 worker-cascade path with an impossibly low
// per-file timeout genuinely produces scanHealth.status:'partial' (proven
// in test/cascade-pool-wiring.test.js) — reused here as a REAL way to
// exercise strict mode's failure path through the actual bundled CLI,
// without needing module-mocking (which cannot reach inside an
// already-bundled, minified artifact anyway).
test('ci --assurance strict FAILS the build on a genuinely incomplete scan (real worker timeout, not mocked), independent of --fail-on', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none', '--assurance', 'strict'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AGENTIC_SECURITY_NO_STATE: '1',
      AGENTIC_SECURITY_WORKER_CASCADE: '1',
      AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS: '1',
    },
    timeout: 60_000,
  });
  assert.equal(r.status, 1, `strict mode must fail on a real incomplete scan even with --fail-on none; stderr=${r.stderr}`);
  assert.match(r.stderr, /assurance gate FAILED \(mode=strict\)/);
});

test('ci with the SAME real incomplete scan but --assurance standard (the default) does NOT fail over scan health — --fail-on none still exits 0', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AGENTIC_SECURITY_NO_STATE: '1',
      AGENTIC_SECURITY_WORKER_CASCADE: '1',
      AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS: '1',
    },
    timeout: 60_000,
  });
  assert.equal(r.status, 0, `standard mode must not independently fail the build over scan health; stderr=${r.stderr}`);
  assert.match(r.stderr, /scan-health=partial|⚠ scan-health=/, 'the degradation must still be VISIBLE in standard mode, per FR-206 — just not gating');
});

// ── FR-205: "CI cannot silently downgrade deep analysis; any downgrade
// appears in the headline and machine output" — real end-to-end through
// the actual bundled CLI, not a hand-built scanHealth object.
test('ci (FR-205): requesting deep analysis in a CI environment without the override genuinely surfaces the downgrade in [ci]\'s own stderr', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AGENTIC_SECURITY_NO_STATE: '1',
      AGENTIC_SECURITY_DEEP: '1',
      CI: 'true',
      GITHUB_BASE_REF: '', CI_MERGE_REQUEST_TARGET_BRANCH_NAME: '',
      BUILDKITE_PULL_REQUEST_BASE_BRANCH: '', BITBUCKET_PR_DESTINATION_BRANCH: '',
    },
  });
  assert.match(r.stderr, /scan-health=partial/, `the deep-mode CI downgrade must be visible in machine output; stderr=${r.stderr}`);
  assert.match(r.stderr, /deep analysis was requested but did not run/);
});

test('ci (FR-205): --assurance strict genuinely fails the build when deep analysis was silently downgraded in CI', async () => {
  if (!fs.existsSync(cli)) { console.warn('dist/ not built; skipping ci test'); return; }
  const dir = await copyFixture();
  const r = spawnSync('node', [cli, 'ci', dir, '--fail-on', 'none', '--assurance', 'strict'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      AGENTIC_SECURITY_NO_STATE: '1',
      AGENTIC_SECURITY_DEEP: '1',
      CI: 'true',
      GITHUB_BASE_REF: '', CI_MERGE_REQUEST_TARGET_BRANCH_NAME: '',
      BUILDKITE_PULL_REQUEST_BASE_BRANCH: '', BITBUCKET_PR_DESTINATION_BRANCH: '',
    },
  });
  assert.equal(r.status, 1, `strict mode must fail a CI-downgraded deep analysis, tying FR-204 and FR-205 together; stderr=${r.stderr}`);
});
