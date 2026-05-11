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
