// S7 (Stage 1 correctness audit) — `--machine-output` is documented in the
// CLI's own help text ("Always write .agentic-security/findings.{sarif,json,csv}")
// and parsed into args.flags['machine-output'] by parseArgs (a generic
// --flag parser), but writeMachineOutput's gate
// (`profile.profile === 'pro' || profile.machineOutput`) never received
// args at all — only `profile`, which comes from the persisted persona
// config file, never from a CLI flag. A vibecoder-profile user passing
// --machine-output got the same output as not passing it at all
// (findings.json only; no findings.sarif/findings.csv), silently.
import { test } from 'node:test';
import assert from 'node:assert/strict';
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
  const dst = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-machine-output-'));
  for (const entry of await fsp.readdir(fixture, { withFileTypes: true })) {
    if (entry.isFile()) await fsp.copyFile(path.join(fixture, entry.name), path.join(dst, entry.name));
  }
  return dst;
}

test('--machine-output writes findings.sarif and findings.csv, not just findings.json', async () => {
  const dir = await copyFixture();
  try {
    const r = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network', '--machine-output'], { encoding: 'utf8' });
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);
    const stateDir = path.join(dir, '.agentic-security');
    assert.ok(fs.existsSync(path.join(stateDir, 'findings.json')), 'findings.json must always be written');
    assert.ok(fs.existsSync(path.join(stateDir, 'findings.sarif')), '--machine-output must write findings.sarif');
    assert.ok(fs.existsSync(path.join(stateDir, 'findings.csv')), '--machine-output must write findings.csv');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('without --machine-output, only findings.json is written (vibecoder default)', async () => {
  const dir = await copyFixture();
  try {
    const r = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);
    const stateDir = path.join(dir, '.agentic-security');
    assert.ok(fs.existsSync(path.join(stateDir, 'findings.json')));
    assert.ok(!fs.existsSync(path.join(stateDir, 'findings.sarif')), 'findings.sarif must not be written without the flag or --profile pro');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
