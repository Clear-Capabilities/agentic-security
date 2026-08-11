// S7 — commands/supply.md's --sbom, --license, and --cve-alerts modes had
// no concrete invocation at all: the "Implementation" section named the
// backing modules in prose ("Routes to existing modules: ...") but gave no
// file paths, field names, or CLI syntax an agent could actually follow.
// Separately, scan.licenseGraph and scan.sbomDiff (computed by the engine on
// every scan with components) never reached toJSON's output or
// last-scan.json at all — a documentation fix pointing at "read
// scan.licenseGraph" would have been pointing at data that didn't exist
// anywhere (see test/annotator-errors.test.js for that half of the fix).
//
// These tests extract the actual fenced bash block from commands/supply.md
// (not a hand-copied duplicate) and run every mode against a real scan
// fixture, proving each one actually produces the data its own follow-up
// prose in the command promises to use.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = path.join(REPO_ROOT, 'scanner', 'test', 'fixtures', 'vulnerable-js');

function extractBashBlock() {
  const md = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'supply.md'), 'utf8');
  const lines = md.split('\n');
  const fenceStart = lines.findIndex((l) => l.trim() === '```bash');
  const fenceEnd = lines.findIndex((l, i) => i > fenceStart && l.trim() === '```');
  assert.ok(fenceStart >= 0 && fenceEnd > fenceStart, 'expected a fenced bash block in commands/supply.md');
  return lines.slice(fenceStart + 1, fenceEnd).join('\n');
}

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'supply-cmd-'));
  fs.cpSync(FIXTURE, dir, { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runMode(script, args, cwd) {
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'supply-run-')), 'run.sh');
  fs.writeFileSync(scriptPath, script);
  try {
    const out = execFileSync('bash', [scriptPath, ...args], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: REPO_ROOT },
      timeout: 60000,
    });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

test('S7: supply.md --check runs the real scan --only sca CLI invocation', async () => {
  const script = extractBashBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, ['--check', '--json'], p.dir);
    assert.ok(r.status === 0 || r.status <= 3, `expected a verdict exit (<=3); got ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /"findings"/);
  } finally { await p.cleanup(); }
}, { timeout: 60000 });

test('S7: supply.md --sbom produces real sbomDiff + components data', async () => {
  const script = extractBashBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, ['--sbom'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const jsonStart = r.stdout.indexOf('{');
    const parsed = JSON.parse(r.stdout.slice(jsonStart));
    assert.ok(parsed.sbomDiff, 'expected an sbomDiff key in the output');
    assert.ok('summary' in parsed.sbomDiff && 'findings' in parsed.sbomDiff);
    assert.ok(Array.isArray(parsed.components) && parsed.components.length > 0,
      'expected the real component list from the fixture, not an empty array');
  } finally { await p.cleanup(); }
}, { timeout: 60000 });

test('S7: supply.md --license produces real licenseGraph + components data', async () => {
  const script = extractBashBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, ['--license'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const jsonStart = r.stdout.indexOf('{');
    const parsed = JSON.parse(r.stdout.slice(jsonStart));
    assert.ok(parsed.licenseGraph, 'expected a licenseGraph key in the output');
    assert.ok('summary' in parsed.licenseGraph);
    assert.ok(Array.isArray(parsed.components) && parsed.components.length > 0);
  } finally { await p.cleanup(); }
}, { timeout: 60000 });

test('S7: supply.md --cve-alerts runs the real cve-watch subcommand', async () => {
  const script = extractBashBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, ['--cve-alerts'], p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const jsonStart = r.stdout.indexOf('{');
    const parsed = JSON.parse(r.stdout.slice(jsonStart));
    assert.equal(parsed.ok, true);
    assert.ok('depsChecked' in parsed && 'newAdvisories' in parsed);
  } finally { await p.cleanup(); }
}, { timeout: 60000 });
