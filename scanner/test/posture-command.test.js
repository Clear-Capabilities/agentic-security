// S7 — commands/posture.md's Implementation section named backing modules
// in prose ("Dispatches to existing command implementations... All modes
// preserved — no functional regression") without a single concrete
// invocation. --harness and --trend are the first two fixed with real,
// verified commands (the other five — --status, --report-card, --threat,
// --playbook, --mgmt — remain unwired, disclosed as such in the doc rather
// than left silently claiming full coverage).
//
// security-trend.js's computeTrend() had zero callers anywhere in the repo
// before this fix (confirmed by a repo-wide grep, and by its own entry in
// no-dead-modules.test.js's ALLOWLIST) — this command is what makes it
// genuinely reachable, which is why that allowlist entry is removed
// alongside this test (4R-6 decay rule, same precedent as effectiveVersion
// and computeStableId elsewhere in that file).
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = path.join(REPO_ROOT, 'scanner', 'test', 'fixtures', 'vulnerable-js');
const CLI = path.join(REPO_ROOT, 'scanner', 'dist', 'agentic-security.mjs');

function extractImplementationBlock() {
  const md = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'posture.md'), 'utf8');
  const lines = md.split('\n');
  const headingIdx = lines.findIndex((l) => l.trim() === '## Implementation');
  const fenceStart = lines.findIndex((l, i) => i > headingIdx && l.trim() === '```bash');
  const fenceEnd = lines.findIndex((l, i) => i > fenceStart && l.trim() === '```');
  assert.ok(fenceStart > headingIdx && fenceEnd > fenceStart, 'expected a fenced bash block under ## Implementation');
  return lines.slice(fenceStart + 1, fenceEnd).join('\n');
}

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'posture-cmd-'));
  fs.cpSync(FIXTURE, dir, { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runMode(script, arg, cwd) {
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'posture-run-')), 'run.sh');
  fs.writeFileSync(scriptPath, script);
  try {
    const out = execFileSync('bash', [scriptPath, arg], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: REPO_ROOT },
      timeout: 30000,
    });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

test('S7: posture.md --harness runs the real harness CLI subcommand', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject();
  try {
    const r = runMode(script, '--harness', p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /harness/i);
  } finally { await p.cleanup(); }
});

test('S7: posture.md --trend calls the real computeTrend() and reports a real delta', async () => {
  const script = extractImplementationBlock();
  const p = await mkProject();
  try {
    // Two real scans via the CLI so scan-history.json has something to diff.
    // Exit codes <=3 are normal severity verdicts here, not errors.
    for (let i = 0; i < 2; i++) {
      const scanResult = spawnSync('node', [CLI, 'scan', p.dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
      assert.ok(scanResult.status <= 3, `scan must exit <=3; got ${scanResult.status}: ${scanResult.stderr}`);
    }

    const r = runMode(script, '--trend', p.dir);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.hasTrend, true, `expected a real trend after 2 scans; got: ${r.stdout}`);
    assert.equal(typeof parsed.delta, 'number');
    assert.equal(typeof parsed.critDelta, 'number');
  } finally { await p.cleanup(); }
});
