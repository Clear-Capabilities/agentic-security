// S7 (posture --report-card) — cmdScan's post-scan streak update
// (`recordScan(stateDirPath, persistedScan)`) referenced `persistedScan`
// outside the `if (_writesOnScan() && _isSafeStateDir(stateDirPath))` block
// it was declared in with `const` — a ReferenceError on every single scan,
// silently swallowed by the empty `catch {}` around the call. Reproduced
// live: a real CLI scan against a fixture with a package.json (a normal,
// writable project) never created .agentic-security/streak.json at all, no
// matter how many times it ran. Confirmed the mechanism with an isolated
// repro (`if (true) { const x = 42; } x` throws ReferenceError outside the
// block) before treating it as a real bug rather than a scoping assumption.
//
// This means grade tracking, streak days, and achievements — the entire
// posture/streak.js feature — never actually persisted anything when run
// through the real CLI, despite recordScan() itself working correctly when
// called directly (verified independently).
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
  const dst = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-streak-'));
  for (const entry of await fsp.readdir(fixture, { withFileTypes: true })) {
    if (entry.isFile()) await fsp.copyFile(path.join(fixture, entry.name), path.join(dst, entry.name));
  }
  return dst;
}

test('S7: a real CLI scan writes .agentic-security/streak.json with a real grade', async () => {
  const dir = await copyFixture();
  try {
    const r = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);

    const streakPath = path.join(dir, '.agentic-security', 'streak.json');
    assert.ok(fs.existsSync(streakPath), 'streak.json must exist after a scan of a normal, writable project');
    const streak = JSON.parse(fs.readFileSync(streakPath, 'utf8'));
    assert.ok(streak.lastGrade, `expected a real letter grade, got: ${JSON.stringify(streak)}`);
    assert.match(streak.lastGrade, /^[ABCDF][+-]?$/);
    assert.equal(streak.totalScans, 1);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('S7: --no-state (AGENTIC_SECURITY_NO_STATE=1) writes no streak.json either — a non-mutating scan must mutate nothing', async () => {
  const dir = await copyFixture();
  try {
    const r = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network'], {
      encoding: 'utf8', env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
    });
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);
    assert.ok(!fs.existsSync(path.join(dir, '.agentic-security')),
      'a --no-state scan must create no .agentic-security/ directory at all, including streak.json');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
