// PRD FR 01: `scan --watch` with scope flags, end to end through the real CLI. The watcher must ask the same inventory as the scan: a
// change to a Git-ignored file does not rescan, and a change to a TRACKED file under a directory the default filter skips (`dist/`) does.
// The second half is what proves the scope filter is the one in use: the default watcher filter would never rescan for `dist/`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const until = async (cond, ms, what) => {
  const t0 = Date.now();
  while (!cond()) { if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 100)); }
};
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

test('scan --watch with scope flags: an ignored file never rescans, a tracked file under dist/ does', { timeout: 120_000 }, async () => {
  const dir = mkTestTmp('watch-cli-');
  const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  git('init', '-q');
  const files = { '.gitignore': 'generated/\n', 'package.json': '{}', 'src/app.js': 'module.exports = 1;\n', 'dist/keep.js': 'module.exports = 2;\n', 'generated/out.js': 'module.exports = 3;\n' };
  for (const [rel, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); }
  git('add', '.gitignore', 'package.json', 'src/app.js'); git('add', '-f', 'dist/keep.js');

  const child = spawn(process.execPath, [CLI, 'scan', dir, '--watch', '--respect-gitignore'], {
    env: { ...process.env, AGENTIC_SECURITY_NO_TELEMETRY: '1', AGENTIC_SECURITY_LLM_ENDPOINT: '' }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (d) => { err += d.toString(); });
  const rescans = () => (err.match(/^\[watch\] (?!scanning|first scan done|rescan failed)/gm) || []).length;
  try {
    await until(() => /\[watch\] scanning/.test(err), 30_000, 'the watch banner');
    await until(() => /\[watch\] first scan done .*in the scan scope/.test(err), 90_000, 'the first scan');
    await pause(1500); // the watcher starts right after the first scan returns

    fs.writeFileSync(path.join(dir, 'generated/out.js'), 'module.exports = 4;\n');
    await pause(6000);
    assert.equal(rescans(), 0, `a Git-ignored file triggered a rescan:\n${err}`);

    fs.writeFileSync(path.join(dir, 'dist/keep.js'), 'module.exports = 5;\n');
    await until(() => rescans() >= 1, 60_000, 'the rescan for the tracked dist/ file').catch((e) => { throw new Error(`${e.message}\n${JSON.stringify(err.slice(-1500))}`); });
    assert.ok(!/rescan failed/.test(err), err);
  } finally {
    child.kill('SIGTERM');
  }
});
