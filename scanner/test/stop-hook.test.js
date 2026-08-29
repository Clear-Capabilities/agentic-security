// Stop hook smoke test (premortem #C.5).
//
// Verifies the drift-check hook script:
//   - runs without crashing on empty input
//   - exits 0 always (Stop hooks must never block chaining)
//   - flags an untracked .js file under scanner/src/{sast,posture,dataflow,mcp}/
//     whose basename does NOT appear in the relevant subdir CLAUDE.md
//
// We exercise the script in a temp git repo so the WATCHED-prefix logic and
// the basename/stem inclusion check are tested without depending on this
// repo's actual git state.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK = path.resolve(__dirname, '..', '..', 'hooks', 'session-stop-drift-check.js');

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'stop-hook-'));
}

function runHook(cwd) {
  const r = cp.spawnSync('node', [HOOK], {
    cwd, env: { ...process.env, CLAUDE_PROJECT_DIR: cwd },
    // 60s, not 20s and originally not 4s: this spawns a real child process,
    // and the ceiling has to cover the WORST case this test actually runs in,
    // which is `npm test`'s full parallel suite (~200 files), not an idle
    // machine. Measured: the whole file completes in ~444ms run alone, and
    // still blew past 20s under full-suite contention — a >45x starvation
    // factor — where it failed the pre-push gate and blocked a release. Each
    // raise here (4s → 20s → 60s) came from the same false failure: a
    // `status:null` timeout, never a real assertion. 60s matches the budget
    // other real-CLI-subprocess tests in this repo already use for the same
    // reason (see test/cli/attest-provenance.test.js) and still catches a
    // genuine hang, since the real work is sub-second.
    input: '{}', encoding: 'utf8', timeout: 60000,
  });
  return { code: r.status, stderr: r.stderr || '', stdout: r.stdout || '' };
}

test('Stop hook exits 0 with no git repo', () => {
  const dir = mkTmp();
  const r = runHook(dir);
  assert.equal(r.code, 0);
});

test('Stop hook flags untracked posture module not mentioned in CLAUDE.md', () => {
  const dir = mkTmp();
  cp.execFileSync('git', ['init', '-q'], { cwd: dir });
  cp.execFileSync('git', ['-c', 'user.email=t@t.t', '-c', 'user.name=t', 'commit', '--allow-empty', '-m', 'init', '-q'], { cwd: dir });
  fs.mkdirSync(path.join(dir, 'scanner/src/posture'), { recursive: true });
  // CLAUDE.md is empty so the module is definitely not indexed.
  fs.writeFileSync(path.join(dir, 'scanner/src/posture/CLAUDE.md'), '# posture\n\nnothing here\n');
  fs.writeFileSync(path.join(dir, 'scanner/src/posture/new-annotator.js'), '// untracked\nexport function annotate(){}\n');
  const r = runHook(dir);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /new-annotator\.js/, `expected drift warning in stderr, got: ${r.stderr}`);
  assert.match(r.stderr, /scanner\/src\/posture\/CLAUDE\.md/);
});

test('Stop hook drift check stays quiet when module IS mentioned in CLAUDE.md', () => {
  const dir = mkTmp();
  cp.execFileSync('git', ['init', '-q'], { cwd: dir });
  cp.execFileSync('git', ['-c', 'user.email=t@t.t', '-c', 'user.name=t', 'commit', '--allow-empty', '-m', 'init', '-q'], { cwd: dir });
  fs.mkdirSync(path.join(dir, 'scanner/src/posture'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'scanner/src/posture/CLAUDE.md'), '# posture\n\n- `new-annotator.js` — the annotator\n');
  fs.writeFileSync(path.join(dir, 'scanner/src/posture/new-annotator.js'), 'export function annotate(){}\n');
  // Pre-populate AGENTS.md so the second nudge (harness-anatomy #2) stays
  // quiet too; this test isolates the drift-check half of the hook.
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security/AGENTS.md'), '# AGENTS.md\n');
  const r = runHook(dir);
  assert.equal(r.code, 0);
  // Drift portion must be silent (no CLAUDE.md drift warning).
  assert.ok(!/CLAUDE\.md drift/.test(r.stderr), `expected no drift warning, got: ${r.stderr}`);
  assert.ok(!/new-annotator\.js/.test(r.stderr), `module already-indexed, no drift mention expected`);
});

test('Stop hook ignores test files and fixtures', () => {
  const dir = mkTmp();
  cp.execFileSync('git', ['init', '-q'], { cwd: dir });
  cp.execFileSync('git', ['-c', 'user.email=t@t.t', '-c', 'user.name=t', 'commit', '--allow-empty', '-m', 'init', '-q'], { cwd: dir });
  fs.mkdirSync(path.join(dir, 'scanner/src/sast/fixtures'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'scanner/src/sast/test'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'scanner/src/sast/CLAUDE.md'), '# sast\n');
  fs.writeFileSync(path.join(dir, 'scanner/src/sast/fixtures/vulnerable.js'), '// fixture\n');
  fs.writeFileSync(path.join(dir, 'scanner/src/sast/something.test.js'), '// test\n');
  const r = runHook(dir);
  assert.equal(r.code, 0);
  assert.equal(r.stderr.trim(), '', `fixtures/tests should be skipped, got: ${r.stderr}`);
});
