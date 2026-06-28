// Tests for the PreToolUse cache-invalidator guard hook (F2).
import { test } from 'node:test';
import assert from 'node:assert';
import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOOK = path.resolve(__dirname, '..', '..', 'hooks', 'cache-invalidator-guard.js');
const FIXTURE = path.join(__dirname, 'fixtures', 'cache-economics', 'session.jsonl');

function run(evt, env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cache-guard-'));
  try {
    const r = cp.spawnSync('node', [HOOK], {
      cwd: dir,
      env: { ...process.env, CLAUDE_PROJECT_DIR: dir, ...env },
      input: JSON.stringify(evt), encoding: 'utf8', timeout: 5000,
    });
    return { code: r.status, stderr: r.stderr || '', stdout: r.stdout || '' };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('warns when editing CLAUDE.md with a warm cache', () => {
  const r = run({ tool_name: 'Edit', tool_input: { file_path: '/proj/CLAUDE.md' }, transcript_path: FIXTURE });
  assert.equal(r.code, 0);
  assert.match(r.stderr, /invalidates your prompt cache/);
  assert.match(r.stderr, /cached tokens/);
});

test('warns when editing .claude/settings.json with a warm cache', () => {
  const r = run({ tool_name: 'Write', tool_input: { file_path: '/proj/.claude/settings.json' }, transcript_path: FIXTURE });
  assert.match(r.stderr, /Claude Code settings/);
});

test('silent on a normal source file', () => {
  const r = run({ tool_name: 'Edit', tool_input: { file_path: '/proj/src/app.js' }, transcript_path: FIXTURE });
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
});

test('silent when no transcript / no warm cache', () => {
  const r = run({ tool_name: 'Edit', tool_input: { file_path: '/proj/CLAUDE.md' }, transcript_path: '/nope/missing.jsonl' });
  assert.equal(r.stderr, '');
});

test('AGENTIC_SECURITY_QUIET=1 silences it', () => {
  const r = run({ tool_name: 'Edit', tool_input: { file_path: '/proj/CLAUDE.md' }, transcript_path: FIXTURE }, { AGENTIC_SECURITY_QUIET: '1' });
  assert.equal(r.stderr, '');
});

test('kill switch disables it', () => {
  const r = run({ tool_name: 'Edit', tool_input: { file_path: '/proj/CLAUDE.md' }, transcript_path: FIXTURE }, { AGENTIC_SECURITY_CACHE_GUARD: 'off' });
  assert.equal(r.stderr, '');
});
