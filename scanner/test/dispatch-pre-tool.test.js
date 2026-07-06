// Tests for hooks/dispatch-pre-tool.js — the consolidated PreToolUse dispatcher
// (#24). The load-bearing guarantee is that consolidation does NOT weaken the
// security block: a critical edit that the standalone bodyguard would deny must
// still deny here (exit 2). Also verifies the advisory hooks still fire when the
// guard allows.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cp from 'node:child_process';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, '..', '..', 'hooks', 'dispatch-pre-tool.js');

function run(projectDir, evt) {
  return new Promise((resolve) => {
    const child = cp.spawn('node', [BIN], {
      env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '', stdout = '';
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.on('exit', (code) => resolve({ code, stderr, stdout }));
    child.stdin.write(JSON.stringify(evt));
    child.stdin.end();
  });
}

async function mkProject({ mode } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-disp-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"disp-test"}');
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  if (mode) await fsp.writeFile(path.join(stateDir, 'bodyguard.json'), JSON.stringify({ mode }));
  return { dir, stateDir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('dispatcher: critical edit still BLOCKS (exit 2) in block mode', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await run(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
      },
    });
    assert.equal(r.code, 2, 'the security block must survive consolidation');
    assert.match(r.stderr, /BLOCKED/);
    assert.match(r.stderr, /SQL injection/);
  } finally { await p.cleanup(); }
});

test('dispatcher: clean edit exits 0 with no output', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await run(p.dir, {
      tool_name: 'Write',
      tool_input: { file_path: path.join(p.dir, 'app.js'), content: 'function add(a, b) { return a + b; }' },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stderr, '');
    assert.equal(r.stdout, '');
  } finally { await p.cleanup(); }
});

test('dispatcher: advisory context is injected when a finding exists (no block)', async () => {
  const p = await mkProject({ mode: 'warn' });
  try {
    await fsp.writeFile(path.join(p.stateDir, 'last-scan.json'), JSON.stringify({
      findings: [{ file: 'svc.js', line: 3, severity: 'high', vuln: 'SQL injection', stableId: 'abcdef1234567890' }],
    }));
    const r = await run(p.dir, {
      tool_name: 'Edit',
      tool_input: { file_path: path.join(p.dir, 'svc.js'), new_string: 'const x = safeThing();' },
    });
    assert.equal(r.code, 0, 'advisory context must never block the edit');
    assert.match(r.stdout, /agentic-security context for/);
    assert.match(r.stdout, /open finding/);
  } finally { await p.cleanup(); }
});
