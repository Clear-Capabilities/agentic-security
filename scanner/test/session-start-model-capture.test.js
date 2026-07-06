// Tests for hooks/session-start-model-capture.js. The load-bearing guarantee
// for the interactive cost-advisor feature: its bare (non-merge) overwrite of
// model-optimizer-state.json at every SessionStart is what makes an
// interactive subagent-model choice "sticky for the session" and not sticky
// forever — confirm it actually clears those fields, don't just assume the
// existing turns-reset behavior generalizes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cp from 'node:child_process';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, '..', '..', 'hooks', 'session-start-model-capture.js');

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

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-sscap-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  // Optimizer must be enabled (mode:"advise") for this hook to write at all —
  // its own optimizerEnabled() gate treats a missing/non-advise config as off.
  await fsp.writeFile(path.join(stateDir, 'model-optimizer.json'), JSON.stringify({ mode: 'advise' }));
  return { dir, stateDir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('session-start-model-capture: bare overwrite clears a prior session\'s subagentOverride/declined/lastDirectiveTurn', async () => {
  const p = await mkProject();
  try {
    const statePath = path.join(p.stateDir, 'model-optimizer-state.json');
    // Simulate a prior session that had accepted an interactive override.
    await fsp.writeFile(statePath, JSON.stringify({
      model: 'claude-haiku-4-5',
      turns: 7,
      subagentOverride: { model: 'claude-haiku-4-5', effort: null, setAt: 'old' },
      subagentOverrideDeclined: false,
      lastDirectiveTurn: 5,
    }));

    const r = await run(p.dir, { model: 'claude-opus-4-8' });
    assert.equal(r.code, 0);

    const after = JSON.parse(await fsp.readFile(statePath, 'utf8'));
    assert.equal(after.model, 'claude-opus-4-8', 'captures the new session\'s model');
    assert.equal(after.turns, 0, 'resets the turn counter');
    assert.equal(after.subagentOverride, undefined, 'clears the prior override');
    assert.equal(after.subagentOverrideDeclined, undefined, 'clears the prior decline');
    assert.equal(after.lastDirectiveTurn, undefined, 'clears the prior cooldown bookkeeping');
  } finally { await p.cleanup(); }
});

test('session-start-model-capture: missing input.model exits without touching an existing override (known limitation)', async () => {
  const p = await mkProject();
  try {
    const statePath = path.join(p.stateDir, 'model-optimizer-state.json');
    await fsp.writeFile(statePath, JSON.stringify({
      subagentOverride: { model: 'claude-haiku-4-5', effort: null, setAt: 'old' },
    }));

    const r = await run(p.dir, {}); // no model field in the SessionStart payload
    assert.equal(r.code, 0);

    const after = JSON.parse(await fsp.readFile(statePath, 'utf8'));
    assert.deepEqual(after.subagentOverride, { model: 'claude-haiku-4-5', effort: null, setAt: 'old' },
      'documents the existing behavior: absent input.model means this hook exits before writing, so a stale override can survive — a pre-existing limitation, not introduced by the interactive feature');
  } finally { await p.cleanup(); }
});
