// Tests for the UserPromptSubmit dispatcher (#24). Since 0.195.34 it runs one sub-hook, the legacy-alias redirect; the per-prompt
// model-cost advisor was removed. CJS hook modules, loaded via createRequire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { mergeOutputs } = require('../../hooks/dispatch-user-prompt.js');
const HOOKS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'hooks');

test('mergeOutputs: an alias hit → additionalContext, no systemMessage', () => {
  const out = mergeOutputs({ aliasHit: { alias: 'status', replacement: '/posture --status', rest: '' } });
  assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.match(out.hookSpecificOutput.additionalContext, /\/posture --status/);
  assert.equal(out.systemMessage, undefined);
});

test('mergeOutputs: no alias → empty object (dispatcher writes nothing)', () => {
  assert.deepEqual(mergeOutputs({ aliasHit: null }), {});
});

test('the model-cost advisor is gone: no module, no SessionStart model capture, no hook registration', () => {
  for (const f of ['model-cost-advisor.js', 'session-start-model-capture.js']) assert.ok(!fs.existsSync(path.join(HOOKS, f)), `${f} still exists`);
  const hooksJson = fs.readFileSync(path.join(HOOKS, 'hooks.json'), 'utf8');
  assert.doesNotMatch(hooksJson, /model-cost-advisor|model-capture/);
  assert.doesNotMatch(fs.readFileSync(path.join(HOOKS, 'dispatch-user-prompt.js'), 'utf8'), /model-cost-advisor|advise/);
});

test('a project that still has the old advisor config gets no advice from the dispatcher', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dispatch-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'model-optimizer.json'), JSON.stringify({ mode: 'advise', costQualityTradeoff: 10, minSavingsUsd: 0 }));
    const r = spawnSync(process.execPath, [path.join(HOOKS, 'dispatch-user-prompt.js')], {
      cwd: dir, input: JSON.stringify({ prompt: 'fix the typo in README.md', cwd: dir }), encoding: 'utf8', env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, '');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
