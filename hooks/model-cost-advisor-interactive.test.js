'use strict';
// Interactive-mode tests for the model-cost advisor (`"interactive": true` in
// .agentic-security/model-optimizer.json). Separate file from
// model-cost-advisor.test.js on purpose: model-cost-advisor.js resolves its
// config/state file paths ONCE at module load, from CLAUDE_PROJECT_DIR — so
// this file points that at a fresh temp dir BEFORE requiring the module. Doing
// that in the existing test file would risk affecting its module-load order;
// keeping it separate leaves the ~30 existing buildAdvice() assertions
// completely untouched. Run: node --test hooks/model-cost-advisor-interactive.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'as-advisor-'));
process.env.CLAUDE_PROJECT_DIR = TMP;

const { advise, readSubagentOverride, buildInteractiveDirective, MODELS, TIER_RECO } = require('./model-cost-advisor.js');

const STATE_DIR = path.join(TMP, '.agentic-security');
const CFG_PATH = path.join(STATE_DIR, 'model-optimizer.json');
const STATE_PATH = path.join(STATE_DIR, 'model-optimizer-state.json');

function writeCfg(cfg) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(CFG_PATH, JSON.stringify(cfg));
}
function writeState(state) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(STATE_PATH, JSON.stringify(state));
}
function clearState() {
  try { fs.unlinkSync(STATE_PATH); } catch { /* already absent */ }
}

const SIMPLE_PROMPT = 'what is a promise in javascript?';

test('advise — interactive:false preserves the legacy {systemMessage} shape', async () => {
  writeCfg({ mode: 'advise', interactive: false });
  clearState();
  const out = await advise({ prompt: SIMPLE_PROMPT });
  assert.ok(out);
  assert.equal(typeof out.systemMessage, 'string');
  assert.equal(out.additionalContext, undefined);
});

test('advise — interactive:true, undecided, tip exists → both systemMessage and additionalContext', async () => {
  writeCfg({ mode: 'advise', interactive: true });
  clearState();
  const out = await advise({ prompt: SIMPLE_PROMPT });
  assert.ok(out);
  assert.equal(typeof out.systemMessage, 'string');
  assert.equal(typeof out.additionalContext, 'string');
  assert.match(out.additionalContext, /AskUserQuestion/);
  assert.match(out.additionalContext, /Keep current settings/);
});

test('advise — interactive:true, no tip (already on the cheapest model) → null', async () => {
  writeCfg({ mode: 'advise', interactive: true });
  // Already on Haiku — buildAdvice never recommends an "upgrade", so no tip
  // fires regardless of tier (mirrors the proven case in model-cost-advisor.test.js).
  writeState({ model: 'claude-haiku-4-5' });
  const out = await advise({ prompt: 'refactor the entire billing service and migrate the schema' });
  assert.equal(out, null);
});

test('advise — interactive:true + previously declined → null even though a tip would fire', async () => {
  writeCfg({ mode: 'advise', interactive: true });
  writeState({ subagentOverrideDeclined: true });
  const out = await advise({ prompt: SIMPLE_PROMPT });
  assert.equal(out, null);
});

test('advise — interactive:true + accepted override → systemMessage-only re-confirmation, no repeat cost', async () => {
  writeCfg({ mode: 'advise', interactive: true });
  writeState({ subagentOverride: { model: 'claude-haiku-4-5', effort: null, setAt: new Date().toISOString() } });
  const out = await advise({ prompt: SIMPLE_PROMPT });
  assert.ok(out);
  assert.equal(typeof out.systemMessage, 'string');
  assert.match(out.systemMessage, /Haiku 4\.5/);
  assert.equal(out.additionalContext, undefined);
});

test('advise — an invalid/unknown override model is treated as undecided (directive still fires)', async () => {
  writeCfg({ mode: 'advise', interactive: true });
  writeState({ subagentOverride: { model: 'not-a-real-model', effort: null, setAt: 'x' } });
  const out = await advise({ prompt: SIMPLE_PROMPT });
  assert.ok(out);
  assert.equal(typeof out.additionalContext, 'string');
});

test('advise — cooldown suppresses a repeat directive within interactiveCooldownTurns', async () => {
  writeCfg({ mode: 'advise', interactive: true, interactiveCooldownTurns: 3 });
  clearState();
  const first = await advise({ prompt: SIMPLE_PROMPT });
  assert.equal(typeof first.additionalContext, 'string', 'fires the first time');
  const second = await advise({ prompt: SIMPLE_PROMPT });
  assert.equal(second.additionalContext, undefined, 'cooldown suppresses the very next call');
  assert.equal(typeof second.systemMessage, 'string', 'the free tip still shows during cooldown');
});

test('readSubagentOverride — accepted / declined / undecided / invalid states', () => {
  writeState({ subagentOverride: { model: 'claude-haiku-4-5', effort: 'low', setAt: 'x' } });
  assert.deepEqual(readSubagentOverride(), { model: 'claude-haiku-4-5', effort: 'low', setAt: 'x' });

  writeState({ subagentOverrideDeclined: true });
  assert.equal(readSubagentOverride(), 'declined');

  writeState({});
  assert.equal(readSubagentOverride(), null);

  writeState({ subagentOverride: { model: 'bogus-model' } });
  assert.equal(readSubagentOverride(), null);
});

test('buildInteractiveDirective — names the exact write instructions for each answer', () => {
  const dir = buildInteractiveDirective({ tier: 'simple', reco: TIER_RECO.simple, table: MODELS });
  assert.match(dir, /AskUserQuestion/);
  assert.match(dir, /subagentOverrideDeclined/);
  assert.match(dir, /subagentOverride/);
  assert.match(dir, /model-optimizer-state\.json/);
  assert.match(dir, /Haiku 4\.5/);
});

test('cleanup: remove the temp CLAUDE_PROJECT_DIR', () => {
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* best-effort */ }
});
