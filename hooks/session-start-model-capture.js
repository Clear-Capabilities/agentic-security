#!/usr/bin/env node
// SessionStart hook: persist the session's model so the per-prompt advisor
// (hooks/model-cost-advisor.js) can compute a cheaper-model downgrade.
//
// Why this exists: there is no $CLAUDE_MODEL env var, and the model is exposed
// ONLY to SessionStart hooks (input.model, "not guaranteed to be present").
// So we capture it here, once, to .agentic-security/model-optimizer-state.json.
// The advisor falls back to its configured `assumedModel` when this is absent.
//
// Side-effect free beyond writing that one small state file; exits 0 always;
// does nothing if the optimizer is disabled or the model is absent.
//
// Plain CommonJS — zero deps beyond the standard library.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cfgPath = path.join(stateDir, 'model-optimizer.json');
const statePath = path.join(stateDir, 'model-optimizer-state.json');

function optimizerEnabled() {
  if (process.env.AGENTIC_SECURITY_MODEL_OPTIMIZER === 'off') return false;
  try {
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    return cfg.mode === 'advise';
  } catch { return false; } // no config → default off → don't write state
}

function readStdinJSON() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve({});
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

(async () => {
  const input = await readStdinJSON(); // drain stdin so the parent doesn't hang
  if (!optimizerEnabled()) process.exit(0);

  const model = typeof input.model === 'string' ? input.model : null;
  if (!model) process.exit(0); // harness omitted it — advisor uses assumedModel

  try {
    fs.mkdirSync(stateDir, { recursive: true });
    // turns: 0 resets the advisor's per-session cached-context estimate.
    fs.writeFileSync(statePath, JSON.stringify({ model, capturedAt: new Date().toISOString(), turns: 0 }) + '\n');
  } catch { /* best-effort; never break the session */ }
  process.exit(0);
})();
