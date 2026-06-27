#!/usr/bin/env node
// UserPromptSubmit hook: per-prompt model + reasoning-depth advisor.
//
// Looks at the prompt the user just submitted, scores it as simple/medium/
// complex with a ZERO-TOKEN local heuristic (no LLM call, no network), and —
// when a strictly cheaper model+depth would likely do the job just as well —
// shows a one-line tip with the estimated token-cost savings.
//
// HARD LIMITS (see docs/MODEL_COST_OPTIMIZATION_PRD.md §2):
//   • A hook CANNOT switch the model or effort. There is no output field for
//     it anywhere in the Claude Code hook schema. So this is advisory only:
//     it suggests, the user taps /model + /effort.
//   • The tip is emitted via `systemMessage` (shown to the user, out-of-band)
//     and NEVER via `additionalContext` (which would be injected into Claude's
//     context and BILLED as input tokens — defeating the whole point).
//
// Behavior controlled by .agentic-security/model-optimizer.json:
//   { "mode": "off" | "advise", "minSavingsUsd": 0.01,
//     "assumedModel": "claude-opus-4-8" }
//   Default mode: "off" (ships dormant; enable via `/setup --model-optimizer`).
//   Kill switch: env AGENTIC_SECURITY_MODEL_OPTIMIZER=off.
//
// Always exits 0 — never blocks, never erases the prompt.
//
// Plain CommonJS — zero deps beyond the standard library.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cfgPath = path.join(stateDir, 'model-optimizer.json');
const statePath = path.join(stateDir, 'model-optimizer-state.json');

// ── Pricing & capability table ────────────────────────────────────────────
// Per 1M tokens (input / output). Source: claude-api skill, cached 2026-05-26.
// Refresh from docs/MODEL_COST_OPTIMIZATION_PRD.md §2 when rates change.
const MODELS = {
  'claude-opus-4-8':   { key: 'opus',   short: 'opus',   label: 'Opus 4.8',   in: 5, out: 25, effort: true },
  'claude-sonnet-4-6': { key: 'sonnet', short: 'sonnet', label: 'Sonnet 4.6', in: 3, out: 15, effort: true },
  'claude-haiku-4-5':  { key: 'haiku',  short: 'haiku',  label: 'Haiku 4.5',  in: 1, out: 5,  effort: false },
};

// Representative token profile per tier (estimate, not a live count).
const TIER_PROFILE = {
  simple:  { in: 1500,  out: 500 },
  medium:  { in: 8000,  out: 3000 },
  complex: { in: 30000, out: 8000 },
};

// Tier → cheapest sensible model+depth.
const TIER_RECO = {
  simple:  { model: 'claude-haiku-4-5',  effort: null },
  medium:  { model: 'claude-sonnet-4-6', effort: 'low' },
  complex: { model: 'claude-opus-4-8',   effort: 'high' },
};

// Effort acts as a within-model cost multiplier on the output (thinking) leg.
const EFFORT_MULT = { low: 0.6, medium: 1.0, high: 1.4, xhigh: 1.7, max: 2.0 };
function effortMult(effort) {
  if (!effort) return 1.0;
  return EFFORT_MULT[String(effort).toLowerCase()] ?? 1.0;
}

// ── Config / state I/O ──────────────────────────────────────────────────────
function readCfg() {
  const defaults = { mode: 'off', minSavingsUsd: 0.01, assumedModel: 'claude-opus-4-8', models: null };
  try {
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    return { ...defaults, ...parsed };
  } catch { return defaults; }
}

function readSessionModel() {
  try {
    const s = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return typeof s.model === 'string' ? s.model : null;
  } catch { return null; }
}

function readStdinJSON() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve({});
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    // Never hang the prompt submit if stdin is empty.
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

// ── Pure helpers (exported for tests) ───────────────────────────────────────

// Map any model string (full id, dated snapshot, or family word) to a known
// pricing entry. Returns the canonical id key, or null if the family is
// unrecognised (in which case we decline to advise rather than guess).
function modelKey(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  const s = raw.toLowerCase();
  if (s.includes('haiku')) return 'claude-haiku-4-5';
  if (s.includes('sonnet')) return 'claude-sonnet-4-6';
  if (s.includes('opus')) return 'claude-opus-4-8';
  return null;
}

// Zero-token heuristic classifier. Returns 'simple' | 'medium' | 'complex'.
// Rule table documented in docs/MODEL_COST_OPTIMIZATION_PRD.md R4.
const CHEAP_VERBS = /\b(explain|summari[sz]e|rename|format|list|what is|define|describe|translate)\b/i;
const EXPENSIVE_VERBS = /\b(refactor|design|debug|architect|migrate|implement|optimi[sz]e|rewrite|build|integrate)\b/i;
const FILE_MENTION = /(?:\b\w[\w-]*\/[\w./-]+|\b\w[\w-]*\.(?:js|ts|tsx|jsx|py|java|go|rb|php|cs|rs|json|ya?ml|md|sql|sh))\b/i;
const STACKTRACE = /(?:^|\n)\s*(?:at\s+\w|Error:|Traceback|Exception\b|\w+Error\b)/;

function classifyTier(prompt) {
  const text = typeof prompt === 'string' ? prompt : '';
  const len = text.length;
  const fences = (text.match(/```/g) || []).length / 2;
  const lines = (text.match(/\n/g) || []).length + 1;
  const expensive = EXPENSIVE_VERBS.test(text);
  const hasTrace = STACKTRACE.test(text);
  const hasFile = FILE_MENTION.test(text);

  let score = 0; // negative → simpler, positive → more complex
  if (expensive) score += 2;
  if (hasTrace) score += 2;
  if (len > 1500 || fences >= 2) score += 2;
  if (fences >= 1) score += 1;
  if (lines > 15) score += 1;
  if (hasFile) score += 1;
  if (CHEAP_VERBS.test(text)) score -= 1;
  // The "short & chatty" simple bias applies only when no strong complexity
  // signal is present — otherwise a terse "refactor X and migrate Y" would be
  // mis-scored as simple.
  if (len < 280 && fences === 0 && !expensive && !hasTrace && !hasFile) score -= 2;

  if (score <= -2) return 'simple';
  if (score >= 2) return 'complex';
  return 'medium';
}

// Estimated dollar cost of answering a `tier` prompt on `modelId` at `effort`.
function estimateCost(modelId, tier, effort, modelsOverride) {
  const table = modelsOverride || MODELS;
  const m = table[modelId];
  const prof = TIER_PROFILE[tier];
  if (!m || !prof) return null;
  const eff = m.effort ? effortMult(effort) : 1.0;
  const inUsd = (prof.in / 1e6) * m.in;
  const outUsd = (prof.out / 1e6) * m.out * eff;
  return inUsd + outUsd;
}

function roundUsd(n) {
  if (n >= 1) return `$${n.toFixed(2)}`;
  if (n >= 0.01) return `$${n.toFixed(3)}`;
  return `$${n.toFixed(4)}`;
}

// Core decision. Returns a tip string, or null when there's nothing cheaper
// worth suggesting. Pure — all inputs passed in, no I/O.
function buildAdvice({ prompt, currentModel, currentEffort, minSavingsUsd = 0.01, assumedModel = 'claude-opus-4-8', modelAssumed = false, models = null }) {
  const curId = modelKey(currentModel) || modelKey(assumedModel);
  if (!curId) return null;

  const tier = classifyTier(prompt);
  const reco = TIER_RECO[tier];
  const recId = reco.model;

  // R6: only ever suggest a strict, cheaper downgrade.
  const curCost = estimateCost(curId, tier, currentEffort, models);
  const recCost = estimateCost(recId, tier, reco.effort, models);
  if (curCost == null || recCost == null) return null;

  const savings = curCost - recCost;
  if (savings < minSavingsUsd) return null; // includes same/cheaper-already cases

  const pct = Math.round((savings / curCost) * 100);
  const table = models || MODELS;
  const sameModel = curId === recId;
  const assumedNote = modelAssumed ? ' (assuming your model)' : '';

  if (sameModel) {
    // Only the depth changes — keep the model, drop effort.
    return `\u{1F4A1} This ${tier} task could run at lower depth${assumedNote}. `
      + `/effort ${reco.effort} on ${table[recId].label} would cost ~${pct}% less `
      + `(est. ~${roundUsd(curCost)} → ~${roundUsd(recCost)}).`;
  }

  const effortStep = reco.effort ? `  then  /effort ${reco.effort}` : '';
  const depthWord = reco.effort ? ` ${reco.effort}` : '';
  return `\u{1F4A1} This looks like a ${tier} task${assumedNote}. ${table[recId].label}${depthWord} `
    + `would cost ~${pct}% less (est. ~${roundUsd(curCost)} → ~${roundUsd(recCost)}). `
    + `Run:  /model ${table[recId].short}${effortStep}`;
}

// ── Entry point ─────────────────────────────────────────────────────────────
async function main() {
  // Kill switch wins over everything.
  if (process.env.AGENTIC_SECURITY_MODEL_OPTIMIZER === 'off') process.exit(0);

  const cfg = readCfg();
  if (cfg.mode !== 'advise') process.exit(0); // default 'off' → silent no-op

  const input = await readStdinJSON();
  const prompt = input.prompt || '';
  if (!prompt) process.exit(0);

  const captured = readSessionModel();
  const currentModel = captured || cfg.assumedModel;
  const tip = buildAdvice({
    prompt,
    currentModel,
    currentEffort: process.env.CLAUDE_EFFORT || null,
    minSavingsUsd: cfg.minSavingsUsd,
    assumedModel: cfg.assumedModel,
    modelAssumed: !captured,
    models: cfg.models,
  });

  if (tip) {
    // systemMessage ONLY — never additionalContext (that would cost tokens).
    process.stdout.write(JSON.stringify({ systemMessage: tip }));
  }
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = {
  MODELS, TIER_PROFILE, TIER_RECO,
  modelKey, classifyTier, estimateCost, effortMult, roundUsd, buildAdvice,
};
