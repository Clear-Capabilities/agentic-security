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
//   { "mode": "off" | "advise",
//     "costQualityTradeoff": 7,        // 0 = pure quality (never downgrade) … 10 = cheapest
//     "minSavingsUsd": 0.01,           // absolute anti-noise floor
//     "assumedModel": "claude-opus-4-8",
//     "assumedCachedTokens": null }    // null → grow estimate with session turns
//   Default mode: "off" (ships dormant; enable via `/setup --model-optimizer`).
//   Kill switch: env AGENTIC_SECURITY_MODEL_OPTIMIZER=off.
//
// Two ideas borrowed from OpenRouter (see the plan/PRD):
//   • cost_quality_tradeoff dial (their 0–10, default 7) — one knob trading
//     quality for cost; here it sets how eagerly we surface a downgrade.
//   • prompt-cache economics — switching models mid-session discards the cached
//     context prefix, so a switch's true cost includes a one-time cache rewarm.
//     We net that out, and prefer cache-preserving effort-only downgrades.
//
// Always exits 0 — never blocks, never erases the prompt.
//
// Plain CommonJS — zero deps beyond the standard library.
'use strict';
const fs = require('fs');
const path = require('path');
const transcript = require('./lib/transcript.js');

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

// Reasoning depth a tier actually warrants — used for cache-preserving advice
// (drop effort on the CURRENT model instead of switching models).
const TIER_DEPTH = { simple: 'low', medium: 'low', complex: 'high' };
const EFFORT_RANK = { low: 1, medium: 2, high: 3, xhigh: 4, max: 5 };
function effortRank(e) { return e ? (EFFORT_RANK[String(e).toLowerCase()] ?? 3) : 0; }

// ── Prompt-cache economics (learned from OpenRouter) ─────────────────────────
// Switching models mid-session throws away the cached context prefix: the new
// model re-ingests it cold (a cache WRITE ≈ 1.25× input) instead of the cheap
// cache READ ≈ 0.1× input you keep by staying. So a switch carries a one-time
// rewarm penalty we net against its per-prompt saving; effort-only downgrades on
// the SAME model keep the cache and pay nothing. Multipliers per the claude-api
// prompt-caching doc.
const CACHE_READ_MULT = 0.1;
const CACHE_WRITE_MULT = 1.25;
const CACHE_BASE_TOKENS = 2000;     // a roughly-cold session
const CACHE_PER_TURN_TOKENS = 4000; // rough context growth per advised turn

// One-time $ penalty of moving the cached prefix from curId onto recId.
function cacheRewarmPenalty(cachedTokens, curId, recId, modelsOverride) {
  const table = modelsOverride || MODELS;
  const cur = table[curId], rec = table[recId];
  if (!cur || !rec || !cachedTokens) return 0;
  const perMillion = CACHE_WRITE_MULT * rec.in - CACHE_READ_MULT * cur.in;
  return (cachedTokens / 1e6) * perMillion;
}

// Cost-quality dial (OpenRouter's cost_quality_tradeoff): 0 = pure quality
// (never downgrade) … 10 = cheapest (advise on any saving). Maps to the minimum
// fraction of the current cost a downgrade must save before we surface it.
function savingsFractionFloor(dial) {
  const d = Math.max(0, Math.min(10, Number.isFinite(dial) ? dial : 7));
  if (d <= 0) return Infinity;       // pure quality → never advise a downgrade
  return ((10 - d) / 10) * 0.4;      // dial 10 → 0%, 7 → 12%, 1 → 36%
}

// ── Config / state I/O ──────────────────────────────────────────────────────
function readCfg() {
  const defaults = { mode: 'off', costQualityTradeoff: 7, minSavingsUsd: 0.01,
    assumedModel: 'claude-opus-4-8', assumedCachedTokens: null,
    ttlSeconds: 300, breakEvenMaxTurns: 6, models: null };
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

// Advised-turn counter, reset per session by session-start-model-capture.js.
// Drives the growing cached-context estimate (deeper sessions penalise switches
// more). Zero-token, best-effort; never breaks the prompt.
function readTurns() {
  try {
    const s = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return Number.isInteger(s.turns) ? s.turns : 0;
  } catch { return 0; }
}
function bumpTurns(prev) {
  try {
    let s = {};
    try { s = JSON.parse(fs.readFileSync(statePath, 'utf8')); } catch {}
    s.turns = (Number.isInteger(prev) ? prev : 0) + 1;
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(statePath, JSON.stringify(s));
  } catch { /* best-effort */ }
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
//
// Considers two cache-aware candidates and surfaces the bigger qualifying win:
//   A) route to the tier's cheapest model+depth — if that's a model switch, its
//      saving is netted against the one-time cache-rewarm penalty (#1);
//   B) a cache-preserving effort-only downgrade on the CURRENT model.
// Both must clear the cost-quality dial's fraction floor + the absolute floor.
function buildAdvice({ prompt, currentModel, currentEffort, costQualityTradeoff = 7,
  minSavingsUsd = 0.01, assumedModel = 'claude-opus-4-8', modelAssumed = false,
  cachedContextTokens = 0, breakEvenMaxTurns = 6, models = null }) {
  const curId = modelKey(currentModel) || modelKey(assumedModel);
  if (!curId) return null;

  const fracFloor = savingsFractionFloor(costQualityTradeoff);
  if (!Number.isFinite(fracFloor)) return null; // dial 0 → pure quality, never advise

  const table = models || MODELS;
  const tier = classifyTier(prompt);
  const reco = TIER_RECO[tier];
  const curCost = estimateCost(curId, tier, currentEffort, models);
  if (curCost == null) return null;

  // Epsilon guards the float boundary (e.g. 0.025 − 0.015 lands a hair under 0.01).
  const EPS = 1e-9;
  const qualifies = (s) => (s + EPS) >= minSavingsUsd && (s / curCost) >= (fracFloor - EPS);

  // Candidate A — the tier's cheapest model+depth (may be a model switch).
  let A = null;
  {
    const recId = reco.model;
    const base = estimateCost(recId, tier, reco.effort, models);
    if (base != null) {
      const perTurn = curCost - base; // per-prompt saving, before any cache rewarm
      if (recId === curId) {
        // Same model, depth-only change — cache-safe, no break-even.
        if (qualifies(perTurn)) A = { kind: 'effort', model: recId, effort: reco.effort, savings: perTurn };
      } else {
        // Model switch — net the one-time cache rewarm against the per-turn saving
        // as a break-even horizon, and only advise it if it pays off soon (#3).
        const penalty = cacheRewarmPenalty(cachedContextTokens, curId, recId, models);
        const breakEven = penalty <= 0 ? 0 : (perTurn > 0 ? penalty / perTurn : Infinity);
        if (qualifies(perTurn) && breakEven <= breakEvenMaxTurns) {
          A = { kind: 'switch', model: recId, effort: reco.effort, savings: perTurn, breakEven };
        }
      }
    }
  }

  // Candidate B — cache-preserving effort-only downgrade on the CURRENT model.
  let B = null;
  if (table[curId] && table[curId].effort) {
    const target = TIER_DEPTH[tier];
    const cur = currentEffort || 'high'; // assume high when the harness didn't say
    if (effortRank(target) < effortRank(cur)) {
      const bCost = estimateCost(curId, tier, target, models);
      if (bCost != null) {
        const savings = curCost - bCost; // same model → no cache penalty
        if (qualifies(savings)) B = { kind: 'effort', model: curId, effort: target, savings };
      }
    }
  }

  // Bigger win wins; on a tie prefer the cache-safe effort downgrade (B).
  const pick = (A && B) ? (B.savings >= A.savings ? B : A) : (A || B);
  if (!pick) return null;

  const pct = Math.round((pick.savings / curCost) * 100);
  const assumedNote = modelAssumed ? ' (assuming your model)' : '';

  if (pick.kind === 'switch') {
    const depthWord = pick.effort ? ` ${pick.effort}` : '';
    const effortStep = pick.effort ? `  then  /effort ${pick.effort}` : '';
    // Break-even caveat: switching re-warms the cache, so it only pays off if the
    // session continues past N turns (#3). Omitted when the cache is cold/small.
    const be = pick.breakEven >= 1
      ? ` (worth it past ~${Math.ceil(pick.breakEven)} more turns — switching re-warms the cache)`
      : '';
    return `\u{1F4A1} This looks like a ${tier} task${assumedNote}. ${table[pick.model].label}${depthWord} `
      + `would cost ~${pct}% less per turn (est. ~${roundUsd(pick.savings)}/turn).${be} `
      + `Run:  /model ${table[pick.model].short}${effortStep}`;
  }
  // effort-only — keeps the model and its cached context.
  return `\u{1F4A1} This ${tier} task could run at lower depth${assumedNote} — keeps your model and cached context. `
    + `/effort ${pick.effort} on ${table[pick.model].label} would cost ~${pct}% less (est. saves ~${roundUsd(pick.savings)}).`;
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

  // Cached-context size: explicit override → real transcript size (0 if the
  // cache has gone cold past the TTL → free to switch, #3) → turns estimate.
  const turns = readTurns();
  let cachedContextTokens;
  if (typeof cfg.assumedCachedTokens === 'number') {
    cachedContextTokens = cfg.assumedCachedTokens;
  } else {
    const warm = transcript.latest({ transcriptPath: input.transcript_path, projectDir: cwd });
    if (warm) {
      const ttlMs = (cfg.ttlSeconds || 300) * 1000;
      cachedContextTokens = (warm.ageMs != null && warm.ageMs > ttlMs) ? 0 : warm.cacheTokens;
    } else {
      cachedContextTokens = CACHE_BASE_TOKENS + turns * CACHE_PER_TURN_TOKENS;
    }
  }

  const tip = buildAdvice({
    prompt,
    currentModel,
    currentEffort: process.env.CLAUDE_EFFORT || null,
    costQualityTradeoff: cfg.costQualityTradeoff,
    minSavingsUsd: cfg.minSavingsUsd,
    assumedModel: cfg.assumedModel,
    modelAssumed: !captured,
    cachedContextTokens,
    breakEvenMaxTurns: cfg.breakEvenMaxTurns,
    models: cfg.models,
  });

  if (tip) {
    // systemMessage ONLY — never additionalContext (that would cost tokens).
    process.stdout.write(JSON.stringify({ systemMessage: tip }));
  }
  bumpTurns(turns); // advance the session's cached-context estimate
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = {
  MODELS, TIER_PROFILE, TIER_RECO, TIER_DEPTH,
  modelKey, classifyTier, estimateCost, effortMult, roundUsd, buildAdvice,
  cacheRewarmPenalty, savingsFractionFloor, effortRank,
};
