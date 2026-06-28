'use strict';
// CJS twin of the transcript locator/parser for the CJS hooks (model-cost-advisor,
// cache-invalidator-guard). Kept deliberately small; scanner/src/posture/
// cache-economics.js is the ESM source of truth, and
// scanner/test/cache-economics.test.js asserts the two agree on a shared fixture.
//
// Zero deps, no network. Every call is best-effort and never throws.
const fs = require('fs');
const os = require('os');
const path = require('path');

function encodeProjectDir(dir) {
  return String(dir).replace(/[/.]/g, '-');
}

// Locate the session transcript: explicit hook-provided path, else the latest
// jsonl under ~/.claude/projects/<enc>/. Returns null if none.
function locate({ transcriptPath, projectDir } = {}) {
  try {
    if (transcriptPath && fs.existsSync(transcriptPath)) return transcriptPath;
  } catch { /* fall through */ }
  try {
    const dir = path.join(os.homedir(), '.claude', 'projects', encodeProjectDir(projectDir || process.cwd()));
    if (!fs.existsSync(dir)) return null;
    const files = fs.readdirSync(dir)
      .filter(f => f.endsWith('.jsonl'))
      .map(f => ({ f: path.join(dir, f), m: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.m - a.m);
    return files.length ? files[0].f : null;
  } catch { return null; }
}

// Parse priceable assistant-turn usage records (same shape as the ESM parser).
function parse(jsonlPath) {
  let raw;
  try { raw = fs.readFileSync(jsonlPath, 'utf8'); } catch { return []; }
  const out = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try { o = JSON.parse(t); } catch { continue; }
    if (o.type !== 'assistant') continue;
    const msg = o.message;
    const u = msg && msg.usage;
    // Priceable models only — drop "<synthetic>" sidechain/compaction turns so
    // this stays in lockstep with the ESM parser's rateFor() filter.
    if (!u || !msg.model || !/haiku|sonnet|opus/i.test(msg.model)) continue;
    out.push({
      model: msg.model,
      input: u.input_tokens || 0,
      output: u.output_tokens || 0,
      cacheRead: u.cache_read_input_tokens || 0,
      cacheCreate: u.cache_creation_input_tokens || 0,
      ts: o.timestamp ? Date.parse(o.timestamp) : null,
    });
  }
  return out;
}

// Last warm turn: { cacheTokens, model, ageMs } — the prefix a model switch
// would discard, the model it's cached under, and how stale it is. null if none.
function latest(opts = {}) {
  const f = locate(opts);
  if (!f) return null;
  const recs = parse(f);
  for (let i = recs.length - 1; i >= 0; i--) {
    const r = recs[i];
    const warm = r.cacheRead + r.cacheCreate + r.input;
    if (warm > 0) return { cacheTokens: warm, model: r.model, ageMs: r.ts ? Date.now() - r.ts : null };
  }
  return null;
}

// Size of the current warm prefix (input-side tokens), or 0 if unknown.
function latestCacheTokens(opts = {}) {
  const l = latest(opts);
  return l ? l.cacheTokens : 0;
}

// Milliseconds since the last priceable turn (cache-warmth age), or null.
function lastTurnAgeMs(opts = {}) {
  const l = latest(opts);
  return l ? l.ageMs : null;
}

// Actual $ spent so far this session (for F6 cache-budget biasing). Prices the
// real per-turn tokens: cache read ≈0.1×, write ≈1.25×, plus fresh in/out.
const RATE = { haiku: { in: 1, out: 5 }, sonnet: { in: 3, out: 15 }, opus: { in: 5, out: 25 } };
function rateFor(model) {
  const s = String(model || '').toLowerCase();
  if (s.includes('haiku')) return RATE.haiku;
  if (s.includes('sonnet')) return RATE.sonnet;
  if (s.includes('opus')) return RATE.opus;
  return null;
}
function sessionSpendUsd(opts = {}) {
  const f = locate(opts);
  if (!f) return 0;
  let usd = 0;
  for (const r of parse(f)) {
    const rt = rateFor(r.model);
    if (!rt) continue;
    const inRate = rt.in / 1e6, outRate = rt.out / 1e6;
    usd += r.cacheRead * inRate * 0.1 + r.cacheCreate * inRate * 1.25 + r.input * inRate + (r.output || 0) * outRate;
  }
  return usd;
}

module.exports = { locate, parse, latest, latestCacheTokens, lastTurnAgeMs, sessionSpendUsd, encodeProjectDir };
