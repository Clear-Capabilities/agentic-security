// Prompt-cache economics — turn Claude Code's own transcript usage into a
// dollarized report: how much prompt caching saved, how much was wasted on
// avoidable cache misses, and what invalidated the cache.
//
// Source of truth: the Claude Code transcript at
//   ~/.claude/projects/<enc>/<session>.jsonl
// where <enc> is CLAUDE_PROJECT_DIR with `/` and `.` replaced by `-`. Each
// assistant turn carries `message.usage` with input/output/cache_read/
// cache_creation token counts (and a 5m/1h write split). We price those against
// per-model rates to compute real economics — no estimates, no network.
//
// Pure compute on parsed records; only `locateTranscript`/`parseTranscriptUsage`
// touch the filesystem. ESM (scanner tree). A trimmed CJS twin lives at
// hooks/lib/transcript.js for the CJS hooks; test/cache-economics.test.js asserts
// the two agree.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Cents-scale money formatter (fmtUsd in risk-dollars.js targets five-figure
// breach costs and won't round sub-dollar values).
function money(n) {
  const v = Number(n) || 0;
  return Math.abs(v) >= 1 ? `$${v.toFixed(2)}` : `$${v.toFixed(4)}`;
}

// Per-1M-token rates (input / output). Mirror hooks/model-cost-advisor.js MODELS.
const MODEL_RATES = {
  opus:   { label: 'Opus 4.8',   in: 5, out: 25 },
  sonnet: { label: 'Sonnet 4.6', in: 3, out: 15 },
  haiku:  { label: 'Haiku 4.5',  in: 1, out: 5 },
};
const CACHE_READ_MULT = 0.1;   // cache read ≈ 0.1× input
const CACHE_WRITE_MULT = 1.25; // 5-minute cache write ≈ 1.25× input
const CACHE_WRITE_1H_MULT = 2.0; // 1-hour cache write ≈ 2× input
const TTL_MS = 5 * 60 * 1000;

// Map any model string to a rate family. Returns null for unpriceable models
// (e.g. "<synthetic>" sidechain/compaction turns) so they're skipped.
function rateFor(model) {
  if (typeof model !== 'string') return null;
  const s = model.toLowerCase();
  if (s.includes('haiku')) return MODEL_RATES.haiku;
  if (s.includes('sonnet')) return MODEL_RATES.sonnet;
  if (s.includes('opus')) return MODEL_RATES.opus;
  return null;
}

// ── Transcript discovery + parse ─────────────────────────────────────────────

function encodeProjectDir(dir) {
  return String(dir).replace(/[/.]/g, '-');
}

// Locate the session transcript. Prefer an explicit (hook-provided) path; else
// derive the project's transcript dir and take the most-recently-modified jsonl.
function locateTranscript({ transcriptPath, projectDir } = {}) {
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

// Parse a transcript jsonl into per-assistant-turn usage records. Skips lines
// that aren't priceable assistant turns.
function parseTranscriptUsage(jsonlPath) {
  let raw;
  try { raw = fs.readFileSync(jsonlPath, 'utf8'); } catch { return []; }
  const records = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try { o = JSON.parse(t); } catch { continue; }
    if (o.type !== 'assistant') continue;
    const msg = o.message;
    const u = msg && msg.usage;
    if (!u || !msg.model || !rateFor(msg.model)) continue;
    const cc = u.cache_creation || {};
    records.push({
      model: msg.model,
      input: u.input_tokens || 0,
      output: u.output_tokens || 0,
      cacheRead: u.cache_read_input_tokens || 0,
      cacheCreate: u.cache_creation_input_tokens || 0,
      cacheCreate5m: cc.ephemeral_5m_input_tokens || 0,
      cacheCreate1h: cc.ephemeral_1h_input_tokens || 0,
      ts: o.timestamp ? Date.parse(o.timestamp) : null,
    });
  }
  return records;
}

// ── Pure economics ───────────────────────────────────────────────────────────

function writeCostUsd(r, inRate) {
  const m5 = r.cacheCreate5m || 0, m1 = r.cacheCreate1h || 0;
  if (m5 + m1 > 0) return (m5 * CACHE_WRITE_MULT + m1 * CACHE_WRITE_1H_MULT) * inRate;
  return (r.cacheCreate || 0) * CACHE_WRITE_MULT * inRate; // breakdown absent
}

// Aggregate economics over parsed records.
function computeCacheEconomics(records) {
  let turns = 0, inTok = 0, outTok = 0, cacheRead = 0, cacheCreate = 0;
  let actualUsd = 0, uncachedUsd = 0, writePremiumUsd = 0;
  const perModel = {};

  for (const r of records) {
    const rate = rateFor(r.model);
    if (!rate) continue;
    turns++;
    const inRate = rate.in / 1e6, outRate = rate.out / 1e6;

    const readCost = r.cacheRead * inRate * CACHE_READ_MULT;
    const writeCost = writeCostUsd(r, inRate);
    const inCost = r.input * inRate;
    const outCost = r.output * outRate;
    const turnActual = readCost + writeCost + inCost + outCost;
    // What this turn would have cost with NO caching: every input-side token full price.
    const turnUncached = (r.cacheRead + r.cacheCreate + r.input) * inRate + outCost;

    actualUsd += turnActual;
    uncachedUsd += turnUncached;
    writePremiumUsd += writeCost - (r.cacheCreate * inRate); // the >1× premium paid to cache

    inTok += r.input; outTok += r.output; cacheRead += r.cacheRead; cacheCreate += r.cacheCreate;

    const key = rate.label;
    const pm = perModel[key] || (perModel[key] = { turns: 0, actualUsd: 0, cacheRead: 0, inputSide: 0 });
    pm.turns++; pm.actualUsd += turnActual; pm.cacheRead += r.cacheRead;
    pm.inputSide += r.cacheRead + r.cacheCreate + r.input;
  }

  const inputSide = cacheRead + cacheCreate + inTok;
  return {
    turns,
    tokens: { input: inTok, output: outTok, cacheRead, cacheCreate },
    actualUsd,
    uncachedUsd,
    savedUsd: uncachedUsd - actualUsd,         // net $ caching saved (can dip negative early)
    writePremiumUsd,                            // $ invested establishing caches
    cacheHitRatio: inputSide ? cacheRead / inputSide : 0,
    costPerTurnUsd: turns ? actualUsd / turns : 0,
    perModel,
  };
}

// Attribute cache drops: a turn that re-ingests a large prefix cold after a warm
// prior turn. Cause = model-switch | cache-expired | prefix-change.
function detectInvalidators(records) {
  const leaks = [];
  const MIN_WARM = 2000;
  for (let i = 1; i < records.length; i++) {
    const prev = records[i - 1], cur = records[i];
    const prevWarm = prev.cacheRead + prev.input + prev.cacheCreate;
    if (prevWarm < MIN_WARM) continue;
    const curFresh = cur.input + cur.cacheCreate;
    const coldish = cur.cacheRead < prevWarm * 0.25 && curFresh > prevWarm * 0.5;
    if (!coldish) continue;

    let cause;
    if (cur.model !== prev.model) cause = 'model-switch';
    else if (cur.ts && prev.ts && (cur.ts - prev.ts) > TTL_MS) cause = 'cache-expired';
    else cause = 'prefix-change';

    const rate = rateFor(cur.model);
    const inRate = rate ? rate.in / 1e6 : 0;
    // Extra paid vs. having kept the prefix as a cheap cache read.
    const wastedUsd = prevWarm * inRate * (1 - CACHE_READ_MULT);
    leaks.push({ turn: i, cause, wastedUsd, model: cur.model });
  }
  return leaks;
}

// Convenience: locate → parse → compute → detect. Returns { ok:false } when no
// transcript is available.
export function analyzeTranscript(opts = {}) {
  const transcript = locateTranscript(opts);
  if (!transcript) return { ok: false, reason: 'no-transcript' };
  const records = parseTranscriptUsage(transcript);
  if (!records.length) return { ok: false, reason: 'no-priceable-turns', transcript };
  return {
    ok: true,
    transcript,
    metrics: computeCacheEconomics(records),
    leaks: detectInvalidators(records),
  };
}

// ── Report formatting ────────────────────────────────────────────────────────

const CAUSE_LABEL = {
  'model-switch': 'model switch (cache is model-scoped)',
  'cache-expired': 'cache expired (gap > 5-min TTL)',
  'prefix-change': 'prefix changed (system prompt / tools / context edit)',
};

export function formatCacheReport(result) {
  if (!result.ok) {
    return result.reason === 'no-transcript'
      ? 'agentic-security: no Claude Code transcript found for this project yet.'
      : 'agentic-security: transcript has no priceable model turns yet.';
  }
  const m = result.metrics;
  const lines = [];
  lines.push('');
  lines.push('  Prompt-cache economics — this session');
  lines.push(`  ${result.turns ?? m.turns} model turns\n`);
  lines.push(`  cache hit ratio     ${(m.cacheHitRatio * 100).toFixed(1)}%  (input-side tokens served from cache)`);
  lines.push(`  spent               ${money(m.actualUsd)}   (~${money(m.costPerTurnUsd)}/turn)`);
  lines.push(`  ▶ saved by caching  ${money(m.savedUsd)}   vs. ${money(m.uncachedUsd)} with no cache`);
  lines.push(`  invested in caches  ${money(m.writePremiumUsd)}   (write premium over base input)`);
  lines.push('');
  lines.push('  tokens: '
    + `${m.tokens.cacheRead.toLocaleString()} cached-read · `
    + `${m.tokens.cacheCreate.toLocaleString()} cache-write · `
    + `${m.tokens.input.toLocaleString()} fresh-in · `
    + `${m.tokens.output.toLocaleString()} out`);

  const models = Object.keys(m.perModel);
  if (models.length > 1) {
    lines.push('\n  by model:');
    for (const k of models.sort()) {
      const pm = m.perModel[k];
      const hr = pm.inputSide ? (pm.cacheRead / pm.inputSide * 100).toFixed(0) : '0';
      lines.push(`    ${k.padEnd(12)} ${pm.turns} turns · ${money(pm.actualUsd)} · ${hr}% cached`);
    }
  }

  if (result.leaks && result.leaks.length) {
    const wasted = result.leaks.reduce((s, l) => s + l.wastedUsd, 0);
    lines.push(`\n  ⚠ cache leaks (${result.leaks.length}, ~${money(wasted)} wasted re-ingesting context):`);
    const byCause = {};
    for (const l of result.leaks) {
      (byCause[l.cause] || (byCause[l.cause] = { n: 0, usd: 0 })).n++;
      byCause[l.cause].usd += l.wastedUsd;
    }
    for (const c of Object.keys(byCause).sort()) {
      lines.push(`    · ${byCause[c].n}× ${CAUSE_LABEL[c] || c} — ~${money(byCause[c].usd)}`);
    }
    lines.push('    Keep one model + a stable system prompt within a working window to avoid these.');
  } else {
    lines.push('\n  ✓ no cache leaks detected — your context stayed warm.');
  }
  lines.push('');
  return lines.join('\n');
}

// Test surface (underscore export is exempt from the dead-module gate).
export const _internal = {
  MODEL_RATES, CACHE_READ_MULT, CACHE_WRITE_MULT, CACHE_WRITE_1H_MULT,
  rateFor, locateTranscript, parseTranscriptUsage, computeCacheEconomics, detectInvalidators,
};
