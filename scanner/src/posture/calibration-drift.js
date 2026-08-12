// FR-LEARN-9 — Calibration-drift alarm.
//
// Compare self-reported `f.calibrated_confidence` against realized triage
// accuracy from `.agentic-security/triage-feedback.json`. When the absolute
// divergence (Brier-score-style) exceeds a configurable threshold over a
// rolling window, surface a drift alarm.
//
// The alarm fires when the engine has been telling the customer "this is
// 85% likely TP" for some family, but the actual triage TP rate is 50%.
// The remedy is either: (a) re-run calibration, (b) downgrade the affected
// rule pack, or (c) widen the calibration corpus.
//
// State files:
//   .agentic-security/triage-feedback.json   — written by /triage
//   .agentic-security/validator-metrics.json — written by validator-metrics.js
//
// Alarm record shape:
//   {
//     alarm: true,
//     since: "2026-04-23T...",
//     family: "sql-injection",
//     reportedAccuracy: 0.85,
//     realizedAccuracy: 0.51,
//     divergence: 0.34,
//     sampleSize: 42,
//     recommendation: "..."
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from './state-dir.js';

const DEFAULT_THRESHOLD = 0.15;
const MIN_SAMPLE_SIZE = 10;
const WINDOW_DAYS = 30;

function loadTriageFeedback(scanRoot) {
  const fp = statePath(scanRoot, 'triage-feedback.json');
  try {
    if (!fs.existsSync(fp)) return [];
    const data = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(data) ? data : (data.entries || []);
  } catch { return []; }
}

function inWindow(ts, days) {
  if (!ts) return false;
  const cutoff = Date.now() - days * 86_400_000;
  const t = Date.parse(ts);
  return Number.isFinite(t) && t >= cutoff;
}

export function computeDrift(scanRoot, opts = {}) {
  const threshold = opts.threshold ?? DEFAULT_THRESHOLD;
  const minN = opts.minSampleSize ?? MIN_SAMPLE_SIZE;
  const window = opts.windowDays ?? WINDOW_DAYS;
  const fb = loadTriageFeedback(scanRoot);
  if (!fb.length) return { alarms: [], note: 'no-feedback-data' };

  // Group by family. Each entry should carry: family, verdict ('tp'|'fp'|'wontfix'),
  // reportedConfidence (0..1), at.
  // Field names/verdict values here previously didn't match the real
  // producer (commands/triage.md's Step 2): it writes `at`, not `ts`, and
  // never wrote `reportedConfidence` at all (fixed there alongside this —
  // Stage 2 measurement-completeness audit) or a `'wai'` verdict (it only
  // ever writes 'tp'|'fp'|'wontfix'), so this alarm could never fire against
  // real triage data regardless of how badly calibration had drifted.
  const byFamily = new Map();
  for (const e of fb) {
    if (!e || !e.family || !inWindow(e.at, window)) continue;
    if (!['tp', 'fp', 'wontfix'].includes(e.verdict)) continue;
    if (typeof e.reportedConfidence !== 'number') continue;
    if (!byFamily.has(e.family)) byFamily.set(e.family, []);
    byFamily.get(e.family).push(e);
  }

  const alarms = [];
  for (const [family, entries] of byFamily) {
    if (entries.length < minN) continue;
    const realizedAcc = entries.filter(e => e.verdict === 'tp').length / entries.length;
    const reportedAcc = entries.reduce((acc, e) => acc + e.reportedConfidence, 0) / entries.length;
    const divergence = Math.abs(reportedAcc - realizedAcc);
    if (divergence < threshold) continue;
    const firstTs = entries.map(e => e.at).filter(Boolean).sort()[0];
    alarms.push({
      alarm: true,
      since: firstTs,
      family,
      reportedAccuracy: Number(reportedAcc.toFixed(3)),
      realizedAccuracy: Number(realizedAcc.toFixed(3)),
      divergence: Number(divergence.toFixed(3)),
      sampleSize: entries.length,
      recommendation:
        reportedAcc > realizedAcc
          ? `Scanner is overconfident on ${family}: reported ${(reportedAcc * 100).toFixed(0)}%, realized ${(realizedAcc * 100).toFixed(0)}%. Recommend running calibration refresh or downgrading the ${family} rule pack.`
          : `Scanner is underconfident on ${family}: reported ${(reportedAcc * 100).toFixed(0)}%, realized ${(realizedAcc * 100).toFixed(0)}%. The rule is stronger than the calibration table reflects — re-fit the family.`,
    });
  }
  return { alarms, threshold, windowDays: window, minSampleSize: minN };
}
