// Brier-calibrated confidence (P1.3 / FR-UX-1, FR-UX-2).
//
// Today's `confidence` field is an ordinal score: combinations of severity,
// parser type, route-rooting, and a few heuristic adjustments. It correlates
// with true-positive rate but isn't calibrated — a "0.8" today doesn't mean
// "80% likely TP," it means "above-the-fold finding."
//
// This module turns the ordinal score into a calibrated probability via a
// per-family bucket map of historical TP rates from `validator-metrics.json`.
// It also computes:
//
//   - 95% Wilson-score confidence intervals (small-sample-safe; never reports
//     a CI of [0.95, 1.00] from a single observation).
//   - The running Brier score on the labeled history, so the operator can
//     see how well the calibration tracks reality.
//
// HONESTY: when a family has fewer than `MIN_SAMPLES_FOR_CALIBRATION` labels
// (default 30), we refuse to ship a calibrated number and instead emit
// `null` with a reason. Pillar-6 of the parent PRD calls this out: "When the
// verifier cannot rule a finding in or out, surface 'cannot verify' rather
// than pick a confidence number out of a hat."
//
// Seed corpus: the v1 calibration table is seeded from per-family TP/FP
// counts collected by the bench-realworld runner against OWASP Benchmark
// v1.2 and the curated Juliet subsets. Customers' own `validator-metrics.json`
// extends and overrides per-family.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from './state-dir.js';

const MIN_SAMPLES_FOR_CALIBRATION = 30;

// ─── Wilson-score interval ──────────────────────────────────────────────────
//
// Returns [lower, upper] for proportion p with n observations at 95% conf.
// Source: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval

const Z_95 = 1.959963984540054;

export function wilsonInterval(tp, n) {
  if (n <= 0) return [0, 1];
  const p = tp / n;
  const z = Z_95;
  const denom = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  const lower = Math.max(0, (centre - margin) / denom);
  const upper = Math.min(1, (centre + margin) / denom);
  return [lower, upper];
}

// ─── Brier score ─────────────────────────────────────────────────────────────
//
// brier = mean( (prediction - actual)^2 )
// 0 = perfect; 0.25 = worse than coin flip; 1 = always wrong.
// PRD success criterion: ≤ 0.10.

export function brierScore(samples) {
  if (!Array.isArray(samples) || samples.length === 0) return null;
  let sum = 0, n = 0;
  for (const s of samples) {
    if (!s || typeof s.prediction !== 'number' || typeof s.actual !== 'number') continue;
    const p = Math.max(0, Math.min(1, s.prediction));
    const a = Math.max(0, Math.min(1, s.actual));
    sum += (p - a) * (p - a);
    n++;
  }
  return n > 0 ? sum / n : null;
}

// ─── Per-family calibration table ────────────────────────────────────────────
//
// Map<family, { tp, fp, n, calibrated, ci95 }>
//   tp           — labeled true positives in this family
//   fp           — labeled false positives in this family
//   n            — tp + fp
//   calibrated   — tp / n  (only set when n >= MIN_SAMPLES_FOR_CALIBRATION)
//   ci95         — [lower, upper]

export function buildCalibrationTable(history) {
  if (!history || typeof history !== 'object') return {};
  const out = {};
  const families = history.families || history.perFamily || {};
  for (const [fam, raw] of Object.entries(families)) {
    if (!raw || typeof raw !== 'object') continue;
    const tp = Number(raw.tp) || 0;
    const fp = Number(raw.fp) || 0;
    const n = tp + fp;
    if (n === 0) continue;
    const calibrated = n >= MIN_SAMPLES_FOR_CALIBRATION ? tp / n : null;
    const ci95 = wilsonInterval(tp, n);
    out[fam] = { tp, fp, n, calibrated, ci95 };
  }
  return out;
}

function _readJsonMaybe(fp) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

// Load history from .agentic-security/validator-metrics.json + the bundled
// seed file. The bundled seed ships with this release; the customer file
// overrides per-family when N is higher there.
export function loadCalibrationHistory(scanRoot) {
  const customer = _readJsonMaybe(statePath(scanRoot, 'validator-metrics.json')) || {};
  const seedPath = new URL('./calibration-seed.json', import.meta.url);
  let seed = null;
  try { seed = JSON.parse(fs.readFileSync(seedPath, 'utf8')); } catch { seed = null; }
  // Merge: customer takes precedence when its sample count is higher.
  const families = {};
  const merge = (src) => {
    const fams = src?.families || src?.perFamily || {};
    for (const [k, v] of Object.entries(fams)) {
      if (!v || typeof v !== 'object') continue;
      const tp = Number(v.tp) || 0, fp = Number(v.fp) || 0;
      const n = tp + fp;
      const cur = families[k];
      if (!cur || n > cur.tp + cur.fp) families[k] = { tp, fp };
    }
  };
  if (seed) merge(seed);
  if (customer) merge(customer);
  // Merge triage-derived TP/FP counts (auto-feedback loop)
  try {
    const triage = _readJsonMaybe(statePath(scanRoot, 'triage.json'));
    if (triage && triage.findings) {
      const triageFams = {};
      for (const f of Object.values(triage.findings)) {
        const fam = f.family || 'unknown';
        if (!triageFams[fam]) triageFams[fam] = { tp: 0, fp: 0 };
        if (f.state === 'fixed' || f.state === 'open' || f.state === 'in-progress') triageFams[fam].tp++;
        else if (f.state === 'false-positive') triageFams[fam].fp++;
      }
      merge({ families: triageFams });
    }
  } catch { /* triage file optional */ }
  return { families };
}

// ─── Annotation ──────────────────────────────────────────────────────────────
//
// For each finding, set:
//   f.calibrated_confidence       — number in [0,1] or null
//   f.calibrated_confidence_ci    — [lower, upper] or null
//   f.calibrated_n                — sample size used
//   f.calibration_reason          — when null, why ("insufficient-samples" | "no-family")

export function annotateCalibratedConfidence(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  const table = opts.table || buildCalibrationTable(opts.history || loadCalibrationHistory(opts.scanRoot));
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fam = f.family || null;
    if (!fam) {
      f.calibrated_confidence = null;
      f.calibrated_confidence_ci = null;
      f.calibrated_n = 0;
      f.calibration_reason = 'no-family';
      continue;
    }
    const row = table[fam];
    if (!row || typeof row.calibrated !== 'number') {
      f.calibrated_confidence = null;
      f.calibrated_confidence_ci = null;
      f.calibrated_n = row ? row.n : 0;
      f.calibration_reason = row ? 'insufficient-samples' : 'no-history';
      continue;
    }
    f.calibrated_confidence = round3(row.calibrated);
    f.calibrated_confidence_ci = [round3(row.ci95[0]), round3(row.ci95[1])];
    f.calibrated_n = row.n;
    f.calibration_reason = null;
  }
}

function round3(x) { return Math.round(x * 1000) / 1000; }

// ─── Brier on held-out labels ───────────────────────────────────────────────
//
// Premortem #9: the previous `computeBrierFromHistory` was tautological — it
// fed (prediction = row.calibrated, actual = row.calibrated) into brierScore
// and always returned 0. That number is unsafe to surface anywhere because
// readers will interpret it as "calibration is perfect," when it actually
// measures nothing.
//
// The honest computation needs *held-out labels* — verdicts the engine did
// NOT use to fit the calibration table. We accept those as an array of
// { family, predicted, actual } where `predicted` is the calibrated rate
// the model gave (e.g. f.calibrated_confidence) and `actual ∈ {0,1}` is
// the human/system-confirmed truth.
//
// Callers must supply held-out data. There is no fallback that produces
// a number from the seed corpus alone — that path is what produced the
// tautology, and it should fail loudly instead.
export function computeBrierOnHeldOut(samples) {
  if (!Array.isArray(samples) || samples.length === 0) {
    return { brier: null, reason: 'no-held-out-samples' };
  }
  const cleaned = [];
  for (const s of samples) {
    if (!s || typeof s !== 'object') continue;
    const p = typeof s.predicted === 'number' ? Math.max(0, Math.min(1, s.predicted)) : null;
    const a = typeof s.actual === 'number'
      ? (s.actual >= 0.5 ? 1 : 0)
      : (s.actual === true ? 1 : s.actual === false ? 0 : null);
    if (p === null || a === null) continue;
    cleaned.push({ prediction: p, actual: a });
  }
  if (!cleaned.length) return { brier: null, reason: 'no-valid-samples' };
  const brier = brierScore(cleaned);
  return { brier, n: cleaned.length };
}

// Removed: computeBrierFromHistory. Anyone relying on it for a dashboard
// number should switch to computeBrierOnHeldOut(samples) with real labels.

// For tests / introspection.
export const _internals = { MIN_SAMPLES_FOR_CALIBRATION, Z_95, round3 };
