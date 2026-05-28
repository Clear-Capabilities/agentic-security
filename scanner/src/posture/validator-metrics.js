// Per-CWE precision/recall metrics persistence.
//
// PRD success metric §5: "Recall on top-25 CWE classes ≥ 0.92." Tracking
// this requires running a labelled benchmark and persisting the per-family
// scorecard so /security-trend, /report-card, and the dashboard can
// surface the trend over time.
//
// File location: .agentic-security/validator-metrics.json
//
// Shape:
//   {
//     "history": [
//       { "when": "2026-05-18T...", "benchmark": "owasp-benchmark-v1.2",
//         "mode": "blind+strict",
//         "aggregate": { "tp": ..., "fp": ..., "fn": ..., "precision": ..., "recall": ..., "f1": ... },
//         "perFamily": { "<family>": { "tp": ..., "fp": ..., "fn": ..., "precision": ..., "recall": ..., "f1": ... } }
//       }
//     ],
//     "floors": {
//       "perFamily": { "default": { "recall": 0.92 }, "<family>": { "recall": 0.92, "precision": 0.85 } },
//       "aggregate": { "f1": 0.90 }
//     }
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath, safeWriteState } from './state-dir.js';

const HISTORY_CAP = 100;

function _filePath(scanRoot) { return statePath(scanRoot, 'validator-metrics.json'); }

function _read(scanRoot) {
  const fp = _filePath(scanRoot);
  if (!fs.existsSync(fp)) return { history: [], floors: { perFamily: { default: { recall: 0.92 } }, aggregate: { f1: 0.90 } } };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return { history: [], floors: { perFamily: { default: { recall: 0.92 } }, aggregate: { f1: 0.90 } } }; }
}

function _write(scanRoot, data) {
  const fp = _filePath(scanRoot);
  safeWriteState(fp, JSON.stringify(data, null, 2));
}

function _round(n) { return Math.round(n * 10000) / 10000; }

function _computeStats(tp, fp, fn) {
  const precision = tp / Math.max(tp + fp, 1e-9);
  const recall    = tp / Math.max(tp + fn, 1e-9);
  const f1        = (2 * precision * recall) / Math.max(precision + recall, 1e-9);
  return { precision: _round(precision), recall: _round(recall), f1: _round(f1) };
}

// Record one benchmark run.
//   benchmark: 'owasp-benchmark-v1.2' | 'sard-juliet-java' | 'cve-replay' | ...
//   mode: 'blind+strict' | 'non-blind+strict' | 'non-blind+wildcard'
//   perFamily: { fam: { tp, fp, fn } }
export function recordRun(scanRoot, { benchmark, mode, tp, fp, fn, perFamily }) {
  const data = _read(scanRoot);
  const entry = {
    when: new Date().toISOString(),
    benchmark, mode,
    aggregate: { tp, fp, fn, ..._computeStats(tp, fp, fn) },
    perFamily: {},
  };
  for (const [fam, c] of Object.entries(perFamily || {})) {
    if (!c) continue;
    entry.perFamily[fam] = { tp: c.tp || 0, fp: c.fp || 0, fn: c.fn || 0, ..._computeStats(c.tp || 0, c.fp || 0, c.fn || 0) };
  }
  data.history = data.history || [];
  data.history.push(entry);
  if (data.history.length > HISTORY_CAP) data.history = data.history.slice(-HISTORY_CAP);
  _write(scanRoot, data);
  return entry;
}

// Record one PRODUCTION-TRIAGE outcome (operator marked a finding tp/fp).
// This is the per-CWE quality signal from real-world use, complementing the
// per-benchmark numbers above. Without this, the only feedback the engine
// gets is OWASP-Benchmark-tuned; with it, customer-real-world precision
// trends are visible in /security-trend.
//
//   benchmark: 'production-triage' (fixed string, used as the storage key)
//   verdict:   'tp' | 'fp' | 'wontfix'
//   family:    the finding's family name
//
// Aggregated per-CWE counts are stored under
// data.productionTriage[family] = { tp, fp, wontfix, lastAt }.
// summarize() and a future /security-trend command surface this.
export function recordTriage(scanRoot, { family, verdict, stableId }) {
  if (!family || !['tp', 'fp', 'wontfix'].includes(verdict)) return null;
  const data = _read(scanRoot);
  data.productionTriage = data.productionTriage || {};
  const row = data.productionTriage[family] = data.productionTriage[family] || { tp: 0, fp: 0, wontfix: 0, lastAt: null };
  row[verdict] = (row[verdict] || 0) + 1;
  row.lastAt = new Date().toISOString();
  // Cap per-family rows so a runaway triage script can't bloat the file.
  if ((row.tp || 0) + (row.fp || 0) + (row.wontfix || 0) > 10_000) {
    // Stop accumulating; the trend is well-established by now.
    row._capped = true;
    return row;
  }
  void stableId;
  _write(scanRoot, data);
  return row;
}

// Read the latest entry and compare against floors.
export function getLatest(scanRoot, benchmark) {
  const data = _read(scanRoot);
  const matches = (data.history || []).filter(e => !benchmark || e.benchmark === benchmark);
  return matches[matches.length - 1] || null;
}

// Identify families that violate their floors in the latest run.
//   { aggregateBelowFloor: bool, familiesBelowFloor: [{fam, metric, value, floor}] }
export function checkFloors(scanRoot, benchmark) {
  const data = _read(scanRoot);
  const latest = getLatest(scanRoot, benchmark);
  if (!latest) return { aggregateBelowFloor: false, familiesBelowFloor: [], latest: null };
  const floors = data.floors || {};
  const out = { aggregateBelowFloor: false, familiesBelowFloor: [], latest };
  const aggMin = (floors.aggregate || {}).f1;
  if (typeof aggMin === 'number' && latest.aggregate.f1 < aggMin) {
    out.aggregateBelowFloor = true;
    out.aggregateFloor = aggMin;
  }
  const perFamFloors = floors.perFamily || {};
  const defaultFamFloor = perFamFloors.default || {};
  for (const [fam, stats] of Object.entries(latest.perFamily || {})) {
    const famFloor = { ...defaultFamFloor, ...(perFamFloors[fam] || {}) };
    for (const metric of ['precision', 'recall', 'f1']) {
      if (typeof famFloor[metric] === 'number' && stats[metric] < famFloor[metric]) {
        out.familiesBelowFloor.push({ fam, metric, value: stats[metric], floor: famFloor[metric] });
      }
    }
  }
  return out;
}

// Convenience: render a short human summary including both benchmark
// numbers AND the production-triage trend (per-CWE TP/FP from real-world
// operator verdicts via /triage).
export function summarize(scanRoot, benchmark) {
  const latest = getLatest(scanRoot, benchmark);
  const data = _read(scanRoot);
  const lines = [];
  if (latest) {
    const r = latest.aggregate;
    const fams = Object.entries(latest.perFamily || {})
      .sort((a, b) => b[1].tp - a[1].tp);
    lines.push(`Benchmark: ${latest.benchmark} (${latest.mode}) @ ${latest.when.slice(0, 16)}`);
    lines.push(`  F1=${r.f1} P=${r.precision} R=${r.recall} (TP=${r.tp} FP=${r.fp} FN=${r.fn})`);
    for (const [fam, s] of fams.slice(0, 10)) {
      lines.push(`  · ${fam.padEnd(20)} P=${s.precision} R=${s.recall} (TP=${s.tp} FP=${s.fp} FN=${s.fn})`);
    }
  } else {
    lines.push('(no benchmark metrics yet)');
  }
  // Production-triage trend (R3.3 / P1-11 — this is the real-world signal,
  // not the benchmark proxy).
  const triage = data.productionTriage || {};
  const fams = Object.entries(triage)
    .filter(([, c]) => (c.tp || 0) + (c.fp || 0) > 0)
    .sort((a, b) => ((b[1].fp || 0) - (a[1].fp || 0)));
  if (fams.length) {
    lines.push('');
    lines.push('Production-triage trend (real-world precision proxy):');
    for (const [fam, c] of fams.slice(0, 10)) {
      const total = (c.tp || 0) + (c.fp || 0);
      const pHat = total ? (c.tp / total).toFixed(2) : '?';
      lines.push(`  · ${fam.padEnd(20)} P≈${pHat} (TP=${c.tp || 0} FP=${c.fp || 0} wontfix=${c.wontfix || 0})`);
    }
  }
  return lines.join('\n');
}
