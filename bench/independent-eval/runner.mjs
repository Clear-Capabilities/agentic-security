#!/usr/bin/env node
// R16 — independent evaluation harness (PRD §5).
//
// Runs the scanner against a GROUND-TRUTH-labeled corpus and reports per-family
// precision / recall / F1 (+ Brier/ECE via posture/holdout-eval) — the metrics
// that substantiate a "best SAST" claim. This is intentionally separate from
// bench/cve-replay (a self-authored regression gate): R16 is meant to run
// against corpora we did NOT write (OWASP Benchmark, harvested CVE-fix pairs,
// SARD/Juliet). See README.md for wiring a real corpus.
//
// The shipped corpus/ here is a tiny SMOKE fixture that exercises the harness
// end-to-end. It is NOT an independent corpus and must not be cited as one.
//
// Usage:
//   node runner.mjs [--manifest <path>] [--root <dir>] [--json <out>]
//                   [--gate <thresholds.json>] [--quiet]
//   --gate may also be the literal "default" for a baseline threshold set.
//
// Exit codes: 0 = ran (and gate passed, if any); 1 = gate failed; 2 = usage/no data.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';
import { normalizeFindings } from '../../scanner/src/report/index.js';
import { evaluateHeldOut, summarize, summarizePerLanguage } from '../../scanner/src/posture/holdout-eval.js';
import { scoreCorpus, checkGate, normPath } from './score.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) {
      const k = t.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { a[k] = next; i++; }
      else a[k] = true;
    } else a._.push(t);
  }
  return a;
}

function loadManifest(fp) {
  if (!fs.existsSync(fp)) return [];
  const out = [];
  for (const line of fs.readFileSync(fp, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    try {
      const o = JSON.parse(t);
      if (!o || !o.path || !o.label) continue;
      out.push({
        id: o.id || o.path,
        path: o.path,
        language: o.language || null,
        cwe: o.cwe != null ? String(o.cwe) : null,
        family: o.family || 'unknown',
        label: o.label === 'vulnerable' ? 'vulnerable' : 'clean',
      });
    } catch { /* skip malformed lines */ }
  }
  return out;
}

const DEFAULT_THRESHOLDS = {
  // Deliberately conservative — this is a gate skeleton. Real per-family bars
  // get set once an independent corpus with enough samples is wired (see README).
  minSamples: 1,
  aggregateF1: null,
  perFamilyRecall: null,
};

function loadThresholds(val) {
  if (val === true || val === 'default') return DEFAULT_THRESHOLDS;
  try {
    if (fs.existsSync(val)) return { ...DEFAULT_THRESHOLDS, ...JSON.parse(fs.readFileSync(val, 'utf8')) };
    return { ...DEFAULT_THRESHOLDS, ...JSON.parse(val) };
  } catch {
    process.stderr.write(`[independent-eval] could not parse --gate value; using defaults\n`);
    return DEFAULT_THRESHOLDS;
  }
}

function fmt(n) { return n == null ? '  —  ' : n.toFixed(3); }

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = path.resolve(args.manifest || path.join(__dirname, 'corpus', 'manifest.jsonl'));
  const root = path.resolve(args.root || path.dirname(manifestPath));
  const entries = loadManifest(manifestPath);
  if (!entries.length) {
    process.stderr.write(`[independent-eval] no usable manifest entries at ${manifestPath}\n`);
    process.exit(2);
  }

  // Scan a comment-excluded temp COPY so we never write scan state into the
  // repo (premortem: .agentic-security dirs in a scanned tree mask results).
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'indep-eval-'));
  fs.cpSync(root, tmp, { recursive: true, filter: (s) => !s.includes('.agentic-security') && !s.includes('node_modules') });
  process.env.AGENTIC_SECURITY_OFFLINE = '1';

  let findings = [];
  try {
    const { scan } = await runScan(tmp);
    findings = normalizeFindings(scan) || [];
  } catch (e) {
    process.stderr.write(`[independent-eval] scan failed: ${e && e.message}\n`);
    fs.rmSync(tmp, { recursive: true, force: true });
    process.exit(2);
  }

  // Attribute findings to files (relative to the scan root).
  const byFile = {};
  for (const f of findings) {
    if (!f.file) continue;
    let rel = f.file;
    if (path.isAbsolute(rel)) rel = path.relative(tmp, rel);
    rel = normPath(rel);
    const conf = typeof f.confidence === 'number' ? f.confidence
      : typeof f.calibratedConfidence === 'number' ? f.calibratedConfidence : 0.5;
    (byFile[rel] ||= []).push({ family: f.family, cwe: f.cwe, confidence: conf });
  }

  // Remap onto exact manifest keys (tolerate path-prefix differences).
  const aligned = {};
  const keys = Object.keys(byFile);
  for (const e of entries) {
    const want = normPath(e.path);
    if (byFile[want]) { aligned[want] = byFile[want]; continue; }
    const hit = keys.find((k) => k.endsWith('/' + want) || want.endsWith('/' + k) || path.basename(k) === path.basename(want));
    aligned[want] = hit ? byFile[hit] : [];
  }

  const result = scoreCorpus(entries, aligned);
  const cal = evaluateHeldOut(result.calibration);
  fs.rmSync(tmp, { recursive: true, force: true });

  // ---- Report ----
  const quiet = !!args.quiet;
  if (!quiet) {
    process.stdout.write('\nIndependent evaluation — per-family precision / recall / F1\n');
    process.stdout.write(`corpus: ${manifestPath}  (${result.n} samples)\n\n`);
    const rows = Object.entries(result.perFamily).sort((a, b) => a[0].localeCompare(b[0]));
    process.stdout.write('  family                         TP  FP  FN  TN   prec   recall    F1\n');
    process.stdout.write('  ' + '-'.repeat(72) + '\n');
    for (const [fam, m] of rows) {
      process.stdout.write(
        '  ' + fam.padEnd(28) + ' ' +
        String(m.tp).padStart(3) + ' ' + String(m.fp).padStart(3) + ' ' +
        String(m.fn).padStart(3) + ' ' + String(m.tn).padStart(3) + '  ' +
        fmt(m.precision) + '  ' + fmt(m.recall) + '  ' + fmt(m.f1) + '\n');
    }
    const a = result.aggregate;
    process.stdout.write('  ' + '-'.repeat(72) + '\n');
    process.stdout.write(
      '  ' + 'AGGREGATE'.padEnd(28) + ' ' +
      String(a.tp).padStart(3) + ' ' + String(a.fp).padStart(3) + ' ' +
      String(a.fn).padStart(3) + ' ' + String(a.tn).padStart(3) + '  ' +
      fmt(a.precision) + '  ' + fmt(a.recall) + '  ' + fmt(a.f1) + '\n\n');
    process.stdout.write('calibration: ' + summarize(cal) + '\n');
    if (cal && cal.ok) process.stdout.write(summarizePerLanguage(cal) + '\n');
    if (cal && cal.notes && cal.notes.length) {
      for (const note of cal.notes) process.stdout.write('  note: ' + note + '\n');
    }
    if (result.n < 100) {
      process.stdout.write('\n  ⚠  This is a SMOKE fixture, not an independent corpus. Wire a real\n');
      process.stdout.write('     corpus (see README.md) before citing these numbers.\n');
    }
  }

  const out = { generatedAt: new Date().toISOString().slice(0, 10), manifest: manifestPath, ...result, calibration: cal };
  if (args.json) {
    fs.writeFileSync(path.resolve(args.json), JSON.stringify(out, null, 2));
    if (!quiet) process.stdout.write(`\nwrote ${path.resolve(args.json)}\n`);
  }

  // ---- Gate ----
  if (args.gate) {
    const thresholds = loadThresholds(args.gate);
    const g = checkGate(result, thresholds);
    process.stdout.write('\nGate (' + JSON.stringify(thresholds) + '):\n');
    if (g.pass) process.stdout.write('  ✓ passed\n');
    else {
      process.stdout.write('  ✗ FAILED:\n');
      for (const vio of g.violations) process.stdout.write('    - ' + vio + '\n');
      process.exit(1);
    }
  }
  process.exit(0);
}

main().catch((e) => { process.stderr.write(String((e && e.stack) || e) + '\n'); process.exit(2); });
