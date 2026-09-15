#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 3 — Macro-F1 / per-CWE / report layer.
//
// WHY THIS FILE EXISTS RATHER THAN A NEW SCORER. This repo already has a
// working SARD/Juliet benchmark runner:
// `scanner/test/benchmark/realworld/bench-realworld.js` (`--app
// sard-juliet-java|sard-juliet-csharp|sard-juliet-java-strict|
// sard-juliet-csharp-strict --blind --json`). It clones the real NIST SARD
// Juliet mirrors, strips leakage-bearing comments/identifiers in `--blind`
// mode, and already computes per-CWE {tp,fp,fn}. What it does NOT compute is
// this PRD's primary metric (macro F1 — CWE-averaged, PRD §3) or a per-CWE
// report sorted by weakest-first (PRD §46). Duplicating ingestion/scoring
// here would violate this repo's reuse-over-duplication convention — this
// script is a pure post-processing layer over bench-realworld's own --json
// output. See bench/sard/IMPLEMENTATION_STATUS.md for the full architecture
// decision.
//
// Usage:
//   node bench-realworld.js --app sard-juliet-java-strict --blind --json \
//     | node ../../bench/sard/scripts/macro-score.mjs
//   node ../../bench/sard/scripts/macro-score.mjs --input <file.json>
//
// Writes bench/sard/reports/latest.json + latest.md (gitignored — this
// repo's bench/README.md policy is that no benchmark scores are committed).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SARD_ROOT = path.resolve(HERE, '..');
const REPORTS_DIR = path.join(SARD_ROOT, 'reports');
const MANIFEST_PATH = path.join(SARD_ROOT, '..', '..', 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');

function readInput() {
  const idx = process.argv.indexOf('--input');
  if (idx !== -1 && process.argv[idx + 1]) {
    return fs.readFileSync(process.argv[idx + 1], 'utf8');
  }
  // Read stdin synchronously.
  try { return fs.readFileSync(0, 'utf8'); }
  catch (e) { throw new Error(`no --input file and stdin unreadable: ${e.message}`); }
}

// PRD W0.1 — fail closed here too, not just in the upstream harness. This is
// the layer a milestone gate actually reads (`bench-realworld.js --json |
// macro-score.mjs`), and a shell pipeline's exit code is the LAST command's
// by default (no `pipefail`) — so an upstream truncated-and-exit-1 producer
// would otherwise still let this consumer report a clean pass. Checked
// against the raw per-app `r.truncated` from the input, not the copy on
// `report.apps`, so it can't be defeated by a shape change downstream.
const ALLOW_TRUNCATION = process.argv.includes('--allow-truncation');

export function f1(p, r) { return (p + r) === 0 ? 0 : (2 * p * r) / (p + r); }

// A "strict" app (empty wildcardFamilies + preciseMethodScoring) gives
// genuine per-vulnerability TP/FP/FN. A non-strict Juliet app's
// wildcardFamilies means: (a) tp counts every matching-family finding
// anywhere in the corpus rather than one per expected vulnerability, and
// (b) expected entries in a wildcard family are NEVER scored as FN at all
// (see bench-realworld.js `score()`). Per-CWE recall/F1 on such an app is
// not a meaningful vulnerability-level measurement — surfaced as a loud
// caveat rather than silently reporting a misleading number.
function isStrictApp(name) { return /-strict$/.test(name); }

export function perCweTable(perCwe) {
  const rows = [];
  for (const [cwe, c] of Object.entries(perCwe || {})) {
    const tp = c.tp || 0, fp = c.fp || 0, fn = c.fn || 0;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : (tp === 0 && fn === 0 ? 1 : 0);
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : (tp === 0 && fp === 0 ? 1 : 0);
    rows.push({ cwe, tp, fp, fn, precision, recall, f1: f1(precision, recall), support: tp + fn });
  }
  rows.sort((a, b) => a.f1 - b.f1 || b.support - a.support);
  return rows;
}

export function macroF1(rows) {
  if (!rows.length) return 0;
  return rows.reduce((s, r) => s + r.f1, 0) / rows.length;
}

// Adversarial-premortem remediation: macro-F1 is an unweighted mean over
// CWE rows by design (macro-averaging is meant to give a rare CWE equal
// weight to a common one) — that is not itself a bug. What it hides is
// VARIANCE: a CWE with 1 expected instance has a binary 0-or-1 F1 and
// carries the same 1/N weight as one with 1,000, so a handful of tiny-
// support CWEs can swing the headline number with no visibility into it.
// `compare-baseline.mjs` already refuses to trust a per-CWE REGRESSION
// below `MIN_SUPPORT=5` expected entries (the identical constant, kept in
// sync deliberately — this is the same noise-floor judgment call, applied
// to the headline number instead of a delta). This does not change what
// the primary macroF1() above reports (historical numbers stay comparable)
// — it adds a supplementary, explicitly-labeled second figure so a reader
// can see how much of the headline is resting on low-support rows.
const MIN_SUPPORT_FOR_MACRO = 5;

export function macroF1MinSupport(rows, minSupport = MIN_SUPPORT_FOR_MACRO) {
  const eligible = rows.filter(r => r.support >= minSupport);
  const excluded = rows.filter(r => r.support > 0 && r.support < minSupport);
  return {
    value: eligible.length ? eligible.reduce((s, r) => s + r.f1, 0) / eligible.length : null,
    cweCount: eligible.length,
    excludedCwes: excluded.map(r => ({ cwe: r.cwe, support: r.support, f1: r.f1 })),
  };
}

// Normalize "CWE-89" / "CWE89" / "89" to a bare digit string so the GT's
// cwe format and the raw finding's own `.cwe` format (which need not agree
// — CWE-89 vs CWE89 is a real, observed discrepancy between this schema's
// convention and bench-realworld.js's GT builders) don't produce spurious
// "mismatches" that are really just formatting differences.
function cweNum(s) {
  if (!s) return null;
  const m = String(s).match(/(\d+)/);
  return m ? m[1] : null;
}

// PRD §19 — CWE confusion matrix: expected CWE -> reported CWE. Built from
// `tps` (a family match doesn't require an exact CWE match, so a TP can
// still disagree on CWE) and `fps` (nothing was expected at that
// location/family at all). `fns` don't have a "reported" side by
// definition — they're a MISS, not a misclassification — so they're
// deliberately excluded here rather than padded with a fake "NONE" reported
// value that would dominate the matrix without saying anything about
// classification accuracy specifically.
function confusionMatrix(tps, fps) {
  const matrix = {}; // expectedCwe -> { reportedCwe -> count }
  let agreements = 0, disagreements = 0, noCweOnFinding = 0;
  for (const tp of tps || []) {
    const expected = cweNum(tp.cwe);
    if (!expected) continue; // non-Juliet apps' TPs carry no per-entry cwe
    const reported = cweNum(tp.reportedCwe) || '(finding has no cwe field)';
    matrix[expected] = matrix[expected] || {};
    matrix[expected][reported] = (matrix[expected][reported] || 0) + 1;
    if (reported === '(finding has no cwe field)') noCweOnFinding++;
    else if (reported === expected) agreements++;
    else disagreements++;
  }
  for (const fp of fps || []) {
    const reported = cweNum(fp.reportedCwe) || fp.family || '(unknown)';
    const key = '(no vulnerability expected here)';
    matrix[key] = matrix[key] || {};
    matrix[key][reported] = (matrix[key][reported] || 0) + 1;
  }
  return { matrix, agreements, disagreements, noCweOnFinding, cweClassificationAccuracy: (agreements + disagreements) > 0 ? agreements / (agreements + disagreements) : null };
}

// PRD §20 — localization accuracy proxy. `-strict` apps' TPs carry a
// `method` field only when they matched a PRECISE per-method span
// (findJavaMethodSpans/findCsharpMethodSpans); a TP with no `method` field
// matched the coarse file-level fallback entry instead (emitted when a file
// had no recognizable bad()/good*() method shape at all — see
// buildJulietExpected's `anyEmitted` fallback). The fraction with a real
// method span is a genuine (if partial) localization-accuracy signal: it
// answers "of the vulnerabilities this scanner found, how many were
// resolved to more than just 'somewhere in this file'?" Function/source/
// sink-level accuracy (the PRD's fuller ask) would need the finding's own
// source/sink line fields compared against the expected span's — not yet
// threaded through; this is the coarser, currently-available proxy.
function localizationAccuracy(tps) {
  const withSpan = (tps || []).filter(t => t.method).length;
  const total = (tps || []).length;
  return { withPreciseSpan: withSpan, total, rate: total > 0 ? withSpan / total : null };
}

function gitSha() {
  try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: path.join(SARD_ROOT, '..', '..'), encoding: 'utf8' }).trim(); }
  catch { return null; }
}

function manifestEntry(appName) {
  try {
    const m = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
    return m.apps?.[appName] || null;
  } catch { return null; }
}

function main() {
  const raw = readInput();
  const parsed = JSON.parse(raw);
  const results = parsed.results || (Array.isArray(parsed) ? parsed : [parsed]);

  const report = {
    generatedAt: new Date().toISOString(),
    gitSha: gitSha(),
    apps: [],
  };

  const mdLines = [];
  mdLines.push('# SARD benchmark — macro/per-CWE report');
  mdLines.push('');
  mdLines.push(`Generated: ${report.generatedAt}  ·  Git SHA: ${report.gitSha || 'unknown'}`);
  mdLines.push('');
  mdLines.push('Per this repo\'s `bench/README.md` policy, these numbers are local-only and must never be committed or quoted as external claims.');
  mdLines.push('');

  for (const r of results) {
    const strict = isStrictApp(r.name);
    const entry = manifestEntry(r.name);
    const rows = perCweTable(r.perCwe);
    const macro = macroF1(rows);
    const macroMinSupport = macroF1MinSupport(rows);
    const confusion = confusionMatrix(r.tps, r.fps);
    const localization = localizationAccuracy(r.tps);

    // PRD §9.4 — "Separate score-only delta from scanner delta". Computed
    // from bench-realworld.js's scoreLegacy() output: the SAME actual[]/
    // expected[] as the primary result above, scored with the strict,
    // pre-flow-aware-fallback matcher. Any delta between rawOldScorer and
    // rescoredSameFindings below is BY CONSTRUCTION a scoring-methodology
    // effect, not a scanner capability change — the two numbers come from
    // one scan, not two. Absent (both null) for any report produced before
    // this field existed, or for a non-strict/wildcard app where neither
    // scorer variant is a meaningful vulnerability-level measurement anyway.
    let scorerDelta = null;
    if (r.legacyScoring) {
      const legacyRows = perCweTable(r.legacyScoring.perCwe);
      scorerDelta = {
        rawOldScorer: macroF1(legacyRows),
        rescoredSameFindings: macro,
        scannerAfterChange: macro,
        note: 'rawOldScorer and rescoredSameFindings are computed from the IDENTICAL scan (same actual[]/expected[]) — the delta between them is purely a scoring-methodology effect. scannerAfterChange currently just repeats rescoredSameFindings: this script has no mechanism (yet) for comparing against a genuinely PRIOR scan run from before a scanner code change — see bench/sard/IMPLEMENTATION_STATUS.md for how to interpret this until that exists.',
      };
    }

    report.apps.push({
      name: r.name,
      language: r.language,
      strict,
      datasetRepo: entry?.repo || null,
      datasetSha: entry?.sha || null,
      scanned: r.scanned,
      elapsedSec: r.elapsedSec,
      peakRssMb: r.peakRssMb,
      aggregate: { tp: r.tp, fp: r.fp, fn: r.fn, precision: r.precision, recall: r.recall, microF1: r.f1 },
      macroF1: macro,
      macroF1MinSupport: macroMinSupport,
      scorerDelta,
      cweCount: rows.length,
      perCwe: rows,
      cweConfusion: confusion,
      localization,
      truncated: !!r.truncated,
      truncationDetail: r.truncationDetail || null,
    });

    mdLines.push(`## ${r.name} (${r.language})${strict ? '' : '  ⚠ non-strict (wildcardFamilies — see caveat below)'}`);
    mdLines.push('');
    if (!strict) {
      mdLines.push('> **Caveat**: this app uses `wildcardFamilies` permissive matching (bench-realworld.js `score()`).');
      mdLines.push('> TP counts every matching-family finding across the whole corpus rather than one per real');
      mdLines.push('> vulnerability, and expected entries in a wildcard family are never scored as FN. Macro F1 and');
      mdLines.push('> per-CWE recall below are therefore **not** a genuine vulnerability-level measurement. Use the');
      mdLines.push(`> \`${r.name}-strict\` variant (empty wildcardFamilies + preciseMethodScoring) for the PRD's real metric.`);
      mdLines.push('');
    }
    mdLines.push(`Dataset: \`${entry?.repo || 'unknown'}\` @ \`${entry?.sha || 'unknown'}\``);
    mdLines.push('');
    mdLines.push(`Scanned ${r.scanned} findings over ${r.elapsedSec}s, peak RSS ${r.peakRssMb}MB.`);
    mdLines.push('');
    mdLines.push(`**Macro F1 (CWE-averaged, primary metric): ${(macro * 100).toFixed(1)}%**  ·  Micro F1: ${(r.f1 * 100).toFixed(1)}%  ·  Precision: ${(r.precision * 100).toFixed(1)}%  ·  Recall: ${(r.recall * 100).toFixed(1)}%`);
    if (macroMinSupport.excludedCwes.length) {
      const minSupPct = macroMinSupport.value === null ? 'n/a' : `${(macroMinSupport.value * 100).toFixed(1)}%`;
      mdLines.push('');
      mdLines.push(`> **Support-floor diagnostic**: ${macroMinSupport.excludedCwes.length} of ${rows.length} CWE(s) have fewer than ${MIN_SUPPORT_FOR_MACRO} expected instances (binary 0/1 F1, full 1/N weight in the headline macro-F1 above). Macro F1 restricted to CWEs with ≥${MIN_SUPPORT_FOR_MACRO} expected instances: **${minSupPct}** (over ${macroMinSupport.cweCount} CWEs). Low-support CWEs excluded from that figure: ${macroMinSupport.excludedCwes.map(c => `${c.cwe} (n=${c.support}, F1=${(c.f1 * 100).toFixed(0)}%)`).join(', ')}.`);
    }
    if (scorerDelta) {
      mdLines.push('');
      mdLines.push(`> **PRD §9.4 scorer-delta diagnostic** (same scan, both scorers): rawOldScorer (strict, pre-flow-aware) **${(scorerDelta.rawOldScorer * 100).toFixed(1)}%** → rescoredSameFindings (current scorer, same findings) **${(scorerDelta.rescoredSameFindings * 100).toFixed(1)}%** (${scorerDelta.rescoredSameFindings >= scorerDelta.rawOldScorer ? '+' : ''}${((scorerDelta.rescoredSameFindings - scorerDelta.rawOldScorer) * 100).toFixed(1)}pp — a PURE scoring-methodology delta, not a scanner improvement). scannerAfterChange is not independently measured here (no prior-scan comparison mechanism yet) and currently repeats rescoredSameFindings — do not read it as proof of a NEW detection gain until this script gains that capability.`);
    }
    mdLines.push('');
    mdLines.push('| CWE | TP | FP | FN | Precision | Recall | F1 |');
    mdLines.push('|---|---|---|---|---|---|---|');
    for (const row of rows) {
      mdLines.push(`| ${row.cwe} | ${row.tp} | ${row.fp} | ${row.fn} | ${(row.precision * 100).toFixed(1)}% | ${(row.recall * 100).toFixed(1)}% | ${(row.f1 * 100).toFixed(1)}% |`);
    }
    mdLines.push('');

    mdLines.push('**Localization accuracy** (PRD §20 — of true positives, how many resolved to a precise');
    mdLines.push('method-level span rather than only "somewhere in this file"):');
    mdLines.push('');
    if (localization.rate === null) {
      mdLines.push('_No TPs to measure._');
    } else {
      mdLines.push(`${localization.withPreciseSpan}/${localization.total} (${(localization.rate * 100).toFixed(1)}%)`);
    }
    mdLines.push('');

    mdLines.push('**CWE classification accuracy** (PRD §19 — of TPs where the finding carries its own CWE,');
    mdLines.push('does it match the CWE actually expected at that location):');
    mdLines.push('');
    if (confusion.cweClassificationAccuracy === null) {
      mdLines.push(`_No TP carries a \`.cwe\` field to check (${confusion.noCweOnFinding} TP(s) had none) — this scanner`);
      mdLines.push('may not be attaching a CWE to every finding of this kind. Not a scoring failure, a coverage gap.');
    } else {
      mdLines.push(`${confusion.agreements}/${confusion.agreements + confusion.disagreements} (${(confusion.cweClassificationAccuracy * 100).toFixed(1)}%) — ${confusion.noCweOnFinding} additional TP(s) had no \`.cwe\` field at all.`);
    }
    mdLines.push('');
    const confusionRows = Object.entries(confusion.matrix)
      .flatMap(([expected, reportedCounts]) => Object.entries(reportedCounts).map(([reported, count]) => ({ expected, reported, count })))
      .filter(r => r.expected !== r.reported)
      .sort((a, b) => b.count - a.count)
      .slice(0, 25);
    if (confusionRows.length) {
      mdLines.push('Top disagreements (expected CWE → what the finding actually reported):');
      mdLines.push('');
      mdLines.push('| Expected | Reported | Count |');
      mdLines.push('|---|---|---|');
      for (const row of confusionRows) mdLines.push(`| ${row.expected} | ${row.reported} | ${row.count} |`);
      mdLines.push('');
    }
  }

  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, 'latest.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(REPORTS_DIR, 'latest.md'), mdLines.join('\n') + '\n');

  for (const app of report.apps) {
    const msup = app.macroF1MinSupport;
    const msupNote = msup && msup.excludedCwes.length
      ? `  macroF1(support>=${MIN_SUPPORT_FOR_MACRO})=${msup.value === null ? 'n/a' : (msup.value * 100).toFixed(1) + '%'} [${msup.excludedCwes.length} low-support CWE(s) excluded]`
      : '';
    const truncTag = app.truncated ? '  ⚠ TRUNCATED' : '';
    console.log(`${app.name}: macroF1=${(app.macroF1 * 100).toFixed(1)}%  microF1=${(app.aggregate.microF1 * 100).toFixed(1)}%  P=${(app.aggregate.precision * 100).toFixed(1)}%  R=${(app.aggregate.recall * 100).toFixed(1)}%  CWEs=${app.cweCount}${app.strict ? '' : '  [non-strict]'}${msupNote}${truncTag}`);
  }
  console.log(`\nWritten: ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'latest.json'))}, ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'latest.md'))}`);

  const truncatedApps = report.apps.filter(a => a.truncated);
  if (truncatedApps.length && !ALLOW_TRUNCATION) {
    console.error(`\n✗ ${truncatedApps.length} app(s) truncated (${truncatedApps.map(a => a.name).join(', ')}) — this report is NOT a valid milestone-gate measurement. Pass --allow-truncation to accept anyway (exploratory runs only).`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
