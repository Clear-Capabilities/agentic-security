#!/usr/bin/env node
// Score the engine against the independent population.
//
// This is an ACCURACY MEASUREMENT, not a gate. It does not fail a build, it does
// not have a baseline, and it must never grow one: a number you are not allowed
// to move is a number you will start tuning towards.
//
// Per entry, over the CWE the advisory assigned:
//   TP  a matching finding in pre/   (vulnerable version)
//   FN  no matching finding in pre/
//   FP  a matching finding in post/  (fixed version)
//   TN  no matching finding in post/
//
// MATCHING IS CWE-ONLY. Scoring on this engine's own vuln titles or families
// would grade it against vocabulary it chose itself. CWE is the one identifier
// the advisory and the engine both speak, and it is the same choice
// posture/comparison.js makes for the same reason.
//
// AN UNFETCHABLE OR UNSCANNABLE ENTRY IS UNSCORED. It is excluded from every
// denominator and reported by name — never counted as a miss. Counting an
// infrastructure failure as a detection failure silently blames the engine for
// the network, which is exactly the reasoning error the corpus gate's
// "unrunnable is not a pass" rule exists to prevent, pointed the other way.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { entryDir, entryComplete } from './fetch.mjs';

import { snapshotTree, assertTreeUnchanged, disableStateWrites } from '../_lib/tree-integrity.mjs';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MANIFEST = path.join(HERE, 'manifest.json');

/** Below this, a rate is noise. Reported, but labelled unreliable. */
export const MIN_RELIABLE_N = 10;

/** Does any finding carry the labelled CWE? Normalised, exact on the number. */
export function matchesCwe(findings, cwe, files = null) {
  const want = String(cwe || '').toUpperCase().trim();
  if (!/^CWE-\d+$/.test(want)) return false;
  const scoped = localiseToAdvisory(findings, files);
  return scoped.some(f => String(f.cwe || '').toUpperCase().trim() === want);
}

/**
 * Restrict findings to the files the advisory's fix commit touched.
 *
 * WHY, WITH THE NUMBER THAT FORCED IT. Package-scope materialisation (N1) gave
 * the taint engine the callers it needs, and recall rose 12.5% -> 32.5%. It also
 * widened what counts as a false positive to the whole package: an entry could
 * score FP because the same CWE appeared ANYWHERE in the scanned tree. Measured
 * on the 110-entry run, several `post/` scopes contained over 1700 findings, so
 * "a CWE-862 exists somewhere in 1735 findings" was being recorded as a false
 * positive against one advisory about one file.
 *
 * That is not a precision defect, it is a scoping error in the benchmark, and
 * leaving it in place would have invited exactly the wrong response — tuning
 * detectors to suppress real findings in unrelated code in order to move a
 * number.
 *
 * SYMMETRIC ON PURPOSE. The restriction applies to `pre` and `post` alike.
 * Scoring the vulnerable side generously and the fixed side strictly would
 * inflate both recall and precision, which is the shape of a benchmark built to
 * flatter. Context still does its job — the engine reads the whole package to
 * resolve the flow — but the CLAIM is anchored to the files the advisory is
 * actually about.
 *
 * `files = null` disables the restriction, which is what the unit tests use.
 */
export function localiseToAdvisory(findings, files) {
  if (!Array.isArray(files) || files.length === 0) return findings || [];
  const wanted = new Set(files.map(f => String(f)));
  return (findings || []).filter(f => {
    const file = String(f.file || '');
    // Findings carry paths relative to the scanned root, which is the scope
    // directory — so compare by suffix rather than demanding an exact match.
    for (const w of wanted) {
      if (file === w || file.endsWith('/' + w) || w.endsWith('/' + file) || w.endsWith(file)) return true;
    }
    return false;
  });
}

/** Precision/recall/F1 from raw counts, each carrying its {n, d}. */
export function scoreCounts({ tp, fp, fn, tn }) {
  const rate = (n, d) => ({ n, d, value: d > 0 ? n / d : null });
  const precision = rate(tp, tp + fp);
  const recall = rate(tp, tp + fn);
  const f1 = (precision.value !== null && recall.value !== null && (precision.value + recall.value) > 0)
    ? (2 * precision.value * recall.value) / (precision.value + recall.value)
    : null;
  return { tp, fp, fn, tn, precision, recall, f1, scored: tp + fn };
}

function pct(r) {
  if (!r || r.value === null) return 'n/a';
  return `${(r.value * 100).toFixed(1)}% (${r.n}/${r.d})`;
}

/**
 * Remove any scan state the engine wrote INTO a tree it scanned.
 *
 * THIS IS AN INTEGRITY CONTROL, NOT TIDINESS. A scan writes
 * `.agentic-security/` into its own root — threat-model.json,
 * exploit-bundles.json, scan-history.json — and those files CONTAIN CWE
 * IDENTIFIERS from the previous run. Audited on this population: 220 polluted
 * trees, 544 state files carrying `CWE-` strings.
 *
 * Left in place, the second scan of a tree reads the first scan's conclusions as
 * if they were source code. That is the benchmark grading the engine on its own
 * previous output — the precise definition of cheating, arrived at by accident
 * rather than intent, which is the only way it ever shows up in practice.
 *
 * Purged BEFORE every scan, so each measurement sees exactly the upstream files
 * and nothing this project produced. Purging only afterwards would still leave a
 * window where an interrupted run poisons the next one.
 */
export function purgeScanState(dir) {
  let removed = 0;
  const walk = (d, depth = 0) => {
    if (depth > 12) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const p = path.join(d, e.name);
      if (e.name === '.agentic-security') { fs.rmSync(p, { recursive: true, force: true }); removed++; continue; }
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(p, depth + 1);
    }
  };
  walk(dir);
  return removed;
}

export async function scanDirRaw(dir) {
  // Pristine input, every time. See purgeScanState.
  purgeScanState(dir);
  // Snapshot AFTER the purge: the purge is a deliberate removal, so including
  // it would guarantee a spurious "corpus changed" on every entry. What is
  // being asserted is that the SCAN adds nothing, which is the claim that
  // matters. (STATE_SEAM_COMPLETION_PRD M3)
  const before = snapshotTree(dir);
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  const findings = normalizeFindings(scan) || [];
  assertTreeUnchanged(before, snapshotTree(dir), `independent entry ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  // Defence in depth: even with a pristine input, refuse to score a finding
  // whose path is inside our own state directory. A single guard that can be
  // bypassed by a mid-run write is not a guard.
  return {
    findings: findings.filter(f => !String(f.file || '').includes('.agentic-security')),
    suppressions: scan.suppressions || [],
  };
}

async function scanDir(dir) {
  return (await scanDirRaw(dir)).findings;
}

async function main() {
  // STATE_SEAM_COMPLETION_PRD M3 — see scanDir for the per-entry assertion.
  await disableStateWrites();
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const asJson = process.argv.includes('--json');

  const perEntry = [];
  const unscored = [];

  for (const e of manifest.entries) {
    if (!entryComplete(e)) {
      unscored.push({ id: e.id, reason: 'not fetched — run `npm run bench:independent:fetch`' });
      continue;
    }
    const dir = entryDir(e.id);
    let preFindings, postFindings;
    try {
      preFindings = await scanDir(path.join(dir, 'pre'));
      postFindings = await scanDir(path.join(dir, 'post'));
    } catch (err) {
      unscored.push({ id: e.id, reason: `scan failed: ${err.message}` });
      continue;
    }
    const hitPre = matchesCwe(preFindings, e.cwe, e.files);
    const hitPost = matchesCwe(postFindings, e.cwe, e.files);
    // Same verdict with the advisory-file restriction OFF. See `wide` below.
    const hitPreWide = matchesCwe(preFindings, e.cwe, null);
    const hitPostWide = matchesCwe(postFindings, e.cwe, null);
    perEntry.push({
      id: e.id, cwe: e.cwe, language: e.language, repo: e.repo,
      tp: hitPre ? 1 : 0, fn: hitPre ? 0 : 1,
      fp: hitPost ? 1 : 0, tn: hitPost ? 0 : 1,
      tpWide: hitPreWide ? 1 : 0, fnWide: hitPreWide ? 0 : 1,
      fpWide: hitPostWide ? 1 : 0, tnWide: hitPostWide ? 0 : 1,
      preFindings: preFindings.length, postFindings: postFindings.length,
    });
  }

  const sum = (rows) => rows.reduce((a, r) => ({
    tp: a.tp + r.tp, fp: a.fp + r.fp, fn: a.fn + r.fn, tn: a.tn + r.tn,
  }), { tp: 0, fp: 0, fn: 0, tn: 0 });

  const overall = scoreCounts(sum(perEntry));
  // The SAME scans scored without the advisory-file restriction.
  //
  // WHY THIS IS REPORTED RATHER THAN CHOSEN BETWEEN. Two corrections landed
  // together — purging scan state (an accuracy correction: the engine had been
  // partly grading its own prior output) and localiseToAdvisory (a strictness
  // correction in the HARNESS). Recall fell sharply across the pair. Attributing
  // that fall to the engine when it belongs to the benchmark's scope would be the
  // same reasoning error as the contamination, pointed the other way.
  //
  // `overall` is the number this project quotes: it is the defensible claim,
  // because it asks whether the engine flagged the file the advisory is about.
  // `wide` asks only whether the CWE appeared ANYWHERE in the package, which over
  // scopes holding hundreds of findings is close to a lookup of "does this
  // codebase contain this bug class at all" — a question with a much easier yes.
  // The GAP between them is the diagnostic: it is how much of the engine's
  // apparent recall comes from finding the right thing versus from finding
  // something of the right kind somewhere.
  const wide = scoreCounts(sum(perEntry.map(r => ({
    tp: r.tpWide, fp: r.fpWide, fn: r.fnWide, tn: r.tnWide,
  }))));
  const group = (key) => {
    const out = {};
    for (const r of perEntry) {
      const k = r[key] || '(unknown)';
      (out[k] ||= []).push(r);
    }
    return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([k, rows]) => [k, { entries: rows.length, ...scoreCounts(sum(rows)) }]));
  };

  const report = {
    schema: 'agentic-security/independent-population-result@1',
    population: {
      totalEntries: manifest.entries.length,
      scoredEntries: perEntry.length,
      unscored,
      labelSources: [...new Set(manifest.entries.map(e => e.labelSource))],
    },
    reliable: perEntry.length >= MIN_RELIABLE_N,
    // Per-entry rows, so a false positive can be OPENED rather than counted.
    // Aggregates say precision is 50%; only these say which advisory produced
    // the finding in `post/`, which is the difference between "18 defects" and
    // "18 rows that need classifying". Plan R-4 depends on this existing.
    perEntry,
    overall,
    // Diagnostic only — NOT this project's headline. See the comment on `wide`.
    wide: { ...wide, meaning: 'same scans, advisory-file restriction OFF' },
    byLanguage: group('language'),
    byCwe: group('cwe'),
  };

  if (asJson) { process.stdout.write(JSON.stringify(report, null, 2) + '\n'); return 0; }

  const out = process.stdout;
  out.write('\nIndependent evaluation population\n');
  out.write(`  labels from: ${report.population.labelSources.join(', ')}\n`);
  out.write(`  scored ${perEntry.length} of ${manifest.entries.length} entries\n`);
  if (!report.reliable) {
    out.write(`\n  ⚠ n=${perEntry.length} is below ${MIN_RELIABLE_N}. These rates are NOT reliable.\n` +
      '    They are printed so the instrument can be seen working, not so the\n' +
      '    numbers can be quoted. Grow the population before drawing a conclusion.\n');
  }
  out.write('\n  precision  ' + pct(overall.precision) + '\n');
  out.write('  recall     ' + pct(overall.recall) + '\n');
  out.write('  F1         ' + (overall.f1 === null ? 'n/a' : overall.f1.toFixed(3)) + '\n');
  out.write(`  raw        TP=${overall.tp} FP=${overall.fp} FN=${overall.fn} TN=${overall.tn}\n`);

  out.write('\n  same scans, advisory-file restriction OFF (diagnostic, NOT the claim):\n');
  out.write('    precision  ' + pct(wide.precision) + '\n');
  out.write('    recall     ' + pct(wide.recall) + '\n');
  out.write('    The gap against the figures above is how much apparent recall comes\n' +
            '    from flagging the right FILE versus flagging the right CWE somewhere\n' +
            '    in the package. Quote the restricted numbers; read this one to know\n' +
            '    whether a change moved the engine or moved the benchmark.\n');

  out.write('\n  by language\n');
  for (const [k, v] of Object.entries(report.byLanguage)) {
    out.write(`    ${k.padEnd(12)} n=${String(v.entries).padStart(3)}  precision ${pct(v.precision)}  recall ${pct(v.recall)}\n`);
  }
  out.write('\n  by CWE\n');
  for (const [k, v] of Object.entries(report.byCwe)) {
    out.write(`    ${k.padEnd(12)} n=${String(v.entries).padStart(3)}  recall ${pct(v.recall)}\n`);
  }
  if (unscored.length) {
    out.write(`\n  UNSCORED (${unscored.length}) — excluded from every denominator, never counted as misses:\n`);
    for (const u of unscored) out.write(`    · ${u.id}: ${u.reason}\n`);
  }
  out.write('\n  This is a measurement, not a gate. It has no baseline and must not grow one.\n\n');
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(c => process.exit(c)).catch(e => {
    process.stderr.write(`independent runner failed: ${e.message}\n`); process.exit(1);
  });
}
