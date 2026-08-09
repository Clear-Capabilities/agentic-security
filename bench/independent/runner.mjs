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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MANIFEST = path.join(HERE, 'manifest.json');

/** Below this, a rate is noise. Reported, but labelled unreliable. */
export const MIN_RELIABLE_N = 10;

/** Does any finding carry the labelled CWE? Normalised, exact on the number. */
export function matchesCwe(findings, cwe) {
  const want = String(cwe || '').toUpperCase().trim();
  if (!/^CWE-\d+$/.test(want)) return false;
  return (findings || []).some(f => String(f.cwe || '').toUpperCase().trim() === want);
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

async function scanDir(dir) {
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  return normalizeFindings(scan) || [];
}

async function main() {
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
    const hitPre = matchesCwe(preFindings, e.cwe);
    const hitPost = matchesCwe(postFindings, e.cwe);
    perEntry.push({
      id: e.id, cwe: e.cwe, language: e.language, repo: e.repo,
      tp: hitPre ? 1 : 0, fn: hitPre ? 0 : 1,
      fp: hitPost ? 1 : 0, tn: hitPost ? 0 : 1,
      preFindings: preFindings.length, postFindings: postFindings.length,
    });
  }

  const sum = (rows) => rows.reduce((a, r) => ({
    tp: a.tp + r.tp, fp: a.fp + r.fp, fn: a.fn + r.fn, tn: a.tn + r.tn,
  }), { tp: 0, fp: 0, fn: 0, tn: 0 });

  const overall = scoreCounts(sum(perEntry));
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
    overall,
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
