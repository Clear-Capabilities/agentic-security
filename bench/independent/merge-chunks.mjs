#!/usr/bin/env node
// Merge chunked runs of runner.mjs into one RESULT.json.
//
// WHY CHUNKS EXIST. A whole-population run wedged on 2026-08-23 at 0.0% CPU
// after 24 minutes of CPU time and 4.5 hours of wall clock — the signature the
// per-entry watchdog was written for. The watchdog bounds the awaited promise;
// it cannot free the handles a wedged scan still holds, so one stalled entry
// costs the run AND every entry already scored. `runner.mjs --offset= --limit=`
// puts each slice in its own process; this reassembles them.
//
// WHY IT RECOMPUTES RATHER THAN SUMS. Every aggregate is derived here from the
// concatenated `perEntry` rows, not by adding the chunks' pre-computed blocks.
// Summing published aggregates is how a merge quietly disagrees with the thing
// it merged — a ratio-of-sums is not a sum-of-ratios, and nothing would catch
// it. The SELF-CHECK below is the proof: recomputing a single chunk from its own
// rows must reproduce that chunk's own numbers exactly, or this script refuses
// to write.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = () => path.join(HERE, process.argv.includes('--deep') ? 'RESULT-deep.json' : 'RESULT.json');

function ratio(n, d) { return { n, d, value: d === 0 ? null : n / d }; }
function f1(p, r) {
  if (p.value === null || r.value === null || p.value + r.value === 0) return null;
  return (2 * p.value * r.value) / (p.value + r.value);
}
function score(rows, pick) {
  const tp = rows.reduce((a, r) => a + (r[pick.tp] || 0), 0);
  const fp = rows.reduce((a, r) => a + (r[pick.fp] || 0), 0);
  const fn = rows.reduce((a, r) => a + (r[pick.fn] || 0), 0);
  const tn = rows.reduce((a, r) => a + (r[pick.tn] || 0), 0);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  return { tp, fp, fn, tn, precision, recall, f1: f1(precision, recall), scored: rows.length };
}
const LOCAL = { tp: 'tpLocal', fp: 'fpLocal', fn: 'fnLocal', tn: 'tnLocal' };
const WIDE = { tp: 'tpWide', fp: 'fpWide', fn: 'fnWide', tn: 'tnWide' };
const FILE = { tp: 'tp', fp: 'fp', fn: 'fn', tn: 'tn' };

function groupBy(rows, key) {
  const out = {};
  for (const r of rows) (out[r[key] || 'unknown'] ||= []).push(r);
  return out;
}

function aggregates(rows) {
  const localized = score(rows, LOCAL);
  // `tpLocal === 1`, matching the runner exactly. These fields are COUNTS, not
  // booleans — a truthiness test read `survivedFix: 1` as "did not survive" and
  // the self-check caught it, which is the entire reason the self-check exists.
  const localTpRows = rows.filter((r) => r.tpLocal === 1);
  const byLayer = {};
  for (const r of localTpRows) if (r.matchedParser) byLayer[r.matchedParser] = (byLayer[r.matchedParser] || 0) + 1;
  const byLanguageLayer = {};
  for (const [lang, rs] of Object.entries(groupBy(rows, 'language'))) {
    const layers = {};
    for (const r of rs.filter((x) => x.tpLocal === 1)) {
      if (r.matchedParser) layers[r.matchedParser] = (layers[r.matchedParser] || 0) + 1;
    }
    byLanguageLayer[lang] = {
      entries: rs.length,
      localizedTps: rs.reduce((a, r) => a + (r.tpLocal || 0), 0),
      byLayer: layers,
    };
  }
  const taintByLang = {};
  for (const [lang, rs] of Object.entries(groupBy(rows, 'language'))) {
    const tps = rs.filter((r) => r.tpLocal === 1);
    taintByLang[lang] = ratio(tps.filter((r) => r.matchedParser === 'IR-TAINT').length, tps.length);
  }
  const survived = localTpRows.filter((r) => r.survivedFix === 1).length;
  const survivedWide = localTpRows.filter((r) => r.survivedFixWide === 1).length;
  return {
    localized,
    overall: score(rows, FILE),
    wide: score(rows, WIDE),
    fixDiscrimination: {
      ...ratio(localTpRows.length - survived, localTpRows.length),
      meaning: 'localized TPs whose finding disappears from the lines the fix produced',
    },
    fixDiscriminationFileScoped: {
      ...ratio(localTpRows.length - survivedWide, localTpRows.length),
      meaning: 'localized TPs with NO matching finding anywhere in the advisory files afterwards',
    },
    byLayer,
    byLanguageLayer,
    taintShare: {
      overall: ratio(localTpRows.filter((r) => r.matchedParser === 'IR-TAINT').length, localTpRows.length),
      byLanguage: taintByLang,
    },
    // FILE-scoped, matching the runner's own `group('language')`, which sums the
    // plain tp/fp/fn/tn. These were built from `tpLocal` in the first version,
    // and the mismatch surfaced downstream rather than here: docs/SCORECARD.md
    // reads `byLanguage`, so its per-language rows summed to 28 while its own
    // headline — read from `overall` — said 71. A merge must reproduce the
    // thing it merged, including which field a name refers to.
    byLanguage: Object.fromEntries(Object.entries(groupBy(rows, 'language'))
      .map(([k, rs]) => [k, { entries: rs.length, ...score(rs, FILE) }])),
    byCwe: Object.fromEntries(Object.entries(groupBy(rows, 'cwe'))
      .map(([k, rs]) => [k, { entries: rs.length, ...score(rs, FILE) }])),
  };
}

// Every number this script will publish, recomputed from ONE chunk's rows and
// compared with that chunk's own published numbers. A mismatch means the merge
// arithmetic and the runner's disagree, and the merge must not be trusted.
function selfCheck(chunk) {
  const mine = aggregates(chunk.perEntry);
  const problems = [];
  const eq = (label, a, b) => { if (a !== b) problems.push(`${label}: merged ${a} vs runner ${b}`); };
  for (const k of ['tp', 'fp', 'fn', 'tn']) eq(`localized.${k}`, mine.localized[k], chunk.localized[k]);
  for (const k of ['tp', 'fp', 'fn', 'tn']) eq(`overall.${k}`, mine.overall[k], chunk.overall[k]);
  eq('fixDiscrimination.n', mine.fixDiscrimination.n, chunk.fixDiscrimination.n);
  eq('fixDiscrimination.d', mine.fixDiscrimination.d, chunk.fixDiscrimination.d);
  eq('taintShare.n', mine.taintShare.overall.n, chunk.taintShare.overall.n);
  eq('taintShare.d', mine.taintShare.overall.d, chunk.taintShare.overall.d);
  // byLanguage is read by docs/SCORECARD.md, and a field-meaning mismatch here
  // is invisible in this file and wrong two documents away. Checked per key.
  for (const [lang, v] of Object.entries(chunk.byLanguage || {})) {
    const m = mine.byLanguage[lang];
    if (!m) { problems.push(`byLanguage.${lang}: missing after merge`); continue; }
    for (const k of ['entries', 'tp', 'fp', 'fn', 'tn']) eq(`byLanguage.${lang}.${k}`, m[k], v[k]);
  }
  return problems;
}

function main() {
  // Which configuration to merge. Deep and pattern-only are separate
  // measurements and are never mixed — the version/config guard below would
  // refuse anyway, but selecting by name means a half-finished deep run cannot
  // be merged on top of a complete pattern-only one.
  const wantDeep = process.argv.includes('--deep');
  const re = wantDeep ? /^RESULT-chunk-deep-\d+\.json$/ : /^RESULT-chunk-pattern-\d+\.json$/;
  const files = fs.readdirSync(HERE).filter((f) => re.test(f)).sort();
  if (!files.length) { process.stderr.write('no RESULT-chunk-*.json found\n'); process.exit(1); }

  const chunks = files.map((f) => JSON.parse(fs.readFileSync(path.join(HERE, f), 'utf8')));
  const versions = [...new Set(chunks.map((c) => c.engineVersion))];
  const configs = [...new Set(chunks.map((c) => c.configuration))];
  if (versions.length !== 1 || configs.length !== 1) {
    process.stderr.write(`refusing to merge chunks measured differently — engineVersion=${JSON.stringify(versions)} configuration=${JSON.stringify(configs)}\n`);
    process.exit(1);
  }

  for (const [i, c] of chunks.entries()) {
    const problems = selfCheck(c);
    if (problems.length) {
      process.stderr.write(`SELF-CHECK FAILED on ${files[i]}:\n  ${problems.join('\n  ')}\n`);
      process.exit(1);
    }
  }
  process.stderr.write(`self-check passed on all ${chunks.length} chunks\n`);

  // A duplicate would double-count. Chunks are disjoint slices, so this is a
  // guard against a re-run with a shifted offset, not an expected case.
  const seen = new Set();
  const rows = [];
  for (const c of chunks) for (const r of c.perEntry) {
    if (seen.has(r.id)) continue;
    seen.add(r.id); rows.push(r);
  }
  const unscored = [];
  const unscoredSeen = new Set();
  for (const c of chunks) for (const u of (c.population.unscored || [])) {
    const id = typeof u === 'string' ? u : u.id;
    if (unscoredSeen.has(id)) continue;
    unscoredSeen.add(id); unscored.push(u);
  }

  const agg = aggregates(rows);
  const held = rows.filter((r) => r.heldOut);
  const report = {
    schema: 'agentic-security/independent-population-result@2',
    source: 'bench/independent/runner.mjs (chunked) + merge-chunks.mjs',
    measuredAt: new Date().toISOString().slice(0, 10),
    engineVersion: versions[0],
    configuration: configs[0],
    mergedFrom: {
      chunks: files.length,
      files,
      note: 'Aggregates are RECOMPUTED from the concatenated per-entry rows, not summed from the chunks\' own blocks, and a self-check proves the arithmetic reproduces each chunk exactly.',
    },
    population: {
      totalEntries: chunks[0].population.totalEntries,
      scoredEntries: rows.length,
      unscored,
      labelSources: [...new Set(chunks.flatMap((c) => c.population.labelSources || []))],
    },
    reliable: rows.length >= 10,
    perEntry: rows,
    ...agg,
    heldOut: {
      meaning: 'never tune against these; scored separately (T0.7)',
      entries: held.length,
      localized: score(held, LOCAL),
    },
    development: {
      entries: rows.length - held.length,
      localized: score(rows.filter((r) => !r.heldOut), LOCAL),
    },
  };
  fs.writeFileSync(OUT(), JSON.stringify(report, null, 2) + '\n');

  const pc = (r) => (r.value === null ? 'n/a' : `${(r.value * 100).toFixed(2)}%`);
  process.stderr.write(`\nmerged ${rows.length} entries from ${files.length} chunks (${unscored.length} unscored)\n`);
  process.stderr.write(`  localized recall    ${agg.localized.recall.n}/${agg.localized.recall.d} = ${pc(agg.localized.recall)}\n`);
  process.stderr.write(`  localized precision ${agg.localized.precision.n}/${agg.localized.precision.d} = ${pc(agg.localized.precision)}\n`);
  process.stderr.write(`  fix-discrimination  ${agg.fixDiscrimination.n}/${agg.fixDiscrimination.d} = ${pc(agg.fixDiscrimination)}\n`);
  process.stderr.write(`  taint share         ${agg.taintShare.overall.n}/${agg.taintShare.overall.d}\n`);
  process.stderr.write(`  held-out recall     ${report.heldOut.localized.recall.n}/${report.heldOut.localized.recall.d} = ${pc(report.heldOut.localized.recall)}\n`);
  process.stderr.write(`\nwrote ${path.relative(process.cwd(), OUT())}\n`);
}

main();
