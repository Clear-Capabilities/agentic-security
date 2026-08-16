// D1 — per-layer, per-language recall over the CVE-replay corpus.
//
// WHAT THIS ANSWERS THAT THE CORPUS GATE CANNOT. `bench:cve-replay:check` asks
// "was this CVE detected?". This asks "by which analysis layer?" — and the two
// answers diverge sharply. The corpus is 210/210 green with 20 Ruby entries,
// while `bench/engine-recall/RESULTS.md` records a Rails fixture
// (`params[:c]` → `system(c)`) producing ZERO IR-TAINT findings, detected only
// by the regex layer. A language can be entirely unserved by the taint engine
// and the corpus gate stays green.
//
// DEEP MODE IS FORCED ON FOR EVERY ENTRY. The corpus runner enables it only for
// the 6 `deep`-tier entries, so 204 of 210 never exercise the taint engine at
// all. Measuring under those conditions would report the tier configuration
// rather than the engine's capability. Here every entry gets the same, maximal
// chance to be caught by taint — so a zero in the taint column means the engine
// cannot see it, not that it was never asked.
//
// Scoring reuses `corpus-match.js`'s predicate via `matchingFindings`, the same
// one the gate and enrolment use. A finding that does not score the entry is not
// evidence about the entry, no matter which layer produced it.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { disableStateWrites, purgeScanState } from '../_lib/tree-integrity.mjs';
import { runScan } from '../../scanner/src/runScan.js';
import { matcherFor, matchingFindings } from '../../scanner/src/posture/corpus-match.js';
import { layersOf, buildMatrix, summarize, languageOf, LAYER_TAINT } from './attribute.mjs';

await disableStateWrites();

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(HERE, '..', 'cve-replay');
const TIERS = ['regression', 'capability', 'deep'];
const BASELINE = path.join(HERE, 'baseline.json');

const argv = process.argv.slice(2);
const CHECK = argv.includes('--check');
const UPDATE = argv.includes('--update-baseline');
const ONLY = (argv.find(a => a.startsWith('--language=')) || '').split('=')[1] || null;
const JSON_OUT = argv.includes('--json');

function listEntries() {
  const out = [];
  for (const tier of TIERS) {
    const dir = path.join(CORPUS, tier);
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      const entry = path.join(dir, name);
      if (fs.statSync(entry).isDirectory()) out.push({ id: name, tier, dir: entry });
    }
  }
  return out;
}

function filesUnder(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.agentic-security') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return out;
}

async function scoreEntry(entry) {
  const manifest = JSON.parse(fs.readFileSync(path.join(entry.dir, 'manifest.json'), 'utf8'));
  const pre = path.join(entry.dir, 'pre');
  const language = languageOf(manifest, filesUnder(pre));
  if (ONLY && language !== ONLY) return null;

  // Forced on for every entry — see the header.
  const saved = [process.env.AGENTIC_SECURITY_DEEP, process.env.AGENTIC_SECURITY_DEEP_IN_CI];
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(pre);
    const matched = matchingFindings(scan, manifest, matcherFor(manifest));
    return { id: entry.id, tier: entry.tier, language, detected: matched.length > 0, layers: layersOf(matched) };
  } catch (e) {
    // A scan that threw is UNSCORED, not "not detected" — counting a crash as a
    // taint miss would understate the engine and hide the crash.
    return { id: entry.id, tier: entry.tier, language, detected: false, layers: [], error: e.message };
  } finally {
    if (saved[0] === undefined) delete process.env.AGENTIC_SECURITY_DEEP;
    else process.env.AGENTIC_SECURITY_DEEP = saved[0];
    if (saved[1] === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = saved[1];
  }
}

purgeScanState(CORPUS);

const entries = listEntries();
const rows = [];
let errors = 0;
for (const e of entries) {
  const r = await scoreEntry(e);
  if (!r) continue;
  if (r.error) errors++;
  rows.push(r);
  if (!CHECK && rows.length % 25 === 0) process.stderr.write(`  ${rows.length}/${entries.length}\r`);
}

const matrix = buildMatrix(rows);
const langs = Object.keys(matrix).sort();

// The corpus fires ~30 distinct detector labels; printing a column per label is
// unreadable and buries the one column this instrument exists to show. Keep
// TAINT plus the next few most productive layers, and fold the rest into
// `other` — disclosed as a count, never silently dropped.
const TOP_OTHER_LAYERS = 5;
const layerTotals = {};
for (const r of rows) for (const l of r.layers) layerTotals[l] = (layerTotals[l] || 0) + 1;
const otherLayers = Object.entries(layerTotals)
  .filter(([l]) => l !== LAYER_TAINT)
  .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  .slice(0, TOP_OTHER_LAYERS)
  .map(([l]) => l);
const foldedCount = Object.keys(layerTotals).filter(
  l => l !== LAYER_TAINT && !otherLayers.includes(l)).length;

const pad = (s, n) => String(s).padEnd(n);
const pct = (n, d) => d ? `${Math.round((100 * n) / d)}%` : '—';

const allSummary = summarize(rows);
const deepRows = rows.filter(r => r.tier === 'deep');
const deepSummary = summarize(deepRows);

if (!JSON_OUT) {
  console.log('\nPer-layer recall over the CVE-replay corpus (deep mode forced on for every entry)\n');
  const head = [pad('language', 10), pad('entries', 9), pad('detected', 11), pad('IR-TAINT', 13)]
    .concat(otherLayers.map(l => pad(l.toLowerCase(), 12))).concat([pad('other', 7)]);
  console.log(head.join(''));
  console.log('-'.repeat(head.join('').length));
  for (const lang of langs) {
    const c = matrix[lang];
    const taint = c.byLayer[LAYER_TAINT] || 0;
    const otherSum = Object.entries(c.byLayer)
      .filter(([l]) => l !== LAYER_TAINT && !otherLayers.includes(l))
      .reduce((s, [, n]) => s + n, 0);
    const cells = [
      pad(lang, 10), pad(c.total, 9), pad(`${c.detected} (${pct(c.detected, c.total)})`, 11),
      pad(`${taint} (${pct(taint, c.total)})`, 13),
    ].concat(otherLayers.map(l => pad(c.byLayer[l] || 0, 12)))
     .concat([pad(otherSum, 7)]);
    console.log(cells.join(''));
  }

  const totalTaint = rows.filter(r => r.layers.includes(LAYER_TAINT)).length;
  console.log('-'.repeat(head.join('').length));
  console.log(`\n  entries scored      : ${rows.length}${errors ? ` (${errors} errored — unscored, not counted as misses)` : ''}`);
  console.log(`  detected (any layer): ${rows.filter(r => r.detected).length}`);
  console.log(`  detected by TAINT   : ${totalTaint} (${pct(totalTaint, rows.length)})`);
  if (foldedCount) console.log(`  ('other' folds ${foldedCount} lower-volume detector labels)`);
  const blind = langs.filter(l => !(matrix[l].byLayer[LAYER_TAINT] > 0));
  if (blind.length) {
    console.log(`\n  ⚠ languages with ZERO taint-layer recall: ${blind.join(', ')}`);
    console.log(`    These pass the corpus gate on other layers. The taint engine does not see them.`);
  }

  console.log('\nTaint-shaped subset only (deep/ tier — provably invisible without deep mode)\n');
  if (!deepRows.length) {
    console.log('  (no deep-tier entries)');
  } else {
    const deepLangs = [...new Set(deepRows.map(r => r.language))].sort();
    console.log([pad('language', 10), pad('entries', 9), pad('IR-TAINT', 13)].join(''));
    console.log('-'.repeat(32));
    for (const lang of deepLangs) {
      const total = deepSummary.totalByLanguage[lang] || 0;
      const taint = deepSummary.taintByLanguage[lang] || 0;
      console.log([pad(lang, 10), pad(total, 9), pad(`${taint} (${pct(taint, total)})`, 13)].join(''));
    }
    const deepLangsWithNoEntry = langs.filter(l => !deepLangs.includes(l));
    if (deepLangsWithNoEntry.length) {
      console.log(`\n  languages with NO deep-tier entry yet: ${deepLangsWithNoEntry.join(', ')}`);
      console.log(`  (not zero recall — simply not measured on the taint-shaped subset)`);
    }
  }
}

const summary = {
  generatedAt: new Date().toISOString().slice(0, 10),
  ...allSummary,
  deepTier: deepSummary,
};

if (JSON_OUT) {
  console.log(JSON.stringify(summary, null, 2));
}

if (UPDATE) {
  fs.writeFileSync(BASELINE, JSON.stringify(summary, null, 2) + '\n');
  console.log(`\n✓ baseline written to ${path.relative(process.cwd(), BASELINE)}`);
  process.exit(0);
}

if (CHECK) {
  if (!fs.existsSync(BASELINE)) {
    console.error('\n✖ no baseline — run with --update-baseline first');
    process.exit(1);
  }
  const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  const regressions = [];
  for (const [lang, was] of Object.entries(base.taintByLanguage || {})) {
    const now = summary.taintByLanguage[lang] ?? 0;
    if (now < was) regressions.push(`${lang}: taint recall ${was} → ${now}`);
  }
  const baseDeep = (base.deepTier && base.deepTier.taintByLanguage) || {};
  for (const [lang, was] of Object.entries(baseDeep)) {
    const now = (deepSummary.taintByLanguage && deepSummary.taintByLanguage[lang]) ?? 0;
    if (now < was) regressions.push(`${lang} (deep-tier taint-shaped subset): taint recall ${was} → ${now}`);
  }
  if (regressions.length) {
    console.error(`\n✖ taint-layer recall regressed:\n   ${regressions.join('\n   ')}`);
    process.exit(1);
  }
  console.log('\n✓ no taint-layer recall regression (whole corpus or deep-tier subset)');
}
