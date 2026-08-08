#!/usr/bin/env node
// Guards the corpus against being fitted to the detectors it measures.
//
// THE PROBLEM, MEASURED. 206 of 210 corpus entries carry
// `source: "synthetic-shape-of-disclosed-cve"`; none carry the
// "disclosed PoC" tier that `bench/cve-replay/CONTRIBUTING.md` calls the
// highest-signal one. The fixtures are written by the same party as the
// detectors, and CONTRIBUTING's own workflow says to "fix fixtures/detectors
// until new entries pass". That is fitting the test to the model, and it makes
// a 100% detection rate a tautology rather than a measurement.
//
// The clearest instance was self-inflicted: `sast/crypto-specialist.js` and its
// 10 corpus entries were authored in the same session, and when two entries
// failed the DETECTOR was changed until they passed. Nothing prevented it,
// nothing recorded it, and the resulting corpus figure looks identical to one
// earned honestly.
//
// WHAT THIS CHECKS. Two rules, both mechanical:
//
//   1. SAME-COMMIT COUPLING. A commit that adds corpus entries must not also
//      change the detector modules those entries exercise. Land the detector
//      first, then the entries — so an entry is written against a detector that
//      already existed rather than one being tuned to it. This does not make
//      the corpus independent; it makes the coupling visible in history instead
//      of invisible.
//
//   2. PROVENANCE DISCLOSURE. Every entry must declare `source`, and the
//      distribution across source-quality tiers is reported so a reader can see
//      what the corpus is made of. A corpus that is ~100% synthetic is a
//      legitimate artifact — it is a REGRESSION net — but it cannot support a
//      recall claim, and the numbers should make that impossible to forget.
//
// WHAT THIS DOES NOT FIX, AND CANNOT. Neither rule makes the corpus an
// independent test set. Only an externally-sourced, third-party-labelled
// population can do that. This check exists to stop the loop getting tighter
// and to keep the composition honest while that population is acquired.
//
// Usage:
//   node scripts/corpus-provenance-check.mjs              # report + enforce
//   node scripts/corpus-provenance-check.mjs --report     # report only, exit 0

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const CORPUS = path.join(REPO, 'bench', 'cve-replay');
const TIERS = ['regression', 'capability', 'deep'];

const reportOnly = process.argv.includes('--report');

function entries() {
  const out = [];
  for (const tier of TIERS) {
    const dir = path.join(CORPUS, tier);
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const name of names) {
      const mf = path.join(dir, name, 'manifest.json');
      // Single read inside try/catch, NOT existsSync-then-read. This project's
      // own engine flags the check-then-use form as CWE-367 (TOCTOU) — it did,
      // on this very file, which is how the omission was caught. A directory
      // without a manifest is simply not an entry, and the throw says so.
      let raw;
      try { raw = fs.readFileSync(mf, 'utf8'); } catch { continue; }
      try {
        out.push({ tier, id: name, manifest: JSON.parse(raw) });
      } catch {
        out.push({ tier, id: name, manifest: null });
      }
    }
  }
  return out;
}

// The repository the COUPLING check reads history from. Overridable so the rule
// can be exercised against a purpose-built repo: the tests previously pinned
// real commit SHAs from this project's history, which a shallow CI clone does
// not have — the check silently degraded to "history unavailable" and the test
// asserting its output failed for a reason unrelated to the logic.
const GIT_DIR = process.env.CORPUS_PROVENANCE_GIT_DIR || REPO;

function git(args) {
  return execFileSync('git', ['-C', GIT_DIR, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

const errors = [];
const all = entries();

// ---- rule 2: provenance disclosure -----------------------------------------
const bySource = {};
for (const e of all) {
  if (!e.manifest) { errors.push(`${e.tier}/${e.id}: manifest.json does not parse`); continue; }
  const src = e.manifest.source;
  if (!src) { errors.push(`${e.tier}/${e.id}: manifest has no \`source\` — provenance must be declared`); continue; }
  bySource[src] = (bySource[src] || 0) + 1;
}

console.log(`=== corpus provenance (${all.length} entries) ===`);
for (const [src, n] of Object.entries(bySource).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(n).padStart(4)}  ${src}  (${((n / all.length) * 100).toFixed(1)}%)`);
}
const syntheticish = Object.entries(bySource)
  .filter(([s]) => /synthetic|shape|execution-proven/i.test(s))
  .reduce((a, [, n]) => a + n, 0);
console.log(
  `\n  ${((syntheticish / all.length) * 100).toFixed(1)}% of entries are self-authored fixtures rather than\n`
  + '  third-party-labelled real-world code. This corpus is a REGRESSION net: it\n'
  + '  proves nothing that passed before has stopped passing. It cannot support a\n'
  + '  recall claim about arbitrary code, and its detection rate is at the ceiling\n'
  + '  by construction, since an entry is only admitted once it scores.',
);

// ---- rule 1: same-commit coupling ------------------------------------------
// Only meaningful with a working tree and history; degrade rather than fail.
let coupling = null;
try {
  const range = process.env.CORPUS_PROVENANCE_RANGE || 'HEAD~1..HEAD';
  const changed = git(['diff', '--name-only', range]).split('\n').map(s => s.trim()).filter(Boolean);
  const addedEntries = changed.filter(f => /^bench\/cve-replay\/(regression|capability|deep)\/[^/]+\/manifest\.json$/.test(f));
  // Anything that can move a corpus verdict counts as a "detector" here, not
  // just `sast/` and `dataflow/`. The first version watched only those two,
  // which would have missed a change to `posture/relevance.js` (it demotes
  // findings), to the IR parsers (they decide what is even analysable), or to
  // `engine.js` (it wires the whole pipeline) — each of which can flip an entry
  // from FN to TP just as surely as a rule edit.
  const DETECTOR_PATHS = /^scanner\/src\/(sast|dataflow|posture|ir)\/|^scanner\/src\/engine\.js$/;
  const changedDetectors = changed.filter(f => DETECTOR_PATHS.test(f));
  coupling = { range, addedEntries, changedDetectors };
  if (addedEntries.length && changedDetectors.length) {
    errors.push(
      `commit range ${range} changes ${changedDetectors.length} detector file(s) AND adds/changes `
      + `${addedEntries.length} corpus entr(y/ies) together:\n`
      + `    detectors: ${changedDetectors.slice(0, 5).join(', ')}${changedDetectors.length > 5 ? ' …' : ''}\n`
      + `    entries:   ${addedEntries.slice(0, 5).join(', ')}${addedEntries.length > 5 ? ' …' : ''}\n`
      + '    An entry authored alongside the detector it exercises is fitted to that detector, and the\n'
      + '    resulting corpus figure is indistinguishable from one earned honestly. Land the detector\n'
      + '    first, then the entries in a separate commit. Set CORPUS_PROVENANCE_RANGE to check a\n'
      + '    different range.',
    );
  }
} catch {
  console.log('\n  (coupling check skipped: git history unavailable)');
}

if (coupling && !errors.length) {
  console.log(`\n  coupling check over ${coupling.range}: `
    + `${coupling.addedEntries.length} entry change(s), ${coupling.changedDetectors.length} detector change(s) — not co-committed.`);
}

if (errors.length) {
  console.error(`\n✗ CORPUS PROVENANCE${reportOnly ? ' (report only)' : ''}`);
  for (const e of errors) console.error(`  · ${e}`);
  process.exit(reportOnly ? 0 : 1);
}
console.log('\n✓ corpus provenance check passed.');
