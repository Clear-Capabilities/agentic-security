#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md §39-41 — baseline capture + regression gate.
//
// DEVIATION FROM THE PRD'S LITERAL FILE TREE, DELIBERATE: §39 assumes
// `bench/sard/reports/baseline.json` is a committed artifact another
// contributor's CI run compares against, the same way
// `bench/cve-replay/corpus-baseline.json` is committed. This repo's
// `bench/README.md` has a stronger, more specific, pre-existing policy:
// "No benchmark scores are published in this repository ... numbers are
// intentionally not committed or quoted in any user-facing document" —
// because a raw SARD F1 number, unlike cve-replay's per-CVE pass/fail
// verdicts, IS exactly the kind of single-corpus percentage that policy
// exists to keep out of the repo (it can't be quoted out of context if it
// was never committed). So baseline.json here is LOCAL-ONLY (gitignored,
// like bench/sard/reports/*.json already is) — this script gives every
// developer/CI-runner a regression gate against THEIR OWN last known-good
// local run, not a shared committed number. A hosted CI environment that
// wants this gate needs to persist baseline.json as a build cache/artifact
// across runs itself; that wiring is a Phase 10 CI-workflow concern, not
// this script's.
//
// Usage:
//   node bench-realworld.js --app sard-juliet-java-strict --blind --scramble-identifiers --json \
//     | node macro-score.mjs | ... (macro-score.mjs writes reports/latest.json as a side effect)
//   node compare-baseline.mjs --update-baseline   # copies latest.json -> baseline.json
//   node compare-baseline.mjs --check-baseline    # compares latest.json against baseline.json, exits 1 on regression
//
// Regression gate (PRD §41, adapted to F1 percentages rather than pass/fail):
//   macro F1 must not decrease
//   micro F1 must not decrease by more than TOLERANCE
//   precision must not decrease by more than TOLERANCE (proxy for "secure-code FP rate must not materially increase")
//   no per-CWE F1 (among CWEs with >=MIN_SUPPORT expected entries) may regress by more than TOLERANCE

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(HERE, '..', 'reports');
const LATEST_PATH = path.join(REPORTS_DIR, 'latest.json');
const BASELINE_PATH = path.join(REPORTS_DIR, 'baseline.json');

const TOLERANCE = 0.02; // 2 percentage points — configurable via thresholds.json in a future pass, not needed yet with only 2 apps.
const MIN_SUPPORT = 5; // per-CWE regressions below this many expected entries are noise, not signal.

function args() {
  const a = process.argv.slice(2);
  return { update: a.includes('--update-baseline'), check: a.includes('--check-baseline') };
}

function main() {
  const opts = args();
  if (!opts.update && !opts.check) {
    console.error('Usage: compare-baseline.mjs --update-baseline | --check-baseline');
    process.exit(2);
  }
  if (!fs.existsSync(LATEST_PATH)) {
    console.error(`✗ no ${path.relative(process.cwd(), LATEST_PATH)} — run macro-score.mjs first.`);
    process.exit(2);
  }
  const latest = JSON.parse(fs.readFileSync(LATEST_PATH, 'utf8'));

  if (opts.update) {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(latest, null, 2) + '\n');
    console.log(`✓ baseline updated (local-only, gitignored) from ${latest.apps.length} app(s): ${path.relative(process.cwd(), BASELINE_PATH)}`);
    for (const app of latest.apps) console.log(`  ${app.name}: macroF1=${(app.macroF1 * 100).toFixed(1)}% microF1=${(app.aggregate.microF1 * 100).toFixed(1)}%`);
    return;
  }

  if (!fs.existsSync(BASELINE_PATH)) {
    console.error(`✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run --update-baseline first (once per machine/CI runner; it's gitignored, not shared).`);
    process.exit(2);
  }
  const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
  const baselineByName = Object.fromEntries(baseline.apps.map(a => [a.name, a]));

  let failed = false;
  const lines = [];
  for (const app of latest.apps) {
    const base = baselineByName[app.name];
    if (!base) { lines.push(`  + ${app.name}: no baseline entry yet (new app) — informational, not a failure.`); continue; }

    const macroDelta = app.macroF1 - base.macroF1;
    const microDelta = app.aggregate.microF1 - base.aggregate.microF1;
    const precisionDelta = app.aggregate.precision - base.aggregate.precision;

    if (macroDelta < 0) { failed = true; lines.push(`  ✗ ${app.name}: macro F1 regressed ${(base.macroF1*100).toFixed(1)}% -> ${(app.macroF1*100).toFixed(1)}% (${(macroDelta*100).toFixed(1)}pp)`); }
    else lines.push(`  ✓ ${app.name}: macro F1 ${(base.macroF1*100).toFixed(1)}% -> ${(app.macroF1*100).toFixed(1)}% (${macroDelta>=0?'+':''}${(macroDelta*100).toFixed(1)}pp)`);

    if (microDelta < -TOLERANCE) { failed = true; lines.push(`  ✗ ${app.name}: micro F1 regressed beyond tolerance: ${(base.aggregate.microF1*100).toFixed(1)}% -> ${(app.aggregate.microF1*100).toFixed(1)}%`); }
    if (precisionDelta < -TOLERANCE) { failed = true; lines.push(`  ✗ ${app.name}: precision regressed beyond tolerance (secure-code FP proxy): ${(base.aggregate.precision*100).toFixed(1)}% -> ${(app.aggregate.precision*100).toFixed(1)}%`); }

    const baseCwe = Object.fromEntries((base.perCwe || []).map(r => [r.cwe, r]));
    for (const row of app.perCwe || []) {
      const prior = baseCwe[row.cwe];
      if (!prior || prior.support < MIN_SUPPORT) continue;
      const delta = row.f1 - prior.f1;
      if (delta < -TOLERANCE) { failed = true; lines.push(`  ✗ ${app.name} ${row.cwe}: F1 regressed beyond tolerance: ${(prior.f1*100).toFixed(1)}% -> ${(row.f1*100).toFixed(1)}% (support=${row.support})`); }
    }
  }

  console.log('\nSARD baseline check (local-only — see this script\'s header for why there is no committed baseline):');
  for (const l of lines) console.log(l);
  if (failed) {
    console.error('\n✗ SARD regression gate FAILED. If intentional, run `npm run bench:sard:update-baseline`.');
    process.exit(1);
  }
  console.log('\n✓ no regression beyond tolerance.');
}

main();
