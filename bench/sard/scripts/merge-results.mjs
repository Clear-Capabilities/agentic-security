#!/usr/bin/env node
// SARD_80_F1_SCANNER_PRD.md adversarial-premortem remediation, P1 item 8 —
// the mandatory full-corpus, all-language TEST-split gate needs Java, C#,
// and PHP's separate `--json` outputs scored together (one macro-score.mjs
// run, one shared baseline.json) rather than three independent baselines
// that could each go stale at a different pace unnoticed. Pure
// concatenation of each input's `results` array — no scoring logic here,
// this is purely a plumbing helper.
//
// Usage:
//   node merge-results.mjs <file1.json> <file2.json> ... > merged.json

import * as fs from 'node:fs';

function main() {
  const files = process.argv.slice(2);
  if (!files.length) {
    console.error('Usage: merge-results.mjs <file1.json> <file2.json> ...');
    process.exit(2);
  }
  const results = [];
  for (const f of files) {
    let doc;
    try { doc = JSON.parse(fs.readFileSync(f, 'utf8')); }
    catch (e) { console.error(`✗ ${f}: ${e.message}`); process.exit(1); }
    if (!Array.isArray(doc.results)) { console.error(`✗ ${f}: no "results" array`); process.exit(1); }
    results.push(...doc.results);
  }
  console.log(JSON.stringify({ results }));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
