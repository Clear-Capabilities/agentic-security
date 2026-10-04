// Freshness gate for the support registry (QA-002.AC03). Recomputes the registry and its table from the STORED measurement and test
// results and the corpus as it is now, and fails on ANY difference: a drop, an unrecorded improvement, a changed corpus hash, a
// hand edit of the registry or of the table. It never measures; to change a number, re-measure and promote deliberately.
//
//   node bench/language-support/check.mjs        # exit 0 when current, 1 otherwise
import fs from 'node:fs';
import { HOLDOUT, SUITES, REGISTRY, TABLE, currentFrozen } from './promote.mjs';
import { buildRegistry, renderTable } from './registry-build.mjs';

export function checkFreshness({ holdout = HOLDOUT, suites = SUITES, registryPath = REGISTRY, tablePath = TABLE, frozen = currentFrozen() } = {}) {
  const problems = [];
  const measurement = JSON.parse(fs.readFileSync(holdout, 'utf8'));
  const sres = JSON.parse(fs.readFileSync(suites, 'utf8'));
  const stored = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  const { registry } = buildRegistry(measurement, sres, frozen, sres.tools);
  const a = JSON.stringify(registry); const b = JSON.stringify(stored);
  if (a !== b) {
    for (const lang of Object.keys(registry.languages)) {
      for (const cap of Object.keys(registry.languages[lang].rows)) {
        const x = JSON.stringify(registry.languages[lang].rows[cap]); const y = JSON.stringify((stored.languages[lang] || { rows: {} }).rows[cap]);
        if (x !== y) problems.push(`${lang}/${cap}: the stored row differs from the one the measurement gives (${registry.languages[lang].rows[cap].status} vs ${((stored.languages[lang] || { rows: {} }).rows[cap] || {}).status})`);
      }
    }
    if (!problems.length) problems.push('the stored registry differs from the one recomputed from the stored measurement');
  }
  if (fs.readFileSync(tablePath, 'utf8') !== renderTable(registry)) problems.push('docs/language-support.md is not the rendering of the registry (edited by hand, or stale)');
  for (const k of ['holdoutRollup', 'labelsSha256', 'privacyLabelsSha256']) if (measurement.hashes[k] !== frozen[k]) problems.push(`the stored measurement was taken on different data (${k})`);
  return problems;
}

if (process.argv[1] && process.argv[1].endsWith('check.mjs')) {
  const problems = checkFreshness();
  if (problems.length) { process.stderr.write(`language support registry is stale:\n${problems.map((p) => `  - ${p}`).join('\n')}\nRe-measure and promote deliberately: node bench/language-support/promote.mjs\n`); process.exit(1); }
  process.stdout.write('language support registry is current\n');
}
