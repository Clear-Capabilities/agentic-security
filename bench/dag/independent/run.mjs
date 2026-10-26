// Independent precision set runner.  Usage: node run.mjs --check
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digestOf, wilson } from './lib.mjs';
import { flagAll } from './flag.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const banner = `
================================================================================
 INDEPENDENT PRECISION SET: FOR MEASUREMENT ONLY
 Reading these labels while changing detector rules turns this into a development
 set and ends its independence. Any such use MUST be recorded in
 bench/dag/independent/USE-LOG.md before the numbers are quoted.
================================================================================`;
console.log(banner);
if (!process.argv.includes('--check')) { console.error('usage: node run.mjs --check'); process.exit(2); }

const doc = JSON.parse(fs.readFileSync(path.join(HERE, 'labels.json'), 'utf8'));
const actual = digestOf(doc.labels);
if (actual !== doc.labelsDigest) {
  console.error(`FAIL: labelsDigest mismatch (recorded ${doc.labelsDigest}, computed ${actual}). Labels were edited without a USE-LOG entry and re-digest.`);
  process.exit(1);
}

const flagged = await flagAll();
const key = (s) => [s.project, s.file, s.line, s.vuln].join('|');
const labelByKey = new Map(doc.labels.map(l => [key(l), l]));
const flaggedKeys = new Set(flagged.map(key));
// "class" = vuln text with leading function name and digits normalised, so per-function variants group.
const cls = (v) => v.replace(/^[A-Za-z_$][\w$]*\(\) /, '<fn>() ').replace(/\d+/g, 'N');

const mk = () => ({ flagged: 0, tp: 0, fp: 0, ambiguous: 0, unlabeled: 0 });
const byLang = {}, byClass = {};
const add = (t, k, field) => { (t[k] ||= mk())[field]++; };
for (const s of flagged) {
  const l = labelByKey.get(key(s));
  const field = l ? l.verdict : 'unlabeled';
  for (const [t, k] of [[byLang, s.language], [byClass, `${s.language} | ${cls(s.vuln)}`]]) { add(t, k, 'flagged'); add(t, k, field); }
}
const fin = (r) => {
  const n = r.tp + r.fp; const ci = wilson(r.tp, n);
  return { ...r, labeledDenominator: n, precision: n ? +(r.tp / n).toFixed(4) : null, wilson95: ci ? ci.map(x => +x.toFixed(4)) : null };
};
const stale = doc.labels.filter(l => !flaggedKeys.has(key(l)));
const results = {
  scannerVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', '..', 'scanner', 'package.json'), 'utf8')).version,
  labelsDigest: doc.labelsDigest,
  definition: 'precision = tp / (tp + fp); ambiguous and unlabeled excluded from the denominator; 95% Wilson interval',
  perLanguage: Object.fromEntries(Object.entries(byLang).sort().map(([k, v]) => [k, fin(v)])),
  perClass: Object.fromEntries(Object.entries(byClass).sort().map(([k, v]) => [k, fin(v)])),
  staleLabels: stale.length,
};
fs.writeFileSync(path.join(HERE, 'results.json'), JSON.stringify(results, null, 1) + '\n');

const pct = (x) => x === null ? 'n/a' : (100 * x).toFixed(1) + '%';
const row = (k, r) => `| ${k} | ${r.flagged} | ${r.tp} | ${r.fp} | ${r.ambiguous} | ${r.unlabeled} | ${r.labeledDenominator} | ${pct(r.precision)} | ${r.wilson95 ? pct(r.wilson95[0]) + ' to ' + pct(r.wilson95[1]) : 'n/a'} |`;
const head = '| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson |\n|---|---|---|---|---|---|---|---|---|';
const md = `# Independent precision results

Date: ${new Date().toISOString().slice(0, 10)}
Scanner version: ${results.scannerVersion}
Labels digest: ${results.labelsDigest}

MEASUREMENT ONLY. See README.md and USE-LOG.md.

## Per language

${head}
${Object.entries(results.perLanguage).map(([k, v]) => row(k, v)).join('\n')}

## Per vulnerability class (classes with at least one label)

${head}
${Object.entries(results.perClass).filter(([, v]) => v.tp + v.fp + v.ambiguous > 0).map(([k, v]) => row(k, v)).join('\n')}

## Denominators and how to read them

- precision = tp / (tp + fp). Ambiguous sites are excluded from the denominator and counted separately.
- "unlabeled" are flagged sites that were NOT in the labeled random sample (the sample is a seeded random draw of 60 flagged sites per language, not the full flagged set) or are new since labeling. They are never counted. Precision is therefore an estimate for the flagged population of each language from the sample, not a census.
- Stale labels (labeled sites no longer flagged): ${results.staleLabels}.
- Intervals treat the sample as a simple random sample of sites. Sites cluster within files and rule families, so the true uncertainty is wider than shown. Per-class rows are small samples; read the intervals, not the point values.

## Limitations

- Labeled by one LLM agent reading source; not a human audit and not the scanner authors. No second labeler, so labeler disagreement is unmeasured.
- Scan roots and projects were chosen by the labeler (see manifest.json); projects are not a random draw of the ecosystem.
- Labels reflect the state of each project at the pinned commit, acquired on the date in manifest.json.
- The flagged set covers findings, logic vulnerabilities and secrets with a code line of at least 1; dependency and file-level findings (line 0) are out of scope. Test directories are excluded.
- "Weakness at that site" was judged with the rule's name as the claim; a site that is a real but differently-named weakness counts as fp for that rule.
`;
fs.writeFileSync(path.join(HERE, 'results.md'), md);
console.log(md.split('## Per vulnerability class')[0]);
console.log(`unlabeled and stale are reported, never counted. stale labels: ${stale.length}`);
