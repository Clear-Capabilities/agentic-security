// Independent Haskell precision set runner.  Usage: node run.mjs --check
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digestOf, wilson, validatePanel, agreementReport } from './lib.mjs';
import { flagAll } from './flag.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
console.log(`
================================================================================
 INDEPENDENT HASKELL PRECISION SET: FOR MEASUREMENT ONLY
 Reading these labels while changing detector rules turns this into a development
 set and ends its independence. Any such use MUST be recorded in
 bench/dag/independent-haskell/USE-LOG.md before the numbers are quoted.
================================================================================`);
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
const cls = (v) => v.replace(/^[A-Za-z_$][\w$]*\(\) /, '<fn>() ').replace(/\d+/g, 'N');
const kind = (s) => /\.hs$/.test(s.file) ? 'haskell source (.hs)' : 'non-Haskell file in a Haskell project';

const mk = () => ({ flagged: 0, tp: 0, fp: 0, ambiguous: 0, unlabeled: 0 });
const groups = { perProject: {}, perSourceKind: {}, perClass: {}, all: {} };
const add = (t, k, field) => { (t[k] ||= mk())[field]++; };
for (const s of flagged) {
  const l = labelByKey.get(key(s));
  const field = l ? l.verdict : 'unlabeled';
  for (const [t, k] of [[groups.perProject, s.project], [groups.perSourceKind, kind(s)], [groups.perClass, cls(s.vuln)], [groups.all, 'all haskell projects']]) { add(t, k, 'flagged'); add(t, k, field); }
}
const fin = (r) => {
  const n = r.tp + r.fp; const ci = wilson(r.tp, n);
  // sensitivity: ambiguous all counted as fp (lower bound) or all as tp (upper bound)
  const lo = r.tp / (n + r.ambiguous || 1), hi = (r.tp + r.ambiguous) / (n + r.ambiguous || 1);
  return { ...r, labeledDenominator: n, precision: n ? +(r.tp / n).toFixed(4) : null, wilson95: ci ? ci.map(x => +x.toFixed(4)) : null,
    ifAmbiguousAllFp: n + r.ambiguous ? +lo.toFixed(4) : null, ifAmbiguousAllTp: n + r.ambiguous ? +hi.toFixed(4) : null };
};
const finAll = (g) => Object.fromEntries(Object.entries(g).sort().map(([k, v]) => [k, fin(v)]));
const stale = doc.labels.filter(l => !flaggedKeys.has(key(l)));
const results = {
  scannerVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', '..', 'scanner', 'package.json'), 'utf8')).version,
  labelsDigest: doc.labelsDigest,
  definition: 'precision = tp / (tp + fp); ambiguous and unlabeled excluded from the denominator; 95% Wilson interval',
  all: finAll(groups.all), perProject: finAll(groups.perProject), perSourceKind: finAll(groups.perSourceKind), perClass: finAll(groups.perClass),
  staleLabels: stale.length,
};
// The two-labeler panel is optional and additive (see build-labels.mjs --panel). When labels-panel.json exists it must be valid, independent and built on
// exactly these labels; then the agreement and the precision under the ADJUDICATED verdicts are reported BESIDE the single-labeler figures above, which
// are unchanged. With no panel file nothing below runs and results.json has exactly the shape it always had.
const panelFile = path.join(HERE, 'labels-panel.json');
let panelMd = '';
if (fs.existsSync(panelFile)) {
  const panel = JSON.parse(fs.readFileSync(panelFile, 'utf8'));
  const v = validatePanel(panel, doc.labels);
  if (!v.ok || panel.baseLabelsDigest !== doc.labelsDigest) {
    console.error(`FAIL: labels-panel.json is not valid for these labels:\n  ${v.errors.concat(panel.baseLabelsDigest !== doc.labelsDigest ? ['baseLabelsDigest differs from labels.json'] : []).join('\n  ')}`);
    process.exit(1);
  }
  const finalById = new Map(panel.sites.map((s) => [s.id, s.final]));
  const t = { flagged: 0, tp: 0, fp: 0, ambiguous: 0, unlabeled: 0 };
  for (const s of flagged) {
    const l = labelByKey.get(key(s));
    const fin = l ? finalById.get(l.id) : null;
    t.flagged++;
    if (!fin) t.unlabeled++; else t[fin]++;
  }
  const n = t.tp + t.fp; const ci = wilson(t.tp, n);
  results.panel = { agreement: agreementReport(panel), adjudicatedPrecision: { ...t, labeledDenominator: n, precision: n ? +(t.tp / n).toFixed(4) : null, wilson95: ci ? ci.map(x => +x.toFixed(4)) : null } };
  const a = results.panel.agreement;
  panelMd = `\n## Two-labeler panel\n\nLabelers: ${a.labelers.map((l) => `${l.labelerId} (${l.model})`).join(', ')}; adjudicator: ${a.adjudicator ? `${a.adjudicator.labelerId} (${a.adjudicator.model})` : 'none'}.\n\n` +
    a.pairs.map((p) => `- ${p.labelers.join(' and ')}: percent agreement ${p.threeWay.percentAgreement == null ? 'n/a' : (100 * p.threeWay.percentAgreement).toFixed(1) + '%'}, Cohen kappa ${p.threeWay.kappa == null ? 'undefined' : p.threeWay.kappa.toFixed(3)} (${p.decidedOnly.sites} sites decided by both, kappa ${p.decidedOnly.kappa == null ? 'undefined' : p.decidedOnly.kappa.toFixed(3)})`).join('\n') +
    `\n- sites: agreed ${a.statusCounts.agreed}, disagreed ${a.statusCounts.disagreed}, one labeler unsure ${a.statusCounts['one-unsure']}, all unsure ${a.statusCounts['all-unsure']}; adjudicated ${a.adjudicated}, still ambiguous ${a.unsettledAfterAdjudication}\n` +
    `- precision under the adjudicated verdicts: ${t.tp}/${n} = ${n ? (100 * t.tp / n).toFixed(1) + '%' : 'n/a'}${ci ? ` (95% Wilson ${(100 * ci[0]).toFixed(1)}% to ${(100 * ci[1]).toFixed(1)}%)` : ''}; ambiguous ${t.ambiguous}, unlabeled ${t.unlabeled}\n`;
}
fs.writeFileSync(path.join(HERE, 'results.json'), JSON.stringify(results, null, 1) + '\n');

const pct = (x) => x === null ? 'n/a' : (100 * x).toFixed(1) + '%';
const row = (k, r) => `| ${k} | ${r.flagged} | ${r.tp} | ${r.fp} | ${r.ambiguous} | ${r.unlabeled} | ${r.labeledDenominator} | ${pct(r.precision)} | ${r.wilson95 ? pct(r.wilson95[0]) + ' to ' + pct(r.wilson95[1]) : 'n/a'} | ${pct(r.ifAmbiguousAllFp)} to ${pct(r.ifAmbiguousAllTp)} |`;
const head = '| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson | range if ambiguous all fp / all tp |\n|---|---|---|---|---|---|---|---|---|---|';
const tbl = (g) => Object.entries(g).map(([k, v]) => row(k, v)).join('\n');
const md = `# Independent Haskell precision results

Date: ${new Date().toISOString().slice(0, 10)}
Scanner version: ${results.scannerVersion}
Labels digest: ${results.labelsDigest}

MEASUREMENT ONLY. See README.md and USE-LOG.md.

## Overall

${head}
${tbl(results.all)}

## Per project

${head}
${tbl(results.perProject)}

## Per source kind

${head}
${tbl(results.perSourceKind)}

## Per vulnerability class (classes with at least one label)

${head}
${Object.entries(results.perClass).filter(([, v]) => v.tp + v.fp + v.ambiguous > 0).map(([k, v]) => row(k, v)).join('\n')}

## Reading these numbers

- precision = tp / (tp + fp). Ambiguous sites are excluded from the denominator and counted separately; the last column shows the range if they were all fp or all tp.
- Only ${groups.all['all haskell projects'].flagged} sites are flagged in total across 4 projects, so the labeled sample is most of the flagged population (a near census of flags, not a draw from a large population). Unlabeled sites are never counted.
- Recall cannot be measured here: there is no ground-truth list of the vulnerabilities in these projects, and a flag list says nothing about what was missed.
- Intervals treat the sample as simple random. Sites cluster by file and rule (for example ten sampled sites are one Dockerfile rule across sibling build images, and twelve are unsafePerformIO global-state idioms), so the true uncertainty is wider.
- Stale labels (labeled sites no longer flagged): ${results.staleLabels}.
${panelMd}
## Limitations

- One LLM labeler reading source; not a human audit, no second labeler, so labeler disagreement is unmeasured.
- Projects and scan roots were chosen by the labeler, not drawn at random; four projects cover web service, CLI, library and CLI plus web UI.
- A "tp" requires the named weakness to be present and security-meaningful for someone other than the operator invoking the tool; a CLI user's own paths and arguments are not a privilege boundary. Another labeler could draw that line differently, which is why the ambiguous range is shown.
- Labels reflect each project at its pinned commit.
- Dependency and file-level findings (line 0) and test directories are out of scope. The flagged set includes non-Haskell files in the projects (Dockerfiles, one JavaScript file); they are reported as a separate source kind.
`;
fs.writeFileSync(path.join(HERE, 'results.md'), md);
console.log(md.split('## Per vulnerability class')[0]);
console.log(`unlabeled and stale are reported, never counted. stale labels: ${stale.length}`);
