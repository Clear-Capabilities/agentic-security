#!/usr/bin/env node
// Scores the root-cause sweep on seeded sibling sets (bench/sibling-sweep/cases.mjs).
//
//   node bench/sibling-sweep/runner.mjs            print the table
//   node bench/sibling-sweep/runner.mjs --check    compare to BASELINE.json for EQUALITY; exit 1 on any difference
//   node bench/sibling-sweep/runner.mjs --update-baseline
//
// What it measures: whether the sweep reports the planted siblings of a confirmed finding (recall), whether it ever reports a look-alike
// (false matches), whether a sibling that already carries a finding is called known rather than new, whether the finding's own site is
// excluded, and whether found === candidates + mitigated holds. What it does not measure: that a sibling is exploitable. The sweep finds
// structural siblings; it proves nothing about them, and this bench does not either. The corpus is written by the same people who wrote
// the matcher, so a 100% here is a statement about robustness over these shapes, not field recall.
//
// The gate compares for equality, like bench/layer-recall: a drop is a regression and a rise is an unrecorded change, and both fail until
// the baseline is updated on purpose.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sweepRootCauses } from '../../scanner/src/posture/root-cause-sweep.js';
import { CASES, build } from './cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = path.join(HERE, 'BASELINE.json');

export function scoreCase(c) {
  const { finding, findings, files, labels } = build(c);
  const result = sweepRootCauses(findings, files, { confirmedOnly: true });
  const sweep = result.sweeps.find(s => s.fromFindingId === finding.id);
  const out = { id: c.id, lang: c.lang, ran: Boolean(sweep) };
  if (!sweep) return { ...out, sib: { tp: 0, d: labels.sib.length }, form: { tp: 0, d: labels.form.length }, known: { ok: 0, d: labels.known.length }, near: { fp: 0, d: labels.near.length }, lim: {}, ownSiteReported: false, accounting: false };
  const all = sweep.instances || [];
  const truncated = Boolean(sweep.instancesTruncated);
  const byLoc = new Map(all.map(m => [`${m.file}:${m.line}`, m]));
  const reported = loc => byLoc.has(loc);
  const cand = loc => byLoc.get(loc)?.status === 'candidate';
  const mit = loc => byLoc.get(loc)?.status === 'mitigated-or-known';
  const bigCase = truncated;
  return {
    ...out,
    // In the large case the instance list is a bounded sample; the exact counts are what is scored there.
    sib: bigCase ? { tp: sweep.candidates, d: labels.sib.length } : { tp: labels.sib.filter(cand).length, d: labels.sib.length },
    form: { tp: labels.form.filter(cand).length, d: labels.form.length },
    known: { ok: labels.known.filter(mit).length, d: labels.known.length },
    near: { fp: labels.near.filter(reported).length, d: labels.near.length },
    lim: Object.fromEntries(labels.lim.map(loc => [loc, reported(loc) ? 'reported' : 'not reported'])),
    ownSiteReported: all.some(m => m.file === labels.origin.file && m.line === labels.origin.line),
    accounting: sweep.found === sweep.candidates + sweep.mitigated,
    counts: { found: sweep.found, candidates: sweep.candidates, mitigated: sweep.mitigated },
    truncatedDisclosed: truncated ? Boolean(sweep.instancesTruncated) : null,
  };
}

export function measure() {
  const cases = CASES.map(scoreCase);
  const sum = (f) => cases.reduce((a, c) => a + f(c), 0);
  const total = {
    cases: cases.length,
    siblings: { found: sum(c => c.sib.tp), planted: sum(c => c.sib.d) },
    differentlyWritten: { found: sum(c => c.form.tp), planted: sum(c => c.form.d) },
    known: { calledKnown: sum(c => c.known.ok), planted: sum(c => c.known.d) },
    nearMisses: { falselyReported: sum(c => c.near.fp), planted: sum(c => c.near.d) },
    ownSiteReported: sum(c => (c.ownSiteReported ? 1 : 0)),
    accountingHolds: sum(c => (c.accounting ? 1 : 0)),
  };
  return { schema: 'sibling-sweep/v1', total, cases };
}

function main() {
  const args = process.argv.slice(2);
  const m = measure();
  const t = m.total;
  const pct = (a, b) => (b ? `${(100 * a / b).toFixed(1)}%` : 'n/a');
  console.log(`sibling-sweep: ${t.cases} cases`);
  console.log(`  same-shape recall     ${t.siblings.found}/${t.siblings.planted} = ${pct(t.siblings.found, t.siblings.planted)}`);
  console.log(`  other-form recall     ${t.differentlyWritten.found}/${t.differentlyWritten.planted} = ${pct(t.differentlyWritten.found, t.differentlyWritten.planted)}  (siblings built another way; a measured design limit)`);
  console.log(`  known called known    ${t.known.calledKnown}/${t.known.planted}`);
  console.log(`  look-alikes reported  ${t.nearMisses.falselyReported}/${t.nearMisses.planted}  (false matches; lower is better)`);
  console.log(`  own site reported     ${t.ownSiteReported}/${t.cases}  (must be 0)`);
  console.log(`  accounting holds      ${t.accountingHolds}/${t.cases}  (found === candidates + mitigated)`);
  for (const c of m.cases) {
    const lim = Object.entries(c.lim);
    if (lim.length) console.log(`  documented limits [${c.id}]: ${lim.map(([k, v]) => `${k} ${v}`).join('; ')}`);
  }
  if (args.includes('--update-baseline')) { fs.writeFileSync(BASELINE, JSON.stringify(m, null, 2) + '\n'); console.log(`wrote ${path.relative(process.cwd(), BASELINE)}`); return 0; }
  if (args.includes('--check')) {
    const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
    if (JSON.stringify(base) !== JSON.stringify(m)) {
      console.error('sibling-sweep check FAILED: the result differs from BASELINE.json (a drop is a regression; a rise is an unrecorded change).');
      for (const c of m.cases) {
        const b = base.cases.find(x => x.id === c.id);
        if (!b || JSON.stringify(b) !== JSON.stringify(c)) console.error(`  differs: ${c.id}`);
      }
      console.error('  If the change is deliberate: node bench/sibling-sweep/runner.mjs --update-baseline, and say why in the commit.');
      return 1;
    }
    console.log('sibling-sweep check ok: identical to BASELINE.json');
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());
