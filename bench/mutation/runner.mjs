// Metamorphic + adversarial mutation harness.
//
// WHY THIS EXISTS. A detector can score well on a fixed corpus by memorising
// its shapes. This harness measures the opposite property: whether the verdict
// tracks the SEMANTICS of the code. Two mutation classes, and the engine must
// behave differently on each:
//
//   METAMORPHIC  — a semantics-preserving rewrite (rename a variable, swap
//                  string concatenation for a template literal, hoist the sink
//                  into a helper). The verdict MUST NOT move. A verdict that
//                  moves here was keyed on syntax, not meaning.
//
//   ADVERSARIAL  — a semantics-CHANGING near-miss (delete the sanitizer, or
//                  replace it with one from the wrong family). The verdict MUST
//                  move. A verdict that holds here is not analysing the flow.
//
// The score is verdict-flip correctness, not detection count. That is the whole
// point: accumulating patterns cannot raise it, and over-fitting lowers it.
//
// Both directions are gated. A harness that only checks "still detected" would
// pass an engine that labels everything sanitized, and a harness that only
// checks the mutants would pass one that labels nothing.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';
import { runScan } from '../../scanner/src/runScan.js';

// A benchmark must not mutate what it measures. Every mutant is scanned, and a
// scan writes `.agentic-security/` unless told not to — which would leave state
// behind in the temp trees and, worse, normalise the habit. Verified inside,
// not assumed.
await disableStateWrites();

import { DEFAULT_CWE, allCases, judge } from './cases.mjs';

async function verdictFor(c, tmpRoot) {
  const dir = path.join(tmpRoot, c.id);
  fs.mkdirSync(dir, { recursive: true });
  // The filename was hardcoded to app.js, so this gate — the anti-overfitting
  // control — could only ever cover JavaScript. Measured on the CVE corpus, 204
  // of 280 findings are NOT JavaScript, so the check with the broadest mandate
  // had the narrowest reach. A case may now name its own file; JS stays the
  // default so every existing case is unchanged.
  // A case may name a NESTED path, and several must: IaC admission is
  // path-sensitive (`charts/app/values.yaml` is a chart's values file,
  // `charts/app/templates/…` is Go template source and deliberately out of
  // scope), so writing every case at the tree root would test a different
  // program than the one the case describes.
  const target = path.join(dir, c.file || 'app.js');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, c.code);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const cweRe = c.cwe || DEFAULT_CWE;
    // Default stays IR-TAINT: the original cases are all about whether the taint
    // engine labels a flow sanitized. A case can opt into a different producer
    // (`parser`) when it is testing a structural detector instead — without
    // this, a non-taint case silently matches nothing and every verdict reads
    // "not detected", which would look like a passing adversarial case.
    const parserRe = c.parser || /^IR-TAINT$/;
    const hits = (scan.findings || []).filter(
      f => parserRe.test(f.parser || '') && cweRe.test(f.cwe || ''));
    return { detected: hits.length > 0, sanitized: hits.some(f => f.sanitized === true) };
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-mutation-'));
const rows = [];
let failures = 0;

for (const c of allCases()) {
  const v = await verdictFor(c, tmpRoot);
  const { detectOk, verdictOk, expected, gapClosed } = judge(c, v);
  if (gapClosed !== undefined) c.gapClosed = gapClosed;
  if (!verdictOk) failures++;
  rows.push({ ...c, ...v, expected, detectOk, verdictOk });
}

const w = (s, n) => String(s).padEnd(n);
console.log('\nMetamorphic + adversarial mutation gate\n');
console.log(w('case', 38), w('class', 13), w('dimension', 14), w('detected', 10), w('sanitized', 11), w('expected', 10), 'ok');
console.log('-'.repeat(108));
for (const r of rows) {
  console.log(
    w(r.id, 38), w(r.class, 13), w(r.dimension || 'sanitization', 14), w(r.detected, 10),
    w(r.sanitized, 11), w(r.expected, 10), r.verdictOk ? 'PASS' : 'FAIL');
  if (!r.verdictOk) {
    if (r.class === 'known-gap') console.log(r.gapClosed ? `   KNOWN GAP CLOSED: the engine now ${r.expectDetected ? 'detects' : 'ignores'} this. Promote the case out of known-gap. ${r.why}` : `   KNOWN GAP CHANGED: recorded detected=${r.gap.observedDetected}, now detected=${r.detected}. Re-record it. ${r.why}`);
    else console.log(`   ${r.detectOk ? 'verdict' : 'DETECTION'} wrong — ${r.why}`);
  }
}

const metamorphic = rows.filter(r => r.class === 'metamorphic');
const adversarial = rows.filter(r => r.class === 'adversarial');
const pct = (list) => list.length
  ? `${list.filter(r => r.verdictOk).length}/${list.length}` : '0/0';
console.log('-'.repeat(108));
const labelInv = rows.filter(r => r.class === 'label-invariance');
const knownGaps = rows.filter(r => r.class === 'known-gap');
console.log(`metamorphic (verdict must HOLD): ${pct(metamorphic)}`);
console.log(`adversarial (verdict must FLIP): ${pct(adversarial)}`);
console.log(`label-invariance (answer-key comment added, verdict must HOLD): ${pct(labelInv)}`);
console.log(`known gaps (held at their recorded behaviour): ${pct(knownGaps)}`);
for (const g of knownGaps) console.log(`   gap ${g.gap.kind}: ${g.id}`);
// Deliberately excludes the untagged 'baseline' sanity-check case: this line
// reports verdict-FLIP correctness specifically, and baseline is neither a
// metamorphic nor an adversarial mutant. Computing it over `rows` (all cases,
// including baseline) made the printed total disagree with metamorphic+
// adversarial's own sum (3+3=6 vs. a reported denominator of 7) — any
// baseline-only regression showed up as an unexplained "missing" case in this
// summary line with no attribution. `failures` below still covers every row,
// baseline included, so this is a reporting fix, not a gate-strength change.
console.log(`verdict-flip correctness       : ${pct([...metamorphic, ...adversarial, ...labelInv])}`);

fs.rmSync(tmpRoot, { recursive: true, force: true });

if (failures) {
  console.error(`\n✖ ${failures} case(s) wrong. The engine is keying on syntax, not semantics.`);
  process.exit(1);
}
console.log('\n✓ every mutant verdict correct');
