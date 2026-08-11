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

// ── The base program. Tainted input, one sanitizer, one XSS sink. ────────────
// Each case rewrites it; `expectSanitized` is what the engine must conclude.
const CASES = [
  {
    id: 'baseline',
    class: 'baseline',
    expectSanitized: true,
    why: 'xss sanitizer guarding an xss sink',
    code: `app.get('/i', (req, res) => {
  const name = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'metamorphic-rename',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'renaming the variable changes nothing about the flow',
    code: `app.get('/i', (req, res) => {
  const cleanedUserValue = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', cleanedUserValue);
});`,
  },
  {
    id: 'metamorphic-indirection',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'an extra clean copy step does not unsanitize the value',
    code: `app.get('/i', (req, res) => {
  const first = escapeHtml(req.query.name);
  const second = first;
  el.insertAdjacentHTML('beforeend', second);
});`,
  },
  {
    id: 'metamorphic-inline',
    class: 'metamorphic',
    expectSanitized: true,
    why: 'applying the sanitizer inline at the sink is the same program',
    code: `app.get('/i', (req, res) => {
  el.insertAdjacentHTML('beforeend', escapeHtml(req.query.name));
});`,
  },
  {
    id: 'adversarial-sanitizer-removed',
    class: 'adversarial',
    expectSanitized: false,
    why: 'no sanitizer at all — the flow is genuinely unsanitized',
    code: `app.get('/i', (req, res) => {
  const name = req.query.name;
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'adversarial-wrong-family',
    class: 'adversarial',
    expectSanitized: false,
    why: 'shellEscape neutralizes command injection, not XSS',
    code: `app.get('/i', (req, res) => {
  const name = shellEscape(req.query.name);
  el.insertAdjacentHTML('beforeend', name);
});`,
  },
  {
    id: 'adversarial-sanitizer-not-on-path',
    class: 'adversarial',
    expectSanitized: false,
    why: 'the sanitizer is called but its result is discarded — the sink gets raw input',
    code: `app.get('/i', (req, res) => {
  escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', req.query.name);
});`,
  },
];

async function verdictFor(c, tmpRoot) {
  const dir = path.join(tmpRoot, c.id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'app.js'), c.code);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const xss = (scan.findings || []).filter(
      f => f.parser === 'IR-TAINT' && /CWE-79/.test(f.cwe || ''));
    return { detected: xss.length > 0, sanitized: xss.some(f => f.sanitized === true) };
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-mutation-'));
const rows = [];
let failures = 0;

for (const c of CASES) {
  const v = await verdictFor(c, tmpRoot);
  // Precondition: the finding must fire in every case. A mutation that stops
  // detection entirely is not evidence about sanitization — it is a hole, and
  // silently scoring it as "not sanitized" would let a blind engine pass.
  const detectOk = v.detected;
  const verdictOk = detectOk && v.sanitized === c.expectSanitized;
  if (!verdictOk) failures++;
  rows.push({ ...c, ...v, detectOk, verdictOk });
}

const w = (s, n) => String(s).padEnd(n);
console.log('\nMetamorphic + adversarial mutation gate\n');
console.log(w('case', 38), w('class', 13), w('detected', 10), w('sanitized', 11), w('expected', 10), 'ok');
console.log('-'.repeat(94));
for (const r of rows) {
  console.log(
    w(r.id, 38), w(r.class, 13), w(r.detected, 10),
    w(r.sanitized, 11), w(r.expectSanitized, 10), r.verdictOk ? 'PASS' : 'FAIL');
  if (!r.verdictOk) {
    console.log(`   ${r.detectOk ? 'verdict' : 'DETECTION'} wrong — ${r.why}`);
  }
}

const metamorphic = rows.filter(r => r.class === 'metamorphic');
const adversarial = rows.filter(r => r.class === 'adversarial');
const pct = (list) => list.length
  ? `${list.filter(r => r.verdictOk).length}/${list.length}` : '0/0';
console.log('-'.repeat(94));
console.log(`metamorphic (verdict must HOLD): ${pct(metamorphic)}`);
console.log(`adversarial (verdict must FLIP): ${pct(adversarial)}`);
console.log(`verdict-flip correctness       : ${pct(rows)}`);

fs.rmSync(tmpRoot, { recursive: true, force: true });

if (failures) {
  console.error(`\n✖ ${failures} case(s) wrong. The engine is keying on syntax, not semantics.`);
  process.exit(1);
}
console.log('\n✓ every mutant verdict correct');
