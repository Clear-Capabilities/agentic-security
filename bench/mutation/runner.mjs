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

// ── Case shape ───────────────────────────────────────────────────────────────
// Every case declares which DIMENSION of the verdict it is measuring, because
// the two bug classes this harness has had to catch are different kinds of
// wrong:
//
//   dimension: 'sanitization'  (default) — the finding must FIRE in every case
//              and the question is whether the engine calls it `sanitized`.
//              `expectSanitized` is the answer. This is the original family
//              (family-aware sanitizer gating); its CWE is XSS.
//
//   dimension: 'detection'     — the question is whether the finding fires AT
//              ALL. `expectDetected` is the answer. Needed for the receiver-
//              type gate (PRD R6), which can only ever be wrong by suppressing
//              or by failing to suppress — there is no sanitizer in the flow to
//              have an opinion about.
//
// `cwe` selects which findings the case looks at (default: XSS).
const DEFAULT_CWE = /CWE-79/;

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

  // ── PRD R6: the CHA-inferred receiver-type gate on catalog sink matching ───
  // This gate decides whether a bare `.query()` is a SQL sink by consulting the
  // receiver's resolved class. It shipped three times with the same defect: a
  // NAME or SHAPE guess ("the field is called `dbConn`, so its class must be
  // `DbConn`"; "the chain root is `svc`, so ask about `svc`") being trusted as
  // a confident type resolution, which then SUPPRESSED real SQL injections
  // whose receiver name happened to fall outside a fixed vocabulary. A corpus
  // fixture cannot catch that class of bug — the fixtures were themselves
  // named to match the vocabulary. A metamorphic rename can, and does: every
  // case below FAILS on the pre-fix engine.
  {
    id: 'r6-baseline-local',
    class: 'baseline',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'tainted input reaching .query() on a local DB object is SQL injection',
    code: `class Db {
  query(sql) { return sql; }
}
app.get('/s', (req, res) => {
  const d = new Db();
  d.query(req.query.q);
});`,
  },
  {
    id: 'metamorphic-receiver-class-rename',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'renaming `class Db` to `class DatabaseConnection` is the same program — a receiver-type allow-list that only matches the short name is keyed on spelling, not on meaning',
    code: `class DatabaseConnection {
  query(sql) { return sql; }
}
app.get('/s', (req, res) => {
  const d = new DatabaseConnection();
  d.query(req.query.q);
});`,
  },
  {
    id: 'r6-baseline-field',
    class: 'baseline',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'the same SQL injection reached through a `this.<field>` receiver',
    code: `class Repo {
  constructor() { this.db = makeConn(); }
  find(req) { return this.db.query(req.query.q); }
}
app.get('/s', (req, res) => { new Repo().find(req); });`,
  },
  {
    id: 'metamorphic-receiver-field-rename',
    class: 'metamorphic',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: true,
    why: 'renaming the field `this.db` to `this.dbConn` is the same program — a gate that guesses the receiver type from the field name loses the finding on any name outside its vocabulary',
    code: `class Repo {
  constructor() { this.dbConn = makeConn(); }
  find(req) { return this.dbConn.query(req.query.q); }
}
app.get('/s', (req, res) => { new Repo().find(req); });`,
  },
  {
    id: 'adversarial-non-db-receiver',
    class: 'adversarial',
    dimension: 'detection',
    cwe: /CWE-89/,
    expectDetected: false,
    why: 'a `.query()` on a confidently-typed cache is not a SQL sink — this is the false positive the receiver-type gate exists to remove, and it is what stops "delete the gate" from passing the two metamorphic cases above',
    code: `class Cache {
  query(key) { return key; }
}
app.get('/s', (req, res) => {
  const c = new Cache();
  c.query(req.query.q);
});`,
  },
  // ── Go concurrency guard (PRD F12.5) ──────────────────────────────────────
  //
  // Encodes the defect fixed in a5ecb3b: the lock guard matched a BARE receiver
  // (`defer mu.Unlock()`) but not a QUALIFIED one (`defer s.mu.Unlock()`), which
  // is how a mutex held as a struct field is always written. 62% of this
  // detector's findings on real Go were false positives against correct code.
  //
  // These belong in the mutation gate rather than only in a unit test because
  // the failure was a NEAR-MISS discrimination failure — exactly what this gate
  // scores. A rule that starts flagging correct code again fails here even if
  // its unit tests are edited to match the new behaviour.
  {
    id: 'go-concurrency-bare-defer',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: false,
    why: 'a bare `defer mu.Unlock()` releases on every path — no finding',
    code: `func Get(k string) string {
	mu.Lock()
	defer mu.Unlock()
	return d[k]
}`,
  },
  {
    id: 'go-concurrency-qualified-defer',
    class: 'metamorphic',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: false,
    why: 'moving the mutex onto a struct field is the same program — still guarded',
    code: `func (s *Store) Get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[k]
}`,
  },
  {
    id: 'go-concurrency-adversarial-other-lock',
    class: 'adversarial',
    dimension: 'detection',
    file: 'svc.go',
    parser: /^CONCURRENCY$/,
    cwe: /CWE-667/,
    expectDetected: true,
    why: 'the defer releases a DIFFERENT lock, so this one can leak — verdict must flip',
    code: `func (s *Store) Move(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.other.Lock()
	if k == "" {
		return errEmpty
	}
	s.other.Unlock()
	return nil
}`,
  },
];

async function verdictFor(c, tmpRoot) {
  const dir = path.join(tmpRoot, c.id);
  fs.mkdirSync(dir, { recursive: true });
  // The filename was hardcoded to app.js, so this gate — the anti-overfitting
  // control — could only ever cover JavaScript. Measured on the CVE corpus, 204
  // of 280 findings are NOT JavaScript, so the check with the broadest mandate
  // had the narrowest reach. A case may now name its own file; JS stays the
  // default so every existing case is unchanged.
  fs.writeFileSync(path.join(dir, c.file || 'app.js'), c.code);
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

for (const c of CASES) {
  const v = await verdictFor(c, tmpRoot);
  let detectOk, verdictOk, expected;
  if (c.dimension === 'detection') {
    // The detection dimension IS the verdict here — a case may legitimately
    // expect no finding (the adversarial non-DB receiver), so "did it fire"
    // cannot also serve as a precondition.
    expected = c.expectDetected;
    detectOk = true;
    verdictOk = v.detected === c.expectDetected;
  } else {
    // Precondition: the finding must fire in every case. A mutation that stops
    // detection entirely is not evidence about sanitization — it is a hole, and
    // silently scoring it as "not sanitized" would let a blind engine pass.
    expected = c.expectSanitized;
    detectOk = v.detected;
    verdictOk = detectOk && v.sanitized === c.expectSanitized;
  }
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
    console.log(`   ${r.detectOk ? 'verdict' : 'DETECTION'} wrong — ${r.why}`);
  }
}

const metamorphic = rows.filter(r => r.class === 'metamorphic');
const adversarial = rows.filter(r => r.class === 'adversarial');
const pct = (list) => list.length
  ? `${list.filter(r => r.verdictOk).length}/${list.length}` : '0/0';
console.log('-'.repeat(108));
console.log(`metamorphic (verdict must HOLD): ${pct(metamorphic)}`);
console.log(`adversarial (verdict must FLIP): ${pct(adversarial)}`);
// Deliberately excludes the untagged 'baseline' sanity-check case: this line
// reports verdict-FLIP correctness specifically, and baseline is neither a
// metamorphic nor an adversarial mutant. Computing it over `rows` (all cases,
// including baseline) made the printed total disagree with metamorphic+
// adversarial's own sum (3+3=6 vs. a reported denominator of 7) — any
// baseline-only regression showed up as an unexplained "missing" case in this
// summary line with no attribution. `failures` below still covers every row,
// baseline included, so this is a reporting fix, not a gate-strength change.
console.log(`verdict-flip correctness       : ${pct([...metamorphic, ...adversarial])}`);

fs.rmSync(tmpRoot, { recursive: true, force: true });

if (failures) {
  console.error(`\n✖ ${failures} case(s) wrong. The engine is keying on syntax, not semantics.`);
  process.exit(1);
}
console.log('\n✓ every mutant verdict correct');
