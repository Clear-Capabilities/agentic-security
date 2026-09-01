#!/usr/bin/env node
//
// bench/protection-verdict/runner.mjs — Milestone 2, Sub-project H,
// increment 1 ("false-protected release gate for transit/atRest").
//
// WHY THIS EXISTS. Decision 2 (Data Flow Explorer PRD §14) defines a
// release gate: does the engine's own `protected` verdict on
// `edge.protection.transit` / `edge.protection.atRest` track real
// evidence? The score is the FALSE-PROTECTED RATE among the engine's own
// `protected` claims — not detection count, and not a shape match against
// a fixed corpus.
//
// Mirrors bench/mutation/runner.mjs's own scoring mechanism EXACTLY, per
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-h1-plan.md's
// re-verified (not first-guessed) description of it: there is NO explicit
// base/mutant pairing at runtime. Every CASE in the array below is scored
// INDEPENDENTLY against its own `expectVerdict`. "Pairing" exists only by
// CONVENTION — a `class: 'baseline'`/`'metamorphic'` case shares an `id`
// prefix with its `class: 'adversarial'` sibling(s), for a human reading
// the table, never for this runner's own scoring loop.
//
//   BASELINE/METAMORPHIC — a real fixture the engine correctly marks
//                  `protected`, and a semantics-preserving rewrite of it
//                  (rename a variable, reformat a call/object literal).
//                  The verdict must NOT move off `protected`.
//
//   ADVERSARIAL    — a semantics-CHANGING near-miss: `http://` instead of
//                  `https://`; TLS verification disabled nearby; no
//                  encryption at all before a store write; an encrypt call
//                  present in the same function but NOT on the path to the
//                  store write (FR-402's own anti-pattern guard, already
//                  proven live by test/lineage/at-rest-protection.test.js's
//                  own C1/3 case — mirrored here as this corpus's single
//                  most important case). The verdict must NOT read
//                  `protected` — reading it here is a FALSE-PROTECTED
//                  defect, exactly what this gate exists to catch.
//
// SCOPE: `transit` and `atRest` only, per
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-h-scoping.md
// — `edge.protection.handling` has NO real producer anywhere in this
// codebase today (`emptyProtection()` leaves it permanently
// `not_assessed`/`none`; `flow.handling` is a separate field, separate
// vocabulary). That scoping doc names two honest options for a future
// increment and resolves neither here; this corpus does not attempt it.
//
// EVIDENCE-GRADE OVERSTATEMENT (Decision 2's second numerator clause —
// a `protected` verdict whose `evidenceGrade` claims more than the real
// evidence supports, e.g. a `declared`-only assertion rendering as
// `code`/`code_and_config` strength) is DELIBERATELY NOT exercised by this
// corpus. Confirmed directly against the current code before writing a
// single case (not assumed from the plan's own citation of it):
// `resolveTransitProtectionForSite` (src/lineage/transit-protection.js)
// and the inline atRest block (src/lineage/graph-builder.js, search
// `edge.protection.atRest`) both ONLY EVER emit `evidenceGrade: 'code'`
// on a `protected` verdict — grep confirms neither file contains a
// `'declared'`/`'config'`/`'code_and_config'` literal anywhere near either
// producer. There is no real producer today that could even ATTEMPT to
// overstate its evidence grade on a `protected` transit/atRest verdict, so
// this half of the gate has the same permanently-zero-denominator problem
// the scoping doc found for `handling` — inventing a synthetic producer to
// test against would test a producer that does not exist, not this
// engine. Skipped here, exactly as that gap was disclosed rather than
// silently worked around; `expectEvidenceGrade` below is asserted only as
// a same-call-site consistency check on the REAL `'code'` grade every
// producer emits today, never as an overstatement probe.
//
// Each case builds a real DataFlowGraph v1 document from real parsed
// source — parseJsFile -> buildCallGraph -> buildGraphWithCoverage, the
// SAME pipeline bench/data-lineage/runner.mjs and
// test/lineage/{transit,at-rest}-protection.test.js already use (in-memory
// only; no temp directory, no runScan — this corpus needs the lineage
// pipeline directly, not a full SAST scan, so it is faster and simpler
// than bench/mutation/runner.mjs's disk-based approach) — and reads
// `edge.protection[dimension]` off the edge whose DESTINATION NODE KIND
// matches the dimension (`'external'` for transit, `'store'` for atRest,
// per sink-registry.js's own `CATEGORY_NODE_KIND` table). This selector is
// what makes the anti-pattern case work with no special-case code: a
// fixture with two flows (one encrypted-but-irrelevant to a log sink, one
// raw to a store sink) produces two edges, and the selector picks the
// STORE one — mirroring at-rest-protection.test.js's own C1/3 assertion
// exactly (`edgeFor(storeFlow).protection.atRest` must stay the default).

import { parseJsFile } from '../../scanner/src/ir/parser-js.js';
import { buildCallGraph } from '../../scanner/src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../scanner/src/lineage/coverage.js';
import { scanTransitEvidence } from '../../scanner/src/lineage/transit-protection.js';

// The destination-node KIND a case's own dimension is scored against —
// see the header comment above for why this is what selects "the edge
// this case is about" with no per-case selector function needed.
const NODE_KIND_FOR_DIMENSION = { transit: 'external', atRest: 'store' };

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// ── Case shape ───────────────────────────────────────────────────────────────
// {id, class: 'baseline'|'metamorphic'|'adversarial', dimension: 'transit'|
//  'atRest', expectVerdict: 'protected'|'unprotected'|'unknown'|
//  'not_assessed', expectEvidenceGrade (optional), file (default 'a.js'),
//  why, code}
const CASES = [
  // ── transit: a real fetch() call to a literal https:// destination ───────
  {
    id: 'transit-baseline-https',
    class: 'baseline',
    dimension: 'transit',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'a literal https:// destination with no nearby TLS-disable finding is real transit-protection evidence (AC-03)',
    code: `
function h(req) {
  const cardNumber = req.body.card_number;
  fetch("https://payments.example/charge", { method: 'POST', body: cardNumber });
}
`,
  },
  {
    id: 'transit-metamorphic-rename',
    class: 'metamorphic',
    dimension: 'transit',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'renaming the function/params/local changes nothing about the destination scheme',
    code: `
function handlePayment(request) {
  const pan = request.body.card_number;
  fetch("https://payments.example/charge", { method: 'POST', body: pan });
}
`,
  },
  {
    id: 'transit-metamorphic-reformat',
    class: 'metamorphic',
    dimension: 'transit',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'reformatting the call across multiple lines/spacing is the same program',
    code: `
function h( req ) {
  const cardNumber = req.body.card_number;
  fetch(
    "https://payments.example/charge",
    { method: 'POST', body: cardNumber }
  );
}
`,
  },
  {
    id: 'adversarial-transit-http-scheme',
    class: 'adversarial',
    dimension: 'transit',
    expectVerdict: 'unprotected',
    why: 'a literal http:// destination is unprotected transit by construction (AC-03) — the scheme alone is the evidence',
    code: `
function h(req) {
  const cardNumber = req.body.card_number;
  fetch("http://payments.example/charge", { method: 'POST', body: cardNumber });
}
`,
  },
  {
    id: 'adversarial-transit-tls-verify-disabled',
    class: 'adversarial',
    dimension: 'transit',
    expectVerdict: 'unprotected',
    why: 'a nearby rejectUnauthorized:false finding overrides a literal https:// scheme — the scheme alone must never win (AC-04, the core property this dimension exists to check)',
    code: `
function h(req) {
  const cardNumber = req.body.card_number;
  fetch("https://payments.example/charge", { method: 'POST', body: cardNumber, rejectUnauthorized: false });
}
`,
  },

  // ── atRest: a real recognized encrypt call directly on the path to a
  // store write ─────────────────────────────────────────────────────────────
  {
    id: 'atrest-baseline-encrypt-then-store',
    class: 'baseline',
    dimension: 'atRest',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'crypto.createCipheriv() directly on the path to a store-kind sink write is real at-rest evidence (FR-402); callee copied verbatim from transform-catalog.js\'s own js-node-cipheriv examples[]',
    code: `
function handleCheckout(req, db) {
  const cardNumber = req.body.card_number;
  const encryptedPan = crypto.createCipheriv('aes-256-gcm', key, iv).update(cardNumber);
  db.query('INSERT INTO cards (pan) VALUES (?)', [encryptedPan]);
}
`,
  },
  {
    id: 'atrest-metamorphic-rename',
    class: 'metamorphic',
    dimension: 'atRest',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'renaming the function/params/locals changes nothing about the encrypt-then-store flow',
    code: `
function processOrder(request, database) {
  const pan = request.body.card_number;
  const cipherText = crypto.createCipheriv('aes-256-gcm', secretKey, initVector).update(pan);
  database.query('INSERT INTO cards (pan) VALUES (?)', [cipherText]);
}
`,
  },
  {
    id: 'atrest-metamorphic-reformat',
    class: 'metamorphic',
    dimension: 'atRest',
    expectVerdict: 'protected',
    expectEvidenceGrade: 'code',
    why: 'reformatting the chained call and the query call across multiple lines is the same program',
    code: `
function handleCheckout(req, db) {
  const cardNumber = req.body.card_number;
  const encryptedPan = crypto
    .createCipheriv('aes-256-gcm', key, iv)
    .update(cardNumber);
  db.query(
    'INSERT INTO cards (pan) VALUES (?)',
    [encryptedPan]
  );
}
`,
  },
  {
    id: 'adversarial-atrest-no-encryption',
    class: 'adversarial',
    dimension: 'atRest',
    expectVerdict: 'not_assessed',
    why: 'a bare write to a store sink with no recognized encrypt call anywhere on the path must stay the honest not_assessed default, never protected',
    code: `
function handleCheckout(req, db) {
  const cardNumber = req.body.card_number;
  db.query('INSERT INTO cards (pan) VALUES (?)', [cardNumber]);
}
`,
  },
  {
    id: 'adversarial-atrest-encrypt-not-on-path',
    class: 'adversarial',
    dimension: 'atRest',
    expectVerdict: 'not_assessed',
    why: 'FR-402\'s own anti-pattern guard, mirroring at-rest-protection.test.js\'s C1/3 exactly: an encrypt() call present in the SAME function but on a DIFFERENT field\'s path to a DIFFERENT (log) sink must not protect the unrelated, unencrypted write to the store — a cipher present anywhere in the same file/function cannot alone establish protection',
    code: `
function handleCheckout(req, db, logger) {
  const cardNumber = req.body.card_number;
  const other = req.body.other_field;
  const encryptedOther = crypto.createCipheriv('aes-256-gcm', key, iv).update(other);
  logger.info('audit', { other: encryptedOther });
  db.query('INSERT INTO cards (pan) VALUES (?)', [cardNumber]);
}
`,
  },
];

/**
 * Builds a real DataFlowGraph v1 document for one case and returns the
 * verdict/evidenceGrade read off the edge whose destination node kind
 * matches the case's own dimension, plus a count of how many such edges
 * existed (every case here is written to produce exactly one — a count
 * other than 1 is surfaced in the table rather than silently resolved by
 * picking the first).
 */
function verdictFor(c) {
  const file = c.file || 'a.js';
  const files = { [file]: c.code };
  const cg = irOf(files);
  const opts = { repository: 'protection-verdict' };
  if (c.dimension === 'transit') opts.transitEvidenceByFile = scanTransitEvidence(files);
  const { graph } = buildGraphWithCoverage(cg, opts);
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const wantKind = NODE_KIND_FOR_DIMENSION[c.dimension];
  const candidates = graph.edges.filter((e) => nodesById.get(e.to)?.kind === wantKind);
  if (candidates.length === 0) {
    return { verdict: 'no-matching-edge', evidenceGrade: null, edgeCount: 0 };
  }
  const edge = candidates[0];
  const p = edge.protection[c.dimension];
  return { verdict: p?.verdict, evidenceGrade: p?.evidenceGrade, edgeCount: candidates.length };
}

const rows = [];
let failures = 0;

for (const c of CASES) {
  const v = verdictFor(c);
  const verdictOk = v.verdict === c.expectVerdict;
  const gradeOk = c.expectEvidenceGrade === undefined || v.evidenceGrade === c.expectEvidenceGrade;
  const ok = verdictOk && gradeOk && v.edgeCount === 1;
  if (!ok) failures++;
  rows.push({ ...c, ...v, ok, verdictOk, gradeOk });
}

const w = (s, n) => String(s).padEnd(n);
console.log('\nFalse-protected release gate — transit/atRest protection verdicts\n');
console.log(w('case', 42), w('class', 13), w('dimension', 10), w('actual', 20), w('expected', 20), 'ok');
console.log('-'.repeat(112));
for (const r of rows) {
  console.log(
    w(r.id, 42), w(r.class, 13), w(r.dimension, 10), w(r.verdict, 20), w(r.expectVerdict, 20),
    r.ok ? 'PASS' : 'FAIL');
  if (!r.ok) {
    if (!r.verdictOk) console.log(`   verdict wrong — ${r.why}`);
    if (r.verdictOk && !r.gradeOk) console.log(`   evidenceGrade wrong (got ${r.evidenceGrade}, expected ${r.expectEvidenceGrade}) — ${r.why}`);
    if (r.edgeCount !== 1) console.log(`   expected exactly 1 edge of kind '${NODE_KIND_FOR_DIMENSION[r.dimension]}', found ${r.edgeCount} — the fixture is not minimal/unambiguous`);
  }
}

const metamorphic = rows.filter((r) => r.class === 'metamorphic');
const adversarial = rows.filter((r) => r.class === 'adversarial');
const pct = (list) => (list.length ? `${list.filter((r) => r.ok).length}/${list.length}` : '0/0');
console.log('-'.repeat(112));
console.log(`metamorphic (verdict must HOLD at protected)   : ${pct(metamorphic)}`);
console.log(`adversarial (verdict must NOT read protected)  : ${pct(adversarial)}`);
// Deliberately excludes the baseline cases, mirroring bench/mutation/
// runner.mjs's own reporting-line precedent — baseline is neither a
// metamorphic nor an adversarial mutant. `failures` below still covers
// every row, baseline included.
console.log(`verdict-flip correctness (transit)              : ${pct(rows.filter((r) => r.dimension === 'transit' && r.class !== 'baseline'))}`);
console.log(`verdict-flip correctness (atRest)                : ${pct(rows.filter((r) => r.dimension === 'atRest' && r.class !== 'baseline'))}`);

if (failures) {
  console.error(`\n✖ ${failures} case(s) wrong. A 'protected' verdict is not tracking real evidence.`);
  process.exit(1);
}
console.log('\n✓ every transit/atRest protection verdict correct — no false-protected cases found');
