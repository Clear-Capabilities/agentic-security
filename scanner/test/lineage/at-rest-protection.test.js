//
// at-rest-protection.test.js — Milestone 2, Sub-project C, increment 1.
//
// Proves `edge.protection.atRest` for the application-layer evidence
// source: `flow.handling === 'encrypted'` (Milestone 2, Sub-project D,
// increment 1's own `classifyHandling`) wired to a `store`-kind sink, per
// `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-c1-plan.md`
// and the short new §7 in `DESIGN_HANDLING_ANALYZER.md`. This is a
// consistency/wiring proof over `graph-builder.js`, not a new detector —
// the underlying transform recognition is already proven exhaustively by
// `transform-catalog.test.js` and `handling-analyzer.test.js`; this file's
// own job is narrower: prove the SAME `classifyHandling` result that lands
// on `flow.handling` also lands on `edge.protection.atRest`, gated to
// `snk.kind === 'store'`, and prove the FR-402 anti-pattern guard holds on
// real parsed code, not just architecturally.
//
// Every case here runs real parsed JS/TS through the real pipeline
// (`buildGraphWithCoverage`), mirroring `handling-analyzer.test.js`'s own
// AC-02 real-code proof style (`D1/7a`/`D1/7b`) — this increment writes no
// hand-built-path/callGraph unit tests of its own, since the logic under
// test is a five-line in-loop mutation with no interesting internal shape
// to probe in isolation; the interesting property is end-to-end behavior
// on real code, which only the real pipeline can prove.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { HANDLING_VALUES } from '../../src/lineage/schema.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

/** Builds the graph for one inline source file and returns
 * `{graph, flows, edgeFor}` — `edgeFor(flow)` looks up the flow's own
 * (single, in every fixture here) edge by `flow.edgeIds[0]`, and asserts
 * `validateGraph()` is clean before returning anything, so every case
 * below gets that proof for free rather than repeating it per test. */
function build(source) {
  const cg = irOf({ 'a.js': source });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '2026-08-31T00:00:00.000Z' });
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  const edgeFor = (flow) => {
    const e = graph.edges.find((x) => x.id === flow.edgeIds[0]);
    assert.ok(e, `edge ${flow.edgeIds[0]} referenced by flow ${flow.id} must exist`);
    return e;
  };
  const nodeFor = (id) => {
    const n = graph.nodes.find((x) => x.id === id);
    assert.ok(n, `node ${id} must exist`);
    return n;
  };
  return { graph, edgeFor, nodeFor };
}

const DEFAULT_AT_REST = { verdict: 'not_assessed', evidenceGrade: 'none' };

// ── 1. The positive case: crypto.createCipheriv() on the path to a real
// database-write sink (js-sql-query's own receiver shape, `db.query(...)`)
// yields BOTH flow.handling === 'encrypted' AND edge.protection.atRest ===
// {verdict: 'protected', evidenceGrade: 'code'}, from the ONE classifyHandling
// call — proving the two fields are consistent, not two divergent
// computations. `crypto.createCipheriv` is copied verbatim from
// transform-catalog.js's own `js-node-cipheriv` entry's `examples[]`. ────────

test('C1/1: encrypt-then-store — flow.handling and edge.protection.atRest agree, both derived from one classifyHandling call', () => {
  const { graph, edgeFor, nodeFor } = build(`
    function handleCheckout(req, db) {
      const cardNumber = req.body.card_number;
      const encryptedPan = crypto.createCipheriv('aes-256-gcm', key, iv).update(cardNumber);
      db.query('INSERT INTO cards (pan) VALUES (?)', [encryptedPan]);
    }
  `);
  assert.equal(graph.flows.length, 1, 'exactly one flow: card_number -> the database store');
  const flow = graph.flows[0];
  assert.equal(flow.handling, 'encrypted');
  const sink = nodeFor(flow.sink);
  assert.equal(sink.kind, 'store');
  const edge = edgeFor(flow);
  assert.deepEqual(edge.protection.atRest, { verdict: 'protected', evidenceGrade: 'code' });
  // .transit/.handling are untouched by this increment — still the default.
  assert.deepEqual(edge.protection.transit, DEFAULT_AT_REST);
  assert.deepEqual(edge.protection.handling, DEFAULT_AT_REST);
});

// ── 2. The negative case — no encryption: a bare, unencrypted write to the
// same store sink stays the honest default. ─────────────────────────────────

test('C1/2: no recognized transform, bare write to a store sink — atRest stays the default', () => {
  const { graph, edgeFor, nodeFor } = build(`
    function handleCheckout(req, db) {
      const cardNumber = req.body.card_number;
      db.query('INSERT INTO cards (pan) VALUES (?)', [cardNumber]);
    }
  `);
  assert.equal(graph.flows.length, 1);
  const flow = graph.flows[0];
  assert.equal(flow.handling, 'raw');
  assert.equal(nodeFor(flow.sink).kind, 'store');
  assert.deepEqual(edgeFor(flow).protection.atRest, DEFAULT_AT_REST);
});

// ── 3. The anti-pattern-guard proof — AC-06/FR-402's own core property,
// and this increment's single most important test: an encrypt-recognized
// call is present in the SAME FILE/FUNCTION, but on an UNRELATED local
// variable that is never written to the store — the store-write edge's own
// atRest MUST stay the default. `classifyHandling` walks only the flow's
// OWN reconstructed path (source-field -> this exact sink), so the
// unrelated encrypt() call is structurally invisible to it — proving
// FR-402's "a cipher present anywhere in the same file/repository cannot
// alone establish protection for an unrelated store" live, not just
// architecturally implied. ───────────────────────────────────────────────────

test('C1/3: anti-pattern guard — an unrelated encrypt() call in the same function does NOT protect a different, unencrypted write to the store', () => {
  const { graph, edgeFor, nodeFor } = build(`
    function handleCheckout(req, db, logger) {
      const cardNumber = req.body.card_number;
      const other = req.body.other_field;
      const encryptedOther = crypto.createCipheriv('aes-256-gcm', key, iv).update(other);
      logger.info('audit', { other: encryptedOther });
      db.query('INSERT INTO cards (pan) VALUES (?)', [cardNumber]);
    }
  `);
  // Two flows: card_number (raw) -> the store, and other_field (encrypted)
  // -> the log sink. Neither is the "encrypted field written to the
  // store" shape — confirm the STORE-bound flow specifically stays default.
  const storeFlow = graph.flows.find((f) => nodeFor(f.sink).kind === 'store');
  assert.ok(storeFlow, 'a flow reaching the store must exist');
  assert.equal(storeFlow.handling, 'raw', 'the field actually written to the store was never encrypted');
  assert.deepEqual(edgeFor(storeFlow).protection.atRest, DEFAULT_AT_REST);

  // The OTHER flow (to the log sink) is genuinely 'encrypted' — proving
  // this fixture really does contain a recognized encrypt call, not that
  // classifyHandling silently failed to recognize it at all.
  const logFlow = graph.flows.find((f) => nodeFor(f.sink).kind === 'log');
  assert.ok(logFlow, 'a flow reaching the log sink must exist');
  assert.equal(logFlow.handling, 'encrypted');
  // Even though logFlow IS encrypted, its own sink is not a store, so its
  // own edge also stays default (belt-and-suspenders with case 4 below).
  assert.deepEqual(edgeFor(logFlow).protection.atRest, DEFAULT_AT_REST);
});

// ── 4. A non-store-kind sink reached by an encrypt-shaped flow — the
// snk.kind === 'store' filter itself, isolated from the anti-pattern-guard
// case above (which also exercises it, but incidentally). ──────────────────

test('C1/4: encrypted flow to a non-store sink (log) — atRest stays the default', () => {
  const { graph, edgeFor, nodeFor } = build(`
    function handleCheckout(req, logger) {
      const cardNumber = req.body.card_number;
      const encryptedPan = crypto.createCipheriv('aes-256-gcm', key, iv).update(cardNumber);
      logger.info('processing payment', { pan: encryptedPan });
    }
  `);
  assert.equal(graph.flows.length, 1);
  const flow = graph.flows[0];
  assert.equal(flow.handling, 'encrypted');
  assert.equal(nodeFor(flow.sink).kind, 'log');
  assert.deepEqual(edgeFor(flow).protection.atRest, DEFAULT_AT_REST);
});

// ── 5. Every OTHER HANDLING_VALUES member on a store sink stays default —
// proving only 'encrypted' triggers this increment's own logic, not a
// broader "any recognized transform" rule. `masked`/`redacted`/`hashed`/
// `tokenized`/`raw` are each independently reachable through
// classifyHandling on real parsed code (proven per-kind already by
// handling-analyzer.test.js's own D1/1*-D1/2* battery); `unknown` is
// reached here via `decryptCardNumber` (one of the five KIND_TO_HANDLING
// rows that map to 'unknown' — decrypt is the most security-relevant to
// exercise here, since it is the ACTIVE OPPOSITE of protection immediately
// before a sink, per handling-analyzer.test.js's own D1/2a comment). ───────

const otherHandlingCases = [
  { label: 'masked', call: 'maskCard(cardNumber)', want: 'masked' },
  { label: 'redacted', call: 'redactSecrets(cardNumber)', want: 'redacted' },
  { label: 'hashed', call: "crypto.createHash('sha256').update(cardNumber)", want: 'hashed' },
  { label: 'tokenized', call: 'tokenizeCard(cardNumber)', want: 'tokenized' },
  { label: 'unknown (decrypt)', call: 'decryptCardNumber(cardNumber)', want: 'unknown' },
  { label: 'raw (covered again here for completeness of the HANDLING_VALUES sweep)', call: null, want: 'raw' },
];

for (const c of otherHandlingCases) {
  test(`C1/5: handling === '${c.want}' (${c.label}) on a store sink — atRest stays the default`, () => {
    const body = c.call
      ? `const transformedPan = ${c.call};\n      db.query('INSERT INTO cards (pan) VALUES (?)', [transformedPan]);`
      : `db.query('INSERT INTO cards (pan) VALUES (?)', [cardNumber]);`;
    const { graph, edgeFor, nodeFor } = build(`
      function handleCheckout(req, db) {
        const cardNumber = req.body.card_number;
        ${body}
      }
    `);
    assert.equal(graph.flows.length, 1);
    const flow = graph.flows[0];
    assert.equal(flow.handling, c.want);
    assert.equal(nodeFor(flow.sink).kind, 'store');
    assert.deepEqual(edgeFor(flow).protection.atRest, DEFAULT_AT_REST);
  });
}

// `HANDLING_VALUES` has one member neither this file nor any real
// classifyHandling call can ever reach: 'aggregated'. `KIND_TO_HANDLING`
// (handling-analyzer.js) maps the transform-catalog `aggregate` kind to
// the honest `'unknown'`, not `'aggregated'` — pinned directly by
// handling-analyzer.test.js's own `D1/2f` ("deferred to D2, never
// fabricated as 'aggregated' from a single hop"). Since this increment's
// own gate (`handlingResult === 'encrypted'`) can only ever be compared
// against a REAL classifyHandling output, and that output can never be
// `'aggregated'`, there is no real-code fixture that could exercise
// "atRest stays default when handling === 'aggregated'" — asserting it
// here would require fabricating a `flow.handling` value the shipped
// pipeline itself can never produce, which this file will not do. This is
// disclosed, not silently skipped: the sweep above covers every
// REACHABLE non-'encrypted' HANDLING_VALUES member (6 of 7); 'aggregated'
// is the one unreachable-by-construction member, and the sentence above
// is its recorded, tested reason (via the cross-referenced D1/2f pin).
test('C1/6: HANDLING_VALUES accounting — every member is either exercised above or documented as unreachable from classifyHandling', () => {
  const exercisedOrEncrypted = new Set(['encrypted', 'raw', 'masked', 'redacted', 'hashed', 'tokenized', 'unknown']);
  const documentedUnreachable = new Set(['aggregated']);
  assert.deepEqual(
    new Set(HANDLING_VALUES),
    new Set([...exercisedOrEncrypted, ...documentedUnreachable]),
    'HANDLING_VALUES drifted — update this test\'s accounting (and the comment above) to match',
  );
});
