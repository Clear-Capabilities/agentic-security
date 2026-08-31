//
// handling-analyzer.test.js — Milestone 2, Sub-project D, increment 1.
//
// Unit tests for `classifyHandling(path, callGraph)` against hand-built
// paths/callGraphs, one per mapped `HANDLING_VALUES` outcome, plus
// malformed-input safety — mirroring `resolve-destination.test.js`'s own
// hand-built-shape style for a small, single-function increment. The real-
// parsed-code AC-02 proof (masked vs. raw) lives at the bottom of this
// file, reusing the exact fixture shapes already proven in
// `bench/data-lineage/fixtures/js-api-to-log-masked/` and
// `js-api-to-log-raw/`. `validate.js`'s new `HANDLING_VALUES` structural
// check is tested in `test/lineage/validate.test.js`, alongside every
// other per-field validator check, not here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { classifyHandling } from '../../src/lineage/handling-analyzer.js';
import { recognizeTransformation } from '../../src/lineage/transform-catalog.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { HANDLING_VALUES } from '../../src/lineage/schema.js';

// ── hand-built path/callGraph helpers ──────────────────────────────────────

/** `callGraph.functions` is a real `Map<qid, {qid, file, cfg:{nodes}}>` —
 * `ir/callgraph.js#buildCallGraph`'s own shape. */
function mkCallGraph(fnsByQid) {
  const functions = new Map();
  for (const [qid, cfgNodes] of Object.entries(fnsByQid)) {
    functions.set(qid, { qid, file: 'x.js', cfg: { nodes: cfgNodes } });
  }
  return { functions };
}

/** One hop, carrying only the two fields `classifyHandling` reads
 * (`scope`, `siteNodeId`) — every other `Hop` field is irrelevant to this
 * module and deliberately omitted, proving it isn't accidentally read. */
function mkHop(scope, siteNodeId) {
  return { scope, siteNodeId };
}

function mkPath(hops) {
  return { hops };
}

const bareCall = (name, args = []) => ({ kind: 'call', callee: { kind: 'ident', name }, args });
const memberCall = (object, method, args = []) => ({ kind: 'call', callee: { kind: 'member', object: { kind: 'ident', name: object }, prop: method }, args });
/** An `assign`-kind CFG node whose `.source` IS a call — the shape a
 * `const maskedPan = maskCard(cardNumber);` assignment lowers to, and the
 * exact shape the AC-02 fixture's own hop resolves to (§3 item 2 of
 * DESIGN_HANDLING_ANALYZER.md). */
const assignFromCall = (call) => ({ kind: 'assign', target: 'out', source: call });

// ── one test per mapped HANDLING_VALUES outcome ─────────────────────────────

test('D1/1a: mask — naming convention (maskCard), assign-node RHS shape', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('maskCard', [{ kind: 'ident', name: 'pan' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'masked');
  assert.equal(r.recognizedTransform.kind, 'mask');
  assert.equal(r.hopIndex, 0);
});

test('D1/1b: redact — naming convention, bare call-statement CFG node', () => {
  const cg = mkCallGraph({ f: { n1: bareCall('redactSecrets', [{ kind: 'ident', name: 'x' }]) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'redacted');
  assert.equal(r.recognizedTransform.kind, 'redact');
});

test('D1/1c: hash — member-call, library API (crypto.createHash)', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(memberCall('crypto', 'createHash', [{ kind: 'literal', value: 'sha256' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'hashed');
  assert.equal(r.recognizedTransform.kind, 'hash');
});

test('D1/1d: tokenize — naming convention, REVERSIBLE (not a mask)', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('tokenizeCard', [{ kind: 'ident', name: 'pan' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'tokenized');
  assert.equal(r.recognizedTransform.kind, 'tokenize');
  assert.equal(r.recognizedTransform.reversibility, 'reversible');
});

test('D1/1e: encrypt — naming convention', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('encryptCardNumber', [{ kind: 'ident', name: 'pan' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'encrypted');
  assert.equal(r.recognizedTransform.kind, 'encrypt');
});

// ── the five "recognized but not protective" kinds, all -> unknown ─────────

test('D1/2a: decrypt maps to unknown — actively the OPPOSITE of protection immediately before a sink', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('decryptCardNumber', [{ kind: 'ident', name: 'blob' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'decrypt');
});

test('D1/2b: encode maps to unknown — reversible obfuscation, not protection', () => {
  const cg = mkCallGraph({ f: { n1: bareCall('encodeURIComponent', [{ kind: 'ident', name: 'x' }]) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'encode');
});

test('D1/2c: decode maps to unknown', () => {
  const cg = mkCallGraph({ f: { n1: bareCall('decodeURIComponent', [{ kind: 'ident', name: 'x' }]) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'decode');
});

test('D1/2d: truncate maps to unknown — general-purpose shortening, not necessarily a privacy control', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(memberCall('_', 'truncate', [{ kind: 'ident', name: 'x' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'truncate');
});

test('D1/2e: normalize maps to unknown — reversibility itself is unknown at the catalog level', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('normalizeEmail', [{ kind: 'ident', name: 'x' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'normalize');
});

test('D1/2f: aggregate maps to unknown — deferred to D2, never fabricated as "aggregated" from a single hop', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('aggregateByRegion', [{ kind: 'ident', name: 'x' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.handling, 'unknown');
  assert.equal(r.recognizedTransform.kind, 'aggregate');
  // The taxonomy DOES carry 'aggregated' as a value (schema.js) — this
  // module just never emits it in this increment.
  assert.ok(HANDLING_VALUES.includes('aggregated'));
});

// ── raw — the honest empty answer ───────────────────────────────────────────

test('D1/3a: no recognized transform on any hop, and no hops at all — raw', () => {
  const cg = mkCallGraph({ f: { n1: bareCall('logger.info') } });
  const r = classifyHandling(mkPath([]), cg);
  assert.deepEqual(r, { handling: 'raw', recognizedTransform: null, hopIndex: null });
});

test('D1/3b: hops present, but every callee is unrecognized — raw', () => {
  const cg = mkCallGraph({
    f: {
      n1: assignFromCall(bareCall('helper', [{ kind: 'ident', name: 'x' }])),
      n2: bareCall('logger.info', [{ kind: 'ident', name: 'x' }]),
    },
  });
  const r = classifyHandling(mkPath([mkHop('f', 'n1'), mkHop('f', 'n2')]), cg);
  assert.equal(r.handling, 'raw');
  assert.equal(r.recognizedTransform, null);
  assert.equal(r.hopIndex, null);
});

// ── source-to-sink order, first match wins ──────────────────────────────────

test('D1/4a: the match at the LATER hop is found when the earlier hop has none', () => {
  const cg = mkCallGraph({
    f: {
      n1: assignFromCall(bareCall('helper', [{ kind: 'ident', name: 'x' }])),
      n2: assignFromCall(bareCall('maskCard', [{ kind: 'ident', name: 'x' }])),
    },
  });
  const r = classifyHandling(mkPath([mkHop('f', 'n1'), mkHop('f', 'n2')]), cg);
  assert.equal(r.handling, 'masked');
  assert.equal(r.hopIndex, 1);
});

test('D1/4b: the EARLIER hop wins when both hops carry a recognized transform', () => {
  const cg = mkCallGraph({
    f: {
      n1: assignFromCall(bareCall('maskEmail', [{ kind: 'ident', name: 'x' }])),
      n2: assignFromCall(bareCall('maskCard', [{ kind: 'ident', name: 'x' }])),
    },
  });
  const r = classifyHandling(mkPath([mkHop('f', 'n1'), mkHop('f', 'n2')]), cg);
  assert.equal(r.hopIndex, 0);
  assert.equal(r.recognizedTransform.evidence.includes('maskEmail'), true);
});

test('D1/4c: within one hop, multiple calls resolve in expression order — the node\'s own call (bare statement) is checked before nested arg calls', () => {
  // A bare call-statement CFG node whose FIRST argument is itself an
  // unrelated call — the node's own callee (unshifted first, per
  // graph-builder.js's own convention) must win over the argument's call.
  const cg = mkCallGraph({
    f: { n1: bareCall('maskCard', [bareCall('helper', [])]) },
  });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  assert.equal(r.recognizedTransform.kind, 'mask');
});

// ── malformed-input safety — never throws ───────────────────────────────────

test('D1/5: classifyHandling never throws on malformed path/callGraph, always returns the full shape', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('maskCard', [])) } });
  const badPaths = [null, undefined, 42, 'x', [], {}, { hops: null }, { hops: 'nope' }, { hops: [null, undefined, 42, {}] }];
  for (const p of badPaths) {
    const r = classifyHandling(p, cg);
    assert.equal(typeof r, 'object');
    assert.ok(r !== null);
    assert.ok(['raw', 'masked', 'redacted', 'hashed', 'tokenized', 'encrypted', 'aggregated', 'unknown'].includes(r.handling));
    assert.ok('recognizedTransform' in r);
    assert.ok('hopIndex' in r);
  }

  const goodPath = mkPath([mkHop('f', 'n1')]);
  const badCallGraphs = [null, undefined, 42, 'x', [], {}, { functions: null }, { functions: {} }, { functions: 'nope' }];
  for (const bad of badCallGraphs) {
    const r = classifyHandling(goodPath, bad);
    assert.deepEqual(r, { handling: 'raw', recognizedTransform: null, hopIndex: null });
  }
});

test('D1/5b: a hop whose scope/siteNodeId resolves to nothing is skipped, not thrown on', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('maskCard', [])) } });
  const r = classifyHandling(mkPath([
    mkHop('nonexistent-qid', 'n1'),
    mkHop('f', 'nonexistent-node'),
    mkHop(null, null),
    {},
    mkHop('f', 'n1'),
  ]), cg);
  assert.equal(r.handling, 'masked');
  assert.equal(r.hopIndex, 4);
});

test('D1/5c: classifyHandling is deterministic — same input, same output, twice', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(bareCall('maskCard', [])) } });
  const p = mkPath([mkHop('f', 'n1')]);
  assert.deepEqual(classifyHandling(p, cg), classifyHandling(p, cg));
});

// ── recognizedTransform is recognizeTransformation's own decision object, unmodified ──

test('D1/6: recognizedTransform matches a direct recognizeTransformation call on the same descriptor', () => {
  const cg = mkCallGraph({ f: { n1: assignFromCall(memberCall('crypto', 'createHash', [{ kind: 'literal', value: 'sha256' }])) } });
  const r = classifyHandling(mkPath([mkHop('f', 'n1')]), cg);
  const direct = recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createHash' });
  assert.deepEqual(r.recognizedTransform, direct);
});

// ── real-parsed-code AC-02 proof: masked vs. raw ────────────────────────────
//
// Reuses the exact fixture SHAPE already proven in
// bench/data-lineage/fixtures/js-api-to-log-masked/source.js and
// js-api-to-log-raw/source.js (this test does not read those files off
// disk — it inlines the identical source text, so this test suite has no
// dependency on the bench fixture directory's own layout/lifecycle).

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

const MASKED_SOURCE = `
function maskCard(pan) {
  return pan.slice(0, 4) + '********' + pan.slice(-4);
}

function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  const maskedPan = maskCard(cardNumber);
  logger.info('processing payment', { pan: maskedPan });
}
`;

const RAW_SOURCE = `
function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  logger.info('processing payment', { pan: cardNumber });
}
`;

test('D1/7a: AC-02 masked fixture — maskCard() applied before logger.info() yields flow.handling === "masked", validateGraph clean', () => {
  const cg = irOf({ 'a.js': MASKED_SOURCE });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '2026-08-31T00:00:00.000Z' });
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  assert.ok(graph.flows.length > 0, 'at least one flow must reach the log sink');
  assert.ok(graph.flows.every((f) => f.handling === 'masked'), `every flow on the masked fixture must be "masked", got ${JSON.stringify(graph.flows.map((f) => f.handling))}`);
});

test('D1/7b: AC-02 raw fixture — card_number reaches logger.info() with no transform, yields flow.handling === "raw", validateGraph clean', () => {
  const cg = irOf({ 'a.js': RAW_SOURCE });
  const { graph } = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '2026-08-31T00:00:00.000Z' });
  const v = validateGraph(graph);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  assert.equal(graph.flows.length, 1);
  assert.equal(graph.flows[0].handling, 'raw');
});
