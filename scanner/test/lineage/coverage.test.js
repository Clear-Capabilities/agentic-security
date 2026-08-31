import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildDataFlowGraph, enumerateSinkSites } from '../../src/lineage/graph-builder.js';
import {
  detectUnresolvedDestination, renderExpr, resolveSiteDecision,
  buildCoverageLedger, buildGraphWithCoverage,
} from '../../src/lineage/coverage.js';
import { DEFAULTS } from '../../src/lineage/path-query.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// ── detectUnresolvedDestination / renderExpr ──

test('C1/1a: a computed receiver (not a plain ident) is detected as unresolved', () => {
  const cg = irOf({ 'a.js': "function h(getClient, x){ getClient(process.env.ENV).charge(x); }" });
  const { sites } = enumerateSinkSites(cg);
  // no catalog entry matches this made-up callee — build a synthetic site
  // instead, the same "no real fixture reaches this shape" fallback D5
  // established for its own under-reached categories.
  const site = { calleeExpr: { kind: 'member', object: { kind: 'call', callee: { kind: 'ident', name: 'getClient' }, args: [] }, prop: 'charge' }, args: [{ kind: 'ident', name: 'x' }] };
  const r = detectUnresolvedDestination(site);
  assert.ok(r);
  assert.match(r.blockingExpression, /computed expression/);
});

test('C1/1b: a plain-ident receiver with a literal first argument is resolved (no override)', () => {
  const site = { calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'res' }, prop: 'send' }, args: [{ kind: 'literal', value: 'ok' }] };
  assert.equal(detectUnresolvedDestination(site), null);
});

test('C1/1c: a plain-ident receiver with a NON-literal first argument is detected as unresolved (the fetch(url) case)', () => {
  const site = { calleeExpr: { kind: 'ident', name: 'fetch' }, args: [{ kind: 'ident', name: 'url' }] };
  const r = detectUnresolvedDestination(site);
  assert.ok(r);
  assert.equal(r.blockingExpression, 'url');
});

test('C1/1d: a string (non-JS-parser) callee shape is never claimed unresolved on the receiver check — only the argument check can fire for it', () => {
  const site = { calleeExpr: 'pan.slice', args: [{ kind: 'literal', value: 0 }] };
  assert.equal(detectUnresolvedDestination(site), null);
  const site2 = { calleeExpr: 'pan.slice', args: [{ kind: 'ident', name: 'n' }] };
  assert.ok(detectUnresolvedDestination(site2));
});

test('C1/2: renderExpr never throws on malformed input and always returns a non-empty string', () => {
  for (const bad of [null, undefined, 42, 'x', {}, { kind: 'unknown' }, { kind: 'member', object: null, prop: 'x' }]) {
    const s = renderExpr(bad);
    assert.equal(typeof s, 'string');
    assert.ok(s.length > 0);
  }
});

// ── resolveSiteDecision — composition with §4.3 ambiguity + the null-category/privacy guards ──

test('C1/3a: resolveSiteDecision returns undefined for a privacy-catalog site (no vuln.cwe)', () => {
  const site = { entry: { id: 'privacy-js-logger-info', category: 'log' }, decision: { kind: 'log', category: 'log', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'log' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3b: resolveSiteDecision returns undefined for a null-category (process) decision', () => {
  const site = { entry: { id: 'js-exec', vuln: { cwe: 'CWE-78' } }, decision: { kind: 'process', category: null, coverageStatus: 'unsupported', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'ident', name: 'exec' }, args: [{ kind: 'ident', name: 'cmd' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3c: resolveSiteDecision returns undefined for a non-eligible-kind category (http-response) even with a computed argument', () => {
  const site = { entry: { id: 'js-express-res-send', vuln: { cwe: 'CWE-79' }, framework: 'express' }, decision: { kind: 'sink', category: 'http-response', coverageStatus: 'modeled', externality: 'internal', reason: 'x' }, calleeExpr: { kind: 'member', object: { kind: 'ident', name: 'res' }, prop: 'send' }, args: [{ kind: 'ident', name: 'x' }] };
  assert.equal(resolveSiteDecision(site), undefined);
});

test('C1/3d: resolveSiteDecision fires for an external-api site with a computed argument, and coverageStatus/category are preserved per FR-203', () => {
  const site = {
    entry: { id: 'js-ssrf-fetch', vuln: { cwe: 'CWE-918' } },
    decision: { kind: 'external', category: 'external-api', coverageStatus: 'modeled', externality: 'external', reason: 'SSRF sinks are outbound HTTP client calls' },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  const r = resolveSiteDecision(site);
  assert.ok(r);
  assert.equal(r.kind, 'unresolved');
  assert.equal(r.category, 'external-api', 'category is RETAINED per FR-203');
  assert.equal(r.coverageStatus, 'modeled', 'coverageStatus is UNCHANGED per FR-203');
  assert.equal(r.externality, 'unknown');
  assert.match(r.reason, /destination could not be statically resolved/);
});

test('C1/3e: resolveSiteDecision composes with a §4.3 plurality demotion — the demoted coverageStatus survives, not CWE_MAP\'s fresh value', () => {
  const site = {
    entry: { id: 'js-ssrf-fetch', vuln: { cwe: 'CWE-918' } }, // CWE-918 -> external-api, 'modeled' fresh
    decision: { kind: 'external', category: 'external-api', coverageStatus: 'partial', externality: 'external', reason: 'plurality-demoted reason text' },
    ambiguity: { resolvedBy: 'plurality', alternatives: ['other-entry'] },
    calleeExpr: { kind: 'ident', name: 'fetch' },
    args: [{ kind: 'ident', name: 'url' }],
  };
  const r = resolveSiteDecision(site);
  assert.ok(r);
  assert.equal(r.coverageStatus, 'partial', 'the plurality demotion must survive FR-203, never reset to CWE_MAP\'s fresh "modeled"');
  assert.match(r.reason, /destination could not be statically resolved/);
  assert.match(r.reason, /plurality-demoted reason text/, 'the site-level reason is carried forward too, not silently dropped');
});

// ── real end-to-end wiring: buildGraphWithCoverage ──

test('C1/4: buildGraphWithCoverage produces a validateGraph()-clean graph with a finished coverage ledger on real parsed code', async () => {
  const { validateGraph } = await import('../../src/lineage/validate.js');
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
  });
  const r = buildGraphWithCoverage(cg, { repository: 'r' });
  assert.deepEqual(validateGraph(r.graph).errors, []);
  assert.ok(Array.isArray(r.graph.coverage.languages));
  assert.ok(r.graph.coverage.sources.byCategory);
  assert.ok(r.graph.coverage.sinks.byCategory);
  assert.equal(typeof r.graph.coverage.unresolvedDestinations, 'number');
  assert.deepEqual(r.graph.coverage.budgets, DEFAULTS, 'default budgets, none overridden');
});

test('C1/5: buildCoverageLedger\'s byCategory buckets are real, non-vacuous counts on real parsed code — an empty result would NOT pass this', () => {
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
  });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.ok(ledger.sources.byCategory['credentials'] || Object.keys(ledger.sources.byCategory).length > 0,
    'at least one real source category is present with a nonzero count');
  const total = Object.values(ledger.sinks.byCategory).reduce((a, c) => a + c.sites, 0);
  assert.ok(total > 0, 'at least one sink category has at least one site');
});

// ── D5-style empty-graph proof: an empty-but-valid graph must FAIL these tests ──

test('C1/6: an empty callGraph (zero functions) produces a ledger that is DISTINGUISHABLE from a real one — every count is genuinely zero, not just "field present"', () => {
  const emptyCg = { functions: new Map() };
  const built = buildDataFlowGraph(emptyCg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.equal(ledger.sources.matched, 0);
  assert.deepEqual(ledger.sources.byCategory, {}, 'no categories at all — never a category present with a zero count, which would be a different, wrong signal');
  assert.equal(ledger.sinks.callStatementSites, 0);
  assert.deepEqual(ledger.sinks.byCategory, {});
  assert.equal(ledger.unresolvedDestinations, 0);
  assert.equal(ledger.degradedTerminals, 0);
  // The real-code test (C1/5) above asserts nonzero counts on a populated
  // fixture; THIS test would pass just as easily on a broken
  // buildCoverageLedger that always returns zeros. The pairing of the two
  // is the actual proof — matching D5's "an empty-but-valid graph must
  // fail" discipline: a test suite that can't tell the difference between
  // "genuinely empty" and "silently broken" is worthless, and C1/5 is
  // what makes that difference observable.
});

test('C1/7: languages/parseFailures are honestly empty when opts.perFile/opts.parseFailures are omitted — never fabricated', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built);
  assert.deepEqual(ledger.languages, []);
  assert.deepEqual(ledger.parseFailures, []);
});

test('C1/8: languages/parseFailures are populated correctly from opts.perFile/opts.parseFailures — filesExpected includes real failures, filesAnalyzed does not', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const ledger = buildCoverageLedger(built, {
    perFile: { 'a.js': {}, 'b.js': {} },
    parseFailures: [{ file: 'c.js', message: 'unexpected token' }],
  });
  assert.deepEqual(ledger.languages, [{ language: 'js', filesExpected: 3, filesAnalyzed: 2 }]);
  assert.equal(ledger.parseFailures.length, 1);
  assert.equal(ledger.parseFailures[0].language, 'js', 'language is derived from the extension when not supplied');
});

// ── determinism ──

test('C1/9: buildCoverageLedger is deterministic — two calls on the same built graph produce byte-identical ledgers, including byCategory key order', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const built = buildDataFlowGraph(cg, { repository: 'r' });
  const l1 = buildCoverageLedger(built);
  const l2 = buildCoverageLedger(built);
  assert.deepEqual(l1, l2);
  assert.deepEqual(Object.keys(l1.sources.byCategory), [...Object.keys(l1.sources.byCategory)].sort());
  assert.deepEqual(Object.keys(l1.sinks.byCategory), [...Object.keys(l1.sinks.byCategory)].sort());
});

// ── isolation / reuse boundary ──

test('C1/10: coverage.js\'s only local-package imports are sink-registry.js, path-query.js, and graph-builder.js', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../../src/lineage/coverage.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/^import\s+.*?\sfrom\s+['"](.+?)['"];?$/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers.sort(), ['./graph-builder.js', './path-query.js', './sink-registry.js']);
});
