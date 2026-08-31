// Tests for transit-protection.js — Milestone 2, Sub-project B, increments 1
// (transit-protection plumbing skeleton) and 2 (real edge.protection.transit
// verdicts, closing AC-03/AC-04). See src/lineage/DESIGN_TRANSIT_PROTECTION.md
// for the full design, including §6's decision table these B2 tests pin.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanTransitEvidence, resolveTransitProtectionForSite, TRANSIT_PROTECTION_WINDOW_LINES } from '../../src/lineage/transit-protection.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { buildGraphWithCoverage, resolveSiteDecision } from '../../src/lineage/coverage.js';
import { resolveDestination } from '../../src/lineage/resolve-destination.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Reuse the SAME real, already-proven fixture crypto-protocol.js's own
// test suite fires crypto-tls-no-verify against — per the plan's own
// instruction, not a newly invented shape.
const CRYPTO_FIX = path.join(__dirname, '..', 'fixtures', 'crypto-protocol');
const read = (p) => fs.readFileSync(p, 'utf8');

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

test('B1/1: scanTransitEvidence on a real rejectUnauthorized:false fixture returns a Map with that file, including a crypto-tls-no-verify finding', () => {
  const raw = read(path.join(CRYPTO_FIX, 'vulnerable', 'tls-config.js'));
  const result = scanTransitEvidence({ 'tls-config.js': raw });
  assert.ok(result instanceof Map);
  assert.equal(result.size, 1);
  assert.ok(result.has('tls-config.js'));
  const findings = result.get('tls-config.js');
  assert.ok(Array.isArray(findings) && findings.length > 0);
  const f = findings.find((x) => x.family === 'crypto-tls-no-verify');
  assert.ok(f, `expected crypto-tls-no-verify; got ${findings.map((x) => x.family).join(',')}`);
});

test('B1/2: scanTransitEvidence on a clean, crypto-relevant-but-safe fixture returns an empty Map', () => {
  const raw = read(path.join(CRYPTO_FIX, 'clean', 'safe.js'));
  const result = scanTransitEvidence({ 'safe.js': raw });
  assert.ok(result instanceof Map);
  // Measured directly against scanCryptoProtocol before asserting: the clean
  // fixture is crypto-relevant (mentions TLS/jwt/etc.) but triggers zero
  // findings, so scanTransitEvidence must have NO entry for it (never an
  // entry with an empty array — see the module's own header contract).
  assert.equal(result.size, 0);
  assert.equal(result.has('safe.js'), false);
});

test('B1/3: scanTransitEvidence({}) / scanTransitEvidence(undefined) return an empty Map, never throw', () => {
  for (const input of [{}, undefined]) {
    const result = scanTransitEvidence(input);
    assert.ok(result instanceof Map);
    assert.equal(result.size, 0);
  }
});

test('B1/4: scanTransitEvidence skips non-string values and never throws on malformed input', () => {
  const result = scanTransitEvidence({
    'a.js': 123,
    'b.js': null,
    'c.js': undefined,
    'd.js': { not: 'a string' },
  });
  assert.ok(result instanceof Map);
  assert.equal(result.size, 0);
});

test('B1/5: buildLineageGraph.graph is byte-identical with and without opts.fileContents; transitEvidence is present and non-empty only when supplied', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const vulnRaw = read(path.join(CRYPTO_FIX, 'vulnerable', 'tls-config.js'));

  const without = buildLineageGraph(cg, { repository: 'r', deterministic: true });
  const withFC = buildLineageGraph(cg, { repository: 'r', deterministic: true, fileContents: { 'tls-config.js': vulnRaw } });

  assert.equal(without.status, 'complete');
  assert.equal(withFC.status, 'complete');
  assert.deepEqual(without.graph, withFC.graph, 'graph must be byte-identical whether or not opts.fileContents is supplied');

  assert.ok(without.transitEvidence instanceof Map);
  assert.equal(without.transitEvidence.size, 0, 'no fileContents supplied -> empty transitEvidence');

  assert.ok(withFC.transitEvidence instanceof Map);
  assert.equal(withFC.transitEvidence.size, 1);
  assert.ok(withFC.transitEvidence.has('tls-config.js'));
  const fams = withFC.transitEvidence.get('tls-config.js').map((f) => f.family);
  assert.ok(fams.includes('crypto-tls-no-verify'));
});

test('B1/6: buildLineageGraph.transitEvidence defaults to an empty Map when opts.fileContents is omitted entirely', () => {
  const cg = irOf({ 'a.js': "function h(res){ res.send('x'); }" });
  const r = buildLineageGraph(cg, { repository: 'r' });
  assert.ok(r.transitEvidence instanceof Map);
  assert.equal(r.transitEvidence.size, 0);
});

test('B1/7: reuse boundary — transit-protection.js imports only crypto-protocol.js', async () => {
  const src = fs.readFileSync(new URL('../../src/lineage/transit-protection.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['../sast/crypto-protocol.js']);
});

// =========================================================================
// Milestone 2, Sub-project B, increment 2 — real edge.protection.transit
// verdicts (closes AC-03/AC-04). See DESIGN_TRANSIT_PROTECTION.md §6.
// =========================================================================

// Real fixture shape: `req.body.card_number` (a genuine PROVENANCE_MAP
// source, extended to the field per DESIGN_GRAPH_BUILDER.md §3.2) flowing
// into an object-literal argument of a bare `fetch(...)` STATEMENT call —
// the only CFG shape that produces an `escape` provenance node
// (graph-builder.js's own §4.1 doc comment), so this is the minimal real
// shape that produces an actual `data_flow` edge to an `external-api` sink.
function fetchFixture(url, extraProps = '') {
  return `
function h(req) {
  const cardNumber = req.body.card_number;
  fetch(${JSON.stringify(url)}, { method: 'POST', body: cardNumber${extraProps} });
}
`;
}

function onlyEdge(graph) {
  assert.equal(graph.edges.length, 1, `expected exactly one edge; got ${graph.edges.length}`);
  return graph.edges[0];
}

test('B2/1 (AC-03): a literal http:// destination on an external-api site -> unprotected/code, via buildDataFlowGraph directly, no fileContents needed', () => {
  const cg = irOf({ 'a.js': fetchFixture('http://payments.example/charge') });
  const built = buildDataFlowGraph(cg, {
    repository: 'r',
    deterministic: true,
    resolveSiteDecision,
    resolveDestination,
    // No opts.fileContents/opts.transitEvidenceByFile anywhere in this
    // test — proving the scheme-only path works even when no crypto
    // evidence was ever computed at all.
    resolveTransitProtection: (site) => resolveTransitProtectionForSite(site, new Map()),
  });
  const edge = onlyEdge(built.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'unprotected', evidenceGrade: 'code' });
  assert.deepEqual(edge.protection.atRest, { verdict: 'not_assessed', evidenceGrade: 'none' });
  assert.deepEqual(edge.protection.handling, { verdict: 'not_assessed', evidenceGrade: 'none' });
});

test('B2/2 (AC-04): a literal https:// destination with a NEARBY crypto-tls-no-verify finding -> unprotected/code, not protected — the scheme alone must never win', () => {
  // rejectUnauthorized: false is the same real shape crypto-protocol.js's
  // own test suite (and this file's B1/1) already proves fires
  // crypto-tls-no-verify — placed on the same statement as the fetch call
  // itself, well within TRANSIT_PROTECTION_WINDOW_LINES.
  const code = fetchFixture('https://payments.example/charge', ', rejectUnauthorized: false');
  const cg = irOf({ 'a.js': code });
  // buildGraphWithCoverage takes a pre-computed opts.transitEvidenceByFile
  // Map, NOT raw opts.fileContents (see DESIGN_TRANSIT_PROTECTION.md §6.2 —
  // buildGraphWithCoverage never calls scanTransitEvidence itself, only
  // index.js's buildLineageGraph does, exactly once). scanTransitEvidence
  // is called here, in the test, to genuinely supply that file's real text
  // as evidence — mirroring exactly what buildLineageGraph does internally.
  const transitEvidenceByFile = scanTransitEvidence({ 'a.js': code });
  const built = buildGraphWithCoverage(cg, {
    repository: 'r',
    deterministic: true,
    transitEvidenceByFile,
  });
  const edge = onlyEdge(built.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'unprotected', evidenceGrade: 'code' });
});

test('B2/3: a literal https:// destination with NO nearby finding -> protected/code', () => {
  const code = fetchFixture('https://payments.example/charge');
  const cg = irOf({ 'a.js': code });
  const built = buildGraphWithCoverage(cg, {
    repository: 'r',
    deterministic: true,
    transitEvidenceByFile: scanTransitEvidence({ 'a.js': code }),
  });
  const edge = onlyEdge(built.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'protected', evidenceGrade: 'code' });
});

test('B2/4 (AC-05\'s transit contribution): a dynamic/unresolved destination -> edge.protection.transit stays the DEFAULT not_assessed/none', () => {
  const code = `
function h(req, url) {
  const cardNumber = req.body.card_number;
  fetch(url, { method: 'POST', body: cardNumber });
}
`;
  const cg = irOf({ 'a.js': code });
  const built = buildGraphWithCoverage(cg, { repository: 'r', deterministic: true });
  const edge = onlyEdge(built.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'not_assessed', evidenceGrade: 'none' });
});

test('B2/5: a non-network category (database) sink -> edge.protection.transit stays the DEFAULT, proving the external-api-only filter', () => {
  const code = `
function h(req, db) {
  const cardNumber = req.body.card_number;
  db.query('INSERT INTO t (card_number) VALUES (?)', [cardNumber]);
}
`;
  const cg = irOf({ 'a.js': code });
  const built = buildGraphWithCoverage(cg, { repository: 'r', deterministic: true });
  const edge = onlyEdge(built.graph);
  assert.equal(built.graph.nodes.find((n) => n.id === edge.to)?.subtype, 'database');
  assert.deepEqual(edge.protection.transit, { verdict: 'not_assessed', evidenceGrade: 'none' });
});

test('B2/6: byte-identical proof — buildDataFlowGraph with opts.resolveTransitProtection omitted is byte-identical to passing it explicitly as undefined, and transit stays the pre-increment default on every edge', () => {
  const cg = irOf({ 'a.js': fetchFixture('http://payments.example/charge') });
  const commonOpts = { repository: 'r', deterministic: true, resolveSiteDecision, resolveDestination };
  const omitted = buildDataFlowGraph(cg, commonOpts);
  const explicitUndefined = buildDataFlowGraph(cg, { ...commonOpts, resolveTransitProtection: undefined });
  assert.deepEqual(omitted.graph, explicitUndefined.graph, 'graph must be byte-identical whether the hook is omitted or explicitly undefined');
  const edge = onlyEdge(omitted.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'not_assessed', evidenceGrade: 'none' }, 'omitting the hook must leave transit at emptyProtection()\'s own pre-increment default, even for a site that WOULD resolve unprotected with the hook present');
});

test('B2/7: buildGraphWithCoverage composes with a caller-supplied opts.resolveTransitProtection override — the caller\'s own hook always wins over the default built from opts.transitEvidenceByFile', () => {
  const code = fetchFixture('http://payments.example/charge');
  const cg = irOf({ 'a.js': code });
  let calls = 0;
  const built = buildGraphWithCoverage(cg, {
    repository: 'r',
    deterministic: true,
    fileContents: { 'a.js': code },
    resolveTransitProtection: (site) => {
      calls += 1;
      return { verdict: 'protected', evidenceGrade: 'manual' };
    },
  });
  assert.ok(calls > 0, 'the caller-supplied override must actually be invoked');
  const edge = onlyEdge(built.graph);
  // The literal http:// scheme would normally force 'unprotected' — proving
  // this is really the override winning, not a coincidence.
  assert.deepEqual(edge.protection.transit, { verdict: 'protected', evidenceGrade: 'manual' });
});

test('B2/8: single-computation proof — scanCryptoProtocol/scanTransitEvidence runs EXACTLY ONCE per file per buildLineageGraph call, measured live via a Proxy call counter on opts.fileContents', () => {
  const code = fetchFixture('https://payments.example/charge', ', rejectUnauthorized: false');
  const cg = irOf({ 'a.js': code });

  const rawFileContents = { 'a.js': code };
  const reads = new Map();
  const proxiedFileContents = new Proxy(rawFileContents, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && prop in target) reads.set(prop, (reads.get(prop) ?? 0) + 1);
      return Reflect.get(target, prop, receiver);
    },
  });

  const result = buildLineageGraph(cg, { repository: 'r', deterministic: true, fileContents: proxiedFileContents });

  assert.equal(result.status, 'complete');
  // The load-bearing assertion: raw file text for 'a.js' was read exactly
  // once across the WHOLE buildLineageGraph call — index.js's own
  // scanTransitEvidence call, and NOT a second time inside coverage.js's
  // default resolveTransitProtection hook (which must consume the
  // pre-computed opts.transitEvidenceByFile Map instead of re-scanning).
  assert.deepEqual([...reads.entries()], [['a.js', 1]], `expected exactly one read of 'a.js'; got ${reads.get('a.js')}`);

  // Sanity: the single scan's own result is genuinely what drove the
  // verdict — not a coincidental pass with an empty evidence map.
  assert.ok(result.transitEvidence.has('a.js'));
  const edge = onlyEdge(result.graph);
  assert.deepEqual(edge.protection.transit, { verdict: 'unprotected', evidenceGrade: 'code' });
});

test('B2/9: resolveTransitProtectionForSite is defensive — never throws on a malformed site, and honestly declines (undefined) rather than guessing', () => {
  const map = new Map();
  assert.equal(resolveTransitProtectionForSite(undefined, map), undefined);
  assert.equal(resolveTransitProtectionForSite(null, map), undefined);
  assert.equal(resolveTransitProtectionForSite({}, map), undefined);
  assert.equal(resolveTransitProtectionForSite({ decision: {} }, map), undefined);
  assert.equal(resolveTransitProtectionForSite({ decision: { category: 'external-api' } }, undefined), undefined);
  assert.equal(resolveTransitProtectionForSite({ decision: { category: 'database' }, destination: { resolutionStatus: 'literal', literalValue: 'http://x' } }, map), undefined);
});

test('B2/10: TRANSIT_PROTECTION_WINDOW_LINES boundary — a nearby finding at exactly the window edge counts, one line beyond it does not', () => {
  const site = { file: 'a.js', line: 100, decision: { category: 'external-api' }, destination: { resolutionStatus: 'literal', literalValue: 'https://payments.example/charge' } };
  const findingAt = (line) => new Map([['a.js', [{ family: 'crypto-tls-no-verify', file: 'a.js', line }]]]);

  assert.deepEqual(
    resolveTransitProtectionForSite(site, findingAt(100 - TRANSIT_PROTECTION_WINDOW_LINES)),
    { verdict: 'unprotected', evidenceGrade: 'code' },
    'exactly WINDOW lines away must still count',
  );
  assert.deepEqual(
    resolveTransitProtectionForSite(site, findingAt(100 + TRANSIT_PROTECTION_WINDOW_LINES)),
    { verdict: 'unprotected', evidenceGrade: 'code' },
    'exactly WINDOW lines away (other direction) must still count',
  );
  assert.deepEqual(
    resolveTransitProtectionForSite(site, findingAt(100 - TRANSIT_PROTECTION_WINDOW_LINES - 1)),
    { verdict: 'protected', evidenceGrade: 'code' },
    'one line beyond the window must NOT count — falls through to the literal https:// scheme instead',
  );
});

test('B2/11: an unrelated family (e.g. crypto-weak-hash) near the line does not count as transit evidence', () => {
  const site = { file: 'a.js', line: 10, decision: { category: 'external-api' }, destination: { resolutionStatus: 'literal', literalValue: 'https://payments.example/charge' } };
  const map = new Map([['a.js', [{ family: 'crypto-weak-hash', file: 'a.js', line: 10 }]]]);
  assert.deepEqual(resolveTransitProtectionForSite(site, map), { verdict: 'protected', evidenceGrade: 'code' });
});
