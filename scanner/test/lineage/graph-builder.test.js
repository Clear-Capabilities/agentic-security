//
// graph-builder.test.js — Sub-project E, increment 3 (E3).
//
// The permanent test suite for `src/lineage/graph-builder.js`, absorbing
// `E1/6`-`E1/13` (the projection half) from
// `test/lineage/graph-builder-poc.test.js`, re-pointed at the shipped
// module. Per DESIGN_GRAPH_BUILDER.md §9.1's absorption protocol, this
// increment is the confirmed SECOND lander (E2/source-seeding.js already
// landed first and absorbed the seeding half, E1/1-E1/5 + E1/14, into
// test/lineage/source-seeding.test.js) — the PoC file itself is deleted in
// the same commit that lands this file.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildProjectIR } from '../../src/ir/index.js';
import { emptyGraphEnvelope, SOURCE_CATEGORIES, SINK_CATEGORIES, COVERAGE_STATUS_VALUES } from '../../src/lineage/schema.js';
import * as ids from '../../src/lineage/ids.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { emptyProtection } from '../../src/lineage/protection.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { buildDataFlowGraph, enumerateSinkSites, degradedTerminals } from '../../src/lineage/graph-builder.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULN_JS_DIR = path.join(__dirname, '..', 'fixtures', 'vulnerable-js');

function irOf(fileContents) {
  const { callGraph } = buildProjectIR(fileContents);
  return callGraph;
}

function vulnerableJs() {
  return { 'app.js': fs.readFileSync(path.join(VULN_JS_DIR, 'app.js'), 'utf8') };
}

test('E1/6: the projection produces a validated, flagship-scale DataFlowGraph v1 from real parsed code', () => {
  const callGraph = irOf(vulnerableJs());
  const r = buildDataFlowGraph(callGraph, { repository: 'vulnerable-js', generatedAt: '2026-08-31T00:00:00.000Z' });

  const v = validateGraph(r.graph);
  assert.deepEqual(v.errors, [], 'validateGraph must return no errors');
  assert.equal(v.valid, true);

  assert.equal(r.graph.nodes.length, 9);
  assert.equal(r.graph.edges.length, 6);
  assert.equal(r.graph.dataElements.length, 6);
  assert.equal(r.graph.flows.length, 6);

  // §2.4's warning: validity alone proves nothing. An EMPTY graph also
  // validates, so pin non-emptiness as its own assertion.
  const empty = emptyGraphEnvelope({ graphId: ids.graphId({ repository: 'x' }) });
  assert.equal(validateGraph(empty).valid, true, 'an empty graph validates too — this is why the counts above are asserted');

  // The order-of-magnitude claim, against the ONE reference artifact that
  // exists: the hand-built flagship fixture is 14 nodes for a whole
  // synthetic payments platform.
  assert.ok(r.graph.nodes.length <= 14,
    'a 42-line fixture must not out-node a whole synthetic platform (flagship: 14)');
  // Re-measured in this increment against the live tree (2026-08-31, after
  // the receiver-identity hotfix and the schema/validator hotfix) — matches
  // E2's own re-measurement of source-seeding.js's hop count on the same
  // fixture. Node/edge/dataElement/flow counts above are UNCHANGED by the
  // hotfix — the extra hops are additional intraprocedural provenance
  // detail for identity that was already reaching its sink through other
  // paths, not a change to which sources/sinks/fields the projection
  // connects.
  assert.equal(r.hops.length, 23);
});

test('E1/7: node count is SYSTEM-granular and provably invariant under code growth, while edges/flows/dataElements stay field-granular', () => {
  const base = fs.readFileSync(path.join(VULN_JS_DIR, 'app.js'), 'utf8');
  const measured = [];
  for (const copies of [1, 10, 50]) {
    const fc = {};
    for (let i = 0; i < copies; i += 1) fc[`svc${i}/app.js`] = base;
    const r = buildDataFlowGraph(irOf(fc), { repository: 'scale' });
    assert.deepEqual(validateGraph(r.graph).errors, [], `copies=${copies} must still validate`);
    measured.push({ copies, nodes: r.graph.nodes.length, edges: r.graph.edges.length, flows: r.graph.flows.length, de: r.graph.dataElements.length });
  }
  assert.deepEqual(measured, [
    { copies: 1, nodes: 9, edges: 6, flows: 6, de: 6 },
    { copies: 10, nodes: 9, edges: 60, flows: 60, de: 60 },
    { copies: 50, nodes: 9, edges: 300, flows: 300, de: 300 },
  ], 'nodes stay at 9 across a 50x code-size increase; edges/flows/dataElements scale linearly — this IS the projection rule');
});

test('E1/8: the assertions validate.js structurally CANNOT make (§2.4\'s two failure modes)', () => {
  const r = buildDataFlowGraph(irOf(vulnerableJs()), { repository: 'vulnerable-js' });
  const { graph } = r;

  // (a) every node.subtype is a real registry-vocabulary value, or null.
  //     `validate.js` has no check for this at all.
  const vocab = new Set([...SOURCE_CATEGORIES, ...SINK_CATEGORIES]);
  for (const n of graph.nodes) {
    assert.ok(n.subtype === null || vocab.has(n.subtype),
      `node.subtype "${n.subtype}" must be a SOURCE_CATEGORIES/SINK_CATEGORIES member or null (Decision 1)`);
    assert.ok(typeof n.coverageReason === 'string' && n.coverageReason.length > 0,
      'AC-11: every node carries a non-empty coverage reason');
  }

  // (b) node.dataElementIds is only checked to be an ARRAY by validate.js.
  const deIds = new Set(graph.dataElements.map((d) => d.id));
  for (const n of graph.nodes) {
    for (const id of n.dataElementIds) assert.ok(deIds.has(id), `node ${n.id} references unknown dataElement ${id}`);
  }

  // (c) no two DIFFERENT registry decisions collided onto one node id.
  for (const [nodeId, decisions] of r.decisionsByNodeId) {
    const distinct = new Set(decisions.map((d) => JSON.stringify(d)));
    assert.equal(distinct.size, 1, `node ${nodeId} was minted from ${distinct.size} different registry decisions — the discriminator is under-specified`);
  }

  // (d) flow.edgeIds are real `edge:` ids, never `pedge:`/`ppath:` ones.
  for (const f of graph.flows) {
    for (const e of f.edgeIds) assert.ok(e.startsWith('edge:'), `flow.edgeIds must never carry a provenance id — got ${e}`);
    assert.ok(f.id.startsWith('flow:'));
  }
  for (const e of graph.edges) assert.ok(e.id.startsWith('edge:'));
  for (const t of graph.transformations) assert.ok(t.id.startsWith('transform:'));

  // (e) id uniqueness within each entity array (validate.js does check this,
  //     but only because the discriminators below are complete — pin them).
  for (const key of ['nodes', 'edges', 'dataElements', 'flows', 'transformations']) {
    const list = graph[key].map((x) => x.id);
    assert.equal(new Set(list).size, list.length, `${key} contains a duplicate id`);
  }
});

test('E1/9 (item d): multi-candidate sink resolution — promote via the receiver where it disambiguates, else ONE node at the plurality category, `partial`, with the alternatives named', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const site = enumerateSinkSites(cg).sites[0];
  assert.equal(site.entry.id, 'js-express-res-send');
  assert.equal(site.decision.category, 'http-response');
  assert.equal(site.decision.coverageStatus, 'modeled', 'a receiver-resolved match keeps its own coverage status — no demotion');
  assert.equal(site.ambiguity.resolvedBy, 'receiver');
  assert.deepEqual(site.ambiguity.alternatives, ['js-koa-send', 'privacy-js-res-send'],
    'the scoping doc measured 2 candidates via matchSinkOrSanitizer alone; adding matchPrivacySink makes it 3');

  // Same callee, a receiver NOTHING declares a constraint for: no candidate
  // is receiver-justified, the categories disagree, so the plurality rule
  // fires — one node, `partial`, alternatives named in the reason.
  const cg2 = irOf({ 'b.js': 'function h(ctx, x){ ctx.send(x); }' });
  const site2 = enumerateSinkSites(cg2).sites[0];
  assert.equal(site2.ambiguity.resolvedBy, 'plurality');
  assert.equal(site2.decision.coverageStatus, 'partial', 'never a silent pick at full confidence');
  assert.ok(site2.decision.reason.includes('AMBIGUOUS at this call site'));
  for (const alt of site2.ambiguity.alternatives) {
    assert.ok(site2.decision.reason.includes(alt), `the reason must name the alternative category ${alt}`);
  }
  assert.ok(site2.decision.reason.includes('js-koa-send') && site2.decision.reason.includes('privacy-js-res-send'),
    'and every candidate entry id, mirroring sink-registry.js\'s own thirdPartySdk convention');

  // Determinism: the plurality tie-break is lexicographic over the category
  // name, so the same input always resolves the same way.
  const again = enumerateSinkSites(irOf({ 'b.js': 'function h(ctx, x){ ctx.send(x); }' })).sites[0];
  assert.equal(again.decision.category, site2.decision.category);
});

test('E1/10 (item e): §16.7 Finding 2\'s enumerator is computable from path-store.js\'s PUBLIC read API alone, and fires on real degraded code', () => {
  const code = 'function id(v){ return v; }\n'
    + 'function h(req){ const a = req.body.a; const b = req.query.b; const c = req.params.c;\n'
    + '  const x = id(a); const y = id(b); const z = id(c); sinkA(x); sinkB(y); sinkC(z); }';
  const callGraph = irOf({ 'd.js': code });
  const { seeds } = planSeeds(callGraph, { repository: 'd' });
  assert.equal(seeds.length, 3, 'three distinct sources, so `id` is resolved under three distinct entry contexts');

  const run = (cap) => {
    const hops = [];
    runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds), maxContextsPerFn: cap });
    const store = new PathStore();
    store.addHops(hops);
    return { store, hops };
  };

  const wide = run(16);
  assert.equal(wide.hops.filter((h) => h.lossReason).length, 0, 'no degradation under the default cap');
  assert.equal(degradedTerminals(wide.store).length, 0, 'and therefore no degraded terminal — the enumerator does not over-fire');

  const tight = run(2);
  const lossReasons = [...new Set(tight.hops.filter((h) => h.lossReason).map((h) => h.lossReason))];
  assert.deepEqual(lossReasons, ['context-cap-degraded'], 'a real context-cap degradation is reachable from real parsed code');
  const dt = degradedTerminals(tight.store);
  assert.equal(dt.length, 1, 'exactly one truncation-terminal: a `path` node with zero out-edges whose in-edge is degraded');
  assert.equal(dt[0].kind, 'path');
  assert.equal(tight.store.edgesFrom(dt[0].id).length, 0, 'zero out-edges — invisible to sinkCandidates(), which is §16.7 Finding 2 exactly');
  assert.ok(tight.store.edgesTo(dt[0].id).length > 0, 'but reachable through edgesTo()');

  // It is NOT a sinkCandidates() result, which is the whole point.
  assert.ok(!['return', 'escape', 'loss'].includes(dt[0].kind));

  // The node the projection mints for it uses the ALREADY-FIXED vocabulary
  // (DESIGN_REGISTRIES.md's closing section) — never a re-derived one.
  const r = buildDataFlowGraph(callGraph, { repository: 'd', maxContextsPerFn: 2 });
  const unresolved = r.graph.nodes.filter((n) => n.kind === 'unresolved');
  assert.equal(unresolved.length, 1);
  assert.equal(unresolved[0].coverageStatus, 'partial');
  assert.equal(unresolved[0].externality.value, 'unknown');
  assert.ok(unresolved[0].coverageReason.includes('context-cap'), 'the reason names the degradation');
  assert.deepEqual(validateGraph(r.graph).errors, []);
});

test('E1/11 (Step 5): transformation entities — a recognized `mask`, an honest `unknown`, and NO control-credit field of any kind', () => {
  const code = 'function maskCard(pan){ return \'****\' + pan; }\n'
    + 'function handle(req, logger){\n'
    + '  const card = req.body.card_number;\n'
    + '  const masked = maskCard(card);\n'
    + '  logger.info(masked);\n'
    + '  const shaped = reshapeForVendor(card);\n'
    + '  logger.warn(shaped);\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'x.js': code }), { repository: 'tx' });
  assert.deepEqual(validateGraph(r.graph).errors, []);

  const byCallee = Object.fromEntries(r.graph.transformations.map((t) => [t.callee, t]));
  assert.ok(byCallee.maskCard, 'a recognized transform is attributed by callee name');
  assert.equal(byCallee.maskCard.kind, 'mask');
  assert.equal(byCallee.maskCard.reversibility, 'irreversible');
  assert.equal(byCallee.maskCard.confidence.tier, 'medium', 'transform-catalog.js\'s own naming-convention tier, carried through unchanged');

  // §7.2: `recognizeTransformation` returned null but the hop record says a
  // call widened the value — the entity's kind is `unknown`, never
  // `custom` ("custom" asserts a real transform we merely can't name).
  assert.ok(byCallee.reshapeForVendor, 'the unknown case is genuinely reachable on real parsed code');
  assert.equal(byCallee.reshapeForVendor.kind, 'unknown');
  assert.equal(byCallee.reshapeForVendor.reversibility, 'unknown');
  assert.equal(byCallee.reshapeForVendor.algorithm, null);
  assert.ok(byCallee.reshapeForVendor.evidence.includes('unresolved-call'));

  for (const t of r.graph.transformations) {
    assert.equal(t.appliesToAllPaths, null, 'FR-307\'s all-path proof does not exist yet; null, never true/false');
    const keys = Object.keys(t).join(' ');
    assert.ok(!/credit|granted|denied|verdict|protected/i.test(keys),
      `Decision 2: a transformation entity must carry NO control-credit field, not even false — got keys: ${keys}`);
  }

  // §8's flow/edge defaults, on every flow and every edge, always.
  for (const f of r.graph.flows) {
    assert.equal(f.protectionSummary, 'not_assessed');
    assert.equal(f.policyVerdict, 'not_evaluated');
  }
  for (const e of r.graph.edges) {
    assert.deepEqual(e.protection, emptyProtection(),
      '§10.7\'s "derived from the individual edge verdicts" is satisfied trivially because every edge verdict is not_assessed');
  }
});

// =========================================================================
// E1/12 (item g): the reuse boundary — mirrors the self-checking pattern
// every sibling module in this package already uses (path-query.js's exact
// ['./ids.js'] list, source-seeding.js's exact dataflow/ import pair) —
// this time reading graph-builder.js's OWN source, not a test file's.
// =========================================================================

test('E1/12 (item g): the reuse boundary — graph-builder.js imports two PURE functions from src/dataflow/ and nothing else from that package', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/graph-builder.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.ok(specifiers.length > 0, 'sanity: the file does import something');

  const dataflowImports = specifiers.filter((s) => s.includes('/dataflow/'));
  assert.deepEqual(dataflowImports.sort(), [
    '../dataflow/catalog.js',
    '../dataflow/privacy-catalog.js',
  ], 'exactly two dataflow modules, both pure functions — accessPathOf is not directly used by this module (source-seeding.js already extends the seed path with it)');

  for (const s of specifiers) {
    assert.ok(!/dataflow\/(engine|summaries|index)\.js$/.test(s),
      `PRD §18.1: never import dataflow's taint engine, its SummaryCache, or its package entry point — found ${s}`);
  }

  // And confirm what we rely on is a MODULE-LEVEL export of catalog.js,
  // reachable without going through dataflow/engine.js at all.
  const catalogSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'dataflow', 'catalog.js'), 'utf8');
  assert.ok(/^export function matchSinkOrSanitizer\(/m.test(catalogSrc));
  const privacySrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'dataflow', 'privacy-catalog.js'), 'utf8');
  assert.ok(/^export function matchPrivacySink\(/m.test(privacySrc));
});

test('E1/13 (AC-11 coarse half): a sink nothing reaches is still a node with a coverage reason, and the ledger counts the sites the enumerator cannot reach', () => {
  const r = buildDataFlowGraph(irOf(vulnerableJs()), { repository: 'vulnerable-js' });
  const connectedSinkIds = new Set(r.graph.flows.map((f) => f.sink));
  const disconnected = r.graph.nodes.filter((n) => n.kind !== 'source' && !connectedSinkIds.has(n.id));
  assert.ok(disconnected.length > 0, 'vulnerable-js really does contain a matched sink nothing reaches');
  for (const n of disconnected) {
    assert.ok(n.coverageReason.length > 0, 'AC-11: visible, with a reason');
    assert.ok(COVERAGE_STATUS_VALUES.includes(n.coverageStatus));
  }

  // The per-CALL-SITE half of AC-11 lives in the ledger, because the node
  // layer is deliberately category-granular (see DESIGN_GRAPH_BUILDER.md
  // §6.5's flagged, unresolved question for E4/H).
  assert.equal(r.graph.coverage.sinks.callStatementSites, 11);
  assert.equal(r.graph.coverage.sinks.connected, 6);
  assert.equal(r.graph.coverage.sinks.disconnected, 5);
  assert.equal(r.graph.coverage.sinks.nonStatementSitesNotEnumerable, 1,
    'a sink call expression with no `escape` provenance node is COUNTED, never silently dropped');
  assert.equal(r.graph.coverage.sources.matched, 9);
  assert.equal(r.graph.coverage.sources.unseedable, 0);
  // Re-measured in this increment (2026-08-31, post-hotfix): 23, matching
  // E1/6's own hop count and source-seeding.js's own re-measurement.
  assert.equal(r.graph.coverage.provenance.hops, 23);
});
