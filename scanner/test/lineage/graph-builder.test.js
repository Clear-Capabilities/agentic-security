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

test('E3/det (task review MF-2): determinism — generatedAt is genuinely injectable, defaults to a fixed literal never Date.now()/toISOString(), and every entity array is emitted id-sorted regardless of build order', () => {
  const cg = irOf(vulnerableJs());

  // (a) the default is the fixed 1970 literal, not `new Date().toISOString()`.
  const noOpts = buildDataFlowGraph(cg, { repository: 'vulnerable-js' });
  assert.equal(noOpts.graph.generatedAt, '1970-01-01T00:00:00.000Z',
    'generatedAt must default to the fixed literal, never wall-clock time — a wall-clock default breaks --deterministic silently');

  // (b) opts.generatedAt is genuinely honoured, not ignored.
  const withOpts = buildDataFlowGraph(cg, { repository: 'vulnerable-js', generatedAt: '2026-08-31T00:00:00.000Z' });
  assert.equal(withOpts.graph.generatedAt, '2026-08-31T00:00:00.000Z');

  // (c) two builds of the SAME input are byte-identical (the graphId/
  // generatedAt fields aside) — proves determinism end to end, not just
  // that individual arrays happen to be sorted.
  const first = buildDataFlowGraph(cg, { repository: 'vulnerable-js', generatedAt: 'x' });
  const second = buildDataFlowGraph(cg, { repository: 'vulnerable-js', generatedAt: 'x' });
  assert.deepEqual(first.graph, second.graph, 'two builds of the same input must be byte-identical');

  // (d) every entity array is id-sorted, regardless of the order functions
  // were visited in (insertion order into the internal Maps is NOT
  // guaranteed to be id order — this is what actually needs pinning).
  for (const key of ['nodes', 'edges', 'dataElements', 'flows', 'transformations']) {
    const ids = noOpts.graph[key].map((x) => x.id);
    const sorted = [...ids].sort();
    assert.deepEqual(ids, sorted, `graph.${key} must be emitted in id-sorted order`);
  }
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
  // task review MF-1: (c) above is VACUOUS on vulnerable-js alone — its 9
  // nodes all differ by subtypeKey, so a weakened node-id discriminator
  // (dropping coverageStatus/externality) would still pass here. See the
  // dedicated construction below, which actually exercises the case.

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

test('E1/8c (task review MF-1): the node-id discriminator genuinely distinguishes two DIFFERENT decisions that share a subtypeKey — the real construction the vulnerable-js fixture alone never exercises', () => {
  // Both sites resolve to category 'file' (subtypeKey 'file' either way),
  // but one is a §4.3 plurality demotion (coverageStatus 'partial') and the
  // other a direct, unambiguous match (coverageStatus 'modeled'). If the
  // node-id discriminator dropped coverageStatus/externality (as a real
  // regression could), these two GENUINELY DIFFERENT registry decisions
  // would collide onto one node id — exactly what (c) above exists to
  // catch, but on a fixture that can actually trigger it.
  const cg = irOf({
    'a.js': "function a(ctx, x){ ctx.send(x); }", // ambiguous receiver -> plurality/partial
    'b.js': "function b(fs, x){ fs.writeFileSync('/t', x); }", // direct match -> modeled
  });
  const r = buildDataFlowGraph(cg, { repository: 'discriminator-check' });
  const { graph } = r;

  const fileNodes = graph.nodes.filter((n) => n.subtype === 'file');
  assert.equal(fileNodes.length, 2, 'the plurality/partial site and the direct/modeled site must mint TWO distinct nodes, not collide onto one');
  const statuses = fileNodes.map((n) => n.coverageStatus).sort();
  assert.deepEqual(statuses, ['modeled', 'partial'], 'the two nodes carry the two genuinely different coverageStatus values, never merged');

  for (const [nodeId, decisions] of r.decisionsByNodeId) {
    const distinct = new Set(decisions.map((d) => JSON.stringify(d)));
    assert.equal(distinct.size, 1, `node ${nodeId} was minted from ${distinct.size} different registry decisions on this fixture — the discriminator is under-specified`);
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

  // Milestone 2, Sub-project D, increment 2 (FR-307): `logger.info(...)`
  // and `logger.warn(...)` both resolve to the SAME `category: 'log'`
  // registry decision, so — per §6.1's node-identity rule ("a node is a
  // registry decision, never a call site") — they mint the SAME sink node,
  // confirmed directly below rather than assumed. Both `masked` and
  // `shaped` are also derived from the SAME `card` field (one
  // dataElementId). The two statements therefore share one coarse
  // `(source, sink, dataElement)` key, exactly like AC-12's own branching
  // scenario — each transform is present on only ONE of the two flow
  // groups sharing that key, so BOTH become `false`, not the naive
  // "only path to its own call site, so trivially true" a reader
  // considering `maskCard`/`reshapeForVendor` in isolation might expect.
  // (This is stronger than a plain single-path fixture would have been —
  // an earlier draft of this test assumed `logger.info`/`logger.warn`
  // mint two separate nodes and expected `true`/`true`; that assumption
  // was checked directly against this file's real output before writing
  // this comment, not carried over unverified.)
  const logNodes = r.graph.nodes.filter((n) => n.kind === 'log');
  assert.equal(logNodes.length, 1, 'logger.info and logger.warn collapse onto ONE category-granular sink node — the precondition for the false/false result below');
  assert.equal(byCallee.maskCard.appliesToAllPaths, false, 'maskCard\'s own flow is a sibling of reshapeForVendor\'s flow to the SAME sink/field, and lacks reshapeForVendor\'s transform id, so it cannot claim to apply on every path to that coarse group');
  assert.equal(byCallee.reshapeForVendor.appliesToAllPaths, false, 'symmetric reasoning: reshapeForVendor\'s own flow lacks maskCard\'s transform id');

  for (const t of r.graph.transformations) {
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

test('E1/12 (item g): the reuse boundary — graph-builder.js imports four PURE functions from src/dataflow/ and nothing else from that package', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/graph-builder.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.ok(specifiers.length > 0, 'sanity: the file does import something');

  const dataflowImports = specifiers.filter((s) => s.includes('/dataflow/'));
  assert.deepEqual(dataflowImports.sort(), [
    '../dataflow/catalog.js',
    '../dataflow/orm-write-catalog.js',
    '../dataflow/privacy-catalog.js',
    '../dataflow/privacy-sink-policy.js',
  ], 'exactly four dataflow modules, all pure functions — accessPathOf is not directly used by this module (source-seeding.js already extends the seed path with it); orm-write-catalog.js added by Milestone 2, Sub-project E, increment 1 (ORM-write sink recognition), isolated the same way privacy-catalog.js is; privacy-sink-policy.js added by Milestone 2, Sub-project G, increment 1 (isSinkPermitted/permittingRules — FR-408/AC-09), mirroring dataflow/privacy-taint.js\'s own real usage precedent');

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

test('F1: every edge produced by buildDataFlowGraph on real code reads provenance === \'code\' (FR-304, first clause)', () => {
  const r = buildDataFlowGraph(irOf(vulnerableJs()), { repository: 'vulnerable-js' });
  assert.ok(r.graph.edges.length > 0, 'sanity: this fixture really does produce edges');
  for (const e of r.graph.edges) {
    assert.equal(e.provenance, 'code');
  }
  assert.deepEqual(validateGraph(r.graph).errors, []);
});

// =========================================================================
// E4 (Task 1): the additive `opts.resolveSiteDecision` hook + the two
// additive site fields (`args`, `connected`). See DESIGN_GRAPH_BUILDER.md
// §9.4 item 5b and this file's own module-header note above.
// =========================================================================

test('E4/hook-1: opts.resolveSiteDecision is a no-op when omitted — byte-identical to a hardcoded pre-hook golden literal', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, { repository: 'r' });
  // Hardcoded, not a self-comparison (DESIGN_PATH_PROVENANCE.md §13.2a's
  // vacuous-test trap) — captured from this exact fixture before Task 1's
  // changes landed (measured directly: `x` is a bare parameter with no
  // recognized source seeding it, so this fixture mints only the sink
  // node — the plan's own draft literal of 2 was corrected to the real,
  // observed value of 1 during implementation).
  assert.equal(r.graph.nodes.length, 1);
  assert.equal(r.sites.length, 1);
  assert.equal(r.sites[0].decision.kind, 'sink');
  assert.equal(r.sites[0].decision.category, 'http-response');
});

test('E4/hook-2: opts.resolveSiteDecision, when it returns a value, replaces site.decision for every later use', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, {
    repository: 'r',
    resolveSiteDecision: (site) => ({ ...site.decision, kind: 'unresolved', externality: 'unknown', reason: 'forced for test' }),
  });
  assert.equal(r.sites[0].decision.kind, 'unresolved');
  const n = r.graph.nodes.find((x) => x.subtype === 'http-response');
  assert.ok(n, 'a node still exists at the http-response category');
  assert.equal(n.externality.value, 'unknown', 'the node was minted from the OVERRIDDEN decision, not the original');
});

test('E4/hook-3: opts.resolveSiteDecision returning undefined/null/falsy leaves site.decision untouched', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, { repository: 'r', resolveSiteDecision: () => undefined });
  assert.equal(r.sites[0].decision.kind, 'sink');
});

test('E4/args-1: enumerateSinkSites now carries each statement site\'s own call arguments', () => {
  const cg = irOf({ 'a.js': "function h(res, x){ res.send(x, 'literal'); }" });
  const { sites } = enumerateSinkSites(cg);
  assert.equal(sites.length, 1);
  assert.equal(sites[0].args.length, 2);
  assert.equal(sites[0].args[1].kind, 'literal');
});

test('E4/connected-1: buildDataFlowGraph stamps site.connected — true when a real flow reaches it, false when nothing does', () => {
  const cg = irOf({
    'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }",
    'b.js': "function noop(res){ res.send('static'); }",
  });
  const r = buildDataFlowGraph(cg, { repository: 'r' });
  const connectedSite = r.sites.find((s) => s.qid.includes('::h@'));
  const disconnectedSite = r.sites.find((s) => s.qid.includes('::noop@'));
  assert.equal(connectedSite.connected, true);
  assert.equal(disconnectedSite.connected, false);
});

// =========================================================================
// Milestone 2, Sub-project A, increment 1 (FR-202): the additive
// `opts.resolveDestination` hook — SEPARATE from `opts.resolveSiteDecision`
// above, applied at the same point. See DESIGN_DESTINATION_RESOLVER.md §4.
// =========================================================================

test('M2A1/hook-1: opts.resolveDestination is a no-op when omitted — byte-identical to a hardcoded pre-hook golden literal (destination stays null, destinationResolution stays unknown)', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const r = buildDataFlowGraph(cg, { repository: 'r' });
  assert.equal(r.graph.nodes.length, 1);
  assert.equal(r.graph.nodes[0].destination, null);
  assert.equal(r.sites[0].destination, undefined, 'site.destination is never set when the hook is omitted');
});

test('M2A1/hook-2: opts.resolveDestination, when it returns a value, sets node.destination and the connecting edge\'s protocol.destinationResolution', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const r = buildDataFlowGraph(cg, {
    repository: 'r',
    resolveDestination: () => ({ resolutionStatus: 'literal', raw: '"forced"', literalValue: 'forced', blockingExpression: null }),
  });
  const sinkNode = r.graph.nodes.find((n) => n.subtype === 'http-response');
  assert.ok(sinkNode);
  assert.deepEqual(sinkNode.destination, { resolutionStatus: 'literal', raw: '"forced"', literalValue: 'forced', blockingExpression: null });
  const edge = r.graph.edges.find((e) => e.to === sinkNode.id);
  assert.ok(edge, 'req.body.password must connect a source to this sink');
  assert.equal(edge.protocol.destinationResolution, 'literal');
});

test('M2A1/hook-3: opts.resolveDestination returning undefined/null/falsy leaves site.destination unset — node.destination stays null, edge stays unknown', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const r = buildDataFlowGraph(cg, { repository: 'r', resolveDestination: () => undefined });
  assert.equal(r.sites[0].destination, undefined);
  const sinkNode = r.graph.nodes.find((n) => n.subtype === 'http-response');
  assert.equal(sinkNode.destination, null);
  const edge = r.graph.edges.find((e) => e.to === sinkNode.id);
  assert.equal(edge.protocol.destinationResolution, 'unknown');
});

test('M2A1/hook-4: opts.resolveSiteDecision and opts.resolveDestination compose — a site can carry BOTH an overridden decision AND a resolved destination at once', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const r = buildDataFlowGraph(cg, {
    repository: 'r',
    resolveSiteDecision: (site) => ({ ...site.decision, kind: 'unresolved', externality: 'unknown', reason: 'forced for test' }),
    resolveDestination: () => ({ resolutionStatus: 'dynamic', raw: 'computed', literalValue: null, blockingExpression: 'computed' }),
  });
  assert.equal(r.sites[0].decision.kind, 'unresolved', 'resolveSiteDecision\'s override still applies');
  assert.equal(r.sites[0].destination.resolutionStatus, 'dynamic', 'resolveDestination\'s override applies independently, not clobbered by the decision override');
  const n = r.graph.nodes.find((x) => x.destination && x.destination.resolutionStatus === 'dynamic');
  assert.ok(n, 'the minted node carries both the overridden decision AND the resolved destination');
  assert.equal(n.externality.value, 'unknown', 'minted from the OVERRIDDEN decision');
});

// =========================================================================
// Milestone 2, Sub-project D, increment 2 (FR-307): the multi-path
// control-credit aggregation pass. See DESIGN_HANDLING_ANALYZER.md §5.
// =========================================================================

test('FR-307: the trivial `true` case is genuinely reachable — a transform that is the only relevant transform anywhere in its coarse (source, sink, dataElement) group applies to all paths that exist', () => {
  // The single-statement half of what E1/11 above uses — deliberately
  // WITHOUT the second, reshapeForVendor-reaching statement, so this
  // fixture's coarse group has exactly one transform id in play (E1/11's
  // own two-statement fixture puts maskCard and reshapeForVendor in the
  // SAME coarse group as each other, which is why both read `false` there
  // — see that test's own comment). Every flow group this fixture produces
  // (real interprocedural analysis yields more than one — a resolved
  // variant and an ambiguous-correlation variant — even for one textual
  // call site) carries the SAME transform id, so the conjunction is
  // trivially satisfied.
  const code = "function maskCard(pan){ return '****' + pan; }\n"
    + 'function handle(req, logger){\n'
    + '  const card = req.body.card_number;\n'
    + '  const masked = maskCard(card);\n'
    + '  logger.info(masked);\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'trivial-true.js': code }), { repository: 'tt' });
  assert.deepEqual(validateGraph(r.graph).errors, []);
  const maskT = r.graph.transformations.find((t) => t.callee === 'maskCard');
  assert.ok(maskT);
  assert.ok(r.graph.flows.length >= 2, 'sanity: this fixture genuinely produces more than one flow group, so `true` here is not vacuous over a single-group coarse key');
  for (const f of r.graph.flows) assert.ok(f.transformationIds.includes(maskT.id), 'every flow group in this fixture\'s coarse group carries the transform');
  assert.equal(maskT.appliesToAllPaths, true, 'a transform present on EVERY flow group sharing its coarse key must read true, not just non-false');
});

test('AC-12 (FR-307): a transform on ONE branch cannot make appliesToAllPaths true when a SIBLING branch to the SAME sink skips it', () => {
  // One field (req.body.card_number) reaches the SAME logger.info(...) sink
  // CATEGORY via two branches of an if/else: one masks first, the other
  // logs the raw value. `logger.info` matches on a receiver-name pattern
  // (privacy-catalog.js's `receiverTypeIn: ['log|logger|Logger']`, which
  // graph-builder.js's own `receiverJustified` deliberately treats as
  // vacuously satisfied, not a real receiver constraint — see that
  // function's own comment) so both call sites resolve to the identical
  // registry decision and therefore the identical, category-granular sink
  // NODE (§6.1) — confirmed below, not assumed, since AC-12's whole point
  // depends on it being genuinely the same sink.
  const code = "function maskCard(pan){ return '****' + pan; }\n"
    + 'function handle(req, logger, flag){\n'
    + '  const card = req.body.card_number;\n'
    + '  if (flag) {\n'
    + '    const masked = maskCard(card);\n'
    + '    logger.info(masked);\n'
    + '  } else {\n'
    + '    logger.info(card);\n'
    + '  }\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'ac12.js': code }), { repository: 'ac12' });
  assert.deepEqual(validateGraph(r.graph).errors, []);

  const sinkNodes = r.graph.nodes.filter((n) => n.kind === 'log');
  assert.equal(sinkNodes.length, 1, 'both branches\' logger.info(...) call sites must collapse onto ONE registry-decision node, not two — this is the precondition AC-12\'s own rule depends on');
  const snk = sinkNodes[0];

  const maskT = r.graph.transformations.find((t) => t.callee === 'maskCard');
  assert.ok(maskT, 'the masked branch\'s transform is a real, recognized entity');

  // The coarse group for (source, sink, card) contains at least one flow
  // WITH the transform (the masked branch) and at least one flow WITHOUT it
  // (the raw branch) — both sharing the same sink node.
  const coarseFlows = r.graph.flows.filter((f) => f.sink === snk.id);
  assert.ok(coarseFlows.length >= 2, 'both branches must produce real, distinct flow groups');
  assert.ok(coarseFlows.some((f) => f.transformationIds.includes(maskT.id)), 'the masked branch\'s flow carries the transform');
  assert.ok(coarseFlows.some((f) => !f.transformationIds.includes(maskT.id)), 'the raw branch\'s flow does NOT carry the transform');

  // AC-12's own literal claim: a transform on one branch cannot make the
  // full flow green. Proven here as the load-bearing SIGNAL this increment
  // computes — `appliesToAllPaths` false, never true, whenever a sibling
  // flow to the same sink skips the transform.
  assert.equal(maskT.appliesToAllPaths, false, 'AC-12: a transform present on only one of two sibling paths to the same sink must never read as applying to all paths');

  // §5's own scope boundary: this increment does NOT compute
  // flow.protectionSummary — it stays not_assessed on every flow, even the
  // masked one, since awarding an end-to-end verdict from appliesToAllPaths
  // alone is explicitly deferred to a later protection-verdict analyzer.
  for (const f of r.graph.flows) assert.equal(f.protectionSummary, 'not_assessed');
});

test('FR-307 (Sub-project D, increment 2): a transform genuinely present and reached on one COMPLETE path still loses control credit when a sibling path to the same sink is cut short by path-query.js\'s own depth budget before it could be checked', () => {
  // Reuses graph-builder.js's own pre-existing `opts.budget` passthrough to
  // path-query.js's `reconstructPaths` (E3's already-shipped mechanism,
  // not a new one this increment invents) to force a real depth-limit
  // truncation on one branch while a sibling branch to the SAME sink
  // completes and genuinely carries the transform. Both branches route
  // `req.body.card_number` through the SAME single `maskCard` call site
  // (inside the shared `wrap` helper) — the `long` branch pushes that call
  // site several hops further from the sink via a chain of identity calls,
  // so a tight `maxDepth` cuts the BACKWARD walk off before it ever reaches
  // the transform's own hop, while the `short` branch (few hops) still
  // reaches it cleanly.
  const code = "function id(v){ return v; }\n"
    + "function maskCard(pan){ return '****' + pan; }\n"
    + 'function wrap(pan){ return maskCard(pan); }\n'
    + 'function short(req, logger){\n'
    + '  const card = req.body.card_number;\n'
    + '  const masked = wrap(card);\n'
    + '  logger.info(masked);\n'
    + '}\n'
    + 'function long(req, logger){\n'
    + '  const card = req.body.card_number;\n'
    + '  const masked = wrap(card);\n'
    + '  const a1 = id(masked); const a2 = id(a1); const a3 = id(a2); const a4 = id(a3); const a5 = id(a4);\n'
    + '  logger.info(a5);\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'trunc.js': code }), { repository: 'trunc', budget: { maxDepth: 8 } });
  assert.deepEqual(validateGraph(r.graph).errors, []);

  const maskT = r.graph.transformations.find((t) => t.callee === 'maskCard');
  assert.ok(maskT, 'the single, shared maskCard call site is a real, recognized entity');

  const sinkNodes = r.graph.nodes.filter((n) => n.kind === 'log');
  assert.equal(sinkNodes.length, 1, 'short and long both reach the same registry-decision sink node');
  const coarseFlows = r.graph.flows.filter((f) => f.sink === sinkNodes[0].id);

  // A REAL, COMPLETE (non-truncated) flow genuinely carries the transform —
  // this is not a fixture where the transform was never reachable at all.
  const complete = coarseFlows.find((f) => f.transformationIds.includes(maskT.id)
    && !f.limitations.some((l) => l.includes('depth-limit')));
  assert.ok(complete, 'at least one flow group must reach the transform cleanly, with no truncation of any kind — proving the transform really is on a real path to this sink');

  // A SIBLING flow group to the identical sink was genuinely cut short by
  // the depth budget before the walk could reach the transform's own hop —
  // its own `sortedT` therefore never contains the transform id, not
  // because the transform doesn't apply there, but because the analyzer
  // never got to look.
  const truncatedSibling = coarseFlows.find((f) => !f.transformationIds.includes(maskT.id)
    && f.limitations.some((l) => l.includes('reconstruction truncated: depth-limit')));
  assert.ok(truncatedSibling, 'a sibling flow group to the same sink must have been genuinely truncated by the depth budget before reaching the transform');

  // The design doc's own load-bearing claim, proven rather than argued: no
  // special-case code is needed for this — the conservative AND over every
  // flow group in the coarse key already forces `false` the moment ANY
  // sibling's own `sortedT` lacks the id, truncated or not.
  assert.equal(maskT.appliesToAllPaths, false, 'a truncated sibling must conservatively deny control credit — the analyzer never proved the transform applies EVERYWHERE, so it must not claim that it does');
});
