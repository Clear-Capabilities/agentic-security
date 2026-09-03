// observation-correlation.js — M5 deliverable #7b, Task 2: the graph-ID
// match ladder (`matchObservationToGraph`) and the three-valued
// correlation layer (`correlateObservations`) where AC-29 clauses 1-4 are
// actually satisfied.
//
// Builds graphs with a small local `_graph()` helper (hand-built, NOT
// `buildDataFlowGraph`) — this module is pure and must be testable without
// the whole pipeline; a real end-to-end proof lands in Task 5. The shapes
// mirror the real ones read from `graph-builder.js` this session.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  matchObservationToGraph,
  correlateObservations,
} from '../../src/lineage/observation-correlation.js';
import { validateRuntimeObservation } from '../../src/lineage/runtime-observation.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LINEAGE_DIR = path.join(__dirname, '../../src/lineage');
const POSTURE_DIR = path.join(__dirname, '../../src/posture');

// ── Fixture helpers, matching the real shapes read from graph-builder.js ──

function _node(id, over = {}) {
  return {
    id, kind: 'external', subtype: 'external-api', label: 'x', aliases: [], location: null,
    system: { application: 'repo', environment: null },
    destination: null, storeDetail: null, queueDetail: null,
    externality: { value: 'external', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 0.9, tier: 'high' }, coverageStatus: 'modeled', coverageReason: null,
    ...over,
  };
}
function _edge(id, from, to) { return { id, from, to, relationship: 'data_flow', provenance: 'code' }; }
function _flow(id, source, sink, edgeIds) { return { id, source, sink, edgeIds, dataElementIds: [] }; }
function _graph(over = {}) {
  return {
    schemaVersion: '1.0.0', graphId: 'dfg:repo:uncommitted:default',
    nodes: [], edges: [], dataElements: [], flows: [], transformations: [], evidence: [], ...over,
  };
}

function _obs(over = {}) {
  return {
    id: 'observation:1',
    version: '1.0.0',
    adapter: 'native-jsonl',
    source: 'otel-collector',
    environment: 'production',
    windowStart: '2026-01-01T00:00:00.000Z',
    windowEnd: '2026-01-01T02:00:00.000Z',
    matchedNodeIds: [],
    matchedEdgeIds: [],
    matchedFlowIds: [],
    attributes: {},
    eventCountBand: '1',
    firstObservedAt: '2026-01-01T00:30:00.000Z',
    lastObservedAt: '2026-01-01T00:30:00.000Z',
    matchMethod: 'unmatched',
    matchConfidence: 'low',
    retention: { expiresAt: null },
    importedAt: '2026-01-01T01:00:00.000Z',
    ...over,
  };
}

function _deepFreeze(obj) {
  if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
    Object.freeze(obj);
    for (const key of Object.keys(obj)) _deepFreeze(obj[key]);
  }
  return obj;
}

function _deepFreezeGraph(graph) {
  for (const n of graph.nodes) _deepFreeze(n);
  for (const e of graph.edges) _deepFreeze(e);
  for (const f of graph.flows) _deepFreeze(f);
  for (const d of graph.dataElements) _deepFreeze(d);
  _deepFreeze(graph.nodes);
  _deepFreeze(graph.edges);
  _deepFreeze(graph.flows);
  _deepFreeze(graph.dataElements);
  return _deepFreeze(graph);
}

const STRIPE_LITERAL = 'https://api.stripe.com/v1/charges';
function _literalDestination(value, over = {}) {
  return { resolutionStatus: 'literal', raw: value, literalValue: value, blockingExpression: null, ...over };
}

// =====================================================================
// OC/1 — non-exclusion (AC-29 clause 3), the structural property.
// =====================================================================

test('OC/1a: correlateObservations over a deep-frozen graph does not throw and does not change any array length', () => {
  const src = _node('node:src', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const edge = _edge('edge:1', 'node:src', 'node:sink');
  const flow = _flow('flow:1', 'node:src', 'node:sink', ['edge:1']);
  const graph = _deepFreezeGraph(_graph({ nodes: [src, sink], edges: [edge], flows: [flow] }));

  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:frozen' });

  assert.doesNotThrow(() => correlateObservations(graph, [obs], {}));
  const before = { nodes: graph.nodes.length, edges: graph.edges.length, flows: graph.flows.length };
  correlateObservations(graph, [obs], {});
  assert.deepEqual({ nodes: graph.nodes.length, edges: graph.edges.length, flows: graph.flows.length }, before);
});

test('OC/1b: byFlow contains every flow id exactly once, 3 flows with only 1 observed', () => {
  const src = _node('node:src', { kind: 'source' });
  const sinkA = _node('node:sinkA', { destination: _literalDestination(STRIPE_LITERAL) });
  const sinkB = _node('node:sinkB');
  const sinkC = _node('node:sinkC');
  const flows = [
    _flow('flow:a', 'node:src', 'node:sinkA', ['edge:a']),
    _flow('flow:b', 'node:src', 'node:sinkB', ['edge:b']),
    _flow('flow:c', 'node:src', 'node:sinkC', ['edge:c']),
  ];
  const graph = _graph({
    nodes: [src, sinkA, sinkB, sinkC],
    edges: [_edge('edge:a', 'node:src', 'node:sinkA'), _edge('edge:b', 'node:src', 'node:sinkB'), _edge('edge:c', 'node:src', 'node:sinkC')],
    flows,
  });
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:1b' });
  const result = correlateObservations(graph, [obs], {});
  assert.deepEqual(Object.keys(result.byFlow).sort(), graph.flows.map((f) => f.id).sort());
  assert.equal(result.byFlow['flow:a'].layer, 'runtime_observed');
  assert.equal(result.byFlow['flow:b'].layer, 'not_observed_in_window');
  assert.equal(result.byFlow['flow:c'].layer, 'not_observed_in_window');
});

test('OC/1c: observedFlowIds/notObservedFlowIds/notEvaluatedFlowIds exactly partition the flow-id set, in all three evaluated states', () => {
  const src = _node('node:src', { kind: 'source' });
  const sinkA = _node('node:sinkA', { destination: _literalDestination(STRIPE_LITERAL) });
  const sinkB = _node('node:sinkB');
  const flows = [
    _flow('flow:a', 'node:src', 'node:sinkA', ['edge:a']),
    _flow('flow:b', 'node:src', 'node:sinkB', ['edge:b']),
  ];
  const graph = _graph({
    nodes: [src, sinkA, sinkB],
    edges: [_edge('edge:a', 'node:src', 'node:sinkA'), _edge('edge:b', 'node:src', 'node:sinkB')],
    flows,
  });
  const allIds = flows.map((f) => f.id).sort();

  function assertPartition(result) {
    const union = new Set([...result.observedFlowIds, ...result.notObservedFlowIds, ...result.notEvaluatedFlowIds]);
    assert.deepEqual([...union].sort(), allIds);
    const total = result.observedFlowIds.length + result.notObservedFlowIds.length + result.notEvaluatedFlowIds.length;
    assert.equal(total, allIds.length, 'no id counted twice — pairwise intersections empty');
  }

  assertPartition(correlateObservations(graph, null, {}));
  assertPartition(correlateObservations(graph, [], {}));
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assertPartition(correlateObservations(graph, [_obs({ ...match, id: 'observation:1c' })], {}));
});

// =====================================================================
// OC/2 — the match ladder (matchObservationToGraph).
// =====================================================================

test('OC/2a: rung 1 destination_literal/high matches a literal destination node', () => {
  const node = _node('node:x', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({ nodes: [node] });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assert.deepEqual(result.matchedNodeIds, ['node:x']);
  assert.equal(result.matchMethod, 'destination_literal');
  assert.equal(result.matchConfidence, 'high');
});

test('OC/2b: host comparison is case-insensitive; port ignored on both sides unless the observation supplies one, and a supplied port must match the literal\'s own explicit port', () => {
  const plain = _node('node:plain', { destination: _literalDestination(STRIPE_LITERAL) });
  const graphPlain = _graph({ nodes: [plain] });
  assert.deepEqual(
    matchObservationToGraph(graphPlain, { attributes: { 'destination.host': 'API.STRIPE.COM' } }).matchedNodeIds,
    ['node:plain'],
    'case-insensitive host match',
  );

  const withPort = _node('node:port', { destination: _literalDestination('https://api.stripe.com:8443/v1/charges') });
  const graphPort = _graph({ nodes: [withPort] });
  assert.deepEqual(
    matchObservationToGraph(graphPort, { attributes: { 'destination.host': 'api.stripe.com', 'destination.port': 8443 } }).matchedNodeIds,
    ['node:port'],
    'a matching explicit port on both sides matches',
  );
  assert.deepEqual(
    matchObservationToGraph(graphPort, { attributes: { 'destination.host': 'api.stripe.com', 'destination.port': 9999 } }).matchedNodeIds,
    [],
    'a mismatched explicit port is NOT a match',
  );
  assert.deepEqual(
    matchObservationToGraph(graphPlain, { attributes: { 'destination.host': 'api.stripe.com', 'destination.port': 443 } }).matchedNodeIds,
    [],
    'observation supplies a port but the literal carries none explicitly — a mismatch, never a wildcard match',
  );
});

test('OC/2c: a node whose destination.resolutionStatus is not \'literal\' never matches at rung 1', () => {
  const dynamicNode = _node('node:dyn', {
    destination: { resolutionStatus: 'dynamic', raw: 'fetch(url)', literalValue: null, blockingExpression: 'url' },
  });
  const nullDestNode = _node('node:null');
  const graph = _graph({ nodes: [dynamicNode, nullDestNode] });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assert.deepEqual(result, { matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [], matchMethod: 'unmatched', matchConfidence: 'low' });
});

test('OC/2d: rung 2 store_table/medium matches destination.service or schema.name case-insensitively against storeDetail.table', () => {
  const node = _node('node:store', { kind: 'store', destination: null, storeDetail: { table: 'User', operation: 'create', columns: ['email'] } });
  const graph = _graph({ nodes: [node] });

  const byService = matchObservationToGraph(graph, { attributes: { 'destination.service': 'user' } });
  assert.deepEqual(byService.matchedNodeIds, ['node:store']);
  assert.equal(byService.matchMethod, 'store_table');
  assert.equal(byService.matchConfidence, 'medium');

  const bySchema = matchObservationToGraph(graph, { attributes: { 'schema.name': 'USER' } });
  assert.deepEqual(bySchema.matchedNodeIds, ['node:store']);
  assert.equal(bySchema.matchMethod, 'store_table');
});

test('OC/2e: rung 3 queue_topic/medium matches an exact topic; a partial/substring topic does not match', () => {
  const topic = 'https://sqs.us-east-1.amazonaws.com/1/orders';
  const node = _node('node:queue', { kind: 'queue', destination: null, queueDetail: { provider: null, topic, operation: 'publish' } });
  const graph = _graph({ nodes: [node] });

  const exact = matchObservationToGraph(graph, { attributes: { 'destination.service': topic } });
  assert.deepEqual(exact.matchedNodeIds, ['node:queue']);
  assert.equal(exact.matchMethod, 'queue_topic');
  assert.equal(exact.matchConfidence, 'medium');

  // A substring match ('orders' alone) must NOT fire — substring matching
  // over a topic identifier is exactly how a false positive gets in (e.g.
  // 'orders' spuriously matching a sibling topic literally named
  // '.../orders-archive').
  const partial = matchObservationToGraph(graph, { attributes: { 'destination.service': 'orders' } });
  assert.equal(partial.matchMethod, 'unmatched');
  assert.deepEqual(partial.matchedNodeIds, []);
});

test('OC/2f: rungs are ordered — a rung-1 AND rung-2 candidate for one observation returns only the rung-1 node', () => {
  const literalNode = _node('node:literal', { destination: _literalDestination(STRIPE_LITERAL) });
  const storeNode = _node('node:store', { kind: 'store', destination: null, storeDetail: { table: 'user', operation: 'create', columns: [] } });
  const graph = _graph({ nodes: [literalNode, storeNode] });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com', 'destination.service': 'user' } });
  assert.deepEqual(result.matchedNodeIds, ['node:literal']);
  assert.equal(result.matchMethod, 'destination_literal');
});

test('OC/2g: ambiguity — two nodes both matching at rung 1 are BOTH returned, sorted, matchConfidence ambiguous', () => {
  const nodeA = _node('node:b-service', { destination: _literalDestination(STRIPE_LITERAL) });
  const nodeB = _node('node:a-service', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({ nodes: [nodeA, nodeB] });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assert.equal(result.matchedNodeIds.length, 2);
  assert.deepEqual(result.matchedNodeIds, ['node:a-service', 'node:b-service']);
  assert.equal(result.matchConfidence, 'ambiguous');
});

test('OC/2h: no match returns the honest all-empty unmatched shape', () => {
  const node = _node('node:x');
  const graph = _graph({ nodes: [node] });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'nowhere.example.com' } });
  assert.deepEqual(result, { matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [], matchMethod: 'unmatched', matchConfidence: 'low' });
});

test('OC/2i: matchedEdgeIds/matchedFlowIds derive from `to`/`sink` membership, sorted and deduplicated', () => {
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const other = _node('node:other');
  const src1 = _node('node:src1', { kind: 'source' });
  const src2 = _node('node:src2', { kind: 'source' });
  const src3 = _node('node:src3', { kind: 'source' });
  const graph = _graph({
    nodes: [sink, other, src1, src2, src3],
    edges: [
      _edge('edge:2', 'node:src2', 'node:sink'),
      _edge('edge:1', 'node:src1', 'node:sink'),
      _edge('edge:3', 'node:src3', 'node:other'),
    ],
    flows: [
      _flow('flow:2', 'node:src2', 'node:sink', ['edge:2']),
      _flow('flow:1', 'node:src1', 'node:sink', ['edge:1']),
      _flow('flow:3', 'node:src3', 'node:other', ['edge:3']),
    ],
  });
  const result = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assert.deepEqual(result.matchedNodeIds, ['node:sink']);
  assert.deepEqual(result.matchedEdgeIds, ['edge:1', 'edge:2']);
  assert.deepEqual(result.matchedFlowIds, ['flow:1', 'flow:2']);
});

test('OC/2j: matchObservationToGraph composed into a full record passes validateRuntimeObservation for matched, unmatched, and ambiguous cases', () => {
  const single = _node('node:single', { destination: _literalDestination(STRIPE_LITERAL) });
  const dup1 = _node('node:dup1', { destination: _literalDestination('https://svc.example.com/x') });
  const dup2 = _node('node:dup2', { destination: _literalDestination('https://svc.example.com/x') });

  const matched = matchObservationToGraph(_graph({ nodes: [single] }), { attributes: { 'destination.host': 'api.stripe.com' } });
  const unmatched = matchObservationToGraph(_graph({ nodes: [single] }), { attributes: { 'destination.host': 'nowhere.example.com' } });
  const ambiguous = matchObservationToGraph(_graph({ nodes: [dup1, dup2] }), { attributes: { 'destination.host': 'svc.example.com' } });

  for (const [label, m] of [['matched', matched], ['unmatched', unmatched], ['ambiguous', ambiguous]]) {
    const record = _obs({ ...m, id: `observation:${label}` });
    const { valid, errors } = validateRuntimeObservation(record);
    assert.equal(valid, true, `${label}: ${JSON.stringify(errors)}`);
  }
});

test('OC/2k: matchObservationToGraph never throws on malformed input', () => {
  assert.doesNotThrow(() => matchObservationToGraph(null, null));
  assert.doesNotThrow(() => matchObservationToGraph(_graph(), {}));
  assert.doesNotThrow(() => matchObservationToGraph(_graph(), { attributes: null }));
  assert.doesNotThrow(() => matchObservationToGraph({ nodes: null }, { attributes: {} }));

  assert.deepEqual(matchObservationToGraph(null, null), { matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [], matchMethod: 'unmatched', matchConfidence: 'low' });
  assert.deepEqual(matchObservationToGraph(_graph(), {}).matchMethod, 'unmatched');
  assert.deepEqual(matchObservationToGraph(_graph(), { attributes: null }).matchMethod, 'unmatched');
  assert.deepEqual(matchObservationToGraph({ nodes: null }, { attributes: {} }).matchMethod, 'unmatched');
});

// =====================================================================
// OC/3 — the environment filter.
// =====================================================================

function _oneFlowGraph() {
  const src = _node('node:src', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  return _graph({
    nodes: [src, sink],
    edges: [_edge('edge:1', 'node:src', 'node:sink')],
    flows: [_flow('flow:1', 'node:src', 'node:sink', ['edge:1'])],
  });
}

test('OC/3a: opts.environment === null considers every observation regardless of its own environment', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:staging', environment: 'staging' });
  const result = correlateObservations(graph, [obs], { environment: null });
  assert.equal(result.byFlow['flow:1'].layer, 'runtime_observed');
  assert.deepEqual(result.consideredObservationIds, ['observation:staging']);
});

test('OC/3b: opts.environment scopes out a differently-environmented observation into otherEnvironmentObservationIds, never considered', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:staging', environment: 'staging' });
  const result = correlateObservations(graph, [obs], { environment: 'production' });
  assert.deepEqual(result.otherEnvironmentObservationIds, ['observation:staging']);
  assert.deepEqual(result.consideredObservationIds, []);
  assert.equal(result.byFlow['flow:1'].layer, 'not_observed_in_window');
});

test('OC/3c: the environment comparison is exact and case-sensitive', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  // An operator's own environment names are theirs — fuzzy-matching them
  // would silently merge two genuinely distinct environments.
  const obs = _obs({ ...match, id: 'observation:cap', environment: 'Production' });
  const result = correlateObservations(graph, [obs], { environment: 'production' });
  assert.deepEqual(result.otherEnvironmentObservationIds, ['observation:cap']);
  assert.equal(result.byFlow['flow:1'].layer, 'not_observed_in_window');
});

// =====================================================================
// OC/4 — the window filter.
// =====================================================================

test('OC/4a: both windowStart and windowEnd null means every observation is in-window', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:1', windowStart: '2020-01-01T00:00:00.000Z', windowEnd: '2020-01-01T01:00:00.000Z', firstObservedAt: '2020-01-01T00:30:00.000Z', lastObservedAt: '2020-01-01T00:30:00.000Z' });
  const result = correlateObservations(graph, [obs], { windowStart: null, windowEnd: null });
  assert.deepEqual(result.consideredObservationIds, ['observation:1']);
  assert.equal(result.byFlow['flow:1'].layer, 'runtime_observed');
});

test('OC/4b: an observation window with no intersection to the requested window is out-of-window', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:old', windowStart: '2020-01-01T00:00:00.000Z', windowEnd: '2020-01-01T01:00:00.000Z', firstObservedAt: '2020-01-01T00:30:00.000Z', lastObservedAt: '2020-01-01T00:30:00.000Z' });
  const result = correlateObservations(graph, [obs], { windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-01T01:00:00.000Z' });
  assert.deepEqual(result.outOfWindowObservationIds, ['observation:old']);
  assert.equal(result.byFlow['flow:1'].layer, 'not_observed_in_window');
});

test('OC/4c: a partially-overlapping observation window IS considered (interval overlap, not containment)', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  // Observation window straddles opts.windowStart: starts before, ends after.
  const obs = _obs({
    ...match, id: 'observation:straddle',
    windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-01T02:00:00.000Z',
    firstObservedAt: '2026-01-01T00:30:00.000Z', lastObservedAt: '2026-01-01T01:30:00.000Z',
  });
  const result = correlateObservations(graph, [obs], { windowStart: '2026-01-01T01:00:00.000Z', windowEnd: '2026-01-01T03:00:00.000Z' });
  assert.deepEqual(result.consideredObservationIds, ['observation:straddle']);
});

test('OC/4d: a half-open window filter (only windowStart, or only windowEnd) behaves correctly', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const late = _obs({
    ...match, id: 'observation:late',
    windowStart: '2030-01-01T00:00:00.000Z', windowEnd: '2030-01-01T01:00:00.000Z',
    firstObservedAt: '2030-01-01T00:30:00.000Z', lastObservedAt: '2030-01-01T00:30:00.000Z',
  });
  // Only windowStart given: open-ended end — an observation far in the
  // future is still in-window.
  const openEnd = correlateObservations(graph, [late], { windowStart: '2026-01-01T00:00:00.000Z', windowEnd: null });
  assert.deepEqual(openEnd.consideredObservationIds, ['observation:late']);

  const early = _obs({
    ...match, id: 'observation:early',
    windowStart: '2000-01-01T00:00:00.000Z', windowEnd: '2000-01-01T01:00:00.000Z',
    firstObservedAt: '2000-01-01T00:30:00.000Z', lastObservedAt: '2000-01-01T00:30:00.000Z',
  });
  // Only windowEnd given: open-ended start — an observation far in the
  // past is still in-window.
  const openStart = correlateObservations(graph, [early], { windowStart: null, windowEnd: '2026-01-01T00:00:00.000Z' });
  assert.deepEqual(openStart.consideredObservationIds, ['observation:early']);

  // And the boundary still excludes something genuinely outside it.
  const tooLate = correlateObservations(graph, [late], { windowStart: null, windowEnd: '2026-01-01T00:00:00.000Z' });
  assert.deepEqual(tooLate.outOfWindowObservationIds, ['observation:late']);
});

// =====================================================================
// OC/5 — the three-valued layer (AC-29 clause 2, PRD line 2098).
// =====================================================================

function _pinGraph() {
  const src = _node('node:src', { kind: 'source' });
  const sinkA = _node('node:sinkA');
  const sinkB = _node('node:sinkB');
  return _graph({
    nodes: [src, sinkA, sinkB],
    edges: [_edge('edge:a', 'node:src', 'node:sinkA'), _edge('edge:b', 'node:src', 'node:sinkB')],
    flows: [_flow('flow:a', 'node:src', 'node:sinkA', ['edge:a']), _flow('flow:b', 'node:src', 'node:sinkB', ['edge:b'])],
  });
}

test('OC/5a: correlateObservations(graph, null, {}) pins the not_evaluated case as literal JSON', () => {
  const result = correlateObservations(_pinGraph(), null, {});
  assert.deepEqual(result, {
    version: '1.0.0',
    evaluated: false,
    environment: null,
    windowStart: null,
    windowEnd: null,
    observedNodeIds: [],
    observedEdgeIds: [],
    observedFlowIds: [],
    notObservedFlowIds: [],
    notEvaluatedFlowIds: ['flow:a', 'flow:b'],
    byFlow: {
      'flow:a': { layer: 'not_evaluated', observationIds: [], matchMethod: null, matchConfidence: null, environment: null, windowStart: null, windowEnd: null, firstObservedAt: null, lastObservedAt: null, eventCountBand: null, siblingFlowCount: 0, contributingEnvironments: [] },
      'flow:b': { layer: 'not_evaluated', observationIds: [], matchMethod: null, matchConfidence: null, environment: null, windowStart: null, windowEnd: null, firstObservedAt: null, lastObservedAt: null, eventCountBand: null, siblingFlowCount: 0, contributingEnvironments: [] },
    },
    consideredObservationIds: [],
    outOfWindowObservationIds: [],
    otherEnvironmentObservationIds: [],
    unmatchedObservationIds: [],
    invalidObservationIds: [],
    limitations: [
      'No runtime observation store was consulted for this correlation — every flow is reported '
      + 'not_evaluated, never not_observed_in_window; the two are deliberately different answers '
      + '(PRD line 2098).',
    ],
  });
});

test('OC/5b: correlateObservations(graph, [], {}) pins the evaluated-but-empty case as literal JSON', () => {
  const result = correlateObservations(_pinGraph(), [], {});
  assert.deepEqual(result, {
    version: '1.0.0',
    evaluated: true,
    environment: null,
    windowStart: null,
    windowEnd: null,
    observedNodeIds: [],
    observedEdgeIds: [],
    observedFlowIds: [],
    notObservedFlowIds: ['flow:a', 'flow:b'],
    notEvaluatedFlowIds: [],
    byFlow: {
      'flow:a': { layer: 'not_observed_in_window', observationIds: [], matchMethod: null, matchConfidence: null, environment: null, windowStart: null, windowEnd: null, firstObservedAt: null, lastObservedAt: null, eventCountBand: null, siblingFlowCount: 0, contributingEnvironments: [] },
      'flow:b': { layer: 'not_observed_in_window', observationIds: [], matchMethod: null, matchConfidence: null, environment: null, windowStart: null, windowEnd: null, firstObservedAt: null, lastObservedAt: null, eventCountBand: null, siblingFlowCount: 0, contributingEnvironments: [] },
    },
    consideredObservationIds: [],
    outOfWindowObservationIds: [],
    otherEnvironmentObservationIds: [],
    unmatchedObservationIds: [],
    invalidObservationIds: [],
    limitations: [
      'No runtime observation matched any flow in the requested environment/window — the absence of '
      + 'a runtime observation is not evidence a flow did not occur (PRD line 2098).',
    ],
  });
});

test('OC/5c: a store never consulted and a store consulted-and-empty are different answers, distinguishable under JSON.stringify', () => {
  const graph = _pinGraph();
  const notEvaluated = correlateObservations(graph, null, {});
  const evaluatedEmpty = correlateObservations(graph, [], {});
  assert.notDeepEqual(notEvaluated, evaluatedEmpty);
  assert.notEqual(JSON.stringify(notEvaluated), JSON.stringify(evaluatedEmpty));
});

test('OC/5d: undefined behaves identically to null', () => {
  const graph = _pinGraph();
  const withNull = correlateObservations(graph, null, {});
  const withUndefined = correlateObservations(graph, undefined, {});
  assert.deepEqual(withNull, withUndefined);
});

// =====================================================================
// OC/6 — AC-29's own two-flow scenario, end to end.
// =====================================================================

test('OC/6a: AC-29\'s given/then transcribed — one observed flow, one not, both present, neither node dropped', () => {
  const src = _node('node:src', { kind: 'source' });
  const nodeA = _node('node:a', { destination: _literalDestination(STRIPE_LITERAL) });
  const nodeB = _node('node:b', { destination: _literalDestination('https://other.example.com/x') });
  const graph = _graph({
    nodes: [src, nodeA, nodeB],
    edges: [_edge('edge:a', 'node:src', 'node:a'), _edge('edge:b', 'node:src', 'node:b')],
    flows: [_flow('flow:a', 'node:src', 'node:a', ['edge:a']), _flow('flow:b', 'node:src', 'node:b', ['edge:b'])],
  });
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:ac29' });
  const result = correlateObservations(graph, [obs], {});

  assert.equal(result.byFlow['flow:a'].layer, 'runtime_observed');
  assert.equal(result.byFlow['flow:b'].layer, 'not_observed_in_window');
  assert.deepEqual(Object.keys(result.byFlow).sort(), ['flow:a', 'flow:b']);
  assert.ok(graph.nodes.some((n) => n.id === 'node:a'));
  assert.ok(graph.nodes.some((n) => n.id === 'node:b'));

  const entryA = result.byFlow['flow:a'];
  assert.notEqual(entryA.matchMethod, null);
  assert.notEqual(entryA.matchConfidence, null);
  assert.notEqual(entryA.environment, null);
  assert.notEqual(entryA.windowStart, null);
  assert.notEqual(entryA.windowEnd, null);
});

// =====================================================================
// OC/7 — clause 4, method and confidence travel with the match.
// =====================================================================

test('OC/7a: every runtime_observed entry has all non-null fields; every non-observed entry has all null fields', () => {
  const graph = _pinGraph(); // flow:a has a matching sink node destination once we set it below
  graph.nodes.find((n) => n.id === 'node:sinkA').destination = _literalDestination(STRIPE_LITERAL);
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:7a' });
  const result = correlateObservations(graph, [obs], {});

  const observed = result.byFlow['flow:a'];
  for (const field of ['matchMethod', 'matchConfidence', 'environment', 'windowStart', 'windowEnd', 'firstObservedAt', 'lastObservedAt', 'eventCountBand']) {
    assert.notEqual(observed[field], null, `observed.${field} must be non-null`);
  }

  const unobserved = result.byFlow['flow:b'];
  for (const field of ['matchMethod', 'matchConfidence', 'environment', 'windowStart', 'windowEnd', 'firstObservedAt', 'lastObservedAt', 'eventCountBand']) {
    assert.equal(unobserved[field], null, `unobserved.${field} must be null`);
  }
});

test('OC/7b: two observations matching the same (non-shared-sink) flow fold deterministically', () => {
  const src = _node('node:src', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({
    nodes: [src, sink],
    edges: [_edge('edge:1', 'node:src', 'node:sink')],
    flows: [_flow('flow:only', 'node:src', 'node:sink', ['edge:1'])], // exactly one flow at this sink — no sibling demotion
  });

  const obsHigh = _obs({
    id: 'observation:h2', matchMethod: 'store_table', matchConfidence: 'high',
    matchedNodeIds: ['node:sink'], matchedEdgeIds: ['edge:1'], matchedFlowIds: ['flow:only'],
    windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-01T01:00:00.000Z',
    firstObservedAt: '2026-01-01T00:10:00.000Z', lastObservedAt: '2026-01-01T00:10:00.000Z',
    eventCountBand: '1',
  });
  // matchMethod 'destination_literal' sorts before 'store_table' in
  // RUNTIME_MATCH_METHODS — used below to prove the tie-break rule.
  const obsAmbiguous = _obs({
    id: 'observation:h1', matchMethod: 'destination_literal', matchConfidence: 'ambiguous',
    matchedNodeIds: ['node:sink', 'node:other'], matchedEdgeIds: ['edge:1', 'edge:2'], matchedFlowIds: ['flow:only'],
    windowStart: '2026-01-01T00:00:00.000Z', windowEnd: '2026-01-01T01:00:00.000Z',
    firstObservedAt: '2026-01-01T00:05:00.000Z', lastObservedAt: '2026-01-01T00:20:00.000Z',
    eventCountBand: '11-100',
  });

  const result = correlateObservations(graph, [obsHigh, obsAmbiguous], {});
  const entry = result.byFlow['flow:only'];
  assert.equal(entry.siblingFlowCount, 0);
  assert.deepEqual(entry.observationIds, ['observation:h1', 'observation:h2']);
  // Worst confidence across contributors: 'ambiguous' beats 'high'.
  assert.equal(entry.matchConfidence, 'ambiguous');
  // firstObservedAt earliest, lastObservedAt latest across contributors.
  assert.equal(entry.firstObservedAt, '2026-01-01T00:05:00.000Z');
  assert.equal(entry.lastObservedAt, '2026-01-01T00:20:00.000Z');
  // Highest event-count band present.
  assert.equal(entry.eventCountBand, '11-100');
  // matchMethod is the method of the STRONGEST-confidence observation
  // (obsHigh, 'high' beats 'ambiguous'), never a positional/last-write pick.
  assert.equal(entry.matchMethod, 'store_table');
});

test('OC/7b-tiebreak: a tie in confidence breaks by RUNTIME_MATCH_METHODS order for a deterministic matchMethod', () => {
  const src = _node('node:src', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({
    nodes: [src, sink],
    edges: [_edge('edge:1', 'node:src', 'node:sink')],
    flows: [_flow('flow:only', 'node:src', 'node:sink', ['edge:1'])],
  });
  // Both 'high' confidence — tie broken by RUNTIME_MATCH_METHODS order:
  // 'destination_literal' sorts before 'store_table'.
  const obsStore = _obs({
    id: 'observation:store', matchMethod: 'store_table', matchConfidence: 'high',
    matchedNodeIds: ['node:sink'], matchedFlowIds: ['flow:only'],
  });
  const obsLiteral = _obs({
    id: 'observation:literal', matchMethod: 'destination_literal', matchConfidence: 'high',
    matchedNodeIds: ['node:sink'], matchedFlowIds: ['flow:only'],
  });
  const result = correlateObservations(graph, [obsStore, obsLiteral], {});
  assert.equal(result.byFlow['flow:only'].matchMethod, 'destination_literal');
});

// =====================================================================
// OC/8 — Correction 4, sibling-flow honesty.
// =====================================================================

test('OC/8a: one observation matching a sink node with THREE flows demotes all three to ambiguous with siblingFlowCount 2', () => {
  const src1 = _node('node:src1', { kind: 'source' });
  const src2 = _node('node:src2', { kind: 'source' });
  const src3 = _node('node:src3', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({
    nodes: [src1, src2, src3, sink],
    edges: [
      _edge('edge:1', 'node:src1', 'node:sink'),
      _edge('edge:2', 'node:src2', 'node:sink'),
      _edge('edge:3', 'node:src3', 'node:sink'),
    ],
    flows: [
      _flow('flow:1', 'node:src1', 'node:sink', ['edge:1']),
      _flow('flow:2', 'node:src2', 'node:sink', ['edge:2']),
      _flow('flow:3', 'node:src3', 'node:sink', ['edge:3']),
    ],
  });
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  assert.equal(match.matchConfidence, 'high', 'sanity: exactly one node matched, so the observation record itself is high-confidence');
  const obs = _obs({ ...match, id: 'observation:8a' });

  const result = correlateObservations(graph, [obs], {});
  for (const fid of ['flow:1', 'flow:2', 'flow:3']) {
    const entry = result.byFlow[fid];
    assert.equal(entry.layer, 'runtime_observed');
    assert.equal(entry.siblingFlowCount, 2);
    assert.equal(entry.matchConfidence, 'ambiguous');
  }
  // The observation record itself is never rewritten — the demotion is a
  // property of the per-flow answer, not a mutation of the evidence.
  assert.equal(obs.matchConfidence, 'high');
});

test('OC/8b: the same observation against a node with exactly ONE flow keeps high confidence and siblingFlowCount 0', () => {
  const src = _node('node:src', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const graph = _graph({
    nodes: [src, sink],
    edges: [_edge('edge:1', 'node:src', 'node:sink')],
    flows: [_flow('flow:1', 'node:src', 'node:sink', ['edge:1'])],
  });
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:8b' });
  const result = correlateObservations(graph, [obs], {});
  const entry = result.byFlow['flow:1'];
  assert.equal(entry.matchConfidence, 'high');
  assert.equal(entry.siblingFlowCount, 0);
});

// =====================================================================
// OC/9 — boundaries.
// =====================================================================

test('OC/9a: the module\'s static import specifier list is exactly [\'./runtime-observation.js\'], no dynamic import(, no node:fs', () => {
  const modulePath = path.join(LINEAGE_DIR, 'observation-correlation.js');
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['./runtime-observation.js']);
  assert.ok(!/\bimport\s*\(/.test(src), 'no dynamic import(');
  assert.ok(!src.includes('node:fs'), 'no node:fs import');
});

test('OC/9b: remediation-separation import guard — neither remediation module ever imports the runtime-observation family, nor the reverse', () => {
  const OBSERVATION_FILES = ['runtime-observation.js', 'observation-correlation.js', 'observation-store.js', 'observation-adapters.js'];

  const remediationSrc = fs.readFileSync(path.join(LINEAGE_DIR, 'remediation.js'), 'utf8');
  const remediationLedgerSrc = fs.readFileSync(path.join(POSTURE_DIR, 'remediation-ledger.js'), 'utf8');
  for (const f of OBSERVATION_FILES) {
    assert.ok(!remediationSrc.includes(`'./${f}'`), `remediation.js must not import ${f}`);
    assert.ok(!remediationLedgerSrc.includes(`/${f}'`), `remediation-ledger.js must not import ${f}`);
  }

  // The reverse direction, checked for every one of the four files that
  // actually exists today (observation-store.js/observation-adapters.js
  // are Task 3/4 — this loop picks them up automatically once they land).
  for (const f of OBSERVATION_FILES) {
    const p = path.join(LINEAGE_DIR, f);
    if (!fs.existsSync(p)) continue;
    const src = fs.readFileSync(p, 'utf8');
    assert.ok(!src.includes("'./remediation.js'"), `${f} must not import remediation.js`);
    assert.ok(!src.includes('remediation-ledger.js'), `${f} must not import remediation-ledger.js`);
  }
});

test('OC/9c: an observation failing validateRuntimeObservation lands in invalidObservationIds, never considered/observed/out-of-window', () => {
  const graph = _oneFlowGraph();
  const malformedWithId = { id: 'observation:bad', notARealField: true };
  const malformedNoId = { notARealField: true };
  const result = correlateObservations(graph, [malformedWithId, malformedNoId], {});
  assert.deepEqual(result.invalidObservationIds.sort(), ['(no id)', 'observation:bad']);
  assert.deepEqual(result.consideredObservationIds, []);
  assert.deepEqual(result.outOfWindowObservationIds, []);
  assert.deepEqual(result.otherEnvironmentObservationIds, []);
  assert.deepEqual(result.observedFlowIds, []);
  assert.equal(result.evaluated, true);
  assert.equal(result.byFlow['flow:1'].layer, 'not_observed_in_window');
});

test('OC/9c-neighbour: a stale matchedFlowIds entry (no longer present in the graph) is dropped and disclosed, never attributed', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:stale', matchedFlowIds: [...match.matchedFlowIds, 'flow:no-longer-exists'] });
  const result = correlateObservations(graph, [obs], {});
  assert.equal(result.byFlow['flow:1'].layer, 'runtime_observed');
  assert.ok(result.limitations.some((l) => l.includes('stale')), 'limitations discloses the stale drop');

  // An observation whose ENTIRE matchedFlowIds list is stale is
  // considered but unmatched — never silently promoted.
  const whollyStaleObs = _obs({ id: 'observation:wholly-stale', matchMethod: 'destination_literal', matchConfidence: 'high', matchedNodeIds: ['node:sink'], matchedFlowIds: ['flow:no-longer-exists'] });
  const result2 = correlateObservations(graph, [whollyStaleObs], {});
  assert.deepEqual(result2.unmatchedObservationIds, ['observation:wholly-stale']);
  assert.deepEqual(result2.consideredObservationIds, ['observation:wholly-stale']);
  assert.equal(result2.byFlow['flow:1'].layer, 'not_observed_in_window');
});

test('OC/9c-invalid-list: a whole list of invalid observations still returns evaluated: true with every flow not_observed_in_window', () => {
  const graph = _oneFlowGraph();
  // Two distinct id-bearing malformed records plus two id-less ones —
  // invalidObservationIds is deduplicated (like every other id list this
  // module returns), so the id-less pair collapses to one '(no id)' entry.
  const result = correlateObservations(graph, [
    { garbage: 1, id: 'observation:bad1' },
    { garbage: 1, id: 'observation:bad2' },
    'not an object',
    42,
    null,
  ], {});
  assert.equal(result.evaluated, true);
  assert.equal(result.byFlow['flow:1'].layer, 'not_observed_in_window');
  assert.deepEqual(result.invalidObservationIds, ['(no id)', 'observation:bad1', 'observation:bad2']);
  assert.deepEqual(result.consideredObservationIds, []);
  assert.deepEqual(result.observedFlowIds, []);
});

test('OC/9d: correlateObservations never throws on malformed input', () => {
  assert.doesNotThrow(() => correlateObservations(null, null, null));
  assert.doesNotThrow(() => correlateObservations({}, [], {}));
  assert.doesNotThrow(() => correlateObservations({ flows: null }, [_obs()], {}));
  assert.doesNotThrow(() => correlateObservations(_graph(), 'x', {}));

  const r1 = correlateObservations(null, null, null);
  assert.equal(r1.evaluated, false);
  const r4 = correlateObservations(_graph(), 'x', {});
  assert.equal(r4.evaluated, true);
});

// =====================================================================
// OC/10 — limitations honesty.
// =====================================================================

const NO_STORE_SUBSTR = 'no runtime observation store was consulted';
const NON_OBSERVATION_SUBSTR = 'absence of';
const NODE_GRANULARITY_SUBSTR = 'node-granularity boundary';

test('OC/10a: each limitations string is present exactly in its case, and absent in the others', () => {
  const graph = _pinGraph();

  const notEvaluated = correlateObservations(graph, null, {});
  assert.ok(notEvaluated.limitations.some((l) => l.toLowerCase().includes(NO_STORE_SUBSTR)));
  assert.ok(!notEvaluated.limitations.some((l) => l.toLowerCase().includes(NON_OBSERVATION_SUBSTR)));
  assert.ok(!notEvaluated.limitations.some((l) => l.includes(NODE_GRANULARITY_SUBSTR)));

  const evaluatedEmpty = correlateObservations(graph, [], {});
  assert.ok(!evaluatedEmpty.limitations.some((l) => l.toLowerCase().includes(NO_STORE_SUBSTR)));
  assert.ok(evaluatedEmpty.limitations.some((l) => l.toLowerCase().includes(NON_OBSERVATION_SUBSTR)));
  assert.ok(!evaluatedEmpty.limitations.some((l) => l.includes(NODE_GRANULARITY_SUBSTR)));

  // A graph where a sink is shared by two flows, one observation matching it
  // — the sibling-demotion limitation appears, and (since something WAS
  // observed) the "no matches at all" limitation does not.
  const src1 = _node('node:src1', { kind: 'source' });
  const src2 = _node('node:src2', { kind: 'source' });
  const sink = _node('node:sink', { destination: _literalDestination(STRIPE_LITERAL) });
  const siblingGraph = _graph({
    nodes: [src1, src2, sink],
    edges: [_edge('edge:1', 'node:src1', 'node:sink'), _edge('edge:2', 'node:src2', 'node:sink')],
    flows: [_flow('flow:1', 'node:src1', 'node:sink', ['edge:1']), _flow('flow:2', 'node:src2', 'node:sink', ['edge:2'])],
  });
  const match = matchObservationToGraph(siblingGraph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:sibling' });
  const siblingResult = correlateObservations(siblingGraph, [obs], {});
  assert.ok(siblingResult.limitations.some((l) => l.includes(NODE_GRANULARITY_SUBSTR)));
  assert.ok(!siblingResult.limitations.some((l) => l.toLowerCase().includes(NO_STORE_SUBSTR)));
  assert.ok(!siblingResult.limitations.some((l) => l.toLowerCase().includes(NON_OBSERVATION_SUBSTR)));

  // A one-flow graph with a real, unshared match: none of the three
  // limitation strings should appear at all.
  const cleanGraph = _oneFlowGraph();
  const cleanMatch = matchObservationToGraph(cleanGraph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const cleanResult = correlateObservations(cleanGraph, [_obs({ ...cleanMatch, id: 'observation:clean' })], {});
  assert.ok(!cleanResult.limitations.some((l) => l.toLowerCase().includes(NO_STORE_SUBSTR)));
  assert.ok(!cleanResult.limitations.some((l) => l.toLowerCase().includes(NON_OBSERVATION_SUBSTR)));
  assert.ok(!cleanResult.limitations.some((l) => l.includes(NODE_GRANULARITY_SUBSTR)));
});

// =====================================================================
// OC/11 — I2 (final review): a multi-observation byFlow entry is scoped
// to the representative's OWN environment, and discloses the rest.
// =====================================================================

test('OC/11a: the final review\'s own exact repro — production window Aug 1-10 band 1, staging window Aug 15-25 band 1k+ — the resulting entry draws every aggregate from production only, with contributingEnvironments naming both', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });

  const production = _obs({
    ...match, id: 'observation:production',
    environment: 'production', matchConfidence: 'high',
    windowStart: '2026-08-01T00:00:00.000Z', windowEnd: '2026-08-10T00:00:00.000Z',
    firstObservedAt: '2026-08-01T05:00:00.000Z', lastObservedAt: '2026-08-09T05:00:00.000Z',
    eventCountBand: '1',
  });
  const staging = _obs({
    ...match, id: 'observation:staging',
    environment: 'staging', matchConfidence: 'high',
    windowStart: '2026-08-15T00:00:00.000Z', windowEnd: '2026-08-25T00:00:00.000Z',
    firstObservedAt: '2026-08-15T05:00:00.000Z', lastObservedAt: '2026-08-20T11:00:00.000Z',
    eventCountBand: '1k+',
  });

  // No opts.environment filter, so both are considered — the production/
  // staging split happens entirely inside the fold, not the filter.
  const result = correlateObservations(graph, [production, staging], {});
  const entry = result.byFlow['flow:1'];

  assert.equal(entry.layer, 'runtime_observed');
  assert.equal(entry.environment, 'production', 'the representative — both are matchConfidence high, tie broken by matchMethod order');
  assert.equal(entry.windowStart, '2026-08-01T00:00:00.000Z');
  assert.equal(entry.windowEnd, '2026-08-10T00:00:00.000Z');
  // The bug this closes: these three used to aggregate across BOTH
  // contributors, so lastObservedAt (Aug 20) landed OUTSIDE the window
  // shown one line above (Aug 1-10), and eventCountBand read staging's
  // '1k+' under a "production" header.
  assert.equal(entry.firstObservedAt, '2026-08-01T05:00:00.000Z');
  assert.equal(entry.lastObservedAt, '2026-08-09T05:00:00.000Z', 'must never be staging\'s Aug 20 timestamp — that is now excluded, scoped to production only');
  assert.equal(entry.eventCountBand, '1', 'must never be staging\'s 1k+ band under a production header');
  assert.deepEqual(entry.contributingEnvironments, ['production', 'staging'], 'the full set of contributing environments must still be disclosed');

  assert.ok(
    result.limitations.some((l) => l.includes('more than one environment')),
    'a multi-environment contribution must be disclosed in limitations',
  );
});

test('OC/11b: a single-environment flow carries contributingEnvironments with exactly that one environment, and no multi-environment limitation fires', () => {
  const graph = _oneFlowGraph();
  const match = matchObservationToGraph(graph, { attributes: { 'destination.host': 'api.stripe.com' } });
  const obs = _obs({ ...match, id: 'observation:single', environment: 'production' });
  const result = correlateObservations(graph, [obs], {});
  assert.deepEqual(result.byFlow['flow:1'].contributingEnvironments, ['production']);
  assert.ok(!result.limitations.some((l) => l.includes('more than one environment')));
});

test('OC/11c: a flow with zero contributions carries contributingEnvironments: [] (never null)', () => {
  const graph = _oneFlowGraph();
  const result = correlateObservations(graph, [], {});
  assert.deepEqual(result.byFlow['flow:1'].contributingEnvironments, []);
});
