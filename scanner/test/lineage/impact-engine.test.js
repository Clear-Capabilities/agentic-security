import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeImpactAssessment } from '../../src/lineage/impact-engine.js';
import { validateImpactAssessment } from '../../src/lineage/impact-assessment.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input' },
      { id: 'node:mid', kind: 'process', subtype: null },
      { id: 'node:sink', kind: 'sink', subtype: 'external-api' },
      { id: 'node:orphan', kind: 'sink', subtype: 'log' },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:mid', relationship: 'flows_to' },
      { id: 'edge:2', from: 'node:mid', to: 'node:sink', relationship: 'flows_to' },
    ],
    dataElements: [
      { id: 'data:1', name: 'email', dataClasses: ['PII'] },
      { id: 'data:2', name: 'ssn', dataClasses: ['PII', 'CONFIDENTIAL'] },
    ],
    flows: [
      { id: 'flow:1', dataElementIds: ['data:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
      { id: 'flow:2', dataElementIds: ['data:2'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
    ],
    recipientProfiles: [
      { id: 'recipient:vendor', provider: 'vendor', contributingGraphIds: ['node:sink'] },
      { id: 'recipient:unrelated', provider: 'other', contributingGraphIds: ['node:orphan'] },
    ],
    coverage: { languages: [
      { language: 'js', tier: 'partial', filesAnalyzed: 5, filesExpected: 5 },
      { language: 'python', tier: 'pattern-only', filesAnalyzed: 2, filesExpected: 2 },
    ] },
  };
}

test('computeImpactAssessment from a node target: affected set includes every downstream/upstream node and edge', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:mid');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
  assert.deepEqual([...record.affectedEdgeIds].sort(), ['edge:1', 'edge:2']);
  assert.equal(record.targetKind, 'node');
  assert.equal(record.scope, 'possible');
  assert.equal(record.traceKind, 'topology_reachable');
});

test('computeImpactAssessment: affectedDataClasses is the deduplicated union of every flow touching the affected edges', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.deepEqual([...record.affectedDataClasses].sort(), ['CONFIDENTIAL', 'PII']);
});

test('computeImpactAssessment: affectedRecipientProfileIds filters by contributingGraphIds intersection, excluding unrelated profiles', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, ['recipient:vendor']);
});

test('computeImpactAssessment: an edge target resolves to its own from/to nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'edge:2');
  assert.equal(record.targetKind, 'edge');
  assert.ok(record.affectedNodeIds.includes('node:mid'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
  assert.equal(record.traceKind, 'flow_restricted');
});

test('computeImpactAssessment: a flow target resolves to its own source/sink nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'flow:1');
  assert.equal(record.targetKind, 'flow');
  assert.ok(record.affectedNodeIds.includes('node:source'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
  assert.equal(record.traceKind, 'flow_restricted');
});

test('computeImpactAssessment: a dataElement target resolves to every node touched by any flow carrying it', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'data:2');
  assert.equal(record.targetKind, 'dataElement');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
  assert.equal(record.traceKind, 'flow_restricted');
});

test('computeImpactAssessment: a well-formed but non-existent target id degrades honestly to empty arrays, never throws', () => {
  assert.doesNotThrow(() => computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist'));
  const record = computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist');
  assert.deepEqual(record.affectedNodeIds, []);
  assert.deepEqual(record.affectedEdgeIds, []);
  assert.deepEqual(record.affectedDataClasses, []);
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: throws on a malformed targetId (no recognized prefix)', () => {
  assert.throws(() => computeImpactAssessment(_fixtureGraph(), 'not-a-real-prefix:x'));
});

test('computeImpactAssessment: coverageLimitations reports every non-full-tier language, whole-graph', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.equal(record.coverageLimitations.length, 2);
  assert.ok(record.coverageLimitations.some((s) => s.includes('js') && s.includes('partial')));
  assert.ok(record.coverageLimitations.some((s) => s.includes('python') && s.includes('pattern-only')));
});

test('computeImpactAssessment: graph.recipientProfiles absent degrades to empty array, never an error', () => {
  const graph = _fixtureGraph();
  delete graph.recipientProfiles;
  const record = computeImpactAssessment(graph, 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: a dataElement target on a branching topology does NOT sweep in an unrelated sink reached only by a different flow (fix round 1, review-reported)', () => {
  // One source, three sinks (A/B/C). data:shared flows via real Flow
  // records to sinks A and B only; sink C is reached only by a
  // structurally separate flow carrying a different data element.
  // showAllPaths (a topology-wide BFS) would incorrectly sweep sink C
  // in via node:src's edge to it, since it doesn't restrict to any
  // particular flow's own edges — the exact bug this fix closes.
  const graph = {
    graphId: 'graph:branching', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:src', kind: 'source', subtype: 'user-input' },
      { id: 'node:sinkA', kind: 'sink', subtype: 'external-api' },
      { id: 'node:sinkB', kind: 'sink', subtype: 'external-api' },
      { id: 'node:sinkC', kind: 'sink', subtype: 'log' },
    ],
    edges: [
      { id: 'edge:srcA', from: 'node:src', to: 'node:sinkA', relationship: 'flows_to' },
      { id: 'edge:srcB', from: 'node:src', to: 'node:sinkB', relationship: 'flows_to' },
      { id: 'edge:srcC', from: 'node:src', to: 'node:sinkC', relationship: 'flows_to' },
    ],
    dataElements: [
      { id: 'data:shared', name: 'shared', dataClasses: ['PII'] },
      { id: 'data:other', name: 'other', dataClasses: ['CONFIDENTIAL'] },
    ],
    flows: [
      { id: 'flow:a', dataElementIds: ['data:shared'], source: 'node:src', sink: 'node:sinkA', edgeIds: ['edge:srcA'] },
      { id: 'flow:b', dataElementIds: ['data:shared'], source: 'node:src', sink: 'node:sinkB', edgeIds: ['edge:srcB'] },
      { id: 'flow:c', dataElementIds: ['data:other'], source: 'node:src', sink: 'node:sinkC', edgeIds: ['edge:srcC'] },
    ],
  };

  const record = computeImpactAssessment(graph, 'data:shared');
  assert.equal(record.targetKind, 'dataElement');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:sinkA', 'node:sinkB', 'node:src']);
  assert.ok(!record.affectedNodeIds.includes('node:sinkC'), 'unrelated sink C must not be swept in');
  assert.deepEqual([...record.affectedEdgeIds].sort(), ['edge:srcA', 'edge:srcB']);
  assert.ok(!record.affectedEdgeIds.includes('edge:srcC'));
});

test('computeImpactAssessment: id, graphId, graphDigest, generatedAt are all real, non-placeholder values', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.match(record.id, /^impact:[0-9a-f]+$/);
  assert.equal(record.graphId, 'graph:abc');
  assert.ok(record.graphDigest.length > 0);
  assert.ok(record.generatedAt.length > 0);
});

// I1 (final-review-reported): the review's own exact repro shape — one
// app node fanning out to three sinks (A/B/C) via three SEPARATE flows,
// each carrying its own DISTINCT data element, mirroring how a real
// graph-builder discriminates edges by data element (ids.js's edgeId
// includes de.id in its discriminator, so two edges over the same node
// pair carrying different payloads never collide). Before this fix, a
// `flow:`/`edge:` target for the sink-A flow incorrectly reported
// sinkB/sinkC (and TRACKING/INTERNAL) in its blast radius.
function _reviewReproGraph() {
  return {
    graphId: 'graph:review-repro', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:app', kind: 'process', subtype: null },
      { id: 'node:sinkA', kind: 'sink', subtype: 'external-api' },
      { id: 'node:sinkB', kind: 'sink', subtype: 'external-api' },
      { id: 'node:sinkC', kind: 'sink', subtype: 'log' },
    ],
    edges: [
      { id: 'edge:A', from: 'node:app', to: 'node:sinkA', relationship: 'flows_to' },
      { id: 'edge:B', from: 'node:app', to: 'node:sinkB', relationship: 'flows_to' },
      { id: 'edge:C', from: 'node:app', to: 'node:sinkC', relationship: 'flows_to' },
    ],
    dataElements: [
      { id: 'data:card', name: 'card', dataClasses: ['PCI'] },
      { id: 'data:tracking', name: 'tracking', dataClasses: ['TRACKING'] },
      { id: 'data:internal', name: 'internal', dataClasses: ['INTERNAL'] },
    ],
    flows: [
      { id: 'flow:pay', dataElementIds: ['data:card'], source: 'node:app', sink: 'node:sinkA', edgeIds: ['edge:A'] },
      { id: 'flow:ads', dataElementIds: ['data:tracking'], source: 'node:app', sink: 'node:sinkB', edgeIds: ['edge:B'] },
      { id: 'flow:log', dataElementIds: ['data:internal'], source: 'node:app', sink: 'node:sinkC', edgeIds: ['edge:C'] },
    ],
  };
}

test('computeImpactAssessment: a flow: target does not sweep in unrelated sibling flows (I1, final-review-reported)', () => {
  const record = computeImpactAssessment(_reviewReproGraph(), 'flow:pay');
  assert.equal(record.targetKind, 'flow');
  assert.equal(record.traceKind, 'flow_restricted');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:app', 'node:sinkA']);
  assert.ok(!record.affectedNodeIds.includes('node:sinkB'));
  assert.ok(!record.affectedNodeIds.includes('node:sinkC'));
  assert.deepEqual(record.affectedEdgeIds, ['edge:A']);
  assert.deepEqual(record.affectedDataClasses, ['PCI']);
});

test('computeImpactAssessment: the equivalent edge: target does not sweep in unrelated sibling flows (I1, final-review-reported)', () => {
  const record = computeImpactAssessment(_reviewReproGraph(), 'edge:A');
  assert.equal(record.targetKind, 'edge');
  assert.equal(record.traceKind, 'flow_restricted');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:app', 'node:sinkA']);
  assert.ok(!record.affectedNodeIds.includes('node:sinkB'));
  assert.ok(!record.affectedNodeIds.includes('node:sinkC'));
  assert.deepEqual(record.affectedEdgeIds, ['edge:A']);
  assert.deepEqual(record.affectedDataClasses, ['PCI']);
});

test('computeImpactAssessment: an edge: target carried by NO flow still reports itself and its own endpoints, never a fully empty record (N3, final-review re-review)', () => {
  const graph = _reviewReproGraph();
  // A real, dead-end edge no flow currently uses — a legitimate graph
  // shape (e.g. a connection nothing traverses yet), distinct from a
  // genuinely nonexistent edge id.
  graph.nodes.push({ id: 'node:sinkD', kind: 'sink', subtype: 'log' });
  graph.edges.push({ id: 'edge:D', from: 'node:app', to: 'node:sinkD', relationship: 'flows_to' });
  const record = computeImpactAssessment(graph, 'edge:D');
  assert.equal(record.targetKind, 'edge');
  assert.equal(record.traceKind, 'flow_restricted');
  assert.deepEqual(record.affectedEdgeIds, ['edge:D']);
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:app', 'node:sinkD']);
});

// I3: an affected node's real, required coverageStatus surfaces a
// concrete, non-empty limitation naming it; an unaffected node with the
// identical coverageStatus must not appear.
test('computeImpactAssessment: an affected non-modeled node produces a real coverageLimitations entry naming it; an unaffected one with the same status does not', () => {
  const graph = _fixtureGraph();
  graph.nodes.find((n) => n.id === 'node:mid').coverageStatus = 'partial';
  graph.nodes.find((n) => n.id === 'node:orphan').coverageStatus = 'partial';

  const record = computeImpactAssessment(graph, 'node:mid');
  assert.ok(!record.affectedNodeIds.includes('node:orphan'));
  assert.ok(record.affectedNodeIds.includes('node:mid'));
  const entry = record.coverageLimitations.find((s) => s.includes('affected node'));
  assert.ok(entry, 'expected a real per-entity coverage limitation entry');
  assert.ok(entry.includes('node:mid'), 'entry should name the actual affected node');
  assert.ok(!entry.includes('node:orphan'), 'entry must not name the unaffected node');
});

test('computeImpactAssessment: no per-entity coverage limitation is added when every affected entity is modeled', () => {
  const graph = _fixtureGraph();
  const record = computeImpactAssessment(graph, 'node:mid');
  assert.ok(!record.coverageLimitations.some((s) => s.includes('affected node') || s.includes('affected edge')));
});

// M2: the engine's own output must satisfy its own contract — mirrors
// export-briefing.test.js's validateDecisionStory(result.record) precedent.
test('computeImpactAssessment output satisfies validateImpactAssessment for all 4 target kinds', () => {
  const graph = _fixtureGraph();
  for (const targetId of ['node:mid', 'edge:2', 'flow:1', 'data:2']) {
    const record = computeImpactAssessment(graph, targetId);
    const { valid, errors } = validateImpactAssessment(record);
    assert.deepEqual(errors, [], `unexpected errors for target ${targetId}`);
    assert.equal(valid, true, `expected a valid record for target ${targetId}`);
  }
});

// M4: a structurally malformed graph must throw a clearly-distinguishable
// error (never a raw TypeError), so the CLI can classify it as exit 1
// (a graph-content problem) rather than exit 2 (a CLI argument problem).
test('computeImpactAssessment: a graph with nodes but no edges array throws a clearly-distinguishable malformed-graph error, not a raw TypeError', () => {
  const graph = { graphId: 'graph:broken', nodes: [{ id: 'node:x' }] };
  assert.throws(
    () => computeImpactAssessment(graph, 'node:x'),
    (err) => err instanceof Error && err.message.startsWith('computeImpactAssessment: malformed graph'),
  );
});

test('computeImpactAssessment: a well-formed graph with an unrecognized targetId prefix still throws the ORIGINAL, differently-prefixed error', () => {
  assert.throws(
    () => computeImpactAssessment(_fixtureGraph(), 'not-a-real-prefix:x'),
    (err) => err instanceof Error && !err.message.startsWith('computeImpactAssessment: malformed graph'),
  );
});
