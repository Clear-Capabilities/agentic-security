//
// Synthetic DataFlowGraph v1 at the PRD section 21 reference scale
// (5,000 nodes / 10,000 edges), for performance-harness use only — not a
// fixture with any semantic meaning (contrast with
// scanner/src/lineage/fixtures/build-flagship-fixture.mjs, which encodes
// real Appendix D content). Import `generateSyntheticGraph(nodeCount,
// edgeCount)` directly rather than shelling out, so the perf runner pays
// no extra process-spawn overhead when timing graph-scale operations.

import { emptyGraphEnvelope } from '../../../scanner/src/lineage/schema.js';
import { graphId, nodeId, edgeId, dataElementId, flowId } from '../../../scanner/src/lineage/ids.js';
import { emptyProtection } from '../../../scanner/src/lineage/protection.js';

export function generateSyntheticGraph(nodeCount = 5000, edgeCount = 10000) {
  const graph = emptyGraphEnvelope({
    graphId: graphId({ repository: 'synthetic-perf', commit: 'synthetic', configHash: `${nodeCount}x${edgeCount}` }),
  });

  const kinds = ['source', 'process', 'store', 'log', 'external'];
  for (let i = 0; i < nodeCount; i++) {
    const kind = kinds[i % kinds.length];
    graph.nodes.push({
      id: nodeId(kind, ['synthetic-perf', `n${i}`]),
      kind, subtype: 'synthetic', label: `Node ${i}`, aliases: [],
      location: null, system: {}, destination: null,
      externality: { value: 'internal', evidenceRefs: [] },
      lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
      confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
    });
  }

  const de = dataElementId('synthetic_field', ['synthetic-perf']);
  graph.dataElements.push({
    id: de, name: 'synthetic_field', aliases: [], declaredType: null,
    dataClasses: [], aiContexts: [], sourceLocations: [], dataSubjectCategory: null,
    classificationEvidence: [], manualOverride: false,
  });

  for (let i = 0; i < edgeCount; i++) {
    const from = graph.nodes[i % nodeCount].id;
    const to = graph.nodes[(i * 7 + 1) % nodeCount].id;
    graph.edges.push({
      id: edgeId(from, to, 'data_flow', [String(i)]),
      from, to, relationship: 'data_flow',
      fieldMappings: [], protocol: { name: 'synthetic', destinationResolution: 'literal' },
      boundaryCrossings: [], provenance: 'code', protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled',
    });
  }

  for (let i = 0; i < 500; i++) {
    const source = graph.nodes[i % nodeCount].id;
    const sink = graph.nodes[(nodeCount - 1 - i) % nodeCount].id;
    graph.flows.push({
      id: flowId(source, sink, [de], [String(i)]),
      dataElementIds: [de], source, sink, edgeIds: [], transformationIds: [],
      alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed',
      evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
      findingRefs: [], governanceRefs: {}, limitations: [],
    });
  }

  return graph;
}
