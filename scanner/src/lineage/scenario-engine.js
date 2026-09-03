// scenario-engine.js — M5 deliverable #3a (FR-502): the clone-and-
// override engine. Deep-clones the base graph, applies each declared
// Scenario operation, then re-runs the SAME two pure aggregators
// graph-builder.js's own real pipeline uses (aggregateVerdicts,
// isSinkPermitted) over only the flows an operation actually touched —
// never re-running the taint/path pipeline, per this sub-project's own
// scoping doc.
//
// The exact recomputation this module mirrors, confirmed by direct
// read of graph-builder.js's own real edge/flow minting pass:
//   flow.protectionSummary = aggregateVerdicts([
//     edge.protection.transit.verdict,
//     edge.protection.atRest.verdict,
//     edge.protection.handling.verdict,
//   ])
//   flow.policyVerdict = isSinkPermitted(dataElement.dataClasses, sinkNode.subtype,
//     opts.privacySinkPolicy, { environment: opts.environment, destination: sinkNode.destination?.literalValue ?? null })
//     ? 'permitted' : 'prohibited'  (or 'not_evaluated' if no policy/classes/sinkKind)

import { aggregateVerdicts } from './protection.js';
import { isSinkPermitted } from '../dataflow/privacy-sink-policy.js';

function _deepClone(v) { return JSON.parse(JSON.stringify(v)); }

function _byId(arr) { return new Map((arr ?? []).map((x) => [x.id, x])); }

function _recomputeProtectionSummary(edge) {
  return aggregateVerdicts([
    edge.protection.transit.verdict,
    edge.protection.atRest.verdict,
    edge.protection.handling.verdict,
  ]);
}

function _recomputePolicyVerdict(flow, graph, opts) {
  if (opts.privacySinkPolicy == null) return null; // signal: leave flow.policyVerdict untouched
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  const classes = de?.dataClasses ?? [];
  const sinkKind = sinkNode?.subtype ?? null;
  if (!classes.length || !sinkKind) return 'not_evaluated';
  const ctx = { environment: opts.environment ?? null, destination: sinkNode?.destination?.literalValue ?? null };
  return isSinkPermitted(classes, sinkKind, opts.privacySinkPolicy, ctx) ? 'permitted' : 'prohibited';
}

// Every flow using this edge (by edgeIds membership) gets protectionSummary
// recomputed; policyVerdict only for flows whose sink node's destination
// or the flow's own dataClasses could plausibly have changed — but since
// applyScenario always calls this after ANY node/edge touch to be safe
// (recomputation is cheap and idempotent), scope is simply "every flow
// touching this edge or this node".
function _touchedFlows(graph, { edgeId, nodeId }) {
  return graph.flows.filter((f) =>
    (edgeId && f.edgeIds.includes(edgeId)) ||
    (nodeId && (f.source === nodeId || f.sink === nodeId)));
}

function _recomputeTouchedFlows(graph, touch, opts) {
  for (const flow of _touchedFlows(graph, touch)) {
    const edge = graph.edges.find((e) => flow.edgeIds.includes(e.id));
    if (edge) flow.protectionSummary = _recomputeProtectionSummary(edge);
    const newPolicyVerdict = _recomputePolicyVerdict(flow, graph, opts);
    if (newPolicyVerdict !== null) flow.policyVerdict = newPolicyVerdict;
  }
}

function _applyRequireTransitProtection(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  edge.protection.transit = { verdict: 'protected', evidenceGrade: 'assumed' };
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyHandling(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  // Mirrors graph-builder.js's own gate: 'encrypted' handling before a
  // store sink is what earns the atRest 'protected' verdict there.
  if (op.handling === 'encrypted') {
    edge.protection.atRest = { verdict: 'protected', evidenceGrade: 'assumed' };
  } else {
    edge.protection.handling = { verdict: 'protected', evidenceGrade: 'assumed' };
  }
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyRemoveEntity(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  const removedEdgeIds = new Set(graph.edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => e.id));
  graph.edges = graph.edges.filter((e) => !removedEdgeIds.has(e.id));
  graph.flows = graph.flows.filter((f) => f.source !== node.id && f.sink !== node.id
    && !f.edgeIds.some((id) => removedEdgeIds.has(id)));
  graph.nodes = graph.nodes.filter((n) => n.id !== node.id);
  return { ok: true };
}

function _applyReplaceRecipientFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  node[op.field] = op.value;
  _recomputeTouchedFlows(graph, { nodeId: node.id }, op._opts);
  return { ok: true };
}

function _applyChangeStorageFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  node.storeDetail = { ...(node.storeDetail ?? {}), [op.field]: op.value };
  return { ok: true };
}

function _applyChangeGovernanceFact(graph, op) {
  const flow = _byId(graph.flows).get(op.targetFlowId);
  if (!flow) return { ok: false, reason: `targetFlowId "${op.targetFlowId}" not found in graph.flows` };
  flow.governanceRefs = { ...(flow.governanceRefs ?? {}), [op.field]: op.value };
  return { ok: true };
}

const _APPLIERS = {
  require_transit_protection: _applyRequireTransitProtection,
  apply_handling: _applyHandling,
  remove_entity: _applyRemoveEntity,
  replace_recipient_fact: _applyReplaceRecipientFact,
  change_storage_fact: _applyChangeStorageFact,
  change_governance_fact: _applyChangeGovernanceFact,
};

/**
 * Apply `scenario.operations` to a deep clone of `baseGraph`. Never
 * mutates `baseGraph`. An operation whose target id does not exist in
 * the graph is skipped (reported in `skippedOperations`), never thrown —
 * a Scenario written against an older snapshot must degrade honestly.
 * `opts.privacySinkPolicy`/`opts.environment` mirror graph-builder.js's
 * own opts; omitting privacySinkPolicy means policyVerdict
 * recomputation is skipped entirely (base value kept on every touched
 * flow) rather than guessed.
 */
export function applyScenario(baseGraph, scenario, opts = {}) {
  const graph = _deepClone(baseGraph);
  const appliedOperations = [];
  const skippedOperations = [];
  for (const op of scenario.operations ?? []) {
    const applier = _APPLIERS[op.kind];
    if (!applier) {
      skippedOperations.push({ operation: op, reason: `unrecognized operation kind "${op.kind}"` });
      continue;
    }
    const result = applier(graph, { ...op, _opts: opts });
    if (result.ok) appliedOperations.push({ operation: op });
    else skippedOperations.push({ operation: op, reason: result.reason });
  }
  return { graph, appliedOperations, skippedOperations };
}
