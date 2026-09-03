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

// Aggregates protectionSummary across EVERY edge belonging to `flow`, not
// just one of them — a flow's `edgeIds` can in principle name more than
// one edge (graph-builder.js's own real flows are always single-edge
// today, but the schema and this module both accept a multi-edge array
// with no restriction), and aggregateVerdicts's own documented purpose is
// exactly this cross-branch/cross-edge reduction (PRD §8.4). Picking a
// single arbitrary edge here would silently go stale the moment a
// scenario is built against a genuinely multi-hop flow.
function _recomputeProtectionSummaryForFlow(flow, graph) {
  const edges = graph.edges.filter((e) => flow.edgeIds.includes(e.id));
  const verdicts = edges.flatMap((e) => [
    e.protection.transit.verdict,
    e.protection.atRest.verdict,
    e.protection.handling.verdict,
  ]);
  return aggregateVerdicts(verdicts);
}

function _recomputePolicyVerdict(flow, graph, opts) {
  if (opts.privacySinkPolicy == null) return null; // signal: leave flow.policyVerdict untouched
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  const classes = de?.dataClasses ?? [];
  const sinkKind = sinkNode?.subtype ?? null;
  if (!classes.length || !sinkKind) return 'not_evaluated';
  const ctx = {
    environment: opts.environment ?? process.env.AGENTIC_SECURITY_ENVIRONMENT ?? null,
    destination: sinkNode?.destination?.literalValue ?? null,
  };
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
    flow.protectionSummary = _recomputeProtectionSummaryForFlow(flow, graph);
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
  // Mirrors graph-builder.js's own gate (~line 757): 'encrypted' handling
  // only earns the atRest 'protected' verdict when the edge's sink node
  // is store-kind (database/file/object-storage/cache/client-storage/
  // backup/export). For any other sink kind (e.g. 'external-api',
  // 'queue') "at rest" isn't even a meaningful concept — falls through to
  // the same 'handling' dimension the non-encrypted case already sets.
  const sinkNode = graph.nodes.find((n) => n.id === edge.to);
  if (op.handling === 'encrypted' && sinkNode?.kind === 'store') {
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

// Scoped, at the applier level, to exactly `node.destination` — this
// sub-project's own scoping doc maps "replace a provider or move region"
// onto node.destination, the graph-level equivalent of a recipient's
// technical endpoint, and nothing else. scenario.js's own
// SCENARIO_OPERATION_REQUIRED_FIELDS only requires `field` be a non-empty
// string, never restricts its value — a real applied write to any other
// top-level node field (e.g. 'subtype') would land on the node but be
// completely invisible to scenario-diff.js's WATCHED_SCENARIO_FIELDS.node
// (which only watches 'destination'/'storeDetail'), since that list can
// only stay exhaustive if this applier never writes outside it. Rejecting
// any other field here — never widening the watch list — is what keeps
// that list exhaustive by construction. Mirrors the existing "skip a
// target id it can't find" pattern: reported in skippedOperations, never
// thrown.
function _applyReplaceRecipientFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  if (op.field !== 'destination') {
    return { ok: false, reason: `replace_recipient_fact only supports field "destination" (got "${op.field}") — this operation is scoped to a node's recipient/destination fact only` };
  }
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
 *
 * Scenario-shape validation (`validateScenario`, `scenario.js`) is the
 * CALLER's responsibility, not this module's — this function does no
 * upfront shape checking beyond each operation's own per-target `_byId`
 * lookup. An unrecognized `op.kind` is skipped via the `_APPLIERS` map
 * lookup below rather than validated against `SCENARIO_OPERATION_KINDS`
 * ahead of time. This mirrors `recipient-profile.js`'s own precedent,
 * where `validateRecipientProfile` is never called internally by any
 * producer either — the CLI layer (Task 4) calls `validateScenario`
 * before `applyScenario`, by design.
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
