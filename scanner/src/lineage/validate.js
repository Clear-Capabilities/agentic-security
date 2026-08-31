//
// Structural validator for DataFlowGraph v1 (PRD section 10). Hand-rolled
// rather than a generic JSON-Schema interpreter + a new `ajv`-style
// dependency, matching this codebase's existing preference for
// hand-rolled implementations over new runtime deps (see every parser in
// scanner/src/ir/). scanner/src/lineage/dataflow-graph.schema.json (Task
// 6) is the authoritative JSON Schema document for external interop /
// documentation; this file is what the engine actually calls at graph-
// build phase 12 (PRD 18.3: "Validate the graph contract and freeze it
// before rendering").
//
// Never throws. A malformed top-level input produces one error and
// returns early; a malformed nested entity is skipped for further
// structural checks on ITSELF but does not stop validation of siblings.

import {
  SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES,
  TRANSFORM_KINDS, REVERSIBILITY_VALUES, DESTINATION_RESOLUTION_VALUES, POLICY_STATES,
  FLOW_SUMMARY_VALUES, EVIDENCE_TYPES, GRAPH_SCOPE_SOURCES, HANDLING_VALUES, STORE_OPERATION_VALUES,
  QUEUE_OPERATION_VALUES,
} from './schema.js';
import { isValidProtectionDimension, PROTECTION_DIMENSIONS } from './protection.js';
import { LINEAGE_DATA_CLASSES, isAiContext } from './classification.js';

function _err(errors, path, message) {
  errors.push({ path, message });
}

function _requireArray(graph, key, errors) {
  if (!Array.isArray(graph[key])) _err(errors, `$.${key}`, `${key} must be an array`);
}

function _requireObject(graph, key, errors) {
  if (typeof graph[key] !== 'object' || graph[key] === null || Array.isArray(graph[key])) {
    _err(errors, `$.${key}`, `${key} must be an object`);
  }
}

const ID_PREFIXES = {
  node: /^node:/,
  edge: /^edge:/,
  data: /^data:/,
  flow: /^flow:/,
  transform: /^transform:/,
  evidence: /^evidence:/,
};

function _validateNode(node, idx, errors, seenIds) {
  const path = (suffix) => `$.nodes[${idx}]${suffix}`;
  if (!node || typeof node !== 'object') { _err(errors, path(''), 'node must be an object'); return; }
  if (typeof node.id !== 'string' || !node.id) _err(errors, path('.id'), 'node.id is required');
  else {
    if (!ID_PREFIXES.node.test(node.id)) _err(errors, path('.id'), `node.id must start with "node:"`);
    seenIds.add(node.id);
  }
  if (!NODE_KINDS.includes(node.kind)) _err(errors, path('.kind'), `unrecognized node kind "${node.kind}"`);
  // node.subtype is optional and may be `null` — an `unsupported`-coverage
  // node (e.g. a sink registry decision with `category: null`, PRD 6.4/
  // DESIGN_REGISTRIES.md §9.0) legitimately carries no subtype at all,
  // either as an absent field or an explicit `null`; only a present,
  // non-null, non-string value (a number, object, array, etc.) is invalid.
  if (Object.prototype.hasOwnProperty.call(node, 'subtype') && node.subtype !== null && typeof node.subtype !== 'string') {
    _err(errors, path('.subtype'), 'node.subtype must be a string or null');
  }
  if (typeof node.label !== 'string' || !node.label) _err(errors, path('.label'), 'node.label is required');
  if (!Array.isArray(node.aliases)) _err(errors, path('.aliases'), 'node.aliases must be an array');
  if (!Array.isArray(node.dataElementIds)) _err(errors, path('.dataElementIds'), 'node.dataElementIds must be an array');
  if (!Array.isArray(node.evidenceRefs)) _err(errors, path('.evidenceRefs'), 'node.evidenceRefs must be an array');
  if (!COVERAGE_STATUS_VALUES.includes(node.coverageStatus)) _err(errors, path('.coverageStatus'), `unrecognized coverageStatus "${node.coverageStatus}"`);
  if (node.externality && !EXTERNALITY_VALUES.includes(node.externality.value)) {
    _err(errors, path('.externality.value'), `unrecognized externality "${node.externality.value}"`);
  }
  // Milestone 2, Sub-project A, increment 1: `node.destination` is `null`
  // on every node this increment doesn't resolve — only checked when
  // non-null, mirroring `_validateEdge`'s own `edge.protocol` pattern below.
  if (node.destination && typeof node.destination === 'object') {
    if (!DESTINATION_RESOLUTION_VALUES.includes(node.destination.resolutionStatus)) {
      _err(errors, path('.destination.resolutionStatus'), `unrecognized destination.resolutionStatus "${node.destination.resolutionStatus}"`);
    }
    if (node.destination.resolutionStatus !== 'literal' && node.destination.literalValue !== null) {
      _err(errors, path('.destination.literalValue'), 'destination.literalValue must be null unless resolutionStatus is "literal"');
    }
  }
  // Milestone 2, Sub-project E, increment 2: `node.storeDetail` is `null`
  // on every node this increment doesn't populate — only checked when
  // non-null, mirroring `node.destination`'s own "only checked when the
  // parent object is present" shape immediately above.
  if (node.storeDetail && typeof node.storeDetail === 'object') {
    if (node.storeDetail.operation !== null && !STORE_OPERATION_VALUES.includes(node.storeDetail.operation)) {
      _err(errors, path('.storeDetail.operation'), `unrecognized storeDetail.operation "${node.storeDetail.operation}"`);
    }
    if (Object.prototype.hasOwnProperty.call(node.storeDetail, 'columns') && !Array.isArray(node.storeDetail.columns)) {
      _err(errors, path('.storeDetail.columns'), 'storeDetail.columns must be an array');
    } else if (Array.isArray(node.storeDetail.columns)) {
      node.storeDetail.columns.forEach((c, i) => {
        if (typeof c !== 'string') _err(errors, path(`.storeDetail.columns[${i}]`), 'storeDetail.columns entries must be strings');
      });
    }
  }
  // Milestone 2, Sub-project E, increment 3: `node.queueDetail` is `null`
  // on every node this increment doesn't populate — only checked when
  // non-null, mirroring `node.storeDetail`'s own "only checked when the
  // parent object is present" shape immediately above.
  if (node.queueDetail && typeof node.queueDetail === 'object') {
    if (node.queueDetail.operation !== null && !QUEUE_OPERATION_VALUES.includes(node.queueDetail.operation)) {
      _err(errors, path('.queueDetail.operation'), `unrecognized queueDetail.operation "${node.queueDetail.operation}"`);
    }
    if (node.queueDetail.topic !== null && typeof node.queueDetail.topic !== 'string') {
      _err(errors, path('.queueDetail.topic'), 'queueDetail.topic must be a string or null');
    }
  }
}

function _validateDataElement(de, idx, errors, seenIds) {
  const path = (suffix) => `$.dataElements[${idx}]${suffix}`;
  if (!de || typeof de !== 'object') { _err(errors, path(''), 'dataElement must be an object'); return; }
  if (typeof de.id !== 'string' || !de.id) _err(errors, path('.id'), 'dataElement.id is required');
  else {
    if (!ID_PREFIXES.data.test(de.id)) _err(errors, path('.id'), `dataElement.id must start with "data:"`);
    seenIds.add(de.id);
  }
  if (typeof de.name !== 'string' || !de.name) _err(errors, path('.name'), 'dataElement.name is required');
  if (!Array.isArray(de.dataClasses)) _err(errors, path('.dataClasses'), 'dataElement.dataClasses must be an array');
  else {
    for (let i = 0; i < de.dataClasses.length; i++) {
      const cls = de.dataClasses[i];
      if (!LINEAGE_DATA_CLASSES.includes(cls)) {
        _err(errors, path(`.dataClasses[${i}]`), `unrecognized data class "${cls}"`);
      }
    }
  }
  if (!Array.isArray(de.aiContexts)) _err(errors, path('.aiContexts'), 'dataElement.aiContexts must be an array');
  else {
    for (let i = 0; i < de.aiContexts.length; i++) {
      const ctx = de.aiContexts[i];
      if (!isAiContext(ctx)) {
        _err(errors, path(`.aiContexts[${i}]`), `unrecognized AI processing context "${ctx}"`);
      }
    }
  }
}

function _validateEdge(edge, idx, errors, nodeIds, dataElementIds) {
  const path = (suffix) => `$.edges[${idx}]${suffix}`;
  if (!edge || typeof edge !== 'object') { _err(errors, path(''), 'edge must be an object'); return; }
  if (typeof edge.id !== 'string' || !edge.id) _err(errors, path('.id'), 'edge.id is required');
  else if (!ID_PREFIXES.edge.test(edge.id)) _err(errors, path('.id'), `edge.id must start with "edge:"`);
  if (!nodeIds.has(edge.from)) _err(errors, path('.from'), `unknown node id "${edge.from}"`);
  if (!nodeIds.has(edge.to)) _err(errors, path('.to'), `unknown node id "${edge.to}"`);
  if (edge.relationship !== 'data_flow') _err(errors, path('.relationship'), `unrecognized relationship "${edge.relationship}"`);
  if (!Array.isArray(edge.fieldMappings)) _err(errors, path('.fieldMappings'), 'edge.fieldMappings must be an array');
  else {
    edge.fieldMappings.forEach((fm, i) => {
      if (!MAPPING_TYPES.includes(fm?.mappingType)) _err(errors, path(`.fieldMappings[${i}].mappingType`), `unrecognized mappingType "${fm?.mappingType}"`);
      for (const deId of fm?.dataElementIds || []) {
        if (!dataElementIds.has(deId)) _err(errors, path(`.fieldMappings[${i}].dataElementIds`), `unknown dataElement id "${deId}"`);
      }
    });
  }
  if (!edge.protection || typeof edge.protection !== 'object') {
    _err(errors, path('.protection'), 'edge.protection is required');
  } else {
    for (const dim of PROTECTION_DIMENSIONS) {
      if (!isValidProtectionDimension(edge.protection[dim])) _err(errors, path(`.protection.${dim}`), `invalid protection dimension`);
    }
  }
  if (edge.protocol && typeof edge.protocol === 'object') {
    if (!DESTINATION_RESOLUTION_VALUES.includes(edge.protocol.destinationResolution)) {
      _err(errors, path('.protocol.destinationResolution'), `unrecognized destinationResolution "${edge.protocol.destinationResolution}"`);
    }
  }
}

function _validateFlow(flow, idx, errors, nodeIds, dataElementIds, edgeIds) {
  const path = (suffix) => `$.flows[${idx}]${suffix}`;
  if (!flow || typeof flow !== 'object') { _err(errors, path(''), 'flow must be an object'); return; }
  if (typeof flow.id !== 'string' || !flow.id) _err(errors, path('.id'), 'flow.id is required');
  else if (!ID_PREFIXES.flow.test(flow.id)) _err(errors, path('.id'), `flow.id must start with "flow:"`);
  if (!nodeIds.has(flow.source)) _err(errors, path('.source'), `unknown node id "${flow.source}"`);
  if (!nodeIds.has(flow.sink)) _err(errors, path('.sink'), `unknown node id "${flow.sink}"`);
  for (const deId of flow.dataElementIds || []) {
    if (!dataElementIds.has(deId)) _err(errors, path('.dataElementIds'), `unknown dataElement id "${deId}"`);
  }
  for (const eId of flow.edgeIds || []) {
    if (!edgeIds.has(eId)) _err(errors, path('.edgeIds'), `unknown edge id "${eId}"`);
  }
  if (!POLICY_STATES.includes(flow.policyVerdict)) _err(errors, path('.policyVerdict'), `unrecognized policyVerdict "${flow.policyVerdict}"`);
  if (!FLOW_SUMMARY_VALUES.includes(flow.protectionSummary)) _err(errors, path('.protectionSummary'), `unrecognized protectionSummary "${flow.protectionSummary}"`);
  // Milestone 2, Sub-project D, increment 1: `flow.handling` is `null` on
  // every flow this increment's own caller chose not to populate — only
  // checked when non-null, mirroring `_validateNode`'s own `node.destination`
  // pattern above.
  if (flow.handling != null && !HANDLING_VALUES.includes(flow.handling)) {
    _err(errors, path('.handling'), `unrecognized handling "${flow.handling}"`);
  }
}

function _validateTransformation(t, idx, errors) {
  const path = (suffix) => `$.transformations[${idx}]${suffix}`;
  if (!t || typeof t !== 'object') { _err(errors, path(''), 'transformation must be an object'); return; }
  if (typeof t.id !== 'string' || !t.id) _err(errors, path('.id'), 'transformation.id is required');
  else if (!ID_PREFIXES.transform.test(t.id)) _err(errors, path('.id'), `transformation.id must start with "transform:"`);
  if (!TRANSFORM_KINDS.includes(t.kind)) _err(errors, path('.kind'), `unrecognized transformation kind "${t.kind}"`);
  if (!REVERSIBILITY_VALUES.includes(t.reversibility)) _err(errors, path('.reversibility'), `unrecognized reversibility "${t.reversibility}"`);
}

function _validateEvidence(e, idx, errors) {
  const path = (suffix) => `$.evidence[${idx}]${suffix}`;
  if (!e || typeof e !== 'object') { _err(errors, path(''), 'evidence must be an object'); return; }
  if (typeof e.id !== 'string' || !e.id) _err(errors, path('.id'), 'evidence.id is required');
  else if (!ID_PREFIXES.evidence.test(e.id)) _err(errors, path('.id'), `evidence.id must start with "evidence:"`);
  if (!EVIDENCE_TYPES.includes(e.evidenceType)) _err(errors, path('.evidenceType'), `unrecognized evidenceType "${e.evidenceType}"`);
}

/**
 * Report a validation error for every duplicate id beyond the first
 * occurrence in a top-level entity array. Entities with a missing/invalid
 * id are skipped here — that is already reported by the per-entity
 * structural check, and treating `undefined` as a colliding "id" would be
 * noise, not signal.
 */
function _checkDuplicateIds(items, key, errors) {
  const seenAt = new Map();
  items.forEach((item, idx) => {
    if (!item || typeof item.id !== 'string' || !item.id) return;
    if (seenAt.has(item.id)) {
      _err(errors, `$.${key}[${idx}].id`, `duplicate id "${item.id}" (also used at $.${key}[${seenAt.get(item.id)}])`);
    } else {
      seenAt.set(item.id, idx);
    }
  });
}

/**
 * Structurally validate a DataFlowGraph v1 envelope. Returns
 * `{valid, errors}` and never throws.
 */
export function validateGraph(graph) {
  const errors = [];
  if (!graph || typeof graph !== 'object' || Array.isArray(graph)) {
    return { valid: false, errors: [{ path: '$', message: 'graph must be an object' }] };
  }

  if (graph.schemaVersion !== SCHEMA_VERSION) {
    _err(errors, '$.schemaVersion', `expected "${SCHEMA_VERSION}", got "${graph.schemaVersion}"`);
  }
  if (typeof graph.graphId !== 'string' || !graph.graphId.startsWith('dfg:')) {
    _err(errors, '$.graphId', 'graphId must be a string starting with "dfg:"');
  }
  for (const key of ['nodes', 'edges', 'dataElements', 'transformations', 'flows', 'controls', 'policies', 'evidence', 'limitations']) {
    _requireArray(graph, key, errors);
  }
  for (const key of ['scope', 'scanHealth', 'taxonomy', 'coverage', 'extensions']) {
    _requireObject(graph, key, errors);
  }
  if (graph.scope && typeof graph.scope === 'object' && !Array.isArray(graph.scope)) {
    if (!GRAPH_SCOPE_SOURCES.includes(graph.scope.source)) {
      _err(errors, '$.scope.source', `unrecognized scope.source "${graph.scope.source}"`);
    }
  }

  const nodeIds = new Set();
  const dataElementIds = new Set();
  const edgeIds = new Set();

  (Array.isArray(graph.nodes) ? graph.nodes : []).forEach((n, i) => _validateNode(n, i, errors, nodeIds));
  (Array.isArray(graph.dataElements) ? graph.dataElements : []).forEach((d, i) => _validateDataElement(d, i, errors, dataElementIds));
  (Array.isArray(graph.edges) ? graph.edges : []).forEach((e, i) => {
    _validateEdge(e, i, errors, nodeIds, dataElementIds);
    if (e && typeof e.id === 'string') edgeIds.add(e.id);
  });
  (Array.isArray(graph.flows) ? graph.flows : []).forEach((f, i) => _validateFlow(f, i, errors, nodeIds, dataElementIds, edgeIds));
  (Array.isArray(graph.transformations) ? graph.transformations : []).forEach((t, i) => _validateTransformation(t, i, errors));
  (Array.isArray(graph.evidence) ? graph.evidence : []).forEach((e, i) => _validateEvidence(e, i, errors));

  _checkDuplicateIds(Array.isArray(graph.nodes) ? graph.nodes : [], 'nodes', errors);
  _checkDuplicateIds(Array.isArray(graph.edges) ? graph.edges : [], 'edges', errors);
  _checkDuplicateIds(Array.isArray(graph.dataElements) ? graph.dataElements : [], 'dataElements', errors);
  _checkDuplicateIds(Array.isArray(graph.flows) ? graph.flows : [], 'flows', errors);

  return { valid: errors.length === 0, errors };
}
