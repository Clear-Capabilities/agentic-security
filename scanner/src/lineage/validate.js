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

import { SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES } from './schema.js';
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
  if (typeof node.label !== 'string' || !node.label) _err(errors, path('.label'), 'node.label is required');
  if (!Array.isArray(node.aliases)) _err(errors, path('.aliases'), 'node.aliases must be an array');
  if (!Array.isArray(node.dataElementIds)) _err(errors, path('.dataElementIds'), 'node.dataElementIds must be an array');
  if (!Array.isArray(node.evidenceRefs)) _err(errors, path('.evidenceRefs'), 'node.evidenceRefs must be an array');
  if (!COVERAGE_STATUS_VALUES.includes(node.coverageStatus)) _err(errors, path('.coverageStatus'), `unrecognized coverageStatus "${node.coverageStatus}"`);
  if (node.externality && !EXTERNALITY_VALUES.includes(node.externality.value)) {
    _err(errors, path('.externality.value'), `unrecognized externality "${node.externality.value}"`);
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

  return { valid: errors.length === 0, errors };
}
