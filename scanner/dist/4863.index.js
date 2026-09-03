export const id = 4863;
export const ids = [4863];
export const modules = {

/***/ 4863:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  loadRemoteGraphExport: () => (/* binding */ loadRemoteGraphExport)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: ./src/lineage/schema.js
var schema = __webpack_require__(4073);
// EXTERNAL MODULE: ./src/lineage/protection.js
var protection = __webpack_require__(965);
// EXTERNAL MODULE: ./src/lineage/classification.js
var classification = __webpack_require__(2602);
;// CONCATENATED MODULE: ./src/lineage/validate.js
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
  if (!schema/* NODE_KINDS */.xA.includes(node.kind)) _err(errors, path('.kind'), `unrecognized node kind "${node.kind}"`);
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
  if (!schema/* COVERAGE_STATUS_VALUES */.R0.includes(node.coverageStatus)) _err(errors, path('.coverageStatus'), `unrecognized coverageStatus "${node.coverageStatus}"`);
  if (node.externality && !schema/* EXTERNALITY_VALUES */.TB.includes(node.externality.value)) {
    _err(errors, path('.externality.value'), `unrecognized externality "${node.externality.value}"`);
  }
  // Milestone 2, Sub-project A, increment 1: `node.destination` is `null`
  // on every node this increment doesn't resolve — only checked when
  // non-null, mirroring `_validateEdge`'s own `edge.protocol` pattern below.
  if (node.destination && typeof node.destination === 'object') {
    if (!schema/* DESTINATION_RESOLUTION_VALUES */.JU.includes(node.destination.resolutionStatus)) {
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
    if (node.storeDetail.operation !== null && !schema/* STORE_OPERATION_VALUES */.P4.includes(node.storeDetail.operation)) {
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
    if (node.queueDetail.operation !== null && !schema/* QUEUE_OPERATION_VALUES */.hY.includes(node.queueDetail.operation)) {
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
      if (!classification/* LINEAGE_DATA_CLASSES */.e6.includes(cls)) {
        _err(errors, path(`.dataClasses[${i}]`), `unrecognized data class "${cls}"`);
      }
    }
  }
  if (!Array.isArray(de.aiContexts)) _err(errors, path('.aiContexts'), 'dataElement.aiContexts must be an array');
  else {
    for (let i = 0; i < de.aiContexts.length; i++) {
      const ctx = de.aiContexts[i];
      if (!(0,classification/* isAiContext */.MY)(ctx)) {
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
      if (!schema/* MAPPING_TYPES */.$W.includes(fm?.mappingType)) _err(errors, path(`.fieldMappings[${i}].mappingType`), `unrecognized mappingType "${fm?.mappingType}"`);
      for (const deId of fm?.dataElementIds || []) {
        if (!dataElementIds.has(deId)) _err(errors, path(`.fieldMappings[${i}].dataElementIds`), `unknown dataElement id "${deId}"`);
      }
    });
  }
  if (!edge.protection || typeof edge.protection !== 'object') {
    _err(errors, path('.protection'), 'edge.protection is required');
  } else {
    for (const dim of protection/* PROTECTION_DIMENSIONS */.Ai) {
      if (!(0,protection/* isValidProtectionDimension */.u9)(edge.protection[dim])) _err(errors, path(`.protection.${dim}`), `invalid protection dimension`);
    }
  }
  if (edge.protocol && typeof edge.protocol === 'object') {
    if (!schema/* DESTINATION_RESOLUTION_VALUES */.JU.includes(edge.protocol.destinationResolution)) {
      _err(errors, path('.protocol.destinationResolution'), `unrecognized destinationResolution "${edge.protocol.destinationResolution}"`);
    }
  }
  if (!schema/* EDGE_PROVENANCE_VALUES */.L9.includes(edge.provenance)) {
    _err(errors, path('.provenance'), `unrecognized provenance "${edge.provenance}"`);
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
  if (!schema/* POLICY_STATES */.QA.includes(flow.policyVerdict)) _err(errors, path('.policyVerdict'), `unrecognized policyVerdict "${flow.policyVerdict}"`);
  if (!schema/* FLOW_SUMMARY_VALUES */.lw.includes(flow.protectionSummary)) _err(errors, path('.protectionSummary'), `unrecognized protectionSummary "${flow.protectionSummary}"`);
  // Milestone 2, Sub-project D, increment 1: `flow.handling` is `null` on
  // every flow this increment's own caller chose not to populate — only
  // checked when non-null, mirroring `_validateNode`'s own `node.destination`
  // pattern above.
  if (flow.handling != null && !schema/* HANDLING_VALUES */.DC.includes(flow.handling)) {
    _err(errors, path('.handling'), `unrecognized handling "${flow.handling}"`);
  }
}

function _validateTransformation(t, idx, errors) {
  const path = (suffix) => `$.transformations[${idx}]${suffix}`;
  if (!t || typeof t !== 'object') { _err(errors, path(''), 'transformation must be an object'); return; }
  if (typeof t.id !== 'string' || !t.id) _err(errors, path('.id'), 'transformation.id is required');
  else if (!ID_PREFIXES.transform.test(t.id)) _err(errors, path('.id'), `transformation.id must start with "transform:"`);
  if (!schema/* TRANSFORM_KINDS */.DK.includes(t.kind)) _err(errors, path('.kind'), `unrecognized transformation kind "${t.kind}"`);
  if (!schema/* REVERSIBILITY_VALUES */.vw.includes(t.reversibility)) _err(errors, path('.reversibility'), `unrecognized reversibility "${t.reversibility}"`);
}

function _validateEvidence(e, idx, errors) {
  const path = (suffix) => `$.evidence[${idx}]${suffix}`;
  if (!e || typeof e !== 'object') { _err(errors, path(''), 'evidence must be an object'); return; }
  if (typeof e.id !== 'string' || !e.id) _err(errors, path('.id'), 'evidence.id is required');
  else if (!ID_PREFIXES.evidence.test(e.id)) _err(errors, path('.id'), `evidence.id must start with "evidence:"`);
  if (!schema/* EVIDENCE_TYPES */.il.includes(e.evidenceType)) _err(errors, path('.evidenceType'), `unrecognized evidenceType "${e.evidenceType}"`);
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
function validateGraph(graph) {
  const errors = [];
  if (!graph || typeof graph !== 'object' || Array.isArray(graph)) {
    return { valid: false, errors: [{ path: '$', message: 'graph must be an object' }] };
  }

  if (graph.schemaVersion !== schema/* SCHEMA_VERSION */.f$) {
    _err(errors, '$.schemaVersion', `expected "${schema/* SCHEMA_VERSION */.f$}", got "${graph.schemaVersion}"`);
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
    if (!schema/* GRAPH_SCOPE_SOURCES */.nZ.includes(graph.scope.source)) {
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

// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(859);
;// CONCATENATED MODULE: ./src/lineage/federation-loader.js
// federation-loader.js — M5 deliverable #8 (FR-304's "declared" half):
// loadRemoteGraphExport(filePath) reads an exportGraphJSON-shaped file
// (dataflow export --format json's own artifact) — chosen over the
// local server's signed-graph reader (`scanner/src/server/`, whose
// loadSignedGraph is what `agentic-security explore` uses) for the
// cross-machine reason this deliverable's own scoping investigation
// found: loadSignedGraph authenticates against a PER-INSTALL HMAC key,
// which is the wrong trust model for a file that crossed a repo/machine
// boundary in the common case (two repos scanned on two different
// machines sign under two different keys by default, so pointing
// loadSignedGraph at a second repo's checkout would, in the common case,
// correctly report 'tampered' even though nothing was actually
// tampered with). exportGraphJSON's portable, embedded-digest artifact
// is a SELF-CONSISTENCY check instead — never authentication, disclosed
// as such everywhere this module or its callers describe it.
//
// Mirrors that reader's own four-distinct-outcome discipline, with one
// structural difference: a digest mismatch here is NOT a blocking
// failure (`ok:false`) the way all four of its reasons are — it is a
// WARNING the caller must show, never silently swallowed, and does not
// by itself block a --yes write (the operator is explicitly asserting
// this file). `ok:true, digestMatches:false` is therefore a real,
// valid, non-failing outcome; only `missing`/`malformed`/
// `invalid-graph` set `ok:false`.





/**
 * @param {string} filePath
 * @returns {{
 *   ok: boolean,
 *   graph: object|null,
 *   digest: string|null,
 *   digestMatches: boolean|null,
 *   reason: 'missing'|'malformed'|'invalid-graph'|'digest-mismatch'|null,
 *   message: string|null,
 * }}
 */
function loadRemoteGraphExport(filePath) {
  if (!filePath || typeof filePath !== 'string' || !external_node_fs_.existsSync(filePath)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `No remote graph export found at ${filePath}. Run \`dataflow export --format json\` in the remote repository and point --remote-graph at the resulting file.`,
    };
  }

  let body;
  try {
    body = external_node_fs_.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `Remote graph export found at ${filePath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} is not valid JSON (${e && e.message ? e.message : e}).`,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || typeof parsed.digest !== 'string' || !parsed.digest
    || !parsed.graph || typeof parsed.graph !== 'object' || Array.isArray(parsed.graph)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} does not look like an \`exportGraphJSON\` artifact — expected top-level "digest" (string) and "graph" (object) fields. Run \`dataflow export --format json\` to produce a valid one.`,
    };
  }

  const { valid, errors } = validateGraph(parsed.graph);
  if (!valid) {
    return {
      ok: false, graph: null, digest: parsed.digest, digestMatches: null, reason: 'invalid-graph',
      message: `Remote graph export at ${filePath} does not contain a well-formed DataFlowGraph v1 document: ${errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`,
    };
  }

  const recomputed = (0,export_json.computeGraphDigest)(parsed.graph);
  const digestMatches = recomputed === parsed.digest;
  if (!digestMatches) {
    return {
      ok: true, graph: parsed.graph, digest: parsed.digest, digestMatches: false, reason: 'digest-mismatch',
      message: 'WARNING: the remote export\'s embedded digest does not match its own content (self-consistency check failed) — this is NOT authentication, only a check that the file has not been altered since it was exported. Proceeding is a real trust decision the operator is making explicitly.',
    };
  }

  return { ok: true, graph: parsed.graph, digest: parsed.digest, digestMatches: true, reason: null, message: null };
}


/***/ })

};
