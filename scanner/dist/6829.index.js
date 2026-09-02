export const id = 6829;
export const ids = [6829];
export const modules = {

/***/ 6829:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   OBLIGATION_EVIDENCE_PACK_SCHEMA: () => (/* binding */ OBLIGATION_EVIDENCE_PACK_SCHEMA),
/* harmony export */   buildObligationEvidencePack: () => (/* binding */ buildObligationEvidencePack),
/* harmony export */   ensureKeyPair: () => (/* reexport safe */ _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_0__.ensureKeyPair),
/* harmony export */   signObligationEvidencePack: () => (/* binding */ signObligationEvidencePack),
/* harmony export */   verifyObligationEvidencePack: () => (/* binding */ verifyObligationEvidencePack)
/* harmony export */ });
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8317);
/* harmony import */ var _evidence_grade_wording_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3540);
/* harmony import */ var _lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(859);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(7598);
// obligation-evidence-pack.js — Milestone 4 sub-project 6c: signed,
// versioned evidence packs for a Regulatory Obligation Overlay framework
// evaluation (FR-504, PRD §10.10). Fourth sibling in the
// evidence-bundle.js family — see that module's own header for the
// shared-key rationale, and provenance-evidence-bundle.js for the most
// directly mirrored precedent (same reused ensureKeyPair/keyPaths/
// canonicalJson, own schema string, own build/sign/verify trio, own
// top-level-key allowlist).
//
// WHAT THIS IS NOT
// -----------------
// Not a reuse of evidence-bundle.js's own bundle shape (that's a single
// FINDING's evidence — proofTier/taintPath/etc; this artifact has no
// finding at all). Not compliance-evidence-signing.js's ComplianceEvidence
// manifest either — that signs the pre-existing family:/module:/rule:-
// driven present/partial/absent/manual walkthrough status; this signs the
// newer, additive graph: mapping type's own real ObligationMapping
// records (evaluateGraphFlowPredicate/buildObligationMappingFromGraphPredicate,
// sub-project 6b) — a distinct FR-504 artifact with its own field list
// (scope, framework versions, facts, evidence index, unknown/manual
// items, accepted exceptions, scan health, limitations, graph digest,
// reproducibility metadata).
//
// THE EVIDENCE-INDEX DESIGN DECISION (see the scoping doc for the full
// writeup)
// -----------------------------------------------------------------
// A real ObligationMapping record's own `evidence[]` is structurally
// always empty today (graph-builder.js hardcodes `edge.evidenceRefs: []`
// on every minted edge, disclosed in obligation-predicates.js's own
// header). Rather than ship an evidence pack whose "evidence index" is
// honestly, permanently empty, this module builds a REAL evidence index
// from each fact's own `contributingGraphIds` (real flow ids
// evaluateGraphFlowPredicate already returns) — resolving each flow id
// back into a small, real summary (source/sink kind, dataElement
// dataClasses, the edge's own transit/atRest/handling verdicts) by
// joining against the graph's own entity arrays. `record.evidence` is
// still carried through verbatim on each fact (honest, even though
// empty) — the evidence index is an ADDITIONAL section built from data
// that genuinely IS populated, not a replacement that hides the gap.






const OBLIGATION_EVIDENCE_PACK_SCHEMA = 'agentic-security/obligation-evidence-pack@1';

function _asArray(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * Resolve one ObligationMapping fact's contributingGraphIds (real flow
 * ids) into a small, real, human-and-machine-readable summary per flow —
 * the evidence index's own per-fact contribution. Never throws: a flow id
 * that no longer resolves against this graph (a stale pack re-evaluated
 * against a newer graph, or a malformed fact) is simply skipped, not
 * fabricated.
 */
function _resolveEvidenceForFact(fact, joins) {
  const { flowsById, nodesById, edgesById, dataElementsById } = joins;
  const flowIds = _asArray(fact?.contributingGraphIds);
  const resolved = [];
  for (const flowId of flowIds) {
    const flow = flowsById.get(flowId);
    if (!flow) continue;
    const sourceNode = nodesById.get(flow.source);
    const sinkNode = nodesById.get(flow.sink);
    // Reads only edgeIds[0] — mirrors obligation-predicates.js's own
    // disclosed, currently-unreachable limitation (graph-builder.js always
    // mints single-edge flows; see that module's own header) rather than
    // inventing a different convention for the same case here.
    const edge = edgesById.get(_asArray(flow.edgeIds)[0]);
    const dataClasses = _asArray(flow.dataElementIds)
      .map((id) => dataElementsById.get(id))
      .filter(Boolean)
      .flatMap((d) => _asArray(d.dataClasses));
    resolved.push({
      flowId,
      source: sourceNode ? { kind: sourceNode.kind ?? null, subtype: sourceNode.subtype ?? null } : null,
      sink: sinkNode ? { kind: sinkNode.kind ?? null, subtype: sinkNode.subtype ?? null } : null,
      dataClasses: [...new Set(dataClasses)],
      transitVerdict: edge?.protection?.transit?.verdict ?? null,
      atRestVerdict: edge?.protection?.atRest?.verdict ?? null,
      handlingVerdict: edge?.protection?.handling?.verdict ?? null,
    });
  }
  return resolved;
}

function _buildJoins(graph) {
  return {
    flowsById: new Map(_asArray(graph?.flows).filter(Boolean).map((f) => [f.id, f])),
    nodesById: new Map(_asArray(graph?.nodes).filter(Boolean).map((n) => [n.id, n])),
    edgesById: new Map(_asArray(graph?.edges).filter(Boolean).map((e) => [e.id, e])),
    dataElementsById: new Map(_asArray(graph?.dataElements).filter(Boolean).map((d) => [d.id, d])),
  };
}

/**
 * Build an unsigned evidence pack from a framework evaluation. Never
 * throws: every field degrades honestly on missing input rather than
 * fabricating a value — a null/absent graph yields empty facts/
 * evidenceIndex and a null graphDigest/scope, never a guess.
 *
 * @param {object} args
 * @param {object|null} args.graph - the scan's DataFlowGraph v1 document (scan.lineageGraph), or null
 * @param {object} args.framework - the loaded framework object (auditor-walkthrough.js#loadFramework's return)
 * @param {Array}  args.evaluation - auditor-walkthrough.js#evaluateFramework's return (per-control entries, each carrying .obligationMappings)
 * @param {object|null} [args.scanHealth] - scan.scanHealth, passed through verbatim; null if not supplied, never fabricated
 * @param {string|null} [args.engineVersion]
 * @param {string|null} [args.rulesetVersion]
 * @param {string|null} [args.bundleSha]
 * @param {string} [args.generatedAt] - defaults to new Date().toISOString()
 */
function buildObligationEvidencePack({
  graph, framework, evaluation, scanHealth, engineVersion, rulesetVersion, bundleSha, generatedAt,
} = {}) {
  const facts = _asArray(evaluation).flatMap((e) => _asArray(e?.obligationMappings));
  const joins = _buildJoins(graph);
  const evidenceIndex = facts.map((fact) => ({
    obligationId: fact?.id ?? null,
    requirementId: fact?.requirementId ?? null,
    evidence: _resolveEvidenceForFact(fact, joins),
  }));

  return {
    schema: OBLIGATION_EVIDENCE_PACK_SCHEMA,
    framework: {
      id: framework?.id ?? null,
      name: framework?.name ?? null,
      version: framework?.controlsDigest ?? null,
      publisher: framework?.publisher ?? null,
      url: framework?.url ?? null,
    },
    scope: graph?.scope ?? null,
    facts,
    evidenceIndex,
    unknownItems: facts.filter((f) => f?.state === 'unknown'),
    manualItems: facts.filter((f) => f?.state === 'manual_required'),
    acceptedExceptions: facts.filter((f) => f?.state === 'accepted_exception'),
    scanHealth: scanHealth ?? null,
    limitations: _asArray(graph?.limitations),
    graphDigest: graph ? (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__/* .computeGraphDigest */ .a)(graph) : null,
    reproducibility: {
      graphId: graph?.graphId ?? null,
      graphDigest: graph ? (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__/* .computeGraphDigest */ .a)(graph) : null,
      engineVersion: engineVersion ?? null,
      rulesetVersion: rulesetVersion ?? null,
      bundleSha: bundleSha ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
    },
    disclaimer: _evidence_grade_wording_js__WEBPACK_IMPORTED_MODULE_1__/* .EVIDENCE_GRADE_DISCLAIMER */ .ux,
  };
}

/** Sign a pack. Returns a new object; the input is not mutated. */
function signObligationEvidencePack(pack, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_3__.sign(null, Buffer.from((0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(pack), 'utf8'), privateKeyPem);
  return {
    ...pack,
    signature: { algorithm: 'ed25519', canonicalisation: OBLIGATION_EVIDENCE_PACK_SCHEMA, value: sig.toString('base64') },
  };
}

const OBLIGATION_EVIDENCE_PACK_TOP_LEVEL_KEYS = new Set([
  'schema', 'framework', 'scope', 'facts', 'evidenceIndex', 'unknownItems',
  'manualItems', 'acceptedExceptions', 'scanHealth', 'limitations',
  'graphDigest', 'reproducibility', 'disclaimer', 'signature',
]);

/**
 * Verify with a PUBLIC key only. Rejects any top-level key outside the
 * allowlist BEFORE checking the signature — same EA-03 discipline every
 * sibling in this family carries: a signature only covers the bytes it
 * was computed over, so a key stapled on after signing would otherwise
 * verify as authentic.
 */
function verifyObligationEvidencePack(pack, publicKeyPem) {
  if (!pack || typeof pack !== 'object') return { ok: false, reason: 'pack is not an object' };
  if (pack.schema !== OBLIGATION_EVIDENCE_PACK_SCHEMA) return { ok: false, reason: `unrecognised schema: ${pack.schema}` };
  const unknownKeys = Object.keys(pack).filter((k) => !OBLIGATION_EVIDENCE_PACK_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = pack.signature;
  if (!sig?.value) return { ok: false, reason: 'pack is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  const { signature, ...unsigned } = pack;
  let ok = false;
  try {
    ok = node_crypto__WEBPACK_IMPORTED_MODULE_3__.verify(null, Buffer.from((0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_0__/* .canonicalJson */ .dj)(unsigned), 'utf8'), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return ok
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the pack contents — it was modified after signing' };
}




/***/ })

};
