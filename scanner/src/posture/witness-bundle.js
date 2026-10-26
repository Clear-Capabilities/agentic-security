// Replayable path witness bundles (DAG-10, R10.1 to R10.7).
//
// WHAT THIS ADDS
// --------------
// `evidence-bundle.js` signs a per-FINDING claim. A path witness is the evidence for one source-to-sink
// PATH, built so that someone holding only the referenced artifacts can re-derive it offline:
//
//   * the DataFlowGraph (bound by `computeGraphDigest`),
//   * the provenance store export (the raw hop stream plus the out-of-band truncation marks, bound by digest),
//   * the source blobs the path's scopes name (bound by sha256),
//   * the analysis configuration and the transfer-model fingerprints (bound by digest).
//
// A bundle records every edge in order with its full derivation inputs and its call/return binding. The
// replay verifier rebuilds a `PathStore` from the hop stream, requires every recorded edge to be the edge the
// store derives (same id, same endpoints, same discriminator fields, same truncation mark), requires the edges
// to chain, and re-checks every call/return binding against the hops that carry it. Altering an edge, a
// source blob, a call-site binding or the configuration digest makes replay fail.
//
// WHAT A VALID SIGNATURE PROVES
// -----------------------------
// Integrity only: the bundle is the one the signer produced. It does not say the transfer model is correct,
// the finding is real or the path is exploitable. Replay adds: the recorded path re-derives from the
// referenced artifacts under the recorded model fingerprints. It still does not validate the model itself.
//
// FOUR EVIDENCE STATUSES, KEPT APART
// ----------------------------------
// `evidence` carries exactly modeledPath, feasibility, runtimeSupport and exploitProof, each a status and
// nothing else. The verifier rejects any other key there, so a score or a merged confidence cannot be added
// without failing the check. See witness-runtime.js for the rules each one follows.
//
// PARTIAL STAYS PARTIAL
// ---------------------
// Completion is recorded as explicit fields (path, query, analysis, store) plus a derived `overall`. Every
// required field must be present after parsing (a missing field is invalid, never "complete"), and replay
// RE-DERIVES the path's terminal reason and the truncation marks from the artifacts, so a bundle edited to
// claim complete, or a partial one whose fields were dropped in transit, fails.
//
// REDACTION
// ---------
// The bundle holds ids, hashes, kinds, scopes and access paths, never payloads. Free text is passed through
// the existing secret redactor; identities are keyed-hash tokens (`identity-token.js`); a trace or session id
// becomes an opaque reference. Digests and ids are kept, so an authorized replay still works.

import * as crypto from 'node:crypto';
import { PathStore, HOP_FIELDS, classifyIn, classifyOut } from '../lineage/path-store.js';
import { provenanceEdgeId, provenanceNodeId, pathId as makePathId } from '../lineage/ids.js';
import { computeGraphDigest } from '../lineage/export-json.js';
import { DEFAULTS as PATH_QUERY_DEFAULTS } from '../lineage/path-query.js';
import { makeIdentityTokenizer } from '../lineage/identity-token.js';
import { redactString } from '../mcp/redact.js';
import { canonicalJson, keyFingerprint, TRUST_BASES, buildLocalIssuance } from './evidence-bundle.js';
import {
  assessRuntimeSupport, bindExploitProofs, validateControlEvidence, buildEvidenceStatuses,
  sanitizeCausalGroups, EVIDENCE_STATUS_KEYS, MODELED_PATH_STATUSES, FEASIBILITY_STATUSES, RUNTIME_SUPPORT_STATUSES, EXPLOIT_PROOF_STATUSES,
} from './witness-runtime.js';

export const WITNESS_SCHEMA = 'agentic-security/path-witness@1';
const PROVENANCE_ARTIFACT_SCHEMA = 'agentic-security/provenance-hops@1';

const WITNESS_BOUNDS = Object.freeze({ maxPathEdges: 5000, maxHops: 2_000_000, maxSources: 2000, maxSourceBytes: 64 * 1024 * 1024 });

const PROVES = 'The contents of this bundle are exactly what the signer attested, unmodified.';
const DOES_NOT_PROVE =
  'A signature is an integrity claim only. It does not prove the finding is real or exploitable, and it does not ' +
  'prove any transfer model is correct. Replay shows the recorded path re-derives from the referenced artifacts under ' +
  'the recorded model fingerprints; it does not validate those models. Modeled path, feasibility, runtime support and ' +
  'exploit proof are separate statuses and are never combined into one confidence.';

const WITNESS_UNSIGNED_KEYS = [
  'schema', 'graphRef', 'query', 'references', 'path', 'artifacts', 'sources', 'config', 'transferModels',
  'controlEvidence', 'completion', 'evidence', 'runtime', 'exploit', 'graphBinding', 'redaction', 'engine',
  'proves', 'doesNotProve',
];
const WITNESS_TOP_KEYS = new Set([...WITNESS_UNSIGNED_KEYS, 'issuance', 'signature']);
const OVERALL = ['complete', 'partial', 'cancelled', 'unavailable', 'invalid'];

const sha = (text) => `sha256:${crypto.createHash('sha256').update(text).digest('hex')}`;
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const jsonSafe = (v) => JSON.parse(JSON.stringify(v));
const same = (a, b) => canonicalJson(a) === canonicalJson(b);
const fileOfScope = (scope) => (typeof scope === 'string' ? scope.split('::')[0] : null);

// ---- artifacts -------------------------------------------------------------------------------------

/**
 * The provenance store export: the normalized hop stream plus the truncation marks that never travel as hops.
 * `incomplete` is `analysisCompletion.incomplete` from the graph builder (entries `{qid, context, reasons}`).
 */
export function exportProvenanceArtifact({ hops, incomplete = [] }) {
  const seen = new Map();
  for (const h of arr(hops)) {
    const norm = Object.fromEntries(HOP_FIELDS.map((f) => [f, h?.[f] ?? null]));
    seen.set(canonicalJson(norm), norm);
  }
  const hopList = [...seen.keys()].sort().map((k) => seen.get(k));
  const truncations = arr(incomplete)
    .map((u) => ({ scope: u.qid ?? u.scope ?? null, context: u.context ?? null, reason: u.reasons?.[0] ?? u.reason ?? 'analysis-incomplete' }))
    .sort((a, b) => (canonicalJson(a) < canonicalJson(b) ? -1 : 1));
  return { schema: PROVENANCE_ARTIFACT_SCHEMA, hops: hopList, truncations, digest: sha(canonicalJson({ hops: hopList, truncations })) };
}

function artifactDigest(a) {
  return sha(canonicalJson({ hops: a.hops, truncations: a.truncations }));
}

function rebuildStore(artifact, storeLimits) {
  const store = new PathStore(storeLimits);
  store.addHops(artifact.hops);
  for (const t of arr(artifact.truncations)) store.markTruncated(t.scope, t.context, t.reason);
  return store;
}

/**
 * Fingerprints of the behaviour replay relies on. Computed by RUNNING the classifiers on fixed probe hops, not
 * by hashing source text, so a minified bundle and the source tree agree and a behavioural change is caught.
 */
export function transferModelFingerprints() {
  const base = { kind: 'production', subKind: 'ident', scope: 's', dataElementId: 'd', fromPath: null, toPath: null, syntacticPath: null, nodeId: 'n', line: 1, widenReason: null, lossReason: null, context: 'c', peerScope: null, peerContext: null };
  const probes = [
    { ...base, fromPath: 'a' }, { ...base, peerScope: 'p', peerContext: 'pc' }, { ...base, peerScope: 'p', peerContext: 'pc', lossReason: 'context-cap-degraded' }, base,
    { ...base, kind: 'write-out', subKind: 'assign', toPath: 'b' }, { ...base, kind: 'write-out', subKind: 'assign', toPath: 'b', peerScope: 'p', peerContext: 'pc' },
    { ...base, kind: 'write-out', subKind: 'return' }, { ...base, kind: 'write-out', subKind: 'call-arg' }, { ...base, kind: 'write-out', subKind: 'x', lossReason: 'unsupported-target' },
  ];
  const probeResults = probes.map((p) => (p.kind === 'write-out' ? classifyOut(p) : classifyIn(p)));
  const edgeProbe = provenanceEdgeId({ fromNodeId: 'a', toNodeId: 'b', dataElementId: 'd', scope: 's', context: 'c', siteNodeId: 'n', inKind: 'production', inSubKind: 'ident', outKind: 'write-out', outSubKind: 'assign', widenReasons: ['w'], lossReasons: [] });
  const nodeProbe = provenanceNodeId({ kind: 'path', scope: 's', context: 'c', path: 'p', siteNodeId: null, dataElementId: 'd' });
  return {
    hopRecord: sha(canonicalJson(HOP_FIELDS)),
    halfEdgeClassification: sha(canonicalJson(probeResults)),
    identity: sha(canonicalJson([edgeProbe, nodeProbe])),
    pathQueryDefaults: sha(canonicalJson(PATH_QUERY_DEFAULTS)),
  };
}

// ---- records ---------------------------------------------------------------------------------------

function bindingOf(store, edge) {
  const from = store.getNode(edge.fromNodeId); const to = store.getNode(edge.toNodeId);
  const fromPeer = !!from && (from.scope !== edge.scope || from.context !== edge.context);
  const toPeer = !!to && (to.scope !== edge.scope || to.context !== edge.context);
  let direction = 'local'; let callee = null;
  if (fromPeer && toPeer) direction = 'invalid';
  else if (fromPeer) { direction = 'return'; callee = from; } else if (toPeer) { direction = 'call'; callee = to; }
  return {
    siteNodeId: edge.siteNodeId, callerScope: edge.scope, callerContext: edge.context, direction,
    calleeScope: callee ? callee.scope : null, calleeContext: callee ? callee.context : null, line: edge.line ?? null,
  };
}

function edgeRecordOf(store, edge) {
  return {
    edgeId: edge.id, fromNodeId: edge.fromNodeId, toNodeId: edge.toNodeId, dataElementId: edge.dataElementId,
    scope: edge.scope, context: edge.context, siteNodeId: edge.siteNodeId,
    inKind: edge.inKind, inSubKind: edge.inSubKind, outKind: edge.outKind, outSubKind: edge.outSubKind,
    widenReasons: [...edge.widenReasons], lossReasons: [...edge.lossReasons],
    crossScope: !!edge.crossScope, ambiguousCorrelation: !!edge.ambiguousCorrelation, originated: !!edge.originated,
    truncated: !!edge.truncated, line: edge.line ?? null, binding: bindingOf(store, edge),
  };
}

function nodeRef(n) { return n ? { nodeId: n.id, kind: n.kind, scope: n.scope, context: n.context } : null; }

function deriveOverall(c) {
  if (c.query.status === 'invalid') return 'invalid';
  if (c.analysis.status === 'cancelled') return 'cancelled';
  if (c.analysis.status === 'unavailable' || c.query.status === 'unavailable') return 'unavailable';
  if (c.query.status === 'cancelled') return 'cancelled';
  if (c.path.complete !== true || c.query.status !== 'complete' || c.analysis.status !== 'complete' || c.store.limitHit !== false) return 'partial';
  return 'complete';
}

function terminalReasonFor(store, path, maxDepth) {
  const first = path.nodeIds[0];
  const incoming = store.edgesTo(first);
  if (incoming.length === 0) {
    return store.diagnostics().orphanedPeerSources.some((o) => o.nodeId === first) ? 'incomplete-record' : 'origin';
  }
  // The walk checks depth before it looks for a cycle, so a node at the depth limit is a depth-limit stop.
  if (Number.isInteger(maxDepth) && path.nodeIds.length - 1 >= maxDepth) return 'depth-limit';
  const onPath = new Set(path.nodeIds);
  return incoming.every((e) => onPath.has(e.fromNodeId)) ? 'cycle' : 'depth-limit';
}

function compactEdgeStates(edgeStates, graphEdgeIds) {
  if (!isObj(edgeStates) || !edgeStates.evaluated) return { evaluated: false, byEdge: {} };
  const byEdge = {};
  for (const id of graphEdgeIds) {
    const s = edgeStates.byEdge?.[id];
    byEdge[id] = { states: arr(s?.states).filter((x) => typeof x === 'string').sort(), uncertainObservations: Number.isInteger(s?.uncertainObservations) ? s.uncertainObservations : 0 };
  }
  return { evaluated: true, byEdge };
}

// ---- build -----------------------------------------------------------------------------------------

/**
 * Build an unsigned witness bundle for one reconstructed path.
 *
 * @param {object} o
 * @param {object} o.result       the `reconstructPaths` result the path came from
 * @param {object} [o.path]       one of `result.paths` (default: the first, or the one named by `o.pathId`)
 * @param {object} o.store        the PathStore the result was computed over
 * @param {object} o.graph        the DataFlowGraph the store's analysis produced
 * @param {object} o.provenance   `exportProvenanceArtifact(...)` of the same analysis
 * @param {object} [o.analysisConfig] extra configuration to bind (budgets already recorded)
 * @param {object} [o.sourceBlobs] { file: text } the path's scopes name
 * @param {object} [o.graphBinding] { flowId } to bind the path to a DataFlowGraph flow (required for runtime evidence)
 * @param {object|null} [o.controlEvidence] the DAG-04 slot; null until it exists
 * @param {object} [o.runtime]    { edgeStates, causalGroups, expected }
 * @param {object[]} [o.exploitProofs]
 * @returns {{ok:true, bundle:object}|{ok:false, reason:string}}
 */
export function buildWitnessBundle(o = {}) {
  const { result, store, graph, provenance } = o;
  if (!isObj(result) || !store || !isObj(graph) || !isObj(provenance)) return { ok: false, reason: 'result, store, graph and provenance are required' };
  if (provenance.schema !== PROVENANCE_ARTIFACT_SCHEMA || artifactDigest(provenance) !== provenance.digest) return { ok: false, reason: 'provenance artifact is malformed or its digest does not match' };
  const path = o.path ?? (o.pathId ? result.paths.find((p) => p.id === o.pathId) : result.paths[0]);
  if (!path || !arr(path.edgeIds).length) return { ok: false, reason: 'no path to witness (an empty or unknown result has nothing to attest)' };
  if (path.edgeIds.length > WITNESS_BOUNDS.maxPathEdges) return { ok: false, reason: `path exceeds ${WITNESS_BOUNDS.maxPathEdges} edges` };

  const edges = [];
  for (const id of path.edgeIds) {
    const e = store.getEdge(id);
    if (!e) return { ok: false, reason: `edge ${id} is not in the supplied store` };
    edges.push(edgeRecordOf(store, e));
  }
  const srcNode = store.getNode(edges[0].fromNodeId); const sinkNode = store.getNode(edges[edges.length - 1].toNodeId);
  if (!srcNode || !sinkNode) return { ok: false, reason: 'path endpoints are not in the supplied store' };

  const storeLimits = store.limitStatus();
  // The store handed in must be the one the provenance export describes: rebuild from the export and require
  // identical edges. Otherwise the bundle could not be replayed, or a truncation mark could be missing from it.
  const check = rebuildStore(provenance, storeLimits.limits);
  for (const rec of edges) {
    const e = check.getEdge(rec.edgeId);
    if (!e || !same(rec, edgeRecordOf(check, e))) return { ok: false, reason: `the supplied store and the provenance export disagree on edge ${rec.edgeId}` };
  }
  const budget = { ...result.budget }; delete budget.expansionsUsed;
  const config = { pathQuery: budget, storeLimits: storeLimits.limits, ...(isObj(o.analysisConfig) ? { extra: o.analysisConfig } : {}) };
  const analysisConfigDigest = sha(canonicalJson(config));
  const graphDigest = computeGraphDigest(graph);

  const files = [...new Set([srcNode, sinkNode, ...edges.flatMap((e) => [store.getNode(e.fromNodeId), store.getNode(e.toNodeId)])].map((n) => fileOfScope(n?.scope)).filter(Boolean))].sort();
  const sources = []; const unboundSourceFiles = [];
  for (const f of files) {
    const text = o.sourceBlobs?.[f];
    if (typeof text === 'string' || Buffer.isBuffer(text)) {
      const buf = Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8');
      sources.push({ file: f, sha256: sha(buf), bytes: buf.length });
    } else unboundSourceFiles.push(f);
  }

  const aCompletion = graph.coverage?.analysisCompletion ?? { status: 'complete' };
  const completion = {
    path: { complete: path.complete === true, terminalReason: path.terminal?.reason ?? null, analysisTruncated: path.analysisTruncated === true, ambiguousHopCount: path.ambiguousHopCount ?? 0 },
    query: {
      status: result.status ?? 'partial', queryExhausted: result.status !== 'invalid' && result.truncated === false,
      truncated: result.truncated === true, truncationReasons: arr(result.truncationReasons),
      modelCoverage: (aCompletion.status === 'complete' && !storeLimits.hit && path.analysisTruncated !== true) ? 'complete' : 'partial',
      negativeClaimAllowed: false, droppedPathCount: result.droppedPathCount ?? 0, enumeratedPathCount: result.enumeratedPathCount ?? 0, cyclesClipped: result.cyclesClipped ?? 0,
    },
    analysis: { status: aCompletion.status ?? 'complete', incompleteUnits: arr(aCompletion.incomplete).length, reasons: [...new Set(arr(aCompletion.incomplete).flatMap((u) => arr(u.reasons)))].sort() },
    store: { limitHit: storeLimits.hit === true, hopsRefused: storeLimits.hopsRefused, groupsSkipped: storeLimits.groupsSkipped.length, edgesRefused: storeLimits.edgesRefused },
  };
  completion.overall = deriveOverall(completion);

  // ---- graph binding, runtime evidence, proofs ----
  let graphBinding = null; let pathGraphEdgeIds = [];
  if (o.graphBinding) {
    const flow = arr(graph.flows).find((f) => f.id === o.graphBinding.flowId);
    if (!flow) return { ok: false, reason: `flow ${o.graphBinding.flowId} is not in the graph` };
    pathGraphEdgeIds = arr(flow.edgeIds).slice();
    graphBinding = { flowId: flow.id, edgeIds: pathGraphEdgeIds, sourceNodeId: flow.source ?? flow.sourceNodeId ?? null, sinkNodeId: flow.sink ?? flow.sinkNodeId ?? null };
  } else if (o.runtime) return { ok: false, reason: 'runtime evidence needs graphBinding.flowId: telemetry maps to DataFlowGraph edges' };

  const ce = o.controlEvidence ?? null;
  const ceCheck = validateControlEvidence(ce, edges.map((e) => e.edgeId));
  if (!ceCheck.ok) return { ok: false, reason: `control evidence: ${ceCheck.errors.join('; ')}` };

  const tokenize = o.tokenize ?? makeIdentityTokenizer();
  let runtime;
  if (o.runtime) {
    const groups = sanitizeCausalGroups(o.runtime.causalGroups, { tokenize });
    const expected = sanitizeExpected(o.runtime.expected, tokenize);
    const edgeStates = compactEdgeStates(o.runtime.edgeStates, pathGraphEdgeIds);
    runtime = { consulted: edgeStates.evaluated, inputs: { edgeStates, causalGroups: groups.groups, expected }, droppedFields: groups.droppedFields, rejectedGroups: groups.rejected.length };
  } else runtime = { consulted: false, inputs: null, droppedFields: 0, rejectedGroups: 0 };
  runtime.assessment = runtimeAssessment(runtime, pathGraphEdgeIds);

  const sinkRef = sinkNode.id;
  const exploitInputs = arr(o.exploitProofs).map((p) => sanitizeProof(p));
  const exploit = { inputs: exploitInputs, ...bindExploitProofs(exploitInputs, { sinkRef, dataElementId: edges[0].dataElementId, graphDigest, analysisConfigDigest }) };

  const sourcePath = redactString(srcNode.path ?? ''); const sinkPath = redactString(sinkNode.path ?? '');
  const redactions = (srcNode.path && sourcePath !== srcNode.path ? 1 : 0) + (sinkNode.path && sinkPath !== sinkNode.path ? 1 : 0);

  const bundle = jsonSafe({
    schema: WITNESS_SCHEMA,
    graphRef: { id: graph.graphId ?? null, digest: graphDigest, analysisConfigDigest },
    query: { direction: 'backward', sinkRef, argumentIndex: null, accessPath: sinkPath || null, contextRef: sinkNode.context ?? null },
    references: {
      source: nodeRef(srcNode), sink: nodeRef(sinkNode),
      field: { dataElementId: edges[0].dataElementId, sourcePath: sourcePath || null, sinkPath: sinkPath || null },
      unboundSourceFiles,
    },
    path: {
      pathId: path.id, nodeIds: arr(path.nodeIds), hopCount: edges.length, edges,
      terminal: { nodeId: path.terminal?.nodeId ?? null, reason: path.terminal?.reason ?? null, kind: path.terminal?.kind ?? null },
    },
    artifacts: { provenance: { schema: provenance.schema, digest: provenance.digest, hopCount: provenance.hops.length, truncationCount: provenance.truncations.length } },
    sources,
    config,
    transferModels: transferModelFingerprints(),
    controlEvidence: ce,
    completion,
    evidence: buildEvidenceStatuses({ pathComplete: completion.path.complete && completion.overall === 'complete', controlEvidence: ce, runtime: runtime.assessment, exploit }),
    runtime,
    exploit,
    graphBinding,
    redaction: { redactions, identityTokens: 'keyed-hash (idt_)', sessionRefs: 'opaque (sref_)', payloads: 'never recorded' },
    engine: { engineVersion: o.engine?.engineVersion ?? null, bundleSha: o.engine?.bundleSha ?? null, commit: o.engine?.commit ?? null },
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  });
  return { ok: true, bundle };
}

function sanitizeExpected(e, tokenize) {
  const x = isObj(e) ? e : {};
  const ref = (v) => (typeof v === 'string' && /^[A-Za-z0-9._:@/-]{1,160}$/.test(v) ? v : null);
  const w = isObj(x.window) ? { start: typeof x.window.start === 'string' ? x.window.start : null, end: typeof x.window.end === 'string' ? x.window.end : null } : null;
  const tok = typeof x.identityToken === 'string' && /^idt_[0-9a-f]{16}$/.test(x.identityToken) ? x.identityToken : (typeof x.identity === 'string' ? tokenize(x.identity) : null);
  return { environment: ref(x.environment), deploymentRef: ref(x.deploymentRef), deploymentConfigDigest: ref(x.deploymentConfigDigest), identityToken: tok, window: w, maxWindowMs: Number.isFinite(x.maxWindowMs) ? x.maxWindowMs : null };
}

function sanitizeProof(p) {
  if (!isObj(p)) return { id: null, kind: null };
  const ref = (v) => (typeof v === 'string' && /^[A-Za-z0-9._:@/-]{1,160}$/.test(v) ? v : null);
  return {
    id: ref(p.id), kind: ['proof', 'dnr-hunt', 'incident'].includes(p.kind) ? p.kind : null, sinkRef: ref(p.sinkRef), dataElementId: ref(p.dataElementId),
    graphDigest: ref(p.graphDigest), analysisConfigDigest: ref(p.analysisConfigDigest), note: typeof p.note === 'string' ? redactString(p.note).slice(0, 200) : null,
  };
}

function runtimeAssessment(runtime, pathGraphEdgeIds) {
  if (!runtime.inputs) return assessRuntimeSupport({ pathEdgeIds: pathGraphEdgeIds, edgeStates: null });
  const x = runtime.inputs;
  return assessRuntimeSupport({
    pathEdgeIds: pathGraphEdgeIds, edgeStates: x.edgeStates,
    causalGroups: x.causalGroups, expected: { ...x.expected, maxWindowMs: x.expected.maxWindowMs ?? undefined },
  });
}

// ---- signing ---------------------------------------------------------------------------------------

function signedBytes(bundle) {
  const signed = {};
  for (const k of WITNESS_UNSIGNED_KEYS) signed[k] = bundle[k];
  if (bundle.issuance !== undefined) signed.issuance = bundle.issuance;
  return Buffer.from(canonicalJson(signed), 'utf8');
}

/** Sign with the same Ed25519 key and self-issued trust basis as finding evidence bundles. */
export function signWitnessBundle(bundle, privateKeyPem) {
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const withIssuance = { ...bundle, issuance: buildLocalIssuance(publicKeyPem) };
  const sig = crypto.sign(null, signedBytes(withIssuance), privateKeyPem);
  return { ...withIssuance, signature: { algorithm: 'ed25519', canonicalisation: WITNESS_SCHEMA, value: sig.toString('base64') } };
}

/** Integrity check with a PUBLIC key. Never throws. */
export function verifyWitnessSignature(bundle, publicKeyPem) {
  if (!isObj(bundle)) return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== WITNESS_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  const unknown = Object.keys(bundle).filter((k) => !WITNESS_TOP_KEYS.has(k));
  if (unknown.length) return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknown.join(', ')}` };
  const missing = WITNESS_UNSIGNED_KEYS.filter((k) => !Object.prototype.hasOwnProperty.call(bundle, k));
  if (missing.length) return { ok: false, reason: `required field(s) missing (a missing field is never read as complete): ${missing.join(', ')}` };
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let ok = false;
  try { ok = crypto.verify(null, signedBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64')); } catch (e) { return { ok: false, reason: `verification error: ${e.message}` }; }
  if (!ok) return { ok: false, reason: 'signature does not match the bundle contents: it was modified after signing' };
  const iss = bundle.issuance;
  if (iss === undefined) return { ok: true, reason: null, trustBasis: 'none-declared', independentlyCertified: false, issuer: null, trustNote: 'No trust basis is declared. Treat it as unattested provenance.' };
  const basis = isObj(iss) ? TRUST_BASES[iss.trustBasis] : undefined;
  if (!basis) return { ok: false, reason: `unsupported trust basis: ${JSON.stringify(iss?.trustBasis ?? null)}` };
  if (iss.independentlyCertified !== false) return { ok: false, reason: 'a self-issued bundle may not claim independent certification' };
  let fp; try { fp = keyFingerprint(publicKeyPem); } catch (e) { return { ok: false, reason: `verification error: ${e.message}` }; }
  if (iss.issuer?.keyFingerprint !== fp) return { ok: false, reason: 'the declared issuer key does not match the key that verified the signature' };
  return { ok: true, reason: null, trustBasis: iss.trustBasis, independentlyCertified: false, issuer: iss.issuer, trustNote: basis.statement };
}

/** Strict parse: JSON, then the same required-field gate verification uses. */
export function parseWitnessBundle(text) {
  let b; try { b = JSON.parse(text); } catch (e) { return { ok: false, reason: `not JSON: ${e.message}` }; }
  if (!isObj(b) || b.schema !== WITNESS_SCHEMA) return { ok: false, reason: 'not a path witness bundle' };
  const shape = shapeFailures(b);
  return shape.length ? { ok: false, reason: shape[0].detail } : { ok: true, bundle: b };
}

// ---- replay ----------------------------------------------------------------------------------------

function shapeFailures(b) {
  const f = (detail) => [{ code: 'schema', detail }];
  const missing = WITNESS_UNSIGNED_KEYS.filter((k) => !Object.prototype.hasOwnProperty.call(b, k));
  if (missing.length) return f(`required field(s) missing: ${missing.join(', ')}`);
  const c = b.completion;
  if (!isObj(c) || !isObj(c.path) || !isObj(c.query) || !isObj(c.analysis) || !isObj(c.store)) return f('completion record is incomplete');
  if (typeof c.path.complete !== 'boolean' || typeof c.query.truncated !== 'boolean' || typeof c.store.limitHit !== 'boolean') return f('completion flags must be booleans');
  if (!['complete', 'partial', 'cancelled', 'unavailable', 'invalid'].includes(c.query.status) || typeof c.analysis.status !== 'string') return f('completion status is missing');
  if (!OVERALL.includes(c.overall)) return f('completion.overall is missing or unknown');
  if (!isObj(b.path) || !Array.isArray(b.path.edges) || !Array.isArray(b.path.nodeIds)) return f('path record is malformed');
  if (!isObj(b.evidence) || Object.keys(b.evidence).sort().join() !== [...EVIDENCE_STATUS_KEYS].sort().join()) return f('evidence must hold exactly the four separate statuses and nothing else (no merged score or confidence)');
  const legal = { modeledPath: MODELED_PATH_STATUSES, feasibility: FEASIBILITY_STATUSES, runtimeSupport: RUNTIME_SUPPORT_STATUSES, exploitProof: EXPLOIT_PROOF_STATUSES };
  for (const k of EVIDENCE_STATUS_KEYS) {
    if (!isObj(b.evidence[k]) || Object.keys(b.evidence[k]).join() !== 'status') return f(`evidence.${k} must be a status only`);
    if (!legal[k].includes(b.evidence[k].status)) return f(`evidence.${k} has an unknown status`);
  }
  return [];
}

/**
 * Offline, bounded replay of a bundle against the artifact set it names.
 *
 * @param {object} bundle
 * @param {{graph:object, provenance:object, sources?:Object<string,string>, config?:object}} artifacts
 * @returns {{ok:boolean, failures:{code:string,detail:string}[], warnings:string[], derived:object}}
 */
export function replayWitness(bundle, artifacts, opts = {}) {
  const bounds = { ...WITNESS_BOUNDS, ...opts.bounds };
  const failures = []; const warnings = []; const derived = {};
  const fail = (code, detail) => { if (failures.length < 50) failures.push({ code, detail }); };
  const early = isObj(bundle) ? shapeFailures(bundle) : [{ code: 'schema', detail: 'bundle is not an object' }];
  if (early.length) return { ok: false, failures: early, warnings, derived };
  if (bundle.schema !== WITNESS_SCHEMA) return { ok: false, failures: [{ code: 'schema', detail: `unrecognised schema ${bundle.schema}` }], warnings, derived };
  const unknown = Object.keys(bundle).filter((k) => !WITNESS_TOP_KEYS.has(k));
  if (unknown.length) fail('schema', `unrecognised top-level key(s): ${unknown.join(', ')}`);
  if (bundle.proves !== PROVES || bundle.doesNotProve !== DOES_NOT_PROVE) fail('schema', 'the proves / doesNotProve statements were altered or dropped');
  if (!isObj(artifacts) || !isObj(artifacts.graph) || !isObj(artifacts.provenance)) return { ok: false, failures: [...failures, { code: 'artifacts', detail: 'graph and provenance artifacts are required to replay' }], warnings, derived };
  if (bundle.path.edges.length === 0 || bundle.path.edges.length > bounds.maxPathEdges) fail('bounds', `path has ${bundle.path.edges.length} edges (allowed 1 to ${bounds.maxPathEdges})`);
  if (arr(bundle.sources).length > bounds.maxSources) fail('bounds', 'too many source entries');
  const prov = artifacts.provenance;
  if (prov.schema !== PROVENANCE_ARTIFACT_SCHEMA || !Array.isArray(prov.hops) || !Array.isArray(prov.truncations)) {
    fail('artifacts', 'provenance artifact is malformed');
    return { ok: false, failures, warnings, derived };
  }
  if (prov.hops.length > bounds.maxHops) { fail('bounds', 'provenance artifact exceeds the replay hop bound'); return { ok: false, failures, warnings, derived }; }
  if (failures.some((x) => x.code === 'bounds')) return { ok: false, failures, warnings, derived };

  // 1. artifact and configuration digests
  if (computeGraphDigest(artifacts.graph) !== bundle.graphRef.digest) fail('graph-digest', 'the graph artifact does not match the digest the bundle was built against');
  if ((artifacts.graph.graphId ?? null) !== bundle.graphRef.id) fail('graph-id', 'the graph artifact is a different graph than the bundle names');
  if (artifactDigest(prov) !== bundle.artifacts.provenance.digest) fail('provenance-digest', 'the provenance store export does not match the digest the bundle was built against');
  if (sha(canonicalJson(bundle.config)) !== bundle.graphRef.analysisConfigDigest) fail('config-digest', 'the recorded configuration does not match its digest');
  if (isObj(artifacts.config) && sha(canonicalJson(artifacts.config)) !== bundle.graphRef.analysisConfigDigest) fail('config-digest', 'the supplied configuration does not match the bundle configuration digest');
  if (!same(bundle.transferModels, transferModelFingerprints())) fail('transfer-model', 'the transfer-model fingerprints differ from this verifier; replay under a different model proves nothing');

  // 2. source blobs
  let totalBytes = 0;
  for (const s of arr(bundle.sources)) {
    const text = artifacts.sources?.[s.file];
    if (typeof text !== 'string' && !Buffer.isBuffer(text)) { fail('source-blob-missing', `source blob ${s.file} was not supplied`); continue; }
    const buf = Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8');
    totalBytes += buf.length;
    if (totalBytes > bounds.maxSourceBytes) { fail('bounds', 'source blobs exceed the replay byte bound'); break; }
    if (sha(buf) !== s.sha256) fail('source-blob-altered', `source blob ${s.file} does not match its recorded digest`);
  }
  if (arr(bundle.references.unboundSourceFiles).length) warnings.push(`${bundle.references.unboundSourceFiles.length} referenced source file(s) were not bound by digest`);

  // 3. rebuild the store and re-derive every edge
  const store = rebuildStore(prov, bundle.config?.storeLimits);
  const lim = store.limitStatus();
  derived.storeLimitHit = lim.hit;
  if (lim.hit !== bundle.completion.store.limitHit) fail('completeness', 'the recorded store-limit state differs from the replayed store');
  const hopIndex = new Map();
  for (const h of prov.hops) {
    if (h.peerScope == null) continue;
    const k = canonicalJson([h.scope, h.nodeId, h.dataElementId, h.context, h.peerScope, h.peerContext]);
    hopIndex.set(k, true);
  }
  const edges = bundle.path.edges; const nodeIds = [];
  edges.forEach((rec, i) => {
    if (!isObj(rec)) { fail('edge-altered', `edge ${i} is not an object`); return; }
    const recomputed = provenanceEdgeId({ ...rec, widenReasons: arr(rec.widenReasons), lossReasons: arr(rec.lossReasons) });
    if (recomputed !== rec.edgeId) fail('edge-derivation', `edge ${i} (${rec.edgeId}) does not derive from its recorded fields`);
    const e = store.getEdge(rec.edgeId);
    if (!e) { fail('edge-missing', `edge ${i} (${rec.edgeId}) is not derived by the provenance store export`); return; }
    const truth = edgeRecordOf(store, e);
    if (!same(rec, truth)) fail('edge-altered', `edge ${i} (${rec.edgeId}) differs from the edge the store derives`);
    // call/return binding, against the model and against the carrying hops
    const b = truth.binding;
    if (b.direction === 'invalid') fail('binding', `edge ${i} has both endpoints in a callee namespace`);
    if (truth.crossScope !== (b.direction === 'call' || b.direction === 'return')) fail('binding', `edge ${i} crossScope disagrees with its binding direction`);
    if (b.direction === 'call' || b.direction === 'return') {
      const k = canonicalJson([b.callerScope, b.siteNodeId, truth.dataElementId, b.callerContext, b.calleeScope, b.calleeContext]);
      if (!hopIndex.has(k)) fail('binding', `edge ${i}: no recorded hop carries the ${b.direction} binding to ${b.calleeScope}`);
    }
    if (!same(rec.binding, b)) fail('binding', `edge ${i} call-site binding was altered`);
    if (i === 0) nodeIds.push(rec.fromNodeId);
    if (i > 0 && edges[i - 1].toNodeId !== rec.fromNodeId) fail('path-chain', `edge ${i} does not continue from edge ${i - 1}`);
    nodeIds.push(rec.toNodeId);
  });
  if (!same(nodeIds, bundle.path.nodeIds)) fail('path-chain', 'recorded node sequence does not follow from the edge sequence');
  const last = nodeIds[nodeIds.length - 1];
  if (makePathId({ startNodeId: last, edgeIds: edges.map((e) => e.edgeId) }) !== bundle.path.pathId) fail('path-chain', 'path id does not derive from the edge sequence');

  // 4. references
  const src = store.getNode(nodeIds[0]); const sink = store.getNode(last);
  if (!same(nodeRef(src), bundle.references.source) || !same(nodeRef(sink), bundle.references.sink)) fail('references', 'source or sink reference does not match the replayed store');
  if (bundle.query.sinkRef !== last || bundle.query.contextRef !== (sink?.context ?? null)) fail('references', 'query sink or context reference does not match the replayed path');
  if (bundle.references.field.dataElementId !== edges[0]?.dataElementId) fail('references', 'field reference does not match the path');
  if (src && bundle.references.field.sourcePath !== (redactString(src.path ?? '') || null)) fail('references', 'source access path does not match the replayed store');
  if (sink && bundle.references.field.sinkPath !== (redactString(sink.path ?? '') || null)) fail('references', 'sink access path does not match the replayed store');
  const files = new Set([src, sink, ...nodeIds.map((id) => store.getNode(id))].map((n) => fileOfScope(n?.scope)).filter(Boolean));
  const covered = new Set([...arr(bundle.sources).map((s) => s.file), ...arr(bundle.references.unboundSourceFiles)]);
  if (!same([...files].sort(), [...covered].sort())) fail('source-blob-missing', 'the source files named by the path scopes are not all bound or declared unbound');

  // 5. completion, re-derived
  if (src) {
    const reason = terminalReasonFor(store, { nodeIds }, bundle.config?.pathQuery?.maxDepth);
    derived.terminalReason = reason;
    if (bundle.path.terminal.reason !== reason || bundle.completion.path.terminalReason !== reason) fail('completeness', `terminal reason is ${reason} on replay, not ${bundle.path.terminal.reason}`);
    const pathComplete = reason === 'origin';
    if (bundle.completion.path.complete !== pathComplete) fail('completeness', 'path completeness was altered: the path ends at a non-origin node');
    const anyTruncated = edges.some((_, i) => store.getEdge(edges[i].edgeId)?.truncated) || nodeIds.some((id) => store.getNode(id)?.truncated);
    if (anyTruncated && bundle.completion.analysis.status === 'complete') fail('completeness', 'a node or edge on the path is marked truncated but the analysis is recorded complete');
    if (prov.truncations.length > 0 && bundle.completion.analysis.status === 'complete') fail('completeness', 'the provenance export records incomplete analysis units but the bundle claims complete');
    const overall = deriveOverall({ ...bundle.completion, path: { ...bundle.completion.path, complete: pathComplete && bundle.completion.path.complete } });
    derived.overall = overall;
    if (overall !== bundle.completion.overall) fail('completeness', `overall completeness is ${overall} on replay, not ${bundle.completion.overall}`);
    if (bundle.completion.query.negativeClaimAllowed !== false) fail('completeness', 'a witness cannot carry a negative claim');
  }

  // 6. graph binding, control evidence, runtime, proofs, evidence statuses
  const gb = bundle.graphBinding;
  if (gb) {
    const flow = arr(artifacts.graph.flows).find((f) => f.id === gb.flowId);
    if (!flow) fail('graph-binding', `flow ${gb.flowId} is not in the graph artifact`);
    else if (!same(arr(flow.edgeIds), gb.edgeIds)) fail('graph-binding', 'the flow edge ids differ from the graph artifact');
    const gEdges = new Set(arr(artifacts.graph.edges).map((e) => e.id));
    if (gb.edgeIds.some((id) => !gEdges.has(id))) fail('graph-binding', 'a bound graph edge is not in the graph artifact');
  }
  const ceCheck = validateControlEvidence(bundle.controlEvidence, edges.map((e) => e.edgeId));
  if (!ceCheck.ok) fail('control-evidence', ceCheck.errors.join('; '));
  const rt = bundle.runtime;
  const reAssessed = isObj(rt) ? runtimeAssessment(rt, gb ? gb.edgeIds : []) : null;
  if (!reAssessed || !same(reAssessed, rt.assessment)) fail('runtime-inconsistent', 'the recorded runtime assessment does not follow from its recorded inputs');
  if (rt?.inputs && !gb) fail('runtime-inconsistent', 'runtime inputs without a graph binding');
  const reBound = bindExploitProofs(arr(bundle.exploit?.inputs), { sinkRef: last, dataElementId: edges[0]?.dataElementId, graphDigest: bundle.graphRef.digest, analysisConfigDigest: bundle.graphRef.analysisConfigDigest });
  if (!same({ status: reBound.status, bound: reBound.bound, rejected: reBound.rejected }, { status: bundle.exploit?.status, bound: bundle.exploit?.bound, rejected: bundle.exploit?.rejected })) fail('proof-binding', 'the recorded proof binding does not follow from the sink, value and configuration it is bound to');
  if (reAssessed && bundle.completion) {
    const ev = buildEvidenceStatuses({ pathComplete: bundle.completion.path.complete && derived.overall === 'complete', controlEvidence: bundle.controlEvidence, runtime: reAssessed, exploit: reBound });
    if (!same(ev, bundle.evidence)) fail('evidence-statuses', 'the four evidence statuses do not follow from their inputs');
  }
  return { ok: failures.length === 0, failures, warnings, derived };
}

/**
 * Integrity (public key) plus, when artifacts are supplied, offline replay.
 * `verdict`: 'replayed' (both hold), 'integrity-only' (signature valid, no replay attempted), 'invalid'.
 */
export function verifyWitness(bundle, publicKeyPem, artifacts, opts = {}) {
  const signature = verifyWitnessSignature(bundle, publicKeyPem);
  const statement = { proves: PROVES, doesNotProve: DOES_NOT_PROVE };
  if (!signature.ok) return { ok: false, verdict: 'invalid', signature, replay: { performed: false, ok: false, failures: [], warnings: [] }, statement };
  if (!artifacts) return { ok: true, verdict: 'integrity-only', signature, replay: { performed: false, ok: false, failures: [], warnings: [] }, statement };
  const replay = replayWitness(bundle, artifacts, opts);
  return { ok: replay.ok, verdict: replay.ok ? 'replayed' : 'invalid', signature, replay: { performed: true, ...replay }, statement };
}
