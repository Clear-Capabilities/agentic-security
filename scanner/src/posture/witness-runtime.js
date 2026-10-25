// Runtime support, feasibility and exploit-proof evidence for a path witness (DAG-10, R10.3 to R10.7).
//
// Pure: no fs, no network, never throws, never mutates its inputs. It READS the per-edge states that
// `lineage/runtime-edge-states.js` already derives and adds the one thing those states cannot say: whether
// the observed edges of a path belong to ONE execution.
//
// FOUR EVIDENCE STATUSES, NEVER MERGED
// ------------------------------------
//   modeledPath    the static analysis connected source to sink (complete or partial)
//   feasibility    a predicate / control check on the path (a nullable slot until DAG-04 supplies it)
//   runtimeSupport what telemetry says about the path (this file)
//   exploitProof   explicit, execution-backed proof bound to this sink, value and configuration
// They are reported side by side. There is deliberately no function here (and the verifier rejects any bundle
// field) that combines them into a score, a level or a single confidence.
//
// WHAT RUNTIME SUPPORT MAY CLAIM
// ------------------------------
//   * Several edges observed does NOT prove one end-to-end execution. `path_supported` needs ONE causal group
//     (a trace or session the caller can name) that covers EVERY edge, in a compatible environment,
//     deployment, time window and identity scope, with unambiguous edge mappings. Edges seen in unrelated
//     traces are `edge_partial`, however many there are.
//   * Low-confidence and ambiguous mappings stay CANDIDATES (`candidate_only`); they never count as observed.
//   * No telemetry is not evidence of safety: `no_observation_in_window` and `not_consulted` are different
//     answers and neither says "the path is not exercised".
//   * A denied observation proves only that attempt was refused (`blocked_attempt`), not every execution.
//
// KNOWN LIMIT: the closed-world RuntimeObservation contract carries no trace or session token (by design:
// it is metadata-only). Causal groups are therefore supplied by the caller from a source that has one, and
// without them the strongest honest answer from the observation store alone is `edge_partial`.

import * as crypto from 'node:crypto';
import { redactString } from '../mcp/redact.js';
import { makeIdentityTokenizer } from '../lineage/identity-token.js';

export const RUNTIME_SUPPORT_STATUSES = Object.freeze([
  'not_consulted', 'no_observation_in_window', 'candidate_only', 'edge_partial', 'path_supported', 'blocked_attempt',
]);
export const EXPLOIT_PROOF_STATUSES = Object.freeze(['none', 'bound', 'rejected']);
export const FEASIBILITY_STATUSES = Object.freeze(['not_assessed', 'feasible', 'infeasible', 'unknown']);
export const MODELED_PATH_STATUSES = Object.freeze(['connected_complete', 'connected_partial']);
export const EVIDENCE_STATUS_KEYS = Object.freeze(['modeledPath', 'feasibility', 'runtimeSupport', 'exploitProof']);

const DEFAULT_MAX_WINDOW_MS = 5 * 60 * 1000;
const TRUSTED_CONFIDENCE = new Set(['high', 'medium']);
const REF_RE = /^[A-Za-z0-9._:@/-]{1,160}$/;
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

/** A caller trace/session id becomes an opaque reference: comparable, never the raw value. */
function pseudonymizeSessionRef(raw) {
  return typeof raw === 'string' && raw.length > 0 ? `sref_${sha(`session-ref:v1:${raw}`).slice(0, 16)}` : null;
}

function iso(v) {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

/**
 * Reduce caller-supplied causal groups to the closed set of fields the assessment reads. Unknown fields are
 * dropped and only COUNTED (their names could themselves carry a value). Identities are tokenized with the
 * existing keyed-hash convention; a raw identity with no tokenizer is dropped, never kept.
 */
export function sanitizeCausalGroups(groups, { tokenize = makeIdentityTokenizer() } = {}) {
  const out = []; const rejected = []; let droppedFields = 0;
  const GROUP_KEYS = new Set(['id', 'sessionRef', 'sessionId', 'traceId', 'environment', 'deploymentRef', 'deploymentConfigDigest',
    'identity', 'identityToken', 'firstObservedAt', 'lastObservedAt', 'edgeObservations']);
  const OBS_KEYS = new Set(['edgeId', 'firstObservedAt', 'lastObservedAt', 'matchConfidence', 'matchedEdgeIds', 'observationIds']);
  arr(groups).forEach((g, i) => {
    if (!isObj(g)) { rejected.push({ index: i, reason: 'not-an-object' }); return; }
    droppedFields += Object.keys(g).filter((k) => !GROUP_KEYS.has(k)).length;
    // Idempotent: an already-opaque reference is kept, so re-sanitizing a recorded group (replay) changes nothing.
    const ref = typeof g.sessionRef === 'string' && /^sref_[0-9a-f]{16}$/.test(g.sessionRef)
      ? g.sessionRef : pseudonymizeSessionRef(g.sessionRef ?? g.sessionId ?? g.traceId);
    const token = typeof g.identityToken === 'string' && /^idt_[0-9a-f]{16}$/.test(g.identityToken)
      ? g.identityToken : (typeof g.identity === 'string' ? tokenize(g.identity) : null);
    const ident = (v) => (typeof v === 'string' && REF_RE.test(v) ? v : null);
    const edgeObservations = [];
    for (const o of arr(g.edgeObservations)) {
      if (!isObj(o) || typeof o.edgeId !== 'string' || !REF_RE.test(o.edgeId)) continue;
      droppedFields += Object.keys(o).filter((k) => !OBS_KEYS.has(k)).length;
      edgeObservations.push({
        edgeId: o.edgeId,
        firstObservedAt: iso(o.firstObservedAt) === null ? null : o.firstObservedAt,
        lastObservedAt: iso(o.lastObservedAt) === null ? null : o.lastObservedAt,
        matchConfidence: ['high', 'medium', 'low', 'ambiguous'].includes(o.matchConfidence) ? o.matchConfidence : 'ambiguous',
        matchedEdgeIds: arr(o.matchedEdgeIds).filter((x) => typeof x === 'string' && REF_RE.test(x)).sort(),
        observationIds: arr(o.observationIds).filter((x) => typeof x === 'string' && REF_RE.test(x)).sort().slice(0, 8),
      });
    }
    out.push({
      id: ident(g.id) ?? `group-${i}`,
      sessionRef: ref,
      environment: ident(g.environment),
      deploymentRef: ident(g.deploymentRef),
      deploymentConfigDigest: ident(g.deploymentConfigDigest),
      identityToken: token ?? null,
      firstObservedAt: iso(g.firstObservedAt) === null ? null : g.firstObservedAt,
      lastObservedAt: iso(g.lastObservedAt) === null ? null : g.lastObservedAt,
      edgeObservations: edgeObservations.sort((a, b) => (a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0)),
    });
  });
  return { groups: out, rejected, droppedFields };
}

/** Why a single causal group cannot support the WHOLE path (empty list means it can). */
function groupIncompatibilities(group, pathEdgeIds, expected, maxWindowMs) {
  const why = [];
  if (!group.sessionRef) why.push('no-session-or-trace-reference');
  const covered = new Map(group.edgeObservations.map((o) => [o.edgeId, o]));
  const missing = pathEdgeIds.filter((id) => !covered.has(id));
  if (missing.length) why.push(`edges-not-in-group:${missing.length}`);
  if (!expected.environment) why.push('environment-unspecified');
  else if (group.environment !== expected.environment) why.push('environment-mismatch');
  if (!expected.deploymentRef) why.push('deployment-unspecified');
  else if (group.deploymentRef !== expected.deploymentRef) why.push('deployment-mismatch');
  if (expected.deploymentConfigDigest && group.deploymentConfigDigest && expected.deploymentConfigDigest !== group.deploymentConfigDigest) {
    why.push('deployment-configuration-mismatch');
  }
  if (expected.identityToken && group.identityToken && expected.identityToken !== group.identityToken) why.push('identity-scope-mismatch');
  const first = iso(group.firstObservedAt); const last = iso(group.lastObservedAt);
  if (first === null || last === null) why.push('time-window-missing');
  else {
    if (last < first) why.push('time-window-inverted');
    if (last - first > maxWindowMs) why.push('time-window-too-wide');
    const w = expected.window;
    if (w && (iso(w.start) !== null && first < iso(w.start) || iso(w.end) !== null && last > iso(w.end))) why.push('outside-requested-window');
  }
  // Edge-level mapping and order: each edge's own interval is inside the group window and the path order
  // is not contradicted (an edge cannot have been last seen before its predecessor was first seen).
  let prevFirst = null;
  for (const id of pathEdgeIds) {
    const o = covered.get(id);
    if (!o) continue;
    if (!TRUSTED_CONFIDENCE.has(o.matchConfidence) || o.matchedEdgeIds.length > 1) { why.push('ambiguous-edge-mapping'); break; }
    const f = iso(o.firstObservedAt); const l = iso(o.lastObservedAt);
    if (f === null || l === null) { why.push('edge-time-missing'); break; }
    if (first !== null && last !== null && (f < first || l > last)) { why.push('edge-outside-group-window'); break; }
    if (prevFirst !== null && l < prevFirst) { why.push('causal-order-violated'); break; }
    prevFirst = f;
  }
  return why;
}

/**
 * Assess what telemetry says about ONE path.
 *
 * @param {object} p
 * @param {string[]} p.pathEdgeIds  DataFlowGraph edge ids of the path, source first.
 * @param {object|null} p.edgeStates the result of `deriveEdgeStates` (null or evaluated:false means no telemetry was consulted)
 * @param {object[]} [p.causalGroups]
 * @param {object} [p.expected] { environment, deploymentRef, deploymentConfigDigest, identityToken, window, maxWindowMs }
 */
export function assessRuntimeSupport({ pathEdgeIds, edgeStates, causalGroups = [], expected = {}, tokenize } = {}) {
  const ids = arr(pathEdgeIds).filter((x) => typeof x === 'string');
  const base = {
    pathEdgeCount: ids.length, observedEdgeIds: [], unobservedEdgeIds: [], candidateEdgeIds: [], blockedEdgeIds: [],
    wholePath: { supported: false, groupId: null, reasons: [] }, groupsConsidered: 0, rejectedGroups: 0, droppedFields: 0,
    statements: [],
  };
  if (!ids.length || !isObj(edgeStates) || !edgeStates.evaluated) {
    return { ...base, status: 'not_consulted', statements: ['No telemetry was consulted for this path. That is not an observation of absence.'] };
  }
  const sanitized = sanitizeCausalGroups(causalGroups, { tokenize });
  base.groupsConsidered = sanitized.groups.length; base.rejectedGroups = sanitized.rejected.length; base.droppedFields = sanitized.droppedFields;

  for (const id of ids) {
    const s = edgeStates.byEdge?.[id];
    const states = arr(s?.states);
    if (states.includes('RUNTIME_OBSERVED')) base.observedEdgeIds.push(id);
    else if (states.includes('RUNTIME_BLOCKED')) base.blockedEdgeIds.push(id);
    else {
      base.unobservedEdgeIds.push(id);
      if ((s?.uncertainObservations ?? 0) > 0) base.candidateEdgeIds.push(id);
    }
    // An edge observed AND denied keeps both facts.
    if (states.includes('RUNTIME_OBSERVED') && states.includes('RUNTIME_BLOCKED')) base.blockedEdgeIds.push(id);
  }

  const allObserved = base.observedEdgeIds.length === ids.length;
  if (allObserved) {
    const maxWindowMs = Number.isFinite(expected.maxWindowMs) && expected.maxWindowMs > 0 ? expected.maxWindowMs : DEFAULT_MAX_WINDOW_MS;
    let best = null;
    for (const g of sanitized.groups) {
      const why = groupIncompatibilities(g, ids, expected, maxWindowMs);
      if (!why.length) { best = { g, why: [] }; break; }
      if (!best || why.length < best.why.length) best = { g, why };
    }
    if (best && !best.why.length) {
      base.wholePath = { supported: true, groupId: best.g.id, reasons: [] };
      return { ...base, status: 'path_supported', statements: [
        'Every edge was observed inside ONE compatible trace or session. This supports that this path executed in that session; it does not prove the data was sensitive or that the path is exploitable.',
      ] };
    }
    base.wholePath.reasons = best ? best.why : ['no-causal-group-supplied'];
  } else {
    base.wholePath.reasons = ['not-every-edge-observed'];
  }

  if (base.blockedEdgeIds.length && base.blockedEdgeIds.some((id) => !base.observedEdgeIds.includes(id))) {
    return { ...base, status: 'blocked_attempt', statements: [
      'A denied observation proves only that this attempt was refused. It does not show every execution of this path is blocked.',
    ] };
  }
  if (base.observedEdgeIds.length) {
    return { ...base, status: 'edge_partial', statements: [
      'Some edges were observed, but not within one compatible trace or session. Independently observed edges do not establish an end-to-end execution.',
    ] };
  }
  if (base.candidateEdgeIds.length) {
    return { ...base, status: 'candidate_only', statements: [
      'Only low-confidence or ambiguous mappings were seen. They remain candidates and are not counted as observed.',
    ] };
  }
  return { ...base, status: 'no_observation_in_window', statements: [
    'Telemetry was consulted and nothing mapped to this path in the window. That is not evidence that the path is unreachable or safe.',
  ] };
}

/**
 * R10.6: external proof references are bound to the sink, the value and the configuration. A reference that is
 * stale or mismatched is REJECTED with its reasons; it is never re-attached to the changed graph.
 */
export function bindExploitProofs(proofs, expected) {
  const bound = []; const rejected = [];
  for (const [i, p] of arr(proofs).entries()) {
    const id = isObj(p) && typeof p.id === 'string' && REF_RE.test(p.id) ? p.id : `proof-${i}`;
    if (!isObj(p)) { rejected.push({ id, reasons: ['not-an-object'] }); continue; }
    const reasons = [];
    if (!['proof', 'dnr-hunt', 'incident'].includes(p.kind)) reasons.push('unknown-kind');
    if (!p.sinkRef || !p.dataElementId || !p.graphDigest || !p.analysisConfigDigest) reasons.push('unbound');
    else {
      if (p.sinkRef !== expected.sinkRef) reasons.push('sink-mismatch');
      if (p.dataElementId !== expected.dataElementId) reasons.push('value-mismatch');
      if (p.graphDigest !== expected.graphDigest) reasons.push('stale-graph');
      if (p.analysisConfigDigest !== expected.analysisConfigDigest) reasons.push('configuration-mismatch');
    }
    if (reasons.length) rejected.push({ id, reasons });
    else bound.push({ id, kind: p.kind, executionBacked: p.kind === 'proof', note: typeof p.note === 'string' ? redactString(p.note).slice(0, 200) : null });
  }
  bound.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  rejected.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  // Rejected references stay listed with their reasons whatever the status; they are never silently dropped.
  return { status: bound.length ? 'bound' : rejected.length ? 'rejected' : 'none', bound, rejected };
}

/** Validate the nullable DAG-04 slot. Returns { ok, errors }. */
export function validateControlEvidence(ce, pathEdgeIds) {
  if (ce === null) return { ok: true, errors: [] };
  const errors = [];
  if (!isObj(ce)) return { ok: false, errors: ['control evidence must be an object or null'] };
  if (!FEASIBILITY_STATUSES.includes(ce.status) || ce.status === 'not_assessed') errors.push('control evidence status must be feasible, infeasible or unknown');
  const set = new Set(pathEdgeIds);
  for (const k of ['predicateRefs', 'controlRefs']) {
    if (!Array.isArray(ce[k])) { errors.push(`${k} must be an array`); continue; }
    for (const r of ce[k]) {
      if (!isObj(r) || !set.has(r.edgeId) || typeof r.ref !== 'string' || !REF_RE.test(r.ref)) errors.push(`${k} entry must name an edge on this path and an identifier-shaped ref`);
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * The four statuses, side by side. Returns exactly the four keys in EVIDENCE_STATUS_KEYS and nothing that
 * ranks, scores or combines them.
 */
export function buildEvidenceStatuses({ pathComplete, controlEvidence, runtime, exploit }) {
  return {
    modeledPath: { status: pathComplete ? 'connected_complete' : 'connected_partial' },
    feasibility: { status: controlEvidence ? controlEvidence.status : 'not_assessed' },
    runtimeSupport: { status: runtime.status },
    exploitProof: { status: exploit.status },
  };
}
