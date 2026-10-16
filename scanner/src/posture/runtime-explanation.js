// Side-by-side static / runtime explanation of one finding (E5-07).
//
// One object, built once from one snapshot, feeds every surface: the CLI JSON, the SARIF result property, the explorer's two panes, and the export.
// Because they all read the same object, they cannot disagree, and because the object carries a digest of its own content, a pane built from a
// different snapshot is detected (`panesInSync`) instead of being shown beside the other.
//
//   static    what the code says: the finding's static reachability level and the edges of its path
//   runtime   what a running build showed: per-edge state, build-match counts, sampling, and the observations that are MISSING, each named
//   compare   the path's corroboration (pathCorroboration): corroborated only when every edge is `both`
//
// DETERMINISTIC. No clock, no randomness, keys in a fixed order, arrays sorted: the same inputs give byte-identical output and the same digest.
// OFFLINE. Nothing here reads the network; the inputs are values already computed.
// PRIVATE. The explanation is built field by field from normalized values (routes with ids generalised, symbols, counts, states). No raw runtime
// record is embedded, and `exportExplanation` scans every string it is about to emit with the same canary patterns the ingestion step uses and
// REFUSES to export if one matches.
import { createHash } from 'node:crypto';
import { canaryHit } from './runtime-trace-ingest.js';
import { pathCorroboration } from './graph-reconciliation.js';
import { buildEvidenceLevels } from './exploitability-evidence.js';

const EXPLANATION_SCHEMA = 'agentic-security/runtime-explanation@1';
const SKIP_CANARY = new Set(['commit', 'buildHash', 'imageDigest', 'digest', 'snapshotDigest']);

const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
const digestOf = (o) => createHash('sha256').update(JSON.stringify(canon(o))).digest('hex');

function missingFor(edge) {
  if (!edge) return 'the path edge is not in the reconciled graph: no runtime statement is possible';
  if (edge.state === 'both') return null;
  if (edge.state === 'conflicted') return `runtime evidence contradicts the static graph for ${edge.key}`;
  if (edge.state === 'unknown') return edge.reason || `runtime records for ${edge.key} cannot be tied to this snapshot`;
  if (edge.mismatchedRecords > 0) return `only a different build was observed using ${edge.key}`;
  return `no runtime record observed for ${edge.key}`;
}

/**
 * @param {object} finding
 * @param {{reconciled?:object, pathKeys?:string[], sampling?:object, snapshotIdentity?:object, windowDays?:number}} ctx
 */
export function buildRuntimeExplanation(finding, ctx = {}) {
  const { levels } = buildEvidenceLevels(finding);
  const keys = [...(ctx.pathKeys || [])];
  const byKey = new Map(((ctx.reconciled && ctx.reconciled.edges) || []).map((e) => [e.key, e]));
  const edges = keys.map((k) => { const e = byKey.get(k); return { key: k, state: e ? e.state : 'statically_inferred', confidence: e ? e.confidence : null, matchedRecords: e ? e.matchedRecords : 0, mismatchedRecords: e ? e.mismatchedRecords : 0, unattestedRecords: e ? e.unattestedRecords : 0 }; });
  const missing = [];
  if (!ctx.reconciled) missing.push('no runtime trace was reconciled with the static graph');
  keys.forEach((k) => { const m = ctx.reconciled ? missingFor(byKey.get(k)) : null; if (m) missing.push(m); });
  const sampling = ctx.sampling && ctx.sampling.state ? { state: ctx.sampling.state, ...(typeof ctx.sampling.rate === 'number' ? { rate: ctx.sampling.rate } : {}) } : { state: 'undisclosed' };
  if (sampling.state !== 'complete') missing.push(sampling.state === 'sampled' ? `the trace samples ${sampling.rate} of traffic: absence of an observation proves nothing` : 'the trace does not say how much traffic it samples: absence of an observation proves nothing');
  const s = ctx.snapshotIdentity || {};
  const snapshot = { commit: s.commit ?? null, buildHash: s.buildHash ?? null, imageDigest: s.imageDigest ?? null, environment: s.environment ?? null, dirty: s.dirty === true };
  const body = {
    schema: EXPLANATION_SCHEMA,
    findingId: finding && finding.id != null ? String(finding.id) : null,
    snapshot,
    static: { staticallyReachable: levels.staticallyReachable, externallyReachable: levels.externallyReachable, pathEdges: keys },
    runtime: { observed: levels.runtimeObserved, sampling, windowDays: ctx.windowDays ?? null, edges, missingObservations: [...new Set(missing)].sort() },
    compare: ctx.reconciled ? pathCorroboration(ctx.reconciled, keys) : { state: 'uncorroborated', reason: 'no runtime evidence was supplied' },
    offline: true,
  };
  return { ...body, digest: digestOf(body) };
}

/** True when the explanation still hashes to its own digest, i.e. nothing was altered after it was built. */
export function explanationIntact(e) {
  if (!e || typeof e !== 'object' || typeof e.digest !== 'string') return false;
  const { digest, ...body } = e;
  return digestOf(body) === digest;
}

/** The properties a SARIF result or CLI JSON entry carries. A compact view of the same object, with the digest that ties it back. */
export function explanationSummary(e) {
  return { schema: e.schema, digest: e.digest, compare: e.compare.state, runtimeObserved: e.runtime.observed.value, sampling: e.runtime.sampling.state, missingObservations: e.runtime.missingObservations.length, snapshotCommit: e.snapshot.commit };
}

/**
 * The explorer's two panes, both derived from one explanation. Selecting an edge returns BOTH panes for that edge, stamped with the snapshot digest.
 */
export function buildViewModel(e) {
  const rows = new Map(e.runtime.edges.map((r) => [r.key, r]));
  return {
    snapshotDigest: e.digest,
    keys: [...rows.keys()],
    select(key) {
      const r = rows.get(key);
      if (!r) return null;
      return {
        key, snapshotDigest: e.digest,
        staticPane: { key, kind: key.split('|')[0], inStaticGraph: true, reachability: e.static.staticallyReachable.value },
        runtimePane: { key, state: r.state, confidence: r.confidence, matched: r.matchedRecords, mismatched: r.mismatchedRecords, unattested: r.unattestedRecords, missing: r.state === 'both' ? null : missingFor({ key, ...r }) },
      };
    },
  };
}

/** Two panes may be shown together only when they are about the same key and were built from the same snapshot. */
export function panesInSync(sel) {
  return !!sel && sel.staticPane.key === sel.runtimePane.key && sel.staticPane.key === sel.key && typeof sel.snapshotDigest === 'string';
}
export function selectionsInSync(a, b) { return !!a && !!b && a.snapshotDigest === b.snapshotDigest && a.key === b.key; }

/**
 * JSON for sharing. Refuses (throws) when any string in it matches a secret or personal-data pattern.
 */
export function exportExplanation(e) {
  if (!explanationIntact(e)) throw new Error('refusing to export: the explanation was altered after it was built');
  const walk = (v, k) => {
    if (typeof v === 'string') { if (!SKIP_CANARY.has(k)) { const hit = canaryHit(v); if (hit) throw new Error(`refusing to export: a value matches the ${hit} pattern`); } }
    else if (Array.isArray(v)) v.forEach((x) => walk(x, k));
    else if (v && typeof v === 'object') for (const [kk, x] of Object.entries(v)) walk(x, kk);
  };
  walk(e, null);
  return JSON.stringify(canon(e), null, 2) + '\n';
}
