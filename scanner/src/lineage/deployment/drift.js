// drift.js: boundary drift between two revisions, with dependency-aware invalidation and impact-driven rescans (X-306).
//
// Four jobs, all pure (graphs in, records out; no clock, no file or network access):
//
//  1. `diffBoundaryGraphs` compares two validated graphs at stable node and edge ids and names what changed in terms a
//     reviewer cares about: new exposure, changed privilege, tenant-boundary weakening, removed controls. Those four are
//     `material`. Every other change to a non-structural relation is reported too (it still changes how a finding is
//     conditioned) but is not material. It also diffs the SOURCES the two graphs were built from and names the edges each
//     changed file supported, so a drift can be explained from the file that moved.
//  2. `planRescan` maps each change to the hypotheses (findings) it can affect and lists the focused rescans. A hypothesis is
//     affected only when its bound service is the service a change touches, or can reach it, or is reachable from it, in
//     either revision. Unchanged components are not rescanned. A hypothesis that cannot be tied to a service cannot be proven
//     independent of a change, so it makes the plan INCOMPLETE; so does a graph gap that stands for a missing dependency.
//  3. `incrementalAnnotate` recomputes only the affected hypotheses and carries the rest forward. `compareScoped` then lets a
//     test (or a caller) check the incremental result against a complete recomputation. Equivalence is the property that
//     justifies not rescanning; an incomplete plan never claims it.
//  4. `invalidatePathsForSources` drops exactly the paths a changed source file supported (through the edges and node
//     declarations that cite it), reusing `invalidateChangedSources` for the graph itself.

import { indexGraph, validateBoundaryGraph } from './boundary-graph.js';
import { invalidateChangedSources } from './ingest.js';
import { bindFindingToService, exposureReach, TRAVERSED_RELATIONS } from './attack-paths.js';
import { semanticId, digestOf, hypothesisIdFromFinding } from '../../posture/assurance/identity.js';

export const DRIFT_SCHEMA = 'agentic-security/boundary-drift';
export const DRIFT_VERSION = '1.0.0';

export const DRIFT_CATEGORIES = Object.freeze([
  'new-exposure', 'changed-privilege', 'tenant-weakening', 'removed-control',
  'control-added', 'privilege-reduced', 'exposure-reduced', 'connectivity-added', 'connectivity-removed', 'edge-changed',
  'zone-changed', 'node-resolution-changed', 'service-added', 'service-removed',
]);
export const MATERIAL_CATEGORIES = Object.freeze(['new-exposure', 'changed-privilege', 'tenant-weakening', 'removed-control']);
const MATERIAL = new Set(MATERIAL_CATEGORIES);

// A gap of these kinds means a dependency of the graph is missing, so a conclusion drawn from it is incomplete.
export const DEPENDENCY_GAP_CODES = Object.freeze([
  'source-missing', 'source-changed', 'repository-unavailable', 'access-denied', 'version-mismatch', 'revision-unknown',
  'graph-integrity', 'limit-exceeded', 'unresolved-identity',
]);
const DEPENDENCY_GAPS = new Set(DEPENDENCY_GAP_CODES);

const TRAVERSED = new Set(TRAVERSED_RELATIONS);
const STRUCTURAL = new Set(['defined-in', 'deployed-in', 'scoped-to']);
const MAX_CLOSURE_HOPS = 8;

const sortedUnique = (a) => [...new Set(a)].sort();
const keyOf = (n) => `${n.kind}|${n.name}|${n.environment ?? ''}`;
const isDeny = (e) => e.effect === 'deny' || e.relation === 'network-denies';

// ------------------------------------------------------------ diff

function stable(v) { return JSON.stringify(v, Object.keys(v ?? {}).sort()); }

function sameEdgeBody(a, b) {
  return a.pathState === b.pathState && a.confidence === b.confidence && stable(a.attrs ?? {}) === stable(b.attrs ?? {});
}

/**
 * Compare two boundary graphs.
 *
 * @returns {{ ok: boolean, diff: object|null, errors: object[] }} never throws
 */
export function diffBoundaryGraphs(before, after) {
  const vb = validateBoundaryGraph(before), va = validateBoundaryGraph(after);
  if (!vb.ok || !va.ok) return { ok: false, diff: null, errors: [...vb.errors.map((e) => ({ ...e, side: 'before' })), ...va.errors.map((e) => ({ ...e, side: 'after' }))] };
  if (before.repository !== null && after.repository !== null && before.repository !== after.repository) {
    return { ok: false, diff: null, errors: [{ code: 'RULE_VIOLATION', path: 'repository', message: `graphs are for different repositories ('${before.repository}' and '${after.repository}'); a diff across repositories would hide every id as added or removed` }] };
  }
  const bi = indexGraph(before), ai = indexGraph(after);
  const bEdges = new Map(before.edges.map((e) => [e.id, e]));
  const aEdges = new Map(after.edges.map((e) => [e.id, e]));
  const nodeOf = (id) => ai.nodesById.get(id) ?? bi.nodesById.get(id);
  const changes = [];
  const push = (category, o) => {
    const nodeIds = sortedUnique(o.nodeIds ?? []);
    const edgeIds = sortedUnique(o.edgeIds ?? []);
    const env = o.environment ?? null;
    changes.push({
      id: semanticId('bdrift', { category, nodeIds, edgeIds, detail: o.detail ?? null }, ['category', 'nodeIds', 'edgeIds', 'detail']),
      category, material: MATERIAL.has(category), nodeIds, edgeIds, environment: env, tenant: o.tenant ?? null,
      description: o.description, before: o.before ?? null, after: o.after ?? null,
    });
  };
  const endpointsOf = (e) => [e.from, e.to];

  // 1. exposure
  const rb = exposureReach(before), ra = exposureReach(after);
  const rank = { definite: 2, unresolved: 1 };
  for (const [id, a] of [...ra].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    const n = ai.nodesById.get(id);
    if (!n || !['service', 'resource', 'route'].includes(n.kind)) continue;
    const b = rb.get(id);
    if (!b || rank[a.state] > rank[b.state]) {
      push('new-exposure', {
        nodeIds: [id], edgeIds: a.via, environment: n.environment, tenant: n.tenant, detail: a.state,
        description: `${n.kind} '${n.name}' is ${a.state === 'definite' ? 'reachable' : 'possibly reachable'} from an exposed entry point${b ? ' (it was only possibly reachable before)' : ' and was not before'}`,
        before: b ? b.state : null, after: a.state,
      });
    }
  }
  for (const [id, b] of [...rb].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    const n = bi.nodesById.get(id);
    if (!n || !['service', 'resource', 'route'].includes(n.kind)) continue;
    const a = ra.get(id);
    if (!a || rank[a.state] < rank[b.state]) {
      push('exposure-reduced', { nodeIds: [id], edgeIds: b.via, environment: n.environment, tenant: n.tenant, detail: a ? a.state : 'gone', description: `${n.kind} '${n.name}' is ${a ? 'less certainly' : 'no longer'} reachable from an exposed entry point`, before: b.state, after: a ? a.state : null });
    }
  }

  // 2. edges added
  for (const e of after.edges) {
    if (bEdges.has(e.id) || STRUCTURAL.has(e.relation)) continue;
    const f = nodeOf(e.from), t = nodeOf(e.to);
    const label = `${e.relation} ${f?.name} -> ${t?.name}`;
    const base = { nodeIds: endpointsOf(e), edgeIds: [e.id], environment: e.environment, tenant: e.tenant };
    if (f?.tenant != null && t?.tenant != null && f.tenant !== t.tenant) {
      push('tenant-weakening', { ...base, detail: 'cross-tenant-edge', description: `new ${label} crosses from tenant ${f.tenant} to tenant ${t.tenant}`, after: e.relation });
    }
    if (isDeny(e)) push('control-added', { ...base, description: `new explicit deny: ${label}`, after: e.relation });
    else if (e.relation === 'grants' && e.effect === 'allow') push('changed-privilege', { ...base, detail: 'grant-added', description: `new grant: ${label}`, after: e.attrs ?? {} });
    else if (e.relation === 'assumes') push('changed-privilege', { ...base, detail: 'identity-assumed', description: `workload ${f?.name} now assumes identity ${t?.name}`, after: e.relation });
    else if (TRAVERSED.has(e.relation)) push('connectivity-added', { ...base, description: `new ${label}`, after: e.relation });
  }

  // 3. edges removed
  for (const e of before.edges) {
    if (aEdges.has(e.id) || STRUCTURAL.has(e.relation)) continue;
    const f = nodeOf(e.from), t = nodeOf(e.to);
    const label = `${e.relation} ${f?.name} -> ${t?.name}`;
    const base = { nodeIds: endpointsOf(e), edgeIds: [e.id], environment: e.environment, tenant: e.tenant };
    if (isDeny(e)) push('removed-control', { ...base, description: `explicit deny removed: ${label}`, before: e.relation });
    else if (e.relation === 'grants' && e.effect === 'allow') push('privilege-reduced', { ...base, description: `grant removed: ${label}`, before: e.attrs ?? {} });
    else if (TRAVERSED.has(e.relation)) push('connectivity-removed', { ...base, description: `removed ${label}`, before: e.relation });
  }

  // 4. edges present in both whose body changed
  for (const e of after.edges) {
    const old = bEdges.get(e.id);
    if (!old || STRUCTURAL.has(e.relation) || sameEdgeBody(old, e)) continue;
    const f = nodeOf(e.from), t = nodeOf(e.to);
    const label = `${e.relation} ${f?.name} -> ${t?.name}`;
    const base = { nodeIds: endpointsOf(e), edgeIds: [e.id], environment: e.environment, tenant: e.tenant };
    if (e.relation === 'grants' && stable(old.attrs ?? {}) !== stable(e.attrs ?? {})) {
      push('changed-privilege', { ...base, detail: 'grant-changed', description: `grant changed: ${label}`, before: old.attrs ?? {}, after: e.attrs ?? {} });
    } else {
      push('edge-changed', { ...base, detail: `${old.pathState}>${e.pathState}`, description: `${label} changed (state ${old.pathState} -> ${e.pathState}, confidence ${old.confidence} -> ${e.confidence})`, before: { pathState: old.pathState, confidence: old.confidence }, after: { pathState: e.pathState, confidence: e.confidence } });
    }
  }

  // 5. nodes
  const afterByKey = new Map();
  for (const n of after.nodes) { if (!afterByKey.has(keyOf(n))) afterByKey.set(keyOf(n), []); afterByKey.get(keyOf(n)).push(n); }
  for (const n of before.nodes) {
    const same = ai.nodesById.get(n.id);
    if (same) {
      if (same.trustZone !== n.trustZone) push('zone-changed', { nodeIds: [n.id], environment: n.environment, tenant: n.tenant, detail: `${n.trustZone}>${same.trustZone}`, description: `${n.kind} '${n.name}' moved from trust zone ${n.trustZone} to ${same.trustZone}`, before: n.trustZone, after: same.trustZone });
      if (same.resolved !== n.resolved) push('node-resolution-changed', { nodeIds: [n.id], environment: n.environment, tenant: n.tenant, detail: `${n.resolved}>${same.resolved}`, description: `${n.kind} '${n.name}' is now ${same.resolved ? 'resolved' : 'unresolved'}`, before: n.resolved, after: same.resolved });
      continue;
    }
    // The id is gone. A tenant binding that was dropped keeps (kind, name, environment) but loses its tenant.
    const twin = (afterByKey.get(keyOf(n)) ?? []).find((m) => m.tenant === null);
    if (n.tenant !== null && twin) {
      push('tenant-weakening', { nodeIds: [n.id, twin.id], environment: n.environment, tenant: n.tenant, detail: 'tenant-binding-lost', description: `${n.kind} '${n.name}' is no longer bound to tenant ${n.tenant}`, before: n.tenant, after: null });
    } else if (n.kind === 'service' && !(afterByKey.get(keyOf(n)) ?? []).length) {
      push('service-removed', { nodeIds: [n.id], environment: n.environment, tenant: n.tenant, description: `service '${n.name}' is no longer in the graph`, before: n.name });
    }
  }
  for (const n of after.nodes) {
    if (!bi.nodesById.has(n.id) && n.kind === 'service' && !before.nodes.some((m) => keyOf(m) === keyOf(n))) {
      push('service-added', { nodeIds: [n.id], environment: n.environment, tenant: n.tenant, description: `service '${n.name}' is new`, after: n.name });
    }
  }

  // Deterministic order, and one record per id.
  const byId = new Map(changes.map((c) => [c.id, c]));
  const list = [...byId.values()].sort((a, b) => (Number(b.material) - Number(a.material)) || (a.category < b.category ? -1 : a.category > b.category ? 1 : a.id < b.id ? -1 : 1));

  // Sources: what moved on disk, and which edges each moved file supported.
  const bSrc = new Map(before.sources.map((s) => [s.file, s]));
  const aSrc = new Map(after.sources.map((s) => [s.file, s]));
  const supportedBy = (graph, file) => graph.edges.filter((e) => e.source?.file === file).map((e) => e.id).sort();
  const sources = { added: [], removed: [], changed: [] };
  for (const [file, s] of [...aSrc].sort()) {
    const o = bSrc.get(file);
    if (!o) sources.added.push({ file, digest: s.digest, edgeIds: supportedBy(after, file) });
    else if (o.digest !== s.digest) sources.changed.push({ file, beforeDigest: o.digest, afterDigest: s.digest, edgeIdsBefore: supportedBy(before, file), edgeIdsAfter: supportedBy(after, file) });
  }
  for (const [file, s] of [...bSrc].sort()) if (!aSrc.has(file)) sources.removed.push({ file, digest: s.digest, edgeIds: supportedBy(before, file) });

  const incomplete = after.gaps.filter((g) => DEPENDENCY_GAPS.has(g.code)).map((g) => ({ code: g.code, subject: g.subject, message: g.message }));
  const byCategory = {};
  for (const c of list) byCategory[c.category] = (byCategory[c.category] ?? 0) + 1;
  const diff = {
    schema: DRIFT_SCHEMA, schemaVersion: DRIFT_VERSION,
    repository: after.repository ?? before.repository, beforeDigest: before.digest, afterDigest: after.digest,
    beforeRevision: before.revision, afterRevision: after.revision,
    changes: list, sources, incomplete,
    summary: { total: list.length, material: list.filter((c) => c.material).length, byCategory },
  };
  return { ok: true, diff, errors: [] };
}

/** Human-readable lines for a diff. States what changed and what it does not show; never says a change is safe. */
export function explainDrift(diff) {
  const lines = [];
  if (!diff || !Array.isArray(diff.changes)) return ['no drift record'];
  lines.push(`Boundary drift: ${diff.summary.total} change(s), ${diff.summary.material} material`);
  for (const c of diff.changes) lines.push(`  ${c.material ? '[material] ' : ''}${c.category}: ${c.description}`);
  if (!diff.changes.length) lines.push('  no change to a non-structural relation was found between these two graphs');
  for (const s of diff.sources.changed) lines.push(`  source changed: ${s.file} (supported ${s.edgeIdsBefore.length} edge(s) before, ${s.edgeIdsAfter.length} now)`);
  for (const s of diff.sources.removed) lines.push(`  source removed: ${s.file} (supported ${s.edgeIds.length} edge(s))`);
  for (const s of diff.sources.added) lines.push(`  source added: ${s.file}`);
  if (diff.incomplete.length) lines.push(`  incomplete inputs: ${sortedUnique(diff.incomplete.map((g) => g.code)).join(', ')}; a change behind them may be missing from this diff`);
  lines.push('  This compares two configured graphs; it does not show how the deployed system behaves.');
  return lines;
}

// ------------------------------------------------------------ impact: which hypotheses a change can affect

function adjacency(graphs) {
  const fwd = new Map(), rev = new Map();
  for (const g of graphs) {
    for (const e of g.edges) {
      if (!TRAVERSED.has(e.relation) && !isDeny(e)) continue;
      if (!fwd.has(e.from)) fwd.set(e.from, new Set());
      fwd.get(e.from).add(e.to);
      if (!rev.has(e.to)) rev.set(e.to, new Set());
      rev.get(e.to).add(e.from);
    }
  }
  return { fwd, rev };
}

function closure(start, map) {
  const seen = new Set(start);
  let frontier = [...start];
  for (let hop = 0; hop < MAX_CLOSURE_HOPS && frontier.length; hop++) {
    const next = [];
    for (const id of frontier) for (const m of map.get(id) ?? []) if (!seen.has(m)) { seen.add(m); next.push(m); }
    frontier = next;
  }
  return seen;
}

/** The (kind|name|environment) keys of every service a change can affect: its own, those that reach it, those it reaches. */
function affectedServiceKeys(change, before, after) {
  const nodes = new Map();
  for (const g of [before, after]) for (const n of g.nodes) nodes.set(n.id, n);
  const { fwd, rev } = adjacency([before, after]);
  const seeds = change.nodeIds.filter((id) => nodes.has(id));
  const reach = new Set([...closure(seeds, fwd), ...closure(seeds, rev)]);
  const keys = new Set();
  for (const id of reach) { const n = nodes.get(id); if (n && n.kind === 'service') keys.add(keyOf(n)); }
  return keys;
}

function serviceKeyOfBinding(finding, bindings, before, after) {
  for (const g of [after, before]) {
    const b = bindFindingToService(finding, bindings, g);
    if (b.status === 'bound') return { status: 'bound', key: keyOf(b.service), reason: b.reason };
    if (b.status === 'unbound' || b.status === 'ambiguous') return { status: b.status, key: null, reason: b.reason };
  }
  // The service exists in neither graph (renamed or removed). Use the binding's own name so a removal still maps.
  const b = bindFindingToService(finding, bindings, after);
  if (b.binding && b.binding.environment) return { status: 'bound', key: `service|${b.binding.service}|${b.binding.environment}`, reason: 'service is absent from both graphs; matched by the binding name' };
  return { status: b.status, key: null, reason: b.reason };
}

/**
 * The focused rescan plan for a diff.
 *
 * @param {object} args
 * @param {object} args.diff        from `diffBoundaryGraphs`
 * @param {object} args.before
 * @param {object} args.after
 * @param {Array<{hypothesisId?:string, finding:object}>} args.hypotheses
 * @param {Array} args.bindings     see `bindFindingToService`
 */
export function planRescan({ diff, before, after, hypotheses = [], bindings = [] } = {}) {
  const affecting = diff.changes;
  const incomplete = diff.incomplete.map((g) => ({ hypothesisId: null, code: g.code, reason: `${g.subject}: ${g.message}` }));
  const serviceKeysByChange = new Map(affecting.map((c) => [c.id, affectedServiceKeys(c, before, after)]));
  const rescan = [], skipped = [];
  for (const h of hypotheses) {
    const finding = h.finding ?? h;
    const hypothesisId = h.hypothesisId ?? hypothesisIdFromFinding(finding);
    const file = finding?.file ?? null;
    const bound = serviceKeyOfBinding(finding, bindings, before, after);
    if (bound.status !== 'bound') {
      if (affecting.length) incomplete.push({ hypothesisId, code: 'unbound-hypothesis', reason: `${bound.reason}; it cannot be shown independent of the ${affecting.length} change(s), so it is neither rescanned nor cleared` });
      else skipped.push({ hypothesisId, file, reason: 'no change between the two graphs' });
      continue;
    }
    const reasons = affecting.filter((c) => serviceKeysByChange.get(c.id).has(bound.key)).map((c) => c.id);
    if (reasons.length) rescan.push({ hypothesisId, file, serviceKey: bound.key, reasons });
    else skipped.push({ hypothesisId, file, reason: `no changed relation touches, reaches or is reached by ${bound.key.split('|')[1]}` });
  }
  const sortById = (a, b) => (String(a.hypothesisId) < String(b.hypothesisId) ? -1 : 1);
  rescan.sort(sortById); skipped.sort(sortById);
  incomplete.sort((a, b) => `${a.code}|${a.hypothesisId}`.localeCompare(`${b.code}|${b.hypothesisId}`));
  return {
    status: incomplete.length ? 'incomplete' : 'complete',
    changeIds: affecting.map((c) => c.id),
    rescan, skipped, incomplete,
    rescanFiles: sortedUnique(rescan.map((r) => r.file).filter(Boolean)),
    statement: incomplete.length
      ? `incomplete: ${incomplete.length} dependency problem(s) mean the plan cannot show that every unaffected hypothesis is independent of the change`
      : `${rescan.length} hypothesis(es) to rescan, ${skipped.length} unaffected and not rescanned`,
  };
}

// ------------------------------------------------------------ incremental vs complete

/** The deployment-conditioned result for one hypothesis, without graph-wide metadata that moves between revisions. */
export function scopedSignature(context) {
  if (!context) return null;
  return digestOf({
    hypothesisId: context.hypothesisId, binding: context.binding.status, service: context.binding.service?.id ?? null,
    exposure: context.exposure.state,
    paths: context.paths.map((p) => ({ id: p.id, kind: p.kind, state: p.state, conditions: p.conditions.map((c) => c.kind), blockers: p.blockers.map((b) => b.edgeId), exploitability: p.exploitability.label })),
    verification: context.verification.map((v) => [v.recordId, v.applicable]),
  });
}

/**
 * Recompute only the hypotheses the plan names and carry the rest forward.
 *
 * @param {object} args
 * @param {object} args.plan
 * @param {Array<{hypothesisId?:string, finding:object}>} args.hypotheses
 * @param {Object<string, object>} args.previous  hypothesisId -> context from the earlier revision
 * @param {(h: object) => object} args.annotate   recompute one hypothesis against the new revision
 */
export function incrementalAnnotate({ plan, hypotheses, previous = {}, annotate }) {
  const idOf = (h) => h.hypothesisId ?? hypothesisIdFromFinding(h.finding ?? h);
  const redo = new Set(plan.rescan.map((r) => r.hypothesisId));
  const unproven = new Set(plan.incomplete.map((i) => i.hypothesisId).filter(Boolean));
  const results = {}, recomputed = [], carried = [], stale = [];
  for (const h of hypotheses) {
    const id = idOf(h);
    if (redo.has(id) || !(id in previous)) { results[id] = annotate(h); recomputed.push(id); }
    else { results[id] = previous[id]; (unproven.has(id) ? stale : carried).push(id); }
  }
  return {
    status: plan.status, results, recomputed: recomputed.sort(), carried: carried.sort(), stale: stale.sort(),
    incomplete: plan.incomplete,
  };
}

/** Compare an incremental result with a complete one on the scoped signature. An incomplete incremental result never matches. */
export function compareScoped(incremental, complete) {
  const ids = sortedUnique([...Object.keys(incremental.results), ...Object.keys(complete)]);
  const differing = ids.filter((id) => scopedSignature(incremental.results[id]) !== scopedSignature(complete[id]));
  const equivalent = incremental.status === 'complete' && differing.length === 0;
  return { equivalent, differing, status: incremental.status };
}

// ------------------------------------------------------------ invalidation of paths by changed sources

/**
 * Which paths a set of changed or removed source files invalidates, and the graph with those relations dropped.
 * A path is invalidated exactly when one of its supporting edges, or the declaration of one of its nodes, cites a changed file.
 *
 * @param {object[]} paths          path records (`computeAttackPaths`)
 * @param {object} graph
 * @param {Object<string,string>|Map} currentDigests  file -> sha256 now (absent means removed)
 */
export function invalidatePathsForSources(paths, graph, currentDigests) {
  const inv = invalidateChangedSources(graph, currentDigests);
  if (!inv.ok) return { ok: false, valid: [], invalidated: [], graph: null, staleFiles: inv.staleFiles, errors: inv.errors };
  const staleEdges = new Set(inv.invalidatedEdgeIds);
  const stale = new Set(inv.staleFiles);
  const declaredOnlyByStale = new Set(graph.nodes.filter((n) => n.declaredBy.length && n.declaredBy.every((d) => stale.has(d.file))).map((n) => n.id));
  const valid = [], invalidated = [];
  for (const p of paths) {
    const edgeIds = p.supportingEdgeIds.filter((id) => staleEdges.has(id));
    const nodeIds = sortedUnique(p.hops.flatMap((h) => [h.from.id, h.to.id]).filter((id) => declaredOnlyByStale.has(id)));
    if (edgeIds.length || nodeIds.length) invalidated.push({ pathId: p.id, edgeIds: sortedUnique(edgeIds), nodeIds });
    else valid.push(p);
  }
  return { ok: true, valid, invalidated, graph: inv.graph, staleFiles: inv.staleFiles, errors: [] };
}
