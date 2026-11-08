// attack-paths.js: deployment-conditioned attack paths (X-305).
//
// Combines a finding's code location with the deployment boundary graph to answer two questions, and states what it could not
// answer next to each result:
//   exposure : can an exposed entry point reach the deployed service that runs this code?
//   impact   : from that service, which privileged resources can it reach, across which trust boundaries?
//
// Rules the module keeps:
//  - A path is a walk over configured or observed edges. Its state is one of the graph's PATH_STATES: `blocked` only because an
//    explicit deny edge sits on a hop; `unresolved` when an endpoint is unresolved, a hop's configuration is unresolved, or a
//    tenant transition makes reachability CONDITIONAL on a binding the configuration does not establish; `runtime-supported`
//    only when every network hop has a runtime observation (identity hops are configuration and are listed as such);
//    otherwise `possible`. No path found is never reported as "none exists": the graph is only what was supplied.
//  - Traffic coverage is never complete. Observed, sampled and stale hops are reported separately and a path that is
//    `runtime-supported` still says its coverage is `not-established`.
//  - Exploitability is NOT derived from reachability. A path is labelled `exploitable-confirmed` only when a verification record
//    for the same hypothesis passes the trust rules here: it validates, its outcome is `confirmed`, its confirmation level
//    RECOMPUTED from its evidence is `runtime-confirmed` (a claimed level is never read) and its oracle is the one the finding's
//    class names. Confidence scores, model agreement and an unvalidated record never satisfy it.
//  - Pure: a graph in, a context out. No clock (a caller passes `now` to judge staleness), no file or network access.
//
// A finding is tied to a service by an explicit binding (a path prefix to a service name). Nothing is guessed from names: an
// unbound finding yields a context that says so and carries no path.

import { indexGraph, validateBoundaryGraph, boundaryCrossings } from './boundary-graph.js';
import { semanticId, hypothesisIdFromFinding } from '../../posture/assurance/identity.js';
import { validateVerificationRecord, deriveConfirmationLevel } from '../../posture/assurance/verification-record.js';
import { nonTaintClassOf, SCENARIO_CLASSES } from '../../posture/oracles/scenario-classes.js';
import { decideAction, resourceMatches, UNKNOWN_ACTION } from './iam-eval.js';
import { judgePathPromotion } from './proof-binding.js';

export const BOUNDARY_CONTEXT_SCHEMA = 'agentic-security/boundary-context';
// 1.1.0 (threat-model FR-03.3): optional `truncation` (why a search stopped) and `action` (the action a query asked about).
export const BOUNDARY_CONTEXT_VERSION = '1.1.0';

export const TRAVERSED_RELATIONS = Object.freeze(['routes-to', 'calls', 'depends-on', 'network-allows', 'assumes', 'grants']);
const TRAVERSED = new Set(TRAVERSED_RELATIONS);
const NETWORK_RELATIONS = new Set(['routes-to', 'calls', 'depends-on', 'network-allows']);

export const PATH_LIMITS = Object.freeze({ maxHops: 8, maxPaths: 200, maxExpansions: 20000 });
export const DEFAULT_STALE_AFTER_MS = 7 * 24 * 3600 * 1000;

export const EXPLOITABILITY_LABELS = Object.freeze([
  'not-established', 'exploitable-confirmed', 'oracle-confirmed-path-blocked', 'oracle-confirmed-path-unresolved',
]);

const STATE_RANK = { 'runtime-supported': 0, possible: 1, unresolved: 2, blocked: 3 };

const ASSUME = Object.freeze({
  edges: 'edges are declared or observed relationships; none of them shows that a request succeeded',
  layers: 'only the supplied configuration was read; host firewalls, service meshes and organisation level policies were not',
  route: 'a routing rule from configuration states where traffic is forwarded; it was not exercised',
  depends: 'a declared dependency implies connectivity, not that a call happens',
  identity: 'the workload runs as the identity named in configuration',
  grant: 'the policy as written is the policy in force',
  tenantShared: 'a tenant-scoped service reaches a resource with no tenant binding in the supplied configuration',
  lowConfidence: 'an edge on this path has low confidence',
  inferred: 'an edge on this path is an inference from naming, not a configured or observed relationship',
});

const nul = (v) => (v === undefined ? null : v);
const sortedUnique = (a) => [...new Set(a)].sort();

function nodeSummary(n) {
  return {
    id: n.id, kind: n.kind, name: n.name, environment: nul(n.environment), tenant: nul(n.tenant), repository: nul(n.repository),
    trustZone: n.trustZone, resolved: n.resolved,
  };
}

function edgeSummary(e) {
  return {
    id: e.id, relation: e.relation, effect: e.effect, provenance: e.provenance, confidence: e.confidence, pathState: e.pathState,
    environment: nul(e.environment), tenant: nul(e.tenant), sourceRevision: nul(e.sourceRevision),
    source: e.source ? { file: e.source.file, digest: e.source.digest, parser: e.source.parser, parserVersion: e.source.parserVersion } : null,
    observationInterval: e.observationInterval ? { start: e.observationInterval.start, end: e.observationInterval.end } : null,
    completeness: nul(e.completeness), attrs: e.attrs && typeof e.attrs === 'object' ? { ...e.attrs } : {},
  };
}

// ------------------------------------------------------------ binding a finding to a service

/**
 * Tie a finding's code location to a deployed service by an explicit binding. The longest matching path prefix wins; two equally
 * long prefixes naming different services are ambiguous and bind nothing.
 *
 * @param {object} finding   needs `file`
 * @param {Array<{pathPrefix:string, service:string, repository?:string, environment?:string, tenant?:string}>} bindings
 * @param {object} graph     a validated boundary graph
 * @returns {{status:'bound'|'unbound'|'ambiguous'|'service-not-in-graph'|'ambiguous-service', service:object|null, binding:object|null, reason:string}}
 */
export function bindFindingToService(finding, bindings, graph) {
  const file = typeof finding?.file === 'string' ? finding.file.replace(/\\/g, '/').replace(/^\.\//, '') : '';
  if (!file) return { status: 'unbound', service: null, binding: null, reason: 'the finding has no file, so it cannot be tied to a service' };
  const list = (Array.isArray(bindings) ? bindings : []).filter((b) => b && typeof b.pathPrefix === 'string' && b.pathPrefix.trim() && typeof b.service === 'string' && b.service);
  const matches = [];
  for (const b of list) {
    const prefix = b.pathPrefix.replace(/\\/g, '/').replace(/^\.\//, '');
    if (prefix.split('/').includes('..')) continue;
    if (b.repository && graph.repository && b.repository !== graph.repository) continue;
    const hit = prefix.endsWith('/') ? file.startsWith(prefix) : (file === prefix || file.startsWith(`${prefix}/`));
    if (hit) matches.push({ b, len: prefix.length });
  }
  if (!matches.length) return { status: 'unbound', service: null, binding: null, reason: list.length ? `no service binding covers ${file}` : 'no service bindings were supplied' };
  const top = Math.max(...matches.map((m) => m.len));
  const best = matches.filter((m) => m.len === top);
  const names = sortedUnique(best.map((m) => `${m.b.service}|${m.b.environment ?? ''}|${m.b.tenant ?? ''}`));
  if (names.length > 1) return { status: 'ambiguous', service: null, binding: null, reason: `${file} is covered by equally specific bindings for different services` };
  const b = best[0].b;
  const nodes = graph.nodes.filter((n) => n.kind === 'service' && n.name === b.service
    && (b.environment === undefined || n.environment === b.environment) && (b.tenant === undefined || n.tenant === b.tenant));
  const binding = { pathPrefix: b.pathPrefix, service: b.service, repository: nul(b.repository), environment: nul(b.environment), tenant: nul(b.tenant) };
  if (!nodes.length) return { status: 'service-not-in-graph', service: null, binding, reason: `service '${b.service}' is not in the supplied boundary graph` };
  if (nodes.length > 1) return { status: 'ambiguous-service', service: null, binding, reason: `service '${b.service}' exists in several environments or tenants; the binding must name one` };
  return { status: 'bound', service: nodeSummary(nodes[0]), binding, reason: `${file} is bound to service '${b.service}'` };
}

// ------------------------------------------------------------ path computation

function hopsFrom(ix, nodeId) {
  const hops = new Map();
  for (const e of ix.out.get(nodeId) ?? []) {
    const h = hops.get(e.to) ?? { edges: [], denies: [] };
    if (e.effect === 'deny' || e.relation === 'network-denies') h.denies.push(e);
    else if (TRAVERSED.has(e.relation)) h.edges.push(e);
    hops.set(e.to, h);
  }
  // threat-model FR-03.1: a deny statement whose resource is a pattern (`*`, `arn:aws:s3:::bucket/*`) is a node of its own, so before
  // this it never reached the hop to the concrete resource it covers. It now applies to every resource its pattern matches.
  const patternDenies = [];
  for (const [to, h] of hops) {
    const name = ix.nodesById.get(to)?.name ?? '';
    if (/[*?]/.test(name)) for (const d of h.denies) if (d.relation === 'grants') patternDenies.push({ d, pattern: name });
  }
  for (const [to, h] of hops) {
    const name = ix.nodesById.get(to)?.name ?? '';
    for (const { d, pattern } of patternDenies) if (d.to !== to && resourceMatches(pattern, name) && !h.denies.includes(d)) h.denies.push(d);
  }
  for (const [k, h] of [...hops]) if (!h.edges.length) hops.delete(k);
  return hops;
}

function baseState(h, from, to) {
  if (h.edges.some((e) => e.pathState === 'runtime-supported')) return 'runtime-supported';
  if (!from.resolved || !to.resolved || h.edges.every((e) => e.pathState === 'unresolved' || e.pathState === 'blocked')) return 'unresolved';
  return 'possible';
}

/**
 * Decide a hop. A network deny, or a deny on a relation other than an IAM grant, blocks it as before. An IAM hop is decided per
 * action (threat-model FR-03.1): with a requested action, that action only; without one, every action the allow statements grant, and
 * the hop is possible when any of them is. A deny blocks only an action it matches, under a condition that holds for the request
 * context; a condition that cannot be evaluated leaves the action unresolved.
 * @returns {{state:string, denies:object[], actions:object[]|null}}
 */
function hopDecision(h, from, to, q = null) {
  const other = h.denies.filter((d) => d.relation !== 'grants');
  if (other.length) return { state: 'blocked', denies: other.map((d) => ({ d, why: null })), actions: null };
  const allows = h.edges.filter((e) => e.relation === 'grants' && e.effect === 'allow');
  const iamDenies = h.denies.filter((d) => d.relation === 'grants');
  const base = baseState(h, from, to);
  if (!allows.length) return { state: base, denies: [], actions: null };
  const recorded = [...new Set(allows.flatMap((e) => String(e.attrs?.actions ?? '').split(',').filter(Boolean)))].sort();
  // with no IAM deny on the hop and no requested action there is nothing to decide per action: the grant stands as before
  if (!iamDenies.length && !(q && q.action)) return { state: base, denies: [], actions: recorded.length ? recorded.map((action) => ({ action, outcome: base === 'unresolved' ? 'unresolved' : 'possible', blockedBy: [], unresolvedBy: [] })) : null };
  const wanted = q && q.action ? [q.action] : (recorded.length ? recorded : [UNKNOWN_ACTION]);
  const decisions = wanted.map((a) => decideAction(allows, iamDenies, a, q && q.context));
  const pick = (o) => decisions.some((d) => d.outcome === o);
  const state = pick('possible') ? base : pick('unresolved') ? 'unresolved' : pick('blocked') ? 'blocked' : 'not-granted';
  const denies = state === 'blocked' ? decisions.flatMap((d) => d.blockers).map((b) => ({ d: iamDenies.find((x) => x.id === b.edgeId), why: b })) : [];
  return { state, denies, actions: decisions.map(({ action, outcome, blockers, unresolvedBy }) => ({ action, outcome, blockedBy: blockers.map((b) => b.edgeId), unresolvedBy })) };
}

function hopState(h, from, to, q = null) { return hopDecision(h, from, to, q).state; }

function isStale(e, nowMs, staleAfterMs) {
  if (e.attrs?.stale === true) return true;
  if (nowMs === null || !e.observationInterval) return false;
  return nowMs - Date.parse(e.observationInterval.end) > staleAfterMs;
}

function buildPath(ix, seq, hopList, nowMs, staleAfterMs, q = null) {
  const nodes = seq.map((id) => ix.nodesById.get(id));
  const hops = [];
  const conditions = [];
  const blockers = [];
  const assumptions = new Set([ASSUME.edges, ASSUME.layers]);
  const crossings = [];
  const cov = { observed: [], sampled: [], stale: [], unobserved: [] };
  let from = null;
  hopList.forEach((h, i) => {
    from = nodes[i];
    const to = nodes[i + 1];
    const dec = hopDecision(h, from, to, q);
    const state = dec.state;
    const crossing = boundaryCrossings(h.edges[0], ix.nodesById);
    for (const c of crossing) crossings.push({ hop: i, type: c.type, detail: c.detail });
    hops.push({
      index: i, from: nodeSummary(from), to: nodeSummary(to), relations: sortedUnique(h.edges.map((e) => e.relation)), state,
      edges: h.edges.map(edgeSummary).sort((a, b) => (a.id < b.id ? -1 : 1)),
      ...(dec.actions ? { actions: dec.actions } : {}),
    });
    // each blocker is the rule that actually decided the hop, with the action and the condition it matched
    for (const { d, why } of dec.denies) {
      if (!d) continue;
      blockers.push({ hop: i, edgeId: d.id, relation: d.relation, provenance: d.provenance, source: d.source ? { file: d.source.file, digest: d.source.digest } : null,
        detail: `${d.relation} (deny) from ${from.name} to ${to.name}`, ...(why ? { action: why.action, matchedActions: why.matchedActions, condition: why.condition } : {}) });
    }
    if (from.tenant !== null && to.tenant !== null && from.tenant !== to.tenant) {
      conditions.push({ kind: 'tenant-binding', hop: i, detail: `${from.name} (tenant ${from.tenant}) reaches ${to.name} (tenant ${to.tenant}): reachable only if no tenant binding is enforced on this transition, and the configuration does not establish either` });
    } else if (from.tenant !== null && to.tenant === null && to.kind === 'resource') {
      assumptions.add(ASSUME.tenantShared);
    }
    const rels = new Set(h.edges.map((e) => e.relation));
    if (rels.has('routes-to')) assumptions.add(ASSUME.route);
    if (rels.has('depends-on')) assumptions.add(ASSUME.depends);
    if (rels.has('assumes')) assumptions.add(ASSUME.identity);
    if (rels.has('grants')) assumptions.add(ASSUME.grant);
    if (h.edges.some((e) => e.confidence === 'low')) assumptions.add(ASSUME.lowConfidence);
    if (h.edges.some((e) => e.provenance === 'inferred')) assumptions.add(ASSUME.inferred);
    if (h.edges.some((e) => NETWORK_RELATIONS.has(e.relation))) {
      const obs = h.edges.filter((e) => e.provenance === 'runtime-observation');
      if (!obs.length) cov.unobserved.push(i);
      else {
        cov.observed.push(i);
        if (obs.some((e) => e.completeness === 'sampled')) cov.sampled.push(i);
        if (obs.some((e) => isStale(e, nowMs, staleAfterMs))) cov.stale.push(i);
      }
    }
  });
  for (const n of nodes) if (!n.resolved) conditions.push({ kind: 'unresolved-node', hop: null, detail: `${n.kind} '${n.name}' is not defined in the supplied configuration${n.unresolvedReason ? ` (${n.unresolvedReason})` : ''}` });

  const networkHops = hops.filter((h) => h.relations.some((r) => NETWORK_RELATIONS.has(r)));
  let state;
  if (hops.some((h) => h.state === 'blocked')) state = 'blocked';
  else if (hops.some((h) => h.state === 'unresolved') || conditions.length) state = 'unresolved';
  else if (networkHops.length && networkHops.every((h) => h.state === 'runtime-supported')) state = 'runtime-supported';
  else state = 'possible';

  // threat-model FR-03.2: a path that carries several actions keeps their separate outcomes; one is the worst over its IAM hops
  const actionOutcomes = {};
  const RANK = { possible: 0, unresolved: 1, blocked: 2, 'not-granted': 3 };
  for (const hp of hops) for (const a of hp.actions || []) if (!(a.action in actionOutcomes) || RANK[a.outcome] > RANK[actionOutcomes[a.action]]) actionOutcomes[a.action] = a.outcome;
  const observedEnds = hops.flatMap((h) => h.edges).filter((e) => e.observationInterval).map((e) => e.observationInterval);
  const supportingEdgeIds = sortedUnique(hops.flatMap((h) => h.edges.map((e) => e.id)));
  const envs = sortedUnique([...hops.flatMap((h) => h.edges.map((e) => e.environment)), ...nodes.map((n) => n.environment)].filter(Boolean));
  const tenants = sortedUnique(nodes.map((n) => n.tenant).filter(Boolean));
  const dedupCross = [...new Map(crossings.map((c) => [`${c.type}|${c.detail}`, c])).values()];
  return {
    id: semanticId('bpath', { hops: hops.map((h) => h.edges.map((e) => e.id).sort()) }, ['hops']),
    entry: nodeSummary(nodes[0]), target: nodeSummary(nodes[nodes.length - 1]),
    state, conditional: conditions.length > 0, conditions, blockers, assumptions: [...assumptions].sort(),
    ...(Object.keys(actionOutcomes).length ? { actionOutcomes: Object.fromEntries(Object.entries(actionOutcomes).sort()) } : {}),
    ...(q && q.action ? { action: q.action } : {}),
    environments: envs, tenants,
    provenance: sortedUnique(hops.flatMap((h) => h.edges.map((e) => e.provenance))),
    crossings: dedupCross, supportingEdgeIds, hops,
    coverage: {
      trafficCoverage: 'not-established',
      observedHops: cov.observed, sampledHops: cov.sampled, staleHops: cov.stale, unobservedHops: cov.unobserved,
      observedFrom: observedEnds.length ? observedEnds.map((o) => o.start).sort()[0] : null,
      observedUntil: observedEnds.length ? observedEnds.map((o) => o.end).sort().slice(-1)[0] : null,
      staleEvaluated: nowMs !== null,
    },
    exploitability: { label: 'not-established', recordId: null, reason: 'no verification record for this hypothesis was supplied; reachability alone does not show exploitability' },
  };
}

function defaultEntries(graph) {
  return graph.nodes.filter((n) => (n.kind === 'route' || n.kind === 'service') && n.trustZone === 'public' && n.resolved).map((n) => n.id).sort();
}

/** A privileged resource: one an identity is granted (allow) access to, or one the configuration places in the privileged zone. */
function defaultTargets(graph) {
  const granted = new Set(graph.edges.filter((e) => e.relation === 'grants' && e.effect === 'allow').map((e) => e.to));
  return graph.nodes.filter((n) => n.kind === 'resource' && (n.trustZone === 'privileged' || granted.has(n.id))).map((n) => n.id).sort();
}

/**
 * Enumerate simple paths from entry points to targets, bounded in hops, paths and expansions.
 *
 * @param {object} graph
 * @param {object} [o]
 * @param {string[]} [o.entries]    node ids; default: resolved public routes and services
 * @param {string[]} [o.targets]    node ids; default: privileged resources
 * @param {boolean} [o.includeSelf] also report an entry that is itself a target as a zero-hop path
 * @param {number|string} [o.now]   a clock value, only to judge staleness of observed hops
 * @returns {{ ok: boolean, paths: object[], entries: string[], targets: string[], truncated: boolean, limits: object, statement: string, errors: object[] }}
 */
export function computeAttackPaths(graph, o = {}) {
  const v = validateBoundaryGraph(graph);
  if (!v.ok) return { ok: false, paths: [], entries: [], targets: [], truncated: false, truncation: { reasons: [], depthCutoffs: 0, frontier: [], frontierCapped: false }, limits: { ...PATH_LIMITS }, statement: 'the graph failed validation, so no path was computed', errors: v.errors };
  const limits = {
    maxHops: Math.min(o.maxHops ?? PATH_LIMITS.maxHops, PATH_LIMITS.maxHops), maxPaths: Math.min(o.maxPaths ?? PATH_LIMITS.maxPaths, PATH_LIMITS.maxPaths),
    maxExpansions: Math.min(o.maxExpansions ?? PATH_LIMITS.maxExpansions, PATH_LIMITS.maxExpansions),
  };
  const ix = indexGraph(graph);
  const entries = (o.entries ?? defaultEntries(graph)).filter((id) => ix.nodesById.has(id));
  const targets = (o.targets ?? defaultTargets(graph)).filter((id) => ix.nodesById.has(id));
  const targetSet = new Set(targets);
  const nowMs = o.now === undefined || o.now === null ? null : (typeof o.now === 'number' ? o.now : Date.parse(o.now));
  const staleAfterMs = o.staleAfterMs ?? DEFAULT_STALE_AFTER_MS;
  const found = [];
  let expansions = 0;
  let stopped = false;
  const q = o.action ? { action: String(o.action), context: o.context ?? {} } : (o.context ? { action: null, context: o.context } : null);
  // threat-model FR-03.3 (TM-04): every bound that ended the search is recorded, so "no path" after a depth cutoff is never read as
  // "no path exists". Reaching the depth bound on a node with no unvisited continuation is not a cutoff.
  const cut = { depth: 0, results: false, expansions: false, frontier: [] };
  const next = (seq, here) => [...hopsFrom(ix, here)].sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .filter(([to, h]) => !seq.includes(to) && !(q && q.action && hopState(h, ix.nodesById.get(here), ix.nodesById.get(to), q) === 'not-granted'));

  const walk = (seq, hopList) => {
    if (stopped) return;
    const here = seq[seq.length - 1];
    if (hopList.length && targetSet.has(here)) {
      found.push(buildPath(ix, seq, hopList, Number.isNaN(nowMs) ? null : nowMs, staleAfterMs, q));
      if (found.length >= limits.maxPaths) { stopped = true; cut.results = true; return; }
    }
    const cont = next(seq, here);
    if (hopList.length >= limits.maxHops) {
      if (cont.length) { cut.depth++; if (cut.frontier.length < 20) cut.frontier.push({ node: here, depth: hopList.length, unexplored: cont.length }); }
      return;
    }
    for (const [to, h] of cont) {
      if (++expansions > limits.maxExpansions) { stopped = true; cut.expansions = true; return; }
      walk([...seq, to], [...hopList, h]);
    }
  };
  for (const entry of entries) {
    if (o.includeSelf && targetSet.has(entry)) {
      const p = buildPath(ix, [entry], [], Number.isNaN(nowMs) ? null : nowMs, staleAfterMs, q);
      p.assumptions = sortedUnique([...p.assumptions, 'the entry point is itself the target; its public trust zone is declared in configuration']);
      found.push(p);
    }
    walk([entry], []);
  }
  found.sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || a.hops.length - b.hops.length || (a.id < b.id ? -1 : 1));
  const n = found.length;
  const reasons = [...(cut.depth ? ['depth'] : []), ...(cut.results ? ['result-count'] : []), ...(cut.expansions ? ['expansion'] : [])];
  const truncated = reasons.length > 0;
  return {
    ok: true, paths: found, entries, targets, truncated, limits,
    truncation: { reasons, depthCutoffs: cut.depth, frontier: cut.frontier, frontierCapped: cut.depth > cut.frontier.length },
    ...(q && q.action ? { action: q.action } : {}),
    statement: `${n} path(s) found in the supplied configuration${truncated ? ` (search stopped at a limit: ${reasons.join(', ')}; more may exist)` : ''}; a path that is not listed has not been shown to exist or to be absent`,
    errors: [],
  };
}

/**
 * What the entry points can reach under the supplied configuration, without enumerating paths. `definite` means every hop on
 * the way is possible or observed; `unresolved` means at least one hop or endpoint is unresolved. A node behind an explicit
 * deny is not reached. Used by drift detection to compare exposure between two revisions.
 *
 * @returns {Map<string, {state:'definite'|'unresolved', via:string[]}>} node id to how it is reached (an entry maps to itself)
 */
export function exposureReach(graph, { entries } = {}) {
  const ix = indexGraph(graph);
  const start = (entries ?? defaultEntries(graph)).filter((id) => ix.nodesById.has(id));
  const best = new Map();
  const queue = [];
  for (const id of start) {
    best.set(id, { state: ix.nodesById.get(id).resolved ? 'definite' : 'unresolved', via: [] });
    queue.push(id);
  }
  while (queue.length) {
    const id = queue.shift();
    const cur = best.get(id);
    for (const [to, h] of hopsFrom(ix, id)) {
      const st = hopState(h, ix.nodesById.get(id), ix.nodesById.get(to));
      if (st === 'blocked' || st === 'not-granted') continue;
      const state = cur.state === 'unresolved' || st === 'unresolved' ? 'unresolved' : 'definite';
      const prev = best.get(to);
      if (prev && (prev.state === 'definite' || state === 'unresolved')) continue;
      best.set(to, { state, via: [...cur.via, ...h.edges.map((e) => e.id).sort()] });
      queue.push(to);
    }
  }
  return best;
}

// ------------------------------------------------------------ trusted verification

/**
 * Judge whether a verification record is an applicable trusted oracle result for this finding. Nothing is read from a record's
 * own claim: the record is validated, its confirmation level is recomputed from its evidence, and its oracle must be the one the
 * finding's class names (a finding of an unsupported class has no applicable oracle).
 */
export function assessVerification(finding, records, hypothesisId = hypothesisIdFromFinding(finding), { revision = null } = {}) {
  const out = [];
  const cls = nonTaintClassOf(finding);
  for (const rec of Array.isArray(records) ? records : []) {
    if (!rec || typeof rec !== 'object') continue;
    const valid = validateVerificationRecord(rec);
    if (!valid.ok) { out.push({ recordId: typeof rec.id === 'string' ? rec.id : null, outcome: null, applicable: false, reasons: ['the record failed validation'] }); continue; }
    if (rec.hypothesisId !== hypothesisId) continue;
    const reasons = [];
    if (rec.outcome !== 'confirmed') reasons.push(`the outcome is '${rec.outcome}', not confirmed`);
    else if (deriveConfirmationLevel(rec) !== 'runtime-confirmed') reasons.push('no trusted runtime proof from a trusted runner backs the confirmation');
    if (cls && !cls.supported) reasons.push(`the finding's class '${cls.classId}' has no supported oracle`);
    else if (cls) {
      const adapter = SCENARIO_CLASSES.find((c) => c.id === cls.classId)?.adapterId;
      if (!rec.oracle || rec.oracle.id !== adapter) reasons.push(`the record's oracle is not '${adapter}', the oracle for class '${cls.classId}'`);
    }
    // threat-model FR-04.1: an exact matching commit is the minimum for a CURRENT component proof; a record for another revision is
    // kept, with the reason, as historical evidence and never applied to this graph
    let historical = false;
    if (revision && rec.commit !== revision) { historical = true; reasons.push(`the record was made at ${String(rec.commit).slice(0, 12)}, not this graph's revision ${String(revision).slice(0, 12)}; it is historical evidence for that revision only`); }
    out.push({ recordId: rec.id, outcome: rec.outcome, applicable: reasons.length === 0, reasons, ...(historical ? { historical: true, commit: rec.commit } : {}) });
  }
  return out.sort((a, b) => String(a.recordId).localeCompare(String(b.recordId)));
}

function labelPath(path, assessments, pc = null) {
  const ok = assessments.find((a) => a.applicable);
  if (!ok) {
    const why = assessments.length ? assessments.flatMap((a) => a.reasons).slice(0, 3).join('; ') : 'no verification record for this hypothesis was supplied';
    return { label: 'not-established', recordId: null, reason: `${why}; reachability alone does not show exploitability` };
  }
  if (path.state === 'blocked') return { label: 'oracle-confirmed-path-blocked', recordId: ok.recordId, reason: 'the oracle confirmed the effect in its declared scenario, but configuration explicitly denies a hop on this path' };
  if (path.state === 'unresolved') return { label: 'oracle-confirmed-path-unresolved', recordId: ok.recordId, reason: 'the oracle confirmed the effect in its declared scenario, but deployment reachability along this path is unresolved' };
  // threat-model FR-04.1 (TM-05): promotion to exploitable needs an issued binding of this proof to THIS path; a component proof alone
  // is reported beside the path and does not promote it
  const record = pc && pc.records.find((r) => r && r.id === ok.recordId);
  const j = record ? judgePathPromotion({ path, kind: pc.kind, graph: pc.graph, record, bindings: pc.proofBindings, trustRoot: pc.trustRoot, now: pc.now, expect: pc.expect }) : { promote: false, code: 'component-only', reason: 'no binding was supplied', diagnostics: [] };
  if (!j.promote) return { label: 'not-established', recordId: null, reason: `a trusted oracle confirmed the component, but it is not shown on this ${pc ? pc.kind : 'deployed'} path: ${j.reason}`, componentProof: { recordId: ok.recordId, code: j.code, diagnostics: j.diagnostics } };
  return { label: 'exploitable-confirmed', recordId: ok.recordId, reason: 'a trusted oracle confirmed the effect in its declared scenario, and an issued binding ties that proof to this path; deployment reachability comes from configuration or sampled observation, not from a production probe', bindingId: j.bindingId };
}

// ------------------------------------------------------------ the per-finding context

const EXPOSURE_ORDER = ['runtime-supported', 'possible', 'unresolved', 'blocked'];

function summarizeExposure(paths) {
  const states = new Set(paths.map((p) => p.state));
  const state = EXPOSURE_ORDER.find((s) => states.has(s)) ?? 'none-found';
  const statement = {
    'runtime-supported': 'an exposed entry point reaches the service and every network hop was observed in the supplied traces; traffic coverage is not established',
    possible: 'an exposed entry point reaches the service according to configuration; no hop was exercised',
    unresolved: 'an exposed entry point might reach the service, but a hop or condition is unresolved',
    blocked: 'every path found from an exposed entry point crosses an explicit deny',
    'none-found': 'no path from an exposed entry point was found in the supplied configuration; this does not show that none exists',
  }[state];
  return { state, pathCount: paths.length, statement };
}

/**
 * The deployment context of one finding: binding, exposure paths to its service, impact paths from it, trusted-verification
 * assessments, and what the analysis could not cover. Never throws.
 *
 * @param {object} args
 * @param {object} args.graph
 * @param {object} args.finding
 * @param {Array} [args.bindings]  see `bindFindingToService`
 * @param {Array} [args.records]   version-1 verification records
 * @param {number|string} [args.now]
 */
export function analyzeFindingBoundaries({ graph, finding, bindings = [], records = [], now, maxHops, maxPaths, action, context: requestContext, proofBindings = [], trustRoot = {}, expect = {} } = {}) {
  const v = validateBoundaryGraph(graph);
  if (!v.ok) return { ok: false, context: null, errors: v.errors };
  const hypothesisId = hypothesisIdFromFinding(finding);
  const binding = bindFindingToService(finding, bindings, graph);
  const assessments = assessVerification(finding, records, hypothesisId, { revision: graph.revision ?? null });
  const clock = now === undefined || now === null ? Date.now() : (typeof now === 'number' ? now : Date.parse(now));
  const pc = (kind) => ({ kind, graph, records: Array.isArray(records) ? records : [], proofBindings, trustRoot, now: clock, expect });
  const paths = [];
  let truncated = false;
  const truncationReasons = new Set();
  const popts = { now, maxHops, maxPaths, ...(action ? { action } : {}), ...(requestContext ? { context: requestContext } : {}) };
  if (binding.status === 'bound') {
    const exposure = computeAttackPaths(graph, { ...popts, targets: [binding.service.id], includeSelf: true });
    const impact = computeAttackPaths(graph, { ...popts, entries: [binding.service.id] });
    truncated = exposure.truncated || impact.truncated;
    for (const r of [...exposure.truncation.reasons, ...impact.truncation.reasons]) truncationReasons.add(r);
    for (const p of exposure.paths) paths.push({ kind: 'exposure', ...p, exploitability: labelPath(p, assessments, pc('exposure')) });
    for (const p of impact.paths) paths.push({ kind: 'impact', ...p, exploitability: labelPath(p, assessments, pc('impact')) });
  }
  const exposurePaths = paths.filter((p) => p.kind === 'exposure');
  const exposure = binding.status === 'bound' ? summarizeExposure(exposurePaths)
    : { state: 'not-assessed', pathCount: 0, statement: `exposure was not assessed: ${binding.reason}` };

  const uncovered = [];
  if (binding.status !== 'bound') uncovered.push({ type: 'binding', detail: binding.reason, pathId: null });
  const seen = new Set();
  for (const p of paths) {
    const unobserved = new Set(p.coverage.unobservedHops);
    for (const c of p.crossings) {
      if (c.type === 'identity' || unobserved.has(c.hop)) {
        const key = `${c.type}|${c.detail}`;
        if (!seen.has(key)) { seen.add(key); uncovered.push({ type: c.type, detail: c.detail, pathId: p.id, reason: 'configured only; no runtime observation of this boundary' }); }
      }
    }
  }
  for (const g of graph.gaps) uncovered.push({ type: 'gap', detail: `${g.code}: ${g.subject}`, pathId: null });
  uncovered.sort((a, b) => `${a.type}|${a.detail}`.localeCompare(`${b.type}|${b.detail}`));

  const warnings = ['Runtime traffic coverage is not established by any supplied observation; configured relationships were not exercised.'];
  if (binding.status !== 'bound') warnings.push(`This finding is not tied to a deployed service (${binding.status}); no path was computed.`);
  if (graph.gaps.length) warnings.push(`The boundary graph has ${graph.gaps.length} gap(s) (${sortedUnique(graph.gaps.map((g) => g.code)).join(', ')}); relationships behind them are missing, not absent.`);
  if (truncated) warnings.push(`The path search stopped at a limit (${[...truncationReasons].sort().join(', ')}); more paths may exist, so no listed absence is a proof of absence.`);

  const context = {
    schema: BOUNDARY_CONTEXT_SCHEMA, schemaVersion: BOUNDARY_CONTEXT_VERSION, id: '', hypothesisId,
    finding: { id: nul(finding?.id), stableId: nul(finding?.stableId), file: nul(finding?.file), line: Number.isInteger(finding?.line) ? finding.line : null, vuln: nul(finding?.vuln), cwe: nul(finding?.cwe) },
    binding: { status: binding.status, reason: binding.reason, rule: binding.binding, service: binding.service },
    graph: {
      repository: graph.repository, revision: graph.revision, digest: graph.digest,
      environments: sortedUnique(graph.nodes.map((n) => n.environment).filter(Boolean)),
      repositories: sortedUnique([graph.repository, ...graph.nodes.map((n) => n.repository)].filter(Boolean)),
      tenants: sortedUnique(graph.nodes.map((n) => n.tenant).filter(Boolean)),
      gapCodes: sortedUnique(graph.gaps.map((g) => g.code)), gapCount: graph.gaps.length,
    },
    exposure, paths, truncated, truncation: { reasons: [...truncationReasons].sort() },
    ...(action ? { action } : {}),
    verification: assessments, uncovered, warnings,
  };
  context.id = semanticId('bctx', { hypothesisId, graph: graph.digest, binding: binding.binding, service: binding.service?.id ?? null, paths: paths.map((p) => p.id) }, ['hypothesisId', 'graph', 'binding', 'service', 'paths']);
  return { ok: true, context, errors: [] };
}
