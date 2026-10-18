// Edge states and the identity-aware / absent-from-static queries of the Runtime-Corroborated Security Twin (PRD 2: "Edge States",
// section 6). Pure: no fs, no I/O, never throws, never mutates the graph. It READS what `observation-correlation.js` and the
// observation store already hold; it adds no second matching engine and writes nothing into the static graph (the overlay stays an
// overlay).
//
// The six states, and when each is ALLOWED to appear:
//   STATIC_ONLY                no telemetry was consulted at all (not "nothing seen": nothing was looked at)
//   RUNTIME_NOT_OBSERVED       telemetry was consulted for this environment/window and no trusted observation maps to the edge.
//                              Never "unreachable": the window may be short, the exporter partial, the mapping weak.
//   RUNTIME_OBSERVED           at least one high- or medium-confidence observation maps to the edge
//   RUNTIME_BLOCKED           observations map to the edge and every decision recorded for them was `denied` (the path was
//                              attempted and refused); an edge with both allowed and denied observations carries OBSERVED and BLOCKED
//   RUNTIME_POLICY_VIOLATION   the edge was observed (not only denied) AND a flow through it is `prohibited` by the privacy policy
//   RUNTIME_EXPLOIT_CORRELATED the edge was observed AND the operator supplied explicit evidence naming this edge/flow/node as the
//                              target of a proven exploit. Never inferred from observation alone: seeing traffic is not seeing an attack.
// Low-confidence and ambiguous observations (PRD: "low-confidence observations remain unmatched") never create a state; they are
// counted in `uncertainObservations` so the weakness is visible instead of silently dropped.
export const EDGE_STATES = Object.freeze(['STATIC_ONLY', 'RUNTIME_NOT_OBSERVED', 'RUNTIME_OBSERVED', 'RUNTIME_BLOCKED', 'RUNTIME_POLICY_VIOLATION', 'RUNTIME_EXPLOIT_CORRELATED']);
const SEVERITY_ORDER = ['RUNTIME_EXPLOIT_CORRELATED', 'RUNTIME_POLICY_VIOLATION', 'RUNTIME_BLOCKED', 'RUNTIME_OBSERVED', 'RUNTIME_NOT_OBSERVED', 'STATIC_ONLY'];
const TRUSTED = new Set(['high', 'medium']);

const arr = (v) => (Array.isArray(v) ? v : []);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Operator-supplied exploit evidence: [{ kind, id, edgeId?|flowId?|nodeId? }]. Anything malformed is reported, not trusted. */
export function validateExploitEvidence(list) {
  const errors = []; const ok = [];
  if (list === null || list === undefined) return { evidence: [], errors };
  if (!Array.isArray(list)) return { evidence: [], errors: ['exploit evidence must be an array'] };
  list.forEach((e, i) => {
    if (!isObj(e) || typeof e.id !== 'string' || !e.id || !['proof', 'dnr-hunt', 'incident'].includes(e.kind)) { errors.push(`entry ${i}: needs kind (proof|dnr-hunt|incident) and id`); return; }
    const targets = ['edgeId', 'flowId', 'nodeId'].filter((k) => typeof e[k] === 'string' && e[k]);
    if (targets.length !== 1) { errors.push(`entry ${i}: name exactly one of edgeId, flowId, nodeId`); return; }
    ok.push({ kind: e.kind, id: e.id.slice(0, 120), [targets[0]]: e[targets[0]] });
  });
  return { evidence: ok, errors };
}

/**
 * @returns {{ evaluated: boolean, byNode: Record<string, {states: string[], observations: number, allowed: number, denied: number}>, byEdge: Record<string, {states: string[], primary: string, observations: number, allowed: number, denied: number, uncertainObservations: number, identityTokens: string[], exploitEvidence: object[], note: string}>, counts: Record<string, number>, limitations: string[] }}
 */
export function deriveEdgeStates(graph, correlation, observations, { exploitEvidence = [] } = {}) {
  const edges = arr(graph?.edges).filter((e) => isObj(e) && typeof e.id === 'string');
  const flows = arr(graph?.flows).filter((f) => isObj(f) && typeof f.id === 'string');
  const evaluated = !!correlation?.evaluated;
  const considered = new Set(arr(correlation?.consideredObservationIds));
  const byEdge = {}; const counts = Object.fromEntries(EDGE_STATES.map((s) => [s, 0]));
  const limitations = [
    'RUNTIME_NOT_OBSERVED means "no trusted observation in this window", never "unreachable" or "safe".',
    'Only high- and medium-confidence mappings count; low-confidence and ambiguous observations stay unmatched and are counted as uncertain.',
    'RUNTIME_EXPLOIT_CORRELATED requires explicit operator-supplied evidence naming the edge, flow or node; observation alone never sets it.',
  ];
  const flowsByEdge = new Map();
  for (const f of flows) for (const eid of arr(f.edgeIds)) { const a = flowsByEdge.get(eid) ?? []; a.push(f); flowsByEdge.set(eid, a); }
  const obsByEdge = new Map();
  for (const o of arr(observations)) {
    if (!isObj(o) || (evaluated && considered.size && !considered.has(o.id))) continue;
    for (const eid of arr(o.matchedEdgeIds)) { const a = obsByEdge.get(eid) ?? []; a.push(o); obsByEdge.set(eid, a); }
  }
  for (const e of edges) {
    if (!evaluated) { byEdge[e.id] = entry(['STATIC_ONLY'], { note: 'no telemetry was consulted' }); counts.STATIC_ONLY++; continue; }
    const all = obsByEdge.get(e.id) ?? [];
    const trusted = all.filter((o) => TRUSTED.has(o.matchConfidence));
    const uncertain = all.length - trusted.length;
    if (!trusted.length) { byEdge[e.id] = entry(['RUNTIME_NOT_OBSERVED'], { uncertain, note: uncertain ? `${uncertain} low-confidence observation(s) not counted` : 'no observation in this window' }); counts.RUNTIME_NOT_OBSERVED++; continue; }
    const dec = (o) => o.attributes?.['network.securityDecision'];
    const allowed = trusted.filter((o) => dec(o) === 'allowed').length; const denied = trusted.filter((o) => dec(o) === 'denied').length;
    const states = [];
    const onlyDenied = denied > 0 && allowed === 0 && trusted.every((o) => dec(o) === 'denied');
    if (!onlyDenied) states.push('RUNTIME_OBSERVED');
    if (denied > 0) states.push('RUNTIME_BLOCKED');
    const prohibited = flowsByEdge.get(e.id)?.some((f) => f.policyVerdict === 'prohibited');
    if (!onlyDenied && prohibited) states.push('RUNTIME_POLICY_VIOLATION');
    const flowIds = new Set((flowsByEdge.get(e.id) ?? []).map((f) => f.id));
    const nodeIds = new Set([e.source, e.target, e.from, e.to].filter(Boolean));
    const ev = arr(exploitEvidence).filter((x) => x.edgeId === e.id || (x.flowId && flowIds.has(x.flowId)) || (x.nodeId && nodeIds.has(x.nodeId)));
    if (!onlyDenied && ev.length) states.push('RUNTIME_EXPLOIT_CORRELATED');
    const tokens = [...new Set(trusted.map((o) => o.attributes?.['identity.token']).filter(Boolean))].sort();
    byEdge[e.id] = entry(states, { observations: trusted.length, allowed, denied, uncertain, tokens, ev, note: '' });
    for (const s of states) counts[s]++;
  }
  // Observations the matcher placed on a NODE but on no edge or flow (a queue publish, a store write with no modelled path into it).
  // They still carry the allow/deny fact, so the refused queue publish is visible instead of vanishing between edge and node.
  const byNode = {};
  if (evaluated) {
    const perNode = new Map();
    for (const o of arr(observations)) {
      if (!isObj(o) || (considered.size && !considered.has(o.id)) || !TRUSTED.has(o.matchConfidence) || arr(o.matchedEdgeIds).length) continue;
      for (const nid of arr(o.matchedNodeIds)) { const a = perNode.get(nid) ?? []; a.push(o); perNode.set(nid, a); }
    }
    for (const [nid, list] of perNode) {
      const dec = (o) => o.attributes?.['network.securityDecision'];
      const denied = list.filter((o) => dec(o) === 'denied').length; const allowed = list.filter((o) => dec(o) === 'allowed').length;
      const onlyDenied = denied > 0 && denied === list.length;
      byNode[nid] = { states: [...(onlyDenied ? [] : ['RUNTIME_OBSERVED']), ...(denied ? ['RUNTIME_BLOCKED'] : [])], observations: list.length, allowed, denied };
    }
  }
  return { evaluated, byEdge, byNode, counts, limitations };

  function entry(states, { observations = 0, allowed = 0, denied = 0, uncertain = 0, tokens = [], ev = [], note = '' } = {}) {
    const primary = SEVERITY_ORDER.find((s) => states.includes(s));
    return { states, primary, observations, allowed, denied, uncertainObservations: uncertain, identityTokens: tokens, exploitEvidence: ev, note };
  }
}

/**
 * "Show runtime flows absent from the static graph": the observations the matcher could NOT place on any static node, reduced to the
 * destination identifiers the closed-world schema already allows. These are CANDIDATES. The matcher failing to place an observation
 * can mean a path the static analysis missed, or a mapping the matcher is too weak to make; this lists them, it does not decide.
 */
export function runtimeFlowsAbsentFromStatic(observations, correlation) {
  const unmatched = new Set(arr(correlation?.unmatchedObservationIds));
  const rows = [];
  for (const o of arr(observations)) {
    if (!isObj(o) || !unmatched.has(o.id)) continue;
    // an observation the matcher placed on a static NODE is not absent from the static graph; it only lacks a modelled flow
    if (arr(o.matchedNodeIds).length || arr(o.matchedEdgeIds).length) continue;
    const a = isObj(o.attributes) ? o.attributes : {};
    const dest = ['destination.host', 'destination.service', 'destination.port', 'destination.scheme'].filter((k) => a[k] !== undefined).map((k) => `${k.split('.')[1]}=${a[k]}`).join(' ');
    if (!dest) continue;
    rows.push({ observationId: o.id, destination: dest, service: a['service.name'] ?? null, environment: o.environment ?? null, firstObservedAt: o.firstObservedAt ?? null, lastObservedAt: o.lastObservedAt ?? null, eventCountBand: o.eventCountBand ?? null });
  }
  rows.sort((x, y) => (x.destination < y.destination ? -1 : x.destination > y.destination ? 1 : 0));
  return { candidates: rows, note: 'Unmatched observations are candidates, not proof that static analysis missed a path: the matcher may be too weak to place them.' };
}

/** "Show identities using risky paths": identity TOKENS (never identities) seen on edges in the risky states, with a band, never an exact count. */
export function identitiesUsingRiskyPaths(edgeStates) {
  const risky = new Set(['RUNTIME_POLICY_VIOLATION', 'RUNTIME_EXPLOIT_CORRELATED']);
  const byToken = new Map();
  for (const [edgeId, e] of Object.entries(edgeStates?.byEdge ?? {})) {
    if (!e.states.some((s) => risky.has(s))) continue;
    for (const t of e.identityTokens) { const x = byToken.get(t) ?? { token: t, edges: [], states: new Set() }; x.edges.push(edgeId); e.states.filter((s) => risky.has(s)).forEach((s) => x.states.add(s)); byToken.set(t, x); }
  }
  return {
    identities: [...byToken.values()].map((x) => ({ token: x.token, edgeIds: x.edges.sort(), states: [...x.states].sort() })).sort((a, b) => (a.token < b.token ? -1 : 1)),
    note: 'Tokens are keyed hashes under this install\'s key; they identify "the same identity" but never reveal who. Edges with no identity telemetry contribute nothing, which is not evidence that no identity used them.',
  };
}
