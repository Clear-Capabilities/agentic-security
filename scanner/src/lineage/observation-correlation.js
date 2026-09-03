//
// observation-correlation.js — M5 deliverable #7b (Runtime-Corroborated
// Digital Twin, "runtime-observed" half only; "7a", config-declared edges,
// is out of scope for this whole sub-project — see the scoping doc §4.0),
// FR-505, AC-29 clauses 1-4 ("Runtime observation remains metadata-only
// and non-exclusionary" — the Milestone 5 exit-gate clause this module is
// gated on). Pure by contract: no fs, no I/O, never throws.
//
// Task 1 (`runtime-observation.js`) shipped the closed-world
// `RuntimeObservation` structural contract. This module is the SECOND
// half: the actual graph-ID matching (`matchObservationToGraph`) and the
// per-flow correlation layer (`correlateObservations`) that make AC-29
// clauses 1-4 true, not merely documented.
//
// ── Why `observation-correlation.js` and not `runtime-correlation.js` ──
//
// `scanner/src/posture/runtime-correlation.js` already exists and is
// LIVE-WIRED into every scan (`engine.js` imports it and calls
// `annotateRuntimeCorrelation` inside `_runAnnotator`). This codebase has
// already been bitten once by two same-named-but-different annotators
// coexisting under confusable names — see the root `CLAUDE.md`'s
// `annotateGitProvenance` naming rule, which exists for the identical
// reason. Naming this file `runtime-correlation.js` would recreate that
// exact hazard for the second time in this package's own history.
//
// ── What is reused from `posture/runtime-correlation.js`, and what isn't ──
//
// The TECHNIQUE is reused: a most-specific-identifier-first match ladder,
// falling back to an honest no-match; a window filter over observed
// events. The SCHEMA is not. `posture/runtime-correlation.js` is
// code-execution-shaped (`qid`/`fileRel`/`line`,
// `kind: 'function-call' | 'route-hit' | 'syscall' | 'file-touch'`) — it
// answers "was this LINE OF CODE executed." This module is
// destination-shaped (`node.destination.literalValue` /
// `node.storeDetail.table` / `node.queueDetail.topic`) — it answers "was
// this DESTINATION contacted." Nothing is imported from that module, and
// nothing here should ever be made to look like it is.
//
// ── Clause 3 ("non-exclusionary") is structural, not disciplinary ──────
//
// `correlateObservations` returns annotations keyed by id — it never
// filters, removes, reorders, or mutates a graph entity. Both flows in
// AC-29's own two-flow scenario stay present in `graph.nodes`/`.edges`/
// `.flows` and in this function's own `byFlow` map, in every evaluated
// state, always. "Both statically possible paths remain visible even when
// only one shows runtime corroboration" is therefore true BY
// CONSTRUCTION: a future refactor that starts returning a FILTERED flow
// list (e.g. "only flows with runtime evidence") falsifies AC-29 clause 3
// directly, not just this module's own test suite — there is no discipline
// to violate, only a return shape to change.
//
// ── Clause 2 ("three-valued") ───────────────────────────────────────────
//
// `not_evaluated` (the store was never consulted — `observations` was
// `null`/`undefined`) and `not_observed_in_window` (the store WAS
// consulted, genuinely found nothing for this flow/window/environment) are
// two GENUINELY DIFFERENT answers, never collapsed into one "no runtime
// evidence" bucket. PRD line 2098 states this directly: an unobserved flow
// may simply be outside the telemetry window, not absent from the system.
// `evaluated: false` and `evaluated: true` with an empty observation list
// must serialize to two different JSON documents (a store never consulted
// is not the same fact as a store consulted and found empty) — pinned as
// literal JSON by this module's own test suite (`OC/5`).
//
// ── Correction 4's node-granularity boundary (wording corrected, I4) ────
//
// A RuntimeObservation corroborates that a DESTINATION NODE was contacted
// — never which of several flows ENDING AT that node actually produced the
// traffic. This is NOT the same claim as "these flows share a real
// destination": a graph node is a REGISTRY DECISION
// (`graph-builder.js`'s §6.1), and more than one distinct real-world
// destination can collapse onto one node (a pre-existing, disclosed
// coarsening) — so an observation of ONE real destination can
// over-attribute corroboration to a sibling flow whose real destination
// was never observed at all, not merely a flow that happens to share the
// same destination. FR-505's own "cannot prove field-level identity"
// applies here at the granularity the evidence genuinely has: when a
// matched sink node is the endpoint of more than one flow, every one of
// those sibling flows is demoted to `matchConfidence: 'ambiguous'` for
// THAT FLOW'S OWN per-flow answer — the underlying observation record's
// own `high`/`medium`/`low` confidence is never rewritten (the demotion is
// a property of the per-flow READING, not a mutation of the evidence).
// `OC/8` proves this both ways: demoted when siblings exist, undemoted
// when the sink has exactly one flow.
//
// ── `byFlow` is a plain object, never a `Map` ───────────────────────────
//
// This result is persisted inside a signed `lineage-graph.json` artifact
// (Correction 2). A `Map` serializes to `{}` under `JSON.stringify` —
// silently losing every entry — so `byFlow` is a plain, JSON-serializable
// object keyed by flow id, the same convention every other §10.10
// extension-contract module in this package already follows.
//
// ── `correlateObservations` never re-runs the match ladder ─────────────
//
// The match ladder runs exactly once, at IMPORT time, inside
// `matchObservationToGraph`. `correlateObservations` reads a record's
// ALREADY-RECORDED `matchedFlowIds` — it never calls
// `matchObservationToGraph` itself. This is deliberate: it keeps a stored
// observation record honest about what it was actually correlated
// against at import time, and it means a graph rebuilt after a code
// change never silently re-attributes old runtime evidence to new graph
// entities it was never actually checked against. The consequence — an
// older imported record's `matchedFlowIds` naming a flow id that no longer
// exists in a rebuilt graph — is handled defensively: each record's own
// `matchedFlowIds` is filtered against the graph's own real flow-id set
// before folding, and a dropped stale id is disclosed in `limitations`,
// never silently ignored and never silently promoted.

import {
  OBSERVATION_LAYERS,
  RUNTIME_MATCH_METHODS,
  RUNTIME_MATCH_CONFIDENCE,
  validateRuntimeObservation,
} from './runtime-observation.js';

export const CORRELATION_VERSION = '1.0.0';

const [LAYER_RUNTIME_OBSERVED, LAYER_NOT_OBSERVED_IN_WINDOW, LAYER_NOT_EVALUATED] = OBSERVATION_LAYERS;

// Mirrors `runtime-observation.js`'s own `EVENT_COUNT_BANDS` ORDER,
// deliberately without importing it — this module's interfaces-consumed
// list is exactly `OBSERVATION_LAYERS`/`RUNTIME_MATCH_METHODS`/
// `RUNTIME_MATCH_CONFIDENCE`/`validateRuntimeObservation`, and the import
// specifier list must stay exactly `['./runtime-observation.js']` either
// way — but keeping the CONSUMED-NAMES list itself minimal is deliberate
// too, so a future reviewer never has to wonder whether this module reads
// anything beyond what it documents reading.
const _EVENT_COUNT_BAND_ORDER = Object.freeze(['1', '2-10', '11-100', '101-1k', '1k+']);

const UNMATCHED_MATCH_RESULT = Object.freeze({
  matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [], matchMethod: 'unmatched', matchConfidence: 'low',
});

function _isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _sortUnique(arr) {
  return [...new Set(arr)].sort();
}

/**
 * Parses a literal destination URL into `{host, port, pathname}`, all
 * lowercased — `port` is `''` when the URL carries no explicit port.
 * Never regexes a URL by hand; returns `null` on anything unparseable.
 */
function _hostOf(literal) {
  if (typeof literal !== 'string' || literal.length === 0) return null;
  try {
    const u = new URL(literal);
    return { host: u.hostname.toLowerCase(), port: u.port, pathname: u.pathname.toLowerCase() };
  } catch {
    return null;
  }
}

// Rung 1: destination_literal / high. Only a node whose destination is
// genuinely `resolutionStatus: 'literal'` is eligible — matching on a
// `blockingExpression` (a dynamic/unresolved destination) would be
// matching on raw source text, not on a real resolved destination.
function _rung1(nodes, attrs) {
  const obsHostRaw = attrs['destination.host'];
  if (typeof obsHostRaw !== 'string' || obsHostRaw.length === 0) return [];
  const obsHost = obsHostRaw.toLowerCase();
  const obsPortRaw = attrs['destination.port'];
  const hasObsPort = obsPortRaw !== undefined && obsPortRaw !== null;
  const obsPort = hasObsPort ? String(obsPortRaw) : null;

  const matched = [];
  for (const n of nodes) {
    const dest = n?.destination;
    if (!dest || typeof dest !== 'object' || dest.resolutionStatus !== 'literal') continue;
    const parsed = _hostOf(dest.literalValue);
    if (!parsed || parsed.host !== obsHost) continue;
    // A port is ignored on BOTH sides when the observation supplies none.
    // When it does supply one, it must match the literal's own EXPLICIT
    // port — a literal carrying no explicit port is a mismatch, never a
    // wildcard match, since resolving an implicit default port needs
    // scheme knowledge this module does not attempt.
    if (hasObsPort && (!parsed.port || parsed.port !== obsPort)) continue;
    matched.push(n.id);
  }
  return matched;
}

// Rung 2: store_table / medium. `destination.service` OR `schema.name`
// (either alone suffices) matched case-insensitively against
// `node.storeDetail.table`.
function _rung2(nodes, attrs) {
  const svc = typeof attrs['destination.service'] === 'string' ? attrs['destination.service'].toLowerCase() : null;
  const schemaName = typeof attrs['schema.name'] === 'string' ? attrs['schema.name'].toLowerCase() : null;
  if (svc === null && schemaName === null) return [];

  const matched = [];
  for (const n of nodes) {
    const table = n?.storeDetail?.table;
    if (typeof table !== 'string' || table.length === 0) continue;
    const t = table.toLowerCase();
    if ((svc !== null && t === svc) || (schemaName !== null && t === schemaName)) matched.push(n.id);
  }
  return matched;
}

// Rung 3: queue_topic / medium. EXACT `destination.service` equality
// against `node.queueDetail.topic` — a substring/partial topic is
// deliberately NOT a match: substring matching over a topic identifier is
// exactly how a false positive gets in (e.g. `'orders'` matching a topic
// literally named `'...amazonaws.com/1/orders-archive'`).
function _rung3(nodes, attrs) {
  const topic = typeof attrs['destination.service'] === 'string' ? attrs['destination.service'] : null;
  if (topic === null || topic.length === 0) return [];
  const matched = [];
  for (const n of nodes) {
    if (n?.queueDetail?.topic === topic) matched.push(n.id);
  }
  return matched;
}

/**
 * `matchObservationToGraph(graph, draft) -> {matchedNodeIds, matchedEdgeIds,
 * matchedFlowIds, matchMethod, matchConfidence}` — runs once per record at
 * IMPORT time. `draft` is any object with an `attributes` field. Never
 * throws; a malformed graph or draft yields the honest all-empty
 * `'unmatched'`/`'low'` answer.
 *
 * The ladder tries rung 1, then rung 2, then rung 3, stopping at the FIRST
 * rung that produces any match — a graph containing both a rung-1 and a
 * rung-2 candidate for one observation is reported at rung 1 only.
 * Confidence is the rung's own (`'high'`/`'medium'`/`'medium'`) UNLESS
 * more than one node matched at the winning rung, in which case
 * `'ambiguous'` — an ambiguous observation must remain a candidate
 * (neither id dropped), never a silently-arbitrary pick between them
 * (mirrors `runtime-observation.js`'s own RO/6f cross-field rule).
 */
export function matchObservationToGraph(graph, draft) {
  const attrs = draft && typeof draft === 'object' ? draft.attributes : undefined;
  if (!graph || typeof graph !== 'object' || !Array.isArray(graph.nodes) || !_isPlainObject(attrs)) {
    return { ...UNMATCHED_MATCH_RESULT };
  }

  const nodes = graph.nodes.filter((n) => n && typeof n === 'object' && typeof n.id === 'string');

  let matchedNodeIds = _rung1(nodes, attrs);
  let matchMethod = 'destination_literal';
  let baseConfidence = 'high';
  if (matchedNodeIds.length === 0) {
    matchedNodeIds = _rung2(nodes, attrs);
    matchMethod = 'store_table';
    baseConfidence = 'medium';
  }
  if (matchedNodeIds.length === 0) {
    matchedNodeIds = _rung3(nodes, attrs);
    matchMethod = 'queue_topic';
    baseConfidence = 'medium';
  }
  if (matchedNodeIds.length === 0) {
    return { ...UNMATCHED_MATCH_RESULT };
  }

  matchedNodeIds = _sortUnique(matchedNodeIds);
  const matchConfidence = matchedNodeIds.length > 1 ? 'ambiguous' : baseConfidence;

  const nodeIdSet = new Set(matchedNodeIds);
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const flows = Array.isArray(graph.flows) ? graph.flows : [];
  const matchedEdgeIds = _sortUnique(
    edges.filter((e) => e && typeof e === 'object' && nodeIdSet.has(e.to)).map((e) => e.id),
  );
  const matchedFlowIds = _sortUnique(
    flows.filter((f) => f && typeof f === 'object' && nodeIdSet.has(f.sink)).map((f) => f.id),
  );

  return { matchedNodeIds, matchedEdgeIds, matchedFlowIds, matchMethod, matchConfidence };
}

function _minIso(list) {
  let best = null;
  let bestT = Infinity;
  for (const s of list) {
    const t = Date.parse(s);
    if (Number.isFinite(t) && t < bestT) { bestT = t; best = s; }
  }
  return best;
}

function _maxIso(list) {
  let best = null;
  let bestT = -Infinity;
  for (const s of list) {
    const t = Date.parse(s);
    if (Number.isFinite(t) && t > bestT) { bestT = t; best = s; }
  }
  return best;
}

function _highestBand(bands) {
  let best = null;
  let bestIdx = -1;
  for (const b of bands) {
    const idx = _EVENT_COUNT_BAND_ORDER.indexOf(b);
    if (idx > bestIdx) { bestIdx = idx; best = b; }
  }
  return best;
}

// Worst (last-in-order) confidence across a set of contributing
// observations — a risk-precedence reduction mirroring `protection.js`'s
// own `aggregateVerdicts()` convention (worst wins).
function _worstConfidence(confs) {
  let best = null;
  let bestIdx = -1;
  for (const c of confs) {
    const idx = RUNTIME_MATCH_CONFIDENCE.indexOf(c);
    if (idx > bestIdx) { bestIdx = idx; best = c; }
  }
  return best;
}

// The contribution whose OWN confidence is strongest (lowest index in
// RUNTIME_MATCH_CONFIDENCE), ties broken by RUNTIME_MATCH_METHODS order —
// `matchMethod`/`environment`/`windowStart`/`windowEnd` on a multi-
// observation flow entry are all read off this SAME representative, so
// the fields describe one real, consistent, deterministic contributor.
function _pickRepresentative(contribs) {
  let best = null;
  for (const c of contribs) {
    if (!best) { best = c; continue; }
    const cConf = RUNTIME_MATCH_CONFIDENCE.indexOf(c.matchConfidence);
    const bConf = RUNTIME_MATCH_CONFIDENCE.indexOf(best.matchConfidence);
    if (cConf < bConf) { best = c; continue; }
    if (cConf === bConf) {
      const cMeth = RUNTIME_MATCH_METHODS.indexOf(c.matchMethod);
      const bMeth = RUNTIME_MATCH_METHODS.indexOf(best.matchMethod);
      if (cMeth < bMeth) best = c;
    }
  }
  return best;
}

function _emptyByFlowEntry(layer) {
  return {
    layer,
    observationIds: [],
    matchMethod: null,
    matchConfidence: null,
    environment: null,
    windowStart: null,
    windowEnd: null,
    firstObservedAt: null,
    lastObservedAt: null,
    eventCountBand: null,
    siblingFlowCount: 0,
    // I2 (final review): an empty array (never null) for a flow with no
    // contributions at all — keeps the field's type consistent whether or
    // not the flow has evidence, mirroring every other array-valued field
    // on this shape.
    contributingEnvironments: [],
  };
}

/**
 * `correlateObservations(graph, observations, opts) -> CorrelationResult`
 * — runs at READ time, over an already-imported observation set.
 * `observations` is `RuntimeObservation[]`, or `null`/`undefined` meaning
 * NO STORE WAS CONSULTED (the three-valued layer's `not_evaluated` case).
 * `opts` is `{environment, windowStart, windowEnd}`, each nullable. Never
 * throws; never mutates `graph`.
 */
export function correlateObservations(graph, observations, opts) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const environment = o.environment ?? null;
  const windowStart = o.windowStart ?? null;
  const windowEnd = o.windowEnd ?? null;

  const flows = (Array.isArray(graph?.flows) ? graph.flows : [])
    .filter((f) => f && typeof f === 'object' && typeof f.id === 'string');

  const evaluated = observations !== null && observations !== undefined;
  const defaultLayer = evaluated ? LAYER_NOT_OBSERVED_IN_WINDOW : LAYER_NOT_EVALUATED;

  const byFlow = {};
  for (const f of flows) byFlow[f.id] = _emptyByFlowEntry(defaultLayer);

  const result = {
    version: CORRELATION_VERSION,
    evaluated,
    environment,
    windowStart,
    windowEnd,
    observedNodeIds: [],
    observedEdgeIds: [],
    observedFlowIds: [],
    notObservedFlowIds: [],
    notEvaluatedFlowIds: [],
    byFlow,
    consideredObservationIds: [],
    outOfWindowObservationIds: [],
    otherEnvironmentObservationIds: [],
    unmatchedObservationIds: [],
    invalidObservationIds: [],
    limitations: [],
  };

  if (!evaluated) {
    result.notEvaluatedFlowIds = _sortUnique(flows.map((f) => f.id));
    result.limitations = [
      'No runtime observation store was consulted for this correlation — every flow is reported '
      + 'not_evaluated, never not_observed_in_window; the two are deliberately different answers '
      + '(PRD line 2098).',
    ];
    return result;
  }

  const obsArray = Array.isArray(observations) ? observations : [];
  const flowIdSet = new Set(flows.map((f) => f.id));
  const nodeIdSet = new Set(
    (Array.isArray(graph?.nodes) ? graph.nodes : [])
      .filter((n) => n && typeof n === 'object' && typeof n.id === 'string')
      .map((n) => n.id),
  );
  const edgeIdSet = new Set(
    (Array.isArray(graph?.edges) ? graph.edges : [])
      .filter((e) => e && typeof e === 'object' && typeof e.id === 'string')
      .map((e) => e.id),
  );

  // Sibling count per matched sink node, computed ONCE from the graph's
  // own flow list, before the fold below.
  const flowsBySink = new Map();
  for (const f of flows) {
    const arr = flowsBySink.get(f.sink) ?? [];
    arr.push(f.id);
    flowsBySink.set(f.sink, arr);
  }
  const siblingCountByFlowId = new Map();
  for (const fids of flowsBySink.values()) {
    for (const fid of fids) siblingCountByFlowId.set(fid, fids.length - 1);
  }

  const consideredObservationIds = [];
  const outOfWindowObservationIds = [];
  const otherEnvironmentObservationIds = [];
  const unmatchedObservationIds = [];
  const invalidObservationIds = [];
  const observedNodeIds = new Set();
  const observedEdgeIds = new Set();
  const flowContribs = new Map();
  let droppedStaleFlowIds = false;

  for (const obs of obsArray) {
    const { valid } = validateRuntimeObservation(obs);
    if (!valid) {
      const idLabel = obs && typeof obs === 'object' && typeof obs.id === 'string' ? obs.id : '(no id)';
      invalidObservationIds.push(idLabel);
      continue;
    }

    // Environment filter (AC-29's own operator-scoping requirement):
    // exact, case-sensitive comparison — an operator's environment names
    // are theirs, and fuzzy-matching them would silently merge two
    // genuinely distinct environments (e.g. a customer's own
    // "Production" vs. this codebase's own "production").
    if (environment !== null && obs.environment !== environment) {
      otherEnvironmentObservationIds.push(obs.id);
      continue;
    }

    // Window filter: INTERVAL OVERLAP against the requested window, not
    // containment — an observation window merely straddling the
    // requested boundary still counts. `windowStart`/`windowEnd` each
    // null means an open-ended (half-open) bound on that side.
    const obsStart = Date.parse(obs.windowStart);
    const obsEnd = Date.parse(obs.windowEnd);
    const reqStart = windowStart !== null ? Date.parse(windowStart) : -Infinity;
    const reqEnd = windowEnd !== null ? Date.parse(windowEnd) : Infinity;
    const overlaps = obsStart <= reqEnd && obsEnd >= reqStart;
    if (!overlaps) {
      outOfWindowObservationIds.push(obs.id);
      continue;
    }

    consideredObservationIds.push(obs.id);

    for (const id of obs.matchedNodeIds) if (nodeIdSet.has(id)) observedNodeIds.add(id);
    for (const id of obs.matchedEdgeIds) if (edgeIdSet.has(id)) observedEdgeIds.add(id);

    // Never re-run the match ladder here — read the record's own
    // already-recorded matchedFlowIds, filtered against THIS graph's
    // real flow-id set (a stale import naming a since-removed flow is
    // dropped, disclosed, never attributed).
    const filteredFlowIds = obs.matchedFlowIds.filter((id) => flowIdSet.has(id));
    if (filteredFlowIds.length < obs.matchedFlowIds.length) droppedStaleFlowIds = true;

    if (filteredFlowIds.length === 0) {
      unmatchedObservationIds.push(obs.id);
      continue;
    }

    for (const fid of filteredFlowIds) {
      const arr = flowContribs.get(fid) ?? [];
      arr.push({
        obsId: obs.id,
        matchMethod: obs.matchMethod,
        matchConfidence: obs.matchConfidence,
        environment: obs.environment,
        windowStart: obs.windowStart,
        windowEnd: obs.windowEnd,
        firstObservedAt: obs.firstObservedAt,
        lastObservedAt: obs.lastObservedAt,
        eventCountBand: obs.eventCountBand,
      });
      flowContribs.set(fid, arr);
    }
  }

  let anySiblingDemotion = false;
  let anyMultiEnvironment = false;
  for (const [fid, contribs] of flowContribs) {
    const entry = byFlow[fid];
    if (!entry) continue; // defensive — fid is always a real flow id (filtered above)
    const rep = _pickRepresentative(contribs);
    const siblingFlowCount = siblingCountByFlowId.get(fid) ?? 0;
    if (siblingFlowCount > 0) anySiblingDemotion = true;

    // I2 (final review): the aggregated fields below (firstObservedAt/
    // lastObservedAt/eventCountBand/matchConfidence) used to be computed
    // across ALL contributors, while matchMethod/environment/windowStart/
    // windowEnd came from the representative's OWN environment alone — a
    // self-contradictory mix whenever more than one environment
    // contributed (e.g. a "production" window shown next to a "staging"
    // event-count band). Scoped to the representative's OWN environment
    // only, so every field on one entry now describes ONE real,
    // consistent, deterministic environment — with contributingEnvironments
    // disclosing the rest, never silently discarding them.
    const repEnvironmentContribs = contribs.filter((c) => c.environment === rep.environment);
    const contributingEnvironments = _sortUnique(contribs.map((c) => c.environment));
    if (contributingEnvironments.length > 1) anyMultiEnvironment = true;

    entry.layer = LAYER_RUNTIME_OBSERVED;
    entry.observationIds = _sortUnique(contribs.map((c) => c.obsId));
    entry.matchMethod = rep.matchMethod;
    // Correction 4's node-granularity boundary: sharing a sink node with
    // ANY other flow demotes this flow's own confidence to 'ambiguous',
    // regardless of every contributing observation's own confidence —
    // the observation records themselves are never rewritten. Scoped to
    // repEnvironmentContribs per I2 above (never cross-environment).
    entry.matchConfidence = siblingFlowCount > 0 ? 'ambiguous' : _worstConfidence(repEnvironmentContribs.map((c) => c.matchConfidence));
    entry.environment = rep.environment;
    entry.windowStart = rep.windowStart;
    entry.windowEnd = rep.windowEnd;
    entry.firstObservedAt = _minIso(repEnvironmentContribs.map((c) => c.firstObservedAt));
    entry.lastObservedAt = _maxIso(repEnvironmentContribs.map((c) => c.lastObservedAt));
    entry.eventCountBand = _highestBand(repEnvironmentContribs.map((c) => c.eventCountBand));
    entry.siblingFlowCount = siblingFlowCount;
    entry.contributingEnvironments = contributingEnvironments;
  }

  const observedFlowIds = [];
  const notObservedFlowIds = [];
  for (const f of flows) {
    if (byFlow[f.id].layer === LAYER_RUNTIME_OBSERVED) observedFlowIds.push(f.id);
    else notObservedFlowIds.push(f.id);
  }

  const limitations = [];
  if (droppedStaleFlowIds) {
    limitations.push(
      'One or more runtime observations referenced matchedFlowIds no longer present in this graph '
      + '(a stale import) — those references were dropped rather than attributed to a flow they were '
      + 'never actually re-checked against.',
    );
  }
  if (observedFlowIds.length === 0) {
    limitations.push(
      'No runtime observation matched any flow in the requested environment/window — the absence of '
      + 'a runtime observation is not evidence a flow did not occur (PRD line 2098).',
    );
  }
  if (anySiblingDemotion) {
    limitations.push(
      // I4 (final review): the prior wording ("never which of several
      // flows sharing that node produced the traffic") reads as "these
      // flows share a real destination" — false in the case this fires
      // for. A graph NODE is a registry decision (graph-builder.js §6.1)
      // that can represent more than one distinct real-world destination
      // collapsing onto it (a pre-existing, disclosed coarsening,
      // Correction 4/M2-A1) — an observation of one real destination
      // over-attributes corroboration to a sibling flow whose real
      // destination was never observed at all, not merely "shared" with
      // the one that was.
      'A runtime observation corroborates that a matched destination NODE was contacted — but a graph '
      + 'node can represent more than one distinct real-world destination that happens to collapse onto '
      + "it (a pre-existing graph-projection coarsening), not just several flows sharing one real "
      + 'destination. Every flow ending at that node is reported at matchConfidence \'ambiguous\' for '
      + 'exactly this reason (node-granularity boundary, Correction 4).',
    );
  }
  if (anyMultiEnvironment) {
    limitations.push(
      'One or more flows had contributing observations from more than one environment — each such '
      + "flow's own reported fields (matchMethod/matchConfidence/environment/window/firstObservedAt/"
      + 'lastObservedAt/eventCountBand) describe only its representative (strongest-confidence) '
      + "environment; see that flow's own contributingEnvironments for the full set of environments "
      + 'that actually contributed (I2).',
    );
  }

  result.observedNodeIds = _sortUnique([...observedNodeIds]);
  result.observedEdgeIds = _sortUnique([...observedEdgeIds]);
  result.observedFlowIds = _sortUnique(observedFlowIds);
  result.notObservedFlowIds = _sortUnique(notObservedFlowIds);
  result.notEvaluatedFlowIds = [];
  result.consideredObservationIds = _sortUnique(consideredObservationIds);
  result.outOfWindowObservationIds = _sortUnique(outOfWindowObservationIds);
  result.otherEnvironmentObservationIds = _sortUnique(otherEnvironmentObservationIds);
  result.unmatchedObservationIds = _sortUnique(unmatchedObservationIds);
  result.invalidObservationIds = _sortUnique(invalidObservationIds);
  result.limitations = limitations;

  return result;
}
