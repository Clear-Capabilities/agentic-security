// decision-story.js — M4 deliverable #7 (FR-501 §14, DFG-035): the
// DecisionStory extension contract (§10.10) + a transparent 9-factor
// ranking engine over real flows.
//
// Mirrors obligation-mapping.js's own shape exactly: a record is
// explicitly NOT a DataFlowGraph v1 entity (§10.10 — "associated with,
// but not required inside, the immutable base graph"), never added to
// dataflow-graph.schema.json, never routed through validate.js.
//
// Ranking-factor availability, grounded in real investigation (see this
// sub-project's own scoping doc): 7 of 9 factors are direct reads off
// the graph, 1 (breadth) is a small new aggregation defined here, and 2
// (recipientJurisdiction, changeRecency) are honestly `available: false`
// on every flow — never fabricated, never silently dropped from the
// factor list. recipientJurisdiction needs a RecipientProfile extension
// (capability #6, not yet built); changeRecency needs GraphSnapshot/
// GraphDiff (capability #3, Data-Flow Time Machine, not yet built).
//
// PRD's own binding constraint: "never represents an uncalibrated score
// as expected financial loss or breach probability." This module NEVER
// blends factors into a single opaque float — rankFlows performs a
// documented, transparent, CONFIGURABLE (opts.factorOrder) multi-key
// sort over each factor's own ordinal tier. Every factor stays
// individually inspectable on the returned record.

import { SEVERITY_RANK, DEFAULT_TAXONOMY } from '../dataflow/privacy-taxonomy.js';

// The sink-registry categories (sink-registry.js's own CATEGORY_NODE_KIND
// vocabulary) that count as an AI destination for the aiUse factor.
// Exported so export-briefing.js's own "AI providers" chapter-3 listing
// reads the SAME vocabulary rather than keeping a second, independently
// drifting copy (Task 2 review finding, fixed).
export const AI_SINK_SUBTYPES = Object.freeze(['ai-model-provider', 'ai-agent', 'ai-tool']);

export const RANKING_FACTORS = Object.freeze([
  'sensitivity', 'externality', 'controlVerdict', 'recipientJurisdiction',
  'aiUse', 'breadth', 'evidenceConfidence', 'policyState', 'changeRecency',
]);

// Ordinal tier ranks, worst-first, used both to score a flow's own
// factor and to compare two flows during rankFlows's own sort. Every
// factor uses a SMALL, real, disclosed vocabulary — never a blended
// number.
const _TIER_RANK = {
  sensitivity: { critical: 4, high: 3, medium: 2, low: 1, none: 0 },
  externality: { external: 2, unknown: 1, internal: 0 },
  controlVerdict: { unprotected: 4, mixed: 3, unknown: 2, not_assessed: 1, protected: 0, not_applicable: 0 },
  recipientJurisdiction: { unknown: 0 },
  aiUse: { ai_destination: 1, none: 0 },
  breadth: { high: 2, medium: 1, low: 0 },
  // Lower confidence is MORE attention-worthy (an uncertain flow needs
  // review), so the tier rank is inverted relative to the raw score —
  // disclosed here, not left implicit.
  evidenceConfidence: { low: 2, medium: 1, high: 0 },
  policyState: { prohibited: 4, manual_review_required: 3, conditionally_permitted: 2, not_evaluated: 1, permitted: 0 },
  changeRecency: { unknown: 0 },
};

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isArray(v) { return Array.isArray(v); }

/**
 * Structural validation only — mirrors
 * obligation-mapping.js#validateObligationMapping's own {valid, errors}
 * shape and "never throws" contract.
 */
export function validateDecisionStory(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'DecisionStory record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('story:')) {
    err('$.id', 'id is required and must start with "story:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.audienceMode)) err('$.audienceMode', 'audienceMode is required');
  if (!_isPlainObject(record.scopeQuery)) err('$.scopeQuery', 'scopeQuery is required and must be an object');
  if (!_isArray(record.chapters)) err('$.chapters', 'chapters must be an array');
  if (!_isArray(record.contributingGraphIds)) err('$.contributingGraphIds', 'contributingGraphIds must be an array');
  if (!_isArray(record.rankingFactors)) err('$.rankingFactors', 'rankingFactors must be an array');
  if (!_isNonEmptyString(record.evidenceGrade)) err('$.evidenceGrade', 'evidenceGrade is required');
  if (!_isPlainObject(record.coverage)) err('$.coverage', 'coverage is required and must be an object');
  if (!_isArray(record.decisions)) err('$.decisions', 'decisions must be an array');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');

  return { valid: errors.length === 0, errors };
}

function _sensitivityFactor(flow, graph) {
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const classes = de?.dataClasses ?? [];
  if (classes.length === 0) return { available: true, tier: 'none', evidence: [] };
  let worst = 'low';
  for (const cls of classes) {
    const sev = DEFAULT_TAXONOMY[cls]?.severity ?? 'medium';
    if ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[worst] ?? 0)) worst = sev;
  }
  return { available: true, tier: worst, evidence: [de.id] };
}

function _externalityFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const value = sink?.externality?.value ?? 'unknown';
  return { available: true, tier: value, evidence: [flow.sink] };
}

function _controlVerdictFactor(flow) {
  return { available: true, tier: flow.protectionSummary ?? 'not_assessed', evidence: flow.edgeIds ?? [] };
}

function _recipientJurisdictionFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'RecipientProfile extension not yet built (capability #6, Third-Party/Cross-Border Intelligence)' };
}

function _aiUseFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const isAi = AI_SINK_SUBTYPES.includes(sink?.subtype);
  return { available: true, tier: isAi ? 'ai_destination' : 'none', evidence: isAi ? [flow.sink] : [] };
}

/**
 * New small aggregation (the scoping doc's own "smallest real addition"
 * for breadth/blast-radius): how many OTHER flows in the same graph
 * share this flow's own sink node or dataElement. A crude but real,
 * non-fabricated proxy for "how widely does this exposure reach" —
 * never presented as a calibrated blast-radius count, just an ordinal
 * tier over a real, disclosed count.
 */
function _breadthFactor(flow, graph) {
  let sharedCount = 0;
  for (const other of graph.flows) {
    if (other.id === flow.id) continue;
    const sharesSink = other.sink === flow.sink;
    const sharesData = other.dataElementIds.some((id) => flow.dataElementIds.includes(id));
    if (sharesSink || sharesData) sharedCount++;
  }
  const tier = sharedCount >= 5 ? 'high' : sharedCount >= 1 ? 'medium' : 'low';
  return { available: true, tier, evidence: [], sharedFlowCount: sharedCount };
}

function _evidenceConfidenceFactor(flow) {
  const tier = flow.confidence?.tier ?? 'medium';
  return { available: true, tier, evidence: [] };
}

function _policyStateFactor(flow) {
  return { available: true, tier: flow.policyVerdict ?? 'not_evaluated', evidence: flow.evidenceRefs ?? [] };
}

function _changeRecencyFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'GraphSnapshot/GraphDiff not yet built (capability #3, Data-Flow Time Machine)' };
}

/** Score ONE flow on all 9 factors. Never throws on a well-formed graph. */
export function scoreFlow(flow, graph, nodesById) {
  return {
    flowId: flow.id,
    factors: {
      sensitivity: _sensitivityFactor(flow, graph),
      externality: _externalityFactor(flow, nodesById),
      controlVerdict: _controlVerdictFactor(flow),
      recipientJurisdiction: _recipientJurisdictionFactor(),
      aiUse: _aiUseFactor(flow, nodesById),
      breadth: _breadthFactor(flow, graph),
      evidenceConfidence: _evidenceConfidenceFactor(flow),
      policyState: _policyStateFactor(flow),
      changeRecency: _changeRecencyFactor(),
    },
  };
}

/**
 * Score and rank every flow in the graph. opts.factorOrder (default
 * RANKING_FACTORS) is the PRD's own "transparent configurable factors"
 * requirement, made real: a lexicographic multi-key sort over each
 * factor's own ordinal tier rank, in the given priority order — NEVER a
 * blended single score. Ties within all factors preserve original flow
 * order (stable sort).
 */
export function rankFlows(graph, opts = {}) {
  const factorOrder = opts.factorOrder ?? RANKING_FACTORS;
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const scored = graph.flows.map((flow) => ({
    flow,
    ...scoreFlow(flow, graph, nodesById),
    factorOrderUsed: factorOrder,
  }));
  const rankOf = (scoredFlow, factor) => {
    const f = scoredFlow.factors[factor];
    return _TIER_RANK[factor]?.[f.tier] ?? 0;
  };
  return scored.sort((a, b) => {
    for (const factor of factorOrder) {
      const diff = rankOf(b, factor) - rankOf(a, factor);
      if (diff !== 0) return diff;
    }
    return 0;
  });
}
