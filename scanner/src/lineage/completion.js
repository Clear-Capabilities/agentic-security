// completion.js: the shared completion envelope (DAG-07 R07.1/R07.2, PRD 5.2).
//
// One small, pure vocabulary that every long-running or bounded step uses to
// say how far it got: field analysis, summary computation, source seeding,
// graph construction, reverse selection and path queries. It imports nothing
// from any analysis engine, so both the lineage package and the executable
// taint package can produce and consume it.
//
// Two facts are kept apart on purpose:
//   - queryExhausted: did THIS step run to the end of its own frontier?
//   - modelCoverage:  does the MODEL it ran over describe the whole software?
// Exhausting a modeled graph never proves the software has no missing edges,
// so `negativeClaimAllowed` (the only license to say "no modeled path") needs
// a complete status, an exhausted query and an empty frontier, and even then
// the claim is scoped to the modeled graph, never to "no vulnerability".

export const COMPLETION_SCHEMA_VERSION = '1.0.0';

export const COMPLETION_STATUSES = Object.freeze(['complete', 'partial', 'cancelled', 'unavailable', 'invalid']);
export const MODEL_COVERAGE = Object.freeze(['complete', 'partial', 'unknown']);

// Higher rank wins when records are combined: the combined answer is only as
// good as its worst part.
const RANK = { complete: 0, partial: 1, unavailable: 2, cancelled: 3, invalid: 4 };

export const NEGATIVE_CLAIM_SCOPE = 'modeled-graph-only';

function nonNegInt(v) {
  return Number.isInteger(v) && v >= 0 ? v : 0;
}

function uniqSorted(list) {
  return [...new Set((list ?? []).filter((x) => typeof x === 'string' && x.length > 0))].sort();
}

/**
 * Build a validated completion envelope. Unknown statuses become `invalid`
 * (with a reason) rather than being passed through, so a consumer can trust
 * the vocabulary. `negativeClaimAllowed` is always derived here, never taken
 * from the caller.
 */
export function makeCompletion(fields = {}) {
  const reasons = uniqSorted(fields.reasons);
  let status = fields.status;
  if (!COMPLETION_STATUSES.includes(status)) {
    status = 'invalid';
    reasons.push('unknown-completion-status');
  }
  const unexplored = nonNegInt(fields.unexploredFrontierCount);
  const modelCoverage = MODEL_COVERAGE.includes(fields.modelCoverage)
    ? fields.modelCoverage
    : (status === 'complete' ? 'complete' : 'partial');
  // Partial work is never an exhausted query, whatever the caller says.
  const queryExhausted = status === 'complete' && fields.queryExhausted !== false && unexplored === 0;
  const env = {
    schemaVersion: COMPLETION_SCHEMA_VERSION,
    status,
    queryExhausted,
    modelCoverage,
    negativeClaimAllowed: status === 'complete' && queryExhausted && unexplored === 0 && reasons.length === 0,
    reasons: uniqSorted(reasons),
    limits: fields.limits && typeof fields.limits === 'object' ? { ...fields.limits } : {},
    unexploredFrontierCount: unexplored,
  };
  if (env.negativeClaimAllowed) env.negativeClaimScope = NEGATIVE_CLAIM_SCOPE;
  if (typeof fields.unit === 'string') env.unit = fields.unit;
  return env;
}

/** Combine several envelopes: worst status wins, reasons union, frontier sums, limits namespaced by unit. */
export function combineCompletions(list, unit) {
  const items = (list ?? []).filter(Boolean);
  if (items.length === 0) return makeCompletion({ status: 'unavailable', reasons: ['no-completion-records'], unit });
  let status = 'complete';
  let modelCoverage = 'complete';
  let unexplored = 0;
  const reasons = [];
  const limits = {};
  for (const c of items) {
    if ((RANK[c.status] ?? 4) > RANK[status]) status = c.status;
    if (c.modelCoverage === 'partial' || (c.modelCoverage === 'unknown' && modelCoverage === 'complete')) modelCoverage = c.modelCoverage;
    unexplored += nonNegInt(c.unexploredFrontierCount);
    reasons.push(...(c.reasons ?? []));
    if (c.unit) limits[c.unit] = c.limits ?? {};
  }
  return makeCompletion({ status, modelCoverage, unexploredFrontierCount: unexplored, reasons, limits, unit });
}

/**
 * Adapter for the roll-up the field-identity driver / graph builder produce
 * (`analysisCompletion`): {status, functionsAnalyzed, functionsNotAnalyzed,
 * incomplete[], degraded[], storeLimits?, seeding?}.
 */
export function fromAnalysisCompletion(ac) {
  if (!ac || typeof ac !== 'object') return makeCompletion({ status: 'unavailable', reasons: ['no-analysis-completion-record'], unit: 'analysis' });
  const reasons = [];
  for (const u of ac.incomplete ?? []) reasons.push(...(u.reasons ?? ['analysis-incomplete']));
  for (const d of ac.degraded ?? []) reasons.push(d.reason === 'context-cap' ? 'context-cap' : d.reason === 'recursion-nonconverged' ? 'recursion-nonconverged' : 'degraded-context');
  if (ac.status === 'cancelled') reasons.push('cancelled');
  if (ac.storeLimits?.hit) reasons.push('construction-limit');
  if (ac.seeding && ac.seeding.status && ac.seeding.status !== 'complete') reasons.push(...(ac.seeding.reasons ?? ['seeding-incomplete']));
  if (ac.incremental && ac.incremental.status && ac.incremental.status !== 'complete') reasons.push(...(ac.incremental.reasons ?? []));
  const unfinished = (ac.incomplete ?? []).reduce((n, u) => n + nonNegInt(u.unfinishedWork), 0) + nonNegInt(ac.functionsNotAnalyzed);
  const status = COMPLETION_STATUSES.includes(ac.status) ? ac.status : 'invalid';
  const limits = {
    functionsAnalyzed: nonNegInt(ac.functionsAnalyzed),
    functionsNotAnalyzed: nonNegInt(ac.functionsNotAnalyzed),
    incompleteUnits: (ac.incomplete ?? []).length,
    degradedContexts: (ac.degraded ?? []).length,
  };
  if (ac.storeLimits?.hit) {
    limits.hopsRefused = nonNegInt(ac.storeLimits.hopsRefused);
    limits.groupsSkipped = (ac.storeLimits.groupsSkipped ?? []).length;
    limits.edgesRefused = nonNegInt(ac.storeLimits.edgesRefused);
  }
  return makeCompletion({
    status: status === 'complete' && reasons.length ? 'partial' : status,
    modelCoverage: status === 'complete' && reasons.length === 0 ? 'complete' : 'partial',
    unexploredFrontierCount: unfinished,
    reasons, limits, unit: 'analysis',
  });
}

/** Adapter for a `reconstructPaths` result (path-query.js). */
export function fromQueryResult(r) {
  if (!r || typeof r !== 'object') return makeCompletion({ status: 'unavailable', reasons: ['no-query-result'], unit: 'query' });
  const reasons = [...(r.truncationReasons ?? [])];
  if (r.status === 'invalid') reasons.push('invalid-budget');
  if (r.unknownStartNode) reasons.push('unknown-start-node');
  if (r.analysisTruncated) reasons.push('analysis-truncated');
  const status = r.status === 'invalid' ? 'invalid' : (r.status === 'cancelled' ? 'cancelled' : (r.status === 'complete' ? 'complete' : 'partial'));
  return makeCompletion({
    status,
    modelCoverage: r.analysisTruncated ? 'partial' : undefined,
    unexploredFrontierCount: nonNegInt(r.unexploredFrontierCount) || nonNegInt(r.droppedPathCount),
    reasons,
    limits: { ...(r.budget ?? {}) },
    unit: 'query',
  });
}

/**
 * Completion of a whole DataFlowGraph, derived from what the graph already
 * carries. A graph with no completion record at all is NOT assumed complete
 * unless its own scanHealth says so; zero projected flows next to an
 * incomplete analysis is called out explicitly, because an empty result is
 * the case where the limit is easiest to miss.
 */
export function completionOfGraph(graph) {
  if (!graph || typeof graph !== 'object') return makeCompletion({ status: 'unavailable', reasons: ['no-graph'], unit: 'graph' });
  const ac = graph.coverage?.analysisCompletion ?? graph.scanHealth?.analysisCompletion ?? null;
  let env;
  if (ac) {
    env = fromAnalysisCompletion(ac);
  } else if (graph.scanHealth?.status === 'complete') {
    env = makeCompletion({ status: 'complete', modelCoverage: 'complete', unit: 'graph' });
  } else if (graph.scanHealth?.status === 'partial' || graph.scanHealth?.status === 'cancelled') {
    env = makeCompletion({ status: graph.scanHealth.status, reasons: [graph.scanHealth.reason ?? 'scan-health-not-complete'], unit: 'graph' });
  } else {
    env = makeCompletion({ status: 'unavailable', reasons: ['no-completion-record'], unit: 'graph' });
  }
  const flows = Array.isArray(graph.flows) ? graph.flows.length : null;
  if (flows === 0 && env.status !== 'complete') {
    env = makeCompletion({ ...env, reasons: [...env.reasons, 'zero-flows-with-incomplete-analysis'], limits: { ...env.limits, flowsProjected: 0 } });
  } else if (flows !== null) {
    env.limits = { ...env.limits, flowsProjected: flows };
  }
  env.unit = 'graph';
  return env;
}

const REASON_TEXT = {
  'analysis-iteration-budget': 'a function hit its analysis iteration budget',
  'context-cap': 'a call context fell back to a coarser summary (context cap)',
  'recursion-nonconverged': 'recursion did not converge',
  'degraded-context': 'a call context was degraded',
  cancelled: 'the analysis was cancelled',
  'construction-limit': 'a provenance construction limit was reached',
  'zero-flows-with-incomplete-analysis': 'zero flows were projected from an incomplete analysis',
  'seeding-limit': 'source seeding stopped at its limit',
  'incremental-empty-entry-reuse': 'a cached empty-entry summary stood in for a tainted entry',
  'caller-depth-limit': 'the reverse call-graph walk stopped at its depth limit',
  'worklist-limit': 'the reverse selection stopped at its worklist limit',
  'slice-node-budget': 'a backward slice stopped at its node budget',
  'no-completion-record': 'no completion record is available',
};

/** Human-readable lines for CLI output. Empty for a complete envelope. */
export function describeCompletion(env) {
  if (!env || env.status === 'complete') return [];
  const lines = [`analysis ${env.status}: absence of a flow is not evidence that none exists`];
  for (const r of env.reasons ?? []) lines.push(`  - ${REASON_TEXT[r] ?? r}`);
  if (env.unexploredFrontierCount > 0) lines.push(`  - ${env.unexploredFrontierCount} unit(s) of work were left unexplored`);
  return lines;
}

/** Wire digest-neutral summary used by scan health. */
export function summarizeForHealth(env) {
  return {
    status: env.status,
    reasons: env.reasons,
    unexploredFrontierCount: env.unexploredFrontierCount,
    negativeClaimAllowed: env.negativeClaimAllowed,
  };
}
