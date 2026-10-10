// Routing replay report and policy card (X-608.AC01, X-608.AC02).
//
// The report restates a promotion verdict (promotion.js) with exact denominators, so nobody has to rerun the arithmetic to see how
// many tasks stand behind a figure. It never adds a claim the verdict did not earn:
//
//   - a quality difference always appears with its interval, or with the reason it could not be measured;
//   - cost is the MEASURED median and total (retries and tool execution included), or `incomplete`; never a prediction;
//   - cache conditions and latency percentiles for both arms sit beside the cost figure they qualify;
//   - claims are restricted to the strata and model versions the gate actually passed. Unsupported strata and every unmet
//     criterion stay listed, whatever the overall status.
//
// A synthetic population reads `unmeasured` and the report says no advantage is claimed. The output is deterministic: no clock (the
// caller passes `generatedAt` or nothing) and a content hash, so a rerun from the same manifests is checkable byte for byte.

import { digestOf } from '../assurance/identity.js';
import { DRIFT_KINDS } from './drift.js';
import { ROUTING_MODES } from './control.js';

export const REPORT_SCHEMA = 'agentic-security/routing-replay-report';
export const POLICY_CARD_SCHEMA = 'agentic-security/routing-policy-card';

const NOT_CLAIMED = Object.freeze([
  'no routing cost or quality advantage is claimed outside the strata and model versions listed under claims.scope',
  'no claim is made about task kinds, languages, vulnerability classes or context sizes that were not tested',
  'no claim is made for a provider model version other than those tested, or for different prices or cache conditions',
]);

function unmetCriteria(verdict) {
  const out = [];
  const c = verdict.overall?.criteria;
  if (verdict.status !== 'pass') out.push({ gate: 'routing-promotion', status: verdict.status, reason: verdict.reason });
  if (c) {
    if (c.qualityLowerBound.met !== true) out.push({ gate: 'quality-lower-bound', met: c.qualityLowerBound.met, need: c.qualityLowerBound.need, value: c.qualityLowerBound.value });
    if (c.advantage.met !== true) out.push({ gate: 'cost-or-quality-advantage', met: c.advantage.met, needMedianCostReduction: c.advantage.needMedianCostReduction, needQualityGain: c.advantage.needQualityGain });
    if (c.p95Latency.met !== true) out.push({ gate: 'p95-latency', met: c.p95Latency.met, need: c.p95Latency.need, value: c.p95Latency.value });
  }
  for (const i of verdict.invalidations || []) out.push({ gate: 'invalidation', code: i.code, detail: i.detail });
  return out;
}

/**
 * @param {object} o
 * @param {object} o.frozen    freezeTaskSet().frozen
 * @param {object} o.replay    replayPaired() result
 * @param {object} o.verdict   evaluatePromotion() result
 * @param {object} [o.receipts] exportReceipts() result, for its head hash
 * @param {string|null} [o.generatedAt]
 */
export function buildRoutingReplayReport({ frozen, replay, verdict, receipts = null, generatedAt = null }) {
  const pairs = replay?.pairs ?? [];
  const byStratum = {};
  const passed = verdict.status === 'pass';
  for (const [s, v] of Object.entries(verdict.strata || {})) {
    // a stratum is SUPPORTED only when the whole gate passed; meeting the criteria on its own sample is not enough while the gate reads
    // unmeasured, invalid, insufficient-population or fail
    byStratum[s] = {
      frozenTasks: v.frozenTasks, pairedTasks: v.pairedTasks, adjudicated: v.adjudicated, unadjudicated: v.unadjudicated, supported: passed && v.promoted,
      criteriaMetOnSample: v.promoted, reason: passed ? v.reason : (v.promoted ? `criteria met on this sample, but the gate reads '${verdict.status}'` : v.reason),
      quality: v.quality, cost: v.cost, latencyMs: v.latencyMs, criteria: v.criteria,
    };
  }
  const supported = Object.entries(byStratum).filter(([, v]) => v.supported).map(([k]) => k);
  const unsupported = Object.entries(byStratum).filter(([, v]) => !v.supported).map(([k, v]) => ({ stratum: k, reason: v.reason, adjudicated: v.adjudicated }));
  const o = verdict.overall;
  const claims = verdict.claim.allowed
    ? {
      allowed: true, scope: verdict.claim.scope, modelVersions: verdict.claim.modelVersions,
      statements: verdict.claim.scope.map((s) => `Stratum ${s}: the proposed policy met the routing-promotion criteria on ${byStratum[s].adjudicated} paired adjudicated task(s), for model versions ${verdict.claim.modelVersions.join(', ')}, under the cache conditions shown.`),
    }
    : { allowed: false, scope: [], modelVersions: [], statements: [] };
  const report = {
    schema: REPORT_SCHEMA, schemaVersion: '1.0.0', generatedAt, synthetic: verdict.synthetic,
    status: verdict.status, reason: verdict.reason,
    denominators: {
      frozenTasks: frozen.count, pairedTasks: o.pairedTasks, droppedTasks: pairs.filter((p) => p.status === 'dropped').length,
      adjudicated: o.adjudicated, unadjudicated: o.unadjudicated,
      replay: { offline: replay.replay.offline, paidCalls: replay.paidCalls, spentUsd: replay.replay.spentUsd, truncated: replay.replay.truncated, bounds: replay.replay.bounds },
    },
    comparison: { quality: o.quality, cost: o.cost, cache: o.cache, latencyMs: o.latencyMs, failures: o.failures },
    strata: byStratum, supportedStrata: supported, unsupportedStrata: unsupported,
    gate: { thresholds: verdict.thresholds, criteria: o.criteria, invalidations: verdict.invalidations },
    unmetGates: unmetCriteria(verdict),
    claims, notClaimed: NOT_CLAIMED.slice(),
    reproduce: { frozenHash: frozen.hash, replayHash: verdict.replayHash, verdictHash: verdict.verdictHash, receiptsHead: receipts ? receipts.headHash : null, command: 'npm run reproduce:routing' },
    disclosure: verdict.synthetic ? 'SYNTHETIC population: this exercises the machinery and measures nothing about real routing' : 'the figures describe the tested strata and model versions only',
  };
  report.reportHash = digestOf({ ...report, reportHash: undefined });
  return report;
}

const pct = (x) => (x === null || x === undefined ? 'n/a' : `${(x * 100).toFixed(1)}%`);
const num = (x) => (x === null || x === undefined ? 'n/a' : String(x));

/** Plain-text rendering of the report. Same content as the object; nothing is added or softened. */
export function renderRoutingReport(r) {
  const q = r.comparison.quality; const c = r.comparison.cost; const l = r.comparison.latencyMs;
  const lines = [];
  lines.push(`Routing replay report (${r.synthetic ? 'SYNTHETIC' : 'measured'}): ${r.status}`);
  lines.push(r.reason);
  lines.push('');
  lines.push(`Denominators: ${r.denominators.frozenTasks} frozen task(s), ${r.denominators.pairedTasks} paired, ${r.denominators.droppedTasks} dropped, ${r.denominators.adjudicated} paired adjudicated, ${r.denominators.unadjudicated} unadjudicated.`);
  lines.push(`Replay: ${r.denominators.replay.offline ? 'offline (recorded outcomes)' : 'authorized and bounded'}, ${r.denominators.replay.paidCalls} paid call(s), $${r.denominators.replay.spentUsd}${r.denominators.replay.truncated ? ', TRUNCATED' : ''}.`);
  lines.push(`Quality: baseline ${pct(q.baseline)}, proposed ${pct(q.proposed)}, difference ${num(q.difference)}, 95% interval ${q.interval.status === 'measured' ? `[${num(q.interval.low)}, ${num(q.interval.high)}]` : `unmeasured (${q.interval.reason || q.interval.status})`}.`);
  lines.push(`Measured cost: median baseline $${num(c.medianBaselineUsd)}, proposed $${num(c.medianProposedUsd)}, reduction ${pct(c.medianReduction)}${c.complete ? '' : ' (INCOMPLETE: a cost was unknown)'}; retries ${c.retriesBaseline} vs ${c.retriesProposed}.`);
  lines.push(`Cache (baseline): ${JSON.stringify(r.comparison.cache.baseline)}; (proposed): ${JSON.stringify(r.comparison.cache.proposed)}.`);
  lines.push(`Latency ms: p50 ${num(l.baselineP50)} vs ${num(l.proposedP50)}, p95 ${num(l.baselineP95)} vs ${num(l.proposedP95)}, ratio ${num(l.p95Ratio)}${l.complete ? '' : ' (INCOMPLETE)'}.`);
  lines.push(`Failures (baseline): ${JSON.stringify(r.comparison.failures.baseline)}; (proposed): ${JSON.stringify(r.comparison.failures.proposed)}.`);
  lines.push('');
  lines.push(`Supported strata: ${r.supportedStrata.length ? r.supportedStrata.join(', ') : 'none'}.`);
  for (const u of r.unsupportedStrata) lines.push(`  unsupported: ${u.stratum} (${u.reason})`);
  lines.push('Unmet gates:');
  if (!r.unmetGates.length) lines.push('  none'); else for (const g of r.unmetGates) lines.push(`  ${g.gate}: ${JSON.stringify(g)}`);
  lines.push('Claims:');
  if (!r.claims.allowed) lines.push('  none. No routing advantage is claimed.'); else for (const s of r.claims.statements) lines.push(`  ${s}`);
  for (const n of r.notClaimed) lines.push(`  not claimed: ${n}`);
  lines.push(`Reproduce: ${r.reproduce.command} (frozen ${r.reproduce.frozenHash}, verdict ${r.reproduce.verdictHash}).`);
  return lines.join('\n');
}

/** The policy card: what the policy is, what it was tested on, what is not claimed, and how an operator controls it. */
export function buildPolicyCard({ policy, report, control, canaryLimits = null, driftPolicy = null }) {
  const card = {
    schema: POLICY_CARD_SCHEMA, schemaVersion: '1.0.0', synthetic: report.synthetic,
    policy: { version: policy.version, objective: policy.objective, minQualityLower: policy.minQualityLower, maxIntervalWidth: policy.maxIntervalWidth, maxEvidenceAgeDays: policy.maxEvidenceAgeDays, fallbackMode: policy.fallbackMode ?? 'baseline-unverified', budget: policy.budget },
    constraintOrder: ['availability', 'capability', 'privacy', 'context', 'quality', 'uncertainty', 'freshness', 'budget'],
    evidence: { gateStatus: report.status, reason: report.reason, testedStrata: report.supportedStrata, untestedOrUnsupportedStrata: report.unsupportedStrata, testedModelVersions: report.claims.modelVersions },
    claims: report.claims, notClaimed: report.notClaimed, unmetGates: report.unmetGates,
    controls: {
      modes: ROUTING_MODES.slice(), current: control ? { mode: control.mode, pin: control.pin, source: control.source } : null,
      howTo: ['AGENTIC_SECURITY_ROUTING=disabled', 'AGENTIC_SECURITY_ROUTING=pin:<model>', 'AGENTIC_SECURITY_ROUTING=adaptive', 'AGENTIC_SECURITY_NO_MODEL_ROUTING=1 (kill switch)'],
      receipts: 'every shadow decision, replay, drift assessment, canary event and rollback is in an exportable hash-linked receipt log',
    },
    safety: {
      driftTriggers: DRIFT_KINDS.slice(), onInvalidation: driftPolicy?.onInvalidation ?? 'fallback',
      canary: canaryLimits ? { maxTasks: canaryLimits.maxTasks, budgetUsd: canaryLimits.budgetUsd, maxErrorRate: canaryLimits.maxErrorRate, maxConsecutiveErrors: canaryLimits.maxConsecutiveErrors, maxIncorrectRate: canaryLimits.maxIncorrectRate } : null,
    },
    dataHandling: 'feedback keeps an allowlist of metadata; source code and evidence reach a provider only when the task policy and the egress policy both allow it',
    reproduce: report.reproduce,
  };
  card.cardHash = digestOf({ ...card, cardHash: undefined });
  return card;
}
