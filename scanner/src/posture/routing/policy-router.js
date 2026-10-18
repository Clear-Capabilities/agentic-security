// Per-task model routing from MEASURED results (PRD 6, requirements 7 and 8).
//
// The router reads the scoreboard the Eval Lab writes and picks a model for each task independently, under one of four policies:
//
//   best-quality                          the highest measured quality
//   balanced                              the cheapest model whose quality is within `tolerance` of the best
//   lowest-cost-above-quality-threshold   the cheapest model whose quality meets `qualityThreshold`
//   local-only                            the best-quality LOCAL model; a non-local model is never a candidate
//
// What it will not do:
//   * guess. A model with fewer than `minRuns` measured runs, or with unknown cost under a cost-based policy, is excluded with
//     the reason stated, and when nothing is eligible the answer is `blocked`, not a default;
//   * invent a benchmark. `threat-model` has no evaluation task, so routing it is blocked as `no-benchmark-for-task`;
//   * route around the egress policy. A non-local candidate is checked against it, and a denial excludes the model;
//   * fall back from a local model to a cloud one. `local-only` has no non-local path at all.
// This is the policy layer over measurements. The calibrated, per-stratum router in `decide.js` keeps its own job (quality LOWER
// bounds on held-out outcomes); the two do not call each other.
import { evaluateEgress } from '../../egress/policy.js';

export const ROUTER_TASKS = Object.freeze({ 'threat-model': null, hunt: 'detect', falsification: 'falsify', 'exploit-generation': 'exploit', 'patch-generation': 'patch' });
export const ROUTER_POLICIES = Object.freeze(['best-quality', 'balanced', 'lowest-cost-above-quality-threshold', 'local-only']);
const DEFAULT_TOLERANCE = 0.02;
export const DEFAULT_MIN_RUNS = 3;
const QUALITY_LABEL = { hunt: 'Detection quality', falsification: 'Falsification quality', 'exploit-generation': 'Exploit quality', 'patch-generation': 'Patch quality' };

const cmpCost = (a, b) => (a.medianCostUsd == null ? 1 : b.medianCostUsd == null ? -1 : a.medianCostUsd - b.medianCostUsd);

export function routeTask({ task, policy = 'balanced', scoreboard, tolerance = DEFAULT_TOLERANCE, qualityThreshold = null, minRuns = DEFAULT_MIN_RUNS, datasetHash = null, scanRoot, egress = evaluateEgress } = {}) {
  const base = { schema: 'agentic-security/model-route', version: 1, task, policy };
  if (!(task in ROUTER_TASKS)) return { ...base, ok: false, blocked: 'unknown-task', reason: `unknown task "${task}"; choose one of ${Object.keys(ROUTER_TASKS).join(', ')}` };
  if (!ROUTER_POLICIES.includes(policy)) return { ...base, ok: false, blocked: 'invalid-policy', reason: `unknown policy "${policy}"; choose one of ${ROUTER_POLICIES.join(', ')}` };
  if (ROUTER_TASKS[task] === null) return { ...base, ok: false, blocked: 'no-benchmark-for-task', reason: `there is no evaluation task for ${task}, so no model has measured quality for it and none is recommended` };
  if (policy === 'lowest-cost-above-quality-threshold' && !(typeof qualityThreshold === 'number' && qualityThreshold > 0 && qualityThreshold <= 1)) return { ...base, ok: false, blocked: 'invalid-policy', reason: 'lowest-cost-above-quality-threshold needs a quality threshold between 0 and 1' };
  if (!(typeof tolerance === 'number' && tolerance >= 0 && tolerance < 1)) return { ...base, ok: false, blocked: 'invalid-policy', reason: 'tolerance must be between 0 and 1' };

  const all = (scoreboard?.entries ?? []).filter((e) => e.routerTask === task);
  if (!all.length) return { ...base, ok: false, blocked: 'no-evidence', reason: `no model has been benchmarked for ${task}; run: agentic-security models benchmark` };

  // entries measured on different datasets are not comparable: use one dataset, the one with the most candidates unless named
  const byDs = new Map();
  for (const e of all) { const g = byDs.get(e.datasetHash) ?? []; g.push(e); byDs.set(e.datasetHash, g); }
  let ds = datasetHash;
  if (ds && !byDs.has(ds)) return { ...base, ok: false, blocked: 'no-evidence', reason: `no benchmark for ${task} on dataset ${ds}` };
  if (!ds) ds = [...byDs.entries()].sort((a, b) => b[1].length - a[1].length || String(b[1][0].evidence?.measuredAt).localeCompare(String(a[1][0].evidence?.measuredAt)))[0][0];
  const pool = byDs.get(ds);

  const excluded = []; const eligible = [];
  for (const e of pool) {
    const why = [];
    if (e.quality.mean == null) why.push('no measured quality');
    if ((e.quality.n ?? 0) < minRuns) why.push(`only ${e.quality.n ?? 0} measured run(s); ${minRuns} are required`);
    if (policy === 'local-only' && e.local !== true) why.push('not a local model');
    if (e.local !== true && policy !== 'local-only') {
      if (!e.endpoint) why.push('no declared endpoint, so the egress policy cannot judge it');
      else { const d = egress({ scanRoot, purpose: 'model-routing', endpoint: e.endpoint, model: e.model.split('/').slice(1).join('/'), provider: e.model.split('/')[0], role: `route-${task}`, dataClass: 'source-code' }); if (!d.allowed) why.push(`egress policy: ${d.reason}`); }
    }
    if (['balanced', 'lowest-cost-above-quality-threshold'].includes(policy) && e.medianCostUsd == null && !e.local) why.push('cost is unknown, and this policy ranks by cost');
    if (policy === 'lowest-cost-above-quality-threshold' && e.quality.mean != null && e.quality.mean < qualityThreshold) why.push(`quality ${(e.quality.mean * 100).toFixed(0)}% is below the ${(qualityThreshold * 100).toFixed(0)}% threshold`);
    (why.length ? excluded.push({ model: e.model, reasons: why }) : eligible.push(e));
  }
  const evidence = { datasetHash: ds, datasetId: pool[0].datasetId, candidates: pool.length, runs: [...new Set(pool.map((e) => e.evidence?.runId))].filter(Boolean) };
  if (!eligible.length) return { ...base, ok: false, blocked: 'no-eligible-model', reason: 'no benchmarked model satisfies the policy and the evidence requirements', excluded, evidence };

  const byQuality = [...eligible].sort((a, b) => b.quality.mean - a.quality.mean || cmpCost(a, b) || a.model.localeCompare(b.model));
  const best = byQuality[0];
  let chosen = best; let rule;
  if (policy === 'best-quality' || policy === 'local-only') rule = policy === 'local-only' ? 'it has the highest measured quality among local models' : 'it has the highest measured quality';
  else if (policy === 'balanced') {
    const within = eligible.filter((e) => e.quality.mean >= best.quality.mean - tolerance);
    chosen = [...within].sort((a, b) => cmpCost(a, b) || b.quality.mean - a.quality.mean || a.model.localeCompare(b.model))[0];
    rule = chosen === best ? `no cheaper model is within ${(tolerance * 100).toFixed(0)} points of its quality` : `quality is within ${(tolerance * 100).toFixed(0)} points of the best and it is the cheapest such model`;
  } else {
    chosen = [...eligible].sort((a, b) => cmpCost(a, b) || b.quality.mean - a.quality.mean || a.model.localeCompare(b.model))[0];
    rule = `it is the cheapest model with quality at or above ${(qualityThreshold * 100).toFixed(0)}%`;
  }
  const view = (e) => ({ model: e.model, local: e.local, quality: e.quality.mean, qualityCi95: e.quality.ci95, runs: e.quality.n, medianCostUsd: e.medianCostUsd, medianLatencyMs: e.medianLatencyMs });
  const costReduction = chosen !== best && best.medianCostUsd != null && chosen.medianCostUsd != null && best.medianCostUsd > 0 ? 1 - chosen.medianCostUsd / best.medianCostUsd : null;
  return {
    ...base, ok: true, recommended: view(chosen), alternatives: byQuality.filter((e) => e !== chosen).map(view), excluded, evidence,
    comparison: chosen === best ? null : { against: best.model, qualityDifference: best.quality.mean - chosen.quality.mean, costReduction },
    rationale: rule, label: QUALITY_LABEL[task], parameters: { tolerance, qualityThreshold, minRuns },
  };
}

/** The text `models route explain <task>` prints. */
export function explainRoute(r) {
  if (!r.ok) return [`Task: ${r.task}`, `Policy: ${r.policy}`, `No recommendation (${r.blocked}): ${r.reason}`, ...(r.excluded?.length ? ['', 'Excluded:', ...r.excluded.map((e) => `  ${e.model}: ${e.reasons.join('; ')}`)] : [])].join('\n');
  const pc = (x) => (x == null ? 'n/a' : `${(x * 100).toFixed(0)}%`);
  const usd = (x) => (x == null ? 'unknown' : x === 0 ? '$0.00' : x < 0.01 ? `$${x.toFixed(4)}` : `$${x.toFixed(2)}`);
  const sec = (x) => (x == null ? 'unknown' : `${(x / 1000).toFixed(1)}s`);
  const rec = r.recommended;
  const L = [`Recommended: ${rec.model}${rec.local ? ' (local)' : ''}`, `${r.label}: ${pc(rec.quality)}`, `Median cost: ${usd(rec.medianCostUsd)}`, `Median latency: ${sec(rec.medianLatencyMs)}`, `Measured runs: ${rec.runs}`];
  for (const a of r.alternatives) L.push('', `${a.model}${a.local ? ' (local)' : ''}:`, `Quality: ${pc(a.quality)}`, `Cost: ${usd(a.medianCostUsd)}`);
  L.push('');
  if (!r.comparison) L.push(`${rec.model} selected because ${r.rationale}.`);
  else {
    const qd = (r.comparison.qualityDifference * 100).toFixed(0);
    L.push(`${rec.model} selected because ${r.rationale}${r.comparison.costReduction != null ? `: quality difference is ${qd} point${qd === '1' ? '' : 's'} and cost is ${(r.comparison.costReduction * 100).toFixed(0)}% lower than ${r.comparison.against}` : ''}.`);
  }
  if (r.excluded.length) L.push('', 'Not considered:', ...r.excluded.map((e) => `  ${e.model}: ${e.reasons.join('; ')}`));
  L.push('', `Evidence: dataset ${r.evidence.datasetId} (${String(r.evidence.datasetHash).slice(-12)}), ${r.evidence.runs.length} run record(s).`);
  return L.join('\n');
}
