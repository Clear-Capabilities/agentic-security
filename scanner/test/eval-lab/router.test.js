// Policy router (PRD 6, requirements 7 and 8): per-task selection under four policies, explained, and never guessing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { routeTask, explainRoute, ROUTER_TASKS, ROUTER_POLICIES, DEFAULT_MIN_RUNS } from '../../src/posture/routing/policy-router.js';
import { ROUTER_TASK_OF } from '../../src/posture/evaluation/lab/scoreboard.js';

const entry = (model, q, cost, over = {}) => ({ model, armId: model, local: false, endpoint: `https://${model.split('/')[1]}.invalid`, routerTask: 'hunt', evalTask: 'detect', datasetHash: 'sha256:aaaa1111bbbb2222', datasetId: 'ds', quality: { mean: q, stdev: 0.01, ci95: { low: q - 0.02, high: q + 0.02 }, n: 5, representative: true, metric: 'f1' }, medianCostUsd: cost, costKnown: cost != null, medianLatencyMs: 12200, failures: 0, calls: 30, evidence: { runId: `elab-${model}`, measuredAt: '2026-10-01T00:00:00Z' }, ...over });
const sb = (...entries) => ({ entries });
const allow = () => ({ allowed: true });
const A = entry('acme/model-a', 0.92, 0.61); const B = entry('acme/model-b', 0.91, 0.17); const C = entry('acme/model-c', 0.70, 0.02); const L = entry('local/qwen', 0.80, 0, { local: true, endpoint: 'http://127.0.0.1:11434' });

test('the router task table agrees with the lab scoreboard, and threat-model has no benchmark', () => {
  for (const [t, ev] of Object.entries(ROUTER_TASKS)) if (ev) assert.equal(ROUTER_TASK_OF[t], ev, t);
  assert.equal(ROUTER_TASKS['threat-model'], null);
  assert.deepEqual([...ROUTER_POLICIES], ['best-quality', 'balanced', 'lowest-cost-above-quality-threshold', 'local-only']);
});

test('balanced: the PRD example. B is 1 point worse and 72% cheaper, so B is chosen and the explanation says exactly that', () => {
  const r = routeTask({ task: 'hunt', policy: 'balanced', scoreboard: sb(A, B, C), egress: allow });
  assert.equal(r.ok, true); assert.equal(r.recommended.model, 'acme/model-b');
  assert.ok(Math.abs(r.comparison.qualityDifference - 0.01) < 1e-9); assert.ok(Math.abs(r.comparison.costReduction - 0.7213) < 1e-3);
  const text = explainRoute(r);
  assert.match(text, /^Recommended: acme\/model-b/);
  assert.match(text, /Detection quality: 91%/); assert.match(text, /Median cost: \$0\.17/); assert.match(text, /Median latency: 12\.2s/);
  assert.match(text, /acme\/model-a:\nQuality: 92%\nCost: \$0\.61/);
  assert.match(text, /acme\/model-b selected because quality is within 2 points of the best and it is the cheapest such model: quality difference is 1 point and cost is 72% lower than acme\/model-a\./);
});

test('best-quality ignores cost; ties go to the cheaper model', () => {
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A, B, C), egress: allow }).recommended.model, 'acme/model-a');
  const tie = routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(entry('acme/x', 0.9, 0.5), entry('acme/y', 0.9, 0.1)), egress: allow });
  assert.equal(tie.recommended.model, 'acme/y');
});

test('balanced with a wider gap keeps the better model; tolerance is a parameter', () => {
  assert.equal(routeTask({ task: 'hunt', policy: 'balanced', scoreboard: sb(A, C), egress: allow }).recommended.model, 'acme/model-a');
  assert.equal(routeTask({ task: 'hunt', policy: 'balanced', scoreboard: sb(A, C), tolerance: 0.25, egress: allow }).recommended.model, 'acme/model-c');
});

test('lowest-cost-above-quality-threshold: the cheapest model that clears the bar, and the bar is required', () => {
  const r = routeTask({ task: 'hunt', policy: 'lowest-cost-above-quality-threshold', qualityThreshold: 0.85, scoreboard: sb(A, B, C), egress: allow });
  assert.equal(r.recommended.model, 'acme/model-b'); assert.match(r.rationale, /cheapest model with quality at or above 85%/);
  assert.ok(r.excluded.some((e) => e.model === 'acme/model-c' && /below the 85% threshold/.test(e.reasons.join())));
  const none = routeTask({ task: 'hunt', policy: 'lowest-cost-above-quality-threshold', qualityThreshold: 0.99, scoreboard: sb(A, B, C), egress: allow });
  assert.equal(none.ok, false); assert.equal(none.blocked, 'no-eligible-model');
  const missing = routeTask({ task: 'hunt', policy: 'lowest-cost-above-quality-threshold', scoreboard: sb(A), egress: allow });
  assert.equal(missing.blocked, 'invalid-policy');
});

test('local-only never considers a non-local model, even a far better one, and has no fallback', () => {
  const r = routeTask({ task: 'hunt', policy: 'local-only', scoreboard: sb(A, B, L), egress: () => { throw new Error('egress must not be consulted for local-only'); } });
  assert.equal(r.recommended.model, 'local/qwen'); assert.ok(r.excluded.every((e) => /not a local model/.test(e.reasons.join())));
  const none = routeTask({ task: 'hunt', policy: 'local-only', scoreboard: sb(A, B), egress: allow });
  assert.equal(none.ok, false); assert.equal(none.blocked, 'no-eligible-model');
  assert.doesNotMatch(JSON.stringify(none), /"recommended"/);
});

test('the egress policy excludes a non-local model and says why; it is never routed around', () => {
  const deny = (ctx) => (ctx.provider === 'acme' && ctx.model === 'model-a' ? { allowed: false, reason: 'provider acme is not allowed' } : { allowed: true });
  const r = routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A, B), egress: deny });
  assert.equal(r.recommended.model, 'acme/model-b');
  assert.match(r.excluded.find((e) => e.model === 'acme/model-a').reasons.join(), /egress policy: provider acme is not allowed/);
  const noEndpoint = routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(entry('acme/q', 0.9, 0.1, { endpoint: null })), egress: allow });
  assert.equal(noEndpoint.ok, false); assert.match(noEndpoint.excluded[0].reasons.join(), /no declared endpoint/);
});

test('evidence rules: too few runs, no quality, unknown cost under a cost policy, and threat-model are all refused rather than guessed', () => {
  const few = entry('acme/few', 0.99, 0.01, { quality: { mean: 0.99, n: 1, representative: false } });
  const r = routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A, few), egress: allow });
  assert.equal(r.recommended.model, 'acme/model-a');
  assert.match(r.excluded.find((e) => e.model === 'acme/few').reasons.join(), new RegExp(`only 1 measured run\\(s\\); ${DEFAULT_MIN_RUNS} are required`));
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(few), egress: allow, minRuns: 1 }).recommended.model, 'acme/few');
  const costless = routeTask({ task: 'hunt', policy: 'balanced', scoreboard: sb(entry('acme/nocost', 0.9, null)), egress: allow });
  assert.equal(costless.ok, false); assert.match(costless.excluded[0].reasons.join(), /cost is unknown/);
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(entry('acme/nocost', 0.9, null)), egress: allow }).ok, true, 'best-quality does not need cost');
  const tm = routeTask({ task: 'threat-model', policy: 'best-quality', scoreboard: sb(A), egress: allow });
  assert.equal(tm.blocked, 'no-benchmark-for-task'); assert.match(explainRoute(tm), /No recommendation \(no-benchmark-for-task\)/);
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: { entries: [] }, egress: allow }).blocked, 'no-evidence');
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: null, egress: allow }).blocked, 'no-evidence');
  assert.equal(routeTask({ task: 'nonsense', scoreboard: sb(A) }).blocked, 'unknown-task');
  assert.equal(routeTask({ task: 'hunt', policy: 'cheapest', scoreboard: sb(A) }).blocked, 'invalid-policy');
  assert.equal(routeTask({ task: 'hunt', policy: 'balanced', tolerance: 5, scoreboard: sb(A) }).blocked, 'invalid-policy');
});

test('tasks are routed independently, each from its own evidence', () => {
  const patch = entry('acme/model-c', 0.95, 0.05, { routerTask: 'patch-generation', evalTask: 'patch' });
  const board = sb(A, B, patch);
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: board, egress: allow }).recommended.model, 'acme/model-a');
  assert.equal(routeTask({ task: 'patch-generation', policy: 'best-quality', scoreboard: board, egress: allow }).recommended.model, 'acme/model-c');
  assert.equal(routeTask({ task: 'exploit-generation', policy: 'best-quality', scoreboard: board, egress: allow }).blocked, 'no-evidence');
});

test('results measured on different datasets are not compared with each other', () => {
  const other = entry('acme/other', 0.99, 0.01, { datasetHash: 'sha256:cccc3333dddd4444', datasetId: 'ds2' });
  const r = routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A, B, other), egress: allow });
  assert.equal(r.recommended.model, 'acme/model-a', 'the dataset with the most candidates is used, not the highest number');
  assert.equal(r.evidence.candidates, 2);
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A, B, other), datasetHash: 'sha256:cccc3333dddd4444', egress: allow }).recommended.model, 'acme/other');
  assert.equal(routeTask({ task: 'hunt', policy: 'best-quality', scoreboard: sb(A), datasetHash: 'sha256:nope', egress: allow }).blocked, 'no-evidence');
});
