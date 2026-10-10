// X-604: constrained routing decisions. SYNTHETIC calibration (test/helpers/routing-fixtures.js); the models are the catalog's ids used as
// labels only. No model is called. Quality evidence comes from a generated population, so these tests pass `allowSynthetic: true` to
// reach the routing logic, and one test pins that without it synthetic evidence is refused.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { routeConstrained, validateRoutingPolicy, candidateFromCatalog, CONSTRAINTS, BLOCK_CODES } from '../../src/posture/routing/decide.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { buildRoutingTask } from '../../src/posture/routing/outcomes.js';
import { routeModelWithPolicy, routeModelWithTrust } from '../../src/posture/model-routing.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { syntheticPopulation, taskOf, BASE_CONFIG } from '../helpers/routing-fixtures.js';

const book = priceBookFromCatalog();
const LOCAL = 'http://127.0.0.1:11434';
const NOW = '2026-06-01T00:00:00Z';
const HAIKU = 'claude-haiku-4-5'; const SONNET = 'claude-sonnet-4-6'; const OPUS = 'claude-opus-4-8';
const ALL_CAPS = ['code-reasoning', 'tool-use', 'code-edit'];

const POP = syntheticPopulation({
  dev: 60, held: 240,
  models: [
    { id: HAIKU, version: '1', acc: 0.9, costUsd: 0.002, latencyMs: 2000 },
    { id: SONNET, version: '1', acc: 0.93, costUsd: 0.02, latencyMs: 500 },
    { id: OPUS, version: '1', acc: 0.95, costUsd: 0.08, latencyMs: 900 },
  ],
});
const calibrationOf = (outcomes = POP.outcomes, config = {}) => { const r = buildCalibration({ outcomes, config: { ...BASE_CONFIG, baselineModel: OPUS, ...config } }); assert.equal(r.ok, true); return r.artifact; };
const CAL = calibrationOf();
const POLICY = Object.freeze({ version: 'policy-1', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, objective: 'cost', budget: { remainingUsd: 1 }, expectedOutputTokens: 500 });
const cand = (id, over = {}) => ({ ...candidateFromCatalog({ id, provider: 'provider-a', modelVersion: '1', priceBook: book, capabilities: ALL_CAPS, maxContextTokens: 200_000, endpoint: LOCAL }), ...over });
const TRIO = () => [cand(HAIKU), cand(SONNET), cand(OPUS)];
const task = taskOf(1, { requiredCapabilities: ['code-reasoning', 'tool-use'] });
const allow = () => ({ allowed: true });
const run = (o = {}) => routeConstrained({ task, candidates: TRIO(), calibration: CAL, policy: POLICY, now: NOW, baselineRoute: { model: OPUS }, egress: allow, allowSynthetic: true, ...o });
const rejectionsOf = (d, model) => d.candidates.find((c) => c.model === model).rejections;

describe('[X-604.AC01] routes satisfy capability, privacy, context and minimum-quality constraints before optimizing measured cost or latency', () => {
  test('when every candidate complies the cheapest measured cost wins', () => {
    const d = run();
    assert.equal(d.status, 'routed');
    assert.equal(d.selected.model, HAIKU);
    assert.equal(d.selected.via, 'optimized');
    assert.deepEqual(d.alternatives.map((a) => a.model).sort(), [OPUS, SONNET]);
    assert.equal(d.expectedBounds.costUsd.basis, 'measured-median');
    assert.equal(d.expectedBounds.costUsd.measuredMedian, 0.002);
  });

  test('capability comes first: a cheaper model that lacks a required capability is never chosen', () => {
    const d = run({ candidates: [cand(HAIKU, { capabilities: ['code-reasoning'] }), cand(SONNET), cand(OPUS)] });
    assert.equal(d.selected.model, SONNET);
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.constraint === 'capability' && /tool-use/.test(r.detail)));
  });

  test('privacy comes first: a cheaper model the egress policy denies is never chosen', () => {
    const egress = (ctx) => (ctx.model === HAIKU ? { allowed: false, reason: 'provider not approved for source code' } : { allowed: true });
    const d = run({ egress });
    assert.equal(d.selected.model, SONNET);
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.constraint === 'privacy' && r.code === 'egress-denied'));
  });

  test('the real egress policy is the default privacy check: local-only mode denies a remote endpoint', () => {
    const prev = process.env.AGENTIC_SECURITY_EGRESS_MODE;
    process.env.AGENTIC_SECURITY_EGRESS_MODE = 'local-only';
    try {
      const d = routeConstrained({ task, candidates: [cand(HAIKU, { endpoint: 'https://api.provider-a.example/v1' }), cand(SONNET)], calibration: CAL, policy: POLICY, now: NOW, baselineRoute: { model: SONNET }, allowSynthetic: true });
      assert.equal(d.selected.model, SONNET);
      assert.ok(rejectionsOf(d, HAIKU).some((r) => r.constraint === 'privacy'));
    } finally { if (prev === undefined) delete process.env.AGENTIC_SECURITY_EGRESS_MODE; else process.env.AGENTIC_SECURITY_EGRESS_MODE = prev; }
  });

  test('a capability-manifest egress check can replace the plain policy and a candidate with no endpoint cannot be cleared', () => {
    const calls = [];
    const manifestEgress = (ctx) => { calls.push(ctx.model); return { allowed: ctx.model !== SONNET, code: 'host-not-granted' }; };
    const d = run({ manifestEgress, candidates: [cand(HAIKU, { endpoint: null }), cand(SONNET), cand(OPUS)] });
    assert.ok(calls.includes(SONNET) && calls.includes(OPUS));
    assert.equal(d.selected.model, OPUS);
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.code === 'no-endpoint'));
    assert.ok(rejectionsOf(d, SONNET).some((r) => r.constraint === 'privacy'));
  });

  test('context comes first: a model whose window cannot hold the task plus the output is never chosen, and an unknown window is rejected', () => {
    const big = taskOf(2, { contextTokens: 100_000, requiredCapabilities: ['code-reasoning'] });
    const cal = calibrationOf(syntheticPopulation({ dev: 60, held: 240, strata: [{ contextTokens: 100_000, requiredCapabilities: ['code-reasoning'] }], models: [{ id: HAIKU, acc: 0.9 }, { id: SONNET, acc: 0.93 }, { id: OPUS, acc: 0.96 }] }).outcomes);
    const d = run({ task: big, calibration: cal, candidates: [cand(HAIKU, { maxContextTokens: 50_000 }), cand(SONNET, { maxContextTokens: null }), cand(OPUS)] });
    assert.equal(d.selected.model, OPUS);
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.code === 'context-too-small'));
    assert.ok(rejectionsOf(d, SONNET).some((r) => r.code === 'context-unknown'));
  });

  test('minimum quality comes first: a cheaper model whose lower bound is under the minimum is not chosen, even though its point estimate looks fine', () => {
    const weak = calibrationOf(syntheticPopulation({ dev: 60, held: 240, models: [{ id: HAIKU, acc: 0.78, costUsd: 0.002 }, { id: SONNET, acc: 0.93, costUsd: 0.02 }, { id: OPUS, acc: 0.96, costUsd: 0.08 }] }).outcomes);
    const d = run({ calibration: weak, policy: { ...POLICY, minQualityLower: 0.85 } });
    assert.equal(d.selected.model, SONNET);
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.code === 'below-minimum-quality'));
    // and lowering the bar makes the cheaper model eligible again, so the quality rule is what excluded it
    assert.equal(run({ calibration: weak, policy: { ...POLICY, minQualityLower: 0.5 } }).selected.model, HAIKU);
  });

  test('a model with no calibration, or only for another version, has no quality evidence and is never chosen', () => {
    const d = run({ candidates: [cand('model-without-calibration', { price: null }), cand(HAIKU, { modelVersion: '2' }), cand(SONNET)] });
    assert.equal(d.selected.model, SONNET);
    assert.ok(rejectionsOf(d, 'model-without-calibration').some((r) => r.code === 'no-quality-evidence'));
    assert.ok(rejectionsOf(d, HAIKU).some((r) => r.code === 'model-version-mismatch'));
  });

  test('synthetic quality evidence is refused unless explicitly permitted', () => {
    const d = run({ allowSynthetic: false });
    assert.notEqual(d.status, 'routed');
    assert.ok(d.candidates.every((c) => c.rejections.some((r) => r.code === 'synthetic-evidence')));
  });

  test('the latency objective optimizes latency, still only among compliant candidates', () => {
    const d = run({ policy: { ...POLICY, objective: 'latency' } });
    assert.equal(d.selected.model, SONNET);
    const noTools = run({ policy: { ...POLICY, objective: 'latency' }, candidates: [cand(HAIKU), cand(SONNET, { capabilities: [] }), cand(OPUS)] });
    assert.equal(noTools.selected.model, OPUS, 'the fastest model lacked a capability; the next fastest compliant one is chosen');
  });

  test('a randomized sweep never selects a route that fails a hard constraint or the budget', () => {
    let seed = 12345; const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
    const ids = [HAIKU, SONNET, OPUS]; let selections = 0; let blocked = 0;
    for (let i = 0; i < 400; i++) {
      const allowedModels = new Set(ids.filter(() => rnd() < 0.7));
      const egress = (ctx) => ({ allowed: allowedModels.has(ctx.model) });
      const candidates = ids.map((id) => cand(id, { capabilities: ALL_CAPS.filter(() => rnd() < 0.85), maxContextTokens: rnd() < 0.2 ? 2000 : 200_000, available: rnd() < 0.9 }));
      const remaining = [0, 0.004, 0.01, 0.02, 1][Math.floor(rnd() * 5)];
      const policy = { ...POLICY, budget: { remainingUsd: remaining }, fallbackMode: rnd() < 0.5 ? 'block' : 'baseline-unverified', minQualityLower: rnd() < 0.5 ? 0.8 : 0.99 };
      const d = run({ candidates, egress, policy, baselineRoute: { model: ids[Math.floor(rnd() * 3)] } });
      if (d.status === 'blocked') { blocked += 1; assert.equal(d.selected, null); assert.ok(BLOCK_CODES.includes(d.code)); continue; }
      selections += 1;
      const c = candidates.find((x) => x.id === d.selected.model);
      assert.ok(c.available !== false, 'available');
      assert.ok(task.requiredCapabilities.every((cap) => c.capabilities.includes(cap)), 'capability');
      assert.ok(allowedModels.has(c.id), 'privacy');
      assert.ok(c.maxContextTokens >= task.contextTokens + policy.expectedOutputTokens, 'context');
      assert.ok(d.expectedBounds.costUsd.upperBound !== null && d.expectedBounds.costUsd.upperBound <= remaining, `budget ${d.expectedBounds.costUsd.upperBound} <= ${remaining}`);
      if (d.status === 'routed') assert.ok(d.expectedBounds.quality.low >= policy.minQualityLower, 'minimum quality');
      else assert.equal(d.fallback.qualityVerified, false);
    }
    assert.ok(selections > 20 && blocked > 20, `the sweep should exercise both outcomes (${selections} selected, ${blocked} blocked)`);
  });
});

describe('[X-604.AC02] each decision has an explanation, candidate alternatives, evidence freshness, expected bounds and the selected fallback', () => {
  test('a routed decision carries the full explanation', () => {
    const d = run();
    assert.equal(d.schema, 'agentic-security/routing-decision');
    assert.equal(d.policyVersion, 'policy-1');
    assert.equal(d.stratum, task.stratum);
    assert.equal(d.candidates.length, 3);
    for (const c of d.candidates) {
      assert.ok('accepted' in c && Array.isArray(c.rejections));
      assert.ok(c.quality && c.quality.low !== null && c.quality.high !== null);
      assert.ok(c.evidence && typeof c.evidence.ageDays === 'number' && c.evidence.fresh === true && c.evidence.maxAgeDays === 90);
      assert.equal(c.evidence.calibrationHash, CAL.calibrationHash);
      assert.ok(c.expectedCost && 'basis' in c.expectedCost);
    }
    assert.ok(d.expectedBounds.quality.low <= d.expectedBounds.quality.high);
    assert.ok(d.expectedBounds.costUsd.upperBound > 0);
    assert.ok(d.expectedBounds.latencyMs.p95 >= d.expectedBounds.latencyMs.p50);
    assert.equal(d.evidence.fresh, true);
    assert.deepEqual(d.fallback, { considered: false, used: false });
    assert.match(d.reason, /lowest cost/);
    assert.match(d.decisionHash, /^sha256:[0-9a-f]{64}$/);
  });

  test('every candidate shows ALL of its failing constraints, not only the first', () => {
    const egress = (ctx) => ({ allowed: ctx.model !== HAIKU });
    const d = run({ egress, candidates: [cand(HAIKU, { capabilities: [], maxContextTokens: 100 }), cand(SONNET), cand(OPUS)] });
    const constraints = new Set(rejectionsOf(d, HAIKU).map((r) => r.constraint));
    for (const c of ['capability', 'privacy', 'context']) assert.ok(constraints.has(c), c);
    for (const r of rejectionsOf(d, HAIKU)) assert.ok(CONSTRAINTS.includes(r.constraint));
  });

  test('evidence freshness is reported and old evidence is rejected', () => {
    const fresh = run({ now: '2026-05-20T00:00:00Z' });
    assert.ok(fresh.candidates[0].evidence.ageDays < 15);
    const stale = run({ now: '2027-06-01T00:00:00Z' });
    assert.ok(stale.candidates.every((c) => c.evidence.fresh === false && c.rejections.some((r) => r.code === 'stale-evidence')));
    assert.notEqual(stale.status, 'routed');
    // evidence from the future relative to `now` is not fresh either
    assert.notEqual(run({ now: '2026-01-01T00:00:00Z' }).status, 'routed');
  });

  test('a fallback decision names the fallback, says its quality is unverified, and lists the alternatives that were rejected', () => {
    const d = run({ policy: { ...POLICY, minQualityLower: 0.999 } });
    assert.equal(d.status, 'fallback');
    assert.equal(d.selected.model, OPUS);
    assert.equal(d.selected.via, 'fallback');
    assert.equal(d.fallback.used, true); assert.equal(d.fallback.qualityVerified, false); assert.equal(d.fallback.model, OPUS);
    assert.equal(d.code, 'insufficient-quality-evidence');
    assert.match(d.reason, /UNVERIFIED/);
    assert.equal(d.candidates.length, 3);
    assert.equal(d.expectedBounds.quality, null, 'no quality bound is claimed for an unverified fallback');
  });

  test('the same inputs give the same decision hash; a different policy version gives a different one', () => {
    assert.equal(run().decisionHash, run().decisionHash);
    assert.notEqual(run().decisionHash, run({ policy: { ...POLICY, version: 'policy-2' } }).decisionHash);
    assert.notEqual(run().decisionHash, run({ now: '2026-06-02T00:00:00Z' }).decisionHash);
  });

  test('a decision is deep-frozen data: a caller cannot rewrite the explanation after the fact', () => {
    const d = run();
    assert.throws(() => { d.selected = null; });
    assert.throws(() => { d.status = 'blocked'; });
  });
});

describe('[X-604.AC03] budget exhaustion, no compliant model or excessive uncertainty give a bounded fallback or a blocked outcome, never a bypass', () => {
  test('no budget left blocks the task: the fallback does not get to spend money that is not there', () => {
    for (const remainingUsd of [0, -1, 0.0000001]) {
      const d = run({ policy: { ...POLICY, budget: { remainingUsd } } });
      assert.equal(d.status, 'blocked', String(remainingUsd));
      assert.equal(d.code, 'budget-exhausted');
      assert.equal(d.selected, null);
    }
  });

  test('a per-task cap is a constraint too', () => {
    const d = run({ policy: { ...POLICY, budget: { remainingUsd: 10, maxUsdPerTask: 0.001 } } });
    assert.equal(d.status, 'blocked'); assert.equal(d.code, 'budget-exhausted');
    assert.ok(d.candidates.every((c) => c.rejections.some((r) => r.code === 'over-task-cap')));
  });

  test('a budget that only covers the cheap model, whose quality is not enough, blocks rather than overspending on the baseline', () => {
    const weak = calibrationOf(syntheticPopulation({ dev: 60, held: 240, models: [{ id: HAIKU, acc: 0.6, costUsd: 0.002 }, { id: SONNET, acc: 0.93, costUsd: 0.02 }, { id: OPUS, acc: 0.96, costUsd: 0.08 }] }).outcomes);
    const d = run({ calibration: weak, policy: { ...POLICY, budget: { remainingUsd: 0.007 } } });
    assert.equal(d.status, 'blocked');
    assert.equal(d.selected, null);
    assert.ok(rejectionsOf(d, OPUS).some((r) => r.constraint === 'budget'));
  });

  test('no model that satisfies capability, privacy and context is a block, and the baseline fallback does not override it', () => {
    for (const mutate of [
      { candidates: [cand(HAIKU, { capabilities: [] }), cand(SONNET, { capabilities: [] }), cand(OPUS, { capabilities: [] })] },
      { egress: () => ({ allowed: false }) },
      { candidates: [cand(HAIKU, { available: false }), cand(SONNET, { available: false }), cand(OPUS, { available: false })] },
      { candidates: [] },
    ]) {
      const d = run({ ...mutate, baselineRoute: { model: OPUS } });
      assert.equal(d.status, 'blocked');
      assert.equal(d.code, 'no-compliant-model');
      assert.equal(d.selected, null);
    }
  });

  test('excessive uncertainty falls back to the baseline when the baseline passes the hard constraints, and is blocked when policy forbids a fallback', () => {
    const wide = { ...POLICY, maxIntervalWidth: 0.001 };
    const fb = run({ policy: wide });
    assert.equal(fb.status, 'fallback'); assert.equal(fb.code, 'excessive-uncertainty'); assert.equal(fb.selected.model, OPUS);
    const blocked = run({ policy: { ...wide, fallbackMode: 'block' } });
    assert.equal(blocked.status, 'blocked'); assert.equal(blocked.code, 'excessive-uncertainty'); assert.equal(blocked.selected, null);
  });

  test('stale evidence and missing evidence use the same bounded path', () => {
    const stale = run({ now: '2027-06-01T00:00:00Z' });
    assert.equal(stale.status, 'fallback'); assert.equal(stale.code, 'stale-evidence');
    const none = run({ calibration: null });
    assert.equal(none.status, 'fallback'); assert.equal(none.code, 'insufficient-quality-evidence');
    assert.equal(run({ calibration: null, policy: { ...POLICY, fallbackMode: 'block' } }).status, 'blocked');
  });

  test('the fallback must itself satisfy the hard constraints: an unusable baseline is a block', () => {
    const egress = (ctx) => ({ allowed: ctx.model !== OPUS });
    const d = run({ calibration: null, egress, baselineRoute: { model: OPUS } });
    assert.equal(d.status, 'blocked'); assert.equal(d.selected, null);
    const capless = run({ calibration: null, candidates: [cand(HAIKU), cand(SONNET), cand(OPUS, { capabilities: [] })], baselineRoute: { model: OPUS } });
    assert.equal(capless.status, 'blocked');
    const absent = run({ calibration: null, baselineRoute: { model: 'not-a-candidate' } });
    assert.equal(absent.status, 'blocked');
    const noBaseline = run({ calibration: null, baselineRoute: null });
    assert.equal(noBaseline.status, 'blocked');
  });

  test('an unknown cost is never treated as free', () => {
    const d = run({ candidates: [cand('priceless-model', { price: null })], calibration: null });
    assert.ok(d.candidates[0].rejections.some((r) => r.code === 'cost-unknown'));
    assert.equal(d.status, 'blocked');
  });

  test('an invalid policy or task blocks with a typed code and selects nothing', () => {
    for (const bad of [{ ...POLICY, version: '' }, { ...POLICY, minQualityLower: 2 }, { ...POLICY, maxIntervalWidth: 0 }, { ...POLICY, objective: 'vibes' }, { ...POLICY, budget: {} }, { ...POLICY, expectedOutputTokens: -1 }, null]) {
      const d = run({ policy: bad });
      assert.equal(d.status, 'blocked'); assert.equal(d.code, 'invalid-policy'); assert.equal(d.selected, null);
    }
    assert.equal(validateRoutingPolicy(POLICY).ok, true);
    const noTask = run({ task: null });
    assert.equal(noTask.code, 'invalid-task');
    assert.equal(run({ now: 'yesterday' }).code, 'invalid-task');
  });
});

describe('[X-604.AC01] rollout: the existing router is unchanged unless the model-routing feature is on', () => {
  const finding = { severity: 'high', cwe: 'CWE-79', file: 'src/a.js', stableId: 'f-1' };
  const off = resolveAssuranceConfig({ env: {}, platform: 'linux' });
  const on = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1' }, platform: 'linux' });
  const ctxOn = (o = {}) => ({ config: on, candidates: TRIO(), calibration: CAL, policy: POLICY, now: NOW, egress: allow, allowSynthetic: true, requiredCapabilities: ['code-reasoning'], language: 'javascript', ...o });

  test('with the feature off, or no configuration, the result is exactly the pre-existing route', () => {
    const expected = routeModelWithTrust(finding, null);
    assert.deepEqual(routeModelWithPolicy(finding, {}), expected);
    assert.deepEqual(routeModelWithPolicy(finding, { config: off, candidates: TRIO(), calibration: CAL, policy: POLICY, now: NOW }), expected);
    assert.equal('decision' in routeModelWithPolicy(finding, { config: off }), false);
    const killed = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1', AGENTIC_SECURITY_NO_MODEL_ROUTING: '1' }, platform: 'linux' });
    assert.deepEqual(routeModelWithPolicy(finding, { config: killed, candidates: TRIO() }), expected);
  });

  test('with the feature on, the route comes from the constrained decision and carries its explanation', () => {
    const t = buildRoutingTask({ taskId: 'f-1', taskKind: 'repair', language: 'javascript', vulnClass: 'CWE-79', contextTokens: 3000, requiredCapabilities: ['code-reasoning'], synthetic: true });
    assert.equal(t.ok, true);
    const cal = calibrationOf(syntheticPopulation({ dev: 60, held: 240, strata: [{ vulnClass: 'CWE-79', requiredCapabilities: ['code-reasoning'] }], models: [{ id: HAIKU, acc: 0.9, costUsd: 0.002 }, { id: SONNET, acc: 0.93, costUsd: 0.02 }, { id: OPUS, acc: 0.96, costUsd: 0.08 }] }).outcomes);
    const r = routeModelWithPolicy(finding, ctxOn({ calibration: cal, contextTokens: 3000, synthetic: true }));
    assert.equal(r.model, HAIKU);
    assert.equal(r.decision.status, 'routed');
    assert.equal(r.baseline.model, routeModelWithTrust(finding, null).model);
  });

  test('with the feature on and nothing compliant, model is null and blocked is true, never a quiet default', () => {
    const r = routeModelWithPolicy(finding, ctxOn({ candidates: [] }));
    assert.equal(r.model, null); assert.equal(r.blocked, true);
    assert.equal(r.decision.code, 'no-compliant-model');
    const bad = routeModelWithPolicy(finding, ctxOn({ contextTokens: -5 }));
    assert.equal(bad.model, null); assert.equal(bad.blocked, true);
  });
});
