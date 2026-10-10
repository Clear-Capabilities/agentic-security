// X-605.AC01 and X-605.AC02: shadow mode changes nothing, and a bounded paired replay compares proposed against baseline on frozen tasks.
// SYNTHETIC throughout (test/helpers/*): no model is called and no real outcome is used.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { candidateFromCatalog } from '../../src/posture/routing/decide.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { createShadowRecorder } from '../../src/posture/routing/shadow.js';
import { createReceiptLog, verifyReceiptChain } from '../../src/posture/routing/receipts.js';
import { resolveRoutingControl } from '../../src/posture/routing/control.js';
import { replayPaired, evaluatePromotion, freezeTaskSet } from '../../src/posture/routing/promotion.js';
import { syntheticPopulation, taskOf, BASE_CONFIG } from '../helpers/routing-fixtures.js';
import { pairedScenario, BASE, CAND } from '../helpers/routing-promotion-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, '..', '..', 'src', 'posture', 'routing');
const book = priceBookFromCatalog();
const LOCAL = 'http://127.0.0.1:11434';
const NOW = '2026-06-01T00:00:00Z';
const HAIKU = 'claude-haiku-4-5'; const OPUS = 'claude-opus-4-8';
const ALL_CAPS = ['code-reasoning', 'tool-use', 'code-edit'];
const POP = syntheticPopulation({ dev: 60, held: 240, models: [{ id: HAIKU, version: '1', acc: 0.9, costUsd: 0.002, latencyMs: 2000 }, { id: OPUS, version: '1', acc: 0.95, costUsd: 0.08, latencyMs: 900 }] });
const CAL = buildCalibration({ outcomes: POP.outcomes, config: { ...BASE_CONFIG, baselineModel: OPUS } }).artifact;
const POLICY = Object.freeze({ version: 'policy-1', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, objective: 'cost', budget: { remainingUsd: 1 }, expectedOutputTokens: 500 });
const cand = (id) => candidateFromCatalog({ id, provider: 'provider-a', modelVersion: '1', priceBook: book, capabilities: ALL_CAPS, maxContextTokens: 200_000, endpoint: LOCAL });
const decideArgs = (o = {}) => ({ task: taskOf(1, { requiredCapabilities: ['code-reasoning', 'tool-use'] }), candidates: [cand(HAIKU), cand(OPUS)], calibration: CAL, policy: POLICY, now: NOW, egress: () => ({ allowed: true }), allowSynthetic: true, ...o });

let realFetch; let fetchCalls = 0;
before(() => { realFetch = globalThis.fetch; globalThis.fetch = () => { fetchCalls += 1; throw new Error('shadow mode must not use the network client'); }; });
after(() => { globalThis.fetch = realFetch; });

describe('[X-605.AC01] shadow mode records proposed routes without changing production selection or issuing paid calls', () => {
  test('the production route comes back as the very object it was given, while the different proposal is recorded', () => {
    const rec = createShadowRecorder();
    const production = Object.freeze({ model: OPUS, effort: 'high' });
    const r = rec.shadow({ ...decideArgs(), productionRoute: production });
    assert.equal(r.route, production, 'identity: shadow mode hands back the production route untouched');
    assert.equal(r.shadow.proposed.model, HAIKU, 'the policy would have picked a different model');
    assert.notEqual(r.shadow.proposed.model, r.route.model, 'and that proposal did not change what production uses');
    assert.equal(r.paidCalls, 0);
    assert.equal(rec.records().length, 1);
    assert.equal(fetchCalls, 0);
  });

  test('a blocked or fallback proposal is recorded as such and production still stands', () => {
    const rec = createShadowRecorder();
    const r = rec.shadow({ ...decideArgs({ candidates: [cand(HAIKU)], egress: () => ({ allowed: false, reason: 'denied' }) }), productionRoute: { model: OPUS } });
    assert.equal(r.shadow.proposed.status, 'blocked');
    assert.equal(r.shadow.proposed.model, null);
    assert.deepEqual(r.route, { model: OPUS });
  });

  test('no paid call is possible by construction: the module has no transport, adapter or network client', () => {
    for (const f of ['shadow.js']) {
      const src = fs.readFileSync(path.join(SRC, f), 'utf8');
      assert.ok(!/createProviderAdapter|guardedModelCall|\bfetch\s*\(|node:https?|node:net|XMLHttpRequest|\.invoke\s*\(/.test(src), `${f} must not be able to call a provider`);
    }
  });

  test('decisions go to the hash-linked receipt log, and the chain verifies', () => {
    const log = createReceiptLog({ now: () => NOW });
    const rec = createShadowRecorder({ log });
    rec.shadow({ ...decideArgs(), productionRoute: { model: OPUS } });
    rec.shadow({ ...decideArgs({ task: taskOf(2, { requiredCapabilities: ['code-reasoning', 'tool-use'] }) }), productionRoute: { model: OPUS } });
    assert.equal(log.length, 2);
    assert.equal(verifyReceiptChain(log.entries()).ok, true);
  });

  test('when the operator disabled adaptive routing, nothing is decided or recorded', () => {
    const rec = createShadowRecorder({ control: resolveRoutingControl({ env: {}, options: { routing: 'disabled' } }) });
    const production = { model: OPUS };
    const r = rec.shadow({ ...decideArgs(), productionRoute: production });
    assert.equal(r.recorded, false);
    assert.equal(r.route, production);
    assert.equal(rec.records().length, 0);
  });

  test('shadow mode refuses to run without a production route to shadow', () => {
    assert.throws(() => createShadowRecorder().shadow({ ...decideArgs(), productionRoute: null }), /production route/);
  });
});

describe('[X-605.AC02] authorized bounded replay compares proposed and baseline on the same frozen tasks', () => {
  test('an offline replay pairs every frozen task from recorded outcomes with zero paid calls and reports all four differences', async () => {
    const s = pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: 0.05, latencyMs: 1300 }, failEvery: 10 });
    const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: s.outcomes });
    assert.equal(r.ok, true);
    assert.equal(r.paidCalls, 0);
    assert.equal(r.replay.offline, true);
    assert.equal(r.pairs.length, 240, 'one pair per frozen task');
    assert.deepEqual(r.pairs.map((p) => p.taskId), s.frozen.tasks.map((t) => t.taskId), 'the frozen task order and identity');
    const v = evaluatePromotion({ frozen: s.frozen, replay: r });
    assert.ok(v.overall.quality.difference !== null && v.overall.quality.interval.status === 'measured', 'quality difference with an interval');
    assert.ok(v.overall.cost.medianReduction > 0.4, 'measured cost difference');
    assert.ok(v.overall.latencyMs.p95Ratio > 1.2, 'latency difference');
    assert.equal(v.overall.failures.proposed.failed, 24, 'the proposed arm failures are reported, not dropped');
    assert.equal(v.overall.failures.baseline.failed, 0);
  });

  test('an authorized replay obtains only the missing outcomes, within its bounds', async () => {
    const s = pairedScenario({ n: 40 });
    const have = s.outcomes.filter((o) => o.model === BASE || Number(o.taskId.split('-').pop()) % 2 === 0); // the odd tasks lack a proposed outcome
    const missing = s.outcomes.filter((o) => !have.includes(o));
    const calls = [];
    const invoke = async ({ task, model }) => { calls.push(`${task.taskId}|${model}`); return missing.find((o) => o.taskId === task.taskId && o.model === model); };
    const auth = { authorizedBy: 'maintainer-1', maxCalls: 50, maxUsd: 5, perCallUsdCeiling: 0.5 };
    const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: have, authorization: auth, invoke });
    assert.equal(r.ok, true);
    assert.equal(calls.length, 20);
    assert.equal(r.paidCalls, 20);
    assert.ok(r.replay.spentUsd > 0 && r.replay.spentUsd <= auth.maxUsd);
    assert.equal(r.replay.truncated, false);
    assert.equal(r.pairs.filter((p) => p.status === 'paired').length, 40);
    assert.equal(r.replay.authorizedBy, 'maintainer-1');
  });

  test('a replay that reaches its call bound stops, leaves tasks unpaired and cannot be used for the gate', async () => {
    const s = pairedScenario({ n: 40 });
    const have = s.outcomes.filter((o) => o.model === BASE);
    const invoke = async ({ task, model }) => s.outcomes.find((o) => o.taskId === task.taskId && o.model === model);
    const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: have, authorization: { authorizedBy: 'm', maxCalls: 5, maxUsd: 50, perCallUsdCeiling: 1 }, invoke });
    assert.equal(r.paidCalls, 5, 'never beyond the bound');
    assert.equal(r.replay.truncated, true);
    assert.equal(r.pairs.filter((p) => p.status === 'dropped').length, 35);
    const v = evaluatePromotion({ frozen: s.frozen, replay: r });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'truncated-replay'));
  });

  test('the spend bound also stops a replay, and an unknown cost is charged at the ceiling, never zero', async () => {
    const s = pairedScenario({ n: 40, cand: { acc: 0.8, costUsd: null, latencyMs: 1000 } });
    const have = s.outcomes.filter((o) => o.model === BASE);
    const invoke = async ({ task, model }) => s.outcomes.find((o) => o.taskId === task.taskId && o.model === model);
    const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: have, authorization: { authorizedBy: 'm', maxCalls: 1000, maxUsd: 3, perCallUsdCeiling: 1 }, invoke });
    assert.equal(r.paidCalls, 3, 'three calls at the 1.00 ceiling exhaust a 3.00 budget');
    assert.equal(r.replay.spentUsd, 3);
    assert.equal(r.replay.truncated, true);
  });

  test('a paid replay without a complete, finite authorization is refused and calls nothing', async () => {
    const s = pairedScenario({ n: 10 });
    let called = 0;
    const invoke = async () => { called += 1; return null; };
    const base = { frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: [], invoke };
    for (const authorization of [null, {}, { authorizedBy: 'm', maxCalls: Infinity, maxUsd: 5, perCallUsdCeiling: 1 }, { authorizedBy: 'm', maxCalls: 5, maxUsd: Infinity, perCallUsdCeiling: 1 }, { authorizedBy: '', maxCalls: 5, maxUsd: 5, perCallUsdCeiling: 1 }, { authorizedBy: 'm', maxCalls: 5, maxUsd: 5 }, { authorizedBy: 'm', maxCalls: 100000, maxUsd: 5, perCallUsdCeiling: 1 }]) {
      const r = await replayPaired({ ...base, authorization });
      assert.equal(r.ok, false);
      assert.equal(r.code, 'UNBOUNDED_REPLAY');
    }
    assert.equal(called, 0);
  });

  test('a tampered frozen task set is refused', async () => {
    const s = pairedScenario({ n: 10 });
    const tampered = { ...s.frozen, tasks: s.frozen.tasks.slice(1) };
    const r = await replayPaired({ frozen: tampered, shadowRecords: s.shadowRecords, outcomes: s.outcomes });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'FROZEN_SET_EDITED');
  });

  test('a duplicate task in the freeze is refused, so one task cannot be counted twice', () => {
    const t = taskOf(1);
    assert.equal(freezeTaskSet([t, t]).ok, false);
    assert.equal(freezeTaskSet([t, taskOf(2)]).ok, true);
  });

  test('the proposed policy is the model the shadow decision chose, not a second baseline run', async () => {
    const s = pairedScenario({ n: 20, propose: (i) => (i % 2 ? CAND : BASE) });
    const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes: s.outcomes });
    assert.deepEqual([...new Set(r.pairs.map((p) => p.proposed.model))].sort(), [BASE, CAND].sort());
  });
});
