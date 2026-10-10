// X-608: the routing replay report, the policy card, the operator controls and the offline reproduction. GENERATED populations only
// (test/helpers/routing-promotion-fixtures.js); `synthetic: false` reaches the branches of a gate that refuses synthetic data and is not
// a measurement of any model.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { replayPaired, evaluatePromotion, freezeTaskSet } from '../../src/posture/routing/promotion.js';
import { buildRoutingReplayReport, renderRoutingReport, buildPolicyCard } from '../../src/posture/routing/report.js';
import { createReceiptLog, exportReceipts, verifyReceiptChain } from '../../src/posture/routing/receipts.js';
import { resolveRoutingControl, ROUTING_ENV } from '../../src/posture/routing/control.js';
import { routeModelWithPolicy, routeModelWithTrust } from '../../src/posture/model-routing.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { pairedScenario, BASE, CAND } from '../helpers/routing-promotion-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'routing-replay.mjs');
const CLOCK = () => '2026-06-01T00:00:00Z';

async function run(s, { outcomes = s.outcomes, log = null, frozen = s.frozen } = {}) {
  const replay = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes, log });
  const verdict = evaluatePromotion({ frozen, replay, log });
  const receipts = log ? exportReceipts(log) : null;
  return { replay, verdict, report: buildRoutingReplayReport({ frozen, replay, verdict, receipts }) };
}
const POLICY = { version: 'policy-1', objective: 'cost', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, budget: { remainingUsd: 1 } };

describe('[X-608.AC01] the report compares baseline and proposed with exact denominators, uncertainty, measured cost, cache conditions and latency percentiles', () => {
  test('every figure a reader needs is present, and the denominators are exact', async () => {
    const s = pairedScenario({ n: 240, failEvery: 10 });
    const { report: r } = await run(s);
    assert.deepEqual({ frozen: r.denominators.frozenTasks, paired: r.denominators.pairedTasks, dropped: r.denominators.droppedTasks, adjudicated: r.denominators.adjudicated, unadjudicated: r.denominators.unadjudicated }, { frozen: 240, paired: 240, dropped: 0, adjudicated: 240, unadjudicated: 0 });
    assert.equal(r.denominators.replay.paidCalls, 0);
    assert.equal(r.denominators.replay.offline, true);
    const c = r.comparison;
    assert.equal(c.quality.interval.status, 'measured');
    assert.ok(c.quality.interval.low !== null && c.quality.interval.high !== null, 'uncertainty on the quality difference');
    assert.ok(c.cost.medianBaselineUsd > 0 && c.cost.medianProposedUsd > 0 && c.cost.totalBaselineUsd > c.cost.totalProposedUsd, 'measured median and total cost');
    assert.deepEqual(Object.keys(c.cache.baseline).sort(), ['hit', 'ineligible', 'miss', 'partial', 'unknown'], 'cache conditions are stated');
    assert.equal(c.cache.baseline.unknown, 240, 'unknown cache state is reported as unknown, not as a miss');
    for (const k of ['baselineP50', 'baselineP95', 'proposedP50', 'proposedP95', 'p95Ratio']) assert.equal(typeof c.latencyMs[k], 'number', k);
    assert.equal(c.failures.proposed.failed, 24);
    assert.equal(c.failures.baseline.correct + c.failures.baseline.incorrect, 240, 'the failure table sums to the paired denominator');
  });

  test('denominators stay exact when tasks are dropped, and the report says so instead of shrinking the population', async () => {
    const s = pairedScenario({ n: 240 });
    const missing = new Set(s.outcomes.filter((o) => o.model === CAND).slice(0, 7).map((o) => o.id));
    const { report: r } = await run(s, { outcomes: s.outcomes.filter((o) => !missing.has(o.id)) });
    assert.equal(r.denominators.frozenTasks, 240);
    assert.equal(r.denominators.droppedTasks, 7);
    assert.equal(r.denominators.pairedTasks, 233);
    assert.equal(r.status, 'invalid');
    assert.ok(r.unmetGates.some((g) => g.gate === 'invalidation' && g.code === 'dropped-tasks'));
  });

  test('an unmeasured interval or an incomplete cost is shown as such, never as a number', async () => {
    const s = pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: null, latencyMs: 1000 } });
    const { report: r } = await run(s);
    assert.equal(r.comparison.cost.complete, false);
    assert.equal(r.comparison.cost.medianProposedUsd, null);
    assert.match(renderRoutingReport(r), /INCOMPLETE/);
    const few = await run(pairedScenario({ n: 5 }));
    assert.equal(few.report.comparison.quality.interval.status, 'unmeasured');
    assert.match(renderRoutingReport(few.report), /unmeasured/);
  });

  test('the report is reproducible byte for byte and its hash covers its content', async () => {
    const s = pairedScenario({ n: 240 });
    const a = await run(s); const b = await run(s);
    assert.equal(a.report.reportHash, b.report.reportHash);
    assert.deepEqual(a.report, b.report);
    const changed = buildRoutingReplayReport({ frozen: s.frozen, replay: a.replay, verdict: a.verdict, generatedAt: '2026-06-01T00:00:00Z' });
    assert.notEqual(changed.reportHash, a.report.reportHash);
  });

  test('the rendered text carries the same figures and contains no em-dash', async () => {
    const { report: r } = await run(pairedScenario({ n: 240 }));
    const text = renderRoutingReport(r);
    assert.match(text, /240 frozen task/);
    assert.match(text, /Measured cost/);
    assert.match(text, /p95/);
    assert.ok(!text.includes(String.fromCharCode(0x2014)));
  });
});

describe('[X-608.AC02] claims are restricted to tested strata and provider versions; unsupported strata and unmet gates stay visible', () => {
  test('a passing gate yields claims for the promoted strata and the tested model versions only', async () => {
    const { report: r } = await run(pairedScenario({ n: 240, versionOf: (m) => (m === CAND ? '7' : '3') }));
    assert.equal(r.status, 'pass');
    assert.equal(r.claims.allowed, true);
    assert.deepEqual(r.claims.scope, r.supportedStrata);
    assert.deepEqual(r.claims.modelVersions, [`${BASE}@3`, `${CAND}@7`]);
    assert.ok(r.claims.statements.every((t) => /model versions model-base@3, model-cand@7/.test(t)));
    assert.ok(r.notClaimed.some((n) => /model version other than those tested/.test(n)));
    assert.deepEqual(r.unmetGates, []);
  });

  test('an under-sampled stratum is listed as unsupported with its reason and gets no claim', async () => {
    const s = pairedScenario({ n: 240 });
    const keepPy = new Set(s.tasks.filter((t) => t.language === 'python').slice(0, 20).map((t) => t.taskId));
    const tasks = s.tasks.map((t) => (t.language === 'python' && !keepPy.has(t.taskId) ? { ...t, stratum: t.stratum.replace('python', 'javascript') } : t));
    const f = freezeTaskSet(tasks).frozen;
    const records = s.shadowRecords.map((x) => ({ ...x, stratum: tasks.find((t) => t.taskId === x.taskId).stratum }));
    const replay = await replayPaired({ frozen: f, shadowRecords: records, outcomes: s.outcomes });
    const verdict = evaluatePromotion({ frozen: f, replay });
    const r = buildRoutingReplayReport({ frozen: f, replay, verdict });
    assert.deepEqual(r.supportedStrata, ['repair|javascript|CWE-89|xs']);
    const py = r.unsupportedStrata.find((u) => u.stratum === 'repair|python|CWE-89|xs');
    assert.match(py.reason, /20 paired adjudicated task\(s\); 30 are required/);
    assert.ok(!r.claims.statements.some((t) => /python/.test(t)));
  });

  test('an unmet cost or quality gate is listed and no claim is made', async () => {
    const { report: r } = await run(pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: 0.095, latencyMs: 1000 } }));
    assert.equal(r.status, 'fail');
    assert.equal(r.claims.allowed, false);
    assert.deepEqual(r.claims.statements, []);
    assert.ok(r.unmetGates.some((g) => g.gate === 'cost-or-quality-advantage'));
    assert.ok(r.unmetGates.some((g) => g.gate === 'routing-promotion' && g.status === 'fail'));
    assert.deepEqual(r.supportedStrata, [], 'no stratum is called supported while the gate fails');
    assert.match(renderRoutingReport(r), /No routing advantage is claimed/);
  });

  test('a synthetic population claims nothing, even for strata whose own arithmetic meets the criteria', async () => {
    const { report: r } = await run(pairedScenario({ n: 240, synthetic: true }));
    assert.equal(r.status, 'unmeasured');
    assert.equal(r.synthetic, true);
    assert.equal(r.claims.allowed, false);
    assert.deepEqual(r.supportedStrata, []);
    assert.ok(r.unsupportedStrata.some((u) => /criteria met on this sample, but the gate reads 'unmeasured'/.test(u.reason)));
    assert.match(r.disclosure, /SYNTHETIC/);
  });

  test('the policy card repeats the restriction: tested and unsupported strata, no claim without a pass, and the safety limits', async () => {
    const pass = await run(pairedScenario({ n: 240 }));
    const card = buildPolicyCard({ policy: POLICY, report: pass.report, control: resolveRoutingControl({ env: {}, options: {} }), canaryLimits: { maxTasks: 50, budgetUsd: 1, maxErrorRate: 0.2, maxConsecutiveErrors: 4, maxIncorrectRate: 0.3 }, driftPolicy: { onInvalidation: 'shadow' } });
    assert.deepEqual(card.evidence.testedStrata, pass.report.supportedStrata);
    assert.equal(card.claims.allowed, true);
    assert.deepEqual(card.safety.driftTriggers.slice().sort(), ['model-version', 'pricing', 'quality-shift', 'schema']);
    assert.equal(card.safety.onInvalidation, 'shadow');
    assert.equal(card.safety.canary.maxTasks, 50);
    const synth = await run(pairedScenario({ n: 240, synthetic: true }));
    const card2 = buildPolicyCard({ policy: POLICY, report: synth.report, control: null });
    assert.equal(card2.claims.allowed, false);
    assert.deepEqual(card2.evidence.testedStrata, []);
    assert.notEqual(card.cardHash, card2.cardHash);
  });
});

describe('[X-608.AC03] users can pin or disable adaptive routing, export decision receipts, and reproduce the evaluation offline', () => {
  const finding = { severity: 'high', cwe: 'CWE-79', file: 'src/a.js', stableId: 'f-1' };
  const on = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1' }, platform: 'linux' });
  const off = resolveAssuranceConfig({ env: {}, platform: 'linux' });

  test('the control resolves by precedence: option, then environment, then default; a bad value fails closed to disabled', () => {
    assert.equal(resolveRoutingControl({ env: {}, options: {} }).mode, 'adaptive');
    assert.equal(resolveRoutingControl({ env: { [ROUTING_ENV]: 'disabled' }, options: {} }).mode, 'disabled');
    assert.equal(resolveRoutingControl({ env: { [ROUTING_ENV]: 'disabled' }, options: { routing: 'adaptive' } }).mode, 'adaptive', 'an explicit option beats the environment');
    const pin = resolveRoutingControl({ env: {}, options: { routing: 'pin:some-model-1' } });
    assert.deepEqual({ mode: pin.mode, pin: pin.pin }, { mode: 'pinned', pin: 'some-model-1' });
    for (const bad of ['pin:', 'pin:has space', 'pin:../x', 'turbo', 'pin:' + 'a'.repeat(200)]) {
      const c = resolveRoutingControl({ env: {}, options: { routing: bad } });
      assert.equal(c.mode, 'disabled', bad);
      assert.ok(c.error);
    }
  });

  test('routeModelWithPolicy honours disabled: the existing capability route, no decision, the control named', () => {
    const plain = routeModelWithTrust(finding, null);
    const r = routeModelWithPolicy(finding, { config: on, routingOptions: { routing: 'disabled' }, candidates: [] });
    assert.equal(r.model, plain.model);
    assert.equal('decision' in r, false);
    assert.equal(r.routingControl.mode, 'disabled');
    const viaEnv = routeModelWithPolicy(finding, { config: on, env: { [ROUTING_ENV]: 'disabled' } });
    assert.equal(viaEnv.model, plain.model);
    assert.equal(viaEnv.routingControl.source, 'environment');
  });

  test('routeModelWithPolicy honours a pin: that model, no optimisation, marked pinned, with the baseline kept for comparison', () => {
    const r = routeModelWithPolicy(finding, { config: on, routingOptions: { routing: 'pin:my-pinned-model' } });
    assert.equal(r.model, 'my-pinned-model');
    assert.equal(r.pinned, true);
    assert.equal(r.baseline.model, routeModelWithTrust(finding, null).model);
    assert.equal('decision' in r, false);
  });

  test('adaptive stays adaptive, and with the feature off the control changes nothing', () => {
    const adaptive = routeModelWithPolicy(finding, { config: on, routingOptions: { routing: 'adaptive' }, candidates: [] });
    assert.ok(adaptive.decision, 'adaptive routing still makes a constrained decision');
    const plain = routeModelWithTrust(finding, null);
    assert.deepEqual(routeModelWithPolicy(finding, { config: off, routingOptions: { routing: 'pin:x' } }), plain, 'feature off: exactly the pre-existing route');
  });

  test('decision receipts export as a portable chain that verifies offline, and tampering is detected', async () => {
    const log = createReceiptLog({ now: CLOCK });
    await run(pairedScenario({ n: 240 }), { log });
    const exported = exportReceipts(log);
    assert.equal(exported.count, 2);
    assert.deepEqual(exported.receipts.map((r) => r.kind), ['replay', 'promotion']);
    const roundTripped = JSON.parse(JSON.stringify(exported));
    assert.equal(verifyReceiptChain(roundTripped.receipts).ok, true);
    assert.equal(roundTripped.headHash, log.head());
    roundTripped.receipts[1].body.status = 'pass-edited';
    assert.equal(verifyReceiptChain(roundTripped.receipts).ok, false);
    assert.match(exported.disclosure, /not a signature/);
  });

  test('the offline reproduction runs without a network, exits 0, and every control behaves', () => {
    const r = spawnSync(process.execPath, [SCRIPT, '--json'], { encoding: 'utf8', timeout: 120_000, env: { ...process.env, AGENTIC_SECURITY_EGRESS_DENY: '1' } });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.allControlsBehaved, true);
    assert.equal(out.status, 'unmeasured');
    assert.equal(out.claimsAllowed, false);
    assert.deepEqual(out.controls.map((c) => c.name), ['synthetic-never-passes', 'gate-discriminates', 'cherry-pick', 'dropped-failures', 'unbounded-replay', 'reproducible', 'control-honoured']);
    const again = spawnSync(process.execPath, [SCRIPT, '--json'], { encoding: 'utf8', timeout: 120_000 });
    assert.equal(JSON.parse(again.stdout).reportHash, out.reportHash, 'a second run reproduces the report hash');
  });

  test('breaking each control on purpose makes the script exit 1 and name that control', () => {
    for (const fault of ['synthetic-never-passes', 'gate-discriminates', 'cherry-pick', 'dropped-failures', 'unbounded-replay', 'reproducible', 'control-honoured']) {
      const r = spawnSync(process.execPath, [SCRIPT, '--fault', fault, '--json'], { encoding: 'utf8', timeout: 120_000 });
      assert.equal(r.status, 1, `${fault}: ${r.stderr}`);
      const failed = JSON.parse(r.stdout).controls.filter((c) => !c.ok).map((c) => c.name);
      assert.deepEqual(failed, [fault], `${fault} should be the only failing control`);
    }
  });

  test('usage errors exit 2', () => {
    assert.equal(spawnSync(process.execPath, [SCRIPT, '--fault', 'nonsense'], { encoding: 'utf8' }).status, 2);
    assert.equal(spawnSync(process.execPath, [SCRIPT, '--surprise'], { encoding: 'utf8' }).status, 2);
  });

  test('the receipts file option writes a verifiable chain', () => {
    const file = path.join(fs.mkdtempSync(path.join(fs.realpathSync(process.env.TMPDIR || '/tmp'), 'routing-receipts-')), 'receipts.json');
    try {
      const r = spawnSync(process.execPath, [SCRIPT, '--json', '--receipts', file], { encoding: 'utf8', timeout: 120_000 });
      assert.equal(r.status, 0, r.stderr);
      const exported = JSON.parse(fs.readFileSync(file, 'utf8'));
      assert.equal(verifyReceiptChain(exported.receipts).ok, true);
    } finally { fs.rmSync(path.dirname(file), { recursive: true, force: true }); }
  });

  test('the documentation page exists, names the command and the controls, and is registered in the capability ledger', () => {
    const doc = fs.readFileSync(path.join(ROOT, 'docs', 'guides', 'routing-replay.md'), 'utf8');
    for (const needle of ['npm run reproduce:routing', 'AGENTIC_SECURITY_ROUTING', 'pin:', 'disabled', '--fault']) assert.ok(doc.includes(needle), needle);
    assert.ok(!doc.includes(String.fromCharCode(0x2014)));
    const ledger = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'capability-ledger.json'), 'utf8'));
    assert.ok(ledger.unindexedDocs.some((d) => d.path === 'docs/guides/routing-replay.md' && d.taskId === 'CORE-001-T03'));
  });
});
