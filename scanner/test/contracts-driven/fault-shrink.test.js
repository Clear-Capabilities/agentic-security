// E-AC03 on the fault harness: four duplicate deliveries of the planted double-credit step shrink to the two that still credit twice;
// the minimized case fails the SAME authoritative assertion (judged on two fresh replays by the shrinker's own judge), the shrink
// record verifies against both scenarios, and the identities join: plan digest, original and minimized scenario ids, shrink record id,
// and the fresh fault replay. A plan that cannot reproduce shrinks to nothing and is reported as not reproduced.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyFaultPlan, shrinkFaultScenario } from '../../src/posture/invariants/fault-plans.js';
import { verifyShrinkRecord } from '../../src/posture/invariants/shrink.js';
import { generateScenarios } from '../../src/posture/invariants/scenarios.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CASES = path.join(HERE, '..', 'fixtures', 'invariant-benchmark', 'cases');
const load = (c) => ({ inv: createInvariant(JSON.parse(fs.readFileSync(path.join(CASES, c, 'contract.json'), 'utf8'))), fixture: { files: { 'app.mjs': fs.readFileSync(path.join(CASES, c, 'app.mjs'), 'utf8') } } });
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'invariant-scenarios': true, 'verification-oracles': true } } });
const commit = 'a'.repeat(40);
const skip = sandboxAvailable() ? false : 'no confinement backend on this host';

test('E-AC03: a four-delivery fault shrinks to two deliveries with the same failed assertion and joined identities', { skip, timeout: 600_000 }, async () => {
  const bad = load('ledger-duplicate-credit');
  const base = generateScenarios(bad.inv, { fixture: bad.fixture, config }).scenarios[0];
  const compiled = applyFaultPlan(base, { kind: 'duplicate-delivery', copies: 4, step: base.inputs.attack[0] });
  assert.equal(compiled.status, 'ok'); assert.equal(compiled.scenario.inputs.attack.length, 4);
  const r = await shrinkFaultScenario(compiled, { fixture: bad.fixture, commit, config, budget: { maxRuns: 12 } });
  assert.equal(r.status, 'minimized', r.reason);
  assert.equal(r.shrink.minimized.inputs.attack.length, 2, 'two deliveries still credit twice; one does not, so it is never removed');
  assert.equal(r.recordVerified.ok, true);
  assert.ok(r.judged.length >= 2 && r.judged.every((j) => j.kept), 'each fresh replay fails the original assertion');
  assert.equal(r.identity.planDigest, compiled.planDigest);
  assert.equal(r.identity.originalScenarioId, compiled.scenario.id);
  assert.notEqual(r.identity.minimizedScenarioId, compiled.scenario.id);
  assert.equal(r.identity.replay.scenarioId, r.identity.minimizedScenarioId);
  assert.deepEqual(r.identity.replay.outcomes, ['confirmed', 'confirmed']);
  assert.deepEqual(r.identity.invariant, compiled.scenario.invariant);
  // the joined record refuses a substituted scenario
  assert.equal(verifyShrinkRecord({ record: r.shrink.record, original: base, minimized: r.shrink.minimized }).ok, false);
});

test('E-AC03: an idempotent application has nothing to shrink; the fault is reported as not reproduced', { skip, timeout: 300_000 }, async () => {
  const good = load('ledger-idempotent-settle');
  const base = generateScenarios(good.inv, { fixture: good.fixture, config }).scenarios[0];
  const r = await shrinkFaultScenario(applyFaultPlan(base, { kind: 'duplicate-delivery', copies: 3, step: base.inputs.attack[0] }), { fixture: good.fixture, commit, config, budget: { maxRuns: 4 } });
  assert.notEqual(r.status, 'minimized');
  assert.equal(r.status, 'not-reproduced');
});

test('E-AC03: an unsupported plan is not shrunk', async () => {
  const bad = load('ledger-duplicate-credit');
  const base = generateScenarios(bad.inv, { fixture: bad.fixture, config }).scenarios[0];
  const r = await shrinkFaultScenario(applyFaultPlan(base, { kind: 'process-interruption' }), { fixture: bad.fixture, commit, config });
  assert.equal(r.status, 'unsupported');
});
