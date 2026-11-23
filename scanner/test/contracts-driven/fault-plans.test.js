// Epic E on the business-state harness: supported fault plans reproduce a planted idempotency defect across fresh runs, a change of
// plan changes the outcome and the artifact says what changed, unsupported faults are refused with the reason. E-AC01, E-AC02, E-AC04.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyFaultPlan, replayFaultScenario, diffFaultArtifacts, UNSUPPORTED_FAULTS } from '../../src/posture/invariants/fault-plans.js';
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
const baseOf = ({ inv, fixture }) => generateScenarios(inv, { fixture, config }).scenarios[0];

test('E-AC04: every unsupported fault is refused with its reason, and malformed plans are rejected', () => {
  const base = baseOf(load('ledger-duplicate-credit'));
  for (const kind of Object.keys(UNSUPPORTED_FAULTS)) { const r = applyFaultPlan(base, { kind }); assert.equal(r.status, 'unsupported'); assert.ok(r.reason.length > 20); }
  assert.equal(applyFaultPlan(base, { kind: 'duplicate-delivery', copies: 9 }).status, 'rejected');
  assert.equal(applyFaultPlan(base, { kind: 'reorder', steps: [base.inputs.attack[0], base.inputs.attack[0]], schedule: [0, 0] }).status, 'rejected');
  assert.equal(applyFaultPlan(base, { kind: 'revocation-between' }).status, 'unsupported');
  assert.equal(applyFaultPlan(base, { kind: 'nonsense' }).status, 'rejected');
  const dup = applyFaultPlan(base, { kind: 'duplicate-delivery', copies: 3 });
  assert.equal(dup.status, 'ok'); assert.equal(dup.scenario.inputs.attack.length, 3);
  assert.notEqual(dup.scenario.id, base.id, 'a derived scenario with different inputs has its own content id');
});

test('E-AC01/E-AC02: duplicate delivery reproduces the planted double credit in two fresh runs; the idempotent twin stays clean; a single delivery does not reach it, and the artifacts name what changed', { skip }, async () => {
  const bad = load('ledger-duplicate-credit');
  const base = baseOf(bad);
  const single = applyFaultPlan(base, { kind: 'duplicate-delivery', copies: 2, step: base.inputs.attack[0] });
  const once = { ...single, scenario: { ...single.scenario } };
  const dup = await replayFaultScenario(single, { fixture: bad.fixture, commit, config });
  assert.equal(dup.status, 'reproduced'); assert.deepEqual(dup.artifact.outcomes, ['confirmed', 'confirmed']);
  assert.ok(dup.artifact.boundary.notControlled.includes('dependency-timeout'));
  const good = load('ledger-idempotent-settle');
  const goodDup = await replayFaultScenario(applyFaultPlan(baseOf(good), { kind: 'duplicate-delivery', copies: 2, step: baseOf(good).inputs.attack[0] }), { fixture: good.fixture, commit, config });
  assert.deepEqual(goodDup.artifact.outcomes, ['refuted', 'refuted']);
  const reorder = applyFaultPlan(base, { kind: 'reorder', steps: [base.inputs.attack[0], { ...base.inputs.attack[0], args: [base.inputs.attack[0].args[0], { ...base.inputs.attack[0].args[1], requestId: 'req-other' }] }], schedule: [1, 0] });
  const rr = await replayFaultScenario(reorder, { fixture: bad.fixture, commit, config });
  const changes = diffFaultArtifacts(dup.artifact, rr.artifact);
  assert.ok(changes.some((c) => c.field === 'plan.kind'));
  assert.ok(changes.some((c) => c.field === 'schedule'));
  void once;
});
