// E-AC06: the fast and extended fault profiles declare caps on plans, runs per plan, wall time, processes and stored bytes, hold them,
// and report every truncation. The cap tests use a scripted runner (they test the accounting, not an application); the last test runs
// the fast profile for real through the trust boundary on the planted double-credit case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FAULT_PROFILES, runFaultProfile } from '../../src/posture/invariants/fault-plans.js';
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
const bad = load('ledger-duplicate-credit');
const base = generateScenarios(bad.inv, { fixture: bad.fixture, config }).scenarios[0];
const dup = (copies) => ({ kind: 'duplicate-delivery', copies, step: base.inputs.attack[0] });
const scripted = (outcome = 'confirmed') => async (scenario) => ({ scenarioId: scenario.id, status: 'completed', outcome });

test('the two profiles are distinct, bounded and declared; an unknown profile is refused', async () => {
  for (const p of ['fast', 'extended']) for (const k of ['maxPlans', 'runsPerPlan', 'maxWallMs', 'maxProcesses', 'maxArtifactBytes']) assert.ok(Number.isFinite(FAULT_PROFILES[p][k]) && FAULT_PROFILES[p][k] > 0, `${p}.${k}`);
  assert.ok(FAULT_PROFILES.extended.maxPlans > FAULT_PROFILES.fast.maxPlans && FAULT_PROFILES.extended.runsPerPlan > FAULT_PROFILES.fast.runsPerPlan && FAULT_PROFILES.extended.maxWallMs > FAULT_PROFILES.fast.maxWallMs);
  assert.equal((await runFaultProfile(base, [dup(2)], { profile: 'exhaustive', fixture: bad.fixture, commit, config, runner: scripted() })).status, 'rejected');
});

test('the plan cap truncates and lists every skipped plan; runs per plan follow the profile; one process at a time', async () => {
  const plans = Array.from({ length: 9 }, (_, i) => dup(2 + (i % 3)));
  let calls = 0; const runner = async (s) => { calls += 1; return scripted()(s); };
  const fast = await runFaultProfile(base, plans, { profile: 'fast', fixture: bad.fixture, commit, config, runner });
  assert.equal(fast.plansRun, FAULT_PROFILES.fast.maxPlans); assert.equal(fast.truncated, true);
  assert.deepEqual(fast.skipped.map((s) => s.cap), Array(9 - FAULT_PROFILES.fast.maxPlans).fill('maxPlans'));
  assert.equal(calls, FAULT_PROFILES.fast.maxPlans * FAULT_PROFILES.fast.runsPerPlan);
  assert.equal(fast.used.maxConcurrentProcesses, 1); assert.equal(fast.withinCaps, true);
  const ext = await runFaultProfile(base, plans, { profile: 'extended', fixture: bad.fixture, commit, config, runner: scripted() });
  assert.equal(ext.plansRun, 9); assert.equal(ext.truncated, false);
  assert.ok(ext.results.every((r) => r.artifact.outcomes.length === FAULT_PROFILES.extended.runsPerPlan));
  assert.match(ext.note, /prove nothing exhaustively/);
});

test('a plan whose worst case would overrun the wall budget is not started, and the skip names the cap', async () => {
  let t = 0; const now = () => t;
  const runner = async (s) => { t += 10_000; return scripted()(s); };
  const r = await runFaultProfile(base, [dup(2), dup(3), dup(4)], { profile: 'fast', fixture: bad.fixture, commit, config, runner, now });
  const worst = base.limits.timeBudgetMs * FAULT_PROFILES.fast.runsPerPlan;
  assert.ok(r.used.elapsedMs <= FAULT_PROFILES.fast.maxWallMs, 'the run ends inside its wall budget');
  if (worst > FAULT_PROFILES.fast.maxWallMs) assert.equal(r.plansRun, 0);
  assert.ok(r.skipped.every((s) => s.cap === 'maxWallMs' && s.worstCaseMs === worst));
  assert.equal(r.truncated, r.skipped.length > 0);
});

test('the byte cap compacts an artifact that would overrun it to its identity and outcomes, and says so; a cap can be lowered, never raised', async () => {
  const plans = Array.from({ length: 4 }, () => dup(2));
  const free = await runFaultProfile(base, plans, { profile: 'fast', fixture: bad.fixture, commit, config, runner: scripted() });
  const each = free.results[0].bytes;
  const r = await runFaultProfile(base, plans, { profile: 'fast', tighten: { maxArtifactBytes: each * 2 + 200 }, fixture: bad.fixture, commit, config, runner: scripted() });
  assert.deepEqual(r.tightened, ['maxArtifactBytes']);
  assert.ok(r.results.slice(0, 2).every((x) => !x.compacted));
  assert.ok(r.results.slice(2).every((x) => x.compacted && x.artifact.compacted && x.artifact.outcomes.length === 2));
  assert.ok(r.used.artifactBytes <= r.caps.maxArtifactBytes); assert.equal(r.withinCaps, true); assert.equal(r.truncated, true);
  const raised = await runFaultProfile(base, plans, { profile: 'fast', tighten: { maxPlans: FAULT_PROFILES.fast.maxPlans + 1 }, fixture: bad.fixture, commit, config, runner: scripted() });
  assert.equal(raised.status, 'rejected');
  assert.throws(() => { FAULT_PROFILES.fast.maxPlans = 99; }, TypeError, 'the declared profiles cannot be edited at run time');
});

test('the fast profile for real: duplicate delivery reproduces the planted double credit within the fast caps', { skip, timeout: 300_000 }, async () => {
  const r = await runFaultProfile(base, [dup(2), { kind: 'dependency-timeout' }], { profile: 'fast', fixture: bad.fixture, commit, config });
  assert.equal(r.results[0].status, 'reproduced');
  assert.deepEqual(r.results[0].artifact.outcomes, ['confirmed', 'confirmed']);
  assert.equal(r.results[1].status, 'unsupported');
  assert.equal(r.withinCaps, true); assert.ok(r.used.elapsedMs <= FAULT_PROFILES.fast.maxWallMs);
  assert.deepEqual(r.coverage, { reproduced: 1, notReproduced: 0, unsupported: 1, rejected: 0 });
});
