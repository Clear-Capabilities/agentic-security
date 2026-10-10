// LOOP-002: spend that is not the model worker's, and spend nobody reported. Two controls, each proven in both directions against the
// REAL controller driving a disposable repository with a SCRIPTED stand-in worker (helpers.js). No model is called, no money is spent,
// no network is used: a "paid" step here is a local command that writes a witness file when it actually ran.
//
//   * the provider/infrastructure ENVELOPE: a separately metered budget, off unless a person preauthorized it in the profile, charged by
//     controller-run steps that declare a cost BEFORE they run, and closed (no later paid step) once it cannot cover one;
//   * the unknown-billing RESERVE: an attempt whose stream reported no cost is charged a defined upper bound, never zero, and paid work
//     stops when that reserve no longer fits under the cap.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MiniRepo, alive } from './helpers.js';
import { chargeEnvelope, envelopeConfig, modelCharge, stepCost, emptyProvider } from '../lib/envelope.mjs';
import { validateBoundsConfig } from '../lib/bounds.mjs';
import { buildCompletionReport } from '../lib/report.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REAL = JSON.parse(readFileSync(join(HERE, '..', 'profiles', 'assurance-differentiation.json'), 'utf8'));
void alive;

const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
const waitTerminal = (repo, timeoutMs = 90000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs, label: 'terminal status' });
const waitQuiet = async (repo) => {
  const s = await waitTerminal(repo);
  if (s.controller.pid) await repo.waitFor(async () => !alive(s.controller.pid), { timeoutMs: 20000, label: 'controller exit' });
  return repo.status();
};
const readReport = async (repo) => {
  await repo.waitFor(async () => existsSync(repo.runPath('completion-report.json')), { timeoutMs: 15000, label: 'completion-report.json' });
  return JSON.parse(readFileSync(repo.runPath('completion-report.json'), 'utf8'));
};
const eventsOf = (repo) => readFileSync(repo.runPath('events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const calls = (repo) => (repo.exists('worker-calls.log') ? repo.read('worker-calls.log').trim().split('\n').filter(Boolean) : []);
const R = (id, weight = 1, deps = []) => ({ id, weight, deps, criteria: ['the criterion'] });
const long = { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 };

// A paid infrastructure step: a command that leaves a witness file only if the controller really ran it. The witness goes under
// .loop-engineering/, which the tree digest ignores, so it cannot make the final verification's tree look unstable.
const paid = (id, cost) => ({ id, cwd: '.', executable: 'node', args: ['-e', `require('node:fs').writeFileSync('.loop-engineering/paid-${id}', '1')`], timeoutSeconds: 30, ...cost });
const FREE = { id: 'free', cwd: '.', executable: 'node', args: ['-e', "require('node:fs').writeFileSync('.loop-engineering/ran-free', '1')"], timeoutSeconds: 30 };
const ENV_ON = (over = {}) => ({ enabled: true, capUsd: 25, unknownBillingReserveUsd: 25, preauthorization: { by: 'the supervising session', at: '2026-10-10T00:00:00Z', capUsd: 25 }, ...over });
const ENV_OFF = () => ({ enabled: false, capUsd: 25, unknownBillingReserveUsd: 25, preauthorization: null });

function envelopeRepo(gates, providerEnvelope) {
  return new MiniRepo([R('CORE-001')], { profile: { limits: long, finalGates: gates, extra: { finalVerification: { required: true }, providerEnvelope } } });
}

// ============================================================ the envelope: pure accounting

test('[LOOP-002.AC02] the envelope charges a declared cost, refuses a step that would pass the cap, and once it has refused for want of room no later (smaller) step slips in', () => {
  const cfg = envelopeConfig({ providerEnvelope: ENV_ON() });
  assert.equal(cfg.enabled, true);
  const p = emptyProvider();
  assert.deepEqual(chargeEnvelope(p, cfg, { id: 'a', costUsd: 10 }), { ok: true, charged: 10, paid: true, unknown: false });
  assert.equal(chargeEnvelope(p, cfg, { id: 'b', costUsd: 15 }).ok, true, 'exactly the cap is allowed');
  assert.equal(p.usedUsd, 25);
  const over = chargeEnvelope(p, cfg, { id: 'c', costUsd: 0.5 });
  assert.equal(over.ok, false);
  assert.equal(over.kind, 'exhausted');
  assert.equal(p.usedUsd, 25, 'a refused step is not charged');
  // a fresh meter: an over-cap step is refused, then a small one is refused too (exhausted is sticky)
  const q = emptyProvider();
  assert.equal(chargeEnvelope(q, cfg, { id: 'big', costUsd: 26 }).kind, 'exhausted');
  assert.equal(chargeEnvelope(q, cfg, { id: 'small', costUsd: 1 }).ok, false, 'no cherry-picking a cheaper step after the envelope refused one');
  assert.equal(q.usedUsd, 0);
  assert.deepEqual(q.stops.map((s) => s.step), ['big', 'small']);
  // a free step is never metered and never refused
  assert.deepEqual(chargeEnvelope(q, cfg, { id: 'free' }), { ok: true, charged: 0, paid: false });
});

test('[LOOP-002.AC02] the envelope is OFF unless the profile enables it with a preauthorization: a paid step is refused when it is disabled, absent, or enabled without one', () => {
  for (const profile of [{ providerEnvelope: ENV_OFF() }, {}, { providerEnvelope: { ...ENV_ON(), preauthorization: null } }]) {
    const cfg = envelopeConfig(profile);
    assert.equal(cfg.enabled, false);
    const p = emptyProvider();
    const r = chargeEnvelope(p, cfg, { id: 'x', costUsd: 1 });
    assert.equal(r.ok, false);
    assert.equal(r.kind, 'not-enabled');
    assert.match(r.reason, /not enabled and preauthorized/);
    assert.equal(p.usedUsd, 0);
  }
  assert.equal(envelopeConfig({ providerEnvelope: ENV_ON() }).enabled, true);
});

test('[LOOP-002.AC02] an unknown cost is never zero: a step that declares costUnknown is charged the defined reserve, and the reserve is what is checked against the cap', () => {
  const cfg = envelopeConfig({ providerEnvelope: ENV_ON({ capUsd: 30, unknownBillingReserveUsd: 25, preauthorization: { by: 'x', at: '2026-10-10T00:00:00Z', capUsd: 30 } }) });
  assert.deepEqual(stepCost({ id: 'u', costUnknown: true }, cfg), { paid: true, usd: 25, unknown: true });
  assert.deepEqual(stepCost({ id: 'f' }, cfg), { paid: false, usd: 0, unknown: false });
  const p = emptyProvider();
  assert.deepEqual(chargeEnvelope(p, cfg, { id: 'u1', costUnknown: true }), { ok: true, charged: 25, paid: true, unknown: true });
  assert.equal(chargeEnvelope(p, cfg, { id: 'u2', costUnknown: true }).kind, 'exhausted', 'a second unknown charge would pass the cap, so paid work stops');
  assert.equal(p.usedUsd, 25);
  assert.equal(p.charges[0].unknown, true);
});

test('[LOOP-002.AC02] the model attempt charge: a reported cost is exact, an unreported one is at least the reserve and never zero, a profile with no reserve keeps the legacy accounting', () => {
  assert.deepEqual(modelCharge({ reportedUsd: 0.37, reserveUsd: 4 }), { usd: 0.37, estimated: false, reserve: false });
  assert.deepEqual(modelCharge({ reportedUsd: 0, reserveUsd: 4 }), { usd: 0, estimated: false, reserve: false }, 'a reported zero is a report, not an unknown');
  assert.deepEqual(modelCharge({ reportedUsd: null, runningUsd: 0, tokenUsd: 0, reserveUsd: 4 }), { usd: 4, estimated: true, reserve: true });
  assert.equal(modelCharge({ reportedUsd: null, runningUsd: 1.5, tokenUsd: 0, reserveUsd: 4 }).usd, 4, 'a partial running figure is a lower bound: the reserve is the upper bound');
  assert.equal(modelCharge({ reportedUsd: null, runningUsd: 5, tokenUsd: 0, reserveUsd: 4 }).usd, 5, 'but a larger observed figure wins');
  assert.equal(modelCharge({ reportedUsd: null, runningUsd: 0, tokenUsd: 2, reserveUsd: 4 }).usd, 4);
  assert.deepEqual(modelCharge({ reportedUsd: null, runningUsd: 0, tokenUsd: 0, reserveUsd: null }), { usd: 0, estimated: true, reserve: false });
});

test('[LOOP-002.AC02] spend configuration is validated: the reserve is finite, positive and fits the cap; an enabled envelope needs a preauthorization at its cap; a paid step needs an envelope block', () => {
  const bad = (mut) => { const p = structuredClone(REAL); mut(p); const problems = []; validateBoundsConfig(p, problems); return problems.join('\n'); };
  assert.equal(bad(() => {}), '');
  assert.match(bad((p) => { p.limits.unknownBillingReserveUsd = 0; }), /unknownBillingReserveUsd must be a finite positive number: unknown billing is never zero-cost/);
  assert.match(bad((p) => { p.limits.unknownBillingReserveUsd = 51; }), /exceeds the whole-run claudeBudgetUsd/);
  assert.match(bad((p) => { p.providerEnvelope.enabled = true; }), /enabled needs preauthorization/);
  assert.match(bad((p) => { p.providerEnvelope.enabled = true; p.providerEnvelope.preauthorization = { by: '', at: 'x', capUsd: 25 }; }), /enabled needs preauthorization/);
  assert.match(bad((p) => { p.providerEnvelope.enabled = true; p.providerEnvelope.preauthorization = { by: 'a person', at: '2026-10-10', capUsd: 10 }; }), /below the envelope cap 25/);
  assert.match(bad((p) => { p.providerEnvelope.capUsd = 0; }), /capUsd must be a finite positive number/);
  assert.match(bad((p) => { p.providerEnvelope.unknownBillingReserveUsd = 26; }), /no more than capUsd/);
  assert.match(bad((p) => { p.finalGates[0].costUsd = -1; }), /costUsd must be a finite positive number/);
  assert.match(bad((p) => { p.finalGates[0].costUsd = 1; p.finalGates[0].costUnknown = true; }), /not both/);
  assert.match(bad((p) => { delete p.providerEnvelope; p.finalGates[0].costUsd = 1; }), /a paid step needs a providerEnvelope block/);
  assert.equal(bad((p) => { p.providerEnvelope.enabled = true; p.providerEnvelope.preauthorization = { by: 'a person', at: '2026-10-10', capUsd: 25 }; }), '', 'a preauthorized envelope is valid');
});

test('[LOOP-002.AC02] the real profile declares the envelope OFF at $25, a $6 unknown-billing reserve, and no longer lists the enforced controls as unenforced', () => {
  assert.equal(REAL.providerEnvelope.enabled, false);
  assert.equal(REAL.providerEnvelope.capUsd, 25);
  assert.equal(REAL.providerEnvelope.preauthorization, null, 'no person has preauthorized the envelope');
  assert.equal(REAL.limits.unknownBillingReserveUsd, 6);
  assert.ok(REAL.limits.unknownBillingReserveUsd <= REAL.limits.claudeBudgetUsd);
  assert.deepEqual(REAL.unenforced.map((u) => u.field).sort(), ['budgetsAreCapsNotAuthorization', 'linuxEnforcementBackend']);
});

// ============================================================ the envelope: the real controller

test('[LOOP-002.AC02] the controller meters paid steps against the separate envelope BEFORE running them: steps inside the cap run, the one that would pass it is not run, and the stop is recorded in state, events and the report', async () => {
  const repo = envelopeRepo([FREE, paid('A', { costUsd: 10 }), paid('B', { costUsd: 10 }), paid('C', { costUsd: 10 }), paid('D', { costUsd: 1 })], ENV_ON());
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'blocked', 'a refused paid gate fails the final verification');
    assert.equal(repo.exists('.loop-engineering/ran-free'), true, 'a free step runs');
    assert.equal(repo.exists('.loop-engineering/paid-A'), true);
    assert.equal(repo.exists('.loop-engineering/paid-B'), true);
    assert.equal(repo.exists('.loop-engineering/paid-C'), false, 'the step that would pass the $25 cap was NOT run');
    assert.equal(repo.exists('.loop-engineering/paid-D'), false, 'and a cheaper step after the refusal does not slip in');
    const st = repo.state();
    assert.equal(st.budgets.provider.usedUsd, 20);
    assert.ok(st.budgets.usdUsed < 1, `the model spend is separate (${st.budgets.usdUsed})`);
    assert.deepEqual(st.budgets.provider.stops.map((x) => [x.step, x.kind]), [['C', 'exhausted'], ['D', 'exhausted']]);
    const ev = eventsOf(repo);
    assert.deepEqual(ev.filter((e) => e.type === 'provider-charge').map((e) => [e.step, e.usd]), [['A', 10], ['B', 10]]);
    assert.deepEqual(ev.filter((e) => e.type === 'provider-stop').map((e) => e.step), ['C', 'D']);
    const rep = await readReport(repo);
    assert.equal(rep.budgets.providerEnvelope.usedUsd, 20);
    assert.equal(rep.budgets.providerEnvelope.capUsd, 25);
    assert.equal(rep.budgets.providerEnvelope.enabled, true);
    assert.equal(rep.budgets.providerEnvelope.preauthorizedBy, 'the supervising session');
    assert.ok(rep.budgetStops.some((b) => b.kind === 'provider-envelope-exhausted' && b.step === 'C'));
    assert.equal(rep.verdict, 'incomplete');
    assert.match(readFileSync(repo.path('.loop-engineering', 'runs', repo.runId(), 'final-report.json'), 'utf8'), /paid step was not run/);
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC02] with the envelope OFF a paid step is never run (not even a cheap one), a free step still is, and nothing is charged', async () => {
  const repo = envelopeRepo([FREE, paid('A', { costUsd: 1 })], ENV_OFF());
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'blocked');
    assert.equal(repo.exists('.loop-engineering/ran-free'), true);
    assert.equal(repo.exists('.loop-engineering/paid-A'), false, 'a paid step without a preauthorized envelope is not run');
    const st = repo.state();
    assert.equal(st.budgets.provider.usedUsd, 0);
    assert.equal(st.budgets.provider.enabled, false);
    assert.equal(st.budgets.provider.stops[0].kind, 'not-enabled');
    assert.match(st.budgets.provider.stops[0].reason, /envelope is not enabled and preauthorized/);
  } finally { await repo.cleanup(); }
  // direction two: the same gates with the envelope on and the step inside the cap -> the paid step runs and the run completes
  const ok = envelopeRepo([FREE, paid('A', { costUsd: 1 })], ENV_ON());
  try {
    assert.equal((await ok.init()).code, 0);
    assert.equal((await ok.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(ok);
    assert.equal(s.status, 'completed', s.statusReason);
    assert.equal(ok.exists('.loop-engineering/paid-A'), true);
    assert.equal(ok.state().budgets.provider.usedUsd, 1);
    assert.equal((await readReport(ok)).budgets.providerEnvelope.stops.length, 0);
  } finally { await ok.cleanup(); }
});

test('[LOOP-002.AC02] a paid step of unknown cost is charged the reserve, and a second one is not run once the reserve no longer fits', async () => {
  const repo = envelopeRepo([paid('U1', { costUnknown: true }), paid('U2', { costUnknown: true })], ENV_ON({ capUsd: 30, unknownBillingReserveUsd: 25, preauthorization: { by: 'the supervising session', at: '2026-10-10T00:00:00Z', capUsd: 30 } }));
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'blocked');
    assert.equal(repo.exists('.loop-engineering/paid-U1'), true);
    assert.equal(repo.exists('.loop-engineering/paid-U2'), false);
    const st = repo.state();
    assert.equal(st.budgets.provider.usedUsd, 25, 'the unknown cost was charged as the reserve, not as zero');
    assert.equal(st.budgets.provider.charges[0].unknown, true);
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC02] an exhausted envelope is not reset by a restart, and an envelope enabled without a preauthorization refuses the run at init', async () => {
  const repo = envelopeRepo([paid('A', { costUsd: 20 }), paid('B', { costUsd: 10 })], ENV_ON());
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    await waitQuiet(repo);
    assert.equal(repo.state().budgets.provider.usedUsd, 20);
    // a controller restart (resume) re-reads the profile and keeps the meter: the final phase runs again, its $20 step is charged against
    // what is LEFT ($5), not against a fresh $25, and is refused (B was already refused once)
    const r = await repo.cli(['resume']);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    await repo.waitFor(async () => repo.state().budgets.provider.stops.some((x) => x.step === 'A'), { timeoutMs: 60000, label: 'second final phase refused' });
    await waitQuiet(repo);
    const p = repo.state().budgets.provider;
    assert.equal(p.usedUsd, 20, 'the meter was kept across the restart and not reset to make room');
    assert.equal(p.stops.find((x) => x.step === 'A').kind, 'exhausted');
  } finally { await repo.cleanup(); }
  const noAuth = envelopeRepo([FREE], { ...ENV_ON(), preauthorization: null });
  try {
    const i = await noAuth.init();
    assert.notEqual(i.code, 0);
    assert.match(i.stderr + i.stdout, /enabled needs preauthorization/);
  } finally { await noAuth.cleanup(); }
});

// ============================================================ unknown billing reserve: the real controller

const REQS3 = [R('CORE-001'), R('X-201'), R('QA-001')];
const reserveRepo = (mode, limits = {}) => new MiniRepo(REQS3, { workerMode: { default: mode }, profile: { limits: { ...long, claudeBudgetUsd: 10, perAttemptBudgetUsd: 6, unknownBillingReserveUsd: 4, ...limits } } });

test('[LOOP-002.AC02] attempts that report no cost are charged the defined reserve (never zero) and paid work STOPS when the reserve would exceed the cap', async () => {
  const repo = reserveRepo('no-cost-fix');
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'paused-budget');
    assert.match(s.statusReason, /unknown billing: the last attempt reported no cost, and the defined upper-bound reserve of \$4 no longer fits under the \$10 cap/);
    assert.equal(calls(repo).length, 2, 'two attempts fit ($4 + $4 of $10); the third did not start');
    const st = repo.state();
    assert.equal(st.budgets.usdUsed, 8, 'each unreported attempt cost the reserve');
    assert.equal(st.budgets.usdReserved, 8);
    assert.equal(st.budgets.billingUnknown, true);
    const ends = eventsOf(repo).filter((e) => e.type === 'attempt-end');
    assert.deepEqual(ends.map((e) => [e.costUsd, e.costIsUnknownBillingReserve]), [[4, true], [4, true]]);
    const rep = await readReport(repo);
    assert.equal(rep.budgets.used.usdUnknownBillingReserve, 8);
    assert.equal(rep.budgets.limits.unknownBillingReserveUsd, 4);
    assert.ok(rep.budgetStops.some((b) => b.kind === 'run-budget' && /unknown billing/.test(b.detail)));
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC02] the same run with a worker that REPORTS its cost is charged the reported figure, uses no reserve, and completes (the stop above is the reserve, not the cap)', async () => {
  const repo = reserveRepo('fix');
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'completed', s.statusReason);
    const st = repo.state();
    assert.ok(st.budgets.usdUsed < 1, `reported costs only (${st.budgets.usdUsed})`);
    assert.equal(st.budgets.usdReserved || 0, 0);
    assert.equal(st.budgets.billingUnknown || false, false);
    assert.equal(calls(repo).length, 3);
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC02] a profile that predates the reserve keeps the legacy accounting: an unreported cost is charged only its token estimate, so the reserve is what makes it never zero', async () => {
  const repo = new MiniRepo(REQS3, { workerMode: { default: 'no-cost-fix' }, profile: { limits: { ...long, claudeBudgetUsd: 10, perAttemptBudgetUsd: 6 } } });
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    const s = await waitQuiet(repo);
    assert.equal(s.status, 'completed', s.statusReason);
    assert.ok(repo.state().budgets.usdUsed < 0.01, 'no reserve configured: only the token-derived estimate is charged (the real profile configures a reserve)');
  } finally { await repo.cleanup(); }
  assert.equal(typeof REAL.limits.unknownBillingReserveUsd, 'number', 'the assurance profile does configure it');
});

test('[LOOP-002.AC02] an attempt that never reached the model (the worker would not start) is not charged the reserve', async () => {
  const repo = new MiniRepo([R('CORE-001')], { workerMode: { default: 'auth-fail' }, profile: { limits: { ...long, claudeBudgetUsd: 10, perAttemptBudgetUsd: 6, unknownBillingReserveUsd: 4 } } });
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background'])).code, 0);
    await waitQuiet(repo);
    assert.equal(repo.state().budgets.usdReserved || 0, 0, 'a missing login cost nothing, so no reserve was charged');
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC02] the completion report keeps the two budgets apart and says so when no envelope is configured', () => {
  const status = { runId: 'r', status: 'completed', requirements: [], budgets: { usdUsed: 3, attemptsUsed: 1, wallUsedMs: 1, usdReserved: 2, provider: { enabled: true, capUsd: 25, usedUsd: 5, preauthorizedBy: 'a person', charges: [{ step: 'A', usd: 5 }], stops: [] } }, limits: { claudeBudgetUsd: 50, unknownBillingReserveUsd: 6 }, final: { required: false } };
  const rep = buildCompletionReport(status);
  assert.equal(rep.budgets.used.usd, 3);
  assert.equal(rep.budgets.providerEnvelope.usedUsd, 5, 'the envelope is its own figure');
  assert.equal(rep.budgets.used.usdUnknownBillingReserve, 2);
  delete status.budgets.provider;
  assert.equal(buildCompletionReport(status).budgets.providerEnvelope, undefined, 'no envelope block for a run that never had one');
});
