// X-707: coverage-aware portfolio progress and review queues. SYNTHETIC repositories and findings only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  planPortfolio, newStore, openStore, leaseUnit, startUnit, completeUnit, failUnit, blockUnit, cancelUnits, readStore,
} from '../../src/posture/portfolio/work-units.js';
import { applyResume } from '../../src/posture/portfolio/resume.js';
import { scheduleNext, heartbeat, runScheduled, readLedger, HEARTBEAT } from '../../src/posture/portfolio/scheduler.js';
import {
  buildProgressView, aggregateFindings, reviewItemsFromInvariantCoverage, reviewItemsFromBoundaryContexts, portfolioProgressFields, attachPortfolioProgress, PROGRESS_SCHEMA, PROGRESS_VERSION, FINDINGS_SCHEMA,
} from '../../src/posture/portfolio/progress.js';
import { runPortfolioCommand } from '../../src/posture/portfolio/cli.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { rollupFleet, renderFleetSummary, renderFleetHtml } from '../../src/posture/fleet.js';
import { createServer } from '../../src/mcp/server.js';
import { ALL_TOOLS } from '../../src/mcp/tools.js';
import { toolCapabilityFor } from '../../src/capabilities/tool-registry.js';
import { DEPS, COMMIT, sha, ok, estimateOf, manyUnitsPlan, BIG_BUDGETS } from './helpers.js';
import { FLEET_RESULTS } from './fixtures-input.js';

const T = 1_000_000;
const ON = { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' };
const cfg = (env = {}) => resolveAssuranceConfig({ env });
const verify = (s, id, at = T) => { const l = leaseUnit(s, { holder: 'w', now: at, ttlMs: 60_000, unitId: id }); startUnit(s, { unitId: id, attemptId: l.attemptId, now: at }); return completeUnit(s, { unitId: id, attemptId: l.attemptId, resultDigest: sha(`r-${id}`), dependencies: DEPS, now: at }); };

// alpha: all verified. beta: one verified, one blocked, one failed. gamma: one pending, one stale (was verified, input changed), one leased.
function fixtureStore() {
  const p = planPortfolio({ repositories: ['alpha', 'beta', 'gamma'].map((name) => ({ name, commit: COMMIT })), authorized: ['alpha', 'beta', 'gamma'], taskTypes: ['sast-scan', 'boundary-graph', 'sca-reachability'], synthetic: true });
  const s = newStore(p.plan);
  const of = (repo, type) => Object.values(s.units).find((u) => u.repository === repo && u.taskType === type).id;
  for (const t of ['sast-scan', 'boundary-graph', 'sca-reachability']) verify(s, of('alpha', t));
  verify(s, of('beta', 'sast-scan'));
  blockUnit(s, { unitId: of('beta', 'boundary-graph'), reason: 'deployment export not supplied', now: T });
  const fid = of('beta', 'sca-reachability');
  s.units[fid].maxRetries = 0;
  const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 60_000, unitId: fid });
  failUnit(s, { unitId: fid, attemptId: l.attemptId, reason: 'advisory database unreachable', now: T });
  const stale = of('gamma', 'sast-scan');
  verify(s, stale);
  applyResume(s, { revalidate: [], invalidate: [{ unitId: stale, changed: ['code'], reason: 'code digest changed' }] }, T + 1);
  leaseUnit(s, { holder: 'worker-g', now: T, ttlMs: 60_000, unitId: of('gamma', 'boundary-graph') });
  return { s, of };
}

describe('[X-707.AC01] progress separately reports verified units, blocked/failed/stale units, repository coverage, remaining budget and pending human review', () => {
  test('[X-707.AC01] each category is its own field, and only verified units count as progress', () => {
    const { s, of } = fixtureStore();
    const r = buildProgressView({ store: s, now: T + 1000 });
    assert.equal(r.ok, true);
    const v = r.view;
    assert.deepEqual([v.schema, v.schemaVersion], [PROGRESS_SCHEMA, PROGRESS_VERSION]);
    assert.equal(v.units.total, 9);
    assert.equal(v.units.verified, 4, 'alpha 3 + beta 1; the stale, leased, failed and blocked units do not count');
    assert.deepEqual(v.units.blocked.items.map((x) => x.unitId), [of('beta', 'boundary-graph')]);
    assert.equal(v.units.blocked.items[0].reason, 'deployment export not supplied');
    assert.deepEqual(v.units.failed.items.map((x) => x.unitId), [of('beta', 'sca-reachability')]);
    assert.equal(v.units.failed.items[0].reason, 'advisory database unreachable');
    assert.deepEqual(v.units.stale.items.map((x) => x.unitId), [of('gamma', 'sast-scan')]);
    assert.deepEqual(v.units.stale.items[0].changedDimensions, ['code']);
    assert.equal(v.units.inFlight, 1);
    assert.equal(v.units.pending, 2, 'the stale unit is pending again, and one gamma unit never started');
    assert.equal(v.units.counts.verified + v.units.counts.blocked + v.units.counts.failed + v.units.counts.pending + v.units.counts.leased + v.units.counts.running + v.units.counts.canceled, 9);
  });

  test('[X-707.AC01] repository coverage names fully verified, partial, incomplete and not-started repositories', () => {
    const { s } = fixtureStore();
    const cov = buildProgressView({ store: s, now: T }).view.coverage;
    assert.equal(cov.total, 3);
    assert.equal(cov.fullyVerified, 1);
    const by = Object.fromEntries(cov.repositories.map((r) => [r.repository, r]));
    assert.equal(by.alpha.status, 'fully-verified');
    assert.equal(by.beta.status, 'partial');
    assert.equal(by.beta.problems, 2);
    assert.equal(by.gamma.status, 'not-started', 'its earlier result is stale, so nothing in gamma is currently verified');
    assert.equal(by.gamma.inFlight, 1);
    const none = newStore(planPortfolio({ repositories: [{ name: 'z', commit: COMMIT }], authorized: ['z'], taskTypes: ['sast-scan'], synthetic: true }).plan);
    assert.equal(buildProgressView({ store: none, now: T }).view.coverage.repositories[0].status, 'not-started');
  });

  test('[X-707.AC01] a leased or running unit, a failed attempt, an expired lease and a duplicate completion never raise the verified count', () => {
    const s = newStore(planPortfolio({ repositories: [{ name: 'a', commit: COMMIT }], authorized: ['a'], taskTypes: ['sast-scan', 'boundary-graph'], synthetic: true }).plan);
    const ids = Object.keys(s.units);
    const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 1000, unitId: ids[0] });
    startUnit(s, { unitId: ids[0], attemptId: l.attemptId, now: T });
    assert.equal(buildProgressView({ store: s, now: T }).view.units.verified, 0);
    const first = completeUnit(s, { unitId: ids[0], attemptId: l.attemptId, resultDigest: sha('x'), dependencies: DEPS, now: T });
    const dup = completeUnit(s, { unitId: ids[0], attemptId: l.attemptId, resultDigest: sha('x'), dependencies: DEPS, now: T });
    assert.equal(first.counted, true); assert.equal(dup.counted, false);
    assert.equal(buildProgressView({ store: s, now: T }).view.units.verified, 1);
  });

  test('[X-707.AC01] remaining budget is reported per limit with reservations held back, and an unenforced limit says so', () => {
    const dir = mkTestTmp('prog-'); const file = path.join(dir, 's.json');
    openStore(file, manyUnitsPlan({ a: 2, b: 2 }));
    const budgets = { portfolio: { concurrency: 3, wallMs: 10_000, spendUsd: 5, requests: 100, storageBytes: 1000 }, repositories: { a: { spendUsd: 2 } } };
    const l = scheduleNext(file, { budgets, estimateOf, holder: 'w', now: T });
    assert.ok(l.lease);
    const v = buildProgressView({ store: readStore(file), ledger: readLedger(file), budgets, now: T }).view;
    assert.equal(v.budget.declared, true);
    assert.deepEqual(v.budget.portfolio.spendUsd, { limit: 5, used: 0, reserved: 1, remaining: 4, enforced: true });
    assert.equal(v.budget.portfolio.concurrency.remaining, 2);
    assert.equal(v.budget.repositories.a.spendUsd.limit, 2);
    assert.equal(v.budget.repositories.b.spendUsd.enforced, false, 'no repository limit for b: said plainly, not shown as unlimited-by-default');
    assert.equal(v.budget.repositories.b.spendUsd.remaining, null);
    assert.equal(buildProgressView({ store: readStore(file), now: T }).view.budget.declared, false);
  });

  test('[X-707.AC01] pending human review lists blocked units, unapproved contracts and unresolved boundaries, by kind', () => {
    const { s } = fixtureStore();
    const items = [
      ...reviewItemsFromInvariantCoverage({ invariants: [{ id: 'inv:1', key: 'orders-tenant', state: 'proposed' }, { id: 'inv:2', key: 'orders-ok', state: 'approved' }] }),
      ...reviewItemsFromBoundaryContexts([{ id: 'bctx:1', exposure: { state: 'unresolved' }, binding: { status: 'bound' }, finding: { repository: 'beta' } }, { id: 'bctx:2', exposure: { state: 'possible' }, binding: { status: 'bound' } }, { id: 'bctx:3', exposure: { state: 'possible' }, binding: { status: 'unbound' } }]),
    ];
    const rv = buildProgressView({ store: s, now: T, reviewItems: items }).view.review;
    assert.equal(rv.pending, 4);
    assert.deepEqual(rv.byKind, { 'blocked-unit': 1, 'boundary-resolution': 2, 'contract-approval': 1 });
    assert.ok(rv.items.some((i) => i.kind === 'contract-approval' && /advisory until a reviewer approves/.test(i.reason)));
    assert.equal(buildProgressView({ store: s, now: T }).view.review.pending, 1, 'without supplied sources only the blocked unit is pending');
  });

  test('[X-707.AC01] negative: a missing store or clock is a typed error, and a secret-shaped failure reason is withheld from the view', () => {
    assert.equal(buildProgressView({ now: T }).ok, false);
    assert.equal(buildProgressView({ store: newStore(manyUnitsPlan({ a: 1 })) }).errors[0].code, 'NO_NOW');
    const s = newStore(manyUnitsPlan({ a: 1 }));
    const id = Object.keys(s.units)[0];
    blockUnit(s, { unitId: id, reason: 'upstream said token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD was bad', now: T });
    const text = JSON.stringify(buildProgressView({ store: s, now: T }).view);
    assert.equal(text.includes('ghp_abcdef'), false);
    assert.match(text, /withheld: secret-shaped text/);
  });

  test('[X-707.AC01] the status view of a 3000-unit portfolio builds well inside the 2 second status bound', () => {
    const plan = manyUnitsPlan({ big: 2000, mid: 800, small: 200 });
    const s = newStore(plan);
    const t0 = Date.now();
    const r = buildProgressView({ store: s, now: T });
    const ms = Date.now() - t0;
    assert.equal(r.ok, true);
    assert.equal(r.view.units.total, 3000);
    assert.ok(ms < 2000, `built in ${ms} ms`);
  });
});

describe('[X-707.AC02] aggregate findings deduplicate by stable identity while preserving per-repository/environment evidence and separate affected releases', () => {
  const f = (stableId, over = {}) => ({ stableId, severity: 'medium', vuln: 'SQL injection', cwe: 'CWE-89', family: 'injection', file: 'src/db.js', line: 10, ...over });
  const entries = () => [
    { repository: 'shop', environment: 'prod', release: 'shop@2.1.0', commit: 'a'.repeat(40), finding: f('sid:aaa', { severity: 'high' }), evidenceRef: 'vrec:1' },
    { repository: 'shop', environment: 'staging', release: 'shop@2.2.0-rc1', commit: 'b'.repeat(40), finding: f('sid:aaa', { severity: 'medium' }) },
    { repository: 'billing', environment: 'prod', release: 'billing@9.0.0', commit: 'c'.repeat(40), finding: f('sid:aaa', { severity: 'high', file: 'lib/query.js', line: 44 }) },
    { repository: 'billing', environment: 'prod', release: 'billing@9.0.0', commit: 'c'.repeat(40), finding: f('sid:bbb', { severity: 'low', vuln: 'weak hash', cwe: 'CWE-328' }) },
  ];

  test('[X-707.AC02] one stable identity is one aggregate finding with every occurrence kept', () => {
    const a = aggregateFindings(entries());
    assert.equal(a.schema, FINDINGS_SCHEMA);
    assert.equal(a.occurrences, 4);
    assert.equal(a.unique, 2);
    const one = a.items.find((i) => i.identity === 'sid:aaa');
    assert.equal(one.occurrenceCount, 3);
    assert.deepEqual(one.repositories, ['billing', 'shop']);
    assert.deepEqual(one.environments, ['prod', 'staging']);
    assert.deepEqual(one.occurrences.map((o) => `${o.repository}/${o.environment}/${o.file}:${o.line}`), ['billing/prod/lib/query.js:44', 'shop/prod/src/db.js:10', 'shop/staging/src/db.js:10']);
    assert.equal(one.occurrences.find((o) => o.repository === 'shop' && o.environment === 'prod').evidenceRef, 'vrec:1');
    assert.equal(one.occurrences.find((o) => o.environment === 'staging').commit, 'b'.repeat(40), 'each occurrence keeps its own commit');
  });

  test('[X-707.AC02] affected releases are listed separately, per finding and per release, and severity differences stay visible', () => {
    const a = aggregateFindings(entries());
    const one = a.items.find((i) => i.identity === 'sid:aaa');
    assert.deepEqual(one.affectedReleases, ['billing@9.0.0', 'shop@2.1.0', 'shop@2.2.0-rc1']);
    assert.deepEqual(a.byRelease['shop@2.1.0'], ['sid:aaa']);
    assert.deepEqual(a.byRelease['billing@9.0.0'], ['sid:aaa', 'sid:bbb']);
    assert.equal(one.severity, 'high', 'the aggregate carries the worst severity');
    assert.deepEqual(one.severities, ['high', 'medium'], 'and the per-occurrence severities are not collapsed away');
  });

  test('[X-707.AC02] deduplication is by identity, never by text: same message, file and line with different stable ids stay two findings', () => {
    const a = aggregateFindings([
      { repository: 'r', finding: f('sid:one') }, { repository: 'r', finding: f('sid:two') },
    ]);
    assert.equal(a.unique, 2);
  });

  test('[X-707.AC02] a finding with no stable id is never merged: it is listed apart with the reason', () => {
    const a = aggregateFindings([{ repository: 'r', finding: f(undefined) }, { repository: 'r', finding: f(undefined) }, { repository: 'r', finding: f('') }]);
    assert.equal(a.unique, 0);
    assert.equal(a.unidentified.length, 3);
    assert.match(a.unidentified[0].note, /no stable id/);
  });

  test('[X-707.AC02] blocking findings are attributed to their repositories only, and malformed entries are skipped, not guessed', () => {
    const a = aggregateFindings([...entries(), null, { finding: f('sid:x') }, { repository: 'r' }, { repository: 7, finding: f('sid:y') }]);
    assert.deepEqual(a.repositoriesWithBlockingFindings, ['billing', 'shop']);
    assert.equal(a.occurrences, 4);
    assert.deepEqual(aggregateFindings(entries(), { blockingSeverity: 'critical' }).repositoriesWithBlockingFindings, []);
    assert.deepEqual(aggregateFindings([entries()[3]]).repositoriesWithBlockingFindings, [], 'a low finding does not block at the default threshold');
  });

  test('[X-707.AC02] aggregation is order independent and a secret-shaped description never enters the view', () => {
    const e = entries();
    assert.deepEqual(aggregateFindings(e), aggregateFindings([...e].reverse()));
    const leak = aggregateFindings([{ repository: 'r', finding: f('sid:z', { vuln: 'key AKIAIOSFODNN7EXAMPLE leaked', description: 'AKIAIOSFODNN7EXAMPLE' }) }]);
    const text = JSON.stringify(leak);
    assert.equal(text.includes('AKIAIOSFODNN7EXAMPLE'), false);
  });

  test('[X-707.AC02] the view embeds the aggregate when findings are supplied and omits it (null) when they are not', () => {
    const { s } = fixtureStore();
    assert.equal(buildProgressView({ store: s, now: T }).view.findings, null);
    const v = buildProgressView({ store: s, now: T, findings: entries() }).view;
    assert.equal(v.findings.unique, 2);
    assert.equal(v.completion.findingsSupplied, true);
  });
});

describe('[X-707.AC03] progress updates within the declared heartbeat bounds, stale workers remain visible, and a completed controller does not imply every repository passed', () => {
  test('[X-707.AC03] the declared bounds are a 5 second heartbeat and a 15 second stale threshold, and the view carries them', () => {
    assert.equal(HEARTBEAT.intervalMs, 5000);
    assert.equal(HEARTBEAT.staleAfterMs, 15000);
    const { s } = fixtureStore();
    assert.deepEqual(buildProgressView({ store: s, now: T }).view.heartbeat, { intervalMs: 5000, staleAfterMs: 15000 });
  });

  test('[X-707.AC03] a worker is live up to 15 s without a heartbeat and stale after, exactly at the boundary, and the stale one stays listed', () => {
    const dir = mkTestTmp('hb-'); const file = path.join(dir, 's.json');
    openStore(file, manyUnitsPlan({ a: 3 }));
    const b = BIG_BUDGETS({ concurrency: 3 });
    const l1 = scheduleNext(file, { budgets: b, estimateOf, holder: 'quiet', now: T, ttlMs: 600_000 });
    const l2 = scheduleNext(file, { budgets: b, estimateOf, holder: 'chatty', now: T, ttlMs: 600_000 });
    heartbeat(file, { unitId: l2.lease.unitId, attemptId: l2.lease.attemptId, now: T + 14_000, ttlMs: 600_000 });
    const view = (now) => buildProgressView({ store: readStore(file), ledger: readLedger(file), now }).view.workers;
    const at15 = view(T + 15_000);
    assert.equal(at15.items.find((w) => w.holder === 'quiet').status, 'live', 'exactly 15000 ms of silence is still within the bound');
    const at15001 = view(T + 15_001);
    const quiet = at15001.items.find((w) => w.holder === 'quiet');
    assert.equal(quiet.status, 'stale');
    assert.equal(quiet.ageMs, 15_001);
    assert.equal(at15001.items.find((w) => w.holder === 'chatty').status, 'live', 'a heartbeat 1 s ago keeps its worker live');
    assert.equal(at15001.stale, 1);
    const later = view(T + 40_000);
    assert.equal(later.items.length, 2, 'both workers are still listed');
    assert.equal(later.stale, 2);
    assert.equal(later.items.find((w) => w.holder === 'chatty').lastSignalAt, T + 14_000);
    // and the stale worker shows up in the headline lines, not only in the detail
    assert.match(buildProgressView({ store: readStore(file), ledger: readLedger(file), now: T + 40_000 }).view.lines.join('\n'), /2 stale or silent/);
  });

  test('[X-707.AC03] a worker that never sent a heartbeat is measured from its lease, so a silent worker cannot look live', () => {
    const s = newStore(manyUnitsPlan({ a: 1 }));
    const id = Object.keys(s.units)[0];
    leaseUnit(s, { holder: 'mute', now: T, ttlMs: 600_000, unitId: id });
    assert.equal(buildProgressView({ store: s, now: T + 1000 }).view.workers.items[0].status, 'live');
    assert.equal(buildProgressView({ store: s, now: T + 20_000 }).view.workers.items[0].status, 'stale');
  });

  test('[X-707.AC03] the driver heartbeats on its own cadence while an attempt runs, with no help from the worker\'s output', async () => {
    const dir = mkTestTmp('hb2-'); const file = path.join(dir, 's.json');
    openStore(file, manyUnitsPlan({ a: 1 }));
    // the executor writes nothing and returns nothing for 400 ms; heartbeats are recorded by the driver at 40 ms
    await runScheduled({ file, budgets: BIG_BUDGETS(), estimateOf, executor: async (u) => { await new Promise((r) => setTimeout(r, 400)); return ok(u); }, workers: 1, heartbeatMs: 40 });
    const u = Object.values(readStore(file).units)[0];
    const beats = u.events.filter((e) => e.type === 'renewed');
    assert.ok(beats.length >= 5, `expected several heartbeats during a 400 ms attempt at 40 ms, got ${beats.length}`);
    assert.equal(u.state, 'verified');
  });

  test('[X-707.AC03] a finished controller with unverified units says so and never implies success', () => {
    const { s } = fixtureStore();
    // an operator stopped the run: nothing is leased or pending any more, only verified, failed and canceled units remain
    cancelUnits(s, { reason: 'stopped for review', now: T });
    const c = buildProgressView({ store: s, now: T }).view.completion;
    assert.equal(c.controllerFinished, true);
    assert.equal(c.allUnitsVerified, false);
    assert.equal(c.passAssessment, 'not-implied');
    assert.match(c.statement, /controller has finished, but \d+ of \d+ unit\(s\) are not verified/);
    assert.match(c.statement, /does not mean any repository passed/);
    assert.equal(/\bsafe\b/i.test(c.statement), false);
  });

  test('[X-707.AC03] even with every unit verified, the view does not say every repository passed, and shows blocking findings when supplied', () => {
    const s = newStore(manyUnitsPlan({ a: 2, b: 2 }));
    for (const id of Object.keys(s.units)) verify(s, id);
    const bare = buildProgressView({ store: s, now: T }).view;
    assert.equal(bare.completion.controllerFinished, true);
    assert.equal(bare.completion.allUnitsVerified, true);
    assert.match(bare.completion.statement, /does not mean every repository passed \(findings were not supplied/);
    const withFindings = buildProgressView({ store: s, now: T, findings: [{ repository: 'b', finding: { stableId: 'sid:1', severity: 'critical', vuln: 'x' } }] }).view;
    assert.deepEqual(withFindings.completion.repositoriesWithBlockingFindings, ['b']);
    assert.match(withFindings.completion.statement, /1 repository has high-or-worse findings/);
    assert.match(withFindings.lines.join('\n'), /not independent certification/, 'the not-a-guarantee line is always present');
  });

  test('[X-707.AC03] a controller still working says it has not finished', () => {
    const { s } = fixtureStore();
    const c = buildProgressView({ store: s, now: T }).view.completion;
    assert.equal(c.controllerFinished, false);
    assert.match(c.statement, /has not finished/);
  });
});

describe('[X-707] behind the portfolio-assurance feature: off by default means existing output is unchanged', () => {
  const pins = JSON.parse(fs.readFileSync(new URL('../fixtures/portfolio/pre-change-pins.json', import.meta.url), 'utf8'));

  test('[X-707.AC01] flag off: the fleet rollup, its summary and its HTML are byte-identical to the output pinned before this feature existed', () => {
    const rollup = rollupFleet(FLEET_RESULTS);
    assert.deepEqual(JSON.parse(JSON.stringify(rollup)), pins.rollup);
    assert.equal(renderFleetSummary(rollup), pins.summary);
    assert.equal(renderFleetHtml(rollup, FLEET_RESULTS), pins.html);
    const { s } = fixtureStore();
    const attached = attachPortfolioProgress(rollup, { config: cfg(), store: s, now: T });
    assert.equal(attached, rollup, 'off: the very same object comes back');
    assert.deepEqual(portfolioProgressFields({ config: cfg(), store: s, now: T }), {});
    assert.equal(renderFleetSummary(attached), pins.summary);
  });

  test('[X-707.AC01] flag on: every pinned field is still there unchanged, and the portfolio clause is added after them, separately', () => {
    const { s } = fixtureStore();
    const on = attachPortfolioProgress(rollupFleet(FLEET_RESULTS), { config: cfg(ON), store: s, now: T });
    assert.ok(on.portfolioProgress);
    const { portfolioProgress, ...rest } = on;
    assert.deepEqual(JSON.parse(JSON.stringify(rest)), pins.rollup);
    const summary = renderFleetSummary(on);
    assert.ok(summary.startsWith(pins.summary.replace(/\.$/, '')), 'the existing sentence is untouched');
    assert.match(summary, / PORTFOLIO: 4\/9 unit\(s\) verified, 1\/3 repo\(s\) fully verified, 1 pending human review;/);
    // the page leads with the same summary sentence, so it carries the clause too; everything else on the page is byte-identical
    assert.equal(renderFleetHtml(on, FLEET_RESULTS).replace(summary, pins.summary), pins.html);
  });

  test('[X-707.AC01] the kill switch beats the flag', () => {
    const { s } = fixtureStore();
    assert.deepEqual(portfolioProgressFields({ config: cfg({ ...ON, AGENTIC_SECURITY_NO_PORTFOLIO_ASSURANCE: '1' }), store: s, now: T }), {});
  });

  function fixtureFiles() {
    const dir = mkTestTmp('cli-'); const file = path.join(dir, 'store.json');
    openStore(file, manyUnitsPlan({ alpha: 2, beta: 1 }));
    return { dir, file };
  }

  test('[X-707.AC01] the CLI is disabled by default (exit 1, nothing read) and prints the same view when the feature is on', async () => {
    const { dir, file } = fixtureFiles();
    let err = ''; let out = '';
    const off = await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: { store: file } }, { cwd: dir, env: {}, out: (x) => { out += x; }, err: (x) => { err += x; } });
    assert.equal(off, 1);
    assert.match(err, /disabled/);
    assert.equal(out, '');
    const on = await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: { store: 'store.json', json: true, now: String(T) } }, { cwd: dir, env: ON, out: (x) => { out += x; }, err: (x) => { err += x; } });
    assert.equal(on, 0);
    const parsed = JSON.parse(out);
    assert.equal(parsed.units.total, 3);
    assert.deepEqual(parsed, buildProgressView({ store: readStore(file), ledger: readLedger(file), now: T }).view, 'the CLI and the library projection are the same object');
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: {} }, { cwd: dir, env: ON, err: () => {} }), 2);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'frobnicate'], flags: {} }, { cwd: dir, env: ON, err: () => {} }), 2);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: { store: 'missing.json' } }, { cwd: dir, env: ON, err: () => {} }), 1);
  });

  test('[X-707.AC01] a corrupt store is refused by the CLI, never summarised', async () => {
    const { dir, file } = fixtureFiles();
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    Object.values(doc.units)[0].state = 'verified';
    fs.writeFileSync(file, JSON.stringify(doc));
    let err = '';
    const code = await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: { store: file } }, { cwd: dir, env: ON, out: () => {}, err: (x) => { err += x; } });
    assert.equal(code, 1);
    assert.match(err, /STORE_CORRUPT/);
  });

  test('[X-707.AC03] the MCP tool is registered, classified read-only, confined to the session root, gated, and returns no secret', async () => {
    const tool = ALL_TOOLS.find((t) => t.name === 'portfolio_progress');
    assert.ok(tool);
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.equal(toolCapabilityFor('portfolio_progress').effect, 'read');
    const { dir, file } = fixtureFiles();
    fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify([{ repository: 'alpha', environment: 'prod', release: 'alpha@1', finding: { stableId: 'sid:m', severity: 'high', vuln: 'x' } }]));
    const { handleRequest } = createServer({ sessionRoot: dir });
    const call = async (args) => JSON.parse((await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'portfolio_progress', arguments: args } })).result.content[0].text);
    const KEY = 'AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE';
    const prior = process.env[KEY];
    try {
      delete process.env[KEY];
      assert.equal((await call({ store_file: 'store.json' })).status, 'disabled');
      process.env[KEY] = '1';
      const r = await call({ store_file: 'store.json', findings_file: 'findings.json', now: T });
      assert.equal(r.ok, true, JSON.stringify(r));
      assert.equal(r.view.units.total, 3);
      assert.equal(r.view.findings.unique, 1);
      assert.equal(r.view.completion.passAssessment, 'not-implied');
      assert.deepEqual(r.view, buildProgressView({ store: readStore(file), ledger: readLedger(file), now: T, findings: JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8')) }).view, 'MCP and library agree');
      for (const args of [{ store_file: '../x.json' }, { store_file: '/etc/passwd' }, { store_file: 'store.json', findings_file: '../../f.json' }]) {
        const bad = await call(args);
        assert.equal(bad.ok, false, JSON.stringify(args));
        assert.match(bad.reason, /path refused|escapes|outside/);
      }
      fs.writeFileSync(path.join(dir, 'bad.json'), '{"not":"a store"}');
      assert.equal((await call({ store_file: 'bad.json' })).ok, false);
    } finally { if (prior === undefined) delete process.env[KEY]; else process.env[KEY] = prior; }
  });
});

