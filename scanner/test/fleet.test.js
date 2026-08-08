// PRD Epic 5 — fleet orchestration.
//
// The four properties tested here are each a failure mode when absent, and
// three of them are silent: a fleet run that dies partway, or folds a crashed
// repo into "0 findings", or reports a count delta instead of which findings
// are new, all LOOK like successful scans.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  runFleet, rollupFleet, ownersFor, renderFleetSummary, renderFleetHtml, loadFleetState,
} from '../src/posture/fleet.js';

const finding = (over = {}) => ({
  stableId: 'id-' + Math.random().toString(36).slice(2, 8),
  severity: 'critical', file: 'src/app.js', line: 2, vuln: 'V', ...over,
});

// A fake scanner: maps repo -> scan result, or throws for repos marked to fail.
function fakeScan(map) {
  return async (repo) => {
    const v = map[repo];
    if (v instanceof Error) throw v;
    return { scan: v || { findings: [] } };
  };
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-'));

test('scans many repos and rolls them up', async () => {
  const repos = ['r1', 'r2', 'r3'];
  const r = await runFleet({
    repos, concurrency: 2, runScan: fakeScan({
      r1: { findings: [finding(), finding({ severity: 'high' })] },
      r2: { findings: [finding({ severity: 'low' })] },
      r3: { findings: [] },
    }),
  });
  assert.equal(r.ok, true);
  assert.equal(r.rollup.repos, 3);
  assert.equal(r.rollup.scanned, 3);
  assert.equal(r.rollup.total, 3);
  assert.equal(r.rollup.bySeverity.critical, 1);
  assert.equal(r.rollup.bySeverity.high, 1);
});

test('a repo that throws is FAILED, never folded into zero findings', async () => {
  // The silent-zero failure: a crashed repo counted as clean makes a fleet
  // report say everything is fine because nothing ran.
  const r = await runFleet({
    repos: ['ok', 'boom'], concurrency: 2,
    runScan: fakeScan({ ok: { findings: [finding()] }, boom: new Error('parser exploded') }),
  });
  assert.equal(r.rollup.scanned, 1);
  assert.equal(r.rollup.failed, 1);
  assert.equal(r.rollup.failures[0].repo, 'boom');
  assert.match(r.rollup.failures[0].error, /parser exploded/);
  const failedEntry = r.results.find(x => x.repo === 'boom');
  assert.equal(failedEntry.total, null, 'a failed repo must not report a finding count');
});

test('one exploding repo does not take the run down', async () => {
  const repos = ['a', 'b', 'c', 'd'];
  const r = await runFleet({
    repos, concurrency: 2,
    runScan: fakeScan({ a: { findings: [finding()] }, b: new Error('x'), c: new Error('y'), d: { findings: [finding()] } }),
  });
  assert.equal(r.results.length, 4, 'every repo must be accounted for');
  assert.equal(r.rollup.scanned, 2);
  assert.equal(r.rollup.failed, 2);
});

test('the run is resumable — completed repos are skipped', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'fleet.json');
    const seen = [];
    const scan = async (repo) => { seen.push(repo); return { scan: { findings: [finding()] } }; };

    await runFleet({ repos: ['r1', 'r2'], stateFile, runScan: scan, concurrency: 1 });
    assert.deepEqual(seen, ['r1', 'r2']);

    // Second invocation with a superset: only the new repo is scanned.
    seen.length = 0;
    const second = await runFleet({ repos: ['r1', 'r2', 'r3'], stateFile, runScan: scan, concurrency: 1 });
    assert.deepEqual(seen, ['r3'], 'completed repos were re-scanned');
    assert.deepEqual(second.skipped, ['r1', 'r2']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the checkpoint is written per repo, so a kill mid-run still resumes', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'fleet.json');
    let n = 0;
    const scan = async () => {
      if (++n === 2) throw new Error('killed');
      return { scan: { findings: [] } };
    };
    await runFleet({ repos: ['r1', 'r2', 'r3'], stateFile, runScan: scan, concurrency: 1 });
    const state = loadFleetState(stateFile);
    assert.ok(state.completed.r1, 'the repo completed before the failure was not checkpointed');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('resume:false rescans everything', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'fleet.json');
    const seen = [];
    const scan = async (r) => { seen.push(r); return { scan: { findings: [] } }; };
    await runFleet({ repos: ['r1'], stateFile, runScan: scan });
    seen.length = 0;
    await runFleet({ repos: ['r1'], stateFile, runScan: scan, resume: false });
    assert.deepEqual(seen, ['r1']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('concurrency is bounded', async () => {
  let inFlight = 0, peak = 0;
  const scan = async () => {
    inFlight++; peak = Math.max(peak, inFlight);
    await new Promise(r => setTimeout(r, 5));
    inFlight--;
    return { scan: { findings: [] } };
  };
  await runFleet({ repos: Array.from({ length: 20 }, (_, i) => `r${i}`), concurrency: 3, runScan: scan });
  assert.ok(peak <= 3, `concurrency exceeded its bound (peak ${peak})`);
});

test('delta is by stable id, not by count', async () => {
  // "3 more criticals than last week" says nothing about WHICH. A scheduled run
  // has to notify on the new ones.
  const before = { results: [{ repo: 'r1', ok: true, ids: ['keep-1', 'keep-2'] }] };
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({
      r1: { findings: [finding({ stableId: 'keep-1' }), finding({ stableId: 'brand-new' })] },
    }),
    previous: before,
  });
  assert.deepEqual(r.rollup.newFindings.r1, ['brand-new']);
  // A finding that disappeared must not show up as new.
  assert.ok(!r.rollup.newFindings.r1.includes('keep-2'));
});

test('no previous run means no delta section, rather than everything being "new"', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: { findings: [finding()] } }) });
  assert.equal(r.rollup.newFindings, undefined);
});

// --- owner routing ---------------------------------------------------------

test('CODEOWNERS routing uses last-match-wins', () => {
  // First-match would route everything to the most general owner — the one
  // least able to act on the finding.
  const co = [
    '*            @org/everyone',
    '/src/api/    @org/api-team',
    '/src/api/billing/** @org/billing',
  ].join('\n');
  assert.deepEqual(ownersFor(co, 'README.md'), ['@org/everyone']);
  assert.deepEqual(ownersFor(co, 'src/api/routes.js'), ['@org/api-team']);
  assert.deepEqual(ownersFor(co, 'src/api/billing/charge.js'), ['@org/billing']);
});

test('CODEOWNERS comments and blank lines are ignored', () => {
  const co = '# a comment\n\n*  @org/all\n# /src/ @org/nobody\n';
  assert.deepEqual(ownersFor(co, 'src/x.js'), ['@org/all']);
});

test('no CODEOWNERS means no owners, not a guess', () => {
  assert.deepEqual(ownersFor(null, 'a.js'), []);
  assert.deepEqual(ownersFor('', 'a.js'), []);
});

test('findings are routed to owners during a fleet run', async () => {
  const dir = tmp();
  try {
    fs.writeFileSync(path.join(dir, 'CODEOWNERS'), '*  @org/all\n/src/  @org/src-team\n');
    const r = await runFleet({
      repos: [dir],
      runScan: fakeScan({ [dir]: { findings: [finding({ stableId: 's1', file: 'src/app.js' })] } }),
    });
    assert.deepEqual(r.results[0].owners['@org/src-team'], ['s1']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// --- reporting -------------------------------------------------------------

test('the summary leads with failures when there are any', () => {
  const rollup = rollupFleet([
    { repo: 'a', ok: true, total: 1, bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, proven: 1, ids: [] },
    { repo: 'b', ok: false, error: 'boom', ids: [] },
  ]);
  const line = renderFleetSummary(rollup);
  assert.match(line, /^1 of 2 repo\(s\) FAILED/);
  assert.match(line, /unknown, not zero/);
});

test('the rollup page is self-contained and marks failed repos', () => {
  // PRD AC3: renders fully offline from local artifacts.
  const results = [
    { repo: 'a', ok: true, total: 1, bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, proven: 1, ids: [] },
    { repo: 'b', ok: false, error: 'boom', ids: [] },
  ];
  const html = renderFleetHtml(rollupFleet(results), results);
  assert.match(html, /SCAN FAILED/);
  assert.ok(!/https?:\/\//.test(html), 'the rollup must not reference anything external');
  assert.ok(!/<script/i.test(html), 'no scripts — it must render on an air-gapped machine');
});

test('repo names are escaped into the page', () => {
  const results = [{ repo: '<img src=x onerror=alert(1)>', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [] }];
  const html = renderFleetHtml(rollupFleet(results), results);
  assert.ok(!html.includes('<img src=x'), 'a repo name was injected into the report unescaped');
  assert.match(html, /&lt;img/);
});

test('runFleet refuses without a scanner rather than reporting an empty fleet', async () => {
  const r = await runFleet({ repos: ['a'] });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no runScan/);
});
