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

// ── FR-1005 (assurance-hardening PRD): "Central rollups do not require
//    uploading repository source or unrestricted snippets." Structural
//    guard — same shape as label-isolation.test.js's FR-903 guard — proving
//    a raw source excerpt never survives into the per-repo result entry,
//    the aggregate rollup, or the rendered HTML page, not just asserting it
//    by reading the code once. ──

const SECRET_SNIPPET = 'const apiKey = "sk-live-should-never-leave-the-repo-0123456789";';

test('FR-1005: a finding carrying a raw source snippet never reaches the per-repo result entry', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({ r1: { findings: [finding({ snippet: SECRET_SNIPPET })] } }),
  });
  const entry = r.results.find((x) => x.repo === 'r1');
  assert.equal(JSON.stringify(entry).includes(SECRET_SNIPPET), false,
    `the per-repo entry must never carry a raw finding snippet, got: ${JSON.stringify(entry)}`);
  assert.ok(!('findings' in entry), 'the entry must not carry the raw findings array at all — only counts/ids/owners');
});

test('FR-1005: a finding carrying a raw source snippet never reaches the rollup or the rendered HTML page', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({ r1: { findings: [finding({ snippet: SECRET_SNIPPET, file: '/etc/very/secret/path.js' })] } }),
  });
  assert.equal(JSON.stringify(r.rollup).includes(SECRET_SNIPPET), false);
  const html = renderFleetHtml(r.rollup, r.results);
  assert.equal(html.includes(SECRET_SNIPPET), false,
    'the rendered fleet page must never contain a raw source snippet from any finding');
});

// ── FR-1006 (assurance-hardening PRD): "scan freshness" — WHEN a repo was
//    last scanned, not just whether it was. `state.completed[repo].at` used
//    to be a stub that was always null, never populated, never read
//    anywhere — confirmed by direct grep before this fix — the same as the
//    field not existing at all. ──

test('FR-1006: a successful scan stamps a real, non-null scannedAt on the result entry', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: { findings: [] } }) });
  const entry = r.results.find((x) => x.repo === 'r1');
  assert.equal(typeof entry.scannedAt, 'string');
  assert.ok(!Number.isNaN(Date.parse(entry.scannedAt)), `scannedAt must be a real, parseable timestamp, got: ${entry.scannedAt}`);
});

test('FR-1006: a FAILED scan also stamps a real scannedAt — the attempt happened even though it did not succeed', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: new Error('boom') }) });
  const entry = r.results.find((x) => x.repo === 'r1');
  assert.equal(entry.ok, false);
  assert.equal(typeof entry.scannedAt, 'string');
  assert.ok(!Number.isNaN(Date.parse(entry.scannedAt)));
});

test('FR-1006: the checkpoint records the SAME scannedAt the result entry carries, not a stub — this is the exact field that used to be hardcoded null', async () => {
  const dir = tmp();
  try {
    const stateFile = path.join(dir, 'state.json');
    const r = await runFleet({ repos: ['r1'], stateFile, runScan: fakeScan({ r1: { findings: [] } }) });
    const entry = r.results.find((x) => x.repo === 'r1');
    const state = loadFleetState(stateFile);
    assert.equal(state.completed.r1.at, entry.scannedAt);
    assert.notEqual(state.completed.r1.at, null, 'the checkpoint\'s "at" field must be a real timestamp, not the old always-null stub');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-1006: renderFleetHtml surfaces scan freshness — the scanned-at value appears in the rendered page for both a successful and a failed repo', async () => {
  const r = await runFleet({
    repos: ['r1', 'r2'],
    runScan: fakeScan({ r1: { findings: [] }, r2: new Error('boom') }),
  });
  const html = renderFleetHtml(r.rollup, r.results);
  const r1 = r.results.find((x) => x.repo === 'r1');
  const r2 = r.results.find((x) => x.repo === 'r2');
  assert.ok(html.includes(r1.scannedAt), 'the successful repo\'s scannedAt must appear in the rendered page');
  assert.ok(html.includes(r2.scannedAt), 'the FAILED repo\'s scannedAt must also appear — a failed attempt still happened at a real time');
  assert.match(html, /<th>scanned at<\/th>/);
});

// --- FR-1006: assurance-health (scanHealth) + policy drift, distinct from risk ---

test('FR-1006: a per-repo entry carries the scan\'s own scanHealth (FR-206), not re-derived', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({ r1: { findings: [], scanHealth: { schemaVersion: 1, status: 'partial', conditions: ['2 annotator(s) threw'] } } }),
  });
  assert.deepEqual(r.results[0].scanHealth, { schemaVersion: 1, status: 'partial', conditions: ['2 annotator(s) threw'] });
});

test('FR-1006: a scan with no scanHealth field degrades to null, never fabricated', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: { findings: [] } }) });
  assert.equal(r.results[0].scanHealth, null);
});

test('FR-1006: a repo with no policy bundles configured has policyDrift: null (no baseline to drift from)', async () => {
  const dir = tmp();
  try {
    const r = await runFleet({ repos: [dir], runScan: fakeScan({ [dir]: { findings: [] } }) });
    assert.equal(r.results[0].policyDrift, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-1006: a repository-scope override of an organization key is reported as policy drift', async () => {
  const dir = tmp();
  try {
    const { signPolicyBundle, buildPolicyBundle } = await import('../src/posture/policy-bundle.js');
    const { privateKey, publicKey } = (await import('node:crypto')).generateKeyPairSync('ed25519');
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const bundleDir = path.join(dir, '.agentic-security', 'policy-bundles');
    fs.mkdirSync(bundleDir, { recursive: true });
    fs.writeFileSync(path.join(bundleDir, 'organization.json'), JSON.stringify(signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high' }), privateKeyPem)));
    fs.writeFileSync(path.join(bundleDir, 'repository.json'), JSON.stringify(signPolicyBundle(buildPolicyBundle('repository', { severityFloor: 'low' }), privateKeyPem)));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'policy-bundle-public-key.pem'), publicKeyPem);

    const r = await runFleet({ repos: [dir], runScan: fakeScan({ [dir]: { findings: [] } }) });
    const drift = r.results[0].policyDrift;
    assert.ok(drift, 'expected a policyDrift object');
    assert.equal(drift.overrides.length, 1);
    assert.equal(drift.overrides[0].key, 'severityFloor');
    assert.equal(drift.overrides[0].organizationValue, 'high');
    assert.equal(drift.overrides[0].effectiveValue, 'low');
    assert.equal(drift.overrides[0].overriddenBy, 'repository');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-1006: a rejected (tampered) policy bundle is reported as drift too — the policy that should apply is silently not enforced', async () => {
  const dir = tmp();
  try {
    const { signPolicyBundle, buildPolicyBundle } = await import('../src/posture/policy-bundle.js');
    const { privateKey, publicKey } = (await import('node:crypto')).generateKeyPairSync('ed25519');
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const bundleDir = path.join(dir, '.agentic-security', 'policy-bundles');
    fs.mkdirSync(bundleDir, { recursive: true });
    const signed = signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high' }), privateKeyPem);
    const tampered = { ...signed, policy: { severityFloor: 'low' } };
    fs.writeFileSync(path.join(bundleDir, 'organization.json'), JSON.stringify(tampered));
    fs.writeFileSync(path.join(dir, '.agentic-security', 'policy-bundle-public-key.pem'), publicKeyPem);

    const r = await runFleet({ repos: [dir], runScan: fakeScan({ [dir]: { findings: [] } }) });
    const drift = r.results[0].policyDrift;
    assert.ok(drift, 'expected a policyDrift object');
    assert.equal(drift.rejected.length, 1);
    assert.equal(drift.rejected[0].scope, 'organization');
    assert.match(drift.rejected[0].reason, /modified after signing/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-1006: rollupFleet counts governance gaps SEPARATELY from risk findings', () => {
  const results = [
    { repo: 'clean', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [], scanHealth: { status: 'complete' }, policyDrift: null },
    { repo: 'partial-health', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [], scanHealth: { status: 'partial', conditions: ['x'] }, policyDrift: null },
    { repo: 'drifted', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [], scanHealth: { status: 'complete' }, policyDrift: { accepted: [], rejected: [], overrides: [{ key: 'a', organizationValue: 1, effectiveValue: 2, overriddenBy: 'repository' }] } },
  ];
  const rollup = rollupFleet(results);
  assert.equal(rollup.reposWithPartialScanHealth, 1);
  assert.equal(rollup.reposWithPolicyDrift, 1);
  assert.equal(rollup.total, 0, 'zero risk findings even though 2 of 3 repos have a governance gap — the two must not be conflated');
});

test('FR-1006: renderFleetSummary reports governance gaps in a clause separate from the risk sentence', () => {
  const rollup = rollupFleet([
    { repo: 'r1', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [], scanHealth: { status: 'partial', conditions: ['x'] }, policyDrift: null },
  ]);
  const summary = renderFleetSummary(rollup);
  assert.match(summary, /GOVERNANCE:/);
  assert.match(summary, /1 repo\(s\) with a partial/);
});

test('FR-1006: renderFleetHtml puts risk findings and governance gaps in SEPARATE sections', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({ r1: { findings: [finding()], scanHealth: { status: 'partial', conditions: ['1 annotator(s) threw'] } } }),
  });
  const html = renderFleetHtml(r.rollup, r.results);
  assert.match(html, /<h2>Risk findings<\/h2>/);
  assert.match(html, /<h2>Governance \/ coverage gaps<\/h2>/);
  assert.match(html, /partial: 1 annotator\(s\) threw/);
  // the governance table must come AFTER the risk table, not interleaved.
  assert.ok(html.indexOf('Risk findings') < html.indexOf('Governance'));
});

test('FR-1006: renderFleetHtml reports "nothing to report" when no repo has a governance gap', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: { findings: [] } }) });
  const html = renderFleetHtml(r.rollup, r.results);
  assert.match(html, /Nothing to report/);
});

test('FR-1005 extended to FR-1006: scanHealth/policyDrift never carry a raw finding snippet — they are governance metadata, not finding data', async () => {
  const SECRET_SNIPPET = 'const apiKey = "sk-live-should-never-leave-the-repo-0123456789";';
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({
      r1: {
        findings: [finding({ snippet: SECRET_SNIPPET })],
        scanHealth: { schemaVersion: 1, status: 'partial', conditions: ['1 annotator(s) threw: why-fired'] },
      },
    }),
  });
  const html = renderFleetHtml(r.rollup, r.results);
  assert.ok(!JSON.stringify(r.results[0].scanHealth).includes(SECRET_SNIPPET));
  assert.ok(!html.includes(SECRET_SNIPPET));
});

// ── M4 §4.4: provenance-aware fleet debt / MTTR rollups ────────────────────
//
// The real per-repo entry that `runFleet` produces does NOT carry a `scan`
// key or a raw findings array at all (FR-1005, asserted above — `!('findings'
// in entry)`); `provenanceDebt`/`mttr` are DERIVED summaries the worker
// computes from the untrimmed findings before trimming the entry down, same
// pattern as `owners`/`scanHealth`/`policyDrift`. Tests below build entries
// in that real shape (`{ repo, ok, total, bySeverity, proven, ids,
// provenanceDebt, mttr }`), matching the existing FR-1006 tests above, plus
// end-to-end tests through `runFleet` with a `fakeScan` that returns raw
// `findingProvenance`-bearing findings and a `scan.mttr` aggregate.

const completeFinding = (over = {}) => finding({
  findingProvenance: { status: 'complete', findingOrigin: { authorDate: '2020-01-01T00:00:00Z' } },
  ...over,
});

test('M4 §4.4: rollupFleet computes oldestProvenDebt from complete-status findingProvenance only', () => {
  const results = [
    {
      repo: 'repo-a', ok: true, total: 1, bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, proven: 0, ids: ['f1'],
      provenanceDebt: { oldest: { findingId: 'f1', authorDate: '2020-01-01T00:00:00Z', ageDays: 2000 }, completeCount: 1 },
      mttr: null,
    },
    {
      // Older by authorDate, but its status is 'partial' — must NOT win. Since
      // `provenanceDebt` is computed from complete-status findings only, a repo
      // whose only findingProvenance is 'partial' surfaces no `oldest` at all.
      repo: 'repo-b', ok: true, total: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, proven: 0, ids: ['f2'],
      provenanceDebt: { oldest: null, completeCount: 0 },
      mttr: null,
    },
  ];
  const rollup = rollupFleet(results);
  assert.equal(rollup.provenance.oldestProvenDebt.repo, 'repo-a');
  assert.equal(rollup.provenance.oldestProvenDebt.ageDays, 2000);
  assert.deepEqual(rollup.provenance.reposWithNoProvenDebt, ['repo-b']);
});

test('M4 §4.4: a repo with zero complete-status findings is disclosed in reposWithNoProvenDebt, not silently omitted', () => {
  const results = [
    {
      repo: 'repo-c', ok: true, total: 1, bySeverity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, proven: 0, ids: ['f3'],
      provenanceDebt: { oldest: null, completeCount: 0 },
      mttr: null,
    },
  ];
  const rollup = rollupFleet(results);
  assert.equal(rollup.provenance.oldestProvenDebt, null);
  assert.ok(rollup.provenance.reposWithNoProvenDebt.includes('repo-c'));
});

test('M4 §4.4: a results entry with no provenanceDebt at all (older checkpoint / hand-built fixture) degrades to "no proven debt", not a crash', () => {
  const results = [
    { repo: 'legacy', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [] },
  ];
  const rollup = rollupFleet(results);
  assert.equal(rollup.provenance.oldestProvenDebt, null);
  assert.deepEqual(rollup.provenance.reposWithNoProvenDebt, ['legacy']);
});

test('M4 §4.4: rollupFleet computes a count-weighted fleet MTTR from each repo\'s own scan.mttr aggregate', () => {
  const results = [
    {
      repo: 'a', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [],
      provenanceDebt: { oldest: null, completeCount: 0 }, mttr: { count: 2, meanDays: 10, medianDays: 10, perSeverity: {} },
    },
    {
      repo: 'b', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [],
      provenanceDebt: { oldest: null, completeCount: 0 }, mttr: { count: 1, meanDays: 40, medianDays: 40, perSeverity: {} },
    },
  ];
  const rollup = rollupFleet(results);
  assert.equal(rollup.provenance.mttr.n, 3);
  // weighted mean: (2*10 + 1*40) / 3 = 20
  assert.equal(rollup.provenance.mttr.meanDays, 20);
  assert.deepEqual(rollup.provenance.mttr.byAgeBasis, {}, 'no scan.remediatedFindings array exists anywhere to derive a real ageBasis breakdown from — an empty object is honest, a fabricated one would not be');
});

test('M4 §4.4: renderFleetSummary mentions provenance debt honestly (repo+age, or an explicit "none" line)', () => {
  const withDebt = rollupFleet([
    {
      repo: 'repo-a', ok: true, total: 1, bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, proven: 0, ids: ['f1'],
      provenanceDebt: { oldest: { findingId: 'f1', authorDate: '2020-01-01T00:00:00Z', ageDays: 2000 }, completeCount: 1 },
      mttr: null,
    },
  ]);
  const summaryWithDebt = renderFleetSummary(withDebt);
  assert.match(summaryWithDebt, /proven|provenance/i);
  assert.match(summaryWithDebt, /repo-a/);
  assert.match(summaryWithDebt, /2000d/);

  const withNone = rollupFleet([
    { repo: 'repo-c', ok: true, total: 0, bySeverity: {}, proven: 0, ids: [], provenanceDebt: { oldest: null, completeCount: 0 }, mttr: null },
  ]);
  const summaryWithNone = renderFleetSummary(withNone);
  assert.match(summaryWithNone, /no proven-origin findings/i);
});

test('M4 §4.4: runFleet threads a per-repo provenanceDebt derived from findingProvenance onto the result entry, end to end', async () => {
  const r = await runFleet({
    repos: ['r1', 'r2'],
    runScan: fakeScan({
      r1: { findings: [completeFinding({ stableId: 'old-one', findingProvenance: { status: 'complete', findingOrigin: { authorDate: '2015-06-01T00:00:00Z' } } })] },
      r2: { findings: [finding({ findingProvenance: { status: 'partial', findingOrigin: { authorDate: '2001-01-01T00:00:00Z' } } })] },
    }),
  });
  const e1 = r.results.find((x) => x.repo === 'r1');
  const e2 = r.results.find((x) => x.repo === 'r2');
  assert.ok(e1.provenanceDebt.oldest, 'complete-status finding should produce an oldest debt entry');
  assert.equal(e1.provenanceDebt.oldest.findingId, 'old-one');
  assert.equal(e2.provenanceDebt.oldest, null, 'partial-status-only repo must not surface an oldest debt entry, despite an older authorDate');
  assert.equal(r.rollup.provenance.oldestProvenDebt.repo, 'r1');
  assert.ok(r.rollup.provenance.reposWithNoProvenDebt.includes('r2'));
});

test('M4 §4.4: provenanceDebt on the per-repo entry never carries a raw finding snippet, file, or line — id/date/age only (FR-1005 extended)', async () => {
  const SECRET_SNIPPET = 'const apiKey = "sk-live-should-never-leave-the-repo-0123456789";';
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({
      r1: { findings: [completeFinding({ snippet: SECRET_SNIPPET, file: '/etc/very/secret/path.js' })] },
    }),
  });
  const entry = r.results.find((x) => x.repo === 'r1');
  assert.ok(!JSON.stringify(entry.provenanceDebt).includes(SECRET_SNIPPET));
  assert.ok(!JSON.stringify(entry.provenanceDebt).includes('/etc/very/secret/path.js'));
  const html = renderFleetHtml(r.rollup, r.results);
  assert.ok(!html.includes(SECRET_SNIPPET));
});

test('M4 §4.4: runFleet threads scan.mttr through onto the result entry when the injected scanner provides it', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({ r1: { findings: [], mttr: { count: 3, meanDays: 5, medianDays: 5, perSeverity: {} } } }),
  });
  const entry = r.results.find((x) => x.repo === 'r1');
  assert.deepEqual(entry.mttr, { count: 3, meanDays: 5, medianDays: 5, perSeverity: {} });
  assert.equal(r.rollup.provenance.mttr.n, 3);
});

test('M4 §4.4: a FAILED repo carries provenanceDebt:null and mttr:null, not a fabricated zero', async () => {
  const r = await runFleet({ repos: ['boom'], runScan: fakeScan({ boom: new Error('parser exploded') }) });
  const entry = r.results.find((x) => x.repo === 'boom');
  assert.equal(entry.provenanceDebt, null);
  assert.equal(entry.mttr, null);
});

test('M4 §4.4: renderFleetHtml adds a separate "Provenance-Proven Debt" section listing the oldest finding per repo and an MTTR line', async () => {
  const r = await runFleet({
    repos: ['r1'],
    runScan: fakeScan({
      r1: { findings: [completeFinding({ stableId: 'x1' })], mttr: { count: 1, meanDays: 12, medianDays: 12, perSeverity: {} } },
    }),
  });
  const html = renderFleetHtml(r.rollup, r.results);
  assert.match(html, /<h2>Provenance-Proven Debt<\/h2>/);
  assert.match(html, /r1/);
  assert.match(html, /Fleet MTTR: 1 remediated finding/);
  // the provenance section must come after both the risk and governance sections.
  assert.ok(html.indexOf('Governance') < html.indexOf('Provenance-Proven Debt'));
});

test('M4 §4.4: renderFleetHtml reports the no-remediation-yet case honestly rather than a fabricated MTTR', async () => {
  const r = await runFleet({ repos: ['r1'], runScan: fakeScan({ r1: { findings: [] } }) });
  const html = renderFleetHtml(r.rollup, r.results);
  assert.match(html, /No complete-status \(proven-origin\) findings across the fleet/);
  assert.match(html, /Fleet MTTR: no remediated findings recorded yet/);
});
