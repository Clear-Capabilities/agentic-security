// Exposure window (requirement 5), the record store, and the unified view (requirement 8).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { computeExposureWindow, loadDeployments, formatExposureWindow, isAncestor, commitDate, MAX_DEPLOYMENTS } from '../../src/posture/dnr/exposure-window.js';
import { saveRecord, listRecords, latestRecord, hasTamperedRecords } from '../../src/posture/dnr/store.js';
import { buildLifecycleView, formatLifecycleView } from '../../src/posture/dnr/view.js';
import { saveProof } from '../../src/posture/proof-fabric/store.js';

function repoWithHistory() {
  const dir = mkTestTmp('dnr-git-');
  const git = (args, date) => { const r = spawnSync('git', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t', ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}) } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
  git(['init', '-q', '-b', 'main']);
  const commit = (name, date) => { fs.writeFileSync(path.join(dir, 'f.txt'), name); git(['add', '.']); git(['commit', '-q', '-m', name], date); return git(['rev-parse', 'HEAD']); };
  const base = commit('base', '2024-03-01T10:00:00Z');
  const intro = commit('introduce flaw', '2024-03-03T10:00:00Z');
  const mid = commit('unrelated', '2024-03-10T10:00:00Z');
  const fix = commit('fix flaw', '2024-03-21T10:00:00Z');
  return { dir, base, intro, mid, fix };
}
const finding = (intro) => ({ id: 'F1', stableId: 'F1', findingProvenance: { findingOrigin: { commit: intro, authorDate: '2024-03-03T10:00:00Z' } } });

test('window: the PRD example — introduced, deployed, fixed, deployed, telemetry from the 10th', () => {
  const { dir, base, intro, mid, fix } = repoWithHistory();
  const deployments = [
    { commit: base, deployedAt: '2024-03-02T09:00:00Z' },
    { commit: intro, deployedAt: '2024-03-04T09:00:00Z' },
    { commit: mid, deployedAt: '2024-03-12T09:00:00Z' },
    { commit: fix, deployedAt: '2024-03-23T09:00:00Z' },
  ];
  const w = computeExposureWindow({ finding: finding(intro), repo: dir, deployments, fixCommit: fix, telemetry: { start: '2024-03-10T00:00:00Z', end: '2024-04-01T00:00:00Z' } });
  assert.equal(w.status, 'complete');
  assert.equal(w.vulnerabilityIntroduced.at, '2024-03-03T10:00:00.000Z');
  assert.equal(w.firstVulnerableDeployment.at, '2024-03-04T09:00:00.000Z');
  assert.equal(w.fixCommitted.at, '2024-03-21T10:00:00.000Z');
  assert.equal(w.fixDeployed.at, '2024-03-23T09:00:00.000Z');
  assert.equal(w.observableWindow.start, '2024-03-10T00:00:00.000Z');
  assert.equal(w.observableWindow.end, '2024-03-23T09:00:00.000Z');
  assert.equal(w.unobservableBefore.start, '2024-03-04T09:00:00.000Z', 'exposure before telemetry is reported, not dropped');
  assert.equal(w.stillExposed, false);
  const text = formatExposureWindow(w);
  assert.match(text, /Vulnerability introduced: 2024-03-03/);
  assert.match(text, /Observable exposure window: 2024-03-10 to 2024-03-23/);
  assert.match(text, /Exposed but not observable: 2024-03-04 to 2024-03-10/);
});

test('window: nothing is invented — missing inputs are listed as unknown and the status says partial or unavailable', () => {
  const { dir, intro } = repoWithHistory();
  const none = computeExposureWindow({ finding: { id: 'F1' }, repo: dir });
  assert.equal(none.status, 'unavailable');
  assert.equal(none.vulnerabilityIntroduced, null); assert.equal(none.firstVulnerableDeployment, null); assert.equal(none.observableWindow, null);
  assert.ok(none.unknowns.length >= 3);
  const noFix = computeExposureWindow({ finding: finding(intro), repo: dir, deployments: [{ commit: intro, deployedAt: '2024-03-04T09:00:00Z' }], telemetry: { start: '2024-03-10T00:00:00Z', end: '2024-04-01T00:00:00Z' } });
  assert.equal(noFix.status, 'partial');
  assert.equal(noFix.stillExposed, true, 'the newest recorded deployment still contains the flaw');
  assert.equal(noFix.observableWindow.openEnded, true);
  assert.ok(noFix.unknowns.some((u) => /fix commit/.test(u)));
  assert.match(formatExposureWindow(noFix), /present \(fix not deployed\)/);
  const noTel = computeExposureWindow({ finding: finding(intro), repo: dir, deployments: [{ commit: intro, deployedAt: '2024-03-04T09:00:00Z' }] });
  assert.equal(noTel.observableWindow, null);
  assert.ok(noTel.unknowns.some((u) => /telemetry window/.test(u)));
});

test('window: a deployment git cannot resolve is surfaced, not assumed vulnerable or safe', () => {
  const { dir, intro } = repoWithHistory();
  const w = computeExposureWindow({ finding: finding(intro), repo: dir, deployments: [{ commit: 'deadbeefdeadbeef', deployedAt: '2024-03-05T00:00:00Z' }], telemetry: { start: '2024-03-01T00:00:00Z', end: '2024-04-01T00:00:00Z' } });
  assert.equal(w.unresolvedDeployments.length, 1);
  assert.equal(w.firstVulnerableDeployment, null);
  assert.ok(w.unknowns.some((u) => /could not be resolved/.test(u)));
  assert.equal(isAncestor(dir, 'deadbeefdeadbeef', intro), null);
  assert.equal(commitDate(dir, 'deadbeefdeadbeef'), null);
});

test('window: deployment history is validated, bounded and environment-filtered', () => {
  const dir = mkTestTmp('dnr-dep-');
  const f = (name, v) => { const p = path.join(dir, name); fs.writeFileSync(p, typeof v === 'string' ? v : JSON.stringify(v)); return p; };
  const ok = loadDeployments(f('a.json', { deployments: [{ commit: 'ABCDEF1', deployedAt: '2024-03-01T00:00:00Z', environment: 'prod' }, { commit: 'abcdef2', deployedAt: '2024-03-02T00:00:00Z', environment: 'staging' }] }), { environment: 'prod' });
  assert.equal(ok.deployments.length, 1); assert.equal(ok.deployments[0].commit, 'abcdef1');
  const bad = loadDeployments(f('b.json', [{ commit: 'not-hex', deployedAt: '2024-03-01T00:00:00Z' }, { commit: 'abcdef1', deployedAt: 'yesterday' }, 'str']));
  assert.equal(bad.deployments.length, 0); assert.equal(bad.problems.length, 3);
  assert.ok(loadDeployments(f('c.json', 'not json')).problems[0].includes('could not read'));
  assert.ok(loadDeployments(f('d.json', { nope: 1 })).problems.length);
  const big = loadDeployments(f('e.json', Array.from({ length: MAX_DEPLOYMENTS + 5 }, (_, i) => ({ commit: 'abcdef1', deployedAt: `2024-01-01T00:00:${String(i % 60).padStart(2, '0')}Z` }))));
  assert.equal(big.deployments.length, MAX_DEPLOYMENTS); assert.ok(big.problems.some((p) => /only the first/.test(p)));
  assert.ok(loadDeployments(path.join(dir, 'missing.json')).problems.length);
});

const root = () => { const d = mkTestTmp('dnr-store-'); fs.mkdirSync(path.join(d, '.git')); fs.mkdirSync(path.join(d, '.agentic-security'), { recursive: true }); return d; };

test('store: round trip, secrets scrubbed, tamper detected and never trusted', () => {
  const d = root();
  const s = saveRecord(d, 'F1', 'hunt', { verdict: 'OBSERVED', note: 'leaked ghp_abcdefghijklmnopqrstuvwxyz0123456789 here' });
  assert.equal(s.ok, true, s.reason);
  const text = fs.readFileSync(s.file, 'utf8');
  assert.doesNotMatch(text, /ghp_abcdefghijklmnopqrstuvwxyz0123456789/);
  assert.equal(latestRecord(d, 'F1', 'hunt').record.verdict, 'OBSERVED');
  fs.writeFileSync(s.file, text.replace('OBSERVED', 'NOT_OBSERVED'));
  assert.equal(listRecords(d, 'F1', 'hunt')[0].tampered, true);
  assert.equal(latestRecord(d, 'F1', 'hunt'), null, 'a tampered record is not served as the latest');
  assert.equal(hasTamperedRecords(d, 'F1', 'hunt'), true);
  assert.equal(saveRecord(d, 'F1', 'bogus-kind', {}).ok, false);
  assert.equal(listRecords(d, 'nope', 'hunt').length, 0);
});

test('store: a hostile finding id cannot escape the state directory', () => {
  const d = root();
  const s = saveRecord(d, '../../../etc/evil', 'hunt', { verdict: 'OBSERVED' });
  assert.equal(s.ok, true);
  assert.ok(s.file.startsWith(path.join(d, '.agentic-security', 'dnr')), s.file);
});

test('view: shows only what exists; an absent step is missing, not inferred', () => {
  const d = root();
  fs.writeFileSync(path.join(d, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: 'F1', stableId: 'F1', vuln: 'command injection', file: 'app.js', line: 9 }] }));
  let v = buildLifecycleView(d, 'F1');
  assert.equal(v.steps.FIND.status, 'done'); assert.match(v.steps.FIND.text, /Candidate finding/);
  for (const k of ['PROVE', 'HUNT', 'FIX', 'VERIFY', 'DETECT']) assert.equal(v.steps[k].status, 'missing', k);
  saveProof(d, { findingId: 'F1', state: 'EXPLOIT_CONFIRMED', attempts: { run: 3, successes: 3, required: 3 }, independentReplay: { status: 'confirmed' } });
  saveRecord(d, 'F1', 'hunt', { verdict: 'OBSERVED', window: { start: '2024-03-10T00:00:00Z', end: '2024-04-06T00:00:00Z' }, matches: { count: 2 } });
  saveRecord(d, 'F1', 'fix', { verified: true, completeness: 'FULL', legs: { postPatch: { attempts: 3, completed: 3, exploitSucceeded: 0 } } });
  saveRecord(d, 'F1', 'detection', { ir: { id: 'det-1' }, validation: { status: 'VALIDATED' }, proof: { recordDigest: 'x' } });
  v = buildLifecycleView(d, 'F1');
  assert.match(v.steps.FIND.text, /Confirmed vulnerability/);
  assert.equal(v.steps.PROVE.text, 'Exploit reproduced 3/3, independent replay confirmed');
  assert.match(v.steps.HUNT.text, /27 day\(s\) of telemetry searched, 2 matching event\(s\) observed/);
  assert.equal(v.steps.FIX.text, 'FULL verified remediation');
  assert.equal(v.steps.VERIFY.text, 'Original exploit blocked');
  assert.equal(v.steps.DETECT.text, 'Recurrence rule enabled (det-1)');
  assert.match(formatLifecycleView(v), /\[x\] DETECT/);
});

test('view: an unvalidated detection is not "enabled", and a tampered record is called out and not used', () => {
  const d = root();
  saveRecord(d, 'F2', 'detection', { ir: { id: 'det-2' }, validation: { status: 'FAILED' } });
  assert.equal(buildLifecycleView(d, 'F2').steps.DETECT.status, 'partial');
  assert.match(buildLifecycleView(d, 'F2').steps.DETECT.text, /not enabled/);
  const s = saveRecord(d, 'F2', 'fix', { verified: true, completeness: 'FULL', legs: { postPatch: { attempts: 3, completed: 3, exploitSucceeded: 0 } } });
  fs.writeFileSync(s.file, fs.readFileSync(s.file, 'utf8').replace('"FULL"', '"PARTIAL"'));
  const v = buildLifecycleView(d, 'F2');
  assert.equal(v.steps.FIX.status, 'missing');
  assert.deepEqual(v.tampered, ['fix']);
  assert.match(formatLifecycleView(v), /failed their integrity check/);
});
