// The release orchestrator (scripts/ship/): its decisions in isolation, and the whole flow against a scripted git and gh.
// No network, no repository, no real clock: every effect is injected.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chooseReleaseSha, parseChecks, classifyChecks, findStuckJobs, classifyReleaseFailure, npmFacts, preflightProblems, cmpVersions, ShipState, waitFor } from '../../scripts/ship/lib.mjs';
import { runShip } from '../../scripts/ship/run.mjs';

const T = (c) => c.repeat(40).slice(0, 40);

// ── decisions ──────────────────────────────────────────────────────────────────────────────────────────────

test('release commit: the verified PR head when the merge commit has the identical tree; the merge commit when it does not', () => {
  const trees = { 'a^{tree}': T('1'), 'b^{tree}': T('1'), 'c^{tree}': T('2') };
  const git = (args) => `${trees[args[1]] || 'zz'}\n`;
  assert.deepEqual(chooseReleaseSha({ prHead: 'a', mergeSha: 'b', git }).sha, 'a');
  assert.equal(chooseReleaseSha({ prHead: 'a', mergeSha: 'b', git }).treeEquivalent, true);
  const moved = chooseReleaseSha({ prHead: 'a', mergeSha: 'c', git });
  assert.equal(moved.sha, 'c');
  assert.equal(moved.treeEquivalent, false, 'a different tree was never verified');
  assert.equal(chooseReleaseSha({ prHead: 'a', mergeSha: 'a', git }).treeEquivalent, true, 'a fast-forward');
  assert.throws(() => chooseReleaseSha({ prHead: 'a', mergeSha: 'q', git }), /could not read the commit trees/, 'an unreadable tree is an error, never "equivalent"');
});

test('checks: only an explicit pass is green; unknown, failing, pending and missing blocking checks are not', () => {
  const rows = parseChecks('test\tpass\t5m\turl\ncorpus\tpass\t1m\turl\nlint\tskipping\t0\turl\n');
  const ok = classifyChecks(rows, ['test', 'corpus', 'lint']);
  assert.equal(ok.green, true);
  assert.equal(classifyChecks(parseChecks('test\tfail\t1m\tu'), ['test']).failing[0], 'test');
  assert.deepEqual(classifyChecks(parseChecks('test\tpending\t0\tu'), ['test']).pending, ['test']);
  assert.equal(classifyChecks(parseChecks('test\tmystery\t0\tu'), ['test']).green, false, 'an unknown state is never read as green');
  const missing = classifyChecks(parseChecks('test\tpass\t1m\tu'), ['test', 'dependency-currency']);
  assert.deepEqual(missing.missing, ['dependency-currency']);
  assert.equal(missing.green, false);
  assert.equal(classifyChecks(parseChecks('test\tpass\t1m\tu'), ['test', 'dependency-currency'], { allowMissing: ['dependency-currency'] }).green, true);
});

test('stuck jobs: only an in-progress job older than the limit', () => {
  const now = Date.parse('2026-10-08T12:00:00Z');
  const jobs = [
    { name: 'nvim', status: 'in_progress', startedAt: '2026-10-08T10:50:00Z' },   // 70 min
    { name: 'test', status: 'in_progress', startedAt: '2026-10-08T11:40:00Z' },   // 20 min
    { name: 'old-done', status: 'completed', startedAt: '2026-10-08T09:00:00Z' },
  ];
  assert.deepEqual(findStuckJobs(jobs, now, { maxMinutes: 40 }).map((j) => j.name), ['nvim']);
  assert.deepEqual(findStuckJobs(jobs, now, { maxMinutes: 90 }), []);
});

test('release failure: a real gate failure is never retried, even when its siblings were cancelled by fail-fast', () => {
  const infra = classifyReleaseFailure([{ name: 'gate', conclusion: 'failure', steps: [{ name: 'Set up job', conclusion: 'failure' }] }]);
  assert.equal(infra.kind, 'infra');
  assert.equal(classifyReleaseFailure([{ name: 'gate (tests 2/4)', conclusion: 'cancelled', steps: [] }]).kind, 'infra');
  const mixed = classifyReleaseFailure([
    { name: 'gate (tests 1/4)', conclusion: 'cancelled', steps: [] },
    { name: 'gate (benches)', conclusion: 'failure', steps: [{ name: 'Release gate', conclusion: 'failure' }] },
  ]);
  assert.equal(mixed.kind, 'gate', 'the cancellation was a consequence; the gate failure is the cause');
  assert.match(mixed.reason, /Release gate/);
  assert.equal(classifyReleaseFailure([{ name: 'publish', conclusion: 'failure', steps: [{ name: 'Publish with provenance', conclusion: 'failure' }] }]).kind, 'gate', 'a failed publish step is not retried blindly');
  assert.equal(classifyReleaseFailure([{ name: 'gate', conclusion: 'success', steps: [] }]).kind, 'none');
});

test('preflight: each late failure is found before anything is pushed', () => {
  const good = { version: '1.2.3', files: { 'README.md': 'badge 1.2.3', 'CLAUDE.md': 'Version: 1.2.3' }, changelog: '## 1.2.3 - x\n', npmLatest: '1.2.2', branch: 'release/1.2.3', dirty: 0 };
  assert.deepEqual(preflightProblems(good), []);
  assert.match(preflightProblems({ ...good, branch: 'main' }).join(), /not main/);
  assert.match(preflightProblems({ ...good, dirty: 3 }).join(), /3 uncommitted/);
  assert.match(preflightProblems({ ...good, npmLatest: '1.2.3' }).join(), /not greater/);
  assert.match(preflightProblems({ ...good, files: { 'README.md': 'badge 1.2.2' } }).join(), /README\.md does not mention version 1\.2\.3/);
  assert.match(preflightProblems({ ...good, changelog: '## 1.2.2 - old\n' }).join(), /no "## 1\.2\.3" entry/);
  assert.match(preflightProblems({ ...good, version: '1.2' }).join(), /not X\.Y\.Z/);
  assert.ok(cmpVersions('0.10.0', '0.9.9') > 0, 'numeric, not lexical');
});

test('npm facts: published, attested, latest; an absent version is simply not published', () => {
  const pk = { 'dist-tags': { latest: '1.2.3' }, versions: { '1.2.3': { dist: { attestations: { url: 'x' } }, description: 'abc' } }, time: { '1.2.3': '2026-10-08T00:00:00Z' }, readme: 'hello' };
  assert.deepEqual({ ...npmFacts(pk, '1.2.3') }, { published: true, latest: '1.2.3', isLatest: true, attested: true, publishedAt: '2026-10-08T00:00:00Z', descriptionLength: 3, readmeLength: 5 });
  assert.equal(npmFacts(pk, '1.2.4').published, false);
  assert.equal(npmFacts({ 'dist-tags': { latest: '1.2.3' }, versions: { '1.2.3': { dist: {} } } }, '1.2.3').attested, false);
});

test('waitFor: returns on the first truthy probe, times out on the injected clock, and backs off but never past the cap', async () => {
  let t = 0; const sleeps = [];
  const clock = { now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; } };
  let n = 0;
  assert.equal((await waitFor(() => (++n === 4 ? 'yes' : null), { timeoutMs: 1e9, intervalMs: 1000, maxIntervalMs: 2000, ...clock })).value, 'yes');
  assert.ok(sleeps.every((s) => s <= 2000));
  assert.ok(sleeps[1] > sleeps[0], 'it backs off');
  t = 0; sleeps.length = 0;
  const r = await waitFor(() => null, { timeoutMs: 5000, intervalMs: 1000, maxIntervalMs: 1000, ...clock });
  assert.equal(r.ok, false);
  assert.ok(t >= 5000 && t <= 6000);
});

test('state: saved atomically, reloaded, and phase timings recorded', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-state-'));
  let t = 1000;
  const s = new ShipState(path.join(dir, 's.json'), () => t);
  s.begin('push'); t += 5000; s.finish('push', true, 'pushed');
  assert.equal(s.data.phases.push.seconds, 5);
  const again = ShipState.load(path.join(dir, 's.json'));
  assert.equal(again.data.phases.push.state, 'done');
  assert.match(again.summary(), /push\s+done 5s/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── the whole flow, against a scripted git and gh ──────────────────────────────────────────────────────────────

const HEAD = 'a'.repeat(40), MERGE = 'b'.repeat(40);

function world(overrides = {}) {
  const w = {
    calls: [], now: 0, branch: 'release/1.2.3', head: HEAD, mergeSha: MERGE, trees: { [HEAD]: T('1'), [MERGE]: T('1') },
    pending: 1, checkState: 'pass', releaseRuns: [{ status: 'completed', conclusion: 'success' }], runJobs: [], npmAfter: 2, npmCalls: 0, attested: true,
    releaseCheckCode: 0, ciOnMerge: 'success', mergeState: 'MERGED', created: false, ...overrides,
  };
  w.sh = (cmd, args) => {
    const line = `${cmd} ${args.join(' ')}`;
    w.calls.push(line);
    const ok = (out = '') => ({ code: 0, out, err: '' });
    if (cmd === 'git') {
      if (args[0] === 'branch') return ok(`${w.branch}\n`);
      if (args[0] === 'status') return ok('');
      if (args[0] === 'rev-parse' && args[1] === 'HEAD') return ok(`${w.head}\n`);
      if (args[0] === 'rev-parse' && /\^\{tree\}$/.test(args[1])) return ok(`${w.trees[args[1].replace('^{tree}', '')]}\n`);
      if (args[0] === 'rev-parse' && args[1] === '-q') return { code: 1, out: '', err: '' };
      if (args[0] === 'ls-remote') return ok('');
      if (args[0] === 'log') return ok('release: 1.2.3\n');
      return ok();
    }
    if (cmd === 'node') return { code: w.releaseCheckCode, out: w.releaseCheckCode ? 'FAIL  Full test suite passes\n' : 'Release gate passed\n', err: '' };
    if (cmd === 'gh') {
      if (args[0] === 'auth') return ok();
      if (args[0] === 'pr' && args[1] === 'list') return ok(JSON.stringify(w.created ? [{ number: 7, url: 'u', headRefOid: HEAD }] : []));
      if (args[0] === 'pr' && args[1] === 'create') { w.created = true; return ok('https://x/pull/7'); }
      if (args[0] === 'pr' && args[1] === 'checks') { if (w.pending-- > 0) return ok('test\tpending\t0\tu\ncorpus\tpass\t1m\tu\n'); return ok(`test\t${w.checkState}\t1m\tu\ncorpus\tpass\t1m\tu\n`); }
      if (args[0] === 'pr' && args[1] === 'merge') return ok();
      if (args[0] === 'pr' && args[1] === 'view') return ok(JSON.stringify({ state: w.mergeState, mergeCommit: { oid: MERGE }, headRefOid: HEAD }));
      if (args[0] === 'run' && args[1] === 'list') {
        if (args.includes('--workflow')) return ok(JSON.stringify([{ databaseId: 99, headBranch: 'v1.2.3', status: 'in_progress', conclusion: null }]));
        if (args.includes('--commit')) return ok(JSON.stringify([{ status: 'completed', conclusion: w.ciOnMerge, workflowName: 'ci' }]));
        return ok(JSON.stringify(w.runList || []));
      }
      if (args[0] === 'run' && args[1] === 'view') {
        if (args.includes('jobs')) return ok(JSON.stringify({ jobs: w.runJobs }));
        const r = w.releaseRuns.length > 1 ? w.releaseRuns.shift() : w.releaseRuns[0];
        return ok(JSON.stringify(r));
      }
      if (args[0] === 'run') return ok();
    }
    return ok();
  };
  w.fetchJson = async () => { w.npmCalls++; const pub = w.npmCalls >= w.npmAfter; return { 'dist-tags': { latest: '1.2.2' }, versions: pub ? { '1.2.3': { dist: w.attested ? { attestations: {} } : {}, description: 'd' } } : {}, time: {}, readme: 'r' }; };
  return w;
}

function ctxFor(w) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-run-'));
  const files = {
    'scanner/package.json': JSON.stringify({ version: '1.2.3' }), 'CHANGELOG.md': '## 1.2.3 - x\n', 'CLAUDE.md': '1.2.3', 'README.md': '1.2.3', '.claude-plugin/plugin.json': '1.2.3', '.claude-plugin/marketplace.json': '1.2.3', 'gemini-extension.json': '1.2.3',
    '.github/required-checks.json': JSON.stringify({ blocking: ['test', 'corpus', 'dependency-currency'] }),
  };
  return { sh: w.sh, fetchJson: w.fetchJson, readFile: (p) => { if (!(p in files)) throw new Error(`no file ${p}`); return files[p]; }, now: () => w.now, sleep: async (ms) => { w.now += ms; }, log: () => {}, state: new ShipState(path.join(dir, 'state.json'), () => w.now), _dir: dir };
}
const ran = (w, re) => w.calls.filter((c) => re.test(c));

test('flow: tree-equivalent merge releases the verified PR head, runs the gate once, tags, watches the release and npm, and never bypasses anything', async () => {
  const w = world(); const ctx = ctxFor(w);
  const r = await runShip(ctx, { maxRetries: 2 });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(ran(w, /^git (-c \S+ )?tag -a/), [`git tag -a v1.2.3 -m 1.2.3 ${HEAD}`], 'the verified PR head is tagged, not the merge commit');
  assert.equal(ran(w, /^node scripts\/release-check\.mjs/).length, 1);
  assert.equal(ran(w, /--no-verify|--allow-unverified-ci|--force|-f /).length, 0, 'no gate is bypassed and nothing is force-pushed');
  assert.ok(ran(w, /^git -c credential\.helper=!gh auth git-credential push origin v1\.2\.3/).length === 1);
  const order = ['push -u origin', 'pr create', 'pr merge', 'release-check', 'tag -a', 'push origin v1.2.3'].map((p) => w.calls.findIndex((c) => c.includes(p)));
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'phases run in order');
  assert.equal(ctx.state.data.phases.npm.state, 'done');
  assert.equal(ran(w, /--commit/).length, 0, 'no second CI wait for an equivalent tree');
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: when the merge commit differs from the verified head, it waits for CI on the merge commit and releases that', async () => {
  const w = world({ trees: { [HEAD]: T('1'), [MERGE]: T('2') } }); const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(ran(w, /tag -a/), [`git tag -a v1.2.3 -m 1.2.3 ${MERGE}`]);
  assert.equal(ran(w, /run list --commit/).length >= 1, true, 'it waited for CI on the unverified tree');
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: a different tree whose CI failed is never released', async () => {
  const w = world({ trees: { [HEAD]: T('1'), [MERGE]: T('2') }, ciOnMerge: 'failure' }); const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false); assert.equal(r.phase, 'verify');
  assert.equal(ran(w, /tag -a|release-check/).length, 0);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: a failing blocking check stops before the merge; nothing is merged, tagged or published', async () => {
  const w = world({ checkState: 'fail', pending: 0 }); const ctx = ctxFor(w);
  const r = await runShip(ctx, { allowMissing: ['dependency-currency'] });
  assert.equal(r.ok, false); assert.equal(r.phase, 'checks');
  assert.match(r.message, /test/);
  assert.equal(ran(w, /pr merge|tag -a|npm/).length, 0);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: a job stuck past the limit is cancelled and re-run, then the flow continues', async () => {
  let listed = 0;
  const w = world({ pending: 3 });
  const base = w.sh;
  w.sh = (cmd, args) => {
    if (cmd === 'gh' && args[0] === 'run' && args[1] === 'list' && args.includes('--branch')) { w.calls.push('gh run list --branch'); return { code: 0, err: '', out: JSON.stringify(listed++ === 0 ? [{ databaseId: 5, status: 'in_progress', conclusion: null, workflowName: 'ci' }] : []) }; }
    if (cmd === 'gh' && args[0] === 'run' && args[1] === 'view' && args.includes('jobs') && args[2] === '5') { w.calls.push('gh run view 5 jobs'); return { code: 0, err: '', out: JSON.stringify({ jobs: [{ name: 'nvim-plugin', status: 'in_progress', startedAt: new Date(w.now - 70 * 60000).toISOString() }] }) }; }
    if (cmd === 'gh' && args[0] === 'run' && args[1] === 'view' && args[2] === '5') { w.calls.push('gh run view 5 status'); return { code: 0, err: '', out: JSON.stringify({ status: 'completed' }) }; }
    return base(cmd, args);
  };
  const ctx = ctxFor(w);
  const r = await runShip(ctx, { allowMissing: ['dependency-currency'] });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(ran(w, /^gh run cancel 5/).length, 1);
  assert.equal(ran(w, /^gh run rerun 5 --failed/).length, 1);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: the release gate failing stops before the tag', async () => {
  const w = world({ releaseCheckCode: 1 }); const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false); assert.equal(r.phase, 'verify');
  assert.match(r.message, /FAIL/);
  assert.equal(ran(w, /tag -a|push origin v1\.2\.3/).length, 0, 'nothing is tagged or pushed after a failed gate');
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: an infrastructure failure of the release workflow is re-run once; a gate failure is not re-run', async () => {
  const infra = world({ releaseRuns: [{ status: 'completed', conclusion: 'failure' }, { status: 'completed', conclusion: 'success' }], runJobs: [{ name: 'gate', conclusion: 'cancelled', steps: [] }] });
  const c1 = ctxFor(infra);
  const r1 = await runShip(c1, {});
  assert.equal(r1.ok, true, JSON.stringify(r1));
  assert.equal(ran(infra, /^gh run rerun 99 --failed/).length, 1);
  const real = world({ releaseRuns: [{ status: 'completed', conclusion: 'failure' }], runJobs: [{ name: 'gate', conclusion: 'failure', steps: [{ name: 'Release gate', conclusion: 'failure' }] }] });
  const c2 = ctxFor(real);
  const r2 = await runShip(c2, {});
  assert.equal(r2.ok, false); assert.equal(r2.phase, 'release');
  assert.equal(ran(real, /^gh run rerun/).length, 0, 'a real gate failure is never retried');
  assert.equal(c2.state.data.phases.npm, undefined, 'npm is not even checked after a failed release');
  fs.rmSync(c1._dir, { recursive: true, force: true }); fs.rmSync(c2._dir, { recursive: true, force: true });
});

test('flow: a version on npm without a provenance attestation fails the run', async () => {
  const w = world({ attested: false }); const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false); assert.equal(r.phase, 'npm');
  assert.match(r.message, /WITHOUT a provenance attestation/);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: preflight problems stop everything before a single push', async () => {
  const w = world({ branch: 'main' }); const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false); assert.equal(r.phase, 'preflight');
  assert.equal(ran(w, /push|pr create/).length, 0);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: a dry run stops before the merge', async () => {
  const w = world(); const ctx = ctxFor(w);
  const r = await runShip(ctx, { dryRun: true });
  assert.equal(r.ok, true); assert.equal(r.dryRun, true);
  assert.equal(ran(w, /pr merge|tag -a/).length, 0);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('flow: resuming after the merge never merges or tags the same release twice', async () => {
  const w = world(); const ctx = ctxFor(w);
  ctx.state.data = { phases: {}, branch: 'release/1.2.3', version: '1.2.3', tag: 'v1.2.3', pr: 7, prHead: HEAD, mergeSha: MERGE, releaseSha: HEAD, treeEquivalent: true };
  for (const p of ['preflight', 'push', 'pr', 'checks', 'merge', 'verify', 'tag']) ctx.state.data.phases[p] = { state: 'done' };
  const r = await runShip(ctx, { resume: true });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(ran(w, /pr merge|tag -a|push -u|release-check/).length, 0, 'finished phases are not repeated');
  assert.equal(ctx.state.data.phases.release.state, 'done');
  assert.equal(ctx.state.data.phases.npm.state, 'done');
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});
