// The release orchestrator (scripts/ship/): its decisions in isolation, and the whole flow against a scripted git and gh.
// No network, no repository, no real clock: every effect is injected.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chooseReleaseSha, parseChecks, classifyChecks, findStuckJobs, classifyReleaseFailure, npmFacts, preflightProblems, cmpVersions, ShipState, waitFor, resumeCommand, statusText, outcomeText, prepareTmpdir, removeFreshTmpdir } from '../../scripts/ship/lib.mjs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
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

test('state: only the recorded keys can be set; a hostile key is ignored and cannot reach the prototype', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-keys-'));
  const s = new ShipState(path.join(dir, 's.json'));
  s.set(JSON.parse('{"__proto__": {"polluted": true}, "evil": 1, "tag": "v1.2.3", "pr": 7}'));
  assert.equal(s.data.tag, 'v1.2.3');
  assert.equal(s.data.pr, 7);
  assert.equal(s.data.evil, undefined, 'an unknown key is not recorded');
  assert.equal({}.polluted, undefined, 'the prototype is untouched');
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
  w.sh = (cmd, args, opts) => {
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
    if (cmd === 'node') w.gateEnv = (opts && opts.env) || {};
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

test('flow: a push the gate refuses names the failed checks, not just the last lines of output', async () => {
  const w = world(); const base = w.sh;
  w.sh = (cmd, args) => (cmd === 'git' && args.includes('push') && !args.includes('v1.2.3') ? { code: 1, out: '', err: 'PASS  Working tree matches\nFAIL  Self-scan precision baseline holds\nSKIP  other\npre-push gate FAILED in 520s\n' } : base(cmd, args));
  const ctx = ctxFor(w);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false); assert.equal(r.phase, 'push');
  assert.match(r.message, /failed checks: Self-scan precision baseline holds/);
  assert.equal(ran(w, /pr create/).length, 0, 'nothing is opened after a refused push');
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

// ── a stale FAILED line, the resume command, timings, and the gate's temp directory ─────────────────────────────

const SHIP = fileURLToPath(new URL('../../scripts/ship.mjs', import.meta.url));

test('failed: a resumed run that gets past the failed phase leaves no FAILED line; --status reports it only for a run that ended failed', async () => {
  const w = world({ releaseCheckCode: 1 }); const ctx = ctxFor(w);
  const r1 = await runShip(ctx, {});
  assert.equal(r1.ok, false); assert.equal(r1.phase, 'verify');
  assert.equal(ctx.state.data.failed.phase, 'verify');
  assert.match(statusText(ctx.state), /FAILED in verify: .*\nresume with: node scripts\/ship\.mjs --resume\n/, 'a stopped run reports its failure and how to continue');
  // the gate is fixed and the run is resumed: it passes verify and finishes
  w.releaseCheckCode = 0;
  // while the resumed run is in flight (here, as the gate starts) the old stop is already gone: a run killed mid-way must not look failed
  const base = w.sh; let during = 'unset';
  ctx.sh = w.sh = (cmd, args, opts) => { if (cmd === 'node') during = ctx.state.data.failed; return base(cmd, args, opts); };
  const r2 = await runShip(ctx, { resume: true });
  assert.equal(r2.ok, true, JSON.stringify(r2));
  assert.equal(during, null, 'cleared when the resumed run started');
  assert.equal(ctx.state.data.failed, null, 'the stale failure is gone');
  assert.equal(ctx.state.failure(), null);
  assert.doesNotMatch(statusText(ctx.state), /FAILED/);
  assert.doesNotMatch(outcomeText(ctx.state, r2), /STOPPED|FAILED|resume with/);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('failed: a resumed run clears the old failure when it starts, and a new stop replaces it', async () => {
  const w = world({ releaseCheckCode: 1 }); const ctx = ctxFor(w);
  await runShip(ctx, {});
  assert.equal(ctx.state.data.failed.phase, 'verify');
  // resumed, it fails somewhere else: the record names the NEW stop, not the old one
  const base = w.sh;
  w.releaseCheckCode = 0;
  w.sh = (cmd, args, opts) => (cmd === 'git' && args.includes('push') && args.includes('v1.2.3') ? { code: 1, out: '', err: 'remote refused the tag' } : base(cmd, args, opts));
  ctx.sh = w.sh;
  const r = await runShip(ctx, { resume: true });
  assert.equal(r.ok, false); assert.equal(r.phase, 'tag');
  assert.equal(ctx.state.data.failed.phase, 'tag');
  assert.match(ctx.state.data.failed.message, /pushing the tag failed/);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('failed: failure() ignores a record for a finished run or for a phase that has since completed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-fail-'));
  const s = new ShipState(path.join(dir, 's.json'));
  s.data = { phases: { verify: { state: 'failed' } }, failed: { phase: 'verify', message: 'x' }, events: [] };
  assert.equal(s.failure().phase, 'verify', 'a run that is stopped on that phase is failed');
  s.data.phases.verify.state = 'done';
  assert.equal(s.failure(), null, 'the phase it names has completed');
  s.data.phases.verify.state = 'failed'; s.data.finished = 1;
  assert.equal(s.failure(), null, 'the run finished');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--status never resets or rewrites the state (run for real, against a throwaway state directory)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-status-'));
  const file = path.join(dir, 'state.json');
  const failed = { phases: { preflight: { state: 'done', seconds: 3 }, verify: { state: 'failed', seconds: 41 } }, started: 1000, events: [], branch: 'release/9.9.9', failed: { phase: 'verify', message: 'the release gate failed: FAIL  x' }, tmpdir: '/tmp/some dir', tmpdirGiven: true };
  fs.writeFileSync(file, JSON.stringify(failed, null, 1));
  const before = fs.readFileSync(file);
  const run = () => spawnSync(process.execPath, [SHIP, '--status'], { env: { ...process.env, SHIP_STATE_DIR: dir }, encoding: 'utf8', timeout: 60000 });
  const a = run();
  assert.equal(a.status, 0, a.stderr);
  assert.match(a.stdout, /FAILED in verify: the release gate failed/);
  assert.match(a.stdout, /resume with: node scripts\/ship\.mjs --resume --tmpdir '\/tmp\/some dir'/, 'the exact command, with the operator\'s directory quoted');
  assert.match(a.stdout, /TIMINGS preflight=3s verify=41s total=44s/);
  assert.deepEqual(fs.readFileSync(file), before, '--status left the state file byte for byte as it was');
  // a run that has since finished prints no FAILED line, and is still not rewritten
  const finished = { ...failed, finished: 5000, failed: null };
  fs.writeFileSync(file, JSON.stringify(finished, null, 1));
  const before2 = fs.readFileSync(file);
  const b = run();
  assert.equal(b.status, 0, b.stderr);
  assert.doesNotMatch(b.stdout, /FAILED|resume with/);
  assert.deepEqual(fs.readFileSync(file), before2);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('resume command: exact, quoted, and it carries a dry run and an operator-chosen temp directory but not a generated one', () => {
  assert.equal(resumeCommand({}), 'node scripts/ship.mjs --resume');
  assert.equal(resumeCommand({ dryRun: true }), 'node scripts/ship.mjs --resume --dry-run');
  assert.equal(resumeCommand({ tmpdir: '/var/t/gate', tmpdirGiven: true }), 'node scripts/ship.mjs --resume --tmpdir /var/t/gate');
  assert.equal(resumeCommand({ tmpdir: "/tmp/it's here", tmpdirGiven: true }), "node scripts/ship.mjs --resume --tmpdir '/tmp/it'\\''s here'");
  assert.equal(resumeCommand({ tmpdir: '/tmp/ship-tmp-abc123', tmpdirGiven: false }), 'node scripts/ship.mjs --resume', 'a fresh directory is made again on resume');
});

test('stopping prints the exact resume command and the phase timings', async () => {
  const w = world({ releaseCheckCode: 1 }); const ctx = ctxFor(w);
  const base = w.sh;
  ctx.sh = w.sh = (cmd, args, opts) => { if (cmd === 'node') w.now += 7000; return base(cmd, args, opts); };
  const r = await runShip(ctx, { tmpdir: '/var/t/gate' });
  assert.equal(r.ok, false);
  const text = outcomeText(ctx.state, r, { now: w.now });
  assert.match(text, /STOPPED in verify: /);
  assert.match(text, /resume with: node scripts\/ship\.mjs --resume --tmpdir \/var\/t\/gate\n/);
  assert.match(text, /\nTIMINGS preflight=0s .*verify=7s .*total=\d+s\n/);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('timings: one line of per-phase seconds in phase order, summed; a run with no finished phase says so', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-time-'));
  let t = 0;
  const s = new ShipState(path.join(dir, 's.json'), () => t);
  assert.equal(s.timingsLine(), 'TIMINGS (no phase finished) total=0s');
  s.begin('checks'); t += 12000; s.finish('checks', true);       // recorded out of order on purpose
  s.begin('push'); t += 5000; s.finish('push', true);
  s.begin('verify'); t += 30000; s.finish('verify', false, 'gate failed');   // a failed phase still has its seconds
  assert.equal(s.timingsLine(), 'TIMINGS push=5s checks=12s verify=30s total=47s');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('tmpdir: unless one is named, the release gate gets a fresh empty directory from the context, which is removed after a successful release', async () => {
  const w = world(); const ctx = ctxFor(w);
  const made = [], removed = [];
  ctx.makeTmpdir = () => { const d = `/tmp/ship-tmp-fake${made.length}`; made.push(d); return d; };
  ctx.removeTmpdir = (d) => removed.push(d);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(made, ['/tmp/ship-tmp-fake0'], 'one directory, made when the gate runs');
  assert.deepEqual([w.gateEnv.TMPDIR, w.gateEnv.TMP, w.gateEnv.TEMP], ['/tmp/ship-tmp-fake0', '/tmp/ship-tmp-fake0', '/tmp/ship-tmp-fake0']);
  assert.equal(ctx.state.data.tmpdir, '/tmp/ship-tmp-fake0'); assert.equal(ctx.state.data.tmpdirGiven, false);
  assert.deepEqual(removed, ['/tmp/ship-tmp-fake0']);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('tmpdir: a named directory is used as given, nothing is made, and nothing is removed', async () => {
  const w = world(); const ctx = ctxFor(w);
  let made = 0; const removed = [];
  ctx.makeTmpdir = () => { made++; return '/tmp/unused'; };
  ctx.removeTmpdir = (d) => removed.push(d);
  const r = await runShip(ctx, { tmpdir: '/var/t/mine' });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(made, 0); assert.deepEqual(removed, []);
  assert.equal(w.gateEnv.TMPDIR, '/var/t/mine');
  assert.equal(ctx.state.data.tmpdirGiven, true);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('tmpdir: after a stop the generated directory is kept for inspection', async () => {
  const w = world({ releaseCheckCode: 1 }); const ctx = ctxFor(w);
  const removed = [];
  ctx.makeTmpdir = () => '/tmp/ship-tmp-kept'; ctx.removeTmpdir = (d) => removed.push(d);
  const r = await runShip(ctx, {});
  assert.equal(r.ok, false);
  assert.deepEqual(removed, []);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
});

test('tmpdir: prepareTmpdir makes a new empty directory inside the OS temp folder each time; removeFreshTmpdir removes only those', () => {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ship-base-')));
  const a = prepareTmpdir(undefined, { base }), b = prepareTmpdir(undefined, { base });
  assert.equal(a.created, true); assert.notEqual(a.dir, b.dir);
  assert.equal(path.dirname(a.dir), base); assert.match(path.basename(a.dir), /^ship-tmp-/);
  assert.deepEqual(fs.readdirSync(a.dir), [], 'empty');
  // a named directory: created when missing, existing contents left alone
  const named = path.join(base, 'named', 'deep');
  assert.deepEqual(prepareTmpdir(named, { base }), { dir: named, created: false });
  fs.writeFileSync(path.join(named, 'keep.txt'), 'x');
  prepareTmpdir(named, { base });
  assert.equal(fs.readFileSync(path.join(named, 'keep.txt'), 'utf8'), 'x', 'never emptied');
  // removal
  fs.writeFileSync(path.join(a.dir, 'junk'), 'x');
  assert.equal(removeFreshTmpdir(a.dir, { base }), true); assert.equal(fs.existsSync(a.dir), false);
  assert.equal(removeFreshTmpdir(named, { base }), false, 'not a generated name');
  const plain = path.join(base, 'somebody-elses'); fs.mkdirSync(plain);
  assert.equal(removeFreshTmpdir(plain, { base }), false, 'directly inside the temp folder but not made by prepareTmpdir');
  assert.equal(fs.existsSync(plain), true);
  const elsewhere = path.join(base, 'named', 'ship-tmp-nested'); fs.mkdirSync(elsewhere);
  assert.equal(removeFreshTmpdir(elsewhere, { base }), false, 'not directly inside the temp folder');
  const target = path.join(base, 'target'); fs.mkdirSync(target); fs.writeFileSync(path.join(target, 'precious'), 'x');
  const link = path.join(base, 'ship-tmp-link'); fs.symlinkSync(target, link);
  assert.equal(removeFreshTmpdir(link, { base }), false, 'a symlink is never followed');
  assert.equal(fs.existsSync(path.join(target, 'precious')), true);
  assert.equal(removeFreshTmpdir('', { base }), false);
  assert.equal(fs.existsSync(named), true);
  fs.rmSync(base, { recursive: true, force: true });
});

test('[REL-003.AC03] flow: hosted CI attestation of the remote closure prerequisites is printed as evidence and never fails a published release', async () => {
  const w = world(); const ctx = ctxFor(w); const lines = []; ctx.log = (l) => lines.push(l);
  const r = await runShip(ctx, { maxRetries: 2 });
  assert.equal(r.ok, true, 'a missing attestation does not fail the release');
  const text = lines.join('\n');
  assert.match(text, /hosted CI attestation of the remote closure prerequisites \(informational; it does not gate or undo this release\): NOT all attested/);
  assert.match(text, /NOT attested remote-nixos-host \[job-missing\]/);
  assert.equal(ctx.state.data.remoteAttestation.attested.length, 0);
  fs.rmSync(ctx._dir, { recursive: true, force: true });
  // and when asking for it blows up, the release still succeeds
  const w2 = world(); const inner = w2.sh;
  w2.sh = (cmd, args, o) => { if (cmd === 'gh' && args[0] === 'api') throw new Error('network down'); return inner(cmd, args, o); };
  const ctx2 = ctxFor(w2); const lines2 = []; ctx2.log = (l) => lines2.push(l);
  const r2 = await runShip(ctx2, { maxRetries: 2 });
  assert.equal(r2.ok, true);
  assert.match(lines2.join('\n'), /bad-response|informational only/);
  fs.rmSync(ctx2._dir, { recursive: true, force: true });
});
