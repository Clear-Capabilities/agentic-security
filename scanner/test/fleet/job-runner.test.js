// The fleet controller (PRD 4 requirements 2 to 5 and 9): idempotent planning, leases and fencing, retries, timeouts, a hung
// repository, resume, the content-addressed cache, and organization health. The scan itself is injected here; the real child-process
// scan is covered by the CLI test.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { mkTestTmp } from '../helpers/tmp.js';
import { createMemoryJobStore, createSqliteJobStore } from '../../src/posture/fleet/job-store.js';
import { planRun, runJobs, loadArtifacts, reclaimDeadWorkers, childScan } from '../../src/posture/fleet/job-runner.js';
import { repoFingerprint, scannerIdentity, cacheKey, readCache, writeCache } from '../../src/posture/fleet/scan-cache.js';
import { computeOrgHealth, renderOrgHealth } from '../../src/posture/fleet/org-health.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function manifestOf(ids, over = {}) {
  const root = mkTestTmp('fleet-run-');
  const repos = ids.map((id) => { const p = path.join(root, id); fs.mkdirSync(p); fs.writeFileSync(path.join(p, 'a.js'), `// ${id}\n`); return { id, path: p, required: true }; });
  return { root, manifest: { organization: 'acme', repositories: repos, resources: [], workers: 2, retries: 1, perRepoTimeoutMs: 2000, ...over } };
}
const entry = (repo, total = 1, scanHealth = { status: 'complete' }) => ({ repo, ok: true, total, bySeverity: { critical: 0, high: total, medium: 0, low: 0 }, ids: [], scannedAt: new Date().toISOString(), scanHealth, policyDrift: null, provenanceDebt: null, mttr: null });
const okScan = (over = {}) => async (repoPath) => ({ entry: entry(path.basename(repoPath), 2, over.scanHealth), findings: [{ id: `f-${path.basename(repoPath)}`, cwe: 'CWE-78', severity: 'high' }] });
const identity = 'test+0123';
// the content is per repository, as it is in life (two repositories with byte-identical content would legitimately share a cached result)
const fp = (tag) => (repoPath) => ({ commit: 'abc', dirty: false, content: `${tag}:${path.basename(repoPath)}`, lockfiles: {} });
const plan = (m, store, extra = {}) => planRun({ manifest: m.manifest, manifestHash: 'mh', store, identity, fingerprint: fp('git:abc'), ...extra });
const fast = { leaseMs: 60000, heartbeatMs: 20, retryDelayMs: 5, pollMs: 5 };

for (const [name, make] of [['memory', async () => createMemoryJobStore()], ['sqlite', async () => createSqliteJobStore({ file: path.join(mkTestTmp('fleet-db-'), 'f.db') })]]) {
  const T = (title, fn) => test(`[${name}] ${title}`, async () => { const store = await make(); try { await fn(store); } finally { store.close(); } });

  T('planning is idempotent per run id, and a run id is distinct per plan', async (store) => {
    const m = manifestOf(['a', 'b', 'c']);
    const p1 = plan(m, store, { now: 1000 });
    assert.equal(p1.created, 3);
    const again = plan(m, store, { runId: p1.runId, now: 2000 });
    assert.equal(again.created, 0, 'the same run planned twice makes no new jobs');
    const other = plan(m, store, { now: 3000 });
    assert.notEqual(other.runId, p1.runId);
    assert.equal(store.listJobs(p1.runId).length, 3);
  });

  T('every repository gets a result, in a bounded number of workers, and a result is verified against its recorded hash', async (store) => {
    const m = manifestOf(['a', 'b', 'c', 'd', 'e']);
    const { runId } = plan(m, store);
    let live = 0; let peak = 0;
    const scan = async (p, o) => { live++; peak = Math.max(peak, live); await sleep(30); live--; return okScan()(p, o); };
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan, workers: 2, ...fast });
    assert.ok(peak <= 2 && peak >= 1, `peak concurrency ${peak}`);
    const jobs = store.listJobs(runId);
    assert.ok(jobs.every((j) => j.status === 'succeeded' && j.artifactSha256));
    const { artifacts, problems } = loadArtifacts({ store, runId, root: m.root });
    assert.equal(artifacts.size, 5); assert.deepEqual(problems, []);
    assert.equal(artifacts.get('a').findings.length, 1);
    // tamper with one artifact: it is reported and not used
    const file = path.join(m.root, '.agentic-security', 'fleet', 'artifacts', runId, `a.${store.getJob(`${runId}:a`).epoch}.json`);
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('CWE-78', 'CWE-00'));
    const after = loadArtifacts({ store, runId, root: m.root });
    assert.equal(after.artifacts.has('a'), false); assert.match(after.problems[0].problem, /does not match the recorded hash/);
  });

  T('a failing repository is retried, then recorded as failed; the others still finish', async (store) => {
    const m = manifestOf(['good', 'flaky', 'broken']);
    const { runId } = plan(m, store);
    const tries = new Map();
    const scan = async (p, o) => {
      const id = path.basename(p); tries.set(id, (tries.get(id) ?? 0) + 1);
      if (id === 'broken') throw Object.assign(new Error('parser crashed'), { code: 'ERROR' });
      if (id === 'flaky' && tries.get(id) === 1) throw Object.assign(new Error('transient'), { code: 'ERROR' });
      return okScan()(p, o);
    };
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan, ...fast });
    const by = Object.fromEntries(store.listJobs(runId).map((j) => [j.repoId, j]));
    assert.equal(by.good.status, 'succeeded'); assert.equal(by.flaky.status, 'succeeded'); assert.equal(by.flaky.attempts, 2);
    assert.equal(by.broken.status, 'failed'); assert.equal(by.broken.attempts, 2); assert.match(by.broken.error, /parser crashed/);
    const health = computeOrgHealth({ manifest: m.manifest, jobs: store.listJobs(runId) });
    assert.equal(health.assurance, 'red'); assert.equal(health.counts.failed, 1); assert.equal(health.counts.complete, 2);
  });

  T('one hung repository costs one timeout and stops nothing else', async (store) => {
    const m = manifestOf(['hang', 'x', 'y', 'z'], { workers: 2, retries: 0 });
    const { runId } = plan(m, store, { retries: 0 });
    const scan = async (p, o) => {
      if (path.basename(p) === 'hang') return new Promise((_, rej) => { const t = setTimeout(() => rej(Object.assign(new Error('no result within 1s'), { code: 'TIMEOUT' })), 300); o.signal.addEventListener('abort', () => { clearTimeout(t); rej(Object.assign(new Error('cancelled'), { code: 'CANCELLED' })); }); });
      return okScan()(p, o);
    };
    const t0 = Date.now();
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan, ...fast });
    assert.ok(Date.now() - t0 < 3000);
    const by = Object.fromEntries(store.listJobs(runId).map((j) => [j.repoId, j.status]));
    assert.deepEqual(by, { hang: 'timed_out', x: 'succeeded', y: 'succeeded', z: 'succeeded' });
    const h = computeOrgHealth({ manifest: m.manifest, jobs: store.listJobs(runId) });
    assert.equal(h.counts.timedOut, 1); assert.equal(h.assurance, 'red');
    assert.match(renderOrgHealth(h), /Timed out: 1/);
  });

  T('a worker that loses its lease is fenced out: its late result is refused and findings are not duplicated', async (store) => {
    const m = manifestOf(['slow'], { workers: 1 });
    const { runId } = plan(m, store);
    const job = store.claim(runId, { worker: 'zombie:1:0', leaseMs: 10, now: Date.now() });
    await sleep(30);
    assert.equal(store.reclaimExpired(runId, { now: Date.now() }), 1);
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan: okScan(), workers: 1, ...fast });
    const done = store.getJob(job.jobId);
    assert.equal(done.status, 'succeeded'); assert.equal(done.epoch, 2);
    assert.equal(store.complete(job.jobId, job.epoch, { artifactSha256: 'late-zombie', now: Date.now() }), false);
    assert.notEqual(store.getJob(job.jobId).artifactSha256, 'late-zombie');
    const { artifacts } = loadArtifacts({ store, runId, root: m.root });
    assert.equal(artifacts.get('slow').findings.length, 1, 'exactly one set of findings');
  });

  T('a lost heartbeat aborts the scan and discards its result', async (store) => {
    const m = manifestOf(['a'], { workers: 1, retries: 1 });
    const { runId } = plan(m, store);
    let first = true; let aborted = false;
    const scan = async (p, o) => {
      if (first) {
        first = false;
        // while this scan runs, another controller reclaims the job and takes it
        store.reclaimWorker(runId, store.listJobs(runId)[0].worker);
        const stolen = store.claim(runId, { worker: 'other:2:0', leaseMs: 60000, now: Date.now() });
        store.complete(stolen.jobId, stolen.epoch, { status: 'succeeded', artifactSha256: 'winner', summary: { total: 9, artifact: 'x.json' }, now: Date.now() });
        await new Promise((res) => { o.signal.addEventListener('abort', () => { aborted = true; res(); }); setTimeout(res, 1000); });
        return okScan()(p, o);
      }
      return okScan()(p, o);
    };
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan, workers: 1, ...fast });
    assert.equal(aborted, true, 'the scan was told to stop');
    assert.equal(store.listJobs(runId)[0].artifactSha256, 'winner');
  });

  T('resume: a run whose controller died is continued; finished repositories are not scanned again', async (store) => {
    const m = manifestOf(['a', 'b', 'c']);
    const { runId } = plan(m, store);
    // a had finished; b was being scanned by a controller that has since died (pid 99999999 cannot exist); c never started
    const a = store.claim(runId, { worker: 'earlier:1:0', leaseMs: 60000, now: Date.now() });
    store.complete(a.jobId, a.epoch, { status: 'succeeded', artifactSha256: 'prior', summary: { total: 1, artifact: 'prior.json' }, now: Date.now() });
    const b = store.claim(runId, { worker: `${(await import('node:os')).hostname()}:99999999:0`, leaseMs: 600000, now: Date.now() });
    assert.equal(store.getJob(b.jobId).status, 'leased');
    assert.equal(reclaimDeadWorkers(store, runId), 1, 'the dead worker\'s job is recovered without waiting for its lease to expire');
    const scanned = [];
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan: async (p, o) => { scanned.push(path.basename(p)); return okScan()(p, o); }, workers: 1, ...fast });
    assert.deepEqual(scanned.sort(), ['b', 'c'], 'only the unfinished repositories were scanned');
    assert.ok(store.listJobs(runId).every((x) => x.status === 'succeeded'));
    assert.equal(store.getJob(a.jobId).artifactSha256, 'prior', 'the finished result was reused as it was');
  });

  T('a worker on another host is never presumed dead; only lease expiry frees its job', async (store) => {
    const m = manifestOf(['a']);
    const { runId } = plan(m, store);
    store.claim(runId, { worker: 'some-other-host:99999999:0', leaseMs: 600000, now: Date.now() });
    assert.equal(reclaimDeadWorkers(store, runId), 0);
    assert.equal(store.listJobs(runId)[0].status, 'leased');
  });

  T('the cache: an unchanged repository is reused, and each kind of change invalidates it', async (store) => {
    const m = manifestOf(['a', 'b']);
    const cacheDir = path.join(m.root, 'cache');
    const scans = [];
    const scan = async (p, o) => { scans.push(path.basename(p)); return okScan()(p, o); };
    const run = async (extra = {}) => { const { runId } = plan(m, store, { now: Math.random() * 1e9, ...extra }); await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan, cacheDir, ...fast }); return runId; };
    const r1 = await run();
    assert.deepEqual(scans.sort(), ['a', 'b']);
    scans.length = 0;
    const r2 = await run();
    assert.deepEqual(scans, [], 'the second run is served entirely from the cache');
    assert.ok(store.listJobs(r2).every((j) => j.summary.cached === true && j.status === 'succeeded'));
    assert.equal(loadArtifacts({ store, runId: r2, root: m.root }).artifacts.get('a').findings.length, 1);
    await run({ identity: 'test+NEWBUILD' }); assert.deepEqual(scans.sort(), ['a', 'b'], 'a different scanner build invalidates the cache'); scans.length = 0;
    await run({ fingerprint: fp('git:def') }); assert.deepEqual(scans.sort(), ['a', 'b'], 'a different commit invalidates it'); scans.length = 0;
    await run({ config: { deep: true } }); assert.deepEqual(scans.sort(), ['a', 'b'], 'a different configuration invalidates it'); scans.length = 0;
    await run({ fingerprint: () => ({ commit: null, dirty: null, content: null, lockfiles: {} }) }); assert.deepEqual(scans.sort(), ['a', 'b'], 'unknown content is never treated as unchanged'); scans.length = 0;
    await run({ identity: null }); assert.deepEqual(scans.sort(), ['a', 'b'], 'a scanner with no identity never reuses a result');
    void r1;
  });

  T('a partial scan is partial, is not cached, and keeps the organization out of green', async (store) => {
    const m = manifestOf(['a', 'b']);
    const { runId } = plan(m, store);
    const cacheDir = path.join(m.root, 'cache');
    await runJobs({ manifest: m.manifest, store, runId, root: m.root, scan: async (p, o) => okScan({ scanHealth: path.basename(p) === 'b' ? { status: 'partial' } : { status: 'complete' } })(p, o), cacheDir, ...fast });
    const by = Object.fromEntries(store.listJobs(runId).map((j) => [j.repoId, j.status]));
    assert.deepEqual(by, { a: 'succeeded', b: 'partial' });
    const h = computeOrgHealth({ manifest: m.manifest, jobs: store.listJobs(runId) });
    assert.equal(h.assurance, 'degraded'); assert.equal(h.counts.partial, 1);
    assert.equal(fs.readdirSync(cacheDir).length, 1, 'only the complete result was cached');
  });
}

// ---------------------------------------------------------------------------------------------------- org health, pure

test('org health: GREEN only when every required repository has a complete result; nothing requested can vanish from the totals', () => {
  const manifest = { repositories: [{ id: 'a', required: true }, { id: 'b', required: true }, { id: 'c', required: true }, { id: 'opt', required: false }] };
  const job = (repoId, status, extra = {}) => ({ repoId, status, attempts: 1, error: null, summary: null, ...extra });
  const green = computeOrgHealth({ manifest, jobs: [job('a', 'succeeded'), job('b', 'succeeded'), job('c', 'succeeded'), job('opt', 'succeeded')] });
  assert.equal(green.assurance, 'green');
  const missing = computeOrgHealth({ manifest, jobs: [job('a', 'succeeded'), job('b', 'succeeded')] });
  assert.equal(missing.assurance, 'red'); assert.equal(missing.counts.notRun, 2); assert.equal(missing.counts.requested, 4);
  assert.equal(missing.counts.complete + missing.counts.partial + missing.counts.failed + missing.counts.timedOut + missing.counts.cancelled + missing.counts.notRun, 4, 'every requested repository is counted somewhere');
  const queued = computeOrgHealth({ manifest, jobs: [job('a', 'succeeded'), job('b', 'queued'), job('c', 'leased'), job('opt', 'succeeded')] });
  assert.equal(queued.assurance, 'red'); assert.equal(queued.counts.notRun, 2);
  const optionalBad = computeOrgHealth({ manifest, jobs: [job('a', 'succeeded'), job('b', 'succeeded'), job('c', 'succeeded'), job('opt', 'failed')] });
  assert.equal(optionalBad.assurance, 'degraded');
  const partial = computeOrgHealth({ manifest, jobs: [job('a', 'succeeded'), job('b', 'partial'), job('c', 'succeeded'), job('opt', 'succeeded')] });
  assert.equal(partial.assurance, 'degraded');
  const cancelled = computeOrgHealth({ manifest, jobs: [job('a', 'cancelled'), job('b', 'succeeded'), job('c', 'succeeded'), job('opt', 'succeeded')] });
  assert.equal(cancelled.assurance, 'red');
  const big = { repositories: Array.from({ length: 1250 }, (_, i) => ({ id: `r${i}`, required: true })) };
  const jobs = [];
  for (let i = 0; i < 1250; i++) jobs.push(job(`r${i}`, i < 1228 ? 'succeeded' : i < 1239 ? 'partial' : i < 1245 ? 'failed' : 'timed_out'));
  const text = renderOrgHealth(computeOrgHealth({ manifest: big, jobs }));
  assert.match(text, /Repositories requested: 1,250\nComplete: 1,228\nPartial: 11\nFailed: 6\nTimed out: 5\n\nAssurance: RED/);
});

// ---------------------------------------------------------------------------------------------------- cache, pure

test('cache keys: stable for identical input, null for anything unknown; records are digest-checked', () => {
  const f = { content: 'git:abc', lockfiles: { 'package-lock.json': 'x' } };
  const k = cacheKey({ fingerprint: f, config: { a: 1 }, identity: 'v+h' });
  assert.match(k, /^[0-9a-f]{64}$/);
  assert.equal(k, cacheKey({ fingerprint: { ...f }, config: { a: 1 }, identity: 'v+h' }));
  assert.notEqual(k, cacheKey({ fingerprint: { ...f, lockfiles: { 'package-lock.json': 'y' } }, config: { a: 1 }, identity: 'v+h' }), 'a changed lockfile');
  assert.equal(cacheKey({ fingerprint: { content: null, lockfiles: {} }, config: {}, identity: 'v+h' }), null);
  assert.equal(cacheKey({ fingerprint: f, config: {}, identity: null }), null);
  const dir = mkTestTmp('fleet-cache-');
  assert.equal(writeCache(dir, k, { entry: { total: 1 }, findings: [] }), true);
  assert.equal(readCache(dir, k).entry.total, 1);
  fs.writeFileSync(path.join(dir, `${k}.json`), fs.readFileSync(path.join(dir, `${k}.json`), 'utf8').replace('"total":1', '"total":0'));
  assert.equal(readCache(dir, k), null, 'an edited record is a miss');
  assert.equal(readCache(dir, '../../etc/passwd'), null); assert.equal(writeCache(dir, 'nope', {}), false); assert.equal(readCache(dir, null), null);
});

test('fingerprint: a clean git checkout is its commit; an uncommitted change or a lockfile change changes it; a non-git folder is hashed', async () => {
  const { spawnSync } = await import('node:child_process');
  const dir = mkTestTmp('fleet-fp-');
  const git = (...a) => { const r = spawnSync('git', a, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
  git('init', '-q', '-b', 'main'); fs.writeFileSync(path.join(dir, 'a.js'), 'x\n'); fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}'); git('add', '.'); git('commit', '-q', '-m', 'c');
  const clean = repoFingerprint(dir);
  assert.equal(clean.dirty, false); assert.equal(clean.content, `git:${clean.commit}`);
  fs.writeFileSync(path.join(dir, 'a.js'), 'changed\n');
  const dirty = repoFingerprint(dir);
  assert.equal(dirty.dirty, true); assert.notEqual(dirty.content, clean.content); assert.match(dirty.content, /^git\+worktree:/);
  fs.writeFileSync(path.join(dir, 'untracked.js'), 'new\n');
  assert.notEqual(repoFingerprint(dir).content, dirty.content, 'an untracked file counts');
  git('checkout', '--', 'a.js'); fs.rmSync(path.join(dir, 'untracked.js'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{"x":1}');
  assert.notEqual(repoFingerprint(dir).lockfiles['package-lock.json'], clean.lockfiles['package-lock.json']);
  const plain = mkTestTmp('fleet-fp2-'); fs.writeFileSync(path.join(plain, 'a.js'), 'x');
  const p1 = repoFingerprint(plain); fs.writeFileSync(path.join(plain, 'a.js'), 'y');
  assert.match(p1.content, /^tree:/); assert.notEqual(repoFingerprint(plain).content, p1.content);
  assert.ok(scannerIdentity() === null || /^\d+\.\d+\.\d+.*\+[0-9a-f]{64}$/.test(scannerIdentity()));
});

test('the child scan: a real scan in a supervised child returns an entry; a timeout is a TIMEOUT, not a hang', async () => {
  const dir = mkTestTmp('fleet-child-');
  fs.writeFileSync(path.join(dir, 'app.js'), "const { exec } = require('child_process');\napp.post('/p', (req, res) => { exec('ping ' + req.body.host); });\n");
  const out = await childScan(dir, { timeoutMs: 90000 });
  assert.equal(out.entry.ok, true); assert.ok(out.entry.total >= 1); assert.ok(out.findings.length >= 1);
  assert.deepEqual(Object.keys(out.findings[0]).sort(), ['cwe', 'family', 'file', 'id', 'line', 'parser', 'severity', 'stableId', 'vuln']);
  assert.equal(fs.existsSync(path.join(dir, '.agentic-security')), false, 'scanning for the fleet does not write state into the repository');
  await assert.rejects(() => childScan(dir, { timeoutMs: 50 }), (e) => e.code === 'TIMEOUT');
  const ac = new AbortController(); ac.abort();
  await assert.rejects(() => childScan(dir, { timeoutMs: 5000, signal: ac.signal }), (e) => e.code === 'CANCELLED');
  void createHash;
});
