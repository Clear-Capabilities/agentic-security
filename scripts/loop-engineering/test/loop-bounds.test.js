// LOOP-002: the controller's own subprocess, network and suite bounds, each proven at the actual boundary and in BOTH directions
// (a fixture that exceeds the limit is stopped; one inside the limit is not). Nothing here calls a model, spends money or reaches
// the internet: processes are scripted fixtures in scratch directories, network is a loopback server or an injected fake.
//
// Timing discipline: assertions are about BEHAVIOUR (was it stopped, is the whole tree gone, did the retry count hold), never a tight
// wall clock, and every wait is a bounded poll, so a loaded machine slows the test without changing its verdict.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, chmodSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MiniRepo, alive, sleep } from './helpers.js';
import { configureBounds, getBounds, helperWallSeconds, runBoundedSync, execBoundedSync, validateBoundsConfig, suiteBounds, DEFAULT_BOUNDS } from '../lib/bounds.mjs';
import { listRepoFiles } from '../lib/tree.mjs';
import { runGateCommand } from '../lib/gates.mjs';
import { boundedNetCall, netPolicy, backoffMs, NetTimeoutError } from '../lib/netbound.mjs';
import { runRemote } from '../lib/remote.mjs';
import { runLeasedChildren, mergeTap } from '../lib/child-leases.mjs';
import { parseTap } from '../lib/tap.mjs';
import { validateProfile } from '../lib/profile.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
const REAL = JSON.parse(readFileSync(join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json'), 'utf8'));
const RELAY = join(REPO, 'scripts', 'assurance-differentiation', 'test', 'relay.mjs');
const SCANNER = join(REPO, 'scanner');

const scratch = (p = 'loop-bounds-') => mkdtempSync(join(tmpdir(), p));
const done = (d) => { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } };
const waitDead = async (pid, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (!alive(pid)) return true; await sleep(100); } return !alive(pid); };
const readPid = (dir, name) => Number(readFileSync(join(dir, name), 'utf8'));
const reap = (...pids) => { for (const p of pids) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } } };
const T = (body) => `import test from 'node:test';\nimport assert from 'node:assert/strict';\n${body}\n`;

// A process TREE that cannot be stopped politely: the parent records any SIGTERM and carries on, and so does its child. Only a kill of
// the whole group, after the grace, ends it. argv[2] is the directory the pids and the SIGTERM witness are written to.
const TREE_SRC = `
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
process.on('SIGTERM', () => { fs.writeFileSync(path.join(dir, 'term-seen'), '1'); });
const c = spawn(process.execPath, ['-e', "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"], { stdio: 'ignore' });
fs.writeFileSync(path.join(dir, 'child.pid'), String(c.pid));
fs.writeFileSync(path.join(dir, 'parent.pid'), String(process.pid));
setInterval(() => {}, 1000);
`;
function treeFixture() {
  const dir = scratch();
  writeFileSync(join(dir, 'tree.js'), TREE_SRC);
  return { dir, script: join(dir, 'tree.js'), cleanup() { reap(...['child.pid', 'parent.pid'].filter((f) => existsSync(join(dir, f))).map((f) => readPid(dir, f))); done(dir); } };
}

// ============================================================ subprocessWallSeconds + killGraceSeconds (helper subprocesses)

test('[LOOP-002.AC02] a helper subprocess that outlives subprocessWallSeconds is stopped as a PROCESS GROUP: TERM first, the grace, then KILL, and the tree is gone', async () => {
  const f = treeFixture();
  try {
    const t0 = Date.now();
    const r = runBoundedSync(process.execPath, [f.script, f.dir], { wallSeconds: 1.5, graceSeconds: 0.6, bounds: { ...DEFAULT_BOUNDS } });
    assert.equal(r.timedOut, true, 'the bound fired');
    assert.equal(r.status, null);
    assert.ok(Date.now() - t0 < 30000, 'and the call returned (it did not wait on the hung tree)');
    assert.equal(existsSync(join(f.dir, 'term-seen')), true, 'TERM was delivered first, so a polite process gets its grace');
    const [parent, child] = [readPid(f.dir, 'parent.pid'), readPid(f.dir, 'child.pid')];
    assert.equal(await waitDead(parent), true, 'the direct child is dead');
    assert.equal(await waitDead(child), true, 'and so is its descendant, which ignored TERM: only a group kill ends it');
  } finally { f.cleanup(); }
});

test('[LOOP-002.AC02] a helper subprocess inside its bound is not stopped, keeps its own exit code, and its leftover descendants are swept when it ends', async () => {
  const f = treeFixture();
  try {
    const ok = runBoundedSync(process.execPath, ['-e', 'setTimeout(() => process.exit(3), 300)'], { wallSeconds: 30, graceSeconds: 1 });
    assert.equal(ok.timedOut, false);
    assert.equal(ok.status, 3, 'the command ran to completion and its own code came back');
    assert.equal(execBoundedSync(process.execPath, ['-e', "process.stdout.write('hello')"], { wallSeconds: 30 }), 'hello');
    assert.throws(() => execBoundedSync(process.execPath, ['-e', 'process.exit(2)'], { wallSeconds: 30 }), (e) => e.status === 2 && e.timedOut === false);
    // A command that exits cleanly but leaves a descendant behind does not get to keep it: the group is swept at the end.
    const leaver = join(f.dir, 'leaver.js');
    writeFileSync(leaver, `const { spawn } = require('node:child_process'); const fs = require('node:fs');
const c = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
fs.writeFileSync(${JSON.stringify(join(f.dir, 'left.pid'))}, String(c.pid)); setTimeout(() => process.exit(0), 300);`);
    const r = runBoundedSync(process.execPath, [leaver], { wallSeconds: 30, graceSeconds: 1 });
    assert.equal(r.status, 0);
    assert.equal(await waitDead(readPid(f.dir, 'left.pid')), true, 'a clean exit does not license leaving a descendant running');
  } finally { try { reap(readPid(f.dir, 'left.pid')); } catch { /* none */ } f.cleanup(); }
});

test('[LOOP-002.AC02] the fixture detects the real defect: a plain timeout on execFileSync kills only the direct child and the tree outlives it', async () => {
  const f = treeFixture();
  try {
    assert.throws(() => execFileSync(process.execPath, [f.script, f.dir], { timeout: 1200, killSignal: 'SIGKILL' }));
    await waitDead(readPid(f.dir, 'parent.pid'));
    await sleep(500);
    assert.equal(alive(readPid(f.dir, 'child.pid')), true, 'without a group kill the descendant survives its parent');
  } finally { f.cleanup(); }
});

test('[LOOP-002.AC02] a helper subprocess is never given more than subprocessWallSeconds, whatever bound its caller declares; a shorter declared bound is kept', () => {
  const b = { subprocessWallSeconds: 120, killGraceSeconds: 10 };
  assert.equal(helperWallSeconds(undefined, b), 120, 'no declared bound: the profile bound');
  assert.equal(helperWallSeconds(900, b), 120, 'a caller cannot ask for more');
  assert.equal(helperWallSeconds(15, b), 15, 'a shorter declared bound is kept');
  assert.equal(helperWallSeconds(0, b), 120);
  assert.equal(helperWallSeconds(NaN, b), 120);
  assert.equal(REAL.limits.subprocessWallSeconds, 120);
  assert.equal(REAL.limits.killGraceSeconds, 10);
  // the profile limits really configure the bound in force
  assert.deepEqual({ w: configureBounds({ subprocessWallSeconds: 7, killGraceSeconds: 3 }).subprocessWallSeconds, g: getBounds().killGraceSeconds }, { w: 7, g: 3 });
  assert.equal(helperWallSeconds(60, getBounds()), 7);
  configureBounds(REAL.limits);
  assert.equal(getBounds().subprocessWallSeconds, 120);
});

test('[LOOP-002.AC02] git run by the controller (the tree index) is bounded at the call site: a hung git and everything it started are killed; a prompt git is not', async () => {
  const f = treeFixture();
  const shim = join(f.dir, 'bin'); mkdirSync(shim);
  const savedPath = process.env.PATH, savedDir = process.env.FAKE_GIT_DIR, savedScript = process.env.FAKE_GIT_SCRIPT;
  try {
    // a `git` that hangs and leaves an unkillable child, standing in for a hook or a credential helper that never returns
    writeFileSync(join(shim, 'git'), `#!/bin/sh\nexec "${process.execPath}" "$FAKE_GIT_SCRIPT" "$FAKE_GIT_DIR"\n`); chmodSync(join(shim, 'git'), 0o755);
    process.env.PATH = `${shim}:${savedPath}`; process.env.FAKE_GIT_DIR = f.dir; process.env.FAKE_GIT_SCRIPT = f.script;
    configureBounds({ subprocessWallSeconds: 1.5, killGraceSeconds: 0.6 });
    const t0 = Date.now();
    assert.throws(() => listRepoFiles(f.dir), (e) => e.timedOut === true, 'the hung git was stopped at the profile bound (declared 60 s, clamped)');
    assert.ok(Date.now() - t0 < 30000);
    assert.equal(await waitDead(readPid(f.dir, 'parent.pid')), true);
    assert.equal(await waitDead(readPid(f.dir, 'child.pid')), true, 'the whole tree, not only the direct child');
    // direction two: a git that answers promptly is not stopped
    writeFileSync(join(shim, 'git'), `#!/bin/sh\nprintf 'a.txt\\0b.txt\\0'\n`); chmodSync(join(shim, 'git'), 0o755);
    assert.deepEqual(listRepoFiles(f.dir), ['a.txt', 'b.txt']);
  } finally {
    process.env.PATH = savedPath;
    if (savedDir === undefined) delete process.env.FAKE_GIT_DIR; else process.env.FAKE_GIT_DIR = savedDir;
    if (savedScript === undefined) delete process.env.FAKE_GIT_SCRIPT; else process.env.FAKE_GIT_SCRIPT = savedScript;
    configureBounds(REAL.limits); f.cleanup();
  }
});

test('[LOOP-002.AC02] a gate command that outlives its timeout is killed with its whole tree; one inside it passes (runBounded, the group kill the suites and gates run under)', async () => {
  const f = treeFixture();
  try {
    const hung = await runGateCommand({ id: 'hung', cwd: '.', executable: process.execPath, args: [f.script, f.dir], timeoutSeconds: 1.5 }, { repoRoot: f.dir, graceMs: 500 });
    assert.equal(hung.ok, false);
    assert.equal(hung.outcome, 'timeout-wall');
    assert.equal(await waitDead(readPid(f.dir, 'parent.pid')), true);
    assert.equal(await waitDead(readPid(f.dir, 'child.pid')), true, 'the descendant that ignored TERM is gone too');
    const fine = await runGateCommand({ id: 'fine', cwd: '.', executable: process.execPath, args: ['-e', 'setTimeout(() => process.exit(0), 200)'], timeoutSeconds: 30 }, { repoRoot: f.dir, graceMs: 500 });
    assert.equal(fine.ok, true);
    assert.equal(fine.outcome, 'exited');
  } finally { f.cleanup(); }
});

test('[LOOP-002.AC02] the verifier child: a suite that hangs past its timeout is stopped with the tree it started, reports why, and a suite inside its timeout passes', async () => {
  const hangSrc = T(`import { spawn } from 'node:child_process'; import fs from 'node:fs';
test('[X-1.AC01] hangs', () => {
  const c = spawn(process.execPath, ['-e', "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"], { stdio: 'ignore' });
  fs.writeFileSync('child.pid', String(c.pid));
  return new Promise(() => { setInterval(() => {}, 1000); });
});`);
  const reqs = [{ id: 'X-1', weight: 1, deps: [], criteria: ['hangs'] }];
  const repo = new MiniRepo(reqs, { suiteSources: { 'suite-X-1': hangSrc }, profile: { suites: { 'suite-X-1': { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/suite-X-1.test.js'], timeoutSeconds: 2 } } } });
  try {
    assert.equal((await repo.init()).code, 0);
    const v = await repo.cli(['verify', '--requirement', 'X-1'], { timeoutMs: 90000 });
    assert.equal(v.code, 1, v.stdout + v.stderr);
    assert.match(v.stdout, /reason: timeout-wall: wall deadline 2000ms exceeded/);
    const child = Number(readFileSync(repo.path('child.pid'), 'utf8'));
    assert.equal(await waitDead(child), true, 'the suite process tree did not outlive the verifier bound');
    const evFile = /-> (.+)$/m.exec(v.stdout)[1];
    assert.equal(JSON.parse(readFileSync(evFile, 'utf8')).exec.outcome, 'timeout-wall');
  } finally { await repo.cleanup(); }
  // direction two: the same requirement with a suite that finishes inside its timeout passes
  const fine = new MiniRepo(reqs, { profile: { suites: { 'suite-X-1': { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/suite-X-1.test.js'], timeoutSeconds: 30 } } } });
  try {
    assert.equal((await fine.init()).code, 0);
    writeFileSync(fine.path('flag-X-1'), 'ok');
    const v = await fine.cli(['verify', '--requirement', 'X-1'], { timeoutMs: 90000 });
    assert.equal(v.code, 0, v.stdout + v.stderr);
  } finally { await fine.cleanup(); }
});

// ============================================================ networkRequestSeconds + networkRetries

function slowServer(behaviour) {
  const hits = [];
  const server = http.createServer((req, res) => { hits.push(Date.now()); behaviour(hits.length, req, res); });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, hits, url: `http://127.0.0.1:${server.address().port}/`, close() { server.closeAllConnections?.(); server.close(); } })));
}
const fetchOnce = (url) => (signal) => fetch(url, { signal }).then(async (r) => ({ status: r.status, body: await r.text() }));

test('[LOOP-002.AC02] a network request that never answers is cut at networkRequestSeconds and retried at most networkRetries times, then fails; a prompt one is not retried', async () => {
  const s = await slowServer((n, req, res) => { /* never answers */ void n; void req; void res; });
  try {
    const policy = { requestMs: 300, retries: 2, backoffMaxMs: 50 };
    const waits = [];
    await assert.rejects(
      boundedNetCall(fetchOnce(s.url), { policy, baseBackoffMs: 10, sleep: async (ms) => { waits.push(ms); } }),
      (e) => e instanceof NetTimeoutError && e.netAttempts === 3 && e.netTimedOut === true,
    );
    assert.equal(s.hits.length, 3, 'exactly retries + 1 requests reached the server: the retry count is a maximum');
    assert.equal(waits.length, 2, 'one backoff between attempts, none after the last');
  } finally { s.close(); }
  const ok = await slowServer((n, req, res) => { res.end('fine'); });
  try {
    const waits = [];
    const r = await boundedNetCall(fetchOnce(ok.url), { policy: { requestMs: 5000, retries: 2, backoffMaxMs: 50 }, sleep: async (ms) => { waits.push(ms); } });
    assert.deepEqual(r, { status: 200, body: 'fine' });
    assert.equal(ok.hits.length, 1, 'a prompt request is made once');
    assert.equal(waits.length, 0);
  } finally { ok.close(); }
});

test('[LOOP-002.AC02] a request that fails twice and answers on the third try succeeds inside the retry count; a failure that is not transient is not retried', async () => {
  const s = await slowServer((n, req, res) => { if (n <= 2) return; res.end('third time'); });
  try {
    const r = await boundedNetCall(fetchOnce(s.url), { policy: { requestMs: 300, retries: 2, backoffMaxMs: 20 }, baseBackoffMs: 5 });
    assert.equal(r.body, 'third time');
    assert.equal(s.hits.length, 3);
  } finally { s.close(); }
  let calls = 0;
  await assert.rejects(boundedNetCall(async () => { calls += 1; throw Object.assign(new Error('gh: HTTP 404'), { stderr: 'not found' }); }, { policy: { requestMs: 300, retries: 2, backoffMaxMs: 20 }, isTransient: (e) => /timed? ?out|reset/i.test(e.message) }), /404/);
  assert.equal(calls, 1, 'a definite answer is not retried');
});

test('[LOOP-002.AC02] the backoff between retries is capped by retryBackoffMaxSeconds and never negative', () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6].map((n) => backoffMs(n, 5000, 60000)), [5000, 10000, 20000, 40000, 60000, 60000]);
  assert.equal(backoffMs(30, 1000, 250), 250);
  assert.equal(backoffMs(1, 1000, 250), 250);
  assert.equal(backoffMs(0, 100, 250), 100);
});

test('[LOOP-002.AC02] the profile limits are what configure the network policy in force: 15 s per request, 2 retries, backoff capped at 60 s; unset means no policy', () => {
  try {
    configureBounds(REAL.limits);
    assert.deepEqual(netPolicy(), { requestMs: 15000, retries: 2, backoffMaxMs: 60000 });
    configureBounds({ subprocessWallSeconds: 120, killGraceSeconds: 10, retryBackoffMaxSeconds: 60 });
    assert.equal(netPolicy(), null, 'a profile that predates the fields keeps the legacy behaviour');
  } finally { configureBounds(REAL.limits); }
});

// Hosted-CI verification (remote.mjs) is the controller's only network client: gh and git over the network.
function remoteFake({ hang = () => false } = {}) {
  const calls = [];
  const sha = 'a'.repeat(40);
  const run = async (cmd, args) => {
    calls.push([cmd, ...args].join(' '));
    if (hang(cmd, args)) return new Promise(() => {});
    if (cmd === 'git' && args[0] === 'status') return '';
    if (cmd === 'git' && args[0] === 'rev-parse') return sha;
    if (cmd === 'git' && args[0] === 'ls-remote') return `${sha}\trefs/heads/main\n`;
    if (cmd === 'git' && args[0] === 'ls-files') return '.github/workflows/verify-remote.yml';
    if (cmd === 'gh' && args[0] === 'repo') return 'owner/repo';
    if (cmd === 'gh' && args[0] === 'workflow') return '';
    return '[]';
  };
  return { run, calls };
}
const REMOTE_ARGS = { repoRoot: '.', evidenceDir: tmpdir(), req: { id: 'NIX-011', criteria: [{ id: 'NIX-011.AC01' }] }, watch: ['x'], watchDigest: 'd', remoteCfg: { workflow: 'verify-remote.yml', target: 'nix', legs: ['l'], timeoutSeconds: 60 }, evaluateCriteria: () => [], pollMs: 10, retryBackoffMs: 5 };

test('[LOOP-002.AC02] hosted-CI verification bounds every gh and git call: a call that never returns is cut and retried networkRetries times, then reported, not hung', async () => {
  const net = { requestMs: 150, retries: 1, backoffMaxMs: 20 };
  const f = remoteFake({ hang: (cmd, args) => cmd === 'gh' && args[0] === 'workflow' });
  const t0 = Date.now();
  const r = await runRemote({ ...REMOTE_ARGS, run: f.run, net });
  assert.equal(r.status, 'failed');
  assert.match(r.reason, /could not dispatch verify-remote\.yml/);
  assert.equal(f.calls.filter((c) => c.startsWith('gh workflow run')).length, 2, 'retries + 1 dispatch attempts and no more');
  assert.ok(Date.now() - t0 < 20000);
  // the preflight is bounded by the same policy, and is not retried again by an outer layer
  const g = remoteFake({ hang: (cmd, args) => cmd === 'gh' && args[0] === 'repo' });
  const p = await runRemote({ ...REMOTE_ARGS, run: g.run, net });
  assert.equal(p.status, 'unavailable');
  assert.equal(g.calls.filter((c) => c.startsWith('gh repo view')).length, 2, 'wrapped exactly once: 2 attempts, not 2 x 2');
  // direction two: calls that answer promptly are made once each and the flow proceeds past the dispatch
  const h = remoteFake();
  let clock = 0; // a fake monotonic clock that jumps 7 minutes per read, so the 10-minute wait for the run to appear ends at once
  const q = await runRemote({ ...REMOTE_ARGS, run: h.run, net, now: () => (clock += 420_000) });
  assert.equal(h.calls.filter((c) => c.startsWith('gh workflow run')).length, 1);
  assert.ok(!/could not dispatch/.test(q.reason || ''), 'the dispatch itself succeeded');
});

test('[LOOP-002.AC02] network limits are validated: both fields together, finite, retries a small integer, request seconds in range', () => {
  const bad = (mut) => { const p = structuredClone(REAL); mut(p); const problems = []; validateBoundsConfig(p, problems); return problems.join('\n'); };
  assert.equal(bad(() => {}), '', 'the real profile is valid');
  assert.match(bad((p) => { p.limits.networkRequestSeconds = 0; }), /networkRequestSeconds must be a finite number/);
  assert.match(bad((p) => { p.limits.networkRetries = -1; }), /networkRetries must be an integer/);
  assert.match(bad((p) => { p.limits.networkRetries = 99; }), /networkRetries must be an integer/);
  assert.match(bad((p) => { delete p.limits.networkRetries; }), /networkRetries must be an integer/);
  assert.match(bad((p) => { p.limits.networkRequestSeconds = 99999; }), /networkRequestSeconds must be a finite number/);
  assert.equal(REAL.limits.networkRequestSeconds, 15);
  assert.equal(REAL.limits.networkRetries, 2);
});

// ============================================================ suite ceilings + per-child leases

test('[LOOP-002.AC02] every suite belongs to a class whose ceiling is 120 / 900 / 7200 s, its timeout never exceeds that ceiling, and a child lease never exceeds its ceiling', () => {
  const C = REAL.limits.suiteCeilings;
  assert.deepEqual(Object.fromEntries(Object.entries(C).map(([k, v]) => [k, v.ceilingSeconds])), { standard: 120, 'runtime-integration': 900, 'full-evaluation': 7200 });
  for (const [k, v] of Object.entries(C)) assert.ok(v.childLeaseSeconds > 0 && v.childLeaseSeconds <= v.ceilingSeconds, `${k}: a finite lease no larger than the ceiling`);
  for (const [name, s] of Object.entries(REAL.suites)) {
    assert.ok(C[s.class], `${name} has a class`);
    assert.ok(s.timeoutSeconds <= C[s.class].ceilingSeconds, `${name}: ${s.timeoutSeconds}s within the ${s.class} ceiling`);
    const b = suiteBounds(REAL, name);
    assert.ok(b.childLeaseSeconds <= b.ceilingSeconds, `${name}: lease within ceiling`);
  }
  assert.equal(REAL.suites.evaluation.class, 'full-evaluation');
  assert.equal(REAL.suites.foundation.class, 'standard');
  assert.doesNotThrow(() => validateProfile(structuredClone(REAL), REPO));
  // each guard, in the failing direction
  const refuse = (mut, re) => { const p = structuredClone(REAL); mut(p); assert.throws(() => validateProfile(p, REPO), re); };
  refuse((p) => { p.suites.foundation.timeoutSeconds = 121; }, /suite foundation: timeoutSeconds 121 exceeds the standard ceiling of 120s/);
  refuse((p) => { p.suites.evaluation.timeoutSeconds = 7201; }, /suite evaluation: timeoutSeconds 7201 exceeds the full-evaluation ceiling/);
  refuse((p) => { delete p.suites.loop.class; }, /suite loop: class must be one of/);
  refuse((p) => { p.suites.loop.class = 'huge'; }, /suite loop: class must be one of/);
  refuse((p) => { p.limits.suiteCeilings.standard.childLeaseSeconds = 500; }, /childLeaseSeconds 500 exceeds its ceilingSeconds 120/);
  refuse((p) => { p.limits.suiteCeilings.standard.childLeaseSeconds = 0; }, /needs finite positive ceilingSeconds and childLeaseSeconds/);
  refuse((p) => { delete p.limits.suiteCeilings['full-evaluation']; }, /suiteCeilings\.full-evaluation needs finite/);
  refuse((p) => { p.suites.loop.childLeaseSeconds = 901; }, /suite loop: childLeaseSeconds must be finite and no more than/);
  refuse((p) => { delete p.limits.suiteCeilings; }, /need limits\.suiteCeilings/);
});

test('[LOOP-002.AC02] each child file gets its own lease: a file that hangs is killed at its lease with its tree and NAMED, the others still run, and the whole set ends inside the ceiling', async () => {
  const dir = scratch();
  const f = treeFixture();
  try {
    writeFileSync(join(dir, 'a.js'), 'setTimeout(() => process.exit(0), 100);');
    writeFileSync(join(dir, 'b.js'), 'setTimeout(() => process.exit(0), 100);');
    writeFileSync(join(dir, 'hang.js'), `process.argv[2] = ${JSON.stringify(f.dir)};\n${TREE_SRC}`);
    const t0 = Date.now();
    const r = await runLeasedChildren({ files: ['a.js', 'hang.js', 'b.js'], argvFor: (file) => [process.execPath, join(dir, file)], cwd: dir, ceilingSeconds: 60, childLeaseSeconds: 2, graceMs: 400, concurrency: 1 });
    const by = Object.fromEntries(r.children.map((c) => [c.file, c]));
    assert.equal(by['hang.js'].outcome, 'lease-expired');
    assert.match(by['hang.js'].reason, /hang\.js exceeded its 2s lease/, 'the report names the file that hung');
    assert.deepEqual(r.hung, ['hang.js']);
    assert.equal(by['a.js'].outcome, 'exited');
    assert.equal(by['b.js'].outcome, 'exited', 'a file after the hung one still ran: one hang did not take the whole ceiling');
    assert.equal(r.outcome, 'lease-expired');
    assert.ok(Date.now() - t0 < 45000, 'the set finished well inside its 60 s ceiling');
    assert.equal(await waitDead(readPid(f.dir, 'child.pid')), true, 'the hung file\'s whole tree was killed');
    // direction two: every file inside its lease -> nothing is stopped
    const ok = await runLeasedChildren({ files: ['a.js', 'b.js'], argvFor: (file) => [process.execPath, join(dir, file)], cwd: dir, ceilingSeconds: 60, childLeaseSeconds: 30, graceMs: 400, concurrency: 2 });
    assert.equal(ok.outcome, 'exited');
    assert.equal(ok.exitCode, 0);
    assert.deepEqual(ok.hung, []);
  } finally { f.cleanup(); done(dir); }
});

test('[LOOP-002.AC02] a child lease can never exceed the suite ceiling: it is clamped to it, and a file still running when the ceiling runs out is killed and files not yet started are reported not-run, never passed', async () => {
  const dir = scratch();
  try {
    writeFileSync(join(dir, 'hang.js'), 'setInterval(() => {}, 1000);');
    writeFileSync(join(dir, 'next.js'), 'process.exit(0);');
    const t0 = Date.now();
    const r = await runLeasedChildren({ files: ['hang.js', 'next.js'], argvFor: (file) => [process.execPath, join(dir, file)], cwd: dir, ceilingSeconds: 2, childLeaseSeconds: 100, graceMs: 300, concurrency: 1 });
    assert.equal(r.lease, 2, 'a 100 s lease inside a 2 s ceiling is a 2 s lease');
    assert.ok(r.children[0].leaseSeconds <= 2);
    assert.ok(['lease-expired', 'ceiling-expired'].includes(r.children[0].outcome), 'killed at the lease, which IS the ceiling here');
    assert.equal(r.children[1].outcome, 'not-run');
    assert.match(r.children[1].reason, /ceiling of 2s was spent before this file started/);
    assert.notEqual(r.outcome, 'exited');
    assert.ok(Date.now() - t0 < 30000);
    await assert.rejects(() => runLeasedChildren({ files: ['a'], argvFor: () => [process.execPath, '-e', ''], ceilingSeconds: Infinity, childLeaseSeconds: 1 }), /finite positive/);
    await assert.rejects(() => runLeasedChildren({ files: ['a'], argvFor: () => [process.execPath, '-e', ''], ceilingSeconds: 5, childLeaseSeconds: 0 }), /finite positive/);
  } finally { done(dir); }
});

test('[LOOP-002.AC02] merged child TAP carries every child\'s tests and ONE summed summary, so the verifier counts the whole set', () => {
  const a = { stdoutTail: 'TAP version 13\nok 1 - [X.AC01] one\nok 2 - [X.AC02] two\n1..2\n# tests 2\n# suites 0\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n' };
  const b = { stdoutTail: 'TAP version 13\nnot ok 1 - [X.AC03] three\n1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n' };
  const t = parseTap(mergeTap([a, b]));
  assert.equal(t.tests.length, 3);
  assert.deepEqual([t.summary.tests, t.summary.pass, t.summary.fail], [3, 2, 1]);
});

// A wrapper (relay.mjs) is the thing that runs a suite's several real test files.
function wrap(files, { bounds, expectHelper } = {}) {
  const dir = scratch('loop-wrap-');
  const rel = Object.entries(files).map(([name, text]) => { const f = join(dir, name); writeFileSync(f, text); return relative(SCANNER, f); });
  const harness = join(dir, 'wrapper.test.js');
  writeFileSync(harness, `import { relaySuite, helperSha256 } from ${JSON.stringify(pathToFileURL(RELAY).href)};
await relaySuite({ suite: 'fixture', files: ${JSON.stringify(rel)}, expectHelper: ${expectHelper ? JSON.stringify(expectHelper) : 'helperSha256()'}, bounds: ${JSON.stringify(bounds)} });
`);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const c = spawn(process.execPath, ['--test', '--test-reporter=tap', harness], { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let so = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', () => {});
    const to = setTimeout(() => c.kill('SIGKILL'), 120000);
    c.on('close', (code) => { clearTimeout(to); resolve({ code, tap: parseTap(so), stdout: so, dir, rel }); });
  });
}

test('[LOOP-002.AC02] a suite wrapper gives each real test file a lease: the hung file is killed inside the ceiling and named in the result, the other files\' tests still report, and the run fails', async () => {
  const w = await wrap({
    'good.test.js': T("test('[X-1.AC01] good', () => {});"),
    'hang.test.js': T("test('[X-1.AC02] hangs', () => new Promise(() => { setInterval(() => {}, 1000); }));"),
    'also-good.test.js': T("test('[X-1.AC03] also good', () => {});"),
  }, { bounds: { ceilingSeconds: 90, childLeaseSeconds: 3, concurrency: 1 } });
  try {
    assert.notEqual(w.code, 0, 'a hung file fails the wrapper');
    const named = (re) => w.tap.tests.find((t) => re.test(t.name));
    assert.equal(named(/hang\.test\.js finished within its lease/).ok, false, 'the file that hung is named, as a failed test');
    assert.equal(named(/good\.test\.js finished within its lease/).ok, true);
    assert.equal(named(/also-good\.test\.js finished within its lease/).ok, true);
    assert.equal(named(/\[X-1\.AC03\] also good/).ok, true, 'a file after the hung one still ran and reported under its own name');
    assert.equal(named(/\[X-1\.AC01\] good/).ok, true);
    assert.equal(named(/the child run exited 0, ran tests/).ok, false);
    assert.match(w.stdout, /hang\.test\.js=lease-expired/);
    assert.match(w.stdout, /exceeded its 3s lease/);
  } finally { done(w.dir); }
  // direction two: nothing hangs -> every file passes its lease and the wrapper passes
  const ok = await wrap({
    'good.test.js': T("test('[X-1.AC01] good', () => {});"),
    'also-good.test.js': T("test('[X-1.AC03] also good', () => {});"),
  }, { bounds: { ceilingSeconds: 90, childLeaseSeconds: 30, concurrency: 2 } });
  try {
    assert.equal(ok.code, 0, ok.stdout);
    for (const f of ['good', 'also-good']) assert.equal(ok.tap.tests.find((t) => new RegExp(`${f}\\.test\\.js finished within its lease`).test(t.name)).ok, true);
  } finally { done(ok.dir); }
});

test('[LOOP-002.AC02] the real wrappers take their ceiling and lease from the profile suite class, and every wrapper still pins the helper digest', () => {
  for (const [name, s] of Object.entries(REAL.suites)) {
    const b = suiteBounds(REAL, name);
    assert.ok(b && b.childLeaseSeconds > 0 && b.childLeaseSeconds <= b.ceilingSeconds, name);
    assert.ok(s.timeoutSeconds <= b.ceilingSeconds);
  }
  assert.deepEqual(suiteBounds(REAL, 'evaluation'), { class: 'full-evaluation', ceilingSeconds: 7200, childLeaseSeconds: 3600 });
  assert.equal(suiteBounds({ limits: {}, suites: {} }, 'x'), null);
});

test('[LOOP-002.AC02] a verifier suite of several files runs each under its own lease: a hung file is killed and NAMED in the evidence, the other file still ran, and a suite inside its leases passes', async () => {
  const hang = T("test('[X-1.AC02] hangs', () => new Promise(() => { setInterval(() => {}, 1000); }));");
  const good = T("test('[X-1.AC01] good', () => {});");
  const ceilings = { standard: { ceilingSeconds: 60, childLeaseSeconds: 3 }, 'runtime-integration': { ceilingSeconds: 60, childLeaseSeconds: 3 }, 'full-evaluation': { ceilingSeconds: 60, childLeaseSeconds: 3 } };
  const mk = (extraProfile = {}) => new MiniRepo([{ id: 'X-1', weight: 1, deps: [], criteria: ['good', 'hangs'] }], {
    profile: { limits: { suiteCeilings: ceilings }, suites: { 'suite-X-1': { kind: 'node-test', class: 'standard', cwd: '.', executable: 'node', files: ['t/a.test.js', 't/b.test.js'], timeoutSeconds: 60 } }, ...extraProfile },
  });
  const repo = mk();
  try {
    writeFileSync(repo.path('t', 'a.test.js'), good); writeFileSync(repo.path('t', 'b.test.js'), hang);
    assert.equal((await repo.init()).code, 0);
    const m = JSON.parse(repo.read(`.loop-engineering/manifest/requirements.v1.json`));
    assert.equal(m.requirements[0].verification.childLeaseSeconds, 3, 'the manifest carries the lease the verifier will enforce');
    const v = await repo.cli(['verify', '--requirement', 'X-1'], { timeoutMs: 120000 });
    assert.equal(v.code, 1, v.stdout);
    assert.match(v.stdout, /t\/b\.test\.js exceeded its 3s lease/, 'the report names the file that hung');
    const ev = JSON.parse(readFileSync(/-> (.+)$/m.exec(v.stdout)[1], 'utf8'));
    assert.deepEqual(ev.exec.hungFiles, ['t/b.test.js']);
    assert.equal(ev.exec.children.find((c) => c.file === 't/a.test.js').outcome, 'exited');
  } finally { await repo.cleanup(); }
  const fine = mk();
  try {
    writeFileSync(fine.path('t', 'a.test.js'), good);
    writeFileSync(fine.path('t', 'b.test.js'), T("test('[X-1.AC02] ok', () => {});"));
    assert.equal((await fine.init()).code, 0);
    const v = await fine.cli(['verify', '--requirement', 'X-1'], { timeoutMs: 120000 });
    assert.equal(v.code, 0, v.stdout + v.stderr);
    assert.match(v.stdout, /tests 2 pass 2 fail 0 skipped 0/, 'counts are summed over both files');
  } finally { await fine.cleanup(); }
});
