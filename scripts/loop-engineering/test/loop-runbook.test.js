// DOC-003: the background loop and operations runbook (docs/guides/loop-engineering.md).
// Suite "loop-runbook" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// The runbook's commands are EXECUTED here against a disposable repository with a scripted worker, so a command or flag the
// page documents but the controller does not implement fails this suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MiniRepo, alive, RUN_MJS } from './helpers.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DOC = readFileSync(join(ROOT, 'docs', 'guides', 'loop-engineering.md'), 'utf8');
const PROFILE = JSON.parse(readFileSync(join(ROOT, 'scripts', 'loop-engineering', 'profiles', 'haskell-nix.json'), 'utf8'));
const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
const waitTerminal = (repo, timeoutMs = 60000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs, label: 'terminal status' });
const limits = { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 };

/** Every command line in a fenced block of the page that invokes the controller. */
const documented = () => [...DOC.matchAll(/```bash\n([\s\S]*?)```/g)].flatMap((m) => m[1].split('\n')).filter((l) => l.startsWith('node scripts/loop-engineering/run.mjs '));

test('[DOC-003.AC03] every documented command is one the controller implements, and each documented limit exists in the profile', () => {
  const help = spawnSync(process.execPath, [RUN_MJS, '--help'], { encoding: 'utf8' });
  const usage = `${help.stdout}${help.stderr}`;
  const cmds = documented();
  assert.ok(cmds.length >= 10, 'the page documents the lifecycle commands');
  for (const line of cmds) {
    const sub = line.split(/\s+/)[2];
    assert.match(usage, new RegExp(`^\\s+(?:[a-z]+ \\| )*${sub}\\b`, 'm'), `"${sub}" is documented but not in run.mjs --help`);
  }
  for (const want of ['init', 'preflight', 'plan', 'start', 'status', 'pause', 'resume', 'retry', 'verify', 'stop']) assert.ok(cmds.some((c) => c.split(/\s+/)[2] === want), `the page does not show ${want}`);
  for (const key of DOC.match(/`(?:[a-z]+(?:[A-Z][a-z]+)+)`/g).map((k) => k.slice(1, -1)).filter((k) => k !== 'timeoutSeconds' /* a suite field, not a limit */ && (k in PROFILE.limits || /Seconds$|Usd$|Mib$|MiB$|Attempts|Repeats/.test(k)))) {
    assert.ok(key in PROFILE.limits || key in (PROFILE.limits.resource || {}), `the page names the limit ${key}, which the profile does not define`);
  }
});

test('[DOC-003.AC03] the runbook distinguishes the new loop tooling from the shipped scanner and promises nothing beyond finite budgets', () => {
  assert.match(DOC, /new development tool\*?, not part of the scanner/i);
  assert.match(DOC, /not installed with the package/i);
  assert.match(DOC, /It is finite/);
  assert.match(DOC, /does not promise unattended completion/i);
  assert.match(DOC, /installs no launch agent or service of its own/i);
  assert.match(DOC, /none is shipped or tested here/i);
  assert.ok(!/runs? (forever|indefinitely|until done)|fully (autonomous|unattended)/i.test(DOC), 'no unbounded-execution promise');
  for (const must of ['runWallSeconds', 'runMaxAttempts', 'attemptsPerRequirement', 'sameFailureRepeats', 'claudeBudgetUsd']) assert.ok(DOC.includes(must), `the finite budget ${must} is explained`);
});

test('[DOC-003.AC01] a clean-checkout dry run with the documented commands creates the manifest and a dashboard; a bounded worker completes a criterion', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 1, criteria: ['two'] }], { profile: { limits }, workerMode: { default: 'fix' } });
  try {
    const i = await repo.init();
    assert.equal(i.code, 0, i.stderr);
    assert.ok(readdirSync(repo.path('.loop-engineering', 'manifest')).length > 0, 'init froze a manifest');
    const pre = await repo.cli(['preflight']);
    assert.ok([0, 1].includes(pre.code), pre.stdout + pre.stderr);
    assert.match(pre.stdout + pre.stderr, /preflight (passed|FAILED)/);
    const plan = await repo.cli(['plan', '--next']);
    assert.equal(plan.code, 0, plan.stderr); assert.match(plan.stdout, /HS-00\d/);
    const s = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
    assert.equal(s.code, 0, s.stdout + s.stderr);
    assert.match(s.stdout, /dashboard:\s+http:\/\/127\.0\.0\.1:\d+/);
    const url = /dashboard:\s+(http:\/\/127\.0\.0\.1:\d+)/.exec(s.stdout)[1];
    assert.equal((await fetch(`${url}/api/status`)).status, 200, 'the dashboard answers');
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'completed');
    assert.equal(st.verifiedPercent, 100);
    assert.deepEqual(st.requirements.map((r) => r.state), ['verified', 'verified']);
  } finally { await repo.cleanup(); }
});

test('[DOC-003.AC01] a stalled worker is terminated within the bounds, with no orphan, and the run does not wait on it', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { workerMode: { default: 'orphan' } });
  try {
    assert.equal((await repo.init()).code, 0);
    const t = Date.now();
    assert.equal((await repo.cli(['start', '--background', '--serve', '127.0.0.1:0'])).code, 0);
    const st = await waitTerminal(repo, 50000);
    assert.ok(Date.now() - t < 50000);
    assert.notEqual(st.status, 'completed');
    assert.notEqual(st.requirements[0].state, 'verified', 'a stalled worker never produces a verified requirement');
    const pid = Number(readFileSync(repo.path('orphan.pid'), 'utf8'));
    await repo.waitFor(() => !alive(pid), { timeoutMs: 15000, label: 'the worker orphan reclaimed' });
  } finally { await repo.cleanup(); }
});

test('[DOC-003.AC02] resume after an edit re-verifies stale evidence and re-works nothing that still passes', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 3, criteria: ['two'] }], { profile: { limits }, workerMode: { default: 'fix', perReq: { 'HS-002': 'silent-hang' } } });
  try {
    assert.equal((await repo.init()).code, 0);
    assert.equal((await repo.cli(['start', '--background', '--serve', '127.0.0.1:0'])).code, 0);
    await repo.waitFor(async () => { const s = await repo.status(); return s.requirements.find((r) => r.id === 'HS-001')?.state === 'verified' && s.current?.requirement === 'HS-002'; }, { timeoutMs: 40000, label: 'HS-001 verified, HS-002 working' });
    assert.equal((await repo.cli(['stop', '--run', repo.runId()], { timeoutMs: 20000 })).code, 0);
    writeFileSync(repo.path('flag-HS-001'), 'edited while the loop was down');
    const mid = await repo.status();
    const r1 = mid.requirements.find((r) => r.id === 'HS-001');
    assert.equal(r1.state, 'stale'); assert.ok(r1.staleReasons.length > 0, 'the stale state carries its reason');
    assert.ok(mid.verifiedPercent < 100);
    repo.setMode({ default: 'fix' });
    const res = await repo.cli(['resume']);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    const done = await waitTerminal(repo);
    assert.equal(done.status, 'completed'); assert.equal(done.verifiedPercent, 100);
  } finally { await repo.cleanup(); }
});

test('[DOC-003.AC02] a blocked authentication ends the run without a hidden prompt, and a missing tool blocks only its own requirement', async () => {
  const auth = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { workerMode: { default: 'auth-fail' } });
  const tool = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['needs a tool'], requiresTools: ['no-such-tool-xyz'] }, { id: 'HS-002', weight: 3, criteria: ['independent'] }], { workerMode: { default: 'fix' } });
  try {
    assert.equal((await auth.init()).code, 0);
    const t = Date.now();
    assert.equal((await auth.cli(['start', '--background', '--serve', '127.0.0.1:0'])).code, 0);
    const a = await waitTerminal(auth, 40000);
    assert.ok(Date.now() - t < 40000, 'it did not wait for input');
    assert.equal(a.status, 'blocked'); assert.ok(a.blockers.some((b) => b.type === 'auth-missing'));
    assert.equal(a.verifiedPercent, 0);
    // retry re-evaluates an EXTERNAL blocker but never bypasses the caps, and never prompts
    const rt = await auth.cli(['retry', '--requirement', 'HS-001'], { timeoutMs: 20000 });
    assert.ok(rt.code === 0 || /refused|re-?evaluat|not eligible|nothing|no live controller/i.test(rt.stdout + rt.stderr), rt.stdout + rt.stderr);

    assert.equal((await tool.init()).code, 0);
    assert.equal((await tool.cli(['start', '--background', '--serve', '127.0.0.1:0'])).code, 0);
    const b = await waitTerminal(tool);
    const by = Object.fromEntries(b.requirements.map((r) => [r.id, r]));
    assert.equal(by['HS-001'].state, 'blocked'); assert.equal(by['HS-001'].blockers[0].type, 'missing-tool');
    assert.equal(by['HS-002'].state, 'verified');
    assert.equal(by['HS-001'].attempts, 0, 'no model spend on work that cannot be verified here');
  } finally { await auth.cleanup(); await tool.cleanup(); }
});

test('[DOC-003.AC02] stop reclaims every owned process and the final status lists the remaining requirement ids', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 1, criteria: ['two'] }], { profile: { limits }, workerMode: { default: 'orphan' } });
  try {
    assert.equal((await repo.init()).code, 0);
    const s = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
    const pid = Number(/controller PID:\s+(\d+)/.exec(s.stdout)[1]);
    await repo.waitFor(() => existsSync(repo.path('orphan.pid')), { timeoutMs: 30000, label: 'the worker started a child' });
    const child = Number(readFileSync(repo.path('orphan.pid'), 'utf8'));
    assert.ok(alive(child));
    const stop = await repo.cli(['stop', '--run', repo.runId()], { timeoutMs: 30000 });
    assert.equal(stop.code, 0, stop.stderr);
    await repo.waitFor(() => !alive(child) && !alive(pid), { timeoutMs: 20000, label: 'controller and worker child reclaimed' });
    const final = await repo.status();
    assert.equal(final.status, 'stopped');
    const remaining = final.requirements.filter((r) => r.state !== 'verified').map((r) => r.id).sort();
    assert.deepEqual(remaining, ['HS-001', 'HS-002'], 'status names every unverified id');
    assert.ok(final.verifiedPercent < 100);
  } finally { await repo.cleanup(); }
});
