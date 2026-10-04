// LOOP-006: recovery, credentials, permissions and finite retries.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { StreamState, classifyWorker, buildWorkerArgs } from '../lib/claude.mjs';
import { MiniRepo, sleep } from './helpers.js';

const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
const waitTerminal = (repo, timeoutMs = 90000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs, label: 'terminal status' });
const events = (repo) => readFileSync(repo.runPath('events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
async function go(repo, flags = ['--background']) { const i = await repo.init(); assert.equal(i.code, 0, i.stderr); const s = await repo.cli(['start', ...flags]); assert.equal(s.code, 0, s.stdout + s.stderr); }

const fakeRun = (o = {}) => ({ outcome: 'exited', exitCode: 0, stderrTail: '', stdoutTail: '', ...o });
const lines = (...objs) => objs.map((o) => JSON.stringify(o));
function stream(ls) { const s = new StreamState(); for (const l of ls) s.feed(l); return s; }
const OK_RESULT = { type: 'result', subtype: 'success', is_error: false, result: 'done', total_cost_usd: 0.5, num_turns: 3, permission_denials: [] };

test('[LOOP-006.AC01] each blocker class is typed from the actual failure, with no waiting prompt', () => {
  const c = (run, ls = []) => classifyWorker(fakeRun(run), stream(ls));
  assert.ok(c({ exitCode: 1, stderrTail: 'Error: Not logged in. Please run /login' }).blockers.some((b) => b.type === 'auth-missing'), 'missing login');
  assert.ok(c({ exitCode: 1, stderrTail: 'API Error: 401 Unauthorized invalid api key' }).blockers.some((b) => b.type === 'auth-missing'));
  assert.ok(c({ exitCode: 2, stderrTail: 'error: unknown option --bogus' }).blockers.some((b) => b.type === 'unknown-cli-flag'), 'unknown CLI flag');
  assert.ok(c({ exitCode: 1, stderrTail: 'fetch failed: getaddrinfo ENOTFOUND api.anthropic.com' }).blockers.some((b) => b.type === 'network-unavailable'), 'network');
  assert.ok(c({ outcome: 'spawn-failed', exitCode: null, reason: 'spawn claude ENOENT' }).blockers.some((b) => b.type === 'worker-missing'), 'missing tool');
  const denied = c({}, lines({ type: 'result', subtype: 'success', is_error: false, result: 'x', permission_denials: [{ tool_name: 'Bash' }, { tool_name: 'Write' }] }));
  assert.ok(denied.blockers.some((b) => b.type === 'permission-denied' && /Bash/.test(b.detail)), 'denied tool');
  assert.equal(c({}, [JSON.stringify(OK_RESULT)]).blockers.length, 0, 'a clean run has no blockers');
});

test('[LOOP-006.AC01] failed authentication ends the run as blocked with an actionable blocker, within the deadline, without waiting', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 1, criteria: ['two'] }], { workerMode: { default: 'auth-fail' } });
  try {
    const t = Date.now();
    await go(repo);
    const st = await waitTerminal(repo, 40000);
    assert.ok(Date.now() - t < 40000);
    assert.equal(st.status, 'blocked');
    const b = st.blockers.find((x) => x.type === 'auth-missing');
    assert.ok(b, 'typed auth blocker');
    assert.match(b.detail, /log in interactively/);
    assert.equal(st.verifiedPercent, 0);
    // the same blocker stops further paid attempts: only the first requirement was tried
    assert.equal(repo.read('worker-calls.log').trim().split('\n').length, 1);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC01] a missing required tool blocks only its requirement; independent work continues', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['needs ghc'], requiresTools: ['no-such-tool-xyz'] }, { id: 'HS-002', weight: 3, criteria: ['independent'] }], { workerMode: { default: 'fix' } });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    const by = Object.fromEntries(st.requirements.map((r) => [r.id, r]));
    assert.equal(by['HS-001'].state, 'blocked');
    assert.equal(by['HS-001'].blockers[0].type, 'missing-tool');
    assert.deepEqual(by['HS-001'].blockers[0].tools, ['no-such-tool-xyz']);
    assert.equal(by['HS-001'].attempts, 0, 'no model spend on work that cannot be verified here');
    assert.equal(by['HS-002'].state, 'verified');
    assert.equal(st.status, 'blocked');
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC01] an unavailable worker executable is a typed run blocker', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { testHarness: { argv: ['/no/such/worker-binary'], monitorMs: 150, heartbeatMs: 300, graceMs: 500 } } });
  try {
    await go(repo);
    const st = await waitTerminal(repo, 40000);
    assert.equal(st.status, 'blocked');
    assert.ok(st.blockers.some((b) => b.type === 'worker-missing'));
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC02] two identical consecutive failures stop a requirement; it is not repeated', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { workerMode: { default: 'noop' } });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    const r = st.requirements[0];
    assert.equal(r.state, 'blocked');
    assert.equal(r.attempts, 2);
    assert.equal(r.blockers[0].type, 'repeated-failure');
    assert.match(r.blockers[0].detail, /materially different fix/);
    assert.equal(st.verifiedPercent, 0);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC02] three failed attempts stop a requirement even when the failures differ', async () => {
  // Relax the repeat rule so the attempt cap is the thing that fires; each mode fails differently.
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { limits: { sameFailureRepeats: 9 } }, workerMode: { default: 'noop' } });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    const r = st.requirements[0];
    assert.equal(r.attempts, 3);
    assert.equal(r.blockers[0].type, 'attempts-exhausted');
    assert.equal(r.state, 'blocked');
    assert.equal(repo.read('worker-calls.log').trim().split('\n').length, 3, 'no fourth attempt');
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC02] a finite spend budget pauses the run and awards nothing', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 2, criteria: ['two'] }, { id: 'HS-003', weight: 2, criteria: ['three'] }], {
    profile: { limits: { claudeBudgetUsd: 3, perAttemptBudgetUsd: 2, minAttemptBudgetUsd: 1 } }, workerMode: { default: 'noop', cost: 1.6 },
  });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'paused-budget');
    assert.match(st.statusReason, /budget/);
    assert.ok(st.verifiedPercent < 100);
    assert.equal(st.verifiedPercent, 0);
    assert.ok(st.budgets.usdUsed >= 2 && st.budgets.usdUsed <= 3.5, `spent ${st.budgets.usdUsed}`);
    assert.match(st.statusReason, /estimates, not exact charges/);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC02] a finite wall-clock or attempt budget also pauses', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 2, criteria: ['two'] }], { profile: { limits: { runMaxAttempts: 1, sameFailureRepeats: 9 } }, workerMode: { default: 'noop' } });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'paused-budget');
    assert.match(st.statusReason, /attempt budget of 1/);
    assert.equal(st.budgets.attemptsUsed, 1);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC03] restart rechecks the checkout and evidence, preserves history, and schedules only unfinished or stale work', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }, { id: 'HS-002', weight: 3, criteria: ['two'] }], {
    profile: { limits: { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 } }, workerMode: { default: 'fix', perReq: { 'HS-002': 'silent-hang' } },
  });
  try {
    await go(repo, ['--background', '--serve', '127.0.0.1:0']);
    await repo.waitFor(async () => { const s = await repo.status(); return s.requirements.find((r) => r.id === 'HS-001')?.state === 'verified' && s.current?.requirement === 'HS-002' && s.current.phase === 'worker' && s.current.pid ? s : null; }, { label: 'HS-001 verified, HS-002 in flight' });
    const stop = await repo.cli(['stop', '--run', repo.runId()], { timeoutMs: 20000 });
    assert.equal(stop.code, 0, stop.stderr);
    const before = events(repo).length;
    assert.equal((await repo.status()).status, 'stopped');
    // the checkout changes while the run is down: HS-001's evidence is now stale
    writeFileSync(repo.path('flag-HS-001'), 'edited while stopped');
    assert.equal((await repo.status()).requirements.find((r) => r.id === 'HS-001').state, 'stale');
    repo.setMode({ default: 'fix' });
    const res = await repo.cli(['resume']);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /new controller process/);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'completed');
    assert.equal(st.verifiedPercent, 100);
    const ev = events(repo);
    assert.ok(ev.length > before, 'history appended, not reset');
    assert.ok(ev.slice(0, before).some((e) => e.type === 'attempt-start' && e.requirement === 'HS-002'), 'earlier history preserved');
    const after = ev.slice(before);
    assert.ok(after.some((e) => e.type === 'controller-start' && e.restarts >= 1));
    assert.ok(after.some((e) => e.type === 'verify' && e.requirement === 'HS-001'), 'the stale requirement was re-verified');
    assert.equal(after.filter((e) => e.type === 'attempt-start' && e.requirement === 'HS-001').length, 0, 'a requirement whose suite still passes is not re-worked');
    assert.equal(repo.state().restarts, 1);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC03] resume refuses when the frozen PRD changed, and when a completed run has nothing to resume', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { workerMode: { default: 'fix' } });
  try {
    await go(repo);
    await waitTerminal(repo);
    writeFileSync(repo.path('PRD.md'), readFileSync(repo.path('PRD.md'), 'utf8') + '\nextra requirement text\n');
    const r = await repo.cli(['resume']);
    assert.notEqual(r.code, 0);
    assert.match(r.stdout + r.stderr, /completed|PRD changed/);
    const s = await repo.cli(['start', '--background']);
    assert.notEqual(s.code, 0);
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC04] exit 0 with an error result, no result, a truncated stream and permission denials never establish success', () => {
  const okLines = [JSON.stringify(OK_RESULT)];
  assert.equal(classifyWorker(fakeRun(), stream(okLines)).kind, 'completed');
  assert.equal(classifyWorker(fakeRun(), stream(okLines)).workerReportedOk, true);
  const errRes = classifyWorker(fakeRun({ exitCode: 0 }), stream(lines({ type: 'result', subtype: 'error_during_execution', is_error: true, result: 'boom', permission_denials: [] })));
  assert.equal(errRes.kind, 'error-result'); assert.equal(errRes.workerReportedOk, false);
  const maxTurns = classifyWorker(fakeRun({ exitCode: 0 }), stream(lines({ type: 'result', subtype: 'error_max_turns', is_error: false, result: '', permission_denials: [] })));
  assert.equal(maxTurns.kind, 'error-result');
  const none = classifyWorker(fakeRun({ exitCode: 0 }), stream(lines({ type: 'assistant', message: { id: 'a', content: [] } })));
  assert.equal(none.kind, 'no-result'); assert.equal(none.workerReportedOk, false);
  const trunc = new StreamState(); trunc.feed('{"type":"assistant","message":{"id":"m","content":[{"type":"te');
  assert.equal(classifyWorker(fakeRun({ exitCode: 0 }), trunc).kind, 'truncated-stream');
  const den = classifyWorker(fakeRun(), stream(lines({ ...OK_RESULT, permission_denials: [{ tool_name: 'Bash' }] })));
  assert.equal(den.kind, 'permission-denied'); assert.equal(den.workerReportedOk, false);
  assert.equal(classifyWorker(fakeRun({ exitCode: 1 }), stream(okLines)).kind, 'nonzero-exit');
  for (const o of ['timeout-wall', 'timeout-idle', 'resource-limit', 'cancelled', 'spawn-failed']) assert.equal(classifyWorker(fakeRun({ outcome: o, exitCode: null }), new StreamState()).kind, o);
  // turns are counted from DISTINCT message ids, so partial chunks cannot evade the cap
  const s = new StreamState();
  for (let i = 0; i < 5; i++) s.feed(JSON.stringify({ type: 'assistant', message: { id: 'same', content: [] } }));
  s.feed(JSON.stringify({ type: 'assistant', message: { id: 'other', content: [] } }));
  assert.equal(s.turns, 2);
});

test('[LOOP-006.AC04] end to end: an error-result worker is not success, a killed worker cost is labelled an estimate, a reported cost is labelled reported', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 1, criteria: ['one'] }, { id: 'HS-002', weight: 1, criteria: ['two'] }, { id: 'HS-003', weight: 1, criteria: ['three'] }], { workerMode: { default: 'noop', perReq: { 'HS-001': 'error-result', 'HS-002': 'die', 'HS-003': 'denied' } } });
  try {
    await go(repo);
    const st = await waitTerminal(repo);
    assert.equal(st.verifiedPercent, 0);
    const ends = events(repo).filter((e) => e.type === 'attempt-end');
    const kind = (id) => ends.find((e) => e.requirement === id);
    assert.equal(kind('HS-001').kind, 'error-result'); assert.equal(kind('HS-001').costIsEstimate, false);
    assert.equal(kind('HS-002').kind, 'signaled'); assert.equal(kind('HS-002').costIsEstimate, true);
    assert.equal(kind('HS-003').kind, 'permission-denied'); assert.ok(kind('HS-003').blockers.includes('permission-denied'));
    const by = Object.fromEntries(st.requirements.map((r) => [r.id, r]));
    assert.ok(by['HS-003'].blockers.some((b) => b.type === 'permission-denied'), 'the denial is recorded as a blocker');
    assert.ok(st.budgets.usdEstimated >= 0 && st.budgets.usdReported > 0, 'reported and estimated spend are tracked separately');
  } finally { await repo.cleanup(); }
});

test('[LOOP-006.AC04] the real worker argv is scoped, bounded and free of bypass flags', () => {
  const profile = JSON.parse(readFileSync(new URL('../profiles/haskell-nix.json', import.meta.url), 'utf8'));
  const flags = new Set(['--print', '--output-format', '--verbose', '--permission-mode', '--allowedTools', '--disallowedTools', '--include-partial-messages', '--permission-prompts', '--max-budget-usd', '--no-session-persistence', '--strict-mcp-config', '--mcp-config']);
  const args = buildWorkerArgs({ profile, features: flags, budgetUsd: 6 });
  assert.deepEqual(args.slice(0, 4), ['-p', '--output-format', 'stream-json', '--verbose']);
  assert.equal(args[args.indexOf('--permission-mode') + 1], 'dontAsk');
  assert.equal(args[args.indexOf('--permission-prompts') + 1], 'none');
  assert.equal(args[args.indexOf('--max-budget-usd') + 1], '6');
  assert.ok(!args.some((a) => /dangerously|bypass/i.test(a)));
  assert.ok(args[args.indexOf('--disallowedTools') + 1].includes('Bash(git push:*)'));
  // flags the installed CLI does not have are never passed
  const none = buildWorkerArgs({ profile, features: new Set(['--print']), budgetUsd: 6 });
  assert.ok(!none.includes('--permission-prompts') && !none.includes('--max-budget-usd') && !none.includes('--max-turns'));
});
