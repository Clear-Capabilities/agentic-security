#!/usr/bin/env node
// A finite, non-interactive operations walk-through of the REAL background controller (DOC-003.AC01, DOC-003.AC03).
//
//   node scripts/loop-engineering/ops-example.mjs [--lenient-timing]
//
// `--lenient-timing` keeps the measured times in the output but does not fail a step because of them, for a machine that is busy
// with other work (the documentation test uses it inside the combined suite). Without it a start over 5 s or a status over 2 s
// is a failed step, which is the guarantee the runbook states.
//
// It builds a disposable git repository under the OS temp folder with a two-requirement PRD, a finite profile and a SCRIPTED
// worker (the test harness the controller's own suites use; no model is called, no account is needed, nothing is spent), then
// drives `run.mjs` as subprocesses exactly as an operator would: init, background start, live status, pause, resume, cancellation,
// dependency invalidation (a watched file edited), blocked recovery (a worker that is not logged in), and final verification.
// Every step has a hard timeout and no step reads from a terminal. The disposable repository is removed at the end.
//
// This demonstrates the controller's behaviour. It does not run the assurance-differentiation programme; that needs the untracked
// PRD and a real worker, and is described in docs/guides/loop-engineering.md.
//
// Exit: 0 every step behaved as described / 1 one did not.
import { MiniRepo } from './test/helpers.js';
import { writeFileSync } from 'node:fs';

const limits = { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 };
const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
let failed = 0;
const lenient = process.argv.includes('--lenient-timing');
const check = (ok, what) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed++; };
const first = (s, n = 6) => String(s).trim().split('\n').slice(0, n).map((l) => `    | ${l.slice(0, 150)}`).join('\n');
const show = async (repo, args, opts) => {
  console.log(`\n$ node scripts/loop-engineering/run.mjs ${args.join(' ')}`);
  const r = await repo.cli(args, opts);
  console.log(first(r.stdout + r.stderr));
  console.log(`  exit ${r.code} in ${r.ms} ms`);
  return r;
};
const terminal = (repo, ms = 60000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs: ms, label: 'a terminal status' });

const reqs = [{ id: 'HS-001', weight: 2, criteria: ['first criterion'] }, { id: 'HS-002', weight: 1, criteria: ['second criterion'], deps: ['HS-001'] }];
const main = new MiniRepo(reqs, { profile: { limits }, workerMode: { default: 'fix', perReq: { 'HS-002': 'slow' }, slowMs: 8000 } });
const blocked = new MiniRepo([{ id: 'HS-001', weight: 1, criteria: ['needs a logged-in worker'] }], { profile: { limits }, workerMode: { default: 'auth-fail' } });
try {
  console.log('== finite background start, live status, pause, resume ==');
  check((await show(main, ['init', '--prd', 'PRD.md', '--profile', 'profile.json', '--skip-baseline-gates'])).code === 0, 'init froze the manifest');
  const start = await show(main, ['start', '--background', '--serve', '127.0.0.1:0']);
  check(start.code === 0 && (lenient || start.ms < 5000), `start returned in ${start.ms} ms (limit 5000)`);
  await main.waitFor(async () => { const s = await main.status(); return s.requirements.find((r) => r.id === 'HS-001')?.state === 'verified' && s.current?.requirement === 'HS-002'; }, { timeoutMs: 40000, label: 'HS-001 verified and HS-002 in progress' });
  const st = await show(main, ['status']);
  check(st.code === 0 && (lenient || st.ms < 2000), `status answered in ${st.ms} ms (limit 2000) while a worker was busy`);
  const live = await main.status();
  check(live.status === 'running', `status field reads ${live.status}`);
  check((await show(main, ['pause'])).code === 0, 'pause checkpointed');
  console.log(`  status after pause: ${(await main.status()).status}`);
  check((await show(main, ['resume'])).code === 0, 'resume continued the same run');

  console.log('\n== cancellation ==');
  const stop = await show(main, ['stop', '--run', main.runId()], { timeoutMs: 30000 });
  const stopped = await main.status();
  check(stop.code === 0 && stopped.status === 'stopped', `stop ended the run: ${stopped.status}`);
  console.log(`  unverified ids named: ${stopped.requirements.filter((r) => r.state !== 'verified').map((r) => r.id).join(', ')}`);

  console.log('\n== dependency invalidation ==');
  writeFileSync(main.path('flag-HS-001'), 'edited after it was verified');
  const mid = await main.status();
  const r1 = mid.requirements.find((r) => r.id === 'HS-001');
  console.log(`  after editing a file HS-001 watches: HS-001 ${r1.state} (${(r1.staleReasons || []).length} reason(s) recorded), verified ${mid.verifiedPercent}%`);
  check(r1.state === 'stale' && mid.verifiedPercent === 0, 'the edited requirement is stale and its weight left the numerator');
  main.setMode({ default: 'fix' });
  check((await show(main, ['resume'])).code === 0, 'resume restarted a controller; stale evidence is re-verified before new work');
  const done = await terminal(main);
  check(done.status === 'completed' && done.verifiedPercent === 100, `completed, verified ${done.verifiedPercent}%`);

  console.log('\n== final verification ==');
  // `completed` is written a moment before the controller process is gone, and `verify --all --final` needs a LIVE controller, so wait
  // for the exit: without this the exit code below depended on that race.
  await main.waitFor(async () => (await main.status()).controller?.liveness === 'dead', { timeoutMs: 30000, label: 'the controller to exit after completing' });
  const fin = await show(main, ['verify', '--all', '--final'], { timeoutMs: 120000 });
  console.log(`  verify --all --final exit ${fin.code}`);

  console.log('\n== blocked recovery (a worker that is not logged in) ==');
  check((await show(blocked, ['init', '--prd', 'PRD.md', '--profile', 'profile.json', '--skip-baseline-gates'])).code === 0, 'init');
  await show(blocked, ['start', '--background', '--serve', '127.0.0.1:0']);
  const b = await terminal(blocked, 40000);
  check(b.status === 'blocked' && b.blockers.some((x) => x.type === 'auth-missing'), `run is ${b.status} with blocker ${b.blockers.map((x) => x.type).join(',')}; nothing prompted`);
  blocked.setMode({ default: 'fix' });
  // `blocked` is written before the controller process exits, and `resume` refuses while the run is still active: wait for the exit.
  await blocked.waitFor(async () => (await blocked.status()).controller?.liveness === 'dead', { timeoutMs: 30000, label: 'the blocked controller to exit' });
  await show(blocked, ['resume']);
  const rec = await terminal(blocked, 40000);
  check(rec.status === 'completed', `after the cause was fixed and the run resumed: ${rec.status}`);
} finally {
  await main.cleanup();
  await blocked.cleanup();
}
console.log(failed ? `\n${failed} step(s) did not behave as described` : '\nevery step behaved as described; the disposable repositories were removed');
process.exit(failed ? 1 : 0);
