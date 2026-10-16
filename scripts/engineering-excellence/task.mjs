#!/usr/bin/env node
// Task lifecycle commands. Closing a task is checked against the commands the runner executed for it.
//   task.mjs start <id>
//   task.mjs touch <id> [--note text]
//   task.mjs done <id> --accept a,b --changed p1,p2 --bench "text" [--bench "text"] [--limit "text"]...
//   task.mjs satisfy <id> --refs file#section,file2 --accept a --bench "text"
//   task.mjs block <id> --reason text [--next text] [--kind external|failed_repairs|timeout|dependency|policy]
//   task.mjs fail <id> --reason text
//   task.mjs reverify <id>      re-run the recorded passing test commands; evidence that no longer passes reopens the task
import { resolve } from 'node:path';
import { REPO_ROOT } from './lib/model.mjs';
import { TransitionError, blockTask, completeTask, failTask, heartbeat, loadManifest, mutate, readStatus, satisfyTask, startTask } from './lib/store.mjs';
import { runTaskCommand } from './runner.mjs';

function flags(argv) {
  const f = { _: [], list: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { f._.push(a); continue; }
    const k = a.slice(2); const v = argv[++i];
    if (['bench', 'limit'].includes(k)) (f.list[k] ||= []).push(v); else f[k] = v;
  }
  return f;
}
const csv = (s) => (s ? String(s).split(',').map((x) => x.trim()).filter(Boolean) : []);

export async function main(argv, defaultRoot = REPO_ROOT) {
  const [cmd, id, ...rest] = argv;
  const f = flags(rest);
  const root = f.root ? resolve(f.root) : defaultRoot;
  switch (cmd) {
    case 'start': startTask(root, id); console.log(`${id}: in_progress`); return 0;
    case 'touch': heartbeat(root, id, { note: f.note }); console.log(`${id}: heartbeat recorded`); return 0;
    case 'done':
      completeTask(root, id, { acceptanceEvidence: csv(f.accept), changedPaths: csv(f.changed), benchmarkComparisons: f.list.bench || [], knownLimitations: f.list.limit || [] });
      console.log(`${id}: done (evidence validated against the recorded test runs)`); return 0;
    case 'satisfy':
      satisfyTask(root, id, { acceptanceEvidence: csv(f.accept), changedPaths: csv(f.changed), codeRefs: csv(f.refs), benchmarkComparisons: f.list.bench || [], knownLimitations: f.list.limit || [] });
      console.log(`${id}: already_satisfied`); return 0;
    case 'block': blockTask(root, id, { reason: f.reason, nextAction: f.next || '', kind: f.kind || 'external' }); console.log(`${id}: blocked`); return 0;
    case 'fail': failTask(root, id, { reason: f.reason }); console.log(`${id}: failed`); return 0;
    case 'reverify': {
      const doc = readStatus(root);
      const tcs = doc.tasks[id]?.evidence?.testCommands || [];
      if (!tcs.length) { console.error(`${id} has no recorded test evidence to re-run`); return 1; }
      let bad = 0;
      for (const tc of tcs) {
        const argvx = tc.command.split(' ');
        const last = await runTaskCommand({ root, task: id, kind: 'test', timeoutMs: 600000, idleMs: 0, retries: 0, cwd: resolve(tc.cwd || root), blockOnTimeout: false, reverify: true, argv: argvx });
        if (last.res.outcome !== 'exited' || last.res.exitCode !== 0) bad++;
      }
      if (bad) { mutate(root, (d, m) => { void m; const st = d.tasks[id]; st.state = 'in_progress'; st.completedAt = null; st.evidence = null; st.attempts++; st.startedAt = new Date().toISOString(); st.heartbeatAt = st.startedAt; return { type: 'evidence_invalidated', tasks: [{ id, reason: 'reverify failed' }] }; }); console.error(`${id}: evidence no longer passes; task reopened`); return 1; }
      console.log(`${id}: all ${tcs.length} recorded test command(s) still pass`); return 0;
    }
    default:
      console.error('usage: task.mjs start|touch|done|satisfy|block|fail|reverify <task-id> [options]');
      loadManifest(root);
      return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((c) => process.exit(c)).catch((e) => { console.error(e instanceof TransitionError ? `refused: ${e.message}` : `task failed: ${e.message}`); process.exit(e instanceof TransitionError ? 4 : 1); });
}
