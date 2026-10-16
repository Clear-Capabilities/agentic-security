#!/usr/bin/env node
// Terminal observer for the Engineering Excellence program. Read-mostly: it never keeps a worker alive and exits on SIGINT.
//   --once (default)   print the dashboard once
//   --watch [--interval s]   redraw until interrupted (default 2s)
//   --json             machine-readable summary plus per-task state
//   --epic E2          add the per-task table of one epic
//   --failures         blocked and failed tasks with their last bad commands
//   --resume           recover interrupted tasks, then print what to do next
//   --markdown         regenerate docs/engineering-excellence/STATUS.md
//   --revalidate       re-check recorded evidence on disk; tasks whose evidence is gone return to in_progress
//   --restore-backup   replace a corrupt status.json with status.json.bak
import { mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { atomicWriteFile } from '../loop-engineering/lib/util.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { renderFailures, renderMarkdown, renderText } from './lib/render.mjs';
import { StatusCorruptError, loadManifest, nextTasks, readStatus, recoverInterrupted, restoreBackup, revalidateEvidence, summarize } from './lib/store.mjs';

function parse(argv) {
  const o = { mode: 'once', interval: 2, epic: null, root: REPO_ROOT };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--once') o.mode = 'once';
    else if (a === '--watch') o.mode = 'watch';
    else if (a === '--json') o.mode = 'json';
    else if (a === '--failures') o.mode = 'failures';
    else if (a === '--resume') o.mode = 'resume';
    else if (a === '--markdown') o.mode = 'markdown';
    else if (a === '--revalidate') o.mode = 'revalidate';
    else if (a === '--restore-backup') o.mode = 'restore';
    else if (a === '--epic') o.epic = argv[++i];
    else if (a === '--interval') o.interval = Math.max(1, Number(argv[++i]) || 2);
    else if (a === '--root') o.root = resolve(argv[++i]);
    else { console.error(`unknown argument ${a}`); process.exit(2); }
  }
  return o;
}

export function snapshot(root) {
  const manifest = loadManifest(root);
  const doc = readStatus(root);
  if (!doc) throw new Error('status.json does not exist; run: node scripts/engineering-excellence/init.mjs');
  return { manifest, doc };
}

async function main() {
  const o = parse(process.argv.slice(2));
  try {
    if (o.mode === 'restore') { const d = restoreBackup(o.root); console.log(`restored status.json from status.json.bak (revision ${d.revision})`); return 0; }
    if (o.mode === 'resume') {
      const recovered = recoverInterrupted(o.root, { force: true });
      const { manifest, doc } = snapshot(o.root);
      for (const r of recovered) console.log(`recovered interrupted task ${r.id}: now ${r.to}`);
      const moved = revalidateEvidence(o.root);
      for (const m of moved) console.log(`evidence invalidated for ${m.id}: ${m.reason}`);
      const fresh = snapshot(o.root);
      console.log(renderText(fresh.manifest, fresh.doc, { epic: o.epic }));
      const next = nextTasks(fresh.manifest, fresh.doc, 1)[0];
      console.log(next ? `\nRESUME WITH: node scripts/engineering-excellence/task.mjs start ${next.id}   (${next.title})` : '\nNo task is ready. See BLOCKED, FAILED and dependencies above.');
      void manifest; void doc;
      return 0;
    }
    if (o.mode === 'revalidate') {
      const moved = revalidateEvidence(o.root);
      console.log(moved.length ? moved.map((m) => `${m.id}: evidence invalidated (${m.reason})`).join('\n') : 'All recorded evidence still holds on disk.');
      return moved.length ? 1 : 0;
    }
    const draw = () => {
      const { manifest, doc } = snapshot(o.root);
      if (o.mode === 'json') {
        console.log(JSON.stringify({ checkout: doc.checkout, updatedAt: doc.updatedAt, revision: doc.revision, summary: summarize(manifest, doc), tasks: Object.fromEntries(manifest.tasks.map((t) => [t.id, { title: t.title, epic: t.epic, priority: t.priority, requires: t.requires, state: doc.tasks[t.id].state, attempts: doc.tasks[t.id].attempts, blocker: doc.tasks[t.id].blocker, failure: doc.tasks[t.id].failure, evidence: doc.tasks[t.id].evidence }])) }, null, 2));
      } else if (o.mode === 'failures') console.log(renderFailures(manifest, doc));
      else if (o.mode === 'markdown') {
        const out = join(o.root, 'docs', 'engineering-excellence', 'STATUS.md');
        mkdirSync(dirname(out), { recursive: true });
        atomicWriteFile(out, renderMarkdown(manifest, doc) + '\n', 0o644);
        console.log(`wrote ${out}`);
      } else console.log(renderText(manifest, doc, { epic: o.epic }));
    };
    if (o.mode !== 'watch') { draw(); return 0; }
    await new Promise((res) => {
      const tick = () => {
        process.stdout.write('\u001b[2J\u001b[H');
        try { draw(); } catch (e) { console.log(`status unavailable: ${e.message}`); }
        console.log(`\n(refreshing every ${o.interval}s; Ctrl-C to exit; this watcher is not a worker and does not keep one alive)`);
      };
      tick();
      const t = setInterval(tick, o.interval * 1000);
      const stop = () => { clearInterval(t); res(); };
      process.on('SIGINT', stop); process.on('SIGTERM', stop);
    });
    return 0;
  } catch (e) {
    console.error(e instanceof StatusCorruptError ? `STATUS CORRUPT: ${e.message}` : `status failed: ${e.message}`);
    return e instanceof StatusCorruptError ? 3 : 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main().then((c) => process.exit(c));
