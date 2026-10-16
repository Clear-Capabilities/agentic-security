// All-or-nothing multi-file application that survives a crash (E3-07).
//
// fix-history.js already makes ONE file's write crash-safe: backup, pending log entry, atomic rename, promote. A patch that touches
// several files was only safe against an exception: if the process died after file A was promoted and before file B was written, A stayed
// patched and B did not, with nothing that said so. This journal closes that gap. Before the first write the batch is recorded as
// `writing`; after the last file is promoted it is `committed`. On the next run, `recoverBatches` finds any batch still `writing`, settles
// the per-file history first, then reverts every file of the batch that reached its patched content, so the tree returns to what it was.
//
// A fault seam (`faultPoint`) lets a test kill the process at a named point. It does nothing unless BOTH environment variables are set,
// so it cannot fire in normal use.
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath } from '../posture/state-dir.js';
import { readLog, recover, revertEntryById } from '../posture/fix-history.js';

const dirOf = (root) => statePath(root, 'fix-batches');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function faultPoint(name) {
  if (process.env.AGENTIC_SECURITY_TEST_FAULTS !== '1') return;
  if (process.env.AGENTIC_SECURITY_FAULT_AT === name) process.kill(process.pid, 'SIGKILL');
}

async function writeJson(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(3).toString('hex')}`;
  const h = await fsp.open(tmp, 'w');
  try { await h.writeFile(JSON.stringify(value, null, 2)); await h.sync(); } finally { await h.close(); }
  await fsp.rename(tmp, file);
}

export async function beginBatch(scanRoot, { files, findingId }) {
  const id = `batch-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const batch = { id, state: 'writing', findingId: findingId ?? null, startedAt: new Date().toISOString(), files: files.map((f) => ({ file: f.file, newSha: sha(f.content), existed: f.existed })) };
  await writeJson(path.join(dirOf(scanRoot), `${id}.json`), batch);
  return batch;
}

export async function commitBatch(scanRoot, batch) {
  await writeJson(path.join(dirOf(scanRoot), `${batch.id}.json`), { ...batch, state: 'committed', committedAt: new Date().toISOString() });
}

export async function abandonBatch(scanRoot, batch, state = 'rolled-back') {
  await writeJson(path.join(dirOf(scanRoot), `${batch.id}.json`), { ...batch, state, settledAt: new Date().toISOString() });
}

const STRAY_TMP = /^\..+\.tmp-\d+-[0-9a-f]{8}$/;

/**
 * Settle every batch that was still `writing` when a previous run stopped. Safe to call at any time; a no-op when nothing is pending.
 * @returns {Promise<{batch:string, reverted:string[], untouched:string[], failed:string[]}[]>}
 */
export async function recoverBatches(scanRoot) {
  const dir = dirOf(scanRoot);
  let names = [];
  try { names = (await fsp.readdir(dir)).filter((n) => n.endsWith('.json')); } catch { return []; }
  const out = [];
  let settled = false;
  for (const n of names.sort()) {
    let batch; try { batch = JSON.parse(await fsp.readFile(path.join(dir, n), 'utf8')); } catch { continue; }
    if (batch.state !== 'writing') continue;
    if (!settled) { await recover(scanRoot); settled = true; }
    const log = readLog(scanRoot);
    const reverted = []; const untouched = []; const failed = [];
    for (const f of batch.files) {
      const hits = log.filter((e) => e.file === f.file && !e.reverted && e.newSha === f.newSha.slice(0, 16) && e.appliedAt >= batch.startedAt && (e.status === 'applied' || e.status === 'applied-stale'));
      if (!hits.length) { untouched.push(f.file); continue; }
      for (const e of hits.reverse()) {
        const r = await revertEntryById(scanRoot, e.id);
        if (r && !r.error) reverted.push(f.file); else failed.push(f.file);
      }
    }
    // an interrupted atomic write leaves a hidden temp file beside its target
    for (const f of batch.files) {
      const d = path.dirname(path.join(path.resolve(scanRoot), f.file));
      try { for (const t of await fsp.readdir(d)) if (STRAY_TMP.test(t)) await fsp.unlink(path.join(d, t)).catch(() => {}); } catch { /* directory gone */ }
    }
    await abandonBatch(scanRoot, batch, failed.length ? 'rollback-incomplete' : 'rolled-back');
    out.push({ batch: batch.id, reverted: [...new Set(reverted)], untouched, failed });
  }
  return out;
}
