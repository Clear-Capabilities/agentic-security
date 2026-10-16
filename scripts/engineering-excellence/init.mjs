#!/usr/bin/env node
// Idempotent initialisation: tasks.json from the PRD (when the PRD is present), then status.json from tasks.json.
// Re-running preserves every recorded state and evidence; it only adds tasks that are new to the manifest.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { atomicWriteJson } from '../loop-engineering/lib/util.mjs';
import { buildManifest } from './lib/prd-tasks.mjs';
import { REPO_ROOT } from './lib/model.mjs';
import { initStatus, loadManifest, paths } from './lib/store.mjs';

export function init({ root = REPO_ROOT, prd = null } = {}) {
  const P = paths(root);
  const candidates = [prd, resolve(root, 'AGENTIC_SECURITY_ENGINEERING_EXCELLENCE_MASTER.prd'), resolve(root, 'docs/prds/AGENTIC_SECURITY_ENGINEERING_EXCELLENCE_MASTER.prd')].filter(Boolean);
  const prdPath = candidates.find((c) => existsSync(c));
  let manifestWritten = false;
  if (prdPath) {
    const text = readFileSync(prdPath, 'utf8');
    const manifest = buildManifest(text, { prdSha256: createHash('sha256').update(text).digest('hex'), prdName: basename(prdPath) });
    let same = false;
    if (existsSync(P.tasks)) { try { same = JSON.stringify(loadManifest(root)) === JSON.stringify(manifest); } catch { same = false; } }
    if (!same) { atomicWriteJson(P.tasks, manifest); manifestWritten = true; }
  } else if (!existsSync(P.tasks)) {
    throw new Error('neither tasks.json nor the PRD was found; place the PRD at the repository root or docs/prds/ and re-run');
  }
  const r = initStatus(root, loadManifest(root));
  return { prd: prdPath || null, manifestWritten, statusCreated: r.created, tasksAdded: r.added, tasks: Object.keys(r.doc.tasks).length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const r = init({ prd: process.argv[2] || null });
    console.log(`engineering-excellence: ${r.tasks} tasks; manifest ${r.manifestWritten ? 'written' : 'unchanged'}; status ${r.statusCreated ? 'created' : `kept (${r.tasksAdded} new task(s) added)`}${r.prd ? '' : '; PRD not found, used the existing manifest'}`);
  } catch (e) { console.error(`init failed: ${e.message}`); process.exit(1); }
}
