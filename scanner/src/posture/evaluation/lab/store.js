// Persistence for the Eval Lab: `.agentic-security/eval-lab/runs/<runId>.json` and `.agentic-security/eval-lab/scoreboard.json`.
// Same machinery as the proof and detection stores (safe state writes, the encryption policy, retention as evidence, a secret
// scrub before anything touches disk). A run or scoreboard whose content no longer matches its own digest is returned flagged
// and never used for routing: a hand-edited scoreboard must not be able to steer which model gets the work.
import fs from 'node:fs';
import path from 'node:path';
import { statePath, ensureStateDir, safeWriteState } from '../../state-dir.js';
import { maybeEncryptForWrite, maybeDecryptForRead } from '../../encryption-provider.js';
import { digestOf } from '../../assurance/identity.js';
import { scrubDeep } from '../../proof-fabric/store.js';

const DIR = 'eval-lab';
const MAX_BYTES = 64 * 1024 * 1024;
const safeId = (id) => /^[A-Za-z0-9._-]{1,80}$/.test(id);

function write(root, parts, doc) {
  const safe = scrubDeep(doc);
  safe.digest = digestOf({ ...safe, digest: undefined });
  const text = JSON.stringify(safe);
  if (Buffer.byteLength(text) > MAX_BYTES) return { ok: false, reason: 'record exceeds the size limit' };
  if (!ensureStateDir(root)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = maybeEncryptForWrite(root, DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = statePath(root, DIR, ...parts);
  if (!safeWriteState(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.digest, encrypted: enc.encrypted };
}
function read(file) {
  try {
    const doc = JSON.parse(maybeDecryptForRead(fs.readFileSync(file, 'utf8')));
    return { doc, tampered: doc.digest !== digestOf({ ...doc, digest: undefined }) };
  } catch { return { doc: null, tampered: true }; }
}

export const saveRun = (root, run) => (safeId(run.runId) ? write(root, ['runs', `${run.runId}.json`], run) : { ok: false, reason: 'unsafe run id' });
export function loadRun(root, runId) {
  if (!safeId(String(runId))) return { doc: null, tampered: false, missing: true };
  const file = statePath(root, DIR, 'runs', `${runId}.json`);
  if (!fs.existsSync(file)) return { doc: null, tampered: false, missing: true };
  return read(file);
}
export function listRuns(root) {
  const dir = statePath(root, DIR, 'runs');
  let names = [];
  try { names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  return names.map((n) => { const { doc, tampered } = read(path.join(dir, n)); return { runId: n.replace(/\.json$/, ''), tampered, startedAt: doc?.startedAt ?? null, dataset: doc?.dataset?.id ?? null, arms: doc?.arms?.map((a) => a.id) ?? [] }; }).sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
}
export const saveScoreboard = (root, sb) => write(root, ['scoreboard.json'], sb);
export function loadScoreboard(root) {
  const file = statePath(root, DIR, 'scoreboard.json');
  if (!fs.existsSync(file)) return { doc: null, tampered: false, missing: true };
  return read(file);
}
