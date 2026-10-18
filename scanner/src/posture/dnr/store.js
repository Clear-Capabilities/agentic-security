// Persistence for the detection-and-response loop: `.agentic-security/dnr/<findingKey>/<kind>-<digest>.json`.
// Same machinery and the same guarantees as the proof store, reused rather than copied where it is exported:
// safe state-directory writes (no symlinks, no unsafe dirs), the encryption policy, retention as evidence, legal holds, and
// a recursive secret scrub before anything touches disk. A record that no longer matches its own digest is returned FLAGGED,
// never trusted and never silently dropped.
import fs from 'node:fs';
import path from 'node:path';
import { statePath, ensureStateDir, safeWriteState } from '../state-dir.js';
import { maybeEncryptForWrite, maybeDecryptForRead } from '../encryption-provider.js';
import { canonicalize, sha256 } from '../proof-fabric/reproducer.js';
import { scrubDeep, findingKey } from '../proof-fabric/store.js';

const DIR = 'dnr';
const MAX_RECORD_BYTES = 1024 * 1024;
const RECORD_KINDS = Object.freeze(['detection', 'hunt', 'window', 'fix']);

const digestOf = (record) => { const { recordDigest: _omit, ...rest } = record; return sha256(canonicalize(rest)); };

export function saveRecord(root, findingId, kind, record) {
  if (!RECORD_KINDS.includes(kind)) return { ok: false, reason: `unknown record kind: ${kind}` };
  const safe = scrubDeep(record);
  safe.schema = `agentic-security/dnr-${kind}-record`;
  safe.kind = kind;
  safe.findingId = String(findingId);
  safe.savedAt = record.savedAt ?? new Date().toISOString();
  safe.recordDigest = digestOf(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'record exceeds the size limit' };
  if (!ensureStateDir(root)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = maybeEncryptForWrite(root, DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = statePath(root, DIR, findingKey(findingId), `${kind}-${safe.recordDigest.slice(0, 16)}.json`);
  if (!safeWriteState(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

/** Newest-first records of one kind for a finding. Tampered records are flagged. */
export function listRecords(root, findingId, kind) {
  const dir = statePath(root, DIR, findingKey(findingId));
  let names = [];
  try { names = fs.readdirSync(dir).filter((n) => n.startsWith(`${kind}-`) && n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const file = path.join(dir, n);
    try {
      const rec = JSON.parse(maybeDecryptForRead(fs.readFileSync(file, 'utf8')));
      out.push({ file, record: rec, tampered: rec.recordDigest !== digestOf(rec), mtime: fs.statSync(file).mtimeMs });
    } catch { out.push({ file, record: null, tampered: true, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

/** Newest intact record of a kind, or null. A tampered newest record does NOT fall through silently: the caller can see it via listRecords. */
export function latestRecord(root, findingId, kind) {
  return listRecords(root, findingId, kind).find((r) => r.record && !r.tampered) ?? null;
}
export const hasTamperedRecords = (root, findingId, kind) => listRecords(root, findingId, kind).some((r) => r.tampered);
