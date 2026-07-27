// Scan checkpointing / resume (roadmap R8).
//
// Long scans currently restart from zero if interrupted, which is what caps the
// repository size this engine can usefully handle. This module lets the per-file
// loop in `engine.js#runFullScan` durably record what it has already analysed so
// a second invocation replays that work instead of redoing it.
//
// THE PROPERTY THAT MATTERS: a resumed scan must produce the same finding set as
// an uninterrupted one. A checkpoint that silently drops findings converts a slow
// scan into a quietly incomplete one, which is strictly worse than no checkpoint
// at all. Three design decisions follow from that and should not be relaxed:
//
//   1. We persist the *complete* per-file contribution, not just findings —
//      routes, taint sources/sinks/sanitizers, logic vulns, secrets, ciphers,
//      the per-file result the cross-file taint pass reads, and the suppression
//      log delta. Anything the per-file loop appends to must round-trip, or the
//      post-loop cross-file passes would see a different world on resume.
//   2. Only the per-file loop is checkpointed. Every cross-file pass and the
//      whole annotation pipeline re-runs from scratch on resume, so nothing that
//      depends on the global picture can be stale by construction.
//   3. Invalidation is conservative to the point of being blunt. The run key
//      covers the engine version, the ruleset version, the bundle SHA, a content
//      hash of every file in the scan (which subsumes mtime), and the scanner's
//      own environment switches. If any of it moved, the checkpoint is discarded
//      and the scan starts clean. Redoing work is merely slow; resuming stale
//      work is a correctness bug.
//
// CRASH SAFETY: append-and-fsync. The file is a JSONL log — one header line
// pinning the run key, then one self-describing record per completed file,
// each carrying a SHA-256 of its own payload. Every record is written with a
// single `writeSync` and immediately `fsyncSync`'d before the next file is
// analysed, so a process killed at any instant leaves either a complete record
// or a torn tail. On recovery we read forward while records verify and truncate
// the file at the last byte offset that did, so a torn tail is discarded rather
// than resumed into. Nothing is ever rewritten in place, so there is no window
// in which the file is neither the old state nor the new one.
//
// Everything here follows the posture convention of never throwing: a failure to
// open, read or append degrades to "no checkpoint", which just means a full scan.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const STATE_DIR = '.agentic-security';
const FILE_NAME = 'scan-checkpoint.jsonl';
const FORMAT = 'agentic-security-scan-checkpoint/1';

// Env switches that change what the engine emits are part of the run identity.
// These three are deliberately excluded: they change how the run is driven, not
// what it would find.
const RUN_KEY_ENV_EXCLUDE = new Set([
  'AGENTIC_SECURITY_RESUME',
  'AGENTIC_SECURITY_CHECKPOINT_ABORT_AFTER',
  'AGENTIC_SECURITY_HMAC_KEY',
]);

export function checkpointPath(scanRoot) {
  return path.join(scanRoot || '.', STATE_DIR, FILE_NAME);
}

function _sha(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// SHA-256 of the running bundle, taken from the sidecar next to it. Returns
// 'unavailable' when running from source — same convention as the attestation
// path, and deliberately not a guess at some other bundle's hash.
export function bundleShaForRunKey() {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // src/posture/ -> src/ -> scanner/
    const sidecar = path.resolve(here, '..', '..', 'dist', 'agentic-security.mjs.sha256');
    const raw = fs.readFileSync(sidecar, 'utf8').trim();
    const m = /^([0-9a-f]{64})\b/.exec(raw);
    if (m) return m[1];
  } catch { /* not running from a built tree */ }
  return 'unavailable';
}

/**
 * Everything that would invalidate previously-completed per-file work, reduced
 * to one hex digest. Content hashes rather than mtimes: strictly stronger, and
 * immune to filesystems with coarse or non-monotonic timestamps.
 */
export function computeRunKey({
  engineVersion, rulesetVersion, bundleSha,
  fileContents = {}, depFileContents = {}, env = process.env,
} = {}) {
  const h = crypto.createHash('sha256');
  h.update(FORMAT); h.update('\n');
  h.update(String(engineVersion ?? '')); h.update('\n');
  h.update(String(rulesetVersion ?? '')); h.update('\n');
  h.update(String(bundleSha ?? 'unavailable')); h.update('\n');
  for (const [label, map] of [['f', fileContents], ['d', depFileContents]]) {
    const names = Object.keys(map || {}).sort();
    h.update(label); h.update(String(names.length)); h.update('\n');
    for (const n of names) {
      h.update(n); h.update('\0');
      h.update(_sha(String(map[n] ?? '')));
      h.update('\n');
    }
  }
  const envKeys = Object.keys(env || {})
    .filter(k => k.startsWith('AGENTIC_SECURITY_') && !RUN_KEY_ENV_EXCLUDE.has(k))
    .sort();
  h.update('e'); h.update(String(envKeys.length)); h.update('\n');
  for (const k of envKeys) { h.update(k); h.update('='); h.update(String(env[k])); h.update('\n'); }
  return h.digest('hex');
}

// A value is safe to checkpoint only if JSON can carry it back unchanged. Dates,
// regexes, Maps, Sets, functions and BigInts all survive `JSON.stringify` in a
// lossy or throwing way; recording one would mean the resumed run sees different
// data than the uninterrupted run did. We refuse the record instead, and the
// file just gets rescanned.
function _jsonSafe(v, depth = 0, seen = new Set()) {
  if (depth > 24) return false;
  if (v === null || v === undefined) return true;
  const t = typeof v;
  if (t === 'string' || t === 'boolean') return true;
  if (t === 'number') return Number.isFinite(v);
  if (t === 'function' || t === 'symbol' || t === 'bigint') return false;
  if (t !== 'object') return false;
  if (seen.has(v)) return false;
  seen.add(v);
  try {
    if (Array.isArray(v)) {
      for (const x of v) if (!_jsonSafe(x, depth + 1, seen)) return false;
      return true;
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return false;
    for (const k of Object.keys(v)) if (!_jsonSafe(v[k], depth + 1, seen)) return false;
    return true;
  } finally {
    seen.delete(v);
  }
}

function _emptyHandle(reason) {
  return {
    enabled: false, file: null, fd: null, runKey: null,
    recovered: new Map(), order: [], written: new Set(),
    discarded: false, reason,
  };
}

function _headerLine(runKey) {
  return JSON.stringify({ v: FORMAT, runKey }) + '\n';
}

// Read forward from a byte offset, keeping records while they verify. Returns
// the offset of the first byte that did NOT verify, so the caller can truncate.
function _recover(handle, file, runKey) {
  let buf;
  try { buf = fs.readFileSync(file); }
  catch { return -1; } // no file yet
  const text = buf.toString('utf8');
  const nl = text.indexOf('\n');
  if (nl < 0) return 0;
  let header = null;
  try { header = JSON.parse(text.slice(0, nl)); } catch { return 0; }
  if (!header || header.v !== FORMAT || header.runKey !== runKey) return 0;

  let offset = Buffer.byteLength(text.slice(0, nl + 1), 'utf8');
  let cursor = nl + 1;
  for (;;) {
    const end = text.indexOf('\n', cursor);
    if (end < 0) break;                       // torn tail: no terminating newline
    const line = text.slice(cursor, end);
    cursor = end + 1;
    if (!line) { offset = Buffer.byteLength(text.slice(0, cursor), 'utf8'); continue; }
    let rec;
    try { rec = JSON.parse(line); } catch { break; }
    if (!rec || typeof rec.f !== 'string' || typeof rec.d !== 'string') break;
    if (rec.c !== _sha(rec.d)) break;         // tampered or torn-then-patched
    let payload;
    try { payload = JSON.parse(rec.d); } catch { break; }
    if (!handle.recovered.has(rec.f)) handle.order.push(rec.f);
    handle.recovered.set(rec.f, payload);
    offset = Buffer.byteLength(text.slice(0, cursor), 'utf8');
  }
  return offset;
}

/**
 * Open (or start) the checkpoint for `scanRoot` under `runKey`. Never throws.
 * A handle whose `enabled` is false silently no-ops through the rest of the API.
 */
export function openCheckpoint(scanRoot, { runKey } = {}) {
  if (!scanRoot || !runKey) return _emptyHandle('no-run-key');
  const handle = _emptyHandle(null);
  try {
    const dir = path.join(scanRoot, STATE_DIR);
    fs.mkdirSync(dir, { recursive: true });
    const file = checkpointPath(scanRoot);
    handle.file = file;
    handle.runKey = runKey;

    const keepBytes = _recover(handle, file, runKey);
    if (keepBytes <= 0) {
      // Absent, foreign, or unreadable — start clean. Conservative by design.
      handle.recovered.clear();
      handle.order.length = 0;
      handle.discarded = keepBytes === 0;
      fs.writeFileSync(file, _headerLine(runKey));
    } else {
      // Drop any torn tail so appends land after the last verified record.
      try {
        const size = fs.statSync(file).size;
        if (size !== keepBytes) fs.truncateSync(file, keepBytes);
      } catch { /* best-effort */ }
    }

    handle.fd = fs.openSync(file, 'a');
    handle.enabled = true;
  } catch (e) {
    try { if (handle.fd !== null) fs.closeSync(handle.fd); } catch { /* ignore */ }
    return _emptyHandle(String((e && e.message) || e));
  }
  return handle;
}

/**
 * Durably record that `relPath` is fully analysed, along with everything that
 * analysis produced. `findings` is the per-file payload object (see the engine
 * call site); it must be plain JSON data. Returns true only if the record is on
 * disk and fsync'd.
 */
export function recordFileDone(handle, relPath, findings) {
  if (!handle || !handle.enabled || handle.fd === null || typeof relPath !== 'string') return false;
  try {
    if (!_jsonSafe(findings)) return false;
    const d = JSON.stringify(findings === undefined ? null : findings);
    if (typeof d !== 'string') return false;
    const line = JSON.stringify({ f: relPath, c: _sha(d), d }) + '\n';
    fs.writeSync(handle.fd, line);
    fs.fsyncSync(handle.fd);
    handle.written.add(relPath);
    return true;
  } catch {
    return false;
  }
}

/** Files already analysed — recovered from a prior run plus written by this one. */
export function completedFiles(handle) {
  const out = new Set();
  if (!handle) return out;
  for (const f of handle.recovered ? handle.recovered.keys() : []) out.add(f);
  for (const f of handle.written || []) out.add(f);
  return out;
}

/** Recovered per-file payloads, in the order they were originally recorded. */
export function resumeFindings(handle) {
  if (!handle || !handle.recovered) return [];
  return (handle.order || []).map(file => ({ file, findings: handle.recovered.get(file) }));
}

/**
 * Close the handle. `complete: true` means the scan finished — the checkpoint is
 * removed so the next run cannot resume state that has already been consumed.
 */
export function closeCheckpoint(handle, { complete = false } = {}) {
  if (!handle || !handle.enabled) return false;
  let ok = true;
  try { if (handle.fd !== null) fs.closeSync(handle.fd); } catch { ok = false; }
  handle.fd = null;
  handle.enabled = false;
  if (complete && handle.file) {
    try { fs.rmSync(handle.file, { force: true }); } catch { ok = false; }
  }
  return ok;
}
