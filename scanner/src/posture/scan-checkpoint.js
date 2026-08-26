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
//   3. Invalidation is split into a GLOBAL identity and a PER-FILE identity
//      (assurance-hardening PRD FR-208 — "changed inputs invalidate only
//      affected checkpoints and record the invalidation reason"). The engine
//      version, ruleset version, bundle SHA, dependency-manifest contents, and
//      the scanner's own environment switches form the GLOBAL key: any of them
//      changing affects how EVERY file would be analysed (decision #2 above —
//      cross-file/dependency-derived results aren't checkpointed per-file at
//      all), so a global-key mismatch still discards the whole checkpoint,
//      exactly as before. A single scanned file's own content is NOT part of
//      the global key: only THAT file's record is invalidated when its content
//      changes, because a single file's own per-file analysis result depends
//      only on that file's content plus the (unchanged) global identity — the
//      cross-file passes that COULD make it depend on other files always
//      re-run from scratch per decision #2. This was a real, deliberate
//      widening from the original "any change discards everything" design,
//      not a relaxation of the correctness property: it only reuses a
//      per-file result when nothing that result could possibly depend on has
//      moved. Redoing work is merely slow; resuming stale work is a
//      correctness bug, and that bar has not moved.
//
// CRASH SAFETY: append-and-fsync. The file is a JSONL log — one header line
// pinning the global key (plus a plaintext meta summary used only to explain a
// mismatch, never to decide one), then one self-describing record per
// completed file, each carrying a SHA-256 of its own payload AND a SHA-256 of
// the source content it was computed from. Every record is written with a
// single `writeSync` and immediately `fsyncSync`'d before the next file is
// analysed, so a process killed at any instant leaves either a complete record
// or a torn tail. On recovery we read forward while records verify and truncate
// the file at the last byte offset that did, so a torn tail is discarded rather
// than resumed into. Nothing is ever rewritten in place, so there is no window
// in which the file is neither the old state nor the new one. A record whose
// OWN content hash no longer matches the current file is a separate, later
// check from tamper/tear detection — it is structurally intact, so it is not
// truncated away, just excluded from what gets replayed (see `_recover`).
//
// Everything here follows the posture convention of never throwing: a failure to
// open, read or append degrades to "no checkpoint", which just means a full scan.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { stateWritesEnabled } from './state-dir.js';

// DELIBERATELY NOT routed through statePath(). `resolveProjectRoot()` falls
// back to walking upward from process.cwd() when the given root does not exist
// on disk, so `checkpointPath('/some/root')` resolved into the SCANNER'S OWN
// SOURCE TREE — caught by the test that asserts a checkpoint is never written
// there. A checkpoint must land in the root it was handed or nowhere; silently
// relocating it into another directory is the exact failure this line of work
// exists to prevent. The read-only switch above is still honoured.
const STATE_DIR = '.agentic-security';
const FILE_NAME = 'scan-checkpoint.jsonl';
// Bumped from /1: the header now stores a GLOBAL-only key (FR-208) instead of
// one that folds in every scanned file's content, plus a plaintext meta
// summary. A /1 checkpoint on disk must never be half-interpreted under /2
// semantics, so the format bump alone is enough to force a clean discard of
// anything written before this change — the safest possible migration.
const FORMAT = 'agentic-security-scan-checkpoint/2';

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
 *
 * Retained as its own function (still folding in `fileContents`) because it is
 * a useful, independently-tested "did ANYTHING about this scan change"
 * fingerprint, and because `computeGlobalKey` below is defined in terms of it
 * (fileContents forced empty) — changing this function's hash would silently
 * change that one too. Production checkpointing itself uses `computeGlobalKey`,
 * not this function directly; see FR-208's note in the module header for why
 * file content is no longer part of what invalidates the WHOLE checkpoint.
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

/**
 * FR-208: the GLOBAL portion of run identity — everything that would affect
 * how EVERY scanned file is analysed. Deliberately excludes `fileContents`
 * (a single file's own content is checked per-record in `_recover` instead)
 * but keeps `depFileContents`: dependency-manifest-derived findings are not
 * part of any per-file checkpoint record (they're recomputed fresh every run,
 * same as cross-file taint — decision #2 in the module header), so there is
 * no per-file granularity to offer there; any manifest change invalidates
 * everything, same as before this change.
 */
export function computeGlobalKey({ engineVersion, rulesetVersion, bundleSha, depFileContents = {}, env = process.env } = {}) {
  return computeRunKey({ engineVersion, rulesetVersion, bundleSha, fileContents: {}, depFileContents, env });
}

/**
 * A plaintext (non-hashed) summary of the same inputs `computeGlobalKey` folds
 * in, stored alongside the key in the checkpoint header. Used ONLY to explain
 * a global-key mismatch after the fact (`_explainGlobalMismatch`) — never to
 * decide whether one occurred; the key comparison remains the sole source of
 * truth for that, so a caller cannot bypass invalidation by supplying
 * mismatched meta.
 */
export function globalKeyMeta({ engineVersion, rulesetVersion, bundleSha, depFileContents = {}, env = process.env } = {}) {
  return {
    engineVersion: String(engineVersion ?? ''),
    rulesetVersion: String(rulesetVersion ?? ''),
    bundleSha: String(bundleSha ?? 'unavailable'),
    depFingerprint: computeRunKey({ engineVersion: '', rulesetVersion: '', bundleSha: '', fileContents: {}, depFileContents, env: {} }),
    envFingerprint: computeRunKey({ engineVersion: '', rulesetVersion: '', bundleSha: '', fileContents: {}, depFileContents: {}, env }),
  };
}

function _explainGlobalMismatch(oldMeta, newMeta) {
  oldMeta = oldMeta || {};
  newMeta = newMeta || {};
  const parts = [];
  if (oldMeta.engineVersion !== newMeta.engineVersion) parts.push(`engine version changed (${oldMeta.engineVersion || 'unknown'} -> ${newMeta.engineVersion || 'unknown'})`);
  if (oldMeta.rulesetVersion !== newMeta.rulesetVersion) parts.push(`ruleset version changed (${oldMeta.rulesetVersion || 'unknown'} -> ${newMeta.rulesetVersion || 'unknown'})`);
  if (oldMeta.bundleSha !== newMeta.bundleSha) parts.push('the running bundle changed');
  if (oldMeta.depFingerprint !== newMeta.depFingerprint) parts.push('a dependency manifest file changed');
  if (oldMeta.envFingerprint !== newMeta.envFingerprint) parts.push('an AGENTIC_SECURITY_* environment switch changed');
  return parts.length ? `global scan identity changed: ${parts.join(', ')}` : 'global scan identity changed';
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
    enabled: false, file: null, fd: null, globalKey: null,
    recovered: new Map(), order: [], written: new Set(),
    discarded: false, reason, invalidatedFiles: [], fileContents: {},
  };
}

function _headerLine(globalKey, meta) {
  return JSON.stringify({ v: FORMAT, gk: globalKey, meta: meta || {} }) + '\n';
}

// Read forward from a byte offset, keeping records while they verify. Returns
// {offset, discardReason}: offset is the byte position the caller should keep
// (or truncate to); discardReason is set only when offset===0 (the whole
// checkpoint is being discarded) and explains why, per FR-208.
//
// A record whose payload hash (`c`) doesn't verify is torn/tampered and ends
// recovery right there, same as before FR-208. A record that verifies
// structurally but whose OWN content hash (`h`) no longer matches the
// CURRENT content of that file is a different, later check — it is not
// corrupt, so it does not truncate the file; it is simply excluded from
// `handle.recovered` and named in `handle.invalidatedFiles`, so only that
// file gets re-analysed this run.
function _recover(handle, file, globalKey, meta, fileContents) {
  let buf;
  try { buf = fs.readFileSync(file); }
  catch { return { offset: -1, discardReason: null }; } // no file yet
  const text = buf.toString('utf8');
  const nl = text.indexOf('\n');
  if (nl < 0) return { offset: 0, discardReason: 'empty or corrupt checkpoint file' };
  let header = null;
  try { header = JSON.parse(text.slice(0, nl)); } catch { return { offset: 0, discardReason: 'corrupt checkpoint header' }; }
  if (!header || header.v !== FORMAT) return { offset: 0, discardReason: 'checkpoint format changed' };
  if (header.gk !== globalKey) return { offset: 0, discardReason: _explainGlobalMismatch(header.meta, meta) };

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
    // Structurally intact and parseable — advance past it regardless of what
    // the per-file content check below decides; a stale-but-intact record is
    // not a torn or tampered one and must not be truncated away.
    offset = Buffer.byteLength(text.slice(0, cursor), 'utf8');
    // FR-208: per-file content check. A record written with no tracked
    // source hash (`h` absent — e.g. a caller that never supplied
    // fileContents) has nothing to compare against, so it is trusted exactly
    // as it was before this per-file check existed.
    if (rec.h != null) {
      const current = fileContents ? fileContents[rec.f] : undefined;
      if (typeof current !== 'string') {
        handle.invalidatedFiles.push({ file: rec.f, reason: 'no longer part of this scan' });
        continue;
      }
      if (rec.h !== _sha(current)) {
        handle.invalidatedFiles.push({ file: rec.f, reason: 'content changed since it was checkpointed' });
        continue;
      }
    }
    if (!handle.recovered.has(rec.f)) handle.order.push(rec.f);
    handle.recovered.set(rec.f, payload);
  }
  return { offset, discardReason: null };
}

/**
 * Open (or start) the checkpoint for `scanRoot` under `globalKey`. Never
 * throws. A handle whose `enabled` is false silently no-ops through the rest
 * of the API.
 *
 * `fileContents` (FR-208): the CURRENT content of every file this scan would
 * analyse, keyed by the same relative path `recordFileDone` is called with.
 * Passed through to per-file content comparison on recovery, and to
 * `recordFileDone` for hashing each new record's own content. Omitting it
 * (or passing `{}`) degrades every record to trust-on-structural-validity
 * only — the pre-FR-208 behaviour — which is exactly what a caller testing
 * the checkpoint PROTOCOL itself (not per-file invalidation) wants, and
 * exactly what the low-level tests in this module's test file rely on.
 *
 * `meta`: a plaintext summary of the inputs behind `globalKey` (see
 * `globalKeyMeta`), stored in the header purely to explain a mismatch later.
 */
export function openCheckpoint(scanRoot, { globalKey, meta = {}, fileContents = {} } = {}) {
  if (!scanRoot || !globalKey) return _emptyHandle('no-global-key');
  // A read-only scan cannot checkpoint, and must not try. Resume is purely an
  // optimisation — without it the scan recomputes, which is slower and
  // identical — so `--no-state` wins over `AGENTIC_SECURITY_RESUME=1` rather
  // than the two conflicting. The disabled handle no-ops through the rest of
  // the API, so no caller needs a new branch. (PRD M1)
  if (!stateWritesEnabled()) return _emptyHandle('state-writes-disabled');
  const handle = _emptyHandle(null);
  handle.fileContents = fileContents || {};
  try {
    const dir = path.join(scanRoot, STATE_DIR);
    fs.mkdirSync(dir, { recursive: true });
    const file = checkpointPath(scanRoot);
    handle.file = file;
    handle.globalKey = globalKey;

    const { offset: keepBytes, discardReason } = _recover(handle, file, globalKey, meta, handle.fileContents);
    if (keepBytes <= 0) {
      // Absent, foreign, or globally invalidated — start clean. A byte offset
      // of -1 (no file yet) is a fresh checkpoint, not a discard, so it gets
      // no reason; 0 (format/global-key mismatch, or corrupt header) does.
      handle.recovered.clear();
      handle.order.length = 0;
      handle.invalidatedFiles = [];
      handle.discarded = keepBytes === 0;
      handle.reason = keepBytes === 0 ? discardReason : null;
      fs.writeFileSync(file, _headerLine(globalKey, meta));
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
 *
 * Also records a SHA-256 of `relPath`'s current content (from the
 * `fileContents` the handle was opened with), so a later run's `_recover` can
 * tell whether this specific file has changed since — the FR-208 per-file
 * half of invalidation. A handle opened without `fileContents` (or one that
 * doesn't include this path) records no hash, which `_recover` treats as
 * "nothing to compare," matching this module's pre-FR-208 behaviour exactly.
 */
export function recordFileDone(handle, relPath, findings) {
  if (!handle || !handle.enabled || handle.fd === null || typeof relPath !== 'string') return false;
  try {
    if (!_jsonSafe(findings)) return false;
    const d = JSON.stringify(findings === undefined ? null : findings);
    if (typeof d !== 'string') return false;
    const src = handle.fileContents ? handle.fileContents[relPath] : undefined;
    const h = typeof src === 'string' ? _sha(src) : null;
    const line = JSON.stringify({ f: relPath, h, c: _sha(d), d }) + '\n';
    fs.writeSync(handle.fd, line);
    fs.fsyncSync(handle.fd);
    handle.written.add(relPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * FR-208: individually-invalidated files from a checkpoint whose GLOBAL
 * identity still matched — each entry names the file and why (content
 * changed, or the file is no longer part of this scan). Deliberately does
 * NOT enumerate every file when the whole checkpoint was discarded instead
 * (`handle.discarded`/`handle.reason` already say why, once, for all of
 * them — reading the rest of a large journal just to repeat the same reason
 * per file would cost real I/O for no new information). Always `[]` on a
 * disabled handle, a brand-new checkpoint, or a global discard.
 */
export function invalidatedFiles(handle) {
  return (handle && Array.isArray(handle.invalidatedFiles)) ? handle.invalidatedFiles : [];
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
