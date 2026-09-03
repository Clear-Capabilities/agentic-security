// observation-store.js — M5 deliverable #7 (Runtime-Corroborated Digital
// Twin, runtime-observed half only, "7b"; see runtime-observation.js's own
// header for why "7a", config-declared edges, is out of scope for this
// whole sub-project — scoping doc §4.0). FR-505, AC-29. The IMPURE layer:
// a directory of independently-readable, immutable whole files — one file
// per adapter IMPORT, never per observation.
//
// ── The storage ruling, and the three rejected candidates ───────────────
//
// Three existing state-storage shapes in this codebase were each considered
// and rejected, per the scoping doc's §4.4 (Correction 6):
//
//   - `graph-snapshot.js`'s GraphSnapshot store is commit-keyed: one file
//     per commit. That keying cannot express "many observation imports per
//     graph entity" — an operator may import several adapter exports
//     (different windows, different environments, a re-import after fixing
//     a malformed source file) against the SAME commit, and commit-keying
//     would collide them onto one file or silently overwrite.
//   - `posture/provenance/lifecycle.js` rewrites its whole document on
//     every update and is registered with a DELIBERATE no-`retentionClass`
//     policy (permanent history, never auto-expired). An observation
//     import is neither: it is not a document that grows by rewrite, and
//     FR-505 requires it follow real retention/reset rules, not stay
//     permanent forever.
//   - `posture/remediation-ledger` (M5 deliverable #6)'s locked, hash-chained JSONL solves a
//     read-fold-validate-write problem — many callers appending to ONE
//     shared ledger, where the fold and the chain both depend on total
//     order — that does not exist here: an import is a single, complete,
//     independently-valid record with no fold step. Worse, its hash chain
//     makes deletion structurally impossible (unlinking the middle of a
//     chain breaks every entry after it), and FR-505 explicitly requires
//     an observation store follow real retention/reset rules — an
//     append-only hash chain and a retention-and-reset requirement are
//     directly opposed.
//
// The choice, then: mirror `lineage-snapshots/`'s own directory-of-
// immutable-files shape, re-keyed from commit -> import. Each import is
// one whole, self-contained, independently-readable JSON file; nothing
// here ever rewrites a file in place, and nothing here ever folds two
// files into one logical state.
//
// ── No lock, and why (CORRECTED — final review B2) ─────────────────────
//
// Every import is an independent whole file. The only concurrency hazard a
// lock would address is two writers targeting the SAME file. This
// module's own header USED TO claim `observationImportId`'s `importedAt`
// discriminator alone made that impossible — that claim was FALSE:
// `importedAt` (`new Date().toISOString()`) is millisecond-resolution, so
// two concurrent `dataflow observations import --yes` invocations sharing
// adapter/source/environment/window and landing in the same millisecond
// minted the IDENTICAL import id, and the second write silently clobbered
// the first while BOTH processes reported success. Live-reproduced by the
// final review: 5 of 8 concurrent-round trials lost an entire import.
// Fixed two ways, belt and suspenders: (1) the CALLER
// (`cmdDataflowObservationsImport`, `bin/agentic-security.js`) now mints
// `observationImportId` with a fresh random discriminator part, so two
// invocations can never collide regardless of timing; (2) this module's
// own write is now ATOMIC (`_writeAtomicSync`, temp-file-then-rename)
// rather than a bare `writeFileSync`, so even a genuine same-name write
// race (a caller that skipped the id fix, or two callers racing on a
// hand-supplied id) can no longer produce a torn file — the worst case is
// now "one writer's complete content wins," never "a half-written file."
// There is still no read-fold-validate-write critical section anywhere in
// this module (contrast the remediation ledger, which locks for exactly
// that reason) — so there is still nothing for a LOCK specifically to
// protect; the fix is collision-proof ids plus an atomic write, not a lock.
//
// ── `statePath` is called with a STRING LITERAL at every site ──────────
//
// `test/artifact-registry-completeness.test.js`'s own `PATTERNS` regexes
// require a quoted literal as `statePath`'s second argument to detect a
// call site at all — a variable defeats the guard silently. This is not
// theoretical: `graph-snapshot.js:36` calls `statePath(scanRoot, HISTORY_DIR)`
// with a module constant, genuinely escapes the completeness guard today,
// and is registered in artifact-registry.js only because someone
// remembered by hand. `OBSERVATION_STORE_DIR` is exported below as a
// convenience for READERS (display strings, docs) but is deliberately
// never passed as `statePath`'s second argument anywhere in this file —
// `observationsDir` uses the literal `'runtime-observations'` directly, so
// the completeness guard has a real literal to see.
//
// ── Encryption is called explicitly, because the registry flag alone
//    enforces nothing ─────────────────────────────────────────────────
//
// `confidential: true` on an artifact-registry.js entry is a DECLARATION,
// not an enforced control (see this sub-project's own scoping-doc
// Correction 1) — nothing reads that flag automatically at write time.
// The only two confidential artifacts in this tree before this module
// (`compliance-evidence.json`/`.md`) each call `maybeEncryptForWrite`/
// `maybeDecryptForRead` from their own writer (`posture/compliance-
// policy.js:497`/`:546`) — there is no ambient enforcement mechanism to
// inherit. `persistObservationImport`/`loadObservationImports`/
// `loadObservationImport` therefore call those two functions explicitly,
// exactly like that precedent, so the `confidential: true` this module's
// artifact-registry.js entry carries is backed by real behavior, not just
// a claim.
//
// ── Key-shape validation happens BEFORE any path.join ───────────────────
//
// `loadObservationImport(scanRoot, importId)` validates `importId`'s shape
// via `importFileName` before it ever builds a path — a disclosed,
// pre-existing gap this module deliberately does NOT inherit:
// `graph-snapshot.js`'s own `loadSnapshot(scanRoot, commitKey)` joins its
// caller-supplied key straight onto the history directory with no shape
// check at all (`graph-snapshot.js:150-152`), so a crafted `commitKey`
// could in principle read outside the state directory. Not exploited
// today (every real caller passes a git commit or a `--against` flag) and
// deliberately out of scope to fix there — this module's own header
// exists to record that this is a KNOWN, DISCLOSED asymmetry between the
// two sibling stores, not an oversight in either.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath, isSafeStateDir, stateWritesEnabled } from '../posture/state-dir.js';
import { maybeEncryptForWrite, maybeDecryptForRead } from '../posture/encryption-provider.js';
import { validateRuntimeObservation, RUNTIME_OBSERVATION_ADAPTERS } from './runtime-observation.js';
// I1 (final review): every other evidence-bearing artifact in this codebase
// (lineage-graph.json, last-scan.json, the remediation ledger's hash chain)
// carries tamper-evidence — the observation store did not, so a hand-planted
// forged import (a fabricated matchMethod/matchConfidence naming a real
// flow's ids) was indistinguishable from real evidence on read and could
// launder into the signed graph as genuine runtime corroboration. Reused
// UNCHANGED — the same generic, filename-agnostic HMAC primitive
// `lineage-graph.json` itself already uses (confirmed by direct read of
// this file: no filename baked in anywhere).
import { signLastScan, verifyLastScan } from '../posture/integrity.js';

/**
 * The literal top-level directory name under `.agentic-security/`.
 * Exported for readers (display strings, docs) — NEVER pass this as
 * `statePath`'s second argument; see this file's own header for why.
 */
export const OBSERVATION_STORE_DIR = 'runtime-observations';

export const OBSERVATION_IMPORT_VERSION = '1.0.0';

// The closed top-level key set of an ObservationImport record.
const IMPORT_FIELDS = Object.freeze([
  'id', 'version', 'adapter', 'source', 'environment', 'windowStart', 'windowEnd',
  'importedAt', 'retention', 'observations',
]);

const _RETENTION_KEYS = ['expiresAt'];

function _isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _isNonEmptyString(v, maxLen) {
  if (typeof v !== 'string' || v.length === 0) return false;
  if (typeof maxLen === 'number' && v.length > maxLen) return false;
  return true;
}

const _ISO_DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function _isIsoDateTime(v) {
  return typeof v === 'string' && _ISO_DATE_TIME_RE.test(v) && Number.isFinite(Date.parse(v));
}

/**
 * The literal, verbatim `statePath` call this module's completeness-guard
 * discipline depends on. Do not refactor this into a shared helper that
 * takes the directory name as a parameter — `artifact-registry-
 * completeness.test.js`'s `PATTERNS` needs a quoted literal at THIS call
 * site to see it at all.
 */
export function observationsDir(scanRoot) {
  return statePath(scanRoot, 'runtime-observations');
}

// B2 (final review, Part 2): a faithful LOCAL PORT of the established
// temp-file-then-rename shape (`_writeConfigAtomic` in
// `bin/agentic-security.js`, `_writeAtomicAndSync` in
// `posture/fix-history.js`) — NOT an import, since both those helpers are
// module-private and this module's own `persistObservationImport` is
// synchronous (every real caller, including the CLI and this file's own
// test suite, calls it without `await`), so the async `fsp`-based originals
// cannot be reused directly. Mirrors the remediation-ledger module's own
// documented precedent (posture/remediation-ledger, M5 deliverable #6) for
// porting rather than importing an unexported helper. Temp file in the
// SAME directory (so the final `renameSync` is
// same-filesystem and therefore atomic), a random suffix (so two
// concurrent writers can never collide on the temp file itself even before
// B2 Part 1's id-collision fix), fsync before rename when available, and
// the temp file is unlinked on any failure so a crash never leaves a stray
// partial file behind. Closes the "torn file on a genuine write race" risk
// even after Part 1 makes true id collisions impossible — belt and
// suspenders — and fixes `loadObservationImports`'s own silent-swallow-of-
// a-torn-file gap as a side effect (a write can no longer be torn at all).
function _writeAtomicSync(fp, content) {
  const dir = path.dirname(fp);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `.${path.basename(fp)}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  try {
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, fp);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* never existed, or already gone — fine either way */ }
    throw e;
  }
}

/**
 * The store's own file-name key from an import id, or `null` when
 * `importId` is not a well-formed `obsimport:`-prefixed id. Validates the
 * key's SHAPE before any `path.join` — see this file's own header.
 */
export function importFileName(importId) {
  if (typeof importId !== 'string' || !/^obsimport:[0-9a-f]{12}$/.test(importId)) return null;
  return `${importId.slice('obsimport:'.length)}.json`;
}

/**
 * Closed-world structural validation of an ObservationImport record.
 * Mirrors `runtime-observation.js#validateRuntimeObservation`'s own
 * `{valid, errors}`/`[{path, message}]` shape and closed-world discipline
 * one level up: every element of `observations[]` is routed through
 * `validateRuntimeObservation` itself, with its errors re-pathed to
 * `$.observations[i].<path>`. Never throws.
 */
export function validateObservationImport(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!_isPlainObject(record)) {
    err('$', 'ObservationImport record must be an object');
    return { valid: false, errors };
  }

  // Closed-world sweep FIRST, exactly like validateRuntimeObservation's
  // own discipline — an unrecognized top-level key is always an error.
  for (const key of Object.keys(record)) {
    if (!IMPORT_FIELDS.includes(key)) {
      err(`$.${key}`, 'unknown field — ObservationImport records are closed-world: only approved fields are accepted, and an unrecognized field is rejected, never ignored');
    }
  }

  for (const field of IMPORT_FIELDS) {
    if (!(field in record)) err(`$.${field}`, `${field} is required`);
  }

  const idOk = 'id' in record && _isNonEmptyString(record.id) && record.id.startsWith('obsimport:');
  if ('id' in record && !idOk) err('$.id', 'id is required and must start with "obsimport:"');

  if ('version' in record && !_isNonEmptyString(record.version)) err('$.version', 'version is required');

  if ('adapter' in record && !RUNTIME_OBSERVATION_ADAPTERS.includes(record.adapter)) {
    err('$.adapter', `adapter must be one of ${RUNTIME_OBSERVATION_ADAPTERS.join('|')}`);
  }

  if ('source' in record && !_isNonEmptyString(record.source, 512)) {
    err('$.source', 'source is required and must be at most 512 characters');
  }

  if ('environment' in record && !_isNonEmptyString(record.environment, 64)) {
    err('$.environment', 'environment is required and must be at most 64 characters');
  }

  const windowStartOk = 'windowStart' in record && _isIsoDateTime(record.windowStart);
  if ('windowStart' in record && !windowStartOk) err('$.windowStart', 'windowStart must be a parseable ISO-8601 date-time');

  const windowEndOk = 'windowEnd' in record && _isIsoDateTime(record.windowEnd);
  if ('windowEnd' in record && !windowEndOk) err('$.windowEnd', 'windowEnd must be a parseable ISO-8601 date-time');

  if (windowStartOk && windowEndOk && Date.parse(record.windowStart) > Date.parse(record.windowEnd)) {
    err('$.windowEnd', 'windowEnd must not be before windowStart');
  }

  if ('importedAt' in record && !_isIsoDateTime(record.importedAt)) {
    err('$.importedAt', 'importedAt must be a parseable ISO-8601 date-time');
  }

  // retention: closed-key object with exactly `expiresAt`, mirroring
  // runtime-observation.js's own field of the same name and shape.
  if ('retention' in record) {
    const retention = record.retention;
    if (!_isPlainObject(retention)) {
      err('$.retention', 'retention must be an object with exactly the key expiresAt');
    } else {
      for (const key of Object.keys(retention)) {
        if (!_RETENTION_KEYS.includes(key)) {
          err(`$.retention.${key}`, 'unknown field — retention is closed-world: only expiresAt is accepted');
        }
      }
      const expiresAt = retention.expiresAt;
      const expiresAtOk = expiresAt === null || _isIsoDateTime(expiresAt);
      if (!expiresAtOk) {
        err('$.retention.expiresAt', 'retention.expiresAt must be null or a parseable ISO-8601 date-time');
      }
    }
  }

  if ('observations' in record) {
    if (!Array.isArray(record.observations)) {
      err('$.observations', 'observations must be an array');
    } else {
      record.observations.forEach((obs, i) => {
        const { errors: obsErrors } = validateRuntimeObservation(obs);
        for (const e of obsErrors) {
          errors.push({ path: `$.observations[${i}]${e.path.slice(1)}`, message: e.message });
        }
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Persist `importRecord` as one immutable whole file, keyed by its own
 * `id`, written ATOMICALLY (B2) and SIGNED (I1, a sibling `<file>.sig`
 * carrying `signLastScan` of the exact bytes written). Refuses (never
 * partially writes) when the record fails validation, when state writes
 * are disabled, when the target directory is not a safe state directory,
 * when the id cannot be turned into a file name, or when the
 * confidentiality gate (`maybeEncryptForWrite`) itself refuses. The store
 * is the last line of defense: no path exists by which an unvalidated,
 * unsigned, or torn observation reaches disk.
 *
 * @returns {{ok:true, path:string} | {ok:false, reason:string}}
 */
export function persistObservationImport(scanRoot, importRecord) {
  const { valid, errors } = validateObservationImport(importRecord);
  if (!valid) {
    return { ok: false, reason: `invalid ObservationImport record: ${JSON.stringify(errors)}` };
  }

  if (!stateWritesEnabled()) {
    return { ok: false, reason: 'state writes are disabled' };
  }

  const dir = observationsDir(scanRoot);
  if (!isSafeStateDir(dir)) {
    return { ok: false, reason: `refusing to write — ${dir} is not a safe state directory (no project marker found in its parent)` };
  }

  const fileName = importFileName(importRecord.id);
  if (!fileName) {
    return { ok: false, reason: `invalid import id "${importRecord.id}" — cannot derive a file name` };
  }

  const gated = maybeEncryptForWrite(scanRoot, 'runtime-observations', JSON.stringify(importRecord, null, 2));
  if (!gated.ok) {
    return gated;
  }

  const full = path.join(dir, fileName);
  try {
    fs.mkdirSync(dir, { recursive: true });
    // B2 Part 2: atomic write (temp-file-then-rename), replacing the prior
    // bare writeFileSync.
    _writeAtomicSync(full, gated.content);
    // I1: sign the EXACT bytes just written (post-encryption, if any) —
    // the same content a reader will read back and verify against, mirroring
    // `lineage-graph.json`'s own sign-what-you-wrote discipline.
    _writeAtomicSync(`${full}.sig`, signLastScan(gated.content));
  } catch (e) {
    return { ok: false, reason: `write failed: ${e.message}` };
  }

  return { ok: true, path: full };
}

// I1: shared signature check for both readers below — a file nobody
// validated on write (planted by hand, or copied without its .sig sibling)
// must not become trusted by being on disk, at the SAME level of scrutiny
// a torn/malformed file already gets. `false` (tampered — the body doesn't
// match the .sig) and `null` (missing signature entirely — including every
// pre-existing unsigned import a hand-crafted forgery would produce) are
// both UNTRUSTED and treated identically: skip the record, never promote
// it to "valid" just because JSON.parse succeeded. Disclosed via a
// `console.error`, mirroring `recipient-registry.js#loadRecipientConfig`'s
// own established "tolerant degradation, never a silent drop with no
// trace" pattern — never an attribute key/value, only the file path and
// the verification outcome.
function _verifiedOrDisclose(full, raw) {
  const verified = verifyLastScan(raw, `${full}.sig`);
  if (verified === true) return true;
  console.error(
    verified === null
      ? `agentic-security: runtime observation import ${full} has no .sig file — refusing to trust an unsigned import (a hand-planted forgery would look identical). Skipped.`
      : `agentic-security: runtime observation import ${full} FAILED signature verification — its contents do not match ${full}.sig. Refusing to trust a tampered import. Skipped.`,
  );
  return false;
}

/**
 * All persisted imports for scanRoot, newest first by mtime. Never
 * throws — a missing/empty directory, a corrupt file, a non-`.json` file,
 * an UNSIGNED or TAMPERED file (I1), or a file whose content fails
 * `validateObservationImport` are all silently skipped, mirroring
 * `graph-snapshot.js#loadSnapshots`'s own tolerance. A file nobody
 * validated on write (planted by hand) must not become trusted by being on
 * disk — hence the validate-on-read step, now preceded by the signature
 * check.
 */
export function loadObservationImports(scanRoot) {
  const dir = observationsDir(scanRoot);
  if (!fs.existsSync(dir)) return [];
  let files;
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { return []; }
  const withMtime = files.map((f) => {
    const full = path.join(dir, f);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(full).mtimeMs; } catch { /* keep 0 */ }
    return { full, mtimeMs };
  });
  withMtime.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const out = [];
  for (const { full } of withMtime) {
    try {
      const onDisk = fs.readFileSync(full, 'utf8');
      if (!_verifiedOrDisclose(full, onDisk)) continue;
      const raw = maybeDecryptForRead(onDisk);
      const parsed = JSON.parse(raw);
      const { valid } = validateObservationImport(parsed);
      if (valid) out.push(parsed);
    } catch { /* skip corrupt/unreadable file, never throw */ }
  }
  return out;
}

/**
 * One import by its id, or `null`. Validates the key's shape before any
 * `path.join` — see this file's own header. Never throws.
 */
export function loadObservationImport(scanRoot, importId) {
  const fileName = importFileName(importId);
  if (!fileName) return null;
  const full = path.join(observationsDir(scanRoot), fileName);
  try {
    const onDisk = fs.readFileSync(full, 'utf8');
    if (!_verifiedOrDisclose(full, onDisk)) return null;
    const raw = maybeDecryptForRead(onDisk);
    const parsed = JSON.parse(raw);
    const { valid } = validateObservationImport(parsed);
    return valid ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Every observation across every persisted import, flattened and
 * deduplicated by `id` (the newest import's copy wins, since
 * `loadObservationImports` is newest-first), sorted by `id`. Never
 * throws.
 */
export function loadObservations(scanRoot) {
  const imports = loadObservationImports(scanRoot);
  const map = new Map();
  for (const imp of imports) {
    for (const obs of imp.observations ?? []) {
      if (obs && typeof obs.id === 'string' && !map.has(obs.id)) {
        map.set(obs.id, obs);
      }
    }
  }
  return [...map.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * Delete one import file by id. Validates the key's shape before any
 * `path.join` — a malformed/traversal-shaped id refuses and unlinks
 * nothing. Returns `true` on a real deletion, `false` otherwise
 * (malformed id, file already gone, or an unlink error) — never throws.
 *
 * This is the property an append-only hash chain (the remediation ledger's
 * own shape) could not provide: FR-505 requires an observation store
 * follow real artifact encryption, RETENTION, RESET, access-control, and
 * no-egress rules, and a hash chain makes deletion structurally
 * impossible.
 */
export function deleteObservationImport(scanRoot, importId) {
  const fileName = importFileName(importId);
  if (!fileName) return false;
  const full = path.join(observationsDir(scanRoot), fileName);
  try {
    fs.unlinkSync(full);
    // I1: best-effort cleanup of the sibling .sig — never load-bearing for
    // this function's own true/false return (the main file's own unlink is
    // what determines success/failure), just hygiene so a deleted import
    // doesn't leave an orphaned signature file behind.
    try { fs.unlinkSync(`${full}.sig`); } catch { /* absent or already gone — fine either way */ }
    return true;
  } catch {
    return false;
  }
}
