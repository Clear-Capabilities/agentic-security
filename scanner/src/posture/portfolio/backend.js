// Pluggable storage backends and offline operation for portfolios (X-708.AC02, X-708.AC03).
//
// Everything in the portfolio works with no hosted service: state is plain files, written atomically, readable with the standard
// library. This module adds the one thing a single store file cannot give, a defined way to run it from SEVERAL workers or hosts that
// share a directory, and a defined answer when that directory is not there.
//
// THE BACKEND INTERFACE (what a replacement implements)
//   kind                       'local-fs' | 'shared-dir' (a label that appears in every report)
//   describe()                 { kind, root, consistency } and what the backend does NOT claim
//   probe()                    { ok: true } or { ok: false, state: 'blocked', code, reason }; never throws, never creates anything
//   storeFile(name)            the path of a named document, for the portfolio store and ledger
//   withExclusive(name, fn)    run `fn` while holding a cross-process lock; throws BACKEND_UNAVAILABLE if the backend went away
//   acquireLease / renewLease / releaseLease / readLease
//                              a named, expiring, FENCED lease (below)
//
// REFERENCE IMPLEMENTATION. `FileLockBackend` uses exclusive file creation (`open(..., 'wx')`) in a directory. `createLocalBackend`
// makes the directory if needed (single user, durable restart). `createSharedBackend` will NOT: it requires a marker file written by
// an explicit `initSharedBackend`, so an unmounted path, a mistyped path or an empty mount point is a typed `blocked`, never a quietly
// fresh store.
//
// LEASE SEMANTICS (each tested, including two real processes contending):
//   - mutual exclusion: at most one holder has an unexpired lease on a resource at a time;
//   - fencing: every grant increments a `fence` number that never goes down (a release keeps it). A holder presents its fence on
//     renew and release, so a holder that was replaced after its lease expired is refused and learns it lost the lease (`lost`);
//   - expiry takeover: an expired lease can be taken by anyone; the previous holder's renew then fails;
//   - release by anyone but the holder, or with a stale fence, is refused.
//
// WHAT IS NOT CLAIMED. These semantics were verified on one machine's local filesystem, with several processes. Exclusive file
// creation is atomic on a local POSIX filesystem; whether it is atomic on a particular network filesystem depends on that filesystem
// and its mount options, and this build has not tested any. A shared directory used from several HOSTS therefore needs the operator to
// verify exclusive-create atomicity on that mount, and lease expiry compares wall clocks, so hosts' clocks must agree to well within a
// lease. Stale-lock recovery (a holder that died inside a critical section) has a narrow window in which two recoverers can both
// believe they broke the lock; critical sections here last milliseconds, and `lockStaleMs` is far above that. `networkFilesystem` is
// reported `unverified` in `describe()`.
//
// UNAVAILABLE BACKEND. Selecting a shared backend that cannot be used returns `{ ok: false, state: 'blocked', code, reason }` from
// `openBackend`, and there is no fallback argument: nothing here ever "degrades" to a local write. Callers must stop, not substitute.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { digestOf } from '../assurance/identity.js';
import { findSecret } from './bundle.js';
import { verifyStore, typedError } from './work-units.js';
import { ledgerPathFor, readLedger } from './scheduler.js';

export const BACKEND_MARKER = '.agentic-security-backend.json';
export const BACKEND_MARKER_SCHEMA = 'agentic-security/portfolio-backend-marker';
export const STATE_EXPORT_SCHEMA = 'agentic-security/portfolio-state-export';
export const BLOCK_CODES = Object.freeze(['backend-missing', 'backend-not-initialized', 'backend-not-a-directory', 'backend-symlink', 'backend-not-writable', 'backend-marker-invalid']);
export const BACKEND_LIMITS = Object.freeze({ lockStaleMs: 30_000, lockWaitMs: 5000, maxLeaseMs: 6 * 60 * 60_000, maxExportBytes: 64 * 1024 * 1024 });
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
const unavailable = (probe) => typedError('BACKEND_UNAVAILABLE', `the portfolio backend is unavailable (${probe.code}): ${probe.reason}`, { state: 'blocked', probe });

/** The reference backend: exclusive-create file locks in a directory. */
export class FileLockBackend {
  constructor({ kind, root, requireMarker, lockStaleMs = BACKEND_LIMITS.lockStaleMs, lockWaitMs = BACKEND_LIMITS.lockWaitMs, nodeId = null }) {
    this.kind = kind; this.root = path.resolve(root); this.requireMarker = requireMarker;
    this.lockStaleMs = lockStaleMs; this.lockWaitMs = lockWaitMs;
    this.nodeId = nodeId ?? `${os.hostname()}:${process.pid}`;
  }

  describe() {
    return {
      kind: this.kind, root: this.root, requiresMarker: this.requireMarker,
      consistency: {
        mutualExclusion: 'verified for processes sharing one local filesystem (two-process contention test)',
        fencing: 'monotonic per resource; a stale holder is refused on renew and release',
        networkFilesystem: 'unverified',
        clocks: 'lease expiry compares wall clocks; hosts sharing a directory must agree to well within a lease',
        staleLockRecovery: `a lock file older than ${this.lockStaleMs} ms is treated as abandoned; the recovery has a narrow race and is not a substitute for short critical sections`,
      },
    };
  }

  probe() {
    let st;
    try { st = fs.lstatSync(this.root); } catch { return { ok: false, state: 'blocked', code: 'backend-missing', reason: `${this.kind} backend directory does not exist or cannot be read` }; }
    if (st.isSymbolicLink()) return { ok: false, state: 'blocked', code: 'backend-symlink', reason: 'the backend directory is a symbolic link; it is not followed' };
    if (!st.isDirectory()) return { ok: false, state: 'blocked', code: 'backend-not-a-directory', reason: 'the backend path is not a directory' };
    if (this.requireMarker) {
      let m;
      try { m = JSON.parse(fs.readFileSync(path.join(this.root, BACKEND_MARKER), 'utf8')); } catch (e) {
        return { ok: false, state: 'blocked', code: e.code === 'ENOENT' ? 'backend-not-initialized' : 'backend-marker-invalid', reason: e.code === 'ENOENT' ? 'the shared directory has no backend marker: it is not initialized (an unmounted or empty directory is not a store)' : 'the backend marker is unreadable' };
      }
      if (m?.schema !== BACKEND_MARKER_SCHEMA || m.kind !== this.kind) return { ok: false, state: 'blocked', code: 'backend-marker-invalid', reason: 'the backend marker does not describe this kind of backend' };
    }
    try {
      const probeFile = path.join(this.root, `.probe-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
      fs.writeFileSync(probeFile, '', { flag: 'wx' }); fs.unlinkSync(probeFile);
    } catch { return { ok: false, state: 'blocked', code: 'backend-not-writable', reason: 'the backend directory is not writable' }; }
    return { ok: true };
  }

  storeFile(name = 'portfolio-store.json') {
    if (!NAME_RE.test(name)) throw typedError('BAD_NAME', `'${name}' is not an allowed document name`);
    return path.join(this.root, name);
  }

  _lockPath(name) {
    if (!NAME_RE.test(name)) throw typedError('BAD_NAME', `'${name}' is not an allowed lock name`);
    return path.join(this.root, '.locks', `${name}.lock`);
  }

  /** Run `fn` under the named cross-process lock. The backend is re-probed first: a backend that went away is an error, not an empty store. */
  withExclusive(name, fn, { waitMs = this.lockWaitMs } = {}) {
    const p = this.probe();
    if (!p.ok) throw unavailable(p);
    const lock = this._lockPath(name);
    fs.mkdirSync(path.dirname(lock), { recursive: true });
    const token = crypto.randomBytes(12).toString('hex');
    const body = JSON.stringify({ token, node: this.nodeId, pid: process.pid });
    const start = Date.now();
    for (;;) {
      try { fs.writeFileSync(lock, body, { flag: 'wx' }); break; } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        this._breakIfStale(lock);
        if (Date.now() - start > waitMs) throw typedError('LOCK_TIMEOUT', `could not take lock '${name}' within ${waitMs} ms`);
        sleepSync(3);
      }
    }
    try { return fn(); } finally {
      // release only OUR lock: if it was recovered as stale and re-taken, the file belongs to someone else now
      try { if (JSON.parse(fs.readFileSync(lock, 'utf8')).token === token) fs.unlinkSync(lock); } catch { /* already gone */ }
    }
  }

  _breakIfStale(lock) {
    let st; let seen;
    try { st = fs.statSync(lock); seen = JSON.parse(fs.readFileSync(lock, 'utf8')).token; } catch { return; }
    if (Date.now() - st.mtimeMs <= this.lockStaleMs) return;
    const grave = `${lock}.broken-${process.pid}-${crypto.randomBytes(3).toString('hex')}`;
    try { fs.renameSync(lock, grave); } catch { return; }
    let got = null;
    try { got = JSON.parse(fs.readFileSync(grave, 'utf8')).token; } catch { /* unreadable: treated as the stale one */ }
    if (got !== null && got !== seen) { try { fs.linkSync(grave, lock); } catch { /* the lock was re-taken meanwhile: the documented narrow race */ } }
    try { fs.unlinkSync(grave); } catch { /* ignore */ }
  }

  _leaseFile(resource) {
    if (!NAME_RE.test(resource)) throw typedError('BAD_NAME', `'${resource}' is not an allowed lease name`);
    return path.join(this.root, 'leases', `${resource}.json`);
  }

  _readLease(resource) {
    try { return JSON.parse(fs.readFileSync(this._leaseFile(resource), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw typedError('LEASE_CORRUPT', `lease '${resource}' is unreadable`); }
  }

  _writeLease(resource, doc) {
    const file = this._leaseFile(resource);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  readLease(resource) { return this.withExclusive(`lease-${resource}`, () => this._readLease(resource)); }

  acquireLease(resource, { holder, ttlMs, now }) {
    if (typeof holder !== 'string' || !holder) throw typedError('BAD_HOLDER', 'a lease needs a holder');
    if (!(Number.isFinite(ttlMs) && ttlMs >= 1) || !Number.isFinite(now)) throw typedError('BAD_LEASE', 'a lease needs a positive ttlMs and a now');
    const ttl = Math.min(ttlMs, BACKEND_LIMITS.maxLeaseMs);
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (cur && cur.holder && cur.expiresAt > now) return { ok: false, code: 'held', heldBy: cur.holder, expiresAt: cur.expiresAt, fence: cur.fence };
      const fence = (cur?.fence ?? 0) + 1;
      const doc = { resource, holder, fence, expiresAt: now + ttl, acquiredAt: now, node: this.nodeId };
      this._writeLease(resource, doc);
      return { ok: true, fence, expiresAt: doc.expiresAt, takenOver: !!(cur && cur.holder) };
    });
  }

  renewLease(resource, { holder, fence, ttlMs, now }) {
    const ttl = Math.min(ttlMs, BACKEND_LIMITS.maxLeaseMs);
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (!cur || cur.holder !== holder || cur.fence !== fence) return { ok: false, code: 'lost', reason: 'the lease is held by another holder or generation' };
      if (cur.expiresAt <= now) return { ok: false, code: 'expired', reason: 'the lease expired; it must be acquired again' };
      cur.expiresAt = now + ttl;
      this._writeLease(resource, cur);
      return { ok: true, fence, expiresAt: cur.expiresAt };
    });
  }

  releaseLease(resource, { holder, fence }) {
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (!cur || cur.holder !== holder || cur.fence !== fence) return { ok: false, code: 'not-holder', reason: 'only the current holder, with its fence, can release' };
      this._writeLease(resource, { resource, holder: null, fence: cur.fence, expiresAt: 0, node: this.nodeId });
      return { ok: true };
    });
  }
}

/** Create the marker that makes a directory a shared backend. An explicit operator act; `openBackend` never does it. */
export function initSharedBackend(dir, { id = crypto.randomBytes(8).toString('hex') } = {}) {
  const root = path.resolve(dir);
  fs.mkdirSync(root, { recursive: true });
  const marker = path.join(root, BACKEND_MARKER);
  if (fs.existsSync(marker)) return { ok: true, created: false };
  fs.writeFileSync(marker, JSON.stringify({ schema: BACKEND_MARKER_SCHEMA, kind: 'shared-dir', id }), { flag: 'wx' });
  return { ok: true, created: true };
}

export const createLocalBackend = (dir, o = {}) => { fs.mkdirSync(path.resolve(dir), { recursive: true }); return new FileLockBackend({ kind: 'local-fs', root: dir, requireMarker: false, ...o }); };
export const createSharedBackend = (dir, o = {}) => new FileLockBackend({ kind: 'shared-dir', root: dir, requireMarker: true, ...o });

/**
 * Select a backend. `mode` is 'local' or 'shared'. A shared backend that is not usable returns `{ ok: false, state: 'blocked', ... }`;
 * there is no fallback to the local backend, by design.
 */
export function openBackend({ mode, dir }) {
  if (mode !== 'local' && mode !== 'shared') return { ok: false, state: 'blocked', code: 'invalid-mode', reason: "mode must be 'local' or 'shared'" };
  if (typeof dir !== 'string' || !dir) return { ok: false, state: 'blocked', code: 'backend-missing', reason: 'a backend directory is required' };
  const backend = mode === 'local' ? createLocalBackend(dir) : createSharedBackend(dir);
  const p = backend.probe();
  return p.ok ? { ok: true, backend } : p;
}

// ---------------------------------------------------------------- offline export and import

/**
 * A single self-checking file holding the portfolio store and ledger (and optionally the deletion log), for moving state to an
 * air-gapped machine or archiving it. Reads nothing from the network. Refused if the store fails verification or any text in it has a
 * secret shape.
 */
export function exportState({ storeFile, outFile, retentionLog = null, now }) {
  const storeText = fs.readFileSync(storeFile, 'utf8');
  if (storeText.length > BACKEND_LIMITS.maxExportBytes) throw typedError('EXPORT_TOO_LARGE', 'the store is larger than the export limit');
  const store = JSON.parse(storeText);
  const v = verifyStore(store);
  if (!v.ok) throw typedError('STORE_CORRUPT', `refusing to export a store that fails verification: ${v.errors[0].code}`);
  const ledger = readLedger(storeFile);
  const log = retentionLog && fs.existsSync(retentionLog) ? fs.readFileSync(retentionLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  const body = { schema: STATE_EXPORT_SCHEMA, version: 1, ...(store.synthetic ? { synthetic: true } : {}), exportedAtMs: now, store, ledger, retentionLog: log };
  const secret = findSecret(JSON.stringify(body));
  if (secret) throw typedError('SECRET_IN_EXPORT', `the state contains a secret-shaped string (${secret}); it was not exported`);
  const doc = { ...body, digest: digestOf(body) };
  fs.mkdirSync(path.dirname(path.resolve(outFile)), { recursive: true });
  const tmp = `${outFile}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
  fs.renameSync(tmp, outFile);
  return { ok: true, digest: doc.digest, units: Object.keys(store.units).length };
}

/** Offline verification of an export: re-derives its digest and verifies the store inside. Executes nothing. */
export function verifyStateExport(file) {
  let doc;
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > BACKEND_LIMITS.maxExportBytes) return { ok: false, code: 'BAD_FILE', reason: 'not a regular file within the size limit' };
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch { return { ok: false, code: 'BAD_FILE', reason: 'unreadable or not JSON' }; }
  if (doc?.schema !== STATE_EXPORT_SCHEMA || doc.version !== 1) return { ok: false, code: 'BAD_SCHEMA', reason: 'not a portfolio state export of a supported version' };
  const { digest, ...body } = doc;
  if (digestOf(body) !== digest) return { ok: false, code: 'DIGEST_MISMATCH', reason: 'the export was modified after it was written' };
  const v = verifyStore(doc.store);
  if (!v.ok) return { ok: false, code: 'STORE_INVALID', reason: `the store inside fails verification: ${v.errors[0].code}` };
  return { ok: true, doc };
}

/** Import into a backend that holds no portfolio store yet. Verifies first; never overwrites. */
export function importState({ from, backend, name = 'portfolio-store.json' }) {
  const p = backend.probe();
  if (!p.ok) return p;
  const v = verifyStateExport(from);
  if (!v.ok) return { ok: false, state: 'rejected', code: v.code, reason: v.reason };
  const file = backend.storeFile(name);
  return backend.withExclusive('import', () => {
    if (fs.existsSync(file)) return { ok: false, state: 'rejected', code: 'WOULD_OVERWRITE', reason: 'the backend already holds a portfolio store; import never overwrites' };
    fs.writeFileSync(file, JSON.stringify(v.doc.store), { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(ledgerPathFor(file), JSON.stringify(v.doc.ledger), { flag: 'wx', mode: 0o600 });
    return { ok: true, file, units: Object.keys(v.doc.store.units).length };
  });
}

