// remediation-ledger.js — M5 deliverable #6 (Blast-Radius: Remediation
// Command Center, FR-507 + AC-31), Task 2 of the sub-project: the IMPURE
// half. `../lineage/remediation.js` (Task 1) ships the pure RemediationItem
// contract — zero imports, no fs, never throws. This module owns every side
// effect that contract needs to become a real, durable, tamper-evident
// record: file locking, JSONL append, tolerant read, and the hash chain.
//
// This is the SECOND `posture/` → `lineage/` import in the codebase
// (`auditor-walkthrough.js`'s `graph:` branch was the first, per
// `posture/CLAUDE.md`'s "First `posture/` → `lineage/` import" section) —
// noted here so the boundary stays a deliberate, documented exception
// rather than an accident.
//
// ── The append-only contract (PRD line 984) ──────────────────────────────
//
// A remediation item's history is never rewritten, only appended to. Every
// decision — owner assignment, a state change, a manual attestation, an
// accepted-risk exception — is a permanent event, never an edit of a prior
// one. `foldRemediationItem`/`foldRemediationLedger` (Task 1) derive an
// item's CURRENT shape by replaying its events forward; nothing here ever
// mutates a written line.
//
// ── Why the physical shape is a JSONL append, not a whole-file rewrite ────
//
// `fix-metrics.js:69`'s `recordFixAttempt` is the precedent this module
// follows: "One writeSync of one newline-terminated line: a concurrent
// reader sees whole records or nothing, and a torn tail is dropped on
// read." `provenance/lifecycle.js:195`'s `updateLifecycle`, by contrast,
// reads the WHOLE store into memory, folds one scan's worth of changes in,
// and rewrites the WHOLE file — safe there because a lifecycle update is a
// single scan touching potentially every finding at once. A remediation
// ledger is the opposite shape: a human, one item at a time, arbitrarily
// interleaved with edits to every OTHER item. A partial rewrite of a shared
// document risks losing every OTHER item's history to a crash or a bug
// mid-rewrite; an append can only ever add a new, independently-readable
// line.
//
// ── Why a lock is still required, despite the append itself being atomic ──
//
// `fs.appendFileSync` of one line is atomic at the OS level, but writing an
// event is not just "append a line" — it is a READ-MODIFY-WRITE: the
// proposed event must be validated (`validateTransition`) against the
// item's CURRENT folded state, which requires reading and folding every
// prior event first. Two concurrent callers each reading the same "before"
// state and then both appending could both validate against a state that
// is stale by the time either write lands — e.g. two racing attempts to
// open the same item, both seeing "no item yet" and both succeeding, when
// exactly one must win. The lock serializes the whole
// read-fold-validate-append sequence into one critical section per event.
//
// `withLock` below is a faithful local PORT of
// `provenance/lifecycle.js:36`'s own `withLock` — NOT an import, because
// that function is not exported (verified directly against the file: it is
// a bare, module-private `async function withLock`). `isProcessAlive` is
// ported alongside it for the same reason.
//
// ── The hash chain ─────────────────────────────────────────────────────
//
// Byte-identical in behavior to `mcp/audit.js`'s own chain (`_sha`,
// `GENESIS`, `_readLastEntryHash`, `verifyAuditLog`, verified directly
// against that file before writing this one): each event carries `prev`,
// the SHA-256 hex digest of the PREVIOUS line's exact serialized JSON text
// (including that line's own `prev` field). The first event's `prev` is
// the literal string `'GENESIS'`. `readLedgerEvents`/`latestEventHash`
// walk forward from GENESIS; a line that fails to `JSON.parse` (a torn
// tail) or whose `prev` does not match the expected running hash (tamper)
// STOPS the walk. Both functions therefore return the longest verifying
// PREFIX of the file — never the full stream when any of it is
// unverifiable, and never a thrown error. See `_walkLedger` below, which
// both exported readers share so they cannot silently disagree on what
// "the last valid line" means.
//
// `appendLedgerEvent` is async and is the SINGLE place `validateTransition`
// is called in this codebase. No CLI command (Task 3) computes validity
// for itself — every proposed event is validated at this one write
// boundary, inside the lock, against the real current folded state. As of
// final-review fix round 1, this is also the single place THREE more
// things are enforced, all inside the same lock so none of them can race
// the write they guard: an `opened` event is additionally checked against
// `validateOpenPayload` (I4/M11 — previously only the CLI validated an
// `opened` payload's own shape, so a non-CLI caller could append a
// malformed one); the ledger's on-disk tail is checked for tearing before
// anything is appended onto it (I4 — appending onto a torn line would
// merge them into one unparseable line, silently losing the new event,
// and everything after it, forever); and an optional
// `opts.expectedBaseHash` optimistic-concurrency check runs against the
// real `lastHash` computed inside the lock (I5 — previously the CLI's own
// `--base-event` guard ran OUTSIDE the lock, a real TOCTOU: another
// process could append in the window between that check and this
// function's own lock acquisition).

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath, isSafeStateDir, stateWritesEnabled } from './state-dir.js';
import { validateTransition, validateOpenPayload, foldRemediationLedger } from '../lineage/remediation.js';

const GENESIS = 'GENESIS';

function _sha(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

export function ledgerPaths(scanRoot) {
  return {
    ledgerPath: statePath(scanRoot, 'remediation', 'items.jsonl'),
    lockPath: statePath(scanRoot, 'remediation', 'items.lock'),
  };
}

// Shared walk: reads the ledger file (missing → empty), splits on '\n',
// drops empty lines, and walks forward maintaining `expectedPrev` (starting
// at GENESIS) exactly as `mcp/audit.js`'s `verifyAuditLog` does. A parse
// failure or a `prev` mismatch stops the walk without throwing. Returns
// `{events, lastHash}` so `readLedgerEvents`/`latestEventHash` cannot drift
// apart on what "the last valid line" means.
function _walkLedger(scanRoot) {
  const { ledgerPath } = ledgerPaths(scanRoot);
  let raw;
  try {
    raw = fs.readFileSync(ledgerPath, 'utf8');
  } catch {
    return { events: [], lastHash: GENESIS };
  }
  const lines = raw.split('\n').filter(Boolean);
  const events = [];
  let expectedPrev = GENESIS;
  let lastHash = GENESIS;
  for (const line of lines) {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      break; // torn tail — stop, do not throw
    }
    if (!event || typeof event !== 'object' || Array.isArray(event) || event.prev !== expectedPrev) {
      break; // tamper detected — stop, do not throw
    }
    events.push(event);
    lastHash = _sha(line);
    expectedPrev = lastHash;
  }
  return { events, lastHash };
}

// Returns the longest verifying PREFIX of the ledger — never the full
// stream when a tail is torn or a middle line is tampered. Never throws.
export function readLedgerEvents(scanRoot) {
  return _walkLedger(scanRoot).events;
}

// GENESIS when the ledger is empty/missing, or when nothing in it verifies.
export function latestEventHash(scanRoot) {
  return _walkLedger(scanRoot).lastHash;
}

// Reports whether the ledger's real content on disk has more raw lines than
// the longest verifying prefix — i.e. a torn tail OR a tampered middle line
// broke the hash chain partway through. Never throws. This is a read-only
// diagnostic; it does not change what readLedgerEvents/latestEventHash
// return (both still return the longest verifying prefix, unconditionally
// safe by construction) — it exists so a caller (the CLI's `list` command)
// can surface a loud warning instead of silently presenting a shorter or
// stale history as if it were the whole truth. (I7, final-review fix
// round 1.)
export function ledgerIntegrity(scanRoot) {
  const { ledgerPath } = ledgerPaths(scanRoot);
  let raw;
  try {
    raw = fs.readFileSync(ledgerPath, 'utf8');
  } catch {
    return { ok: true, totalLines: 0, verifiedLines: 0 };
  }
  const totalLines = raw.split('\n').filter(Boolean).length;
  const { events } = _walkLedger(scanRoot);
  return { ok: events.length === totalLines, totalLines, verifiedLines: events.length };
}

function isProcessAlive(pid) {
  // POSIX: process.kill(pid, 0) probes existence without sending a signal.
  // EPERM also means the process exists; only ESRCH means dead.
  try { process.kill(pid, 0); return true; }
  catch (e) { return e && e.code === 'EPERM'; }
}

// Faithful local port of `provenance/lifecycle.js:36-88`'s `withLock` — not
// an import, since that function is module-private there. Exclusive `wx`
// open of the lockfile, write the PID, run `fn` in a `try`, `unlink` in
// `finally`. On EEXIST, a stale lock (holding PID not alive, or lockfile
// older than 30s) is reaped, re-reading the lockfile before unlinking so a
// fresh holder taken by another process in the meantime is never raced.
// 25ms retry; 5s timeout throwing a named error.
async function withLock(lockPath, fn) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  const start = Date.now();
  const TIMEOUT_MS = 5000;
  while (true) {
    try {
      const handle = await fsp.open(lockPath, 'wx');
      await handle.writeFile(String(process.pid));
      try { await handle.close(); } catch {}
      try {
        return await fn();
      } finally {
        await fsp.unlink(lockPath).catch(() => {});
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        try {
          const [st, pidStr] = await Promise.all([
            fsp.stat(lockPath),
            fsp.readFile(lockPath, 'utf8').catch(() => ''),
          ]);
          const pid = parseInt(pidStr.trim(), 10);
          const pidAlive = Number.isFinite(pid) && isProcessAlive(pid);
          const old = Date.now() - st.mtimeMs > 30000;
          if (!pidAlive || old) {
            try {
              // Only unlink if the lockfile still holds the PID we just
              // read, so we don't race the unlink against a fresh lock
              // taken by another process in the meantime.
              const recheck = (await fsp.readFile(lockPath, 'utf8').catch(() => '')).trim();
              if (recheck === pidStr.trim()) {
                await fsp.unlink(lockPath);
              }
            } catch {}
            continue;
          }
        } catch {}
        if (Date.now() - start > TIMEOUT_MS) throw new Error('remediation-ledger: lock timed out');
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
}

// Resolves the itemId a proposed event refers to, mirroring
// `foldRemediationLedger`'s own grouping fallback exactly (Task 1's
// `../lineage/remediation.js`: `ev.itemId ?? (ev.type === 'opened' ?
// ev.id : undefined)`) — an `opened` event carries `id` (per
// `foldRemediationItem`'s own use of `openEvent.id`), every other event
// type carries `itemId`. Reusing the identical fallback here, rather than
// reading `eventPayload.itemId` alone, is what makes item resolution agree
// with how the ledger will actually be folded on read — an opened event
// for an id that already exists must resolve to that existing item, not
// silently miss it because the payload only carries `id`.
function _resolveItemId(eventPayload) {
  if (!eventPayload || typeof eventPayload !== 'object') return undefined;
  return eventPayload.itemId ?? (eventPayload.type === 'opened' ? eventPayload.id : undefined);
}

// This function is the single place `validateTransition` is called. No CLI
// command computes validity for itself. `opts.expectedBaseHash` (I5) is an
// optional optimistic-concurrency check, compared against the real
// `lastHash` computed INSIDE the lock — the authoritative half of the
// `--base-event` guard; `undefined` (the flag was never passed) performs no
// check.
export async function appendLedgerEvent(scanRoot, eventPayload, opts = {}) {
  const { ledgerPath, lockPath } = ledgerPaths(scanRoot);
  const dir = path.dirname(ledgerPath);

  // Refused BEFORE the lock is taken, so an unsafe/disabled target never
  // even gets a lockfile written into it.
  if (!isSafeStateDir(dir)) {
    return {
      valid: false,
      errors: [{ field: '(scanRoot)', message: 'refusing to write — not a recognized project state directory' }],
    };
  }
  if (!stateWritesEnabled()) {
    return {
      valid: false,
      errors: [{ field: '(state)', message: 'state writes are disabled (AGENTIC_SECURITY_NO_STATE or setStateWritesEnabled(false))' }],
    };
  }

  return withLock(lockPath, async () => {
    // I4 (final-review fix round 1): refuse to append onto a torn tail —
    // concatenating a new event onto an unterminated final line would
    // merge them into one unparseable line, silently losing this event
    // (and everything after it) forever while still reporting success. A
    // crash/ENOSPC mid-write leaves exactly this shape. Checked first,
    // inside the lock, before anything else touches the file.
    try {
      const raw = fs.readFileSync(ledgerPath, 'utf8');
      if (raw.length > 0 && !raw.endsWith('\n')) {
        return {
          valid: false,
          errors: [{ field: '(ledger)', message: 'the ledger file has a torn/unterminated final line — refusing to append onto it. Recover the file (restore from backup, or manually truncate to its last complete, newline-terminated line) before retrying.' }],
        };
      }
    } catch { /* missing file — nothing to check */ }

    const { events, lastHash } = _walkLedger(scanRoot);

    // I5 (final-review fix round 1): the authoritative optimistic-
    // concurrency check, run against the real `lastHash` computed inside
    // this same critical section — the CLI's own pre-lock check is still
    // useful as a cheap, early fail, but this is the one that cannot be
    // raced by a concurrent writer.
    if (opts.expectedBaseHash !== undefined && opts.expectedBaseHash !== lastHash) {
      return {
        valid: false,
        errors: [{ field: '(base-event)', message: 'the ledger changed since --base-event was computed (a concurrent write) — refusing to append.' }],
      };
    }

    const items = foldRemediationLedger(events);
    const itemId = _resolveItemId(eventPayload);
    const item = itemId != null ? (items[itemId] ?? null) : null;

    // M11: an `opened` event's own shape is validated here too, not just
    // by the CLI — mirrors "the single place validity is enforced" for
    // the one event type `validateTransition` deliberately does not
    // shape-check (it only checks that no item with this id exists yet).
    if (eventPayload && eventPayload.type === 'opened') {
      const openCheck = validateOpenPayload(eventPayload);
      if (!openCheck.valid) {
        return { valid: false, errors: openCheck.errors };
      }
    }

    const { valid, errors } = validateTransition(item, eventPayload);
    if (!valid) {
      return { valid: false, errors };
    }

    const event = { ...eventPayload, prev: lastHash };
    const line = JSON.stringify(event);
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(ledgerPath, line + '\n', 'utf8');
    return { valid: true, errors: [], event, hash: _sha(line) };
  });
}
