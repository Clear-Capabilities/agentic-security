import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { statePath, stateWritesEnabled, isSafeStateDir } from '../state-dir.js';

// Both paths go through the state-dir seam rather than joining the state
// directory name by hand — see test/no-stray-state.test.js.
//
// What that does and does NOT buy: statePath() resolves WHERE state belongs
// (resolveProjectRoot walks up for a project marker), but it performs no
// safety check of its own. The marker check is `isSafeStateDir`, and it lives
// inside safeWriteState()/ensureStateDir() — which updateLifecycle
// deliberately bypasses (see its comment). So this module calls isSafeStateDir
// explicitly before writing; without that it would happily create
// `.agentic-security/` in a directory that is not a recognised project root,
// which is the litter state-dir.js exists to prevent.
function storePath(scanRoot) { return statePath(scanRoot, 'provenance', 'lifecycle.json'); }
function lockPath(scanRoot) { return statePath(scanRoot, 'provenance', 'lifecycle.lock'); }

export function readLifecycle(scanRoot) {
  // Read directly and let the catch handle "missing" — an explicit
  // existsSync() check first is a check-then-use race for no benefit, since
  // the catch already covers every failure mode a stale check would too.
  try {
    return JSON.parse(fs.readFileSync(storePath(scanRoot), 'utf8'));
  } catch {
    return {};
  }
}

// Mirrors posture/fix-history.js's _withLogLock: an exclusive (wx) lockfile,
// released in finally{}. On contention (EEXIST), a stale lock — one whose
// holding PID is no longer alive, or one older than 30s — is reaped before
// falling through to the timeout-based retry loop, so a crashed/killed
// process (not just a throwing one) cannot wedge provenance updates forever.
async function withLock(scanRoot, fn) {
  const lp = lockPath(scanRoot);
  fs.mkdirSync(path.dirname(lp), { recursive: true });
  const start = Date.now();
  const TIMEOUT_MS = 5000;
  while (true) {
    try {
      const handle = await fsp.open(lp, 'wx');
      await handle.writeFile(String(process.pid));
      try { await handle.close(); } catch {}
      try {
        return await fn();
      } finally {
        await fsp.unlink(lp).catch(() => {});
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        try {
          const [st, pidStr] = await Promise.all([
            fsp.stat(lp),
            fsp.readFile(lp, 'utf8').catch(() => ''),
          ]);
          const pid = parseInt(pidStr.trim(), 10);
          const pidAlive = Number.isFinite(pid) && isProcessAlive(pid);
          const old = Date.now() - st.mtimeMs > 30000;
          if (!pidAlive || old) {
            try {
              // Only unlink if the lockfile still holds the PID we just
              // read, so we don't race the unlink against a fresh lock
              // taken by another process in the meantime.
              const recheck = (await fsp.readFile(lp, 'utf8').catch(() => '')).trim();
              if (recheck === pidStr.trim()) {
                await fsp.unlink(lp);
              }
            } catch {}
            continue;
          }
        } catch {}
        if (Date.now() - start > TIMEOUT_MS) throw new Error('provenance/lifecycle: lock timed out');
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
}

function isProcessAlive(pid) {
  // POSIX: process.kill(pid, 0) probes existence without sending a signal.
  // EPERM also means the process exists; only ESRCH means dead.
  try { process.kill(pid, 0); return true; }
  catch (e) { return e && e.code === 'EPERM'; }
}

function isOpenEvent(events) {
  const last = events[events.length - 1];
  return !!last && ['introduced', 'reintroduced', 'reverted', 'cherry-picked'].includes(last.type);
}

/**
 * Fold this scan's findings into `store`, in memory. Pure with respect to the
 * filesystem — extracted so the read-only path below can produce the SAME view
 * the persisting path would, without writing anything.
 *
 * `completeScan` is the one structural guard in this module, and it exists
 * because the two passes below make asymmetric claims:
 *
 *  - The `introduced`/`reintroduced` pass reasons about findings that ARE
 *    present. Present is present regardless of how much of the tree was read,
 *    so it is sound on any scan and always runs.
 *  - The remediation pass reasons about findings that are ABSENT, turning
 *    absence into the positive claim "this was fixed." That is only sound if
 *    the scan actually looked everywhere it could have found them. On a subset
 *    scan (`--changed-since`, `--pr`, an MCP/LSP caller-supplied file list) the
 *    entire rest of the project is absent by construction, so running it marks
 *    every open finding outside the changed set remediated.
 *
 * Skipping the pass leaves those entries OPEN, which is the honest state: the
 * scan has no evidence either way. A later complete scan closes whatever was
 * genuinely fixed. Defaults true so an explicit `completeScan:false` is what
 * suppresses it, never a caller forgetting to pass the flag.
 */
function applyScan(store, currentFindings, { scanId, observedAt, completeScan = true }) {
  const currentIds = new Set(currentFindings.map((f) => f.stableId).filter(Boolean));

  for (const f of currentFindings) {
    if (!f.stableId) continue;
    const events = store[f.stableId] || (store[f.stableId] = []);
    if (isOpenEvent(events)) continue;
    const fp = f.findingProvenance;
    const commit = fp?.findingOrigin?.commit || null;
    const authorDate = fp?.status === 'complete' ? (fp.findingOrigin?.authorDate || observedAt) : observedAt;
    // M3 §3.1: a reintroduction whose resolved findingOrigin is a genuine
    // revert-of-a-fix or a cherry-picked propagation of an earlier
    // introduction is a DIFFERENT lifecycle story than an unrelated
    // reintroduction — both fields are only ever populated by deep-mode
    // resolution (Task 3), so this vocabulary is silent (both null) for
    // every standard-mode scan, which is the honest state: standard mode
    // has no opinion on the distinction.
    let type = events.length === 0 ? 'introduced' : 'reintroduced';
    // `relatedCommit` carries the revert-target / cherry-pick-source SHA that
    // was already read to CLASSIFY `type` above — without this, that SHA was
    // discarded once the classification was made, so a 'reverted'/
    // 'cherry-picked' event recorded THAT something was reverted/cherry-picked
    // but not WHAT commit it was reverted/cherry-picked from, which is the
    // fact a consumer actually needs to follow the link back.
    let relatedCommit = null;
    if (fp?.findingOrigin?.revertOf) { type = 'reverted'; relatedCommit = fp.findingOrigin.revertOf; }
    else if (fp?.findingOrigin?.cherryPickOf) { type = 'cherry-picked'; relatedCommit = fp.findingOrigin.cherryPickOf; }
    events.push({ type, commit, authorDate, scanId, observedAt, relatedCommit });
  }

  if (completeScan !== false) {
    for (const [stableId, events] of Object.entries(store)) {
      if (isOpenEvent(events) && !currentIds.has(stableId)) {
        events.push({ type: 'remediated', commit: null, authorDate: null, scanId, observedAt });
      }
    }
  }

  return store;
}

export async function updateLifecycle(scanRoot, currentFindings, { scanId, observedAt, completeScan = true }) {
  // Read-only scan (`--no-state` / AGENTIC_SECURITY_NO_STATE): return the view
  // this scan WOULD have produced, computed in memory, and persist nothing.
  //
  // Returning the on-disk store unchanged would have been one line shorter and
  // wrong in a quiet way — a caller asking "when was this finding introduced"
  // would get "never" for every finding first seen in this scan, which is a
  // false answer rather than a missing one. The lock is skipped too: a lockfile
  // is itself a write into the scanned tree, and there is nothing to serialise
  // when nothing is written.
  if (!stateWritesEnabled()) {
    return applyScan(readLifecycle(scanRoot), currentFindings, { scanId, observedAt, completeScan });
  }

  // The project-marker check safeWriteState() would have applied, applied here
  // because the write below deliberately does not go through it.
  //
  // Checked BEFORE withLock, not inside it: withLock's first act is
  // `fs.mkdirSync(path.dirname(lockPath))`, so guarding only the store write
  // would still have created `.agentic-security/provenance/` in an
  // unrecognised directory before refusing — the directory IS the litter, so
  // refusing after creating it refuses nothing. Returns the same in-memory view
  // the read-only path returns, for the same reason: a missing answer, not a
  // false one.
  if (!isSafeStateDir(path.dirname(storePath(scanRoot)))) {
    return applyScan(readLifecycle(scanRoot), currentFindings, { scanId, observedAt, completeScan });
  }

  return withLock(scanRoot, async () => {
    const store = applyScan(readLifecycle(scanRoot), currentFindings, { scanId, observedAt, completeScan });
    // Deliberately a direct write, not safeWriteState(): this write is inside a
    // locked critical section and its failure MUST propagate so the lock is
    // released and the caller learns the store was not persisted.
    // safeWriteState swallows errors and returns false, which would turn a
    // failed write into a silent no-op that still looks like success.
    fs.mkdirSync(path.dirname(storePath(scanRoot)), { recursive: true });
    fs.writeFileSync(storePath(scanRoot), JSON.stringify(store, null, 2));
    return store;
  });
}

export function latestOpenIntroduction(store, stableId) {
  const events = store[stableId];
  if (!events || events.length === 0) return null;
  const last = events[events.length - 1];
  // Same open-type vocabulary as isOpenEvent: 'reverted'/'cherry-picked' are
  // still open findings (M3 §3.1) — the classification is about HOW the
  // finding became open, not whether it currently is.
  return ['introduced', 'reintroduced', 'reverted', 'cherry-picked'].includes(last.type) ? last : null;
}
