import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { statePath, stateWritesEnabled } from '../state-dir.js';

// Both paths go through the state-dir seam rather than joining the state
// directory name by hand, so the project-root check applies here too — see
// test/no-stray-state.test.js.
function storePath(scanRoot) { return statePath(scanRoot, 'provenance', 'lifecycle.json'); }
function lockPath(scanRoot) { return statePath(scanRoot, 'provenance', 'lifecycle.lock'); }

export function readLifecycle(scanRoot) {
  try {
    const p = storePath(scanRoot);
    if (!fs.existsSync(p)) return {};
    return JSON.parse(fs.readFileSync(p, 'utf8'));
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
  return !!last && (last.type === 'introduced' || last.type === 'reintroduced');
}

/**
 * Fold this scan's findings into `store`, in memory. Pure with respect to the
 * filesystem — extracted so the read-only path below can produce the SAME view
 * the persisting path would, without writing anything.
 */
function applyScan(store, currentFindings, { scanId, observedAt }) {
  const currentIds = new Set(currentFindings.map((f) => f.stableId).filter(Boolean));

  for (const f of currentFindings) {
    if (!f.stableId) continue;
    const events = store[f.stableId] || (store[f.stableId] = []);
    if (isOpenEvent(events)) continue;
    const fp = f.findingProvenance;
    const commit = fp?.findingOrigin?.commit || null;
    const authorDate = fp?.status === 'complete' ? (fp.findingOrigin?.authorDate || observedAt) : observedAt;
    events.push({ type: events.length === 0 ? 'introduced' : 'reintroduced', commit, authorDate, scanId, observedAt });
  }

  for (const [stableId, events] of Object.entries(store)) {
    if (isOpenEvent(events) && !currentIds.has(stableId)) {
      events.push({ type: 'remediated', commit: null, authorDate: null, scanId, observedAt });
    }
  }

  return store;
}

export async function updateLifecycle(scanRoot, currentFindings, { scanId, observedAt }) {
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
    return applyScan(readLifecycle(scanRoot), currentFindings, { scanId, observedAt });
  }

  return withLock(scanRoot, async () => {
    const store = applyScan(readLifecycle(scanRoot), currentFindings, { scanId, observedAt });
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
  return (last.type === 'introduced' || last.type === 'reintroduced') ? last : null;
}
