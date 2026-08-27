import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

function storePath(scanRoot) { return path.join(scanRoot, '.agentic-security', 'provenance', 'lifecycle.json'); }
function lockPath(scanRoot) { return path.join(scanRoot, '.agentic-security', 'provenance', 'lifecycle.lock'); }

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

export async function updateLifecycle(scanRoot, currentFindings, { scanId, observedAt }) {
  return withLock(scanRoot, async () => {
    const store = readLifecycle(scanRoot);
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
