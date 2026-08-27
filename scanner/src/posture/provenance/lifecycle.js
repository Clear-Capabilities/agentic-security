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

async function withLock(scanRoot, fn) {
  const lp = lockPath(scanRoot);
  fs.mkdirSync(path.dirname(lp), { recursive: true });
  const start = Date.now();
  while (true) {
    try {
      const handle = await fsp.open(lp, 'wx');
      await handle.close();
      try {
        return await fn();
      } finally {
        await fsp.unlink(lp).catch(() => {});
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        if (Date.now() - start > 5000) throw new Error('provenance/lifecycle: lock timed out');
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
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
