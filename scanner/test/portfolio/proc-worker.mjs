// Child process for the X-708 consistency tests. Not a test file: the tests spawn it so that real, separate processes contend for the
// same shared directory. The single argument is a JSON config; the single line printed on stdout is a JSON result.
//
//   { mode: 'lease',   dir, resources: [..], holder, startAt, spacingMs, ttlMs }   try to take each lease at its barrier time
//   { mode: 'drain',   dir, holder, startAt, execDir, maxLeases?, crashAfterStart?, syncDir?, peers? }  drain the shared portfolio store
import fs from 'node:fs';
import path from 'node:path';
import { createSharedBackend, createLocalBackend } from '../../src/posture/portfolio/backend.js';
import { runScheduled } from '../../src/posture/portfolio/scheduler.js';
import { readStore } from '../../src/posture/portfolio/work-units.js';
import { ok, EST, BIG_BUDGETS } from './helpers.js';

// a generous wall estimate: the rendezvous below can hold an attempt for seconds, and the wall bound (rightly) fails an attempt that overruns it
const estimateOf = () => ({ ...EST, wallMs: 60_000 });

const cfg = JSON.parse(process.argv[2]);
const backend = cfg.kind === 'local' ? createLocalBackend(cfg.dir) : createSharedBackend(cfg.dir);
const spinUntil = (t) => { while (Date.now() < t) { /* busy wait so that both processes start the same instant */ } };

if (cfg.mode === 'lease') {
  const results = [];
  cfg.resources.forEach((resource, i) => {
    spinUntil(cfg.startAt + i * cfg.spacingMs);
    const r = backend.acquireLease(resource, { holder: cfg.holder, ttlMs: cfg.ttlMs, now: Date.now() });
    results.push({ resource, ok: r.ok, fence: r.fence ?? null, heldBy: r.heldBy ?? null });
  });
  process.stdout.write(`${JSON.stringify(results)}\n`);
} else if (cfg.mode === 'drain') {
  spinUntil(cfg.startAt);
  const file = backend.storeFile();
  const executed = [];
  let announced = false;
  const r = await runScheduled({
    file, backend, holder: cfg.holder, budgets: BIG_BUDGETS({ concurrency: cfg.slots ?? cfg.concurrency ?? 2 }), estimateOf, maxLeases: cfg.maxLeases ?? Infinity, ttlMs: cfg.ttlMs,
    executor: async (unit) => {
      if (cfg.syncDir && !announced) {
        // rendezvous: this process has a unit in hand; it does not proceed until every peer process has one too, so the run really overlaps
        announced = true;
        fs.writeFileSync(path.join(cfg.syncDir, cfg.holder), '');
        const until = Date.now() + 8000;
        while (Date.now() < until && !cfg.peers.every((h) => fs.existsSync(path.join(cfg.syncDir, h)))) await new Promise((r) => setTimeout(r, 10));
      }
      if (cfg.crashAfterStart) process.exit(17); // a hard crash while the lease is held, before any work is recorded
      // each unit may be executed by exactly one attempt: a second execution finds the marker and records a duplicate
      try { fs.writeFileSync(path.join(cfg.execDir, unit.id.replace(/:/g, '_')), cfg.holder, { flag: 'wx' }); executed.push(unit.id); } catch { fs.writeFileSync(path.join(cfg.execDir, `DUP-${unit.id.replace(/:/g, '_')}-${cfg.holder}`), ''); }
      return ok(unit);
    },
    workers: cfg.concurrency ?? 2,
  });
  const store = readStore(file);
  process.stdout.write(`${JSON.stringify({ stopped: r.stopped, executed, verified: Object.values(store.units).filter((u) => u.state === 'verified').length })}\n`);
}
