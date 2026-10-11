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

// a wall estimate that outlasts the longest the rendezvous below may hold an attempt (its hang guard plus a minute), because the wall bound
// (rightly) fails an attempt that overruns it and that must never be what ends a rendezvous
const estimateOf = () => ({ ...EST, wallMs: (cfg.rendezvousCapMs ?? 120_000) + 60_000 });

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
  // Rendezvous. The first unit this process gets announces "I have a unit in hand"; EVERY executor call in this process then waits at the
  // same gate until every peer has announced too, so the processes really overlap. Gating only the first call (as an earlier version did)
  // let this process's other worker drain the whole queue while a slow-starting peer was still loading, and the peer then found nothing to do.
  // The wait is on the peers' state, not on a clock: it ends when every peer has announced, or when a peer is provably gone (its recorded
  // pid no longer exists, which the test then reports through that peer's exit code). `rendezvousCapMs` is only a hang guard, scaled by the
  // caller for the machine's load; reaching it is reported as a failure, never treated as "they overlapped".
  let gate = null;
  const rendezvous = () => {
    gate ??= (async () => {
      fs.writeFileSync(path.join(cfg.syncDir, `${cfg.holder}.pid`), String(process.pid));
      fs.writeFileSync(path.join(cfg.syncDir, cfg.holder), '');
      const gone = (h) => {
        let pid;
        try { pid = Number(fs.readFileSync(path.join(cfg.syncDir, `${h}.pid`), 'utf8')); } catch { return false; } // not started yet: keep waiting
        try { process.kill(pid, 0); return false; } catch (e) { return e.code === 'ESRCH'; }
      };
      const until = Date.now() + (cfg.rendezvousCapMs ?? 120_000);
      for (;;) {
        const missing = cfg.peers.filter((h) => !fs.existsSync(path.join(cfg.syncDir, h)));
        if (!missing.length) return;
        if (missing.some(gone)) throw new Error(`rendezvous: peer gone before it held a unit: ${missing.join(',')}`);
        if (Date.now() > until) throw new Error(`rendezvous: peers never announced within ${cfg.rendezvousCapMs ?? 120_000} ms: ${missing.join(',')}`);
        await new Promise((r) => setTimeout(r, 10));
      }
    })();
    return gate;
  };
  const r = await runScheduled({
    file, backend, holder: cfg.holder, budgets: BIG_BUDGETS({ concurrency: cfg.slots ?? cfg.concurrency ?? 2 }), estimateOf, maxLeases: cfg.maxLeases ?? Infinity, ttlMs: cfg.ttlMs,
    executor: async (unit) => {
      if (cfg.syncDir) await rendezvous();
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
