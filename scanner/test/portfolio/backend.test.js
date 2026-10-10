// X-708.AC02 and X-708.AC03: durable local and shared backends, tested lease consistency, offline operation, typed blocked states.
// SYNTHETIC portfolios only. The multi-process tests spawn real node processes (test/portfolio/proc-worker.mjs) that contend for one
// directory on THIS machine's local filesystem; nothing here says anything about a network filesystem, and the tests do not pretend to.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  FileLockBackend, createLocalBackend, createSharedBackend, initSharedBackend, openBackend, exportState, verifyStateExport, importState, BACKEND_MARKER, BACKEND_MARKER_SCHEMA, STATE_EXPORT_SCHEMA, BLOCK_CODES, BACKEND_LIMITS,
} from '../../src/posture/portfolio/backend.js';
import { openStore, readStore, mutateStore, leaseUnit, blockUnit } from '../../src/posture/portfolio/work-units.js';
import { runScheduled, readLedger } from '../../src/posture/portfolio/scheduler.js';
import { buildProgressView } from '../../src/posture/portfolio/progress.js';
import { applyRetention } from '../../src/posture/portfolio/retention.js';
import { runPortfolioCommand } from '../../src/posture/portfolio/cli.js';
import { manyUnitsPlan, BIG_BUDGETS, estimateOf, ok } from './helpers.js';

const WORKER = fileURLToPath(new URL('./proc-worker.mjs', import.meta.url));
const SRC = fileURLToPath(new URL('../../src/posture/portfolio/', import.meta.url));
const T = 1_000_000;
const ON = { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' };

function child(cfg) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [WORKER, JSON.stringify(cfg)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    p.stdout.on('data', (d) => { out += d; }); p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => { try { resolve({ code, result: out.trim() ? JSON.parse(out.trim().split('\n').at(-1)) : null, err }); } catch (e) { reject(new Error(`bad worker output (${code}): ${out} ${err}`)); } });
  });
}
const shared = () => { const dir = path.join(mkTestTmp('shared-'), 'portfolio'); initSharedBackend(dir); return { dir, backend: createSharedBackend(dir) }; };

describe('[X-708.AC02] a local filesystem backend gives durable restart and offline export', () => {
  test('[X-708.AC02] a portfolio survives the process that started it: a second process finishes it, and no unit is executed twice', async () => {
    const dir = path.join(mkTestTmp('local-'), 'state'); const execDir = mkTestTmp('exec-');
    const backend = createLocalBackend(dir);
    openStore(backend.storeFile(), manyUnitsPlan({ a: 4, b: 4 }));
    const first = await child({ kind: 'local', mode: 'drain', dir, holder: 'proc-1', startAt: 0, execDir, maxLeases: 3, concurrency: 1 });
    assert.equal(first.code, 0, first.err);
    assert.equal(first.result.verified, 3);
    const mid = readStore(backend.storeFile());
    const keep = JSON.stringify(Object.values(mid.units).filter((u) => u.state === 'verified').map((u) => [u.id, u.result]));
    const second = await child({ kind: 'local', mode: 'drain', dir, holder: 'proc-2', startAt: 0, execDir, concurrency: 1 });
    assert.equal(second.result.verified, 8);
    assert.equal(second.result.stopped, 'drained');
    const end = readStore(backend.storeFile());
    assert.equal(JSON.stringify(Object.values(end.units).filter((u) => mid.units[u.id].state === 'verified').map((u) => [u.id, u.result])), keep, 'work verified before the restart is untouched');
    const files = fs.readdirSync(execDir);
    assert.equal(files.length, 8);
    assert.equal(files.filter((f) => f.startsWith('DUP-')).length, 0, 'nothing ran twice');
  });

  test('[X-708.AC02] a hard crash while holding a lease costs one retry: the lease expires, another process takes the unit, and nothing is lost or double counted', async () => {
    const dir = path.join(mkTestTmp('crash-'), 'state'); const execDir = mkTestTmp('exec-');
    const backend = createLocalBackend(dir);
    openStore(backend.storeFile(), manyUnitsPlan({ a: 2 }));
    const crashed = await child({ kind: 'local', mode: 'drain', dir, holder: 'doomed', startAt: 0, execDir, crashAfterStart: true, concurrency: 1, ttlMs: 250 });
    assert.equal(crashed.code, 17, 'the worker really died mid-attempt');
    const held = Object.values(readStore(backend.storeFile()).units).filter((u) => u.lease);
    assert.equal(held.length, 1, 'its lease was left behind');
    assert.equal(buildProgressView({ store: readStore(backend.storeFile()), ledger: readLedger(backend.storeFile()), now: Date.now() }).view.units.verified, 0);
    await new Promise((r) => setTimeout(r, 400));
    const rescue = await child({ kind: 'local', mode: 'drain', dir, holder: 'rescuer', startAt: 0, execDir, concurrency: 1 });
    assert.equal(rescue.result.verified, 2);
    const end = readStore(backend.storeFile());
    assert.equal(end.units[held[0].id].retryCount, 1, 'the crashed attempt cost exactly one retry');
    assert.equal(end.units[held[0].id].events.filter((e) => e.type === 'expired').length, 1);
    assert.equal(readLedger(backend.storeFile()).settled[held[0].lease.attemptId], 'lease-ended');
    assert.equal(fs.readdirSync(execDir).filter((f) => f.startsWith('DUP-')).length, 0);
  });

  test('[X-708.AC02] offline export is one self-checking file; the same bytes verify with no store, no network and no key', () => {
    const { dir } = (() => { const d = path.join(mkTestTmp('exp-'), 'state'); return { dir: d }; })();
    const backend = createLocalBackend(dir);
    const file = backend.storeFile();
    openStore(file, manyUnitsPlan({ a: 2, b: 1 }));
    mutateStore(file, (s) => { const id = Object.keys(s.units)[0]; const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 1000, unitId: id }); void l; blockUnit(s, { unitId: Object.keys(s.units)[1], reason: 'needs a human', now: T }); });
    const out = path.join(mkTestTmp('out-'), 'portfolio.export.json');
    const r = exportState({ storeFile: file, outFile: out, now: T });
    assert.equal(r.ok, true);
    assert.equal(r.units, 3);
    assert.equal(verifyStateExport(out).ok, true);
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.equal(doc.schema, STATE_EXPORT_SCHEMA);
    assert.equal(doc.synthetic, true);
    assert.equal(doc.exportedAtMs, T, 'the export carries the supplied time, not a clock read');
  });

  test('[X-708.AC02] negative: a modified export, a bad schema, a symlink and an unreadable file are each rejected on verification', () => {
    const d = mkTestTmp('exp2-'); const file = path.join(d, 'store.json');
    openStore(file, manyUnitsPlan({ a: 1 }));
    const out = path.join(d, 'x.json');
    exportState({ storeFile: file, outFile: out, now: T });
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    const edit = (f) => { const c = JSON.parse(JSON.stringify(doc)); f(c); const p = path.join(d, `e${Math.random()}.json`); fs.writeFileSync(p, JSON.stringify(c)); return verifyStateExport(p); };
    assert.equal(edit((c) => { Object.values(c.store.units)[0].retryCount = 9; }).code, 'DIGEST_MISMATCH');
    assert.equal(edit((c) => { c.exportedAtMs = 5; }).code, 'DIGEST_MISMATCH');
    assert.equal(edit((c) => { c.schema = 'other'; }).code, 'BAD_SCHEMA');
    const link = path.join(d, 'link.json'); fs.symlinkSync(out, link);
    assert.equal(verifyStateExport(link).code, 'BAD_FILE');
    fs.writeFileSync(path.join(d, 'junk.json'), 'not json');
    assert.equal(verifyStateExport(path.join(d, 'junk.json')).code, 'BAD_FILE');
    assert.equal(verifyStateExport(path.join(d, 'missing.json')).code, 'BAD_FILE');
  });

  test('[X-708.AC02] negative: a store that fails verification is not exported, and a secret-shaped string is not exported', () => {
    const d = mkTestTmp('exp3-'); const file = path.join(d, 'store.json');
    openStore(file, manyUnitsPlan({ a: 2 }));
    mutateStore(file, (s) => blockUnit(s, { unitId: Object.keys(s.units)[0], reason: 'credential AKIAIOSFODNN7EXAMPLE was rejected', now: T }));
    assert.throws(() => exportState({ storeFile: file, outFile: path.join(d, 'o.json'), now: T }), (e) => e.code === 'SECRET_IN_EXPORT');
    assert.equal(fs.existsSync(path.join(d, 'o.json')), false, 'nothing was written');
    const bad = JSON.parse(fs.readFileSync(file, 'utf8')); Object.values(bad.units)[0].state = 'verified'; fs.writeFileSync(file, JSON.stringify(bad));
    assert.throws(() => exportState({ storeFile: file, outFile: path.join(d, 'o2.json'), now: T }), (e) => e.code === 'STORE_CORRUPT');
  });

  test('[X-708.AC02] import restores the same portfolio into an empty backend, verifies first, and never overwrites an existing one', () => {
    const d = mkTestTmp('imp-'); fs.mkdirSync(path.join(d, 'a')); const file = path.join(d, 'a', 'store.json');
    openStore(file, manyUnitsPlan({ a: 2 }));
    const out = path.join(d, 'x.json');
    exportState({ storeFile: file, outFile: out, now: T });
    const target = createLocalBackend(path.join(d, 'b'));
    const r = importState({ from: out, backend: target });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.deepEqual(readStore(target.storeFile()), readStore(file));
    assert.equal(importState({ from: out, backend: target }).code, 'WOULD_OVERWRITE');
    const tampered = JSON.parse(fs.readFileSync(out, 'utf8')); tampered.exportedAtMs = 1; const tp = path.join(d, 't.json'); fs.writeFileSync(tp, JSON.stringify(tampered));
    assert.equal(importState({ from: tp, backend: createLocalBackend(path.join(d, 'c')) }).code, 'DIGEST_MISMATCH');
  });
});

describe('[X-708.AC02] a customer-operated shared backend supports leases with tested consistency semantics', () => {
  test('[X-708.AC02] a held lease refuses a second holder, names the holder, and each grant carries a larger fence', () => {
    const { backend } = shared();
    const a = backend.acquireLease('controller', { holder: 'alice', ttlMs: 10_000, now: T });
    assert.deepEqual([a.ok, a.fence], [true, 1]);
    const b = backend.acquireLease('controller', { holder: 'bob', ttlMs: 10_000, now: T + 1 });
    assert.equal(b.ok, false);
    assert.equal(b.code, 'held');
    assert.equal(b.heldBy, 'alice');
    assert.equal(backend.acquireLease('controller', { holder: 'alice', ttlMs: 10_000, now: T + 2 }).ok, false, 'a holder renews; it does not re-acquire its own live lease');
    assert.equal(backend.acquireLease('other-resource', { holder: 'bob', ttlMs: 1000, now: T }).ok, true, 'leases are per resource');
  });

  test('[X-708.AC02] expiry hands the lease to the next taker with a higher fence, and the replaced holder is refused on renew and release (fencing)', () => {
    const { backend } = shared();
    const a = backend.acquireLease('r', { holder: 'alice', ttlMs: 1000, now: T });
    const b = backend.acquireLease('r', { holder: 'bob', ttlMs: 1000, now: T + 1000 });
    assert.equal(b.ok, true, 'expired at exactly now');
    assert.equal(b.takenOver, true);
    assert.equal(b.fence, a.fence + 1);
    const stale = backend.renewLease('r', { holder: 'alice', fence: a.fence, ttlMs: 1000, now: T + 1001 });
    assert.deepEqual([stale.ok, stale.code], [false, 'lost']);
    assert.equal(backend.releaseLease('r', { holder: 'alice', fence: a.fence }).code, 'not-holder', 'a zombie cannot release its successor\'s lease');
    assert.equal(backend.readLease('r').holder, 'bob');
    assert.equal(backend.renewLease('r', { holder: 'bob', fence: b.fence, ttlMs: 5000, now: T + 1500 }).ok, true);
  });

  test('[X-708.AC02] renewing an already-expired lease is refused; release frees it but never lowers the fence', () => {
    const { backend } = shared();
    const a = backend.acquireLease('r', { holder: 'alice', ttlMs: 1000, now: T });
    assert.equal(backend.renewLease('r', { holder: 'alice', fence: a.fence, ttlMs: 1000, now: T + 5000 }).code, 'expired');
    const c = backend.acquireLease('r2', { holder: 'carol', ttlMs: 10_000, now: T });
    assert.equal(backend.releaseLease('r2', { holder: 'carol', fence: c.fence }).ok, true);
    const d = backend.acquireLease('r2', { holder: 'dave', ttlMs: 1000, now: T + 1 });
    assert.equal(d.ok, true);
    assert.equal(d.fence, c.fence + 1);
    assert.equal(d.takenOver, false);
  });

  test('[X-708.AC02] bad lease requests are typed errors, and names cannot escape the directory', () => {
    const { backend } = shared();
    assert.throws(() => backend.acquireLease('r', { holder: '', ttlMs: 1, now: T }), (e) => e.code === 'BAD_HOLDER');
    assert.throws(() => backend.acquireLease('r', { holder: 'a', ttlMs: 0, now: T }), (e) => e.code === 'BAD_LEASE');
    assert.throws(() => backend.acquireLease('../escape', { holder: 'a', ttlMs: 10, now: T }), (e) => e.code === 'BAD_NAME');
    assert.throws(() => backend.storeFile('../x'), (e) => e.code === 'BAD_NAME');
    assert.ok(backend.acquireLease('long', { holder: 'a', ttlMs: 1e12, now: T }).expiresAt <= T + BACKEND_LIMITS.maxLeaseMs, 'a lease is capped');
  });

  test('[X-708.AC02] two real processes contend for the same leases: exactly one wins each, and the fences agree', async () => {
    const { dir } = shared();
    const resources = Array.from({ length: 16 }, (_, i) => `res-${i}`);
    const startAt = Date.now() + 900;
    const [p1, p2] = await Promise.all([
      child({ kind: 'shared', mode: 'lease', dir, resources, holder: 'proc-A', startAt, spacingMs: 15, ttlMs: 60_000 }),
      child({ kind: 'shared', mode: 'lease', dir, resources, holder: 'proc-B', startAt, spacingMs: 15, ttlMs: 60_000 }),
    ]);
    assert.equal(p1.code, 0, p1.err); assert.equal(p2.code, 0, p2.err);
    let aWins = 0; let bWins = 0;
    for (const res of resources) {
      const a = p1.result.find((x) => x.resource === res); const b = p2.result.find((x) => x.resource === res);
      assert.equal(Number(a.ok) + Number(b.ok), 1, `${res}: exactly one holder, got A=${a.ok} B=${b.ok}`);
      const loser = a.ok ? b : a;
      assert.equal(loser.heldBy, a.ok ? 'proc-A' : 'proc-B', 'the loser is told who holds it');
      assert.equal((a.ok ? a : b).fence, 1);
      if (a.ok) aWins++; else bWins++;
    }
    assert.equal(aWins + bWins, resources.length);
  });

  test('[X-708.AC02] two real processes drain one shared portfolio together: every unit is verified once, none ran twice, and spend is charged once per unit', async () => {
    // Every safety property is asserted on every attempt. That BOTH processes got work depends on the scheduler (one can finish the whole
    // queue before the other starts), so the overlap is required in at least one of up to three fresh attempts, which keeps the guard
    // against a single-process run without making a release depend on one scheduling roll.
    let overlapped = false;
    for (let attempt = 1; attempt <= 3 && !overlapped; attempt++) {
      const { dir, backend } = shared(); const execDir = mkTestTmp('exec2-');
      openStore(backend.storeFile(), manyUnitsPlan({ a: 8, b: 8, c: 4 }));
      const startAt = Date.now() + 900; const syncDir = mkTestTmp('sync-'); const peers = ['proc-A', 'proc-B'];
      const [p1, p2] = await Promise.all([
        child({ kind: 'shared', mode: 'drain', dir, holder: 'proc-A', startAt, execDir, concurrency: 2, slots: 4, syncDir, peers }),
        child({ kind: 'shared', mode: 'drain', dir, holder: 'proc-B', startAt, execDir, concurrency: 2, slots: 4, syncDir, peers }),
      ]);
      assert.equal(p1.code, 0, p1.err); assert.equal(p2.code, 0, p2.err);
      const store = readStore(backend.storeFile());
      assert.equal(Object.values(store.units).filter((u) => u.state === 'verified').length, 20);
      const files = fs.readdirSync(execDir);
      assert.equal(files.length, 20, `one execution marker per unit, got ${files.join(',')}`);
      assert.equal(files.filter((f) => f.startsWith('DUP-')).length, 0, 'no unit was executed by two processes');
      assert.equal(p1.result.executed.length + p2.result.executed.length, 20);
      const led = readLedger(backend.storeFile());
      assert.equal(Object.keys(led.reservations).length, 0, 'every reservation was settled');
      assert.equal(Object.keys(led.settled).length, 20, 'one settlement per unit, never two');
      assert.ok(Object.values(led.settled).every((h) => h === 'reported'));
      assert.equal(led.usage.portfolio.storageBytes, 20 * 10, 'each unit was charged once for its storage reservation');
      overlapped = p1.result.executed.length > 0 && p2.result.executed.length > 0;
    }
    assert.ok(overlapped, 'both processes did real work in at least one of three attempts');
  });

  test('[X-708.AC02] an abandoned lock is recovered after the stale window, a fresh lock is never broken, and a lock is released only by its owner', () => {
    const { dir } = shared();
    const quick = new FileLockBackend({ kind: 'shared-dir', root: dir, requireMarker: true, lockStaleMs: 200, lockWaitMs: 150 });
    quick.withExclusive('seed', () => 1); // creates .locks
    const lock = path.join(dir, '.locks', 'abandoned.lock');
    fs.writeFileSync(lock, JSON.stringify({ token: 'dead-holder', pid: 999999 }));
    assert.throws(() => quick.withExclusive('abandoned', () => 'x', { waitMs: 100 }), (e) => e.code === 'LOCK_TIMEOUT', 'a fresh lock held by someone else is respected');
    const old = new Date(Date.now() - 5000); fs.utimesSync(lock, old, old);
    assert.equal(quick.withExclusive('abandoned', () => 'recovered'), 'recovered');
    // the owner's release must not delete a lock that was recovered and re-taken by someone else meanwhile
    quick.withExclusive('swap', () => { fs.writeFileSync(path.join(dir, '.locks', 'swap.lock'), JSON.stringify({ token: 'someone-else' })); });
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, '.locks', 'swap.lock'), 'utf8')).token, 'someone-else');
  });

  test('[X-708.AC02] the backend states what it does not claim: network filesystems are unverified and the consistency scope is named', () => {
    const d = shared().backend.describe();
    assert.equal(d.kind, 'shared-dir');
    assert.equal(d.consistency.networkFilesystem, 'unverified');
    assert.match(d.consistency.mutualExclusion, /one local filesystem/);
    assert.match(d.consistency.clocks, /agree/);
  });
});

describe('[X-708.AC03] portfolio functions operate with no mandatory SaaS, and an unavailable shared backend yields a typed blocked state', () => {
  test('[X-708.AC03] the whole cycle (plan, schedule, progress, retention, export, import) runs with every network entry point disabled', async () => {
    const d = mkTestTmp('offline-'); const backend = createLocalBackend(path.join(d, 'state'));
    const realFetch = globalThis.fetch; const realConnect = net.Socket.prototype.connect;
    let attempts = 0;
    globalThis.fetch = () => { attempts++; throw new Error('network is disabled in this test'); };
    net.Socket.prototype.connect = function () { attempts++; throw new Error('network is disabled in this test'); };
    try {
      openStore(backend.storeFile(), manyUnitsPlan({ a: 3, b: 2 }));
      const r = await runScheduled({ file: backend.storeFile(), budgets: BIG_BUDGETS(), estimateOf, executor: async (u) => ok(u), workers: 1, backend });
      assert.equal(r.progress.verified, 5);
      const v = buildProgressView({ store: readStore(backend.storeFile()), ledger: readLedger(backend.storeFile()), now: T });
      assert.equal(v.ok, true);
      const out = path.join(d, 'e.json');
      exportState({ storeFile: backend.storeFile(), outFile: out, now: T });
      const dest = createLocalBackend(path.join(d, 'restored'));
      assert.equal(importState({ from: out, backend: dest }).ok, true);
      const cli = await runPortfolioCommand({ _: ['portfolio', 'progress'], flags: { store: dest.storeFile(), json: true } }, { cwd: d, env: ON, out: () => {}, err: () => {} });
      assert.equal(cli, 0);
      const rr = applyRetention({ root: d, logFile: path.join(d, 'log.jsonl'), actor: 'tester', records: [], now: T });
      assert.equal(rr.ok, true);
    } finally { globalThis.fetch = realFetch; net.Socket.prototype.connect = realConnect; }
    assert.equal(attempts, 0, 'nothing tried to reach a network');
  });

  test('[X-708.AC03] the portfolio modules import no network or hosted-service module and call no fetch', () => {
    for (const f of ['scheduler.js', 'progress.js', 'backend.js', 'retention.js', 'cli.js', 'work-units.js']) {
      const src = fs.readFileSync(path.join(SRC, f), 'utf8');
      assert.equal(/from 'node:(https?|net|tls|dns|dgram|http2)'/.test(src), false, `${f} imports a network module`);
      assert.equal(/\bfetch\(|XMLHttpRequest|WebSocket\(/.test(src), false, `${f} calls the network`);
    }
  });

  test('[X-708.AC03] an uninitialized, missing, empty-mount, linked or damaged shared directory is blocked with a typed code, and nothing is created in it', () => {
    const root = mkTestTmp('blk-');
    const missing = path.join(root, 'not-mounted');
    const m = openBackend({ mode: 'shared', dir: missing });
    assert.deepEqual([m.ok, m.state, m.code], [false, 'blocked', 'backend-missing']);
    assert.equal(fs.existsSync(missing), false, 'a blocked open does not create the directory');
    const empty = path.join(root, 'empty-mount'); fs.mkdirSync(empty);
    const e = openBackend({ mode: 'shared', dir: empty });
    assert.deepEqual([e.state, e.code], ['blocked', 'backend-not-initialized']);
    assert.deepEqual(fs.readdirSync(empty), [], 'an empty mount point is not turned into a store');
    const bad = path.join(root, 'bad-marker'); fs.mkdirSync(bad); fs.writeFileSync(path.join(bad, BACKEND_MARKER), '{"schema":"x"}');
    assert.equal(openBackend({ mode: 'shared', dir: bad }).code, 'backend-marker-invalid');
    fs.writeFileSync(path.join(bad, BACKEND_MARKER), 'not json');
    assert.equal(openBackend({ mode: 'shared', dir: bad }).code, 'backend-marker-invalid');
    const real = path.join(root, 'real'); initSharedBackend(real);
    const link = path.join(root, 'link'); fs.symlinkSync(real, link);
    assert.equal(openBackend({ mode: 'shared', dir: link }).code, 'backend-symlink');
    const file = path.join(root, 'afile'); fs.writeFileSync(file, 'x');
    assert.equal(openBackend({ mode: 'shared', dir: file }).code, 'backend-not-a-directory');
    const ro = path.join(root, 'ro'); initSharedBackend(ro); fs.chmodSync(ro, 0o500);
    try { assert.equal(process.getuid?.() === 0 ? 'backend-not-writable' : openBackend({ mode: 'shared', dir: ro }).code, 'backend-not-writable'); } finally { fs.chmodSync(ro, 0o700); }
    for (const r of [m, e, openBackend({ mode: 'shared', dir: link })]) { assert.ok(BLOCK_CODES.includes(r.code)); assert.equal('backend' in r, false, 'a blocked result carries no backend to use'); }
    assert.equal(openBackend({ mode: 'cloud', dir: real }).code, 'invalid-mode');
    assert.equal(openBackend({ mode: 'shared' }).code, 'backend-missing');
  });

  test('[X-708.AC03] a usable shared backend opens, and initialization is an explicit operator act that is idempotent', () => {
    const dir = path.join(mkTestTmp('init-'), 'p');
    assert.equal(openBackend({ mode: 'shared', dir }).ok, false);
    assert.deepEqual(initSharedBackend(dir), { ok: true, created: true });
    assert.deepEqual(initSharedBackend(dir), { ok: true, created: false });
    assert.equal(openBackend({ mode: 'shared', dir }).ok, true);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, BACKEND_MARKER), 'utf8')).schema, BACKEND_MARKER_SCHEMA);
  });

  test('[X-708.AC03] a backend that disappears mid-run stops the run as blocked: later units are not run, nothing is recreated, nothing is written locally instead', async () => {
    const cwd = mkTestTmp('cwd-'); const root = mkTestTmp('gone-'); const dir = path.join(root, 'portfolio');
    initSharedBackend(dir);
    const backend = createSharedBackend(dir);
    openStore(backend.storeFile(), manyUnitsPlan({ a: 4 }));
    const ran = [];
    const before = process.cwd();
    process.chdir(cwd);
    try {
      const r = await runScheduled({
        file: backend.storeFile(), backend, budgets: BIG_BUDGETS(), estimateOf, workers: 1,
        executor: async (u) => { ran.push(u.id); if (ran.length === 1) fs.rmSync(dir, { recursive: true, force: true }); return ok(u); },
      });
      assert.equal(r.stopped, 'blocked');
      assert.equal(r.blocked.state, 'blocked');
      assert.equal(r.blocked.code, 'backend-missing');
      assert.equal(ran.length, 1, 'no further unit was started');
      assert.equal(fs.existsSync(dir), false, 'the shared directory was not silently recreated');
      assert.deepEqual(fs.readdirSync(cwd), [], 'and no local store was written in its place');
      assert.equal(r.progress, null, 'progress is unknown, not zero and not stale');
    } finally { process.chdir(before); }
  });

  test('[X-708.AC03] losing only the marker (an unmounted share leaving an empty directory behind) also blocks, before the next lease', async () => {
    const { dir, backend } = shared();
    openStore(backend.storeFile(), manyUnitsPlan({ a: 3 }));
    const ran = [];
    const r = await runScheduled({
      file: backend.storeFile(), backend, budgets: BIG_BUDGETS(), estimateOf, workers: 1,
      executor: async (u) => { ran.push(u.id); fs.rmSync(path.join(dir, BACKEND_MARKER)); return ok(u); },
    });
    assert.equal(r.stopped, 'blocked');
    assert.equal(r.blocked.code, 'backend-not-initialized');
    assert.equal(ran.length, 1);
  });

  test('[X-708.AC03] a lock or lease taken on a backend that has gone away throws the typed BACKEND_UNAVAILABLE, never an empty result', () => {
    const { dir, backend } = shared();
    fs.rmSync(path.join(dir, BACKEND_MARKER));
    for (const f of [() => backend.withExclusive('x', () => 1), () => backend.acquireLease('r', { holder: 'a', ttlMs: 10, now: T }), () => backend.readLease('r')]) {
      assert.throws(f, (e) => e.code === 'BACKEND_UNAVAILABLE' && e.state === 'blocked' && e.probe.code === 'backend-not-initialized');
    }
  });

  test('[X-708.AC03] the CLI reports a blocked shared backend with exit 1 and creates nothing; probing a usable one exits 0', async () => {
    const root = mkTestTmp('clib-');
    let err = ''; let out = '';
    const io = { cwd: root, env: ON, out: (s) => { out += s; }, err: (s) => { err += s; } };
    const dir = path.join(root, 'nowhere');
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'backend', 'probe'], flags: { mode: 'shared', dir } }, io), 1);
    assert.match(out, /blocked \(backend-missing\)/);
    assert.match(out, /no other location is used instead/);
    assert.equal(fs.existsSync(dir), false);
    const okDir = path.join(root, 'ok'); initSharedBackend(okDir);
    out = '';
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'backend', 'probe'], flags: { mode: 'shared', dir: okDir } }, io), 0);
    assert.match(out, /usable/);
    assert.match(out, /Network filesystems: unverified/);
    const exportFile = path.join(root, 'e.json'); const store = path.join(root, 's.json'); openStore(store, manyUnitsPlan({ a: 1 }));
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'export'], flags: { store, out: exportFile, now: String(T) } }, io), 0);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'import'], flags: { from: exportFile, mode: 'shared', dir: path.join(root, 'also-nowhere') } }, io), 1);
    assert.match(err, /blocked \(backend-missing\)/);
    assert.equal(fs.existsSync(path.join(root, 'also-nowhere')), false);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'import'], flags: { from: exportFile, mode: 'shared', dir: okDir } }, io), 0);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'import'], flags: { from: exportFile, mode: 'shared', dir: okDir } }, io), 1, 'a second import would overwrite');
  });
});
