// The cross-process lock behind the event log's sequence ids. A live owner is never overridden and a waiter never
// runs the protected section without the lock; a dead or unreadable owner is taken over.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, utimesSync, readFileSync, rmSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withFileLock, appendJsonl } from '../lib/util.mjs';
import { appendEvent, layout } from '../lib/state.mjs';
import { mkdirSync } from 'node:fs';

const tmp = () => mkdtempSync(join(tmpdir(), 'loop-lock-'));
const age = (p, secondsAgo) => { const t = new Date(Date.now() - secondsAgo * 1000); utimesSync(p, t, t); };

test('[LOOP-003.AC03] a lock held by a LIVE process is never taken over, however old, and the section does not run', () => {
  const d = tmp();
  try {
    const lock = join(d, 'a.lock'); writeFileSync(lock, String(process.pid)); age(lock, 3600);
    let ran = false;
    assert.throws(() => withFileLock(lock, () => { ran = true; }, { staleMs: 10, hardMs: 250 }), /held by a live process/);
    assert.equal(ran, false, 'the protected section ran without the lock');
    assert.equal(readFileSync(lock, 'utf8'), String(process.pid), 'a live owner\'s lock is left untouched');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('[LOOP-003.AC03] a lock whose owner process is gone is taken over', () => {
  const d = tmp();
  try {
    const gone = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
    const lock = join(d, 'b.lock'); writeFileSync(lock, gone.stdout);
    assert.equal(withFileLock(lock, () => 'ran', { hardMs: 2000 }), 'ran');
    assert.equal(existsSync(lock), false, 'the lock is released');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('[LOOP-003.AC03] an ownerless lock file is taken over only once it is older than staleMs', () => {
  const d = tmp();
  try {
    const lock = join(d, 'c.lock'); writeFileSync(lock, '');
    assert.throws(() => withFileLock(lock, () => {}, { staleMs: 60000, hardMs: 200 }), /held by a live process/, 'a fresh ownerless file is respected');
    age(lock, 3600);
    assert.equal(withFileLock(lock, () => 'ran', { staleMs: 60000, hardMs: 2000 }), 'ran');
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('[LOOP-003.AC03] the lock is released when the section throws, and the error propagates', () => {
  const d = tmp();
  try {
    const lock = join(d, 'd.lock');
    assert.throws(() => withFileLock(lock, () => { throw new Error('boom'); }), /boom/);
    assert.equal(existsSync(lock), false);
    assert.equal(withFileLock(lock, () => 1), 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('[LOOP-003.AC03] a waiter does not enter while a live process in another process holds the lock, even past the old 2 s steal point', async () => {
  const d = tmp();
  try {
    const lock = join(d, 'e.lock'); const flag = join(d, 'in-section');
    const holder = spawn(process.execPath, ['--input-type=module', '-e', `
      import { withFileLock } from ${JSON.stringify(new URL('../lib/util.mjs', import.meta.url).href)};
      import { writeFileSync } from 'node:fs';
      withFileLock(${JSON.stringify(lock)}, () => { writeFileSync(${JSON.stringify(flag)}, '1'); const t = Date.now() + 2600; while (Date.now() < t); });`], { stdio: 'ignore' });
    const deadline = Date.now() + 20000;
    while (!existsSync(flag) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    assert.ok(existsSync(flag), 'the holder entered its section');
    const started = Date.now();
    let enteredAt = null;
    // runs in a second process so this process\'s event loop and the holder\'s busy loop are independent
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import { withFileLock } from ${JSON.stringify(new URL('../lib/util.mjs', import.meta.url).href)};
      withFileLock(${JSON.stringify(lock)}, () => process.stdout.write(String(Date.now())), { hardMs: 60000 });`], { encoding: 'utf8' });
    enteredAt = Number(r.stdout);
    await new Promise((res) => holder.on('close', res));
    assert.ok(Number.isFinite(enteredAt), r.stderr);
    assert.ok(enteredAt - started >= 1500, `the waiter entered after ${enteredAt - started} ms, while the holder still held the lock`);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('[LOOP-003.AC03] three processes appending at once never share a sequence id, repeated', async () => {
  const d = tmp();
  try {
    for (let round = 0; round < 3; round++) {
      const L = layout(d, `run-${round}`); mkdirSync(L.dir, { recursive: true });
      const worker = `import { appendEvent, layout } from ${JSON.stringify(new URL('../lib/state.mjs', import.meta.url).href)}; const L = layout(${JSON.stringify(d)}, ${JSON.stringify(`run-${round}`)}); for (let i = 0; i < 80; i++) appendEvent(L, 'p', { i });`;
      await Promise.all([1, 2, 3].map(() => new Promise((res) => { const c = spawn(process.execPath, ['--input-type=module', '-e', worker], { stdio: 'ignore' }); c.on('close', res); })));
      const seqs = readFileSync(L.eventsFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l).seq);
      assert.equal(seqs.length, 240); assert.equal(new Set(seqs).size, 240, `round ${round}: duplicate sequence id`);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});
