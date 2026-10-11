// The supervisor's process-tree sweep runs inside the controller's own process, every sweepMs. A synchronous `ps` there blocks the
// event loop for as long as the machine takes to run it, so the sweep must be asynchronous and must never overlap itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { superviseSpawn } from '../src/sandbox/supervise.js';

const SRC = readFileSync(new URL('../src/sandbox/supervise.js', import.meta.url), 'utf8');

test('the supervisor uses no synchronous child-process call', () => {
  const code = SRC.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  assert.ok(!/\b(spawnSync|execFileSync|execSync)\b/.test(code), 'a synchronous child-process call blocks the controller event loop');
  assert.match(code, /sweeping/, 'the periodic sweep is guarded against overlapping itself');
});

test('a grandchild is still found by the asynchronous sweep and ended with the tree', async () => {
  const d = mkdtempSync(join(tmpdir(), 'sup-sweep-'));
  try {
    const pidFile = join(d, 'gc.pid');
    const r = await superviseSpawn('/bin/sh', ['-c', `(sleep 300 & echo $! > '${pidFile}'; wait) & wait`], { cwd: d, env: process.env, timeoutMs: 1500, graceMs: 300, sweepMs: 20 });
    assert.equal(r.timedOut, true);
    assert.ok(existsSync(pidFile));
    const gc = Number(readFileSync(pidFile, 'utf8'));
    assert.ok(Number.isInteger(gc) && gc > 1);
    let alive = true;
    try { process.kill(gc, 0); } catch { alive = false; }
    assert.equal(alive, false, 'the grandchild outlived the supervised tree');
    assert.deepEqual(r.termination.survivors, []);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
