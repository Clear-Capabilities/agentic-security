import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCascadePool, DEFAULT_GRACE_MS } from '../src/pipeline/cascade-worker-pool.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SYNTHETIC_MODULE = path.join(HERE, 'fixtures', 'cascade-worker-pool', 'synthetic-cascade.mjs');

test('createCascadePool: a well-behaved file cascade resolves with its real return value', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 1, fileContents: { 'a.js': 'x' }, scanRoot: '/repo' });
  try {
    const res = await pool.runFile('a.js', 'hello world', '/repo', []);
    assert.equal(res.ok, true);
    assert.equal(res.result.file, 'a.js');
    assert.equal(res.result.contentLength, 'hello world'.length);
    assert.equal(res.result.scanRoot, '/repo');
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: _initCascadeWorkerState runs ONCE per worker, not once per task', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 1, fileContents: { 'a.js': '1', 'b.js': '2' }, scanRoot: '/repo' });
  try {
    const r1 = await pool.runFile('a.js', 'aaa', '/repo', []);
    const r2 = await pool.runFile('b.js', 'bbb', '/repo', []);
    const r3 = await pool.runFile('c.js', 'ccc', '/repo', []);
    // All three tasks route to the SAME single worker (poolSize:1), so initCount must
    // stay 1 across all of them -- proving setup happened once at worker creation,
    // not per file (the whole point of a reused pool vs. one-shot-per-file).
    assert.equal(r1.result.initCount, 1);
    assert.equal(r2.result.initCount, 1);
    assert.equal(r3.result.initCount, 1);
    assert.equal(r1.result.fileCountAtInit, 2);
    assert.equal(r1.result.scanRootAtInit, '/repo');
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: a thrown error inside the cascade is captured, not propagated or hung', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 1, fileContents: {}, scanRoot: null });
  try {
    const res = await pool.runFile('bad.js', 'THROW', null, []);
    assert.equal(res.ok, false);
    assert.match(res.error, /synthetic cascade failure/);
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: a REAL hung cascade is preemptively terminated within timeoutMs+graceMs, and the pool recovers', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 1, fileContents: {}, scanRoot: null, graceMs: 200 });
  try {
    const start = Date.now();
    const res = await pool.runFile('hung.js', 'HANG', null, [], { timeoutMs: 300 });
    const elapsed = Date.now() - start;
    assert.equal(res.ok, false);
    assert.equal(res.timedOut, true);
    assert.ok(elapsed < 3000, `expected termination well under 3s, took ${elapsed}ms`);

    // The pool must have replaced the killed worker -- a SUBSEQUENT file on the
    // same pool must still succeed, not hang or error because the worker is gone.
    const res2 = await pool.runFile('after.js', 'still works', null, []);
    assert.equal(res2.ok, true);
    assert.equal(res2.result.file, 'after.js');

    // The background respawn triggered by the kill must have succeeded (no
    // fire-and-forget failure silently swallowed).
    assert.equal(pool.getSpawnFailureCount(), 0);
    assert.equal(pool.getLastSpawnError(), null);
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: multiple files run correctly across a pool of more than one worker', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 3, fileContents: { 'x.js': '1' }, scanRoot: '/r' });
  try {
    const files = Array.from({ length: 9 }, (_, i) => `f${i}.js`);
    const results = await Promise.all(files.map((f) => pool.runFile(f, `content-${f}`, '/r', [])));
    assert.equal(results.length, 9);
    for (const [i, r] of results.entries()) {
      assert.equal(r.ok, true, `file ${i} failed: ${r.error}`);
      assert.equal(r.result.file, files[i]);
    }
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: input validation fails cleanly instead of hanging', () => {
  assert.throws(() => createCascadePool({}), /modulePath/);
  assert.throws(() => createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 0 }), /poolSize/);
  assert.throws(() => createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: -1 }), /poolSize/);
});

test('createCascadePool: default grace period is honored when unspecified', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 1, fileContents: {}, scanRoot: null });
  try {
    assert.equal(pool.DEFAULT_GRACE_MS, DEFAULT_GRACE_MS);
  } finally {
    await pool.shutdown();
  }
});

test('createCascadePool: shutdown terminates all workers and further calls are refused', async () => {
  const pool = createCascadePool({ modulePath: SYNTHETIC_MODULE, poolSize: 2, fileContents: {}, scanRoot: null });
  await pool.runFile('a.js', 'ok', null, []);
  await pool.shutdown();
  const res = await pool.runFile('b.js', 'ok', null, []);
  assert.equal(res.ok, false);
});
