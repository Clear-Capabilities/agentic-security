// Annotator runner tests (assurance-hardening PRD, Milestone 0/1, FR-106).
//
// engine.js's own annotators are deliberately built never to throw (see
// posture/CLAUDE.md's "no throwing" convention), so there is no natural,
// reliable way to fault-inject a real annotator end-to-end. These tests
// exercise the extracted runAnnotatorAsync() directly with synthetic
// throwing/rejecting callbacks — the actual contract FR-106 is about.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAnnotatorAsync } from '../src/pipeline/annotator-runner.js';

test('runAnnotatorAsync: a synchronous callback\'s value is returned unchanged', async () => {
  const errors = [];
  const result = await runAnnotatorAsync(errors, 'phaseA', () => 42);
  assert.equal(result, 42);
  assert.deepEqual(errors, []);
});

test('runAnnotatorAsync: an async callback\'s resolved value is returned, awaited fully', async () => {
  const errors = [];
  const result = await runAnnotatorAsync(errors, 'phaseB', async () => {
    await new Promise(r => setTimeout(r, 10));
    return 'done';
  });
  assert.equal(result, 'done');
  assert.deepEqual(errors, []);
});

test('runAnnotatorAsync: a thrown synchronous error is captured, not propagated', async () => {
  const errors = [];
  const result = await runAnnotatorAsync(errors, 'phaseSync', () => { throw new Error('sync boom'); });
  assert.equal(result, undefined);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].phase, 'phaseSync');
  assert.match(errors[0].err, /sync boom/);
});

// This is the core FR-106 regression case: before the fix, `try { return
// fn(); }` around an async callback returned fn()'s PENDING promise from
// inside the try block — a later rejection happened after the try/catch had
// already exited, so it became an unhandled rejection instead of a captured
// diagnostic. runAnnotatorAsync's `await fn()` must make this impossible.
test('runAnnotatorAsync: a REJECTED promise from an async callback is captured, not left as an unhandled rejection', async () => {
  const errors = [];
  let unhandled = false;
  const onUnhandled = () => { unhandled = true; };
  process.on('unhandledRejection', onUnhandled);
  try {
    const result = await runAnnotatorAsync(errors, 'phaseAsync', async () => {
      await new Promise(r => setTimeout(r, 5));
      throw new Error('async boom');
    });
    // Give any (incorrectly) unhandled rejection a turn of the event loop
    // to surface before we assert on it.
    await new Promise(r => setTimeout(r, 20));
    assert.equal(result, undefined);
    assert.equal(errors.length, 1);
    assert.equal(errors[0].phase, 'phaseAsync');
    assert.match(errors[0].err, /async boom/);
    assert.equal(unhandled, false, 'the rejection must not surface as an unhandled rejection');
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('runAnnotatorAsync: the caller\'s await genuinely waits — result is not returned before async work finishes', async () => {
  const errors = [];
  const order = [];
  const p = runAnnotatorAsync(errors, 'phaseOrder', async () => {
    await new Promise(r => setTimeout(r, 15));
    order.push('annotator-finished');
    return 'x';
  });
  order.push('call-made');
  await p;
  order.push('await-returned');
  assert.deepEqual(order, ['call-made', 'annotator-finished', 'await-returned'],
    'awaiting runAnnotatorAsync must not resolve before the async callback body completes');
});

test('runAnnotatorAsync: independent calls do not swallow each other\'s errors', async () => {
  const errors = [];
  await runAnnotatorAsync(errors, 'ok', () => 'fine');
  await runAnnotatorAsync(errors, 'bad1', () => { throw new Error('e1'); });
  await runAnnotatorAsync(errors, 'ok2', () => 'still fine');
  await runAnnotatorAsync(errors, 'bad2', async () => { throw new Error('e2'); });
  assert.equal(errors.length, 2);
  assert.deepEqual(errors.map(e => e.phase), ['bad1', 'bad2']);
});
