// Detector runner tests (assurance-hardening PRD, E2 decomposition, D-0028
// step (a) / FR-201).
//
// engine.js's own detectors are, like its annotators, not expected to throw
// in practice — so, mirroring annotator-runner.test.js's own rationale,
// these tests exercise runDetector() directly with synthetic throwing
// callbacks, which is the actual isolation contract FR-201 is about.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDetector } from '../src/pipeline/detector-runner.js';

test('runDetector: a successful callback\'s value is returned unchanged', () => {
  const errors = [];
  const result = runDetector(errors, 'a.js', 'scanFoo', () => 42);
  assert.equal(result, 42);
  assert.deepEqual(errors, []);
});

test('runDetector: an array-returning callback (the common detector shape) passes through unchanged', () => {
  const errors = [];
  const result = runDetector(errors, 'a.js', 'scanFoo', () => [{ id: 1 }, { id: 2 }]);
  assert.deepEqual(result, [{ id: 1 }, { id: 2 }]);
  assert.deepEqual(errors, []);
});

test('runDetector: a thrown Error is captured, not propagated, result is undefined', () => {
  const errors = [];
  const result = runDetector(errors, 'a.js', 'scanFoo', () => { throw new Error('boom'); });
  assert.equal(result, undefined);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].file, 'a.js');
  assert.equal(errors[0].analyzer, 'scanFoo');
  assert.match(errors[0].err, /boom/);
});

test('runDetector: a thrown non-Error value (string, object) is still captured safely, never throws itself', () => {
  const errors = [];
  assert.doesNotThrow(() => runDetector(errors, 'a.js', 'scanBar', () => { throw 'raw string throw'; }));
  assert.equal(errors[errors.length - 1].err, 'raw string throw');
  assert.doesNotThrow(() => runDetector(errors, 'a.js', 'scanBaz', () => { throw { weird: 'object' }; }));
  assert.equal(errors.length, 2);
});

test('runDetector: independent calls do not swallow each other\'s errors, and a failure does not block subsequent calls', () => {
  const errors = [];
  const r1 = runDetector(errors, 'a.js', 'scanOk1', () => ['ok1']);
  const r2 = runDetector(errors, 'a.js', 'scanBad1', () => { throw new Error('e1'); });
  const r3 = runDetector(errors, 'a.js', 'scanOk2', () => ['ok2']);
  const r4 = runDetector(errors, 'b.js', 'scanBad2', () => { throw new Error('e2'); });
  assert.deepEqual(r1, ['ok1']);
  assert.equal(r2, undefined);
  assert.deepEqual(r3, ['ok2']);
  assert.equal(r4, undefined);
  assert.equal(errors.length, 2);
  assert.deepEqual(errors.map(e => e.analyzer), ['scanBad1', 'scanBad2']);
  assert.deepEqual(errors.map(e => e.file), ['a.js', 'b.js']);
});

test('runDetector: this is genuinely the FR-201 acceptance criterion — one detector exception does not prevent a subsequent INDEPENDENT detector from running', () => {
  const errors = [];
  const order = [];
  runDetector(errors, 'a.js', 'scanFirst', () => { order.push('first-ran'); throw new Error('first failed'); });
  runDetector(errors, 'a.js', 'scanSecond', () => { order.push('second-ran'); return ['second-result']; });
  assert.deepEqual(order, ['first-ran', 'second-ran'], 'the second detector must run even though the first threw');
  assert.equal(errors.length, 1);
  assert.equal(errors[0].analyzer, 'scanFirst');
});

test('runDetector: a spread-into-array call site guards correctly against the undefined-on-failure contract', () => {
  const errors = [];
  const aF = [];
  aF.push(...(runDetector(errors, 'a.js', 'scanOk', () => [{ id: 1 }]) || []));
  aF.push(...(runDetector(errors, 'a.js', 'scanFails', () => { throw new Error('x'); }) || []));
  assert.deepEqual(aF, [{ id: 1 }], 'a failed detector must contribute zero findings, not crash the push');
  assert.equal(errors.length, 1);
});
