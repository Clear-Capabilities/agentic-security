// Producer collector tests (assurance-hardening PRD, Milestone 1, FR-102).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectProducerResult } from '../src/pipeline/producer-collector.js';
import { registerProducer, _resetForTests } from '../src/pipeline/producer-registry.js';

test('collectProducerResult: refuses an UNREGISTERED producer — nothing is appended, a diagnostic is recorded', () => {
  _resetForTests();
  const finalFindings = [];
  const diagnostics = [];
  const result = collectProducerResult(finalFindings, diagnostics, 'never-registered', () => [{ id: 'x' }]);
  assert.equal(result.status, 'unregistered');
  assert.equal(finalFindings.length, 0, 'an unregistered producer must never get its findings collected');
  assert.equal(diagnostics.length, 1);
  assert.match(diagnostics[0].err, /not registered/);
});

test('collectProducerResult: a registered producer\'s findings are appended and stamped with producerId', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  const finalFindings = [];
  const diagnostics = [];
  const result = collectProducerResult(finalFindings, diagnostics, 'p1', () => [{ id: 'f1' }, { id: 'f2' }]);
  assert.equal(result.status, 'completed');
  assert.equal(result.count, 2);
  assert.equal(finalFindings.length, 2);
  assert.equal(finalFindings[0].producerId, 'p1');
  assert.equal(finalFindings[1].producerId, 'p1');
  assert.deepEqual(diagnostics, []);
});

test('collectProducerResult: does not overwrite a producerId a finding already carries', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  const finalFindings = [];
  const result = collectProducerResult(finalFindings, [], 'p1', () => [{ id: 'f1', producerId: 'someone-else' }]);
  assert.equal(result.count, 1);
  assert.equal(finalFindings[0].producerId, 'someone-else');
});

test('collectProducerResult: a THROWING producer is captured as a diagnostic, not propagated, nothing appended (the actual A-03 fix — previously a bare catch(_){} left no trace anywhere)', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  const finalFindings = [];
  const diagnostics = [];
  assert.doesNotThrow(() => {
    const result = collectProducerResult(finalFindings, diagnostics, 'p1', () => { throw new Error('producer exploded'); });
    assert.equal(result.status, 'failed');
  });
  assert.equal(finalFindings.length, 0);
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0].phase, 'producer:p1');
  assert.match(diagnostics[0].err, /producer exploded/);
});

test('collectProducerResult: an empty/null result is a clean no-op, not an error', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  for (const returnValue of [null, undefined, [], { findings: [] }]) {
    const finalFindings = [];
    const diagnostics = [];
    const result = collectProducerResult(finalFindings, diagnostics, 'p1', () => returnValue);
    assert.equal(result.status, 'completed');
    assert.equal(result.count, 0);
    assert.deepEqual(finalFindings, []);
    assert.deepEqual(diagnostics, []);
  }
});

test('collectProducerResult: accepts an AnalyzerResult-shaped {findings:[...]} object, not just a bare array', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  const finalFindings = [];
  const result = collectProducerResult(finalFindings, [], 'p1', () => ({ status: 'completed', findings: [{ id: 'f1' }] }));
  assert.equal(result.count, 1);
  assert.equal(finalFindings.length, 1);
});
