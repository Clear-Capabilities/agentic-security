// Producer registry tests (assurance-hardening PRD, Milestone 1, FR-101).
//
// engine.js registers its real late-producers at module load into the same
// kind of module-level singleton this file exercises with synthetic
// fixtures. Verified empirically (not assumed) that this is safe: Node's
// test runner spawns a separate process per test FILE by default (checked
// with two throwaway files sharing globalThis — the second saw `undefined`,
// different pids), so this file's _resetForTests() calls never touch
// engine.js's real registrations, which live in a different file's process.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  registerProducer, isRegisteredProducer, getProducer, listProducers,
  validateNoUnregisteredDependencies, _resetForTests, KNOWN_PHASES_FOR_TESTS,
} from '../src/pipeline/producer-registry.js';

test('registerProducer: a well-formed producer registers successfully', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  assert.equal(isRegisteredProducer('p1'), true);
  assert.deepEqual(getProducer('p1').id, 'p1');
});

test('registerProducer: rejects a duplicate id', () => {
  _resetForTests();
  registerProducer({ id: 'p1', version: '1.0.0', phase: 'sast' });
  assert.throws(() => registerProducer({ id: 'p1', version: '2.0.0', phase: 'sca' }), /duplicate producer id/);
});

test('registerProducer: rejects an unknown phase', () => {
  _resetForTests();
  assert.throws(() => registerProducer({ id: 'p1', version: '1.0.0', phase: 'not-a-real-phase' }), /unknown phase/);
  assert.equal(isRegisteredProducer('p1'), false, 'a rejected registration must not partially register');
});

test('registerProducer: rejects missing id/version', () => {
  _resetForTests();
  assert.throws(() => registerProducer({ version: '1.0.0', phase: 'sast' }), /id required/);
  assert.throws(() => registerProducer({ id: 'p1', phase: 'sast' }), /missing version/);
});

test('registerProducer: rejects a direct dependency cycle (A -> B -> A)', () => {
  _resetForTests();
  registerProducer({ id: 'a', version: '1.0.0', phase: 'sast', dependsOn: ['b'] });
  assert.throws(() => registerProducer({ id: 'b', version: '1.0.0', phase: 'sast', dependsOn: ['a'] }), /dependency cycle/);
  assert.equal(isRegisteredProducer('b'), false, 'a cycle-causing registration must be rolled back, not left partially applied');
});

test('registerProducer: rejects a longer cycle (A -> B -> C -> A)', () => {
  _resetForTests();
  registerProducer({ id: 'a', version: '1.0.0', phase: 'sast', dependsOn: ['b'] });
  registerProducer({ id: 'b', version: '1.0.0', phase: 'sast', dependsOn: ['c'] });
  assert.throws(() => registerProducer({ id: 'c', version: '1.0.0', phase: 'sast', dependsOn: ['a'] }), /dependency cycle/);
});

test('registerProducer: a diamond dependency (not a cycle) registers fine', () => {
  _resetForTests();
  registerProducer({ id: 'base', version: '1.0.0', phase: 'sast' });
  registerProducer({ id: 'left', version: '1.0.0', phase: 'sast', dependsOn: ['base'] });
  registerProducer({ id: 'right', version: '1.0.0', phase: 'sast', dependsOn: ['base'] });
  assert.doesNotThrow(() => registerProducer({ id: 'top', version: '1.0.0', phase: 'sast', dependsOn: ['left', 'right'] }));
});

test('validateNoUnregisteredDependencies: flags a dependency on an id that was never registered', () => {
  _resetForTests();
  registerProducer({ id: 'a', version: '1.0.0', phase: 'sast', dependsOn: ['ghost'] });
  const missing = validateNoUnregisteredDependencies();
  assert.equal(missing.length, 1);
  assert.match(missing[0], /unregistered producer "ghost"/);
});

test('validateNoUnregisteredDependencies: empty when every dependency resolves', () => {
  _resetForTests();
  registerProducer({ id: 'a', version: '1.0.0', phase: 'sast' });
  registerProducer({ id: 'b', version: '1.0.0', phase: 'sast', dependsOn: ['a'] });
  assert.deepEqual(validateNoUnregisteredDependencies(), []);
});

test('listProducers reflects exactly what was registered', () => {
  _resetForTests();
  registerProducer({ id: 'a', version: '1.0.0', phase: 'sast' });
  registerProducer({ id: 'b', version: '1.0.0', phase: 'sca' });
  const ids = listProducers().map(p => p.id).sort();
  assert.deepEqual(ids, ['a', 'b']);
});

test('KNOWN_PHASES_FOR_TESTS is a non-empty, stable list', () => {
  assert.ok(Array.isArray(KNOWN_PHASES_FOR_TESTS));
  assert.ok(KNOWN_PHASES_FOR_TESTS.length > 0);
  assert.ok(Object.isFrozen(KNOWN_PHASES_FOR_TESTS));
});
