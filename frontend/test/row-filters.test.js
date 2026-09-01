import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesFilters } from '../src/lib/row-filters.js';

test('matchesFilters: dataClass — matches when the row has ANY selected class', () => {
  const row = { dataClasses: ['PCI'] };
  assert.ok(matchesFilters(row, { dataClass: ['PCI', 'PHI'] }));
  assert.ok(!matchesFilters({ dataClasses: ['PII'] }, { dataClass: ['PCI'] }));
});

test('matchesFilters: dataClass — a row with no dataClasses property at all is unaffected (not hidden)', () => {
  assert.ok(matchesFilters({}, { dataClass: ['PCI'] }));
});

test('matchesFilters: protection (flow-level aggregate) — unchanged existing behavior', () => {
  assert.ok(matchesFilters({ protectionSummary: 'unprotected' }, { protection: ['unprotected'] }));
  assert.ok(!matchesFilters({ protectionSummary: 'protected' }, { protection: ['unprotected'] }));
  assert.ok(matchesFilters({}, { protection: ['unprotected'] }), 'a row with no protectionSummary is unaffected, not hidden');
});

test('matchesFilters: ai — now checked consistently for ANY row carrying isAiRelevant (closes the real Inventory gap)', () => {
  assert.ok(matchesFilters({ isAiRelevant: true }, { ai: true }));
  assert.ok(!matchesFilters({ isAiRelevant: false }, { ai: true }));
  assert.ok(matchesFilters({}, { ai: true }), 'a row with no isAiRelevant property at all is unaffected, not hidden');
});

test('matchesFilters: transitVerdict/atRestVerdict/handlingVerdict — each a real, independent facet', () => {
  const row = { transitVerdict: 'unprotected', atRestVerdict: 'protected', handlingVerdict: 'unknown' };
  assert.ok(matchesFilters(row, { transitVerdict: ['unprotected'] }));
  assert.ok(!matchesFilters(row, { transitVerdict: ['protected'] }));
  assert.ok(matchesFilters(row, { atRestVerdict: ['protected'] }));
  assert.ok(matchesFilters(row, { handlingVerdict: ['unknown'] }));
  assert.ok(matchesFilters({}, { transitVerdict: ['unprotected'] }), 'a row with no transitVerdict property is unaffected');
});

test('matchesFilters: sourceCategory / sinkCategory / destinationExternality / policyVerdict', () => {
  const row = { sourceCategory: 'http-body', sinkCategory: 'database', destinationExternality: 'external', policyVerdict: 'permitted' };
  assert.ok(matchesFilters(row, { sourceCategory: ['http-body'] }));
  assert.ok(!matchesFilters(row, { sourceCategory: ['env-value'] }));
  assert.ok(matchesFilters(row, { sinkCategory: ['database'] }));
  assert.ok(matchesFilters(row, { destinationExternality: ['external'] }));
  assert.ok(matchesFilters(row, { policyVerdict: ['permitted'] }));
});

test('matchesFilters: multiple active facets all AND together', () => {
  const row = { dataClasses: ['PCI'], protectionSummary: 'unprotected', policyVerdict: 'not_evaluated' };
  assert.ok(matchesFilters(row, { dataClass: ['PCI'], protection: ['unprotected'] }));
  assert.ok(!matchesFilters(row, { dataClass: ['PCI'], policyVerdict: ['permitted'] }));
});

test('matchesFilters: no active filters at all matches everything', () => {
  assert.ok(matchesFilters({}, {}));
  assert.ok(matchesFilters({ dataClasses: ['PCI'] }, {}));
});
