import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadFactor } from './helpers/load.js';

test('a bound is scaled by how oversubscribed the machine is: never below 1, capped at 6, and a bad reading means no scaling', () => {
  assert.equal(loadFactor(2, 10), 1, 'an idle machine keeps the strict bound');
  assert.equal(loadFactor(10, 10), 1);
  assert.equal(loadFactor(30, 10), 3);
  assert.equal(loadFactor(500, 10), 6, 'capped');
  assert.equal(loadFactor(NaN, 10), 1);
  assert.equal(loadFactor(5, 0), 5, 'zero CPUs is treated as one');
});
