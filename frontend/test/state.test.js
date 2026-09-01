import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseStateFromHash, serializeStateToHash, INVENTORY_TABLES } from '../src/lib/state.js';

test('parseStateFromHash returns defaults for an empty hash', () => {
  const state = parseStateFromHash('');
  assert.deepEqual(state, { view: 'architecture', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });
});

test('parseStateFromHash returns defaults for a bare "#"', () => {
  assert.deepEqual(parseStateFromHash('#'), { view: 'architecture', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });
});

test('parseStateFromHash reads view and selectedId', () => {
  const state = parseStateFromHash('#view=trace&selected=flow%3Apci.payment_api');
  assert.equal(state.view, 'trace');
  assert.equal(state.selectedId, 'flow:pci.payment_api');
});

test('parseStateFromHash reads a filters object from a JSON-encoded param', () => {
  const state = parseStateFromHash('#view=architecture&filters=%7B%22class%22%3A%5B%22PCI%22%5D%7D');
  assert.deepEqual(state.filters, { class: ['PCI'] });
});

test('parseStateFromHash falls back to defaults on malformed filters JSON rather than throwing', () => {
  const state = parseStateFromHash('#view=architecture&filters=not-json');
  assert.deepEqual(state.filters, {});
});

test('parseStateFromHash rejects an unknown view name back to the default', () => {
  const state = parseStateFromHash('#view=not-a-real-view');
  assert.equal(state.view, 'architecture');
});

test('serializeStateToHash round-trips through parseStateFromHash', () => {
  const original = { view: 'privacy', selectedId: 'node:process:abc123', filters: { class: ['PHI'], ai: true }, table: INVENTORY_TABLES[0] };
  const hash = serializeStateToHash(original);
  const parsed = parseStateFromHash(hash);
  assert.deepEqual(parsed, original);
});

test('serializeStateToHash never places raw graph-derived text unescaped in a way that breaks URL parsing', () => {
  const withWeirdId = { view: 'trace', selectedId: 'flow:has "quotes" & stuff', filters: {} };
  const hash = serializeStateToHash(withWeirdId);
  const parsed = parseStateFromHash(hash);
  assert.equal(parsed.selectedId, withWeirdId.selectedId);
});

test('parseStateFromHash never throws on adversarial input', () => {
  const adversarialInputs = ['#view=&selected=&filters=', '#%zz', '#view=architecture&filters=[1,2,3', '#a=b=c&&&'];
  for (const input of adversarialInputs) {
    assert.doesNotThrow(() => parseStateFromHash(input), `input "${input}" should not throw`);
  }
});

test('DEFAULT_STATE / parseStateFromHash default the table field to the first inventory category', () => {
  const state = parseStateFromHash('');
  assert.equal(state.table, INVENTORY_TABLES[0]);
});

test('parseStateFromHash reads a valid table value', () => {
  const state = parseStateFromHash(`#view=inventory&table=${INVENTORY_TABLES[3]}`);
  assert.equal(state.table, INVENTORY_TABLES[3]);
});

test('parseStateFromHash rejects an unknown table name back to the default', () => {
  const state = parseStateFromHash('#table=not-a-real-table');
  assert.equal(state.table, INVENTORY_TABLES[0]);
});

test('serializeStateToHash round-trips table', () => {
  const original = { view: 'inventory', selectedId: null, filters: {}, table: INVENTORY_TABLES[5] };
  const hash = serializeStateToHash(original);
  const parsed = parseStateFromHash(hash);
  assert.equal(parsed.table, INVENTORY_TABLES[5]);
});
