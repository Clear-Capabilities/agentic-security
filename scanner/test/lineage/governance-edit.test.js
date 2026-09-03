import { test } from 'node:test';
import assert from 'node:assert/strict';
import { proposeGovernanceEdit } from '../../src/lineage/governance-edit.js';

function _validEntry(overrides = {}) {
  return {
    provider: 'Acme Analytics', serviceType: 'analytics', legalEntity: 'Acme Inc',
    processorRole: 'processor', servicePurpose: 'usage analytics',
    subprocessorChain: [], processingCountries: ['US'], dataResidencyCommitment: null,
    dpaStatus: 'in_place', transferMechanism: null, transferImpactReviewStatus: null,
    retentionCommitment: null, ...overrides,
  };
}

test('proposeGovernanceEdit: a well-formed patch adding a new recipient is valid, with a real diff', () => {
  const current = { recipients: {} };
  const patch = { recipients: { vendor1: _validEntry() } };
  const { valid, errors, diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
  assert.deepEqual(diff.added, ['vendor1']);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.changed, []);
});

test('proposeGovernanceEdit: removing a recipient is reflected in the diff', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { recipients: {} };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, ['vendor1']);
  assert.deepEqual(diff.added, []);
});

test('proposeGovernanceEdit: changing an existing recipient field is reflected in the diff as changed, not added+removed', () => {
  const current = { recipients: { vendor1: _validEntry({ dpaStatus: 'not_in_place' }) } };
  const patch = { recipients: { vendor1: _validEntry({ dpaStatus: 'in_place' }) } };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].key, 'vendor1');
  assert.equal(diff.changed[0].before.dpaStatus, 'not_in_place');
  assert.equal(diff.changed[0].after.dpaStatus, 'in_place');
});

test('proposeGovernanceEdit: an unchanged recipient never appears in the diff at all', () => {
  const entry = _validEntry();
  const current = { recipients: { vendor1: entry } };
  const patch = { recipients: { vendor1: { ...entry } } };
  const { diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.changed, []);
});

test('proposeGovernanceEdit: a recipient whose patch entry has identical values but different KEY INSERTION ORDER is never flagged as changed (task-1 review finding)', () => {
  // Reproduces the review's own exact repro: raw JSON.stringify comparison
  // spuriously flags a recipient as "changed" purely because its patch
  // entry's keys were inserted in a different order than the stored
  // config's own order — a real scenario once Task 2 starts reading
  // hand-authored patch files from disk, since a human editing JSON has no
  // reason to preserve the exact key order of the file they're editing.
  const current = {
    recipients: {
      vendor1: { legalEntity: 'Acme', dpaStatus: 'in_place', processorRole: 'processor' },
    },
  };
  const patch = {
    recipients: {
      vendor1: { processorRole: 'processor', dpaStatus: 'in_place', legalEntity: 'Acme' },
    },
  };
  const { diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.changed, []);
});

test('proposeGovernanceEdit: a recipient whose subprocessorChain ARRAY is merely reordered is still correctly flagged as changed — array order stays semantically meaningful', () => {
  const current = { recipients: { vendor1: _validEntry({ subprocessorChain: ['a', 'b'] }) } };
  const patch = { recipients: { vendor1: _validEntry({ subprocessorChain: ['b', 'a'] }) } };
  const { diff } = proposeGovernanceEdit(current, patch);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].key, 'vendor1');
});

test('proposeGovernanceEdit: a malformed entry in the patch is rejected with a clear, per-key error, and never marked valid', () => {
  const current = { recipients: {} };
  // NOTE: every field `isValidRecipientConfigEntry` checks is nullable/optional
  // (`_isStringOrNull` accepts `undefined`), and it does not validate
  // `provider`/`serviceType` at all — so a sparse object like
  // `{ provider: 'x' }` is actually VALID per the real validator, not
  // malformed. This uses a genuinely invalid enum value instead
  // (`dpaStatus` must be one of `RECIPIENT_DPA_STATUSES` when present).
  const patch = { recipients: { vendor1: { provider: 'x', dpaStatus: 'not_a_real_status' } } };
  const { valid, errors } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.key === 'vendor1'));
});

test('proposeGovernanceEdit: the diff is still computed even when the patch is invalid, so the operator sees what they attempted', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  // See the note above: `{ provider: 'bad' }` alone is actually valid per
  // the real validator, so this uses a genuinely invalid enum value.
  const patch = { recipients: { vendor1: _validEntry(), vendor2: { provider: 'bad', dpaStatus: 'not_a_real_status' } } };
  const { valid, diff } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.deepEqual(diff.added, ['vendor2']);
});

test('proposeGovernanceEdit: never throws on a malformed current/patch shape', () => {
  for (const bad of [null, undefined, {}, { recipients: null }]) {
    assert.doesNotThrow(() => proposeGovernanceEdit(bad, { recipients: {} }));
    assert.doesNotThrow(() => proposeGovernanceEdit({ recipients: {} }, bad));
  }
});
