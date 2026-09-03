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

test('proposeGovernanceEdit: an explicit null patch value removes a recipient, reflected in the diff and in merged', () => {
  // Merge-patch semantics (fix round 1): an OMITTED key is left
  // untouched, not deleted — `null` is the only way to delete. See the
  // "a patch naming only a NEW key ... leaves the untouched key
  // present" test below for the omission case this test used to (wrongly)
  // exercise as a deletion.
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { recipients: { vendor1: null } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, ['vendor1']);
  assert.deepEqual(diff.added, []);
  assert.ok(!('vendor1' in merged.recipients));
});

test('proposeGovernanceEdit (merge-patch semantics): a patch naming only a NEW key leaves an existing, unmentioned key untouched in merged, and out of diff.removed', () => {
  const current = { recipients: { 'vendor0-preexisting': _validEntry() } };
  const patch = { recipients: { 'vendor1-new': _validEntry({ provider: 'New Vendor' }) } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.added, ['vendor1-new']);
  assert.deepEqual(merged.recipients['vendor0-preexisting'], current.recipients['vendor0-preexisting']);
  assert.ok('vendor1-new' in merged.recipients);
});

test('proposeGovernanceEdit (merge-patch semantics): a patch explicitly setting an existing key to null deletes it', () => {
  const current = { recipients: { vendor1: _validEntry(), vendor2: _validEntry({ provider: 'Other' }) } };
  const patch = { recipients: { vendor1: null } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, ['vendor1']);
  assert.ok(!('vendor1' in merged.recipients));
  // The untouched sibling survives.
  assert.deepEqual(merged.recipients.vendor2, current.recipients.vendor2);
});

test('proposeGovernanceEdit (merge-patch semantics): a patch setting a NONEXISTENT key to null is a no-op', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { recipients: { 'never-existed': null } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(merged.recipients, current.recipients);
});

test('proposeGovernanceEdit (merge-patch semantics): a patch entry that fully replaces an existing key still reports it as changed', () => {
  const current = { recipients: { vendor1: _validEntry({ dpaStatus: 'not_in_place' }) } };
  const patch = { recipients: { vendor1: _validEntry({ dpaStatus: 'in_place' }) } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].key, 'vendor1');
  assert.equal(merged.recipients.vendor1.dpaStatus, 'in_place');
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

// --- Final review fix round 1: B1 (real merge base) + I2/I3 (real
// container-shape validation) -------------------------------------------

test('proposeGovernanceEdit (B1): a current-config entry that fails isValidRecipientConfigEntry survives UNCHANGED in merged when the patch touches an unrelated key', () => {
  // Reuses the invalid-processorRole shape from the malformed-entry test
  // above — this simulates what loadRecipientConfig would have silently
  // dropped, but proposeGovernanceEdit now receives the RAW current
  // config (parsed directly from disk by the CLI, never sanitized), so
  // the invalid entry must survive byte-identical.
  const invalidLegacyEntry = { provider: 'x', dpaStatus: 'not_a_real_status' };
  const current = { recipients: { 'legacy-vendor': invalidLegacyEntry, 'good-vendor': _validEntry() } };
  const patch = { recipients: { 'new-vendor': _validEntry({ provider: 'New Vendor' }) } };
  const { valid, diff, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(merged.recipients['legacy-vendor'], invalidLegacyEntry, 'the invalid legacy entry must survive exactly, not be dropped');
  assert.deepEqual(merged.recipients['good-vendor'], current.recipients['good-vendor']);
  assert.ok(merged.recipients['new-vendor']);
});

test('proposeGovernanceEdit (B1): an extra top-level key on the current config (e.g. version) survives into merged after a patch touching only recipients', () => {
  const current = { recipients: { vendor1: _validEntry() }, version: 3, $schema: 'https://example.com/schema.json' };
  const patch = { recipients: { vendor2: _validEntry({ provider: 'Other' }) } };
  const { valid, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, true);
  assert.equal(merged.version, 3);
  assert.equal(merged.$schema, 'https://example.com/schema.json');
  assert.ok(merged.recipients.vendor1);
  assert.ok(merged.recipients.vendor2);
});

test('proposeGovernanceEdit (B1): a current config with the wrong top-level key (typo, e.g. "Recipients") is invalid — never a silent empty-object treatment', () => {
  const current = { Recipients: { vendor1: _validEntry() } }; // capital R — .recipients is undefined
  const patch = { recipients: { vendor2: _validEntry() } };
  const { valid, errors, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => /recipients/i.test(e.message)));
  assert.equal(merged, null, 'there is no safe merge base when the current config shape is unrecognized');
});

test('proposeGovernanceEdit (I2): a patch missing the recipients wrapper entirely is invalid, never a silent empty-diff success', () => {
  const current = { recipients: { vendor1: _validEntry() } };
  const patch = { vendor2: _validEntry() }; // forgot the "recipients" wrapper
  const { valid, errors, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.key === '(top-level)'));
  assert.equal(merged, null);
});

test('proposeGovernanceEdit (I3): a patch with recipients as an array is invalid, never index-keyed recipients', () => {
  const current = { recipients: {} };
  const patch = { recipients: [{ legalEntity: 'ArrayVendor' }] };
  const { valid, errors, merged } = proposeGovernanceEdit(current, patch);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => /array/i.test(e.message)));
  assert.equal(merged, null);
});

test('proposeGovernanceEdit (I3/M1): a patch containing a "" or "__proto__" recipient key is invalid', () => {
  const current = { recipients: {} };
  const emptyKeyPatch = { recipients: { '': _validEntry() } };
  const r1 = proposeGovernanceEdit(current, emptyKeyPatch);
  assert.equal(r1.valid, false);
  assert.ok(r1.errors.some((e) => e.key === ''));
  // Object-literal syntax (`{ __proto__: x }`) sets the PROTOTYPE, not an
  // own enumerable property — JSON.parse does not have that footgun (it
  // uses CreateDataProperty internally), and it's how the real CLI reads
  // a --patch file, so this reproduces a genuine `__proto__`-keyed patch.
  const protoKeyPatch = JSON.parse('{"recipients":{"__proto__":' + JSON.stringify(_validEntry()) + '}}');
  assert.ok(Object.prototype.hasOwnProperty.call(protoKeyPatch.recipients, '__proto__'), 'sanity: this must be a real own property, not the actual prototype link');
  const r2 = proposeGovernanceEdit(current, protoKeyPatch);
  assert.equal(r2.valid, false);
  assert.ok(r2.errors.some((e) => e.key === '__proto__'));
});
