import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  RECIPIENT_PROCESSOR_ROLES,
  RECIPIENT_DPA_STATUSES,
  RECIPIENT_CONFIDENCE_LEVELS,
  RECIPIENT_FACT_FIELDS,
  validateRecipientProfile,
} from '../../src/lineage/recipient-profile.js';
import { OBLIGATION_FACT_TYPES } from '../../src/lineage/obligation-mapping.js';
import { recipientProfileId } from '../../src/lineage/ids.js';

// =====================================================================
// Enum values pinned against HARDCODED LITERALS, not the module's own
// exports — mirrors obligation-mapping.test.js's own "hardcoded golden
// literal, never the shipped implementation" discipline (that file's own
// comment explains why: a self-referential test only proves internal
// consistency, never that the values match the task brief).
// =====================================================================

test('RECIPIENT_PROCESSOR_ROLES matches the brief literal exactly', () => {
  assert.deepEqual(RECIPIENT_PROCESSOR_ROLES, ['processor', 'controller', 'joint_controller', 'unknown']);
});

test('RECIPIENT_DPA_STATUSES matches the brief literal exactly', () => {
  assert.deepEqual(RECIPIENT_DPA_STATUSES, ['in_place', 'not_in_place', 'unknown']);
});

test('RECIPIENT_CONFIDENCE_LEVELS matches the brief literal exactly', () => {
  assert.deepEqual(RECIPIENT_CONFIDENCE_LEVELS, ['high', 'medium', 'low']);
});

test('RECIPIENT_FACT_FIELDS matches the brief literal exactly, and excludes record-level metadata', () => {
  assert.deepEqual(RECIPIENT_FACT_FIELDS, [
    'technicalEndpoint', 'provider', 'serviceType', 'legalEntity',
    'processorRole', 'servicePurpose', 'subprocessorChain',
    'processingCountries', 'dataResidencyCommitment', 'observedRegion',
    'dpaStatus', 'transferMechanism', 'transferImpactReviewStatus',
    'retentionCommitment',
  ]);
  for (const meta of ['contributingGraphIds', 'confidence', 'owner', 'reviewDate', 'conflicts', 'expiration']) {
    assert.ok(!RECIPIENT_FACT_FIELDS.includes(meta), `"${meta}" is record-level metadata and must NOT be in RECIPIENT_FACT_FIELDS`);
  }
});

test('boundary: recipient-profile.js imports EXACTLY ["./obligation-mapping.js"] — a deliberate, disclosed single import', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/recipient-profile.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['./obligation-mapping.js']);
});

// =====================================================================
// Fixture helper — a minimal, fully valid record. Every test below
// starts from a deep-enough clone of this and mutates one field.
// =====================================================================

function _validRecord(overrides = {}) {
  return {
    id: 'recipient:abcdef012345',
    graphId: 'dfg:test-repo:abc123:default',
    graphDigest: 'a'.repeat(64),
    recipientKey: 'anthropic.com',
    technicalEndpoint: 'api.anthropic.com',
    provider: 'anthropic',
    serviceType: 'ai-model-provider',
    legalEntity: 'Anthropic PBC',
    processorRole: 'processor',
    servicePurpose: 'AI model inference',
    subprocessorChain: ['aws'],
    processingCountries: ['US'],
    dataResidencyCommitment: 'US-only',
    observedRegion: null,
    dpaStatus: 'in_place',
    transferMechanism: 'SCCs',
    transferImpactReviewStatus: 'completed',
    retentionCommitment: '30 days',
    contributingGraphIds: ['flow:1234567890ab'],
    fieldEvidence: {
      technicalEndpoint: { factType: 'code_inferred', source: 'catalog:anthropic' },
      provider: { factType: 'code_inferred', source: 'catalog:anthropic' },
      serviceType: { factType: 'code_inferred', source: 'catalog:anthropic' },
      legalEntity: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      processorRole: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      servicePurpose: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      subprocessorChain: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      processingCountries: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      dataResidencyCommitment: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      dpaStatus: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      transferMechanism: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      transferImpactReviewStatus: { factType: 'declared', source: '.agentic-security/recipients.yml' },
      retentionCommitment: { factType: 'declared', source: '.agentic-security/recipients.yml' },
    },
    confidence: 'high',
    owner: 'privacy-team',
    reviewDate: '2026-09-01',
    conflicts: [],
    expiration: null,
    ...overrides,
  };
}

test('a fully valid record passes with zero errors', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord());
  assert.equal(valid, true, `expected zero errors, got: ${JSON.stringify(errors)}`);
  assert.deepEqual(errors, []);
});

test('non-object input is rejected, never throws', () => {
  for (const bad of [null, undefined, 'x', 42, [], () => {}]) {
    assert.doesNotThrow(() => validateRecipientProfile(bad));
    const { valid, errors } = validateRecipientProfile(bad);
    assert.equal(valid, false);
    assert.ok(errors.length >= 1);
  }
});

for (const field of ['id', 'graphId', 'graphDigest', 'recipientKey']) {
  test(`missing required string field "${field}" is rejected`, () => {
    const record = _validRecord({ [field]: undefined });
    const { valid, errors } = validateRecipientProfile(record);
    assert.equal(valid, false);
    assert.ok(errors.some((e) => e.path === `$.${field}`), `expected an error at $.${field}, got: ${JSON.stringify(errors)}`);
  });
}

test('an id not prefixed "recipient:" is rejected', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord({ id: 'obligation:abcdef012345' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.id'));
});

// =====================================================================
// The load-bearing structural rule: fieldEvidence completeness.
// =====================================================================

test('a record missing fieldEvidence for a populated field fails with a clear path naming the field', () => {
  const record = _validRecord();
  delete record.fieldEvidence.legalEntity;
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence.legalEntity'), `expected an error at $.fieldEvidence.legalEntity, got: ${JSON.stringify(errors)}`);
});

test('every populated RECIPIENT_FACT_FIELDS member individually requires its own fieldEvidence entry', () => {
  for (const field of RECIPIENT_FACT_FIELDS) {
    const record = _validRecord();
    if (record[field] === null || (Array.isArray(record[field]) && record[field].length === 0)) continue; // not populated in the base fixture
    delete record.fieldEvidence[field];
    const { valid, errors } = validateRecipientProfile(record);
    assert.equal(valid, false, `expected removing fieldEvidence.${field} to fail validation`);
    assert.ok(errors.some((e) => e.path === `$.fieldEvidence.${field}`), `expected an error at $.fieldEvidence.${field}, got: ${JSON.stringify(errors)}`);
  }
});

test('a null/empty field needs NO fieldEvidence entry', () => {
  const record = _validRecord({
    observedRegion: null,
    dataResidencyCommitment: null,
    fieldEvidence: { ...(_validRecord().fieldEvidence) },
  });
  delete record.fieldEvidence.dataResidencyCommitment;
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, true, `expected null fields to need no evidence, got: ${JSON.stringify(errors)}`);
});

test('a record with an orphaned fieldEvidence key (no matching field) fails', () => {
  const record = _validRecord();
  record.fieldEvidence.notARealField = { factType: 'declared', source: null };
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence.notARealField'), `expected an error at $.fieldEvidence.notARealField, got: ${JSON.stringify(errors)}`);
});

test('a record with a typo\'d fieldEvidence key fails', () => {
  const record = _validRecord();
  record.fieldEvidence.legalEntiy = record.fieldEvidence.legalEntity; // typo, real key still present
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence.legalEntiy'));
});

test('fieldEvidence missing entirely is rejected', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord({ fieldEvidence: undefined }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence'));
});

test('fieldEvidence as an array (not an object) is rejected', () => {
  const { valid } = validateRecipientProfile(_validRecord({ fieldEvidence: [] }));
  assert.equal(valid, false);
});

test('a fieldEvidence entry with an unrecognized factType is rejected', () => {
  const record = _validRecord();
  record.fieldEvidence.provider = { factType: 'vibes', source: null };
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence.provider.factType'));
});

test('every real OBLIGATION_FACT_TYPES member is accepted as a fieldEvidence factType', () => {
  for (const factType of OBLIGATION_FACT_TYPES) {
    const record = _validRecord();
    record.fieldEvidence.provider = { factType, source: null };
    const { valid, errors } = validateRecipientProfile(record);
    assert.equal(valid, true, `factType "${factType}" should be valid, got: ${JSON.stringify(errors)}`);
  }
});

test('a fieldEvidence entry with a non-string, non-null source is rejected', () => {
  const record = _validRecord();
  record.fieldEvidence.provider = { factType: 'code_inferred', source: 42 };
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.fieldEvidence.provider.source'));
});

// =====================================================================
// Enum fields.
// =====================================================================

test('an unrecognized processorRole is rejected, null is accepted, and every real member is accepted', () => {
  const { valid: badValid } = validateRecipientProfile(_validRecord({ processorRole: 'vendor' }));
  assert.equal(badValid, false);
  const { valid: nullValid, errors: nullErrors } = validateRecipientProfile(_validRecord({ processorRole: null, fieldEvidence: (() => { const fe = { ..._validRecord().fieldEvidence }; delete fe.processorRole; return fe; })() }));
  assert.equal(nullValid, true, `null processorRole should be valid, got: ${JSON.stringify(nullErrors)}`);
  for (const role of RECIPIENT_PROCESSOR_ROLES) {
    const { valid, errors } = validateRecipientProfile(_validRecord({ processorRole: role }));
    assert.equal(valid, true, `processorRole "${role}" should be valid, got: ${JSON.stringify(errors)}`);
  }
});

test('an unrecognized dpaStatus is rejected, and every real member is accepted', () => {
  const { valid: badValid } = validateRecipientProfile(_validRecord({ dpaStatus: 'pending' }));
  assert.equal(badValid, false);
  for (const status of RECIPIENT_DPA_STATUSES) {
    const { valid, errors } = validateRecipientProfile(_validRecord({ dpaStatus: status }));
    assert.equal(valid, true, `dpaStatus "${status}" should be valid, got: ${JSON.stringify(errors)}`);
  }
});

test('an unrecognized confidence is rejected, and every real member is accepted', () => {
  const { valid: badValid } = validateRecipientProfile(_validRecord({ confidence: 'certain' }));
  assert.equal(badValid, false);
  for (const level of RECIPIENT_CONFIDENCE_LEVELS) {
    const { valid, errors } = validateRecipientProfile(_validRecord({ confidence: level }));
    assert.equal(valid, true, `confidence "${level}" should be valid, got: ${JSON.stringify(errors)}`);
  }
});

// =====================================================================
// processingCountries.
// =====================================================================

test('processingCountries rejects a malformed entry (lowercase, wrong length, non-string)', () => {
  for (const bad of ['usa', 'U', 123]) {
    const { valid, errors } = validateRecipientProfile(_validRecord({ processingCountries: [bad] }));
    assert.equal(valid, false, `expected "${bad}" to be rejected`);
    assert.ok(errors.some((e) => e.path.startsWith('$.processingCountries')), `expected a processingCountries error for "${bad}", got: ${JSON.stringify(errors)}`);
  }
});

test('processingCountries accepts a well-formed uppercase 2-letter code', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord({ processingCountries: ['US', 'DE', 'JP'] }));
  assert.equal(valid, true, `expected valid country codes to pass, got: ${JSON.stringify(errors)}`);
});

// =====================================================================
// Array fields default to [] when omitted.
// =====================================================================

test('subprocessorChain/contributingGraphIds/conflicts default to [] when omitted, without error', () => {
  const record = _validRecord({
    subprocessorChain: undefined,
    contributingGraphIds: undefined,
    conflicts: undefined,
    fieldEvidence: (() => { const fe = { ..._validRecord().fieldEvidence }; delete fe.subprocessorChain; return fe; })(),
  });
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, true, `expected omitted arrays to default cleanly, got: ${JSON.stringify(errors)}`);
});

test('processingCountries defaults to [] when omitted, without error', () => {
  const record = _validRecord({
    processingCountries: undefined,
    fieldEvidence: (() => { const fe = { ..._validRecord().fieldEvidence }; delete fe.processingCountries; return fe; })(),
  });
  const { valid, errors } = validateRecipientProfile(record);
  assert.equal(valid, true, `expected omitted processingCountries to default cleanly, got: ${JSON.stringify(errors)}`);
});

test('a non-array value for an array field is rejected', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord({ subprocessorChain: 'aws' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.subprocessorChain'));
});

test('multiple simultaneous errors are all reported, not just the first', () => {
  const { valid, errors } = validateRecipientProfile(_validRecord({
    id: undefined, processorRole: 'bogus', dpaStatus: 'bogus',
  }));
  assert.equal(valid, false);
  assert.ok(errors.length >= 3);
});

// =====================================================================
// recipientProfileId — mirrors ids.test.js's own obligationId discriminator
// tests exactly.
// =====================================================================

test('recipientProfileId is deterministic, correctly prefixed, and discriminates on every input field', () => {
  const base = { graphId: 'dfg:repo:abc:default', graphDigest: 'aaaaaaaa', recipientKey: 'anthropic.com' };
  const id = recipientProfileId(base);
  assert.match(id, /^recipient:[0-9a-f]{12}$/);
  assert.equal(recipientProfileId(base), id, 'same inputs must produce the same id');

  assert.notEqual(recipientProfileId({ ...base, recipientKey: 'stripe.com' }), id, 'a different recipientKey must produce a different id');
  assert.notEqual(recipientProfileId({ ...base, graphDigest: 'bbbbbbbb' }), id, 'a different graphDigest (same graphId) must produce a different id');
  assert.notEqual(recipientProfileId({ ...base, graphId: 'dfg:repo:def:default' }), id, 'a different graphId must produce a different id');
});

test('recipientProfileId honors an extra discriminator', () => {
  const base = { graphId: 'dfg:repo:abc:default', graphDigest: 'aaaaaaaa', recipientKey: 'anthropic.com' };
  assert.notEqual(recipientProfileId(base, ['re-eval-2']), recipientProfileId(base, ['re-eval-1']));
});
