import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  OBLIGATION_STATES,
  OBLIGATION_FACT_TYPES,
  APPLICABILITY_INPUT_KEYS,
  validateObligationMapping,
} from '../../src/lineage/obligation-mapping.js';

// =====================================================================
// Import boundary — mirrors flow-grade.test.js's own boundary test
// exactly (§16.1's precedent, cited by this sub-project's own scoping
// doc as the pattern to follow).
// =====================================================================

// =====================================================================
// Enum values pinned against HARDCODED LITERALS, not the module's own
// exports — found by this sub-project's own final whole-branch review:
// every other test in this file iterates `OBLIGATION_STATES`/
// `OBLIGATION_FACT_TYPES`/`APPLICABILITY_INPUT_KEYS` directly, which only
// proves the validator is self-consistent, never that the values match
// the PRD (a mutation test confirmed live — misspelling two enum values
// left all 25 pre-existing tests green). These three are the module's
// entire external contract (the string vocabulary a future predicate
// engine matches against), copied verbatim from
// AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md lines 503-508 (states),
// 976-985 (fact types), and 512 (applicability inputs) — the same
// "hardcoded golden literal, never the shipped implementation" discipline
// this package's own driver.test.js already established for exactly this
// failure mode (E1/driver-1's own comment).
// =====================================================================

test('OBLIGATION_STATES matches the PRD literal exactly (guards against a silent spelling drift the self-referential tests below cannot catch)', () => {
  assert.deepEqual(OBLIGATION_STATES, [
    'evidence_supported', 'gap_detected', 'unknown',
    'manual_required', 'not_applicable', 'accepted_exception',
  ]);
});

test('OBLIGATION_FACT_TYPES matches the PRD literal exactly', () => {
  assert.deepEqual(OBLIGATION_FACT_TYPES, [
    'code_inferred', 'config_correlated', 'runtime_observed',
    'declared', 'manual', 'hypothetical',
  ]);
});

test('APPLICABILITY_INPUT_KEYS matches the PRD literal exactly', () => {
  assert.deepEqual(APPLICABILITY_INPUT_KEYS, [
    'entityRole', 'jurisdiction', 'dataSubject', 'businessProcess',
    'merchantLevel', 'systemScope', 'aiSystemRole',
  ]);
});

test('boundary: obligation-mapping.js imports NOTHING — its specifier list is EXACTLY []', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/obligation-mapping.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'obligation-mapping.js must import nothing — a pure schema/validation module');
});

// =====================================================================
// Fixture helper — a minimal, fully valid record. Every test below
// starts from a deep-enough clone of this and mutates one field.
// =====================================================================

function _validRecord(overrides = {}) {
  return {
    id: 'obligation:abcdef012345',
    graphId: 'dfg:test-repo:abc123:default',
    graphDigest: 'a'.repeat(64),
    framework: 'gdpr',
    frameworkVersion: '2016/679',
    requirementId: 'Art.30',
    requirementSource: 'https://gdpr-info.eu/art-30-gdpr/',
    applicabilityInputs: {
      entityRole: null,
      jurisdiction: null,
      dataSubject: null,
      businessProcess: null,
      merchantLevel: null,
      systemScope: null,
      aiSystemRole: null,
    },
    state: 'unknown',
    predicate: 'flow.policyVerdict === "permitted" for all cross-border transfer flows',
    factType: 'declared',
    contributingGraphIds: ['flow:1234567890ab'],
    evidence: [],
    conflicts: [],
    missingManualArtifacts: [],
    reviewer: null,
    reviewedAt: null,
    expiresAt: null,
    ...overrides,
  };
}

test('a fully valid record passes with zero errors', () => {
  const { valid, errors } = validateObligationMapping(_validRecord());
  assert.equal(valid, true);
  assert.deepEqual(errors, []);
});

test('all applicabilityInputs null is VALID — "not configured" is an honest, allowed answer (FR-504\'s own rule)', () => {
  const { valid } = validateObligationMapping(_validRecord());
  assert.equal(valid, true);
});

test('non-object input is rejected, never throws', () => {
  for (const bad of [null, undefined, 'x', 42, [], () => {}]) {
    assert.doesNotThrow(() => validateObligationMapping(bad));
    const { valid, errors } = validateObligationMapping(bad);
    assert.equal(valid, false);
    assert.ok(errors.length >= 1);
  }
});

for (const field of ['id', 'graphId', 'graphDigest', 'framework', 'frameworkVersion', 'requirementId', 'predicate']) {
  test(`missing required string field "${field}" is rejected`, () => {
    const record = _validRecord({ [field]: undefined });
    const { valid, errors } = validateObligationMapping(record);
    assert.equal(valid, false);
    assert.ok(errors.some((e) => e.path === `$.${field}`), `expected an error at $.${field}, got: ${JSON.stringify(errors)}`);
  });
}

test('an id not prefixed "obligation:" is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ id: 'node:abcdef012345' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.id'));
});

test('an unrecognized state is rejected, and every real OBLIGATION_STATES member is accepted', () => {
  const { valid: badValid } = validateObligationMapping(_validRecord({ state: 'definitely_compliant' }));
  assert.equal(badValid, false);
  for (const state of OBLIGATION_STATES) {
    const { valid, errors } = validateObligationMapping(_validRecord({
      state,
      // accepted_exception has its own extra requirement, satisfy it here
      reviewer: state === 'accepted_exception' ? 'jdoe' : null,
      expiresAt: state === 'accepted_exception' ? '2027-01-01T00:00:00.000Z' : null,
    }));
    assert.equal(valid, true, `state "${state}" should be valid, got errors: ${JSON.stringify(errors)}`);
  }
});

test('an unrecognized factType is rejected, and every real OBLIGATION_FACT_TYPES member is accepted', () => {
  const { valid: badValid } = validateObligationMapping(_validRecord({ factType: 'vibes' }));
  assert.equal(badValid, false);
  for (const factType of OBLIGATION_FACT_TYPES) {
    const { valid } = validateObligationMapping(_validRecord({ factType }));
    assert.equal(valid, true, `factType "${factType}" should be valid`);
  }
});

test('applicabilityInputs missing entirely is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ applicabilityInputs: undefined }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.applicabilityInputs'));
});

test('applicabilityInputs as an array (not an object) is rejected', () => {
  const { valid } = validateObligationMapping(_validRecord({ applicabilityInputs: [] }));
  assert.equal(valid, false);
});

test('every real APPLICABILITY_INPUT_KEYS member accepts a non-null string too', () => {
  for (const key of APPLICABILITY_INPUT_KEYS) {
    const record = _validRecord();
    record.applicabilityInputs[key] = 'controller';
    const { valid, errors } = validateObligationMapping(record);
    assert.equal(valid, true, `key "${key}" set to a string should be valid, got: ${JSON.stringify(errors)}`);
  }
});

test('an applicabilityInputs key set to a non-string, non-null value is rejected', () => {
  const record = _validRecord();
  record.applicabilityInputs.jurisdiction = 42;
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.applicabilityInputs.jurisdiction'));
});

test('contributingGraphIds/evidence/conflicts/missingManualArtifacts default to valid when omitted', () => {
  const record = _validRecord({
    contributingGraphIds: undefined,
    evidence: undefined,
    conflicts: undefined,
    missingManualArtifacts: undefined,
  });
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, true, `expected omitted arrays to default cleanly, got: ${JSON.stringify(errors)}`);
});

test('contributingGraphIds containing a non-string entry is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ contributingGraphIds: ['flow:abc', 42] }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.contributingGraphIds'));
});

test('accepted_exception without a reviewer is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: null, expiresAt: '2027-01-01T00:00:00.000Z',
  }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.reviewer'));
});

test('accepted_exception without an expiresAt is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: 'jdoe', expiresAt: null,
  }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.expiresAt'));
});

test('accepted_exception with both a reviewer and an expiresAt is valid', () => {
  const { valid } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: 'jdoe', expiresAt: '2027-01-01T00:00:00.000Z',
  }));
  assert.equal(valid, true);
});

test('a non-accepted_exception state does NOT require reviewer/expiresAt', () => {
  const { valid } = validateObligationMapping(_validRecord({
    state: 'gap_detected', reviewer: null, expiresAt: null,
  }));
  assert.equal(valid, true);
});

test('multiple simultaneous errors are all reported, not just the first', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    id: undefined, state: 'bogus', factType: 'bogus',
  }));
  assert.equal(valid, false);
  assert.ok(errors.length >= 3);
});
