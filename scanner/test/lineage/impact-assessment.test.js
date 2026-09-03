import { test } from 'node:test';
import assert from 'node:assert/strict';
import { impactAssessmentId } from '../../src/lineage/ids.js';
import {
  IMPACT_TARGET_KINDS,
  IMPACT_SCOPE_VALUES,
  validateImpactAssessment,
} from '../../src/lineage/impact-assessment.js';

test('impactAssessmentId is deterministic and differs on any input change', () => {
  const base = { graphId: 'graph:abc', graphDigest: 'sha256:aaa', targetId: 'node:sink' };
  const a = impactAssessmentId(base);
  const b = impactAssessmentId(base);
  assert.equal(a, b);
  assert.notEqual(a, impactAssessmentId({ ...base, targetId: 'node:other' }));
  assert.match(a, /^impact:[0-9a-f]+$/);
});

test('IMPACT_TARGET_KINDS is exactly the 4 in-scope kinds, no finding kind', () => {
  assert.deepEqual(IMPACT_TARGET_KINDS, ['node', 'edge', 'flow', 'dataElement']);
});

test('validateImpactAssessment: a well-formed record is valid', () => {
  const record = {
    id: impactAssessmentId({ graphId: 'graph:abc', graphDigest: 'sha256:aaa', targetId: 'node:sink' }),
    version: '1.0.0',
    graphId: 'graph:abc', graphDigest: 'sha256:aaa',
    targetId: 'node:sink', targetKind: 'node',
    scope: 'possible',
    affectedNodeIds: ['node:sink'], affectedEdgeIds: [],
    affectedDataClasses: ['PII'],
    affectedRecipientProfileIds: [],
    coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateImpactAssessment: never throws on garbage input, reports errors instead', () => {
  for (const bad of [null, undefined, 42, [], {}, { id: 'not-impact:x' }]) {
    assert.doesNotThrow(() => validateImpactAssessment(bad));
    const { valid, errors } = validateImpactAssessment(bad);
    assert.equal(valid, false);
    assert.ok(errors.length > 0);
  }
});

test('validateImpactAssessment: rejects an unrecognized targetKind', () => {
  const record = {
    id: 'impact:x', version: '1.0.0', graphId: 'g', graphDigest: 'd',
    targetId: 'finding:123', targetKind: 'finding', scope: 'possible',
    affectedNodeIds: [], affectedEdgeIds: [], affectedDataClasses: [],
    affectedRecipientProfileIds: [], coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.targetKind'));
});

test('validateImpactAssessment: rejects a scope other than possible/observed', () => {
  const record = {
    id: 'impact:x', version: '1.0.0', graphId: 'g', graphDigest: 'd',
    targetId: 'node:x', targetKind: 'node', scope: 'definitely',
    affectedNodeIds: [], affectedEdgeIds: [], affectedDataClasses: [],
    affectedRecipientProfileIds: [], coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.scope'));
});
