import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROTECTION_VERDICTS, EVIDENCE_GRADES, PROTECTION_DIMENSIONS,
  emptyProtection, aggregateVerdicts, isValidProtectionDimension,
} from '../../src/lineage/protection.js';

test('enums match PRD section 14.1', () => {
  assert.deepEqual([...PROTECTION_VERDICTS].sort(), ['not_applicable', 'not_assessed', 'protected', 'unknown', 'unprotected'].sort());
  assert.deepEqual([...EVIDENCE_GRADES].sort(), ['code', 'code_and_config', 'config', 'declared', 'manual', 'none', 'runtime'].sort());
  assert.deepEqual([...PROTECTION_DIMENSIONS], ['transit', 'atRest', 'handling']);
});

test('emptyProtection defaults every dimension to not_assessed / none', () => {
  const p = emptyProtection();
  for (const dim of PROTECTION_DIMENSIONS) {
    assert.equal(p[dim].verdict, 'not_assessed');
    assert.equal(p[dim].evidenceGrade, 'none');
  }
});

test('isValidProtectionDimension accepts a well-formed dimension and rejects a bad one', () => {
  assert.equal(isValidProtectionDimension({ verdict: 'protected', evidenceGrade: 'code' }), true);
  assert.equal(isValidProtectionDimension({ verdict: 'super-safe', evidenceGrade: 'code' }), false);
  assert.equal(isValidProtectionDimension({ verdict: 'protected', evidenceGrade: 'trust-me' }), false);
  assert.equal(isValidProtectionDimension(null), false);
});

// PRD section 8.4 risk precedence: unprotected/prohibited -> mixed ->
// unknown/manual_required -> protected/permitted -> not_assessed.
test('aggregateVerdicts: any unprotected wins over everything else', () => {
  assert.equal(aggregateVerdicts(['protected', 'unprotected', 'unknown']), 'unprotected');
});

test('aggregateVerdicts: mixed only applies when this module is told to treat a set as branches (see AC-12)', () => {
  // A caller that already knows it has multiple DISTINCT branches passes
  // 'mixed' in directly as one of the verdicts being aggregated (e.g. an
  // upstream aggregation step already computed "protected on branch A,
  // unprotected on branch B" -> 'mixed'). This function's own precedence
  // table must still rank 'mixed' correctly among the rest.
  assert.equal(aggregateVerdicts(['protected', 'mixed']), 'mixed');
  assert.equal(aggregateVerdicts(['mixed', 'unknown']), 'mixed');
});

test('aggregateVerdicts: unknown beats protected', () => {
  assert.equal(aggregateVerdicts(['protected', 'unknown']), 'unknown');
});

test('aggregateVerdicts: all protected stays protected', () => {
  assert.equal(aggregateVerdicts(['protected', 'protected']), 'protected');
});

test('aggregateVerdicts: not_assessed only when nothing stronger present', () => {
  assert.equal(aggregateVerdicts(['not_assessed', 'not_assessed']), 'not_assessed');
  assert.equal(aggregateVerdicts(['not_assessed', 'protected']), 'protected');
});

test('aggregateVerdicts on empty input is not_assessed, never a guess', () => {
  assert.equal(aggregateVerdicts([]), 'not_assessed');
});

test('aggregateVerdicts throws on an unrecognized verdict rather than silently ranking it low', () => {
  assert.throws(() => aggregateVerdicts(['protected', 'super-safe']), /unrecognized verdict/);
});
