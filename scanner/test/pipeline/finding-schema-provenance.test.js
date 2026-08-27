// finding-schema.js: `findingProvenance` is a REQUIRED identity field (Task 14).
//
// The provenance record is not an enrichment that may or may not have run — the
// coordinator's hard guarantee is that every finding carries a terminal
// findingProvenance object, with the failure modes expressed as statuses
// (not_available / uncommitted / budget_exhausted / error) rather than as a
// missing field. Making it required in the schema is what makes a finding that
// escaped annotation observable instead of silently un-annotated.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFindingCompleteness, FINDING_FIELD_GROUPS } from '../../src/pipeline/finding-schema.js';

test('describeFindingCompleteness flags a finding missing findingProvenance as incomplete', () => {
  const result = describeFindingCompleteness({ id: 'f1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'high' });
  assert.equal(result.isComplete, false);
  assert.ok(result.missingRequiredFields.includes('findingProvenance'));
});

test('describeFindingCompleteness accepts a finding with findingProvenance present', () => {
  const result = describeFindingCompleteness({
    id: 'f1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'high',
    findingProvenance: { status: 'not_available' },
  });
  assert.ok(!result.missingRequiredFields.includes('findingProvenance'));
  assert.equal(result.isComplete, true);
});

test('findingProvenance is required, not optional — a null value does not satisfy it', () => {
  assert.ok(FINDING_FIELD_GROUPS.identity.required.includes('findingProvenance'));
  assert.ok(!FINDING_FIELD_GROUPS.identity.optional.includes('findingProvenance'));
  const result = describeFindingCompleteness({
    id: 'f1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'high',
    findingProvenance: null,
  });
  assert.ok(result.missingRequiredFields.includes('findingProvenance'));
});
