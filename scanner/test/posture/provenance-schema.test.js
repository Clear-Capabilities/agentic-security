import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyProvenance, redactFindingProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';
import { validateFindingProvenance } from '../../src/posture/provenance/validate.js';

test('emptyProvenance produces a terminal, schema-valid object', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a git repo'] });
  assert.equal(fp.status, 'not_available');
  assert.deepEqual(fp.limitations, ['not a git repo']);
  assert.equal(fp.schemaVersion, '1.0');
  const result = validateFindingProvenance({ findingProvenance: fp });
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

test('validateFindingProvenance rejects a missing findingProvenance object', () => {
  const result = validateFindingProvenance({ id: 'f1' });
  assert.equal(result.valid, false);
  assert.match(result.errors[0], /missing findingProvenance/);
});

test('redactFindingProvenance hides author email by default', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc123', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const redacted = redactFindingProvenance(fp);
  assert.equal(redacted.findingOrigin.authorEmail, null);
  assert.equal(redacted.findingOrigin.authorName, 'Jamie Chen');
  const shown = redactFindingProvenance(fp, { includeEmail: true });
  assert.equal(shown.findingOrigin.authorEmail, 'jamie@example.com');
});
