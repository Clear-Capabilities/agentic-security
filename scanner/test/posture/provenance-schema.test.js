import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyProvenance, redactFindingProvenance, pseudonymizeAuthor, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';
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

test('pseudonymizeAuthor: same email always produces the same pseudonym', () => {
  const p1 = pseudonymizeAuthor('Jamie Chen', 'jamie@example.com');
  const p2 = pseudonymizeAuthor('J. Chen', 'jamie@example.com'); // different display name, same email
  assert.equal(p1, p2, 'stable identity must survive a display-name change for the same email');
});

test('pseudonymizeAuthor: different authors produce different pseudonyms', () => {
  const p1 = pseudonymizeAuthor('Alice', 'alice@example.com');
  const p2 = pseudonymizeAuthor('Bob', 'bob@example.com');
  assert.notEqual(p1, p2);
});

test('pseudonymizeAuthor: never reveals the real name or email in its output', () => {
  const p = pseudonymizeAuthor('Jamie Chen', 'jamie@example.com');
  assert.ok(!p.includes('Jamie'), 'pseudonym must not leak the real name');
  assert.ok(!p.includes('jamie@'), 'pseudonym must not leak the real email');
});

test('redactFindingProvenance: pseudonymize:true replaces authorName, pseudonymize:false leaves it untouched (backward compatible default)', () => {
  const fp = { findingOrigin: { authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', commit: 'abc' } };
  const withoutFlag = redactFindingProvenance(fp, {});
  assert.equal(withoutFlag.findingOrigin.authorName, 'Jamie Chen');
  const withFlag = redactFindingProvenance(fp, { pseudonymize: true });
  assert.match(withFlag.findingOrigin.authorName, /^Contributor-[0-9a-f]{8}$/);
});

test('redactFindingProvenance: pseudonymize keys on the real authorEmail even when includeEmail is false', () => {
  // Order-of-operations guard: pseudonymization must use the PRE-redaction
  // authorEmail, not the already-nulled one, or every pseudonym degrades to
  // name-only stability (a weaker guarantee than intended).
  const fp = { findingOrigin: { authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', commit: 'abc' } };
  const viaEmailKey = pseudonymizeAuthor('Jamie Chen', 'jamie@example.com');
  const redacted = redactFindingProvenance(fp, { includeEmail: false, pseudonymize: true });
  assert.equal(redacted.findingOrigin.authorEmail, null);
  assert.equal(redacted.findingOrigin.authorName, viaEmailKey);
});
