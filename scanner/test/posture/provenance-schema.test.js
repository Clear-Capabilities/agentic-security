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

// Fix-round item 3: pseudonymization must reach providerEnrichment
// (FR-PROV-022's reviewer logins + raw CODEOWNERS lines), not just
// findingOrigin -- before this fix, --pseudonymize-authors hid the commit
// author's name while providerEnrichment.reviewers/codeowners still named
// real people in plain text in the same redacted output.
test('redactFindingProvenance: pseudonymize:true scrubs providerEnrichment.reviewers and codeowners too, leaving neither real names nor emails', () => {
  const fp = {
    findingOrigin: { authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', commit: 'abc' },
    providerEnrichment: {
      provider: 'github',
      prNumber: 7,
      reviewers: ['alice', 'bob-reviewer'],
      approvals: 2,
      mergedAt: '2026-01-02T00:00:00Z',
      codeowners: [
        '* @alice @bob-reviewer',
        '/src/ carol@example.com',
        '/infra/ @dave dave@example.com',
      ],
    },
  };

  const redacted = redactFindingProvenance(fp, { pseudonymize: true });

  // findingOrigin still redacted as before.
  assert.match(redacted.findingOrigin.authorName, /^Contributor-[0-9a-f]{8}$/);

  // reviewers: every login replaced with a stable pseudonym, none of the
  // real logins survive.
  assert.equal(redacted.providerEnrichment.reviewers.length, 2);
  for (const r of redacted.providerEnrichment.reviewers) {
    assert.match(r, /^Contributor-[0-9a-f]{8}$/);
  }
  assert.notEqual(redacted.providerEnrichment.reviewers[0], 'alice');
  assert.notEqual(redacted.providerEnrichment.reviewers[1], 'bob-reviewer');
  // Stable identity: the same login always yields the same pseudonym.
  assert.equal(redacted.providerEnrichment.reviewers[0], pseudonymizeAuthor('alice', null));

  // codeowners: no real handle or email substring survives anywhere.
  const codeownersText = redacted.providerEnrichment.codeowners.join('\n');
  for (const needle of ['alice', 'bob-reviewer', 'carol@example.com', 'dave@example.com', '@dave']) {
    assert.ok(!codeownersText.includes(needle), `expected "${needle}" to be scrubbed from codeowners, got: ${codeownersText}`);
  }
  // Every line still has SOME pseudonymized structure (not blanket-wiped),
  // proving this is per-identifier redaction, not a destructive blanket one.
  for (const line of redacted.providerEnrichment.codeowners) {
    assert.match(line, /Contributor-[0-9a-f]{8}/);
  }

  // Non-identity fields on providerEnrichment must survive untouched.
  assert.equal(redacted.providerEnrichment.provider, 'github');
  assert.equal(redacted.providerEnrichment.prNumber, 7);
  assert.equal(redacted.providerEnrichment.approvals, 2);
  assert.equal(redacted.providerEnrichment.mergedAt, '2026-01-02T00:00:00Z');
});

test('redactFindingProvenance: pseudonymize:false leaves providerEnrichment logins visible but still withholds embedded emails by default', () => {
  const fp = {
    findingOrigin: { authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', commit: 'abc' },
    providerEnrichment: {
      provider: 'github', prNumber: 1, reviewers: ['alice'], approvals: null, mergedAt: null,
      codeowners: ['/src/ @alice carol@example.com'],
    },
  };
  const redacted = redactFindingProvenance(fp, {});
  assert.deepEqual(redacted.providerEnrichment.reviewers, ['alice']);
  assert.ok(!redacted.providerEnrichment.codeowners[0].includes('carol@example.com'));
  assert.ok(redacted.providerEnrichment.codeowners[0].includes('@alice'), 'a bare handle is not redacted by default, same precedent as authorName');
});

test('redactFindingProvenance: providerEnrichment:null passes through as null', () => {
  const fp = { findingOrigin: { authorName: 'Jamie Chen', authorEmail: null, commit: 'abc' }, providerEnrichment: null };
  const redacted = redactFindingProvenance(fp, { pseudonymize: true });
  assert.equal(redacted.providerEnrichment, null);
});
