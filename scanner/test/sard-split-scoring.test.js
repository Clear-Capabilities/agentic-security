// SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem remediation, Round 1
// F1 — bench/sard/splits/*.json was computed, self-verified (split.mjs's own
// `--verify` duplicate-crossing audit), and committed, but NEVER consumed by
// the scoring pipeline: every macro-F1 number this project produced was
// measured over the FULL corpus (train+dev+test mixed), making PRD §14/§68's
// "test split is not used for ordinary tuning" acceptance criterion
// unenforceable in practice, not just undocumented.
//
// This file unit-tests the two exported functions bench-realworld.js now
// uses to apply that filter for real (`inRequestedSplit`, `loadSplitDoc`),
// reusing `familyKeyFor` from split.mjs directly — never a reimplementation,
// so this test can never validate a different family-key computation than
// the one that actually produced the on-disk split file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inRequestedSplit, loadSplitDoc } from './benchmark/realworld/bench-realworld.js';
import { familyKeyFor, bucketFor } from '../../bench/sard/scripts/split.mjs';

// A small, hand-built split doc — never the real committed one, so this
// test's assertions can't accidentally start passing only because of
// whatever the real corpus's hash buckets happen to look like today.
function fakeSplitDoc() {
  return {
    families: {
      'CWE89_SQL_Injection__Servlet_getParameter_executeQuery': 'train',
      'CWE79_XSS__Servlet_getParameter_Response_Write': 'dev',
      'CWE90_LDAP_Injection__Servlet_getParameter_search': 'test',
    },
  };
}

test('inRequestedSplit: a file whose family is assigned to the requested split is kept', () => {
  const doc = fakeSplitDoc();
  const rel = 'src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__Servlet_getParameter_search_01.cs';
  assert.equal(inRequestedSplit(rel, doc, 'test'), true);
  assert.equal(inRequestedSplit(rel, doc, 'train'), false);
  assert.equal(inRequestedSplit(rel, doc, 'dev'), false);
});

test('inRequestedSplit: paired multi-file variants (_NNa/_NNb) share one family and one split assignment', () => {
  const doc = fakeSplitDoc();
  const a = 'CWE79_XSS__Servlet_getParameter_Response_Write_54a.java';
  const b = 'CWE79_XSS__Servlet_getParameter_Response_Write_54b.java';
  // Both halves must resolve to the SAME family key (the whole reason
  // split.mjs strips `_NN[ab]`, not just `_NN`) and therefore the same split.
  assert.equal(familyKeyFor(a), familyKeyFor(b));
  assert.equal(inRequestedSplit(a, doc, 'dev'), true);
  assert.equal(inRequestedSplit(b, doc, 'dev'), true);
});

test('inRequestedSplit: a file whose family is NOT in the split doc is excluded (fail closed), never guessed', () => {
  const doc = fakeSplitDoc();
  const rel = 'CWE22_Path_Traversal__Servlet_getParameter_01.java';
  for (const split of ['train', 'dev', 'test']) {
    assert.equal(inRequestedSplit(rel, doc, split), false,
      `an unknown family must never be counted as belonging to any split (got true for "${split}")`);
  }
});

test('inRequestedSplit: a missing-family counter increments exactly once per excluded file, never for a real match', () => {
  const doc = fakeSplitDoc();
  const counter = { count: 0 };
  inRequestedSplit('CWE90_LDAP_Injection__Servlet_getParameter_search_01.cs', doc, 'test', counter);
  assert.equal(counter.count, 0, 'a real, present family must not increment the missing-family counter');
  inRequestedSplit('CWE22_Path_Traversal__Servlet_getParameter_01.java', doc, 'test', counter);
  assert.equal(counter.count, 1, 'an absent family must increment the missing-family counter exactly once');
});

test('inRequestedSplit: matching is by BASENAME, matching how score() itself matches actual findings to expected entries', () => {
  // A scanner finding's own `.file` is reported relative to scanRoot
  // (`repoRoot/src/testcases` for C#), while an `expected[].file` entry is
  // relative to repoRoot — two different prefixes for the identical real
  // file. Both must resolve to the same split, since score() itself matches
  // by basename (test/benchmark/realworld/bench-realworld.js `score()`),
  // never by full relative path.
  const doc = fakeSplitDoc();
  const asExpectedSees = 'src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__Servlet_getParameter_search_01.cs';
  const asActualSees = 'CWE90_LDAP_Injection/CWE90_LDAP_Injection__Servlet_getParameter_search_01.cs';
  assert.equal(inRequestedSplit(asExpectedSees, doc, 'test'), inRequestedSplit(asActualSees, doc, 'test'));
});

test('loadSplitDoc: a real, committed split file for sard-juliet-csharp-strict loads and is well-formed', async () => {
  const doc = await loadSplitDoc('sard-juliet-csharp-strict');
  assert.ok(doc && typeof doc.families === 'object', 'expected a {families: {...}} document');
  assert.ok(Object.keys(doc.families).length > 0, 'expected at least one family assignment in the committed split file');
  for (const bucket of Object.values(doc.families)) {
    assert.ok(['train', 'dev', 'test'].includes(bucket), `unexpected bucket value: ${bucket}`);
  }
});

test('loadSplitDoc: a nonexistent app produces a clear, actionable error, never a bare ENOENT', async () => {
  await assert.rejects(
    () => loadSplitDoc('sard-app-that-does-not-exist'),
    (err) => {
      assert.match(err.message, /--split requires a split file at/);
      assert.match(err.message, /split\.mjs --app sard-app-that-does-not-exist/);
      return true;
    },
  );
});

// This is the property the WHOLE fix exists for: split assignment is
// deterministic and total over any family the real split-builder would ever
// see, reusing the exact seeded-hash function (`bucketFor`) buildSplit()
// uses, so this test can't silently diverge from the real assignment logic.
test('inRequestedSplit composes correctly with the real seeded bucketFor(): every family lands in exactly one of the three buckets', () => {
  const seed = 'sard-split-v1';
  const keys = ['fam-a', 'fam-b', 'fam-c', 'fam-d', 'fam-e'];
  const doc = { families: Object.fromEntries(keys.map((k) => [k, bucketFor(seed, k)])) };
  for (const k of keys) {
    const memberships = ['train', 'dev', 'test'].filter((s) => inRequestedSplit(`${k}_01.java`, doc, s));
    assert.equal(memberships.length, 1, `family "${k}" must belong to exactly one split, got: ${JSON.stringify(memberships)}`);
  }
});
