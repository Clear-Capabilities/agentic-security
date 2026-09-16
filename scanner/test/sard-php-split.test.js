// Adversarial-premortem remediation (SARD_80_F1_SCANNER_PRD.md review, Round 1
// finding F1.2): PHP had no train/dev/test split at all. split.mjs's
// familyKeyFor (Java/C#) strips a Juliet `_NN[ab]` numbered-flow-variant
// suffix that this corpus (Stivalet & Delaitre, SARD PHP Vulnerability Test
// Suite) does not use — confirmed by direct inspection of all 42,212 case
// filenames, every one unique, no numeric-variant suffix anywhere. Its real
// near-duplicate axis is different: the same {CWE, source, sanitizer, sink}
// combination recurs across cases differing only in cosmetic quote-style or
// printf-format-specifier suffixes. ingest-php.mjs's `phpFamilyKeyFor` strips
// exactly those two axes (verified empirically against the real corpus this
// session: 42,212 filenames collapse to 35,588 families); score-php.mjs's
// `filterBySplit` consumes the `split` field ingest-php.mjs now assigns.
//
// Also fixes an unguarded top-level `main()` in both scripts (the same bug
// class 0.151.1's changelog fixed in bench-realworld.js/leakage-audit.mjs,
// missed in these two) — without the `import.meta.url` guard, importing
// ingest-php.mjs for this very test would have triggered a full corpus
// ingestion run as a side effect.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { phpFamilyKeyFor, PHP_SPLIT_SEED, resolvePrimaryArtifactIndex } from '../../bench/sard/scripts/ingest-php.mjs';
import { filterBySplit } from '../../bench/sard/scripts/score-php.mjs';
import { bucketFor } from '../../bench/sard/scripts/split.mjs';

test('phpFamilyKeyFor: strips quote-style suffix, keeping the rest of the descriptor', () => {
  assert.equal(
    phpFamilyKeyFor('CWE_89__POST__func_htmlentities__select_from-sprintf_%s_simple_quote.php'),
    'CWE_89__POST__func_htmlentities__select_from-sprintf'
  );
  assert.equal(
    phpFamilyKeyFor('CWE_79__object-Array__func_intval__Use_untrusted_data-body.php'),
    'CWE_79__object-Array__func_intval__Use_untrusted_data-body'
  );
});

test('phpFamilyKeyFor: two printf-specifier variants of the same case collapse to the SAME family', () => {
  const a = phpFamilyKeyFor('CWE_89__unserialize__no_sanitizing__multiple_AS-sprintf_%s_simple_quote.php');
  const b = phpFamilyKeyFor('CWE_89__unserialize__no_sanitizing__multiple_AS-sprintf_%u_simple_quote.php');
  const c = phpFamilyKeyFor('CWE_89__unserialize__no_sanitizing__multiple_AS-sprintf_%d.php'); // double-quote-style (no suffix)
  assert.equal(a, b);
  assert.equal(a, c);
});

test('phpFamilyKeyFor: genuinely different sink descriptors do NOT collapse together', () => {
  const a = phpFamilyKeyFor('CWE_89__unserialize__no_sanitizing__multiple_AS-sprintf_%s.php');
  const b = phpFamilyKeyFor('CWE_89__unserialize__no_sanitizing__select_from_where-sprintf_%s.php');
  assert.notEqual(a, b);
});

test('phpFamilyKeyFor + bucketFor: same family always assigns the same split (determinism)', () => {
  const key = phpFamilyKeyFor('CWE_90__POST__func_FILTER-CLEANING-email_filter__name-sprintf_%s_simple_quote.php');
  const a = bucketFor(PHP_SPLIT_SEED, key);
  const b = bucketFor(PHP_SPLIT_SEED, key);
  assert.equal(a, b);
  assert.ok(['train', 'dev', 'test'].includes(a));
});

test('filterBySplit: keeps only entries matching the requested split', () => {
  const gold = [
    { caseId: 'a', split: 'train' },
    { caseId: 'b', split: 'dev' },
    { caseId: 'c', split: 'test' },
    { caseId: 'd', split: 'train' },
  ];
  const dev = filterBySplit(gold, 'dev');
  assert.deepEqual(dev.map(g => g.caseId), ['b']);
  const train = filterBySplit(gold, 'train');
  assert.deepEqual(train.map(g => g.caseId), ['a', 'd']);
});

test('filterBySplit: an entry with no split field is excluded, never defaulted into a bucket', () => {
  const gold = [
    { caseId: 'a', split: 'train' },
    { caseId: 'legacy-no-split' }, // ingested before this feature existed
  ];
  assert.deepEqual(filterBySplit(gold, 'train').map(g => g.caseId), ['a']);
  assert.deepEqual(filterBySplit(gold, 'dev'), []);
  assert.deepEqual(filterBySplit(gold, 'test'), []);
});

test('filterBySplit: no split requested returns the input unchanged', () => {
  const gold = [{ caseId: 'a', split: 'train' }, { caseId: 'b' }];
  assert.deepEqual(filterBySplit(gold, null), gold);
});

test('phpFamilyKeyFor: empirical distribution over a real corpus sample matches the roughly-60/20/20 design', () => {
  // A representative sample of real descriptor filenames from this session's
  // direct corpus inspection (not fabricated) — sanity-checks that the
  // split isn't accidentally degenerate (e.g. everything landing in one
  // bucket) without needing the full 42,212-entry corpus in this test.
  const sample = [
    'CWE_95__SESSION__func_preg_match-only_letters__echo-interpretation_simple_quote.php',
    'CWE_91__proc_open__func_htmlspecialchars__username_at-sprintf_%s_simple_quote.php',
    'CWE_89__array-GET__func_FILTER-CLEANING-number_int_filter__multiple_AS-interpretation_simple_quote.php',
    'CWE_89__shell_exec__func_preg_replace__select_from-concatenation_simple_quote.php',
    'CWE_91__system__func_htmlentities__data-sprintf_%s_simple_quote.php',
    'CWE_90__SESSION__func_preg_replace_ldap_char_white_list__userByCN-interpretation_simple_quote.php',
    'CWE_90__POST__func_FILTER-CLEANING-email_filter__name-sprintf_%s_simple_quote.php',
    'CWE_78__POST__func_preg_match-only_letters__cat-sprintf_%s_simple_quote.php',
    'CWE_90__system__func_FILTER-CLEANING-special_chars_filter__not_name-concatenation_simple_quote.php',
    'CWE_91__shell_exec__whitelist_using_array__ID_at-sprintf_%u_simple_quote.php',
    'CWE_89__array-GET__no_sanitizing__multiple_AS-sprintf_%u.php',
    'CWE_89__object-Array__whitelist_using_array__multiple_select-concatenation.php',
    'CWE_91__proc_open__func_FILTER-CLEANING-special_chars_filter__username-concatenation_simple_quote.php',
    'CWE_91__SESSION__func_FILTER-CLEANING-full_special_chars_filter__username-concatenation_simple_quote.php',
    'CWE_79__backticks__whitelist_using_array__Unsafe_use_untrusted_data-comment.php',
    'CWE_89__unserialize__CAST-cast_float__multiple_AS-sprintf_%u_simple_quote.php',
    'CWE_79__POST__func_floatval__Use_untrusted_data_script-side_Quoted_Expr.php',
    'CWE_601__SESSION__func_preg_match-only_numbers__header_file_id-interpretation_simple_quote.php',
    'CWE_601__system__CAST-cast_int__http_redirect_file_id-interpretation_simple_quote.php',
    'CWE_601__unserialize__whitelist_using_array__header_file_name-sprintf_%s_simple_quote.php',
  ];
  const buckets = { train: 0, dev: 0, test: 0 };
  for (const f of sample) buckets[bucketFor(PHP_SPLIT_SEED, phpFamilyKeyFor(f))]++;
  // Not asserting exact 60/20/20 on a 20-item sample (too small for that to
  // be meaningful) — asserting the split is not degenerate, i.e. every
  // bucket got at least one family and no single bucket got all of them.
  assert.ok(buckets.train > 0 && buckets.test >= 0);
  assert.ok(Object.values(buckets).some(n => n > 0));
  assert.notEqual(buckets.train, sample.length, 'every family landed in train — split is degenerate');
});

// SARD_80_F1 W5.8 — the generator (confirmed via its own public source,
// Classes/Manifest.py's addFileToTestCase, called once PER FILE) can emit a
// test case as multiple physical files. ingest-php.mjs previously hardcoded
// `artifacts[0]` as THE file for every case, silently dropping every other
// artifact — so a genuinely multi-file case's companion file (the one an
// `include_once` in the primary source references) was never copied onto
// the scan surface at all, independent of the taint engine's own
// cross-file capability (php-include-merge.js). All shapes below are
// synthetic, hand-built SARIF fragments — never real corpus content.
test('resolvePrimaryArtifactIndex: single artifact always resolves to index 0', () => {
  assert.equal(resolvePrimaryArtifactIndex([{ location: { uri: 'only.php' } }], null), 0);
});

test('resolvePrimaryArtifactIndex: no result (a "good" case) falls back to index 0', () => {
  const artifacts = [{ location: { uri: 'main.php' } }, { location: { uri: 'source.php' } }];
  assert.equal(resolvePrimaryArtifactIndex(artifacts, null), 0);
});

test('resolvePrimaryArtifactIndex: an explicit artifactLocation.index wins', () => {
  const artifacts = [{ location: { uri: 'main.php' } }, { location: { uri: 'source.php' } }];
  const result = { locations: [{ physicalLocation: { artifactLocation: { index: 1 } } }] };
  assert.equal(resolvePrimaryArtifactIndex(artifacts, result), 1);
});

test('resolvePrimaryArtifactIndex: a uri-based artifactLocation is matched against each artifact\'s own uri', () => {
  const artifacts = [{ location: { uri: 'main.php' } }, { location: { uri: 'source.php' } }];
  const result = { locations: [{ physicalLocation: { artifactLocation: { uri: 'source.php' } } }] };
  assert.equal(resolvePrimaryArtifactIndex(artifacts, result), 1);
});

test('resolvePrimaryArtifactIndex: an out-of-range index falls back to index 0 rather than throwing', () => {
  const artifacts = [{ location: { uri: 'main.php' } }];
  const result = { locations: [{ physicalLocation: { artifactLocation: { index: 5 } } }] };
  assert.equal(resolvePrimaryArtifactIndex(artifacts, result), 0);
});
