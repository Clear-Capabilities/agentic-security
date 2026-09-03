import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LANGUAGE_COVERAGE_TIERS, coverageTierForLanguage } from '../../src/lineage/language-coverage-tiers.js';
import { LANGUAGE_COVERAGE_TIER_VALUES } from '../../src/lineage/schema.js';

const LINEAGE_WIRED_LANGUAGES = ['js', 'python', 'java', 'csharp', 'kotlin', 'go', 'php', 'ruby', 'cpp'];
const PATTERN_ONLY_LANGUAGES = ['rust', 'solidity', 'swift', 'dart'];

test('LANGUAGE_COVERAGE_TIERS has exactly the 9 lineage-wired languages plus the 4 pattern-only ones, no more, no fewer', () => {
  const keys = LANGUAGE_COVERAGE_TIERS.map((e) => e.language).sort();
  const expected = [...LINEAGE_WIRED_LANGUAGES, ...PATTERN_ONLY_LANGUAGES].sort();
  assert.deepEqual(keys, expected);
});

test('every entry has a value in LANGUAGE_COVERAGE_TIER_VALUES', () => {
  for (const e of LANGUAGE_COVERAGE_TIERS) {
    assert.ok(LANGUAGE_COVERAGE_TIER_VALUES.includes(e.tier), `${e.language} has unrecognized tier "${e.tier}"`);
  }
});

test('every lineage-wired language is tier "partial" with a real recall number and no entry reaches "full" yet (docs/METRICS.md, measured 2026-08-19: best is python at 66%, well under the 85% bar)', () => {
  for (const lang of LINEAGE_WIRED_LANGUAGES) {
    const e = coverageTierForLanguage(lang);
    assert.equal(e.tier, 'partial');
    assert.equal(typeof e.irTaintRecallPct, 'number');
    assert.ok(e.irTaintRecallPct > 0 && e.irTaintRecallPct < 85);
    assert.equal(e.measuredAt, '2026-08-19');
    assert.equal(e.source, 'docs/METRICS.md');
  }
});

test('the exact 9 recall numbers match docs/METRICS.md verbatim', () => {
  const expected = { python: 66, go: 59, js: 58, csharp: 57, ruby: 55, java: 52, php: 52, kotlin: 48, cpp: 18 };
  for (const [lang, pct] of Object.entries(expected)) {
    assert.equal(coverageTierForLanguage(lang).irTaintRecallPct, pct, `${lang} recall mismatch`);
  }
});

test('every pattern-only language is tier "pattern-only" with no recall number (no lineage engine ever runs against them)', () => {
  for (const lang of PATTERN_ONLY_LANGUAGES) {
    const e = coverageTierForLanguage(lang);
    assert.equal(e.tier, 'pattern-only');
    assert.equal(e.irTaintRecallPct, null);
  }
});

test('coverageTierForLanguage returns null for unknown/unrecognized languages, never fabricates a tier', () => {
  assert.equal(coverageTierForLanguage('unknown'), null);
  assert.equal(coverageTierForLanguage('cobol'), null);
  assert.equal(coverageTierForLanguage(''), null);
  assert.equal(coverageTierForLanguage(undefined), null);
});

test('the table is frozen (Object.freeze) at both the array and entry level', () => {
  assert.ok(Object.isFrozen(LANGUAGE_COVERAGE_TIERS));
  assert.ok(Object.isFrozen(LANGUAGE_COVERAGE_TIERS[0]));
});
