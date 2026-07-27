// R3 — accuracy scorecard aggregation + rendering.
//
// Note on the filename: `test/scorecard.test.js` already exists and covers an
// unrelated feature (dependency-health enrichment on SCA components). This
// file is the accuracy scorecard (corpus detection / correct-silence rates),
// so it takes a non-colliding name rather than extending that file.
//
// What is asserted here is exactly the integrity contract R3 is for:
//   1. per-language and per-CWE aggregation matches hand-computed values
//   2. no percentage is ever rendered without its numerator and denominator
//   3. regeneration is stable: same inputs → identical output apart from the
//      timestamp
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  aggregateCorpus,
  formatRate,
  buildScorecard,
  renderScorecardMarkdown,
  TIMESTAMP_MARKER,
} from '../src/posture/accuracy-scorecard.js';

// ── Hand-computable fixture ─────────────────────────────────────────────────
// 6 scored entries + 1 env-error (must be excluded from every denominator).
//
//   javascript: A pre:TP post:TN | B pre:TP post:FP | C pre:FN post:TN
//   python:     D pre:TP post:TN | E pre:TP (no post tree)
//   java:       F pre:FN post:TN
//   python:     G env-error                      (not scored at all)
//
// pre  (detection):  TP=4, FN=2      → 4/6
// post (silence):    TN=4, FP=1      → 4/5   (E has no post tree)
// by language:
//   javascript  pre 2/3   post 2/3
//   python      pre 2/2   post 1/1
//   java        pre 0/1   post 1/1
// by cwe:
//   CWE-89      A,D       pre 2/2  post 2/2
//   CWE-78      B,E       pre 2/2  post 0/1
//   CWE-79      C,F       pre 0/2  post 2/2
const FIXTURE_DETAIL = [
  { cve: 'A', tier: 'capability', cwe: 'CWE-89', language: 'javascript', status: 'pre:TP post:TN' },
  { cve: 'B', tier: 'capability', cwe: 'CWE-78', language: 'javascript', status: 'pre:TP post:FP' },
  { cve: 'C', tier: 'capability', cwe: 'CWE-79', language: 'javascript', status: 'pre:FN post:TN' },
  { cve: 'D', tier: 'regression', cwe: 'CWE-89', language: 'python', status: 'pre:TP post:TN' },
  { cve: 'E', tier: 'regression', cwe: 'CWE-78', language: 'python', status: 'pre:TP' },
  { cve: 'F', tier: 'capability', cwe: 'CWE-79', language: 'java', status: 'pre:FN post:TN' },
  { cve: 'G', tier: 'deep', cwe: 'CWE-78', language: 'python', status: 'env-error', error: 'parser-unavailable' },
];

function fixtureInputs(generatedAt = '2026-01-01T00:00:00.000Z') {
  return {
    provenance: {
      engineVersion: '9.9.9',
      bundleSha256: 'a'.repeat(64),
      commit: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      nodeVersion: 'v24.0.0',
      generatedAt,
    },
    corpusDetail: FIXTURE_DETAIL,
    selfScan: {
      targets: { hooks: { total: 3, byFile: { 'a.js': 2, 'b.js': 1 } } },
      polyglot: { total: 0, byLanguage: {} },
    },
    committed: {
      corpusBaseline: { generatedAt: '2026-07-27', total: 199, passing: 199 },
      proofCorpus: {
        bundleSha: 'b'.repeat(64),
        targetCount: 1,
        ok: 1,
        failed: 0,
        targets: [{
          id: 'demo', commit: 'c'.repeat(40), status: 'ok',
          coverage: { totals: { inScope: 100, parsed: 94 } },
          determinism: { checked: true, identical: true, results: 12 },
        }],
      },
    },
  };
}

// ── 1. Aggregation ──────────────────────────────────────────────────────────

test('accuracy scorecard — overall detection / silence match hand-computed counts', () => {
  const a = aggregateCorpus(FIXTURE_DETAIL);
  assert.equal(a.overall.detection.n, 4);
  assert.equal(a.overall.detection.d, 6);
  assert.equal(a.overall.silence.n, 4);
  assert.equal(a.overall.silence.d, 5);
  // The env-error entry is excluded from both denominators, and surfaced.
  assert.equal(a.notScored.length, 1);
  assert.equal(a.notScored[0].cve, 'G');
  assert.equal(a.scoredEntries, 6);
});

test('accuracy scorecard — per-language aggregation matches hand-computed values', () => {
  const { byLanguage } = aggregateCorpus(FIXTURE_DETAIL);
  const idx = Object.fromEntries(byLanguage.map(r => [r.key, r]));
  assert.deepEqual([idx.javascript.detection.n, idx.javascript.detection.d], [2, 3]);
  assert.deepEqual([idx.javascript.silence.n, idx.javascript.silence.d], [2, 3]);
  assert.deepEqual([idx.python.detection.n, idx.python.detection.d], [2, 2]);
  assert.deepEqual([idx.python.silence.n, idx.python.silence.d], [1, 1]);
  assert.deepEqual([idx.java.detection.n, idx.java.detection.d], [0, 1]);
  assert.deepEqual([idx.java.silence.n, idx.java.silence.d], [1, 1]);
  // The env-error python entry must not inflate python's denominator.
  assert.equal(idx.python.detection.d, 2);
  // Deterministic ordering (by key) so regeneration is stable.
  assert.deepEqual(byLanguage.map(r => r.key), ['java', 'javascript', 'python']);
});

test('accuracy scorecard — per-CWE aggregation matches hand-computed values', () => {
  const { byCwe } = aggregateCorpus(FIXTURE_DETAIL);
  const idx = Object.fromEntries(byCwe.map(r => [r.key, r]));
  assert.deepEqual([idx['CWE-89'].detection.n, idx['CWE-89'].detection.d], [2, 2]);
  assert.deepEqual([idx['CWE-89'].silence.n, idx['CWE-89'].silence.d], [2, 2]);
  assert.deepEqual([idx['CWE-78'].detection.n, idx['CWE-78'].detection.d], [2, 2]);
  assert.deepEqual([idx['CWE-78'].silence.n, idx['CWE-78'].silence.d], [0, 1]);
  assert.deepEqual([idx['CWE-79'].detection.n, idx['CWE-79'].detection.d], [0, 2]);
  assert.deepEqual([idx['CWE-79'].silence.n, idx['CWE-79'].silence.d], [2, 2]);
  assert.deepEqual(byCwe.map(r => r.key), ['CWE-78', 'CWE-79', 'CWE-89']);
});

test('accuracy scorecard — sum of per-slice numerators equals the overall numerator', () => {
  const a = aggregateCorpus(FIXTURE_DETAIL);
  for (const slice of [a.byLanguage, a.byCwe]) {
    assert.equal(slice.reduce((s, r) => s + r.detection.n, 0), a.overall.detection.n);
    assert.equal(slice.reduce((s, r) => s + r.detection.d, 0), a.overall.detection.d);
    assert.equal(slice.reduce((s, r) => s + r.silence.n, 0), a.overall.silence.n);
    assert.equal(slice.reduce((s, r) => s + r.silence.d, 0), a.overall.silence.d);
  }
});

test('accuracy scorecard — an empty denominator never renders a fabricated rate', () => {
  assert.equal(formatRate(0, 0), '0/0 (n/a)');
  const a = aggregateCorpus([]);
  assert.equal(a.overall.detection.d, 0);
  assert.equal(formatRate(a.overall.detection.n, a.overall.detection.d), '0/0 (n/a)');
});

// ── 2. No bare percentages ──────────────────────────────────────────────────

test('accuracy scorecard — formatRate always carries numerator and denominator', () => {
  assert.equal(formatRate(4, 6), '4/6 (66.7%)');
  assert.equal(formatRate(199, 199), '199/199 (100.0%)');
});

test('accuracy scorecard — rendered document emits no bare percentage', () => {
  const md = renderScorecardMarkdown(buildScorecard(fixtureInputs()));
  // Strip every legitimate `N/D (P%)` form, then assert nothing percent-shaped
  // is left anywhere in the document.
  const stripped = md.replace(/\b\d+\/\d+ \(\d+\.\d+%\)/g, '');
  const leftovers = stripped.match(/\d+(?:\.\d+)?\s*%/g) || [];
  assert.deepEqual(leftovers, [],
    `bare percentage(s) rendered without numerator/denominator: ${leftovers.join(', ')}`);
});

test('accuracy scorecard — the population caveat is stated in the document body', () => {
  const md = renderScorecardMarkdown(buildScorecard(fixtureInputs()));
  assert.match(md, /\*\*not\*\* general-purpose recall/i);
  assert.match(md, /\*\*not\*\* a general\s+false-positive rate/i);
  assert.match(md, /curated/i);
  // And the F1 omission is explained rather than fabricated.
  assert.match(md, /F1/);
  assert.ok(!/F1[^\n]*=\s*\d/.test(md), 'an F1 value must not be asserted');
});

test('accuracy scorecard — headline figures appear with their raw counts', () => {
  const md = renderScorecardMarkdown(buildScorecard(fixtureInputs()));
  assert.match(md, /4\/6 \(66\.7%\)/);   // detection
  assert.match(md, /4\/5 \(80\.0%\)/);   // correct silence
});

test('accuracy scorecard — committed inputs are labelled with their own provenance', () => {
  const md = renderScorecardMarkdown(buildScorecard(fixtureInputs()));
  assert.match(md, /2026-07-27/);              // baseline generatedAt
  assert.match(md, /committed/i);
  // Entries that could not be scored must be disclosed, not dropped.
  assert.match(md, /parser-unavailable/);
});

// ── 3. Regeneration stability ───────────────────────────────────────────────

test('accuracy scorecard — regenerating with identical inputs differs only in the timestamp', () => {
  const a = renderScorecardMarkdown(buildScorecard(fixtureInputs('2026-01-01T00:00:00.000Z')));
  const b = renderScorecardMarkdown(buildScorecard(fixtureInputs('2027-06-05T11:22:33.000Z')));
  assert.notEqual(a, b, 'the timestamp should actually appear in the document');
  const drop = s => s.split('\n').filter(l => !l.includes(TIMESTAMP_MARKER)).join('\n');
  assert.equal(drop(a), drop(b));
  // Exactly one line carries the timestamp, so the diff is trivially auditable.
  assert.equal(a.split('\n').filter(l => l.includes(TIMESTAMP_MARKER)).length, 1);
});

test('accuracy scorecard — machine-readable model is stable apart from generatedAt', () => {
  const a = buildScorecard(fixtureInputs('2026-01-01T00:00:00.000Z'));
  const b = buildScorecard(fixtureInputs('2027-06-05T11:22:33.000Z'));
  a.provenance.generatedAt = b.provenance.generatedAt = 'X';
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('accuracy scorecard — input ordering does not change the output', () => {
  const shuffled = [...FIXTURE_DETAIL].reverse();
  const a = aggregateCorpus(FIXTURE_DETAIL);
  const b = aggregateCorpus(shuffled);
  assert.equal(JSON.stringify(a.byLanguage), JSON.stringify(b.byLanguage));
  assert.equal(JSON.stringify(a.byCwe), JSON.stringify(b.byCwe));
  assert.equal(JSON.stringify(a.overall), JSON.stringify(b.overall));
});
