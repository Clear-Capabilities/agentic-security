import { test } from 'node:test';
import assert from 'node:assert/strict';
import { protectionVisual, worstVerdict, VERDICT_PRECEDENCE } from '../src/lib/protection-visual.js';

test('protectionVisual returns a distinct label, glyph, and line style for every known verdict', () => {
  const verdicts = ['protected', 'unprotected', 'mixed', 'unknown', 'not_applicable', 'not_assessed'];
  const seen = new Set();
  for (const v of verdicts) {
    const visual = protectionVisual(v);
    assert.equal(visual.verdict, v);
    assert.ok(visual.label && visual.label.length > 0, `${v} needs a label`);
    assert.ok(visual.glyph && visual.glyph.length > 0, `${v} needs a glyph`);
    assert.ok(['solid', 'dashed', 'dotted'].includes(visual.lineStyle), `${v} needs a valid lineStyle`);
    assert.ok(visual.colorVar.startsWith('--'), `${v} needs a CSS custom-property colorVar`);
    const dedupeKey = `${visual.label}|${visual.glyph}|${visual.lineStyle}`;
    assert.ok(!seen.has(dedupeKey), `${v}'s label+glyph+lineStyle combination "${dedupeKey}" collides with an earlier verdict — AC-20 requires every verdict distinguishable without relying on color`);
    seen.add(dedupeKey);
  }
});

test('protectionVisual falls back to the not_assessed visual for an unrecognized verdict rather than throwing', () => {
  const visual = protectionVisual('some-future-verdict-not-yet-known');
  assert.equal(visual.verdict, 'not_assessed');
});

test('worstVerdict picks unprotected over everything else', () => {
  assert.equal(worstVerdict(['protected', 'unknown', 'unprotected']), 'unprotected');
});

test('worstVerdict picks mixed when present and no unprotected', () => {
  assert.equal(worstVerdict(['protected', 'mixed', 'not_assessed']), 'mixed');
});

test('worstVerdict picks unknown over protected and not_assessed', () => {
  assert.equal(worstVerdict(['protected', 'unknown', 'not_assessed']), 'unknown');
});

test('worstVerdict prefers protected over not_assessed (a real signal beats no signal)', () => {
  assert.equal(worstVerdict(['not_assessed', 'protected']), 'protected');
});

test('worstVerdict returns not_assessed only when nothing else is present', () => {
  assert.equal(worstVerdict(['not_assessed', 'not_applicable']), 'not_assessed');
});

test('worstVerdict on an empty array returns not_assessed rather than throwing', () => {
  assert.equal(worstVerdict([]), 'not_assessed');
});

test('VERDICT_PRECEDENCE is exported and matches the PRD 8.4 order (unprotected, mixed, unknown, protected, then the no-signal states)', () => {
  assert.deepEqual(VERDICT_PRECEDENCE.slice(0, 4), ['unprotected', 'mixed', 'unknown', 'protected']);
  assert.ok(VERDICT_PRECEDENCE.includes('not_assessed'));
  assert.ok(VERDICT_PRECEDENCE.includes('not_applicable'));
});
