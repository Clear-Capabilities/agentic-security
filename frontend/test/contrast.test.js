import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contrastRatio, meetsAA } from '../src/lib/contrast.js';

test('contrastRatio of a color against itself is 1', () => {
  assert.ok(Math.abs(contrastRatio('#061625', '#061625') - 1) < 0.001);
});

test('contrastRatio of black against white is 21 (the theoretical maximum)', () => {
  assert.ok(Math.abs(contrastRatio('#000000', '#FFFFFF') - 21) < 0.01);
});

test('contrastRatio is symmetric', () => {
  assert.ok(Math.abs(contrastRatio('#F3F7FA', '#061625') - contrastRatio('#061625', '#F3F7FA')) < 0.001);
});

test('throws on a malformed hex color rather than silently producing NaN', () => {
  assert.throws(() => contrastRatio('not-a-color', '#000000'), /invalid hex color/);
});

test('meetsAA applies the 4.5:1 normal-text threshold by default', () => {
  assert.equal(meetsAA('#000000', '#FFFFFF'), true);
  assert.equal(meetsAA('#777777', '#808080'), false);
});

test('meetsAA applies the 3:1 large-text threshold when requested', () => {
  // a pair with a ratio between 3 and 4.5 — chosen to genuinely straddle the two thresholds
  const a = '#767676';
  const b = '#FFFFFF'; // WCAG's own reference: #767676 on white is exactly 4.5:1 (AA normal-text boundary)
  assert.equal(meetsAA(a, b), true);
  const c = '#949494'; // lighter gray — below 4.5:1 on white, but should still clear 3:1
  assert.equal(meetsAA(c, b), false);
  assert.equal(meetsAA(c, b, { largeText: true }), true);
});

test('design-token pairs actually used for body text meet AA (4.5:1)', () => {
  const TEXT_PRIMARY = '#F3F7FA';
  const TEXT_SECONDARY = '#9FB3C5';
  const SURFACE_CANVAS = '#061625';
  const SURFACE_PANEL = '#0B1E2F';
  const results = {
    'text-primary on surface-canvas': contrastRatio(TEXT_PRIMARY, SURFACE_CANVAS),
    'text-primary on surface-panel': contrastRatio(TEXT_PRIMARY, SURFACE_PANEL),
    'text-secondary on surface-canvas': contrastRatio(TEXT_SECONDARY, SURFACE_CANVAS),
    'text-secondary on surface-panel': contrastRatio(TEXT_SECONDARY, SURFACE_PANEL),
  };
  for (const [pair, ratio] of Object.entries(results)) {
    assert.ok(ratio >= 4.5, `${pair} is ${ratio.toFixed(2)}:1, below the 4.5:1 AA threshold`);
  }
});

test('status/class badge colors meet the 3:1 non-text (UI component) threshold against surface-panel', () => {
  // Status/class tokens are always paired with an icon+text label (AC-20), so they
  // are evaluated against WCAG's non-text-contrast minimum (3:1), not the stricter
  // body-text minimum — the text label itself uses text-primary/secondary, already
  // covered above.
  const SURFACE_PANEL = '#0B1E2F';
  const badgeTokens = {
    'status-protected': '#59D17D',
    'status-unprotected': '#FF625C',
    'status-unknown': '#F5B83D',
    'context-ai': '#B47AFF',
    'class-pii': '#28D1C5',
    'class-phi': '#A97BFF',
    'class-pci': '#4CA7FF',
  };
  for (const [name, hex] of Object.entries(badgeTokens)) {
    const ratio = contrastRatio(hex, SURFACE_PANEL);
    assert.ok(ratio >= 3, `${name} (${hex}) on surface-panel is ${ratio.toFixed(2)}:1, below the 3:1 non-text threshold`);
  }
});
