// The hosted block of the time-to-first-finding baseline is derived, not typed: median of hosted samples, factor from the observed
// spread with a floor, every sample and its provenance recorded, and the local block left exactly as it was.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { deriveHosted, withHosted, median, MIN_SAMPLES, MIN_FACTOR, BASELINE } from '../../bench/ttff/hosted-baseline.mjs';

test('median of an even and an odd sample count', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 3);
});

test('the block records the median, a factor no lower than the floor, the sorted samples and the provenance', () => {
  const h = deriveHosted([13956, 11473, 13891, 13961, 14227, 13788, 11252, 11330], { derivedFrom: 'two ci runs', recordedAt: '2026-11-22' });
  assert.equal(h.ms, 13840);
  assert.equal(h.regressionFactor, MIN_FACTOR);
  assert.deepEqual(h.samples, [11252, 11330, 11473, 13788, 13891, 13956, 13961, 14227]);
  assert.match(h.derivedFrom, /^two ci runs .*median of the 8 samples.*14227\/13840/);
  assert.equal(h.recordedAt, '2026-11-22');
});

test('a wide spread raises the factor above the floor: largest over median, rounded up to 0.05, plus the margin', () => {
  const h = deriveHosted([10000, 10000, 10000, 10000, 13000], { derivedFrom: 'x' });
  assert.equal(h.regressionFactor, 1.45);
});

test('too few samples, a bad sample or missing provenance are refused', () => {
  assert.throws(() => deriveHosted([1, 2, 3, 4], { derivedFrom: 'x' }), new RegExp(`at least ${MIN_SAMPLES}`));
  assert.throws(() => deriveHosted([1, 2, 3, 4, 0], { derivedFrom: 'x' }), /positive number/);
  assert.throws(() => deriveHosted([1, 2, 3, 4, 5], {}), /--derived-from/);
});

test('withHosted replaces only the hosted block', () => {
  const base = { schema: 'ttff/v1', ms: 8935, findings: 377, hosted: { ms: 1 } };
  const next = withHosted(base, { ms: 2 });
  assert.deepEqual(next, { schema: 'ttff/v1', ms: 8935, findings: 377, hosted: { ms: 2 } });
  assert.deepEqual(base.hosted, { ms: 1 });
});

test('the committed baseline carries a derived hosted block whose limit is above every one of its samples', () => {
  const b = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  assert.ok(b.hosted && b.hosted.samples.length >= MIN_SAMPLES);
  assert.equal(b.hosted.ms, median(b.hosted.samples));
  assert.ok(b.hosted.regressionFactor >= MIN_FACTOR);
  assert.ok(Math.max(...b.hosted.samples) <= b.hosted.ms * b.hosted.regressionFactor);
  assert.match(b.hosted.derivedFrom, /median/);
});
