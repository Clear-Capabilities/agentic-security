// Gate for the independent-population release check (assurance-hardening
// PRD FR-902): "Gate on advisory-local precision, recall, and F1 plus
// per-language floors | A material regression blocks release unless a
// signed exception explains it."
//
// bench/independent/RESULT.json is a committed measurement artifact
// (scoring takes ~32 minutes, so it is not re-run inline here — same
// reasoning scorecard-freshness already applies to the same file). This
// gate compares it against a committed floor, bench/independent/
// gate-baseline.json, the same shape corpus-baseline.json/layer-recall's
// baseline.json already use elsewhere in this repo.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runIndependentPopulationGate, updateGateBaseline } from '../../scripts/independent-population-gate.mjs';

function repoWith(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'indep-gate-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body));
  }
  return d;
}

const BASELINE = {
  overall: { precision: 0.5, recall: 0.1, f1: 0.15 },
  byLanguage: {
    python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 },
    ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 },
  },
};

function resultWith(overall, byLanguage = {}) {
  return {
    measuredAt: '2026-08-01',
    engineVersion: '9.9.9',
    overall: { precision: { value: overall.precision }, recall: { value: overall.recall }, f1: overall.f1 },
    byLanguage: Object.fromEntries(Object.entries(byLanguage).map(([lang, v]) => [
      lang, { entries: v.entries, precision: { value: v.precision }, recall: { value: v.recall }, f1: v.f1 },
    ])),
  };
}

const CLEAN_RESULT = resultWith(
  { precision: 0.5, recall: 0.1, f1: 0.15 },
  { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
);

const GOOD_WAIVER = {
  reason: 'Known precision drop from a detector rewrite; re-measuring the full population before deliberately re-baselining.',
  reviewBy: '2099-01-01',
};

test('no RESULT.json at all FAILS — never measured is not a pass', () => {
  const r = runIndependentPopulationGate(repoWith({ 'bench/independent/gate-baseline.json': BASELINE }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /never been measured/);
});

test('no gate-baseline.json FAILS — nothing to gate against', () => {
  const r = runIndependentPopulationGate(repoWith({ 'bench/independent/RESULT.json': CLEAN_RESULT }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /nothing to gate against/);
});

test('a RESULT.json matching or exceeding the baseline PASSES', () => {
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': CLEAN_RESULT,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, true);
  assert.match(r.detail, /held at or above/);
});

test('an OVERALL precision/recall/F1 improvement is silent — the gate never blocks a rise', () => {
  const improved = resultWith(
    { precision: 0.9, recall: 0.5, f1: 0.6 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': improved,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, true);
});

test('an overall precision regression with no waiver FAILS and names the exact drop', () => {
  const regressed = resultWith(
    { precision: 0.3, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /overall precision dropped/);
  assert.match(r.detail, /30\.0%/);
  assert.match(r.detail, /50\.0%/);
});

test('a per-language recall regression with no waiver FAILS, naming the specific language', () => {
  const regressed = resultWith(
    { precision: 0.5, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.02, f1: 0.03 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /language 'python' recall dropped/);
});

test('a language present in the baseline but MISSING from RESULT.json FAILS — a whole language vanishing is a regression, not a no-op', () => {
  const missingLang = resultWith(
    { precision: 0.5, recall: 0.1, f1: 0.15 },
    { ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } }, // python dropped entirely
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': missingLang,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /language 'python'.*missing/);
});

test('a language present in RESULT.json but NOT in the baseline is not gated — no floor exists yet to have fallen below', () => {
  const newLang = resultWith(
    { precision: 0.5, recall: 0.1, f1: 0.15 },
    {
      python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 },
      ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 },
      go: { entries: 5, precision: 0.01, recall: 0.01, f1: 0.01 }, // brand new, no baseline entry
    },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': newLang,
    'bench/independent/gate-baseline.json': BASELINE,
  }));
  assert.equal(r.ok, true);
});

test('a regression WITH a valid, unexpired, well-reasoned waiver PASSES but carries a warning', () => {
  const regressed = resultWith(
    { precision: 0.3, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
    '.independent-population-waiver.json': GOOD_WAIVER,
  }));
  assert.equal(r.ok, true);
  assert.match(r.detail, /waived until 2099-01-01/);
  assert.ok(r.warnings.length > 0);
});

test('an EXPIRED waiver does not override a regression', () => {
  const regressed = resultWith(
    { precision: 0.3, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
    '.independent-population-waiver.json': { ...GOOD_WAIVER, reviewBy: '2020-01-01' },
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /expired on 2020-01-01/);
});

test('a waiver with no real reason (too short) does not override a regression — a placeholder is indistinguishable from an oversight', () => {
  const regressed = resultWith(
    { precision: 0.3, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
    '.independent-population-waiver.json': { reason: 'known issue', reviewBy: '2099-01-01' },
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /needs a real reason/);
});

test('a waiver with no reviewBy at all does not override a regression — a waiver with no expiry becomes permanent', () => {
  const regressed = resultWith(
    { precision: 0.3, recall: 0.1, f1: 0.15 },
    { python: { entries: 50, precision: 0.5, recall: 0.1, f1: 0.15 }, ruby: { entries: 30, precision: 0.4, recall: 0.08, f1: 0.12 } },
  );
  const r = runIndependentPopulationGate(repoWith({
    'bench/independent/RESULT.json': regressed,
    'bench/independent/gate-baseline.json': BASELINE,
    '.independent-population-waiver.json': { reason: GOOD_WAIVER.reason },
  }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /needs a reviewBy date/);
});

// ── updateGateBaseline ─────────────────────────────────────────────────────

test('updateGateBaseline overwrites gate-baseline.json from the current RESULT.json', () => {
  const dir = repoWith({ 'bench/independent/RESULT.json': CLEAN_RESULT });
  const b = updateGateBaseline(dir);
  assert.equal(b.overall.precision, 0.5);
  assert.deepEqual(Object.keys(b.byLanguage).sort(), ['python', 'ruby']);
  const written = JSON.parse(fs.readFileSync(path.join(dir, 'bench/independent/gate-baseline.json'), 'utf8'));
  assert.equal(written.overall.precision, 0.5);
});

test('updateGateBaseline throws on a missing RESULT.json — never silently baseline from nothing', () => {
  const dir = repoWith({});
  assert.throws(() => updateGateBaseline(dir));
});
