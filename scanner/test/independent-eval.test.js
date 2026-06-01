// R16 — independent-eval scoring core tests.
//
// These verify the precision/recall/F1 and gate MATH deterministically, with
// hand-constructed findings — no scanner run. The runner's end-to-end behavior
// (scan → attribute → score) is smoke-checked separately; correctness of the
// metrics lives here so it can never silently drift.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prf, matchFamily, scoreCorpus, checkGate, normPath } from '../../bench/independent-eval/score.mjs';

test('prf: standard confusion cell', () => {
  const r = prf({ tp: 3, fp: 1, fn: 1 });
  assert.equal(r.precision, 0.75);
  assert.equal(r.recall, 0.75);
  assert.equal(r.f1, 0.75);
});

test('prf: perfect and empty cells', () => {
  assert.deepEqual(prf({ tp: 2, fp: 0, fn: 0 }), { precision: 1, recall: 1, f1: 1 });
  // No data at all → nulls, NOT a misleading zero.
  assert.deepEqual(prf({ tp: 0, fp: 0, fn: 0 }), { precision: null, recall: null, f1: null });
  // All false positives → precision 0, recall undefined, f1 0.
  assert.deepEqual(prf({ tp: 0, fp: 2, fn: 0 }), { precision: 0, recall: null, f1: 0 });
});

test('matchFamily: family string and CWE containment', () => {
  assert.equal(matchFamily({ family: 'xss' }, { family: 'xss' }), true);
  assert.equal(matchFamily({ family: 'xss' }, { family: 'sql-injection' }), false);
  assert.equal(matchFamily({ cwe: '89' }, { cwe: 'CWE-89' }), true);
  assert.equal(matchFamily({ cwe: '89' }, { cwe: '89' }), true);
  assert.equal(matchFamily({ cwe: '22' }, { cwe: 'CWE-89' }), false);
  assert.equal(matchFamily({ family: 'x', cwe: '89' }, { family: 'y', cwe: 'CWE-89' }), true); // cwe rescues
});

test('normPath strips ./ and normalizes slashes', () => {
  assert.equal(normPath('./a/b.js'), 'a/b.js');
  assert.equal(normPath('a\\b.js'), 'a/b.js');
});

test('scoreCorpus: exercises all four confusion cells', () => {
  const entries = [
    { path: 'v/a.js', family: 'sql-injection', cwe: '89', label: 'vulnerable' }, // detected → TP
    { path: 'v/b.js', family: 'sql-injection', cwe: '89', label: 'vulnerable' }, // missed   → FN
    { path: 'c/c.js', family: 'sql-injection', cwe: '89', label: 'clean' },      // clean ok → TN
    { path: 'c/d.js', family: 'sql-injection', cwe: '89', label: 'clean' },      // flagged  → FP
  ];
  const findingsByFile = {
    'v/a.js': [{ family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 }],
    'c/d.js': [{ family: 'sql-injection', cwe: '89', confidence: 0.7 }],
  };
  const r = scoreCorpus(entries, findingsByFile);
  const sql = r.perFamily['sql-injection'];
  assert.deepEqual({ tp: sql.tp, fp: sql.fp, fn: sql.fn, tn: sql.tn }, { tp: 1, fp: 1, fn: 1, tn: 1 });
  assert.equal(sql.precision, 0.5);
  assert.equal(sql.recall, 0.5);
  assert.equal(sql.f1, 0.5);
  assert.equal(r.aggregate.f1, 0.5);
  assert.equal(r.n, 4);
  // Calibration pairs: confidence of the matching finding, else 0; actual=label.
  const byActual = r.calibration.map((c) => `${c.actual}:${c.predicted}`).sort();
  assert.deepEqual(byActual, ['0:0', '0:0.7', '1:0', '1:0.9']);
});

test('checkGate: passes lenient, fails strict, and treats null metrics as violations', () => {
  const entries = [
    { path: 'v/a.js', family: 'sql-injection', cwe: '89', label: 'vulnerable' },
    { path: 'v/b.js', family: 'sql-injection', cwe: '89', label: 'vulnerable' },
    { path: 'c/c.js', family: 'sql-injection', cwe: '89', label: 'clean' },
    { path: 'c/d.js', family: 'sql-injection', cwe: '89', label: 'clean' },
  ];
  const findingsByFile = {
    'v/a.js': [{ family: 'sql-injection', cwe: 'CWE-89', confidence: 0.9 }],
    'c/d.js': [{ family: 'sql-injection', cwe: '89', confidence: 0.7 }],
  };
  const r = scoreCorpus(entries, findingsByFile); // F1 = 0.5

  assert.equal(checkGate(r, { aggregateF1: 0.1 }).pass, true);

  const strict = checkGate(r, { aggregateF1: 0.9 });
  assert.equal(strict.pass, false);
  assert.match(strict.violations[0], /aggregate\.f1=0\.5 < 0\.9/);

  assert.equal(checkGate(r, { perFamilyRecall: 0.6 }).pass, false);
  assert.equal(checkGate(r, { minSamples: 10 }).pass, false);

  // A family with only TNs → prf null; a perFamilyF1 threshold must flag it as
  // unmeasured rather than silently pass.
  const allClean = scoreCorpus(
    [{ path: 'c/x.js', family: 'xss', cwe: '79', label: 'clean' }],
    {},
  );
  const g = checkGate(allClean, { perFamilyF1: 0.5 });
  assert.equal(g.pass, false);
  assert.match(g.violations.join(' '), /unmeasured/);
});
