// SARD_80_F1_SCANNER_PRD.md (C# investigation): `buildJulietCsExpected`
// builds gold entries' `cwe` field dash-less (`CWE89`), while an actual
// finding's `reportedCwe` (or the vuln-text fallback) is dashed (`CWE-89`,
// the format `dataflow/catalog.js` and every non-Juliet detector use).
// `bumpCwe`'s per-CWE table used to key directly on whichever string it was
// handed, so TP/FN (keyed off the gold's dash-less string) and FP (keyed
// off the finding's dashed string) for the SAME real CWE landed in two
// disjoint rows: one all-TP/FN reading 100% precision, one all-FP reading
// as an unrelated phantom CWE — corrupting the CWE COUNT the macro-F1
// average divides by, not just cosmetic. `_cweKey` canonicalizes both
// sides to `CWE-NN` before bumping.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { score, _cweKey, _cweDigits } from './benchmark/realworld/bench-realworld.js';
import { readFileSync } from 'node:fs';

// The real family map (loadFamilyMap() reads the same file at runtime) —
// an empty map slugifies "SQL Injection (test)" to "sql-injection-test",
// which then fails the expected entry's plain "sql-injection" family
// check and produces a spurious FP instead of the merge this test exists
// to prove.
const FAMILY_MAP = JSON.parse(readFileSync(new URL('./benchmark/expected.json', import.meta.url), 'utf8'))._familyMap;

test('_cweKey/_cweDigits: dashed and dash-less forms of the same CWE canonicalize identically', () => {
  assert.equal(_cweKey('CWE89'), 'CWE-89');
  assert.equal(_cweKey('CWE-89'), 'CWE-89');
  assert.equal(_cweDigits('CWE89'), '89');
  assert.equal(_cweDigits('CWE-89'), '89');
  assert.equal(_cweKey(null), null);
  assert.equal(_cweKey(''), null);
});

// score() itself only returns {tps, fps, fns} — the per-CWE table is built
// from that by `runOne`'s bumpCwe, using the exact same _cweKey. This
// reproduces that bump step directly over score()'s real output, proving
// the fix end-to-end without needing runOne's full app-config plumbing.
function bumpFromScoreResult({ tps, fps, fns }) {
  const perCwe = {};
  const bump = (cwe, k) => { const key = _cweKey(cwe); if (!key) return; (perCwe[key] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  for (const t of tps) bump(t.cwe, 'tp');
  for (const x of fps) bump(x.reportedCwe || (x.vuln && (x.vuln.match(/CWE-?\d+/)?.[0])), 'fp');
  for (const x of fns) bump(x.cwe, 'fn');
  return perCwe;
}

test('score()+bumpCwe: a gold entry with a dash-less cwe and a matching finding with a dashed reportedCwe land in ONE per-CWE row, not two', async () => {
  const expected = [
    { file: 'A.cs', line: 5, lineTolerance: 2, family: 'sql-injection', cwe: 'CWE89' },
  ];
  const actual = [
    { file: 'A.cs', line: 5, family: 'sql-injection', vuln: 'SQL Injection (test)', cwe: 'CWE-89' },
  ];
  const result = await score(actual, expected, FAMILY_MAP, '/tmp', []);
  assert.equal(result.tps.length, 1, `expected the finding to match the expected entry, got tps=${JSON.stringify(result.tps)} fps=${JSON.stringify(result.fps)}`);
  const perCwe = bumpFromScoreResult(result);
  const keys = Object.keys(perCwe);
  assert.deepEqual(keys, ['CWE-89'], `expected exactly one merged CWE-89 row, got: ${JSON.stringify(keys)}`);
  assert.equal(perCwe['CWE-89'].tp, 1);
  assert.equal(perCwe['CWE-89'].fp, 0);
  assert.equal(perCwe['CWE-89'].fn, 0);
});

test('score()+bumpCwe: a genuinely unmatched dashed-CWE finding still counts as a real, separate FP row', async () => {
  const expected = [
    { file: 'A.cs', line: 5, lineTolerance: 2, family: 'sql-injection', cwe: 'CWE89' },
  ];
  const actual = [
    { file: 'A.cs', line: 5, family: 'sql-injection', vuln: 'SQL Injection (test)', cwe: 'CWE-89' },
    { file: 'B.cs', line: 9, family: 'path-traversal', vuln: 'Path Traversal (test)', cwe: 'CWE-22' },
  ];
  const result = await score(actual, expected, FAMILY_MAP, '/tmp', []);
  const perCwe = bumpFromScoreResult(result);
  assert.equal(perCwe['CWE-89'].tp, 1);
  assert.equal(perCwe['CWE-22'].fp, 1);
  assert.equal(perCwe['CWE-22'].tp, 0);
});
