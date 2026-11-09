// PRD M0 and the coverage-accounting target: the pilot capture measures parse and semantic rates with failures in the denominator,
// names files without status, freezes exclusions, and the replay diff never calls itself recall.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readExclusions, exclusionRefusal, coverageMeasure, compareReports } from '../../../bench/haskell-pilot/pilot.mjs';

const cov = (over = {}) => ({ present: true, totals: { eligibleHs: 20 }, stages: { parse: { rate: 0.95, failed: 1 }, semantic: { completed: 18, rate: 0.9 } },
  byFile: { 'A.hs': { eligible: true, parse: 'parsed', flowAnalysis: 'completed' } }, incompleteEntries: [], ...over });

test('coverage meets the targets exactly at 95% parse and 90% semantic, and fails below or with a file lacking status', () => {
  assert.equal(coverageMeasure(cov()).pass, true);
  assert.match(coverageMeasure(cov({ stages: { parse: { rate: 0.94 }, semantic: { rate: 0.9 } } })).reasons.join(), /parse rate 94\.0% is below 95%/);
  assert.match(coverageMeasure(cov({ stages: { parse: { rate: 1 }, semantic: { rate: 0.89 } } })).reasons.join(), /semantic completion 89\.0% is below 90%/);
  const m = coverageMeasure(cov({ byFile: { 'A.hs': { eligible: true, parse: 'parsed' }, 'B.hs': { eligible: false } } }));
  assert.deepEqual(m.filesWithoutStatus, ['A.hs']); assert.equal(m.pass, false);
  assert.equal(coverageMeasure(null).pass, false);
});

test('exclusions need reasons, are digested order-independently, and a changed set is refused after the freeze', () => {
  assert.equal(readExclusions({ exclusions: [{ path: 'v' }] }).ok, false);
  const a = readExclusions({ exclusions: [{ path: 'a', reason: 'r' }, { path: 'b', reason: 's' }] });
  const b = readExclusions({ exclusions: [{ path: 'b', reason: 's' }, { path: 'a', reason: 'r' }] });
  assert.equal(a.digest, b.digest);
  assert.equal(exclusionRefusal(null, a.digest), null);
  assert.equal(exclusionRefusal({ digest: a.digest }, b.digest), null);
  assert.match(exclusionRefusal({ digest: a.digest }, readExclusions({ exclusions: [{ path: 'a', reason: 'r' }] }).digest), /denominator must not move/);
});

test('the replay diff lists lost and new findings, flags lost high and critical ones, and says it is not recall', () => {
  const f = (id, severity, cwe = 'CWE-89') => ({ stableId: id, file: 'A.hs', line: 1, cwe, severity, vuln: 'x' });
  const d = compareReports({ findings: [f('1', 'high'), f('2', 'low'), f('3', 'critical', 'CWE-78')] }, { findings: [f('2', 'low'), f('4', 'medium')] });
  assert.deepEqual([d.before, d.after, d.kept], [3, 2, 1]);
  assert.deepEqual(d.lostCriticalOrHigh.map((x) => x.key).sort(), ['1', '3']);
  assert.deepEqual(d.added.map((x) => x.key), ['4']);
  assert.deepEqual(d.byCwe['CWE-78'], { before: 1, after: 0 });
  assert.match(d.note, /not recall/);
});
