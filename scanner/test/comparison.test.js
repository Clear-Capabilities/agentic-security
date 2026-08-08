// PRD Epic 7.2 — head-to-head comparison scoring.
//
// The number on the table is the least interesting thing here. What the tests
// pin is the exam: that every participant is scored over the same entries, that
// a participant which could not run somewhere is unscored there rather than
// marked wrong, and that the report says both of those things before it shows a
// single rate.
import test from 'node:test';
import assert from 'node:assert/strict';

import { compareParticipants, renderComparison, scoreParticipant } from '../src/posture/comparison.js';

const entries = [
  { id: 'e1', cwe: 'CWE-89' },
  { id: 'e2', cwe: 'CWE-78' },
  { id: 'e3', cwe: 'CWE-22' },
];

const perfect = {
  e1: { pre: [{ cwe: 'CWE-89' }], post: [] },
  e2: { pre: [{ cwe: 'CWE-78' }], post: [] },
  e3: { pre: [{ cwe: 'CWE-22' }], post: [] },
};

test('a participant that detects everything and reports nothing on the fixed tree scores 100%', () => {
  const cmp = compareParticipants(entries, [
    { id: 'a', results: perfect },
    { id: 'b', results: perfect },
  ]);
  assert.equal(cmp.ok, true);
  assert.equal(cmp.scores[0].f1, 1);
  assert.equal(cmp.scores[0].fp, 0);
});

test('a finding that persists on the FIXED tree is a false positive', () => {
  const noisy = {
    e1: { pre: [{ cwe: 'CWE-89' }], post: [{ cwe: 'CWE-89' }] },
    e2: { pre: [{ cwe: 'CWE-78' }], post: [] },
    e3: { pre: [{ cwe: 'CWE-22' }], post: [] },
  };
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: noisy }]);
  const b = cmp.scores.find((s) => s.id === 'b');
  assert.equal(b.fp, 1);
  assert.ok(b.precision < 1);
});

test('rates are computed over the INTERSECTION, never over each participant\'s own subset', () => {
  // The failure this module exists to prevent: `b` crashed on the entry it
  // would have missed. Scored over its own completions it looks perfect.
  const partial = { ...perfect };
  delete partial.e3;
  partial.e3 = { error: 'crashed' };

  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: partial }]);
  assert.equal(cmp.intersection, 2, 'the crashed entry must drop out of BOTH participants\' scores');
  const a = cmp.scores.find((s) => s.id === 'a');
  assert.equal(a.tp, 2, 'the complete participant must be scored on the same two entries, not on three');
  assert.equal(a.completed, 3, 'and its own completion count must still be reported honestly');
});

test('an entry a participant could not run is UNSCORED, never counted as a miss', () => {
  const broken = { e1: { error: 'timed out' }, e2: perfect.e2, e3: perfect.e3 };
  const { per, completed } = scoreParticipant(entries, broken);
  assert.equal(completed, 2);
  assert.equal(per.has('e1'), false, 'a crash must not appear in the score at all');
});

test('participants with no entries in common are refused rather than shown', () => {
  const cmp = compareParticipants(entries, [
    { id: 'a', results: { e1: perfect.e1 } },
    { id: 'b', results: { e2: perfect.e2 } },
  ]);
  assert.equal(cmp.ok, false);
  assert.match(cmp.reason, /nothing they can be compared on/);
  assert.deepEqual(cmp.completion, { a: 1, b: 1 });
});

test('a comparison needs at least two participants', () => {
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }]);
  assert.equal(cmp.ok, false);
  assert.match(cmp.reason, /at least two/);
});

test('CWEs are read out of a SARIF-style ruleId as well as a cwe field', () => {
  const viaRuleId = {
    e1: { pre: [{ ruleId: 'sql-inject external/cwe/cwe-89' }], post: [] },
    e2: { pre: [{ ruleId: 'CWE_78_command' }], post: [] },
    e3: { pre: [{ ruleId: 'nothing-relevant' }], post: [] },
  };
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: viaRuleId }]);
  const b = cmp.scores.find((s) => s.id === 'b');
  assert.equal(b.tp, 2, 'both CWE spellings should match');
  assert.equal(b.fn, 1);
});

test('findings carrying no CWE are counted and disclosed, not silently missed', () => {
  const noCwe = {
    e1: { pre: [{ message: 'something is wrong' }], post: [] },
    e2: perfect.e2, e3: perfect.e3,
  };
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: noCwe }]);
  const b = cmp.scores.find((s) => s.id === 'b');
  assert.equal(b.noCwe, 1);
  const md = renderComparison(cmp);
  assert.match(md, /carrying no CWE/);
  assert.match(md, /reporting-format reason rather than a detection one/);
});

test('the report discloses the exam before the grades', () => {
  const partial = { ...perfect, e3: { error: 'crashed' } };
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: partial }]);
  const md = renderComparison(cmp);
  const disclosure = md.indexOf('that *every*');
  const table = md.indexOf('| Participant |');
  assert.ok(disclosure > -1 && disclosure < table, 'the intersection must be stated above the table');
  assert.match(md, /not completed/);
  assert.match(md, /never scored as a\nmiss/);
});

test('a refused comparison renders as NOT SCORED, never as an empty table', () => {
  const md = renderComparison({ ok: false, reason: 'nope' });
  assert.match(md, /NOT SCORED: nope/);
  assert.ok(!md.includes('| Participant |'));
});

test('the scored entry ids are published so the exam can be checked', () => {
  const cmp = compareParticipants(entries, [{ id: 'a', results: perfect }, { id: 'b', results: perfect }]);
  assert.deepEqual(cmp.scoredEntryIds, ['e1', 'e2', 'e3']);
});

test('nothing in the shipped harness names a participant', async () => {
  // The constraint is structural, not editorial: the module and its driver must
  // carry no tool name, so the comparison is always the operator's to define.
  const fs = await import('node:fs');
  const url = await import('node:url');
  const path = await import('node:path');
  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const sources = [
    fs.readFileSync(path.join(here, '..', 'src', 'posture', 'comparison.js'), 'utf8'),
    fs.readFileSync(path.join(here, '..', '..', 'scripts', 'comparison.mjs'), 'utf8'),
  ].join('\n');
  // A deliberately blunt check: any of these appearing would mean the harness
  // had started shipping an opinion about who the competitors are.
  for (const banned of [/\bsemgrep\b/i, /\bsnyk\b/i, /\bsonar/i, /\bcheckmarx\b/i,
    /\bveracode\b/i, /\bfortify\b/i, /\bbandit\b/i, /\bcodeql\b/i, /\btrivy\b/i]) {
    assert.ok(!banned.test(sources), `the comparison harness names a participant: ${banned}`);
  }
});
