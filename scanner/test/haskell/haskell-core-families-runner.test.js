import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarize, FAMILIES, REQUIRED_PER_LABEL } from '../../../bench/haskell-core-families/runner.mjs';

const mk = (family, label, detected, origin = 'independent') => ({ family, label, detected, confirmed: false, origin });

test('a family is claimable only with enough independent cases and enough recall', () => {
  const rs = [];
  for (let i = 0; i < REQUIRED_PER_LABEL; i++) { rs.push(mk('sql', 'vulnerable', i < 21)); rs.push(mk('sql', 'safe', false)); }
  const s = summarize(rs);
  assert.equal(s.sql.recall, 21 / 25);
  assert.equal(s.sql.status, 'meets-recall-target');
  assert.equal(s.sql.claimable, true);
  assert.equal(summarize(rs, { minRecall: 0.9 }).sql.claimable, false);
});

test('author-seed cases never count toward the required independent cases', () => {
  const rs = [];
  for (let i = 0; i < 40; i++) { rs.push(mk('cmd', 'vulnerable', true, 'author-seed')); rs.push(mk('cmd', 'safe', false, 'author-seed')); }
  const s = summarize(rs);
  assert.equal(s.cmd.recall, 1);
  assert.equal(s.cmd.status, 'insufficient-cases');
  assert.equal(s.cmd.claimable, false);
});

test('a family with no cases is unsupported and one strong family cannot lift another', () => {
  const rs = [];
  for (let i = 0; i < 25; i++) { rs.push(mk('sql', 'vulnerable', true)); rs.push(mk('sql', 'safe', false)); }
  const s = summarize(rs);
  assert.equal(s.sql.claimable, true);
  for (const fam of Object.keys(FAMILIES).filter((f) => f !== 'sql')) { assert.equal(s[fam].status, 'unsupported'); assert.equal(s[fam].claimable, false); }
});

test('a false positive on a safe case is counted against its own family', () => {
  const s = summarize([mk('path', 'vulnerable', true), mk('path', 'safe', true)]);
  assert.equal(s.path.falsePositives, 1);
  assert.equal(s.path.safeCleanRate, 0);
});
