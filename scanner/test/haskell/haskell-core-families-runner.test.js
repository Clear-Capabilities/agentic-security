import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarize, FAMILIES, REQUIRED_PER_LABEL, wilson } from '../../../bench/haskell-core-families/runner.mjs';
import { validateReview, adjudicate, mergeIntoManifest, freezeDigests, holdoutRefusal } from '../../../bench/haskell-core-families/adjudicate.mjs';

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

// PRD FR 04 "Benchmark design": two reviewers label without the scanner's verdict; disagreements and unresolved labels are tracked and
// never become benign controls; the holdout is frozen before it is scored.
const L = (file, label, extra = {}) => ({ file, family: 'sql', group: `g-${file}`, split: 'dev', origin: 'published-fix:x', label, ...extra });
const R = (reviewer, labels, blind = true) => ({ reviewer, blind, labels });

test('a reviewer file must declare blind labelling, and author-seed origins are refused', () => {
  assert.equal(validateReview(R('a', [L('x.hs', 'safe')])).ok, true);
  assert.match(validateReview(R('a', [L('x.hs', 'safe')], false)).reason, /blind: true/);
  assert.match(validateReview(R('a', [L('x.hs', 'safe', { origin: 'author-seed' })])).reason, /not independent/);
  assert.match(validateReview(R('a', [L('x.hs', 'maybe')])).reason, /incomplete label/);
});

test('only unanimous two-reviewer labels are added; disagreement, unsure and single-reviewer cases are unresolved', () => {
  const res = adjudicate([
    R('a', [L('agree.hs', 'vulnerable'), L('split.hs', 'safe'), L('unsure.hs', 'safe'), L('solo.hs', 'safe')]),
    R('b', [L('agree.hs', 'vulnerable'), L('split.hs', 'vulnerable'), L('unsure.hs', 'unsure')]),
  ]);
  assert.deepEqual(res.agreed.map((c) => [c.file, c.label]), [['agree.hs', 'vulnerable']]);
  assert.deepEqual(res.unresolved.map((u) => [u.file, u.reason]).sort(), [
    ['solo.hs', 'fewer than two reviewers'], ['split.hs', 'reviewers disagree on the label'], ['unsure.hs', 'a reviewer is unsure'],
  ]);
  assert.ok(!res.agreed.some((c) => c.label === 'safe'), 'an unresolved label never becomes a benign control');
  assert.equal(res.agreement.cases, 3); assert.equal(res.agreement.agreed, 1);
  assert.ok(res.agreement.kappa < 0.5, 'kappa reports chance-corrected agreement');
});

test('a vulnerable case and its fixed pair cannot be split across dev and holdout', () => {
  const m = { cases: [{ file: 'v.hs', group: 'g1', split: 'dev' }] };
  assert.equal(mergeIntoManifest(m, [{ file: 'f.hs', group: 'g2', split: 'holdout' }]).added, 1);
  assert.throws(() => mergeIntoManifest(m, [{ file: 'f.hs', group: 'g1', split: 'holdout' }]), /spans two splits/);
  assert.equal(mergeIntoManifest(m, [{ file: 'v.hs', group: 'g1', split: 'dev' }]).added, 0, 'never added twice');
});

test('the holdout is scored only under a freeze that still matches the manifest and the definitions', () => {
  const f = freezeDigests({ manifestText: 'm1', runnerText: 'r1' });
  assert.match(holdoutRefusal(null, f), /not frozen/);
  assert.equal(holdoutRefusal(f, freezeDigests({ manifestText: 'm1', runnerText: 'r1' })), null);
  assert.match(holdoutRefusal(f, freezeDigests({ manifestText: 'm2', runnerText: 'r1' })), /manifest changed/);
  assert.match(holdoutRefusal(f, freezeDigests({ manifestText: 'm1', runnerText: 'r2' })), /definitions/);
});

test('recall carries a 95% Wilson interval', () => {
  const [lo, hi] = wilson(21, 25);
  assert.ok(lo > 0.63 && lo < 0.66 && hi > 0.93 && hi < 0.95, `${lo} ${hi}`);
  assert.equal(wilson(0, 0), null);
});
