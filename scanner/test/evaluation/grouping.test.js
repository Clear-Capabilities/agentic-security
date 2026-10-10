// QA-001.AC02: grouping before splitting. SYNTHETIC ids only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { groupTargets, assignSplits, splitStraddles, normalizeUpstream } from '../../src/posture/evaluation/grouping.js';

const T = (id, over = {}) => ({ id, upstream: `example.invalid/${id}`, preCommit: id.padEnd(40, '0').slice(0, 40).replace(/[^0-9a-f]/g, 'a'), postCommit: null, advisoryIds: [], ...over });
const groupIdsOf = (targets) => groupTargets(targets).groupOf;

describe('[QA-001.AC02] relations that join samples into one group', () => {
  test('upstream URL spellings normalise to one project', () => {
    assert.equal(normalizeUpstream('https://GitHub.com/Org/Repo.git/'), 'github.com/org/repo');
    assert.equal(normalizeUpstream('git@github.com:org/repo'), 'github.com/org/repo');
    assert.equal(normalizeUpstream(''), null);
    const g = groupIdsOf([T('a', { upstream: 'https://github.com/o/r.git' }), T('b', { upstream: 'git@github.com:o/r' })]);
    assert.equal(g.a, g.b);
  });

  test('a vulnerable/fixed pair, a shared commit, a fork, a duplicate advisory and a template each group', () => {
    const cases = {
      pair: [T('a', { pairId: 'p1' }), T('b', { pairId: 'p1' })],
      commit: [T('a', { postCommit: 'c'.repeat(40) }), T('b', { preCommit: 'c'.repeat(40) })],
      fork: [T('a', { upstream: 'example.invalid/parent' }), T('b', { forkOf: 'example.invalid/parent' })],
      advisory: [T('a', { advisoryIds: ['ghsa-1111-2222-3333'] }), T('b', { advisoryIds: ['GHSA-1111-2222-3333'] })],
      template: [T('a', { templateFingerprint: 'tpl-1' }), T('b', { templateFingerprint: 'tpl-1' })],
    };
    for (const [name, ts] of Object.entries(cases)) {
      const g = groupIdsOf(ts);
      assert.equal(g.a, g.b, `${name} must group`);
    }
  });

  test('unrelated samples stay apart, and relations are transitive', () => {
    const apart = groupIdsOf([T('a'), T('b'), T('c')]);
    assert.equal(new Set(Object.values(apart)).size, 3);
    const chain = groupIdsOf([T('a', { pairId: 'p' }), T('b', { pairId: 'p', templateFingerprint: 't' }), T('c', { templateFingerprint: 't' })]);
    assert.equal(chain.a, chain.c);
    const r = groupTargets([T('a', { pairId: 'p' }), T('b', { pairId: 'p' })]);
    assert.deepEqual(r.groups[0].reasons, ['pair']);
  });

  test('grouping does not depend on input order or object identity', () => {
    const ts = [T('a', { pairId: 'p' }), T('b', { pairId: 'p' }), T('c'), T('d', { templateFingerprint: 'x' }), T('e', { templateFingerprint: 'x' })];
    const a = groupTargets(ts); const b = groupTargets([...ts].reverse());
    assert.deepEqual(a.groups, b.groups);
  });
});

describe('[QA-001.AC02] splitting never separates a group', () => {
  const population = () => {
    const ts = [];
    for (let i = 0; i < 60; i++) ts.push(T(`t${String(i).padStart(2, '0')}`, { pairId: `p${Math.floor(i / 3)}` }));
    return ts;
  };

  test('no group straddles the line, for any salt (control: a naive per-target split does straddle)', () => {
    const ts = population();
    const { groups } = groupTargets(ts);
    for (const salt of ['', 'a', 'b', 'c', 'seed-9']) {
      const splits = assignSplits(groups, { sealedFraction: 0.3, salt });
      assert.deepEqual(splitStraddles(groups, splits), [], `salt ${salt}`);
      assert.equal(splits.dev.length + splits.sealed.length, ts.length);
    }
    const naive = { dev: ts.filter((_, i) => i % 2 === 0).map((t) => t.id), sealed: ts.filter((_, i) => i % 2 === 1).map((t) => t.id) };
    assert.ok(splitStraddles(groups, naive).length > 0, 'the detector must be able to see a straddle');
  });

  test('assignment is deterministic and an unrelated addition does not move existing groups', () => {
    const ts = population();
    const a = assignSplits(groupTargets(ts).groups, { salt: 's' });
    const b = assignSplits(groupTargets(ts).groups, { salt: 's' });
    assert.deepEqual(a, b);
    const more = assignSplits(groupTargets([...ts, T('zz-new')]).groups, { salt: 's' });
    for (const id of ts.map((t) => t.id)) assert.equal(a.sealed.includes(id), more.sealed.includes(id), `${id} moved`);
  });

  test('the sealed fraction is honoured approximately', () => {
    const splits = assignSplits(groupTargets(population()).groups, { sealedFraction: 0.5, salt: 'x' });
    assert.ok(splits.sealed.length > 0 && splits.dev.length > 0);
  });
});
