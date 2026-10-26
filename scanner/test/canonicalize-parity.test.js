// canonicalize() and setsEqual() were rewritten for speed (prefix lookups instead of a scan of every kept
// path; an identical-members fast path). The result must be exactly what the original quadratic definition gives,
// element for element and in the same order.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, setsEqual, joinSets, hashSet, pathIsCoveredByPrefix } from '../src/dataflow/access-paths.js';

function referenceCanonicalize(set) {
  if (!set || set.size <= 1) return new Set(set || []);
  const sorted = [...set].sort((a, b) => a.length - b.length || (a < b ? -1 : 1));
  const out = new Set();
  for (const path of sorted) {
    let covered = false;
    for (const existing of out) {
      if (pathIsCoveredByPrefix(path, existing)) { covered = true; break; }
    }
    if (!covered) out.add(path);
  }
  return out;
}

function referenceSetsEqual(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  const ca = referenceCanonicalize(a), cb = referenceCanonicalize(b);
  if (ca.size !== cb.size) return false;
  for (const x of ca) if (!cb.has(x)) return false;
  return true;
}

let seed = 987654321;
const rnd = (n) => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed % n; };
const SEGS = ['a', 'b', 'c', 'ab', '*', '[]', '_this_', 'x1'];
function randomPath() {
  const depth = 1 + rnd(4);
  const parts = [];
  for (let i = 0; i < depth; i++) parts.push(SEGS[rnd(SEGS.length)]);
  return parts.join('.');
}
function randomSet(max) {
  const s = new Set();
  const n = rnd(max);
  for (let i = 0; i < n; i++) s.add(randomPath());
  return s;
}

test('canonicalize matches the original definition on random path sets', () => {
  for (let i = 0; i < 4000; i++) {
    const s = randomSet(14);
    assert.deepEqual([...canonicalize(s)], [...referenceCanonicalize(s)], JSON.stringify([...s]));
  }
});

test('canonicalize matches on sets with unusual members', () => {
  const odd = [
    new Set(['', 'a', '.a', 'a.', 'a..b', '.', 'a.b']),
    new Set(['a', 'a.b', 'a.b.c', 'a.bc', 'ab', 'a.']),
    new Set([1, 'a', 'a.b']),
    new Set(['a', null, 'a.b', undefined]),
  ];
  for (const s of odd) {
    let expected; let actual; let expectedThrows = false; let actualThrows = false;
    try { expected = [...referenceCanonicalize(s)]; } catch { expectedThrows = true; }
    try { actual = [...canonicalize(s)]; } catch { actualThrows = true; }
    assert.equal(actualThrows, expectedThrows, JSON.stringify([...s]));
    if (!expectedThrows) assert.deepEqual(actual, expected, JSON.stringify([...s]));
  }
});

test('setsEqual and joinSets/hashSet agree with the original definition', () => {
  for (let i = 0; i < 4000; i++) {
    const a = randomSet(10); const b = rnd(3) === 0 ? new Set(a) : randomSet(10);
    assert.equal(setsEqual(a, b), referenceSetsEqual(a, b), JSON.stringify([[...a], [...b]]));
    assert.deepEqual([...joinSets(a, b)], [...referenceCanonicalize(new Set([...a, ...b]))]);
    assert.equal(hashSet(a), [...referenceCanonicalize(a)].sort().join('|') || 'empty');
  }
  // sets that are equal only after canonicalization still compare equal
  assert.equal(setsEqual(new Set(['x']), new Set(['x', 'x.y'])), true);
  assert.equal(setsEqual(new Set(['x.y']), new Set(['x'])), false);
  assert.equal(setsEqual(null, new Set()), false);
});
