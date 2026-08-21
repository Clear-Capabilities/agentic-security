// Every finding must carry a CWE — the schema in CLAUDE.md says so, and nothing
// backfills it. `report/index.js#normalizeFindings` does `cwe: f.cwe || null`,
// so a detector that omits it ships `null` all the way to SARIF and to every
// CWE-keyed compliance map.
//
// The concurrency checker omitted it on all three of its finding shapes. That
// was invisible in ordinary use — the findings looked complete — but it meant
// 273 findings on a 12-entry Go sample could never match an advisory's CWE, so
// they were structurally excluded from the benchmark's accuracy measurement.
//
// These tests pin the field on each shape independently. A single aggregate
// assertion would pass while two of the three regressed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanConcurrency } from '../src/posture/concurrency-checker.js';

const CWE_SHAPE = /^CWE-\d+$/;

function cwesFor(files) {
  return scanConcurrency(files).map((f) => ({ vuln: f.vuln, cwe: f.cwe }));
}

test('an early return that skips Unlock carries CWE-667 (improper locking)', () => {
  const found = cwesFor({
    'svc.go': [
      'func (s *Store) Get(k string) (string, error) {',
      '\ts.mu.Lock()',
      '\tif k == "" {',
      '\t\treturn "", errEmpty',
      '\t}',
      '\tv := s.data[k]',
      '\ts.mu.Unlock()',
      '\treturn v, nil',
      '}',
    ].join('\n'),
  });

  assert.ok(found.length > 0, 'fixture must produce a locking finding');
  const lock = found.find((f) => /acquires|without releasing/.test(f.vuln));
  assert.ok(lock, `expected a lock finding, got ${JSON.stringify(found)}`);
  assert.equal(lock.cwe, 'CWE-667');
});

test('every concurrency finding carries a well-formed CWE', () => {
  const found = cwesFor({
    'svc.go': [
      'func (s *Store) Get(k string) (string, error) {',
      '\ts.mu.Lock()',
      '\tif k == "" {',
      '\t\treturn "", errEmpty',
      '\t}',
      '\ts.mu.Unlock()',
      '\treturn "", nil',
      '}',
    ].join('\n'),
    'app.py': [
      'import asyncio',
      'def handler(req):',
      '    lock.acquire()',
      '    if not req:',
      '        return None',
      '    lock.release()',
      '    return 1',
    ].join('\n'),
  });

  assert.ok(found.length > 0, 'fixtures must produce findings to check');
  const missing = found.filter((f) => !CWE_SHAPE.test(String(f.cwe || '')));
  assert.deepEqual(
    missing,
    [],
    `findings without a valid cwe: ${JSON.stringify(missing, null, 1)}`,
  );
});

// Negative controls. Without these, a rule that fired on every Go function
// would satisfy the assertions above — they only check the shape of the
// findings that exist, not that the detector still discriminates.
//
// Both guards were written to match a BARE receiver (`defer mu.Unlock()`,
// `with lock:`) and so missed the qualified form (`defer s.mu.Unlock()`,
// `with self.lock:`) — which is the more common shape in real code, because a
// mutex is usually a struct field or an instance attribute rather than a
// package-level variable. The acquire patterns always handled the qualified
// form (`\b(\w+)\.Lock\(\)` captures `mu` from `s.mu.Lock()`), so the two
// halves disagreed and the most idiomatic correct code was the most likely to
// be reported.
const lockFindings = (files) =>
  cwesFor(files).filter((f) => /acquires|without releasing/.test(f.vuln));

for (const [name, src] of [
  ['bare', ['func Get(k string) string {', '\tmu.Lock()', '\tdefer mu.Unlock()', '\treturn d[k]', '}']],
  ['qualified', ['func (s *Store) Get(k string) string {', '\ts.mu.Lock()', '\tdefer s.mu.Unlock()', '\treturn s.data[k]', '}']],
]) {
  test(`go: defer Unlock on a ${name} receiver is not a missed unlock`, () => {
    assert.deepEqual(lockFindings({ 'ok.go': src.join('\n') }), []);
  });
}

for (const [name, src] of [
  ['bare', ['def h(r):', '    with lock:', '        lock.acquire()', '        if not r:', '            return None', '        lock.release()', '        return 1']],
  ['qualified', ['def h(self, r):', '    with self.lock:', '        self.lock.acquire()', '        if not r:', '            return None', '        self.lock.release()', '        return 1']],
]) {
  test(`py: a ${name} \`with\` context manager is not a missed unlock`, () => {
    assert.deepEqual(lockFindings({ 'ok.py': src.join('\n') }), []);
  });
}

test('go: a defer whose lock name merely ENDS WITH this one does not guard it', () => {
  // The receiver prefix is matched with a flat `[\w$.]*` (a nested-quantifier
  // form is a ReDoS shape — this project's own CWE-1333 detector rejects it),
  // so a word boundary is the only thing stopping `s.notmu.Unlock()` from
  // satisfying a lock named `mu`.
  const found = lockFindings({
    'near.go': [
      'func (s *Store) Get(k string) string {',
      '\ts.mu.Lock()',
      '\tdefer s.notmu.Unlock()',
      '\tif k == "" {',
      '\t\treturn ""',
      '\t}',
      '\ts.mu.Unlock()',
      '\treturn s.data[k]',
      '}',
    ].join('\n'),
  });

  assert.ok(
    found.some((f) => /\bmu\b/.test(f.vuln)),
    `mu is not deferred and must still be reported, got ${JSON.stringify(found)}`,
  );
});

test('go: a defer for a DIFFERENT lock does not guard this one', () => {
  // The guard must be per-lock. A body-wide "is there any defer Unlock"
  // test clears every lock in the function as soon as one is deferred.
  const found = lockFindings({
    'two.go': [
      'func (s *Store) Move(k string) error {',
      '\ts.mu.Lock()',
      '\tdefer s.mu.Unlock()',
      '\ts.other.Lock()',
      '\tif k == "" {',
      '\t\treturn errEmpty',
      '\t}',
      '\ts.other.Unlock()',
      '\treturn nil',
      '}',
    ].join('\n'),
  });

  assert.ok(
    found.some((f) => /other/.test(f.vuln)),
    `expected the undeferred lock to be reported, got ${JSON.stringify(found)}`,
  );
});
