// PRD T4.2 — unbounded, caller-influenced allocation/iteration size.
//
// The largest unimplemented class in the PRD's evidence table (14 of the 96
// root-caused real-world misses). Distinct from ReDoS: redos-nfa.js covers
// regex backtracking and correctly reports "safe" for a polynomial .split()
// DoS, and none of these entries involve a regex at all.
//
// The design bet is that condition 3 (no upper-bound check in the window) is
// what makes this shippable: a single `if (n > MAX)` is exactly the fix each
// advisory shipped, so the detector discriminates fixed from vulnerable by
// construction rather than by tuning. Every test below pins one direction.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanResourceExhaustion, _internals } from '../src/sast/resource-exhaustion.js';

test('Python: range() sized from a caller-controlled field fires', () => {
  const f = scanResourceExhaustion('cmap.py',
    'def widths(params):\n    out = {}\n    for i in range(params["stop"]):\n        out[i] = 1\n    return out\n');
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-400');
  assert.equal(f[0].family, 'resource-exhaustion');
  assert.ok(f[0].checkedFor, 'an absence-claim must record what it looked for (T2.2)');
});

test('FIX-DISCRIMINATION: an upper-bound check silences it', () => {
  const f = scanResourceExhaustion('cmap.py',
    'MAX_W = 1000\ndef widths(params):\n    n = params["stop"]\n    if n > MAX_W:\n        raise ValueError("too many")\n    for i in range(n):\n        pass\n');
  assert.deepEqual(f, [], 'the bound is the fix; the finding must disappear');
});

test('REFUSES: a constant size is not caller-controlled', () => {
  assert.deepEqual(scanResourceExhaustion('a.py', 'def f():\n    for i in range(500):\n        pass\n'), []);
});

test('REFUSES: a local computation with no external surface', () => {
  assert.deepEqual(scanResourceExhaustion('a.py', 'def f():\n    n = compute_internal()\n    for i in range(n):\n        pass\n'), []);
});

test('JS: .repeat() sized from a request field fires, Math.min silences it', () => {
  assert.equal(scanResourceExhaustion('a.js', 'function pad(req){ return " ".repeat(req.query.width); }').length, 1);
  assert.deepEqual(
    scanResourceExhaustion('a.js', 'function pad(req){ const w = Math.min(req.query.width, 500); return " ".repeat(w); }'),
    []);
});

test('JS: new Array() and Buffer.alloc() are recognised size operations', () => {
  assert.equal(scanResourceExhaustion('a.js', 'function f(req){ return new Array(req.body.count); }').length, 1);
  assert.equal(scanResourceExhaustion('a.js', 'function f(req){ return Buffer.alloc(req.body.size); }').length, 1);
});

test('non-source files and files with no external surface are skipped cheaply', () => {
  assert.deepEqual(scanResourceExhaustion('a.go', 'for i := range req.Count {}'), []);
  assert.deepEqual(scanResourceExhaustion('a.py', 'def f():\n    return 1\n'), []);
});

test('the bound recogniser accepts the forms real fixes use', () => {
  const { BOUND_RE } = _internals;
  for (const ok of ['if n > 1000:', 'if n > MAX_ENTRIES:', 'min(n, 500)', 'Math.min(a,b)', 'raise ValueError', 'throw new Error']) {
    assert.ok(BOUND_RE.test(ok), `${ok} should read as a bound`);
  }
  assert.ok(!BOUND_RE.test('n = params["stop"]'));
});
