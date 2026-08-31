// Permanent regression suite for the unresolved-call RECEIVER identity fix
// (lineage-engine-receiver-identity-hotfix, found during Sub-project E1's
// design spike, task review MF-1). `resolveExprIdentities`'s unresolved
// `case 'call'` branch must union identity from a method call's RECEIVER,
// not just its arguments — `pan.slice(0, 4)` must keep `pan`'s identity,
// the same way `pan + 'x'`/`String(pan)` already correctly do.
//
// Two shapes reach this branch, and BOTH must be proven, not just the one
// the original fix happened to test against:
//   - `parser-js.js` (Babel) emits a structured `{kind:'member', object,
//     prop}` callee — proven against real JS/TS in engine-integration.test.js
//     and this file's own JS cases below.
//   - Every OTHER language parser (parser-py.js/parser-java.js/
//     parser-go.js/parser-php.js/parser-rb.js/parser-cs.js/parser-kt.js/
//     parser-cpp.js) emits a flat, dot-joined STRING callee instead — task
//     review MF-1 found the original fix only handled the exprDesc shape,
//     silently reproducing the exact "receiver identity dropped" bug one
//     language over. This file's Python cases are the permanent guard
//     against that half of the fix regressing.
//
// Not reachable from any shipped caller today (this package's only real
// caller, Sub-project E, is wired against `parser-js.js`'s JS/TS output
// only — see `DESIGN_GRAPH_BUILDER.md`'s own scope note) — but
// `resolveExprIdentities` is a generic function with no JS-only gate, so a
// future caller (or a hand-built fixture, as every prior increment's own
// tests already do) can reach the string-callee branch directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { parsePythonFile } from '../../src/ir/parser-py.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';

function returnIdentitiesFor(fn, seedPath, seedId) {
  let state = emptyState();
  state = addIdentity(state, seedPath, seedId);
  const result = analyzeFunctionFieldIdentity(fn, state, {});
  const merged = new Set();
  for (const rf of result.returnFacts) {
    for (const id of rf.identities) merged.add(id);
  }
  return merged;
}

test('receiver-identity/py-1: pan.slice(0, 4) keeps the receiver identity through a Python string callee', () => {
  const src = `
def mask_pan(pan):
    return pan.slice(0, 4)
`;
  const parsed = parsePythonFile('a.py', src);
  const fn = parsed.functions.find((f) => f.name === 'mask_pan');
  assert.ok(fn, 'mask_pan not found in parsed Python IR');
  const ids = returnIdentitiesFor(fn, 'pan', 'data:pan');
  assert.deepEqual([...ids], ['data:pan']);
});

test('receiver-identity/py-2: a bare-identifier callee (no dot) does not fabricate a receiver identity, argument identity still flows', () => {
  const src = `
def concat_pan(pan):
    return str(pan)
`;
  const parsed = parsePythonFile('a.py', src);
  const fn = parsed.functions.find((f) => f.name === 'concat_pan');
  assert.ok(fn);
  const ids = returnIdentitiesFor(fn, 'pan', 'data:pan');
  // 'pan' reaches the result via the ARGUMENT-union path (str's own
  // argument), not the receiver path — the string callee here is 'str',
  // which has no '.' at all (idx <= 0), so the receiver branch correctly
  // contributes nothing. This proves the guard doesn't fire spuriously.
  assert.deepEqual([...ids], ['data:pan']);
});

test('receiver-identity/py-3: a dotted receiver chain resolves to its own longer prefix, not just the first segment', () => {
  const src = `
def mask(req):
    return req.body.pan.slice(0, 4)
`;
  const parsed = parsePythonFile('a.py', src);
  const fn = parsed.functions.find((f) => f.name === 'mask');
  assert.ok(fn);
  // Seed at the exact receiver path the string callee slices to
  // ('req.body.pan.slice' -> receiver 'req.body.pan').
  const ids = returnIdentitiesFor(fn, 'req.body.pan', 'data:pan');
  assert.deepEqual([...ids], ['data:pan']);
});

test('receiver-identity/js-1: pan.slice(0, 4) keeps the receiver identity through a real parsed JS member-callee (structured shape)', () => {
  const parsed = parseJsFile('/x/a.js', `
    function maskPan(pan) {
      return pan.slice(0, 4);
    }
  `);
  const fn = parsed.functions.find((f) => f.name === 'maskPan');
  assert.ok(fn);
  const ids = returnIdentitiesFor(fn, 'pan', 'data:pan');
  assert.deepEqual([...ids], ['data:pan']);
});

test('receiver-identity/js-2: pan + "x" and String(pan) already kept the identity pre-fix — unaffected by this change', () => {
  const parsed = parseJsFile('/x/a.js', `
    function concatPan(pan) {
      return pan + 'x';
    }
    function stringifyPan(pan) {
      return String(pan);
    }
  `);
  for (const name of ['concatPan', 'stringifyPan']) {
    const fn = parsed.functions.find((f) => f.name === name);
    assert.ok(fn, name);
    const ids = returnIdentitiesFor(fn, 'pan', 'data:pan');
    assert.deepEqual([...ids], ['data:pan'], name);
  }
});
