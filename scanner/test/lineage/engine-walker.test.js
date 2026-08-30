import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity, identitiesAt } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';

test('a straight-line assignment chain propagates identity through to the return', () => {
  // function f(user) { const email = user.email; return email; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n3',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'email', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'return', line: 1, succ: ['n3'], pred: ['n1'], value: { kind: 'ident', name: 'email' } },
        n3: { kind: 'exit', line: 1, succ: [], pred: ['n2'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

test('reassignment clears stale identity at that path', () => {
  // function f(user) { let x = user.email; x = user.name; return x; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n4',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'name' } },
        n3: { kind: 'return', line: 3, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'x' } },
        n4: { kind: 'exit', line: 3, succ: [], pred: ['n3'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.name', 'data:name');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:name'], 'x must carry only the LAST assignment\'s identity, not both');
});

test('a branch join unions identities from both paths (conservative: either could have executed)', () => {
  // function f(user, flag) { let x; if (flag) { x = user.email; } else { x = user.name; } return x; }
  const fn = {
    params: ['user', 'flag'],
    cfg: {
      entry: 'n0', exit: 'n5',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'if', line: 1, succ: ['n2', 'n3'], pred: ['n0'], cond: { kind: 'ident', name: 'flag' } },
        n2: { kind: 'assign', line: 2, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n3: { kind: 'assign', line: 3, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'name' } },
        n4: { kind: 'return', line: 4, succ: ['n5'], pred: ['n2', 'n3'], value: { kind: 'ident', name: 'x' } },
        n5: { kind: 'exit', line: 4, succ: [], pred: ['n4'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.name', 'data:name');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:name']);
});

test('mutatedParams reports identities written onto a parameter\'s own path by the function body', () => {
  // function f(target, user) { target.copiedEmail = user.email; }
  const fn = {
    params: ['target', 'user'],
    cfg: {
      entry: 'n0', exit: 'n2',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'target.copiedEmail', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'exit', line: 1, succ: [], pred: ['n1'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.mutatedParams.get('target')], ['data:email']);
});

test('an unresolved call\'s widening event is recorded, not silently dropped', () => {
  // function f(secret) { return someFn(secret); }
  const fn = {
    params: ['secret'],
    cfg: {
      entry: 'n0', exit: 'n2',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'return', line: 1, succ: ['n2'], pred: ['n0'],
          value: { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'ident', name: 'secret' }] } },
        n2: { kind: 'exit', line: 1, succ: [], pred: ['n1'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'secret', 'data:x');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.widenings.length, 1);
  assert.equal(result.widenings[0].reason, 'unresolved-call');
  assert.deepEqual(result.widenings[0].dataElementIds, ['data:x']);
});

test('a simple loop back-edge converges (does not infinite-loop) and preserves the identity carried around it', () => {
  // function f(user) { let x = user.email; while (cond) { } return x; }
  // (loop body doesn't touch x — this just proves the worklist terminates on a back-edge)
  const fn = {
    params: ['user', 'cond'],
    cfg: {
      entry: 'n0', exit: 'n5',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n2: { kind: 'loop-header', line: 2, succ: ['n3', 'n4'], pred: ['n1', 'n3'] },
        n3: { kind: 'noop', line: 2, succ: ['n2'], pred: ['n2'] },
        n4: { kind: 'return', line: 3, succ: ['n5'], pred: ['n2'], value: { kind: 'ident', name: 'x' } },
        n5: { kind: 'exit', line: 3, succ: [], pred: ['n4'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});
