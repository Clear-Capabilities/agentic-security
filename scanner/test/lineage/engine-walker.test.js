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

test('FR-301 regression (final whole-branch review counter-example): a field read back off an object literal built via an intermediate variable carries ONLY its own identity, never a sibling field\'s', () => {
  // function f(user) {
  //   const rec = { email: user.email, ssn: user.ssn };
  //   const justEmail = rec.email;
  //   return justEmail;
  // }
  //
  // This is the exact shape that slipped past every individual task review:
  // the object-literal `assign` used to also write the FLAT UNION of
  // {email, ssn} at `rec`'s own path (the bug), which then leaked back into
  // `rec.email` via the (then one-directional) ancestor-coverage rule in
  // identitiesAt. Must fail against the pre-fix `assign` case (flat-union
  // write at the container's own path) and pass against the fix.
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n4',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 2, succ: ['n2'], pred: ['n0'],
          target: 'rec',
          source: {
            kind: 'object',
            props: [
              { key: 'email', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
              { key: 'ssn', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'ssn' } },
            ],
          } },
        n2: { kind: 'assign', line: 3, succ: ['n3'], pred: ['n1'],
          target: 'justEmail', source: { kind: 'member', object: { kind: 'ident', name: 'rec' }, prop: 'email' } },
        n3: { kind: 'return', line: 4, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'justEmail' } },
        n4: { kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'],
    'justEmail must carry ONLY data:email — data:ssn must never leak in via rec');
});

test('returnFacts deduplicates a revisited return node instead of pushing a stale duplicate entry (Fix 2 regression)', () => {
  // A diamond CFG where the join node (n4, the return) is reached by the
  // worklist BEFORE both of its predecessors have contributed their state,
  // forcing at least one revisit before the incoming join settles:
  //
  //   n0 (entry) -> n1 (if)
  //   n1 -> n2 (assign x = user.email) -> n4 (return x)
  //   n1 -> n3 (assign x = user.ssn)   -> n4 (return x)
  //
  // n4's succ list is ordered so its FIRST predecessor to reach it (n2) is
  // processed, queuing n4; n4 runs and records a returnFact carrying only
  // data:email (n3 hasn't run yet). n3 then runs, joins into n4's inState,
  // and re-queues n4 — a genuine revisit. Before Fix 2, this produced TWO
  // entries in returnFacts for the same nodeId, the first stale and missing
  // data:ssn.
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n5',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'if', line: 1, succ: ['n2', 'n3'], pred: ['n0'], cond: { kind: 'ident', name: 'flag' } },
        n2: { kind: 'assign', line: 2, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n3: { kind: 'assign', line: 3, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'ssn' } },
        n4: { kind: 'return', line: 4, succ: ['n5'], pred: ['n2', 'n3'], value: { kind: 'ident', name: 'x' } },
        n5: { kind: 'exit', line: 4, succ: [], pred: ['n4'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  const factsForN4 = result.returnFacts.filter(f => f.nodeId === 'n4');
  assert.equal(factsForN4.length, 1, 'exactly one returnFacts entry for the revisited return node, not a stale duplicate');
  assert.deepEqual([...factsForN4[0].identities].sort(), ['data:email', 'data:ssn'],
    'the single entry must carry the UNION of every branch, not just whichever branch happened to reach the node first');
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
