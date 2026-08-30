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
  // A diamond CFG where the join node (n4, the return) is revisited by the
  // worklist: both of its predecessors (n2, n3) are siblings under the same
  // `if`, so both get queued together and BOTH run (iterations 3 and 4)
  // before n4 is first dequeued (iteration 5) — under this CFG's FIFO
  // timing, n4's incoming join has therefore already settled to the full
  // union by its first visit. So pre-fix (a plain push on every visit) this
  // specific CFG does NOT reproduce a stale-then-correct pair; it reproduces
  // the OTHER half of the original bug: n4 gets dequeued twice (once queued
  // by n2's run, once by n3's run), so it runs twice and pushes two
  // IDENTICAL full-union entries for the same nodeId. That is still a real,
  // separate violation of "one entry per node" (a naive `.find(nodeId)`
  // consumer only sees the first anyway, but `.filter(nodeId)` or a length
  // assertion would wrongly see 2), and this test remains a valid regression
  // guard for it. It does NOT exercise the stale-weaker-entry half of the
  // bug — see the "skewed CFG" test below for that.
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

test('returnFacts unions a genuinely STALE, weaker first visit with a later, stronger one (skewed-timing regression, complementary to the test above)', () => {
  // A CFG deliberately skewed so the two branches reach the return node at
  // DIFFERENT worklist times, unlike the symmetric diamond above: the
  // data:ssn branch (n3) has an extra intermediate hop (n3b, a noop) before
  // it reaches the return node (n4), while the data:email branch (n2) goes
  // straight there.
  //
  //   n0 (entry) -> n1 (if)
  //   n1 -> n2 (assign x = user.email) -----------> n4 (return x)
  //   n1 -> n3 (assign x = user.ssn) -> n3b (noop) -> n4
  //
  // Trace (FIFO worklist): n2 and n3 both run before n4 is first queued.
  // n2's run queues n4 with ONLY n2's contribution (x = {email}) — n3's
  // contribution hasn't reached n4 yet, it's still sitting at n3b. n4 is
  // dequeued and runs with this partial state: a genuinely stale returnFact
  // carrying only data:email. n3b then runs, propagates n3's state into
  // n4's inState (joining to {email, ssn}), and re-queues n4. n4 runs again
  // with the full union. Pre-fix (a plain push on every visit — see git
  // history on Fix 2), this produces a real [stale {email}, correct
  // {email, ssn}] pair, in that order — exercising the more consequential
  // half of the original bug that the symmetric-diamond test above does
  // not. Confirmed via temporary revert of round 1's Fix 2 (the
  // returnFactsByNode Map accumulation) that this CFG shape genuinely
  // reproduces a stale-then-stronger pair before re-applying the fix.
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n6',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'if', line: 1, succ: ['n2', 'n3'], pred: ['n0'], cond: { kind: 'ident', name: 'flag' } },
        n2: { kind: 'assign', line: 2, succ: ['n4'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
        n3: { kind: 'assign', line: 3, succ: ['n3b'], pred: ['n1'],
          target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'ssn' } },
        n3b: { kind: 'noop', line: 3, succ: ['n4'], pred: ['n3'] },
        n4: { kind: 'return', line: 4, succ: ['n6'], pred: ['n2', 'n3b'], value: { kind: 'ident', name: 'x' } },
        n6: { kind: 'exit', line: 4, succ: [], pred: ['n4'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  const factsForN4 = result.returnFacts.filter(f => f.nodeId === 'n4');
  assert.equal(factsForN4.length, 1, 'exactly one returnFacts entry for the revisited return node, not a stale-then-correct pair');
  assert.deepEqual([...factsForN4[0].identities].sort(), ['data:email', 'data:ssn'],
    'the single entry must carry the FULL unioned identity set, not the first (weaker, stale) visit\'s partial one');
});

test('aliasing an object through a plain variable keeps field isolation through the alias (regression — a final review found this survives round 1\'s fix)', () => {
  // function f(user) { const copy = user; const e = copy.email; return e; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n4',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'], target: 'copy', source: { kind: 'ident', name: 'user' } },
        n2: { kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'], target: 'e', source: { kind: 'member', object: { kind: 'ident', name: 'copy' }, prop: 'email' } },
        n3: { kind: 'return', line: 3, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'e' } },
        n4: { kind: 'exit', line: 3, succ: [], pred: ['n3'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

test('aliasing an object and returning the WHOLE alias still aggregates every field (complementary to the isolation test above — proves the fix does not break whole-object reads)', () => {
  // function f(user) { const copy = user; return copy; }
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n3',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'], target: 'copy', source: { kind: 'ident', name: 'user' } },
        n2: { kind: 'return', line: 2, succ: ['n3'], pred: ['n1'], value: { kind: 'ident', name: 'copy' } },
        n3: { kind: 'exit', line: 2, succ: [], pred: ['n2'] },
      },
    },
  };
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);
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
