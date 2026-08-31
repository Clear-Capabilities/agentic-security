// Path provenance hop-recording. See scanner/src/lineage/
// DESIGN_PATH_PROVENANCE.md — the binding spec for the hop record shape and
// injection mechanism.
//
// Increment C1 (Sub-project C, Task 2) instrumented a deliberately small,
// representative FOUR-site subset only (resolveExprIdentities's
// `ident`/`object` cases, step()'s non-wildcard `assign` and `return`
// cases) — NOT full coverage (see DESIGN_PATH_PROVENANCE.md §10).
//
// Increment C2, Task 1 instrumented EVERY remaining `resolveExprIdentities`
// case per §10.1: all four `member` sub-cases (selection hops now DO fire —
// the four-site-only framing above is C1-era history, not current
// behavior), `array`/`tpl`/`binary`/`logical`/`union`, both `call` branches,
// and `assign-expr`; plus the explicit "emits nothing" verdicts for
// `literal`/`unknown`/`default`.
//
// Increment C2, Task 2 (this file, extended again) instruments `step()`'s
// three remaining cases per §10.2: the wildcard-target `assign` branch
// (`write-out/assign-weak`), the unsupported-target `assign` branch (a
// genuine loss site, `lossReason: 'unsupported-target'`), and the bare
// `call` statement (`write-out/call-arg`) — completing full intraprocedural
// coverage of both §10.1 and §10.2. `assign`'s kill
// (`removeIdentitiesAt`) deliberately gets no row of its own, per §10.2's
// own explicit verdict. Cross-file/interprocedural sites (§10.3) remain
// C3's job, out of scope here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity, identitiesAt } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity, contributingKeys, resolveExprIdentities } from '../../src/lineage/engine.js';
import { FieldIdentitySummaryCache, createCallSummaryResolver } from '../../src/lineage/summaries.js';

function parseFn(src, fnName, file = '/x/prov.js') {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must successfully parse this fixture source');
  const fn = ir.functions.find((f) => f.name === fnName);
  assert.ok(fn, `expected a function named "${fnName}" in the parsed IR`);
  return fn;
}

// Decision 8: the worklist re-emits a hop once per node VISIT, not once per
// program point — duplicates are exact repeats (monotonicity argument in
// DESIGN_PATH_PROVENANCE.md §8), so tests must assert on the deduplicated
// set, never raw emission count.
function dedupeHops(hops) {
  const seen = new Map();
  for (const h of hops) {
    const key = JSON.stringify(h, Object.keys(h).sort());
    seen.set(key, h);
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------
// 1. Opt-out is genuinely zero-cost: no `recordHop` on `ctx` (or no `ctx`
//    at all) must produce byte-identical output to calling the function
//    today, for a scenario already pinned in engine-integration.test.js.
// ---------------------------------------------------------------------

test('opt-out: no ctx at all produces the same result as before this task\'s changes (FR-301 core proof scenario)', () => {
  const src = `
function combine(user) {
  return { email: user.email, ssn: user.ssn };
}
`;
  const fn = parseFn(src, 'combine');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);
});

test('opt-out: a ctx WITHOUT recordHop (but with resolveCallSummary, mirroring Sub-project B usage) is unaffected', () => {
  const src = `
    function copyEmail(source) {
      return source.email;
    }
    function caller(user) {
      return copyEmail(user);
    }
  `;
  const ir = parseJsFile('/x/prov2.js', src);
  const calleeFn = ir.functions.find((f) => f.name === 'copyEmail');
  const callerFn = ir.functions.find((f) => f.name === 'caller');

  const resolveCallSummary = (calleeExpr, callArgs, callerState) => {
    if (calleeExpr.kind !== 'ident' || calleeExpr.name !== 'copyEmail') return null;
    let entryState = emptyState();
    // Bind source -> whatever caller's `user` carries, mirroring
    // summaries.js's entryStateFromCall in miniature for this hand-built test.
    const userIds = identitiesAt(callerState, callArgs[0].name);
    for (const id of userIds) entryState = addIdentity(entryState, 'source.email', id);
    const r = analyzeFunctionFieldIdentity(calleeFn, entryState);
    const returnFlat = new Set();
    for (const f of r.returnFacts) for (const id of f.identities) returnFlat.add(id);
    return { returnFlat, returnByPath: new Map() };
  };

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(callerFn, entryState, { resolveCallSummary });

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

// Canonicalizes a Map<path, Set<id>> (exitState / mutatedParams) into a
// sorted, iteration-order-independent array-of-arrays so two structurally
// equal Maps compare equal under assert.deepEqual regardless of insertion
// order or Set iteration order.
function canonicalizeStateMap(map) {
  return [...map.entries()]
    .map(([path, ids]) => [path, [...ids].sort()])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function canonicalizeReturnFacts(returnFacts) {
  return returnFacts
    .map((f) => ({ nodeId: f.nodeId, line: f.line, identities: [...f.identities].sort() }))
    .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
}

function canonicalizeWidenings(widenings) {
  return widenings
    .map((w) => ({ ...w, dataElementIds: [...w.dataElementIds].sort() }))
    .map((w) => JSON.stringify(w, Object.keys(w).sort()))
    .sort();
}

// Decision 1's write-only invariant, made mechanically checkable rather
// than merely asserted in prose: canonicalizes the FULL analysis result —
// all five fields the invariant names (`state`'s externally observable
// form, `exitState`; `returnFacts`; `mutatedParams`; `widenings`) — into a
// Map/Set-iteration-order-independent, JSON-comparable shape.
function canonicalizeResult({ exitState, returnFacts, mutatedParams, widenings }) {
  return {
    exitState: canonicalizeStateMap(exitState),
    returnFacts: canonicalizeReturnFacts(returnFacts),
    mutatedParams: canonicalizeStateMap(mutatedParams),
    widenings: canonicalizeWidenings(widenings),
  };
}

// ---------------------------------------------------------------------
// Sub-project C, increment 2, Task 2, Step 3: the single comprehensive
// coverage-proof fixture — a realistic function exercising EVERY
// hop-emitting case from BOTH §10.1 (Task 1's resolveExprIdentities cases)
// AND §10.2 (this task's step() cases) together. Shared by two tests
// below: it is added as one more fixture to the write-only invariant test
// (per the plan's own instruction — the field-identity-observable output
// must be identical with/without a recorder for THIS fixture too, not
// asserted as a separate, disconnected fact), and used again, with its own
// recorder, by the dedicated coverage-proof test that asserts every
// expected hop shape actually appears.
// ---------------------------------------------------------------------

function buildComprehensiveFixture() {
  const src = `
    function getPhone(source) {
      return source.phone;
    }
    function scenario(user, other, flag, k1, k2, bag) {
      var tmp, leak;
      const alias = user;
      const emailSsn = [user.email, user.ssn];
      const greeting = \`hi \${user.name}\`;
      const nextAge = user.age + 1;
      const nickname = user.nickname || other.nickname;
      const city = flag ? user.city : other.city;
      const wildcardRead = user[k1];
      const nonPathProp = (flag ? user : other).country;
      const nonPathStar = (flag ? user : other)[k2];
      const resolved = getPhone(user);
      const unresolved = helperUnknown(user.secret);
      const viaAssignExpr = (tmp = user).token;
      bag[k1] = user.payload;
      ({ leak } = user);
      logEvent(user.auditField);
      return { alias, emailSsn, greeting, nextAge, nickname, city, wildcardRead, nonPathProp, nonPathStar, resolved, unresolved, viaAssignExpr };
    }
  `;
  const ir = parseJsFile('/x/c2t2-coverage-proof.js', src);
  const calleeFn = ir.functions.find((f) => f.name === 'getPhone');
  const scenarioFn = ir.functions.find((f) => f.name === 'scenario');
  assert.ok(calleeFn && scenarioFn, 'expected both getPhone and scenario to parse');

  // A root-level identity on 'user' itself (not just its fields) is
  // deliberate, not padding: it's what makes `member`'s non-path-base,
  // prop !== '*' branch (`(flag ? user : other).country`) produce a
  // NONZERO residual — every OTHER identity below lives at a descendant
  // path ('user.email', etc.), which the ternary's own byPath already
  // fully accounts for, so without a root-level fact the residual would be
  // empty and that hop would never fire. Mirrors the "ancestor+descendant
  // coexisting" fixture already proven in the structural-guard test above.
  let entryState = addIdentity(emptyState(), 'user', 'data:blob');
  entryState = addIdentity(entryState, 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  entryState = addIdentity(entryState, 'user.name', 'data:name');
  entryState = addIdentity(entryState, 'user.age', 'data:age');
  entryState = addIdentity(entryState, 'user.nickname', 'data:nickname');
  entryState = addIdentity(entryState, 'other.nickname', 'data:other-nickname');
  entryState = addIdentity(entryState, 'user.city', 'data:city');
  entryState = addIdentity(entryState, 'other.city', 'data:other-city');
  entryState = addIdentity(entryState, 'user.payload', 'data:payload');
  entryState = addIdentity(entryState, 'user.auditField', 'data:audit');
  entryState = addIdentity(entryState, 'user.phone', 'data:phone');
  entryState = addIdentity(entryState, 'user.secret', 'data:secret');

  const resolveCallSummary = (calleeExpr, callArgs, callerState) => {
    if (calleeExpr.kind !== 'ident' || calleeExpr.name !== 'getPhone') return null;
    let calleeEntryState = emptyState();
    const userIds = identitiesAt(callerState, callArgs[0].name);
    for (const id of userIds) calleeEntryState = addIdentity(calleeEntryState, 'source.phone', id);
    const r = analyzeFunctionFieldIdentity(calleeFn, calleeEntryState);
    const returnFlat = new Set();
    for (const f of r.returnFacts) for (const id of f.identities) returnFlat.add(id);
    return { returnFlat, returnByPath: new Map() };
  };

  return { fn: scenarioFn, entryState, resolveCallSummary };
}

// ---------------------------------------------------------------------
// L1 fix-round addition: the two tests above never actually compared
// full output between a with-recorder and without-recorder run — they
// hardcoded expected `returnFacts` values only, leaving `exitState`,
// `mutatedParams`, and `widenings` (three of Decision 1's five named
// fields) completely unchecked. A reviewer confirmed this with a real
// mutant: `if (ctx?.recordHop) state = addIdentity(state, 'SIDE_EFFECT',
// 'data:leak');` injected into step()'s assign case still passed all 217
// lineage tests. This test runs each fixture TWICE — once with a recorder
// attached, once without — and deepEquals the canonicalized
// {exitState, returnFacts, mutatedParams, widenings} between the two runs,
// across a representative spread of shapes (straight-line, a wildcard
// write — a site NOT instrumented by this task, an object literal with a
// computed "*" key, a hand-built branch-join fixture that revisits a node
// per Decision 8, and a ctx that also carries resolveCallSummary). This is
// the guard C2 through C6 (roughly 20 more instrumented sites in these
// same functions) will lean on hardest.
// ---------------------------------------------------------------------

test('write-only invariant (Decision 1): attaching a recorder must not change exitState/returnFacts/mutatedParams/widenings, across a spread of fixture shapes', () => {
  const fixtures = [];

  {
    const fn = parseFn(`
function f(user) {
  const u = user;
  const o = { email: u.email, ssn: u.ssn };
  return o;
}
`, 'f', '/x/wo1.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
    fixtures.push({ label: '§6 worked example', fn, entryState, extraCtx: {} });
  }

  {
    const fn = parseFn(`
function combine(user) {
  return { email: user.email, ssn: user.ssn };
}
`, 'combine', '/x/wo2.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
    fixtures.push({ label: 'FR-301 core proof (combine)', fn, entryState, extraCtx: {} });
  }

  {
    // Wildcard-write branch — deliberately NOT one of the four instrumented
    // sites — must remain unaffected by recorder presence too.
    const fn = parseFn(`
      function f(user, k1, k2) {
        const bag = {};
        bag[k1] = user.email;
        bag[k2] = user.ssn;
        return bag;
      }
    `, 'f', '/x/wo3.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
    fixtures.push({ label: 'wildcard-write (uninstrumented branch)', fn, entryState, extraCtx: {} });
  }

  {
    // A computed "*"-keyed object property alongside a literal sibling —
    // the exact shape M1's fix touches.
    const fn = parseFn(`
      function h(user, k) {
        const c = { k: user.ssn, [k]: user.email };
        return c;
      }
    `, 'h', '/x/wo4.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
    fixtures.push({ label: 'object literal with a computed "*" key', fn, entryState, extraCtx: {} });
  }

  {
    // Hand-built branch-join fixture (Decision 8's own re-emission case —
    // the return node here is visited more than once).
    const fn = {
      qid: 'test::branchJoinWriteOnly',
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
    fixtures.push({ label: 'branch-join (hand-built, revisits n4)', fn, entryState, extraCtx: {} });
  }

  {
    // A ctx that ALSO carries resolveCallSummary (Sub-project B usage) —
    // confirm adding recordHop alongside it doesn't perturb the resolved
    // call path either.
    const src = `
      function copyEmail(source) {
        return source.email;
      }
      function caller(user) {
        return copyEmail(user);
      }
    `;
    const ir = parseJsFile('/x/wo5.js', src);
    const calleeFn = ir.functions.find((f) => f.name === 'copyEmail');
    const callerFn = ir.functions.find((f) => f.name === 'caller');
    const resolveCallSummary = (calleeExpr, callArgs, callerState) => {
      if (calleeExpr.kind !== 'ident' || calleeExpr.name !== 'copyEmail') return null;
      let calleeEntryState = emptyState();
      const userIds = identitiesAt(callerState, callArgs[0].name);
      for (const id of userIds) calleeEntryState = addIdentity(calleeEntryState, 'source.email', id);
      const r = analyzeFunctionFieldIdentity(calleeFn, calleeEntryState);
      const returnFlat = new Set();
      for (const f of r.returnFacts) for (const id of f.identities) returnFlat.add(id);
      return { returnFlat, returnByPath: new Map() };
    };
    const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    fixtures.push({ label: 'resolved call (ctx also carries resolveCallSummary)', fn: callerFn, entryState, extraCtx: { resolveCallSummary } });
  }

  // -----------------------------------------------------------------
  // C2 Task 1 additions: 3 more fixtures exercising this task's newly
  // instrumented sites, per the same "attaching a recorder must not
  // change the analysis result" discipline as every fixture above.
  // -----------------------------------------------------------------

  {
    // A member read (path branch, no wildcard) — the exact site Task 1
    // adds selection/member hops for.
    const fn = parseFn(`
      function f(user) {
        return user.email;
      }
    `, 'f', '/x/wo6-member.js');
    const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    fixtures.push({ label: 'member read (C2 Task 1 new site)', fn, entryState, extraCtx: {} });
  }

  {
    // A ternary (`union`) selecting between two member reads — exercises
    // both the new production/union site and, via its branches, the new
    // selection/member site, together.
    const fn = parseFn(`
      function f(user, other, flag) {
        return flag ? user.email : other.email;
      }
    `, 'f', '/x/wo7-ternary.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'other.email', 'data:other-email');
    fixtures.push({ label: 'ternary/union (C2 Task 1 new site)', fn, entryState, extraCtx: {} });
  }

  {
    // A resolved call, dedicated to Task 1's new production/call-resolved
    // hop site (distinct fixture from the pre-existing C1 "ctx also
    // carries resolveCallSummary" fixture above, which was added to prove
    // C1-era opt-out, not this task's new hop).
    const src = `
      function getEmail(source) {
        return source.email;
      }
      function caller(user) {
        return getEmail(user);
      }
    `;
    const ir = parseJsFile('/x/wo8-resolved-call.js', src);
    const calleeFn = ir.functions.find((f) => f.name === 'getEmail');
    const callerFn = ir.functions.find((f) => f.name === 'caller');
    const resolveCallSummary = (calleeExpr, callArgs, callerState) => {
      if (calleeExpr.kind !== 'ident' || calleeExpr.name !== 'getEmail') return null;
      let calleeEntryState = emptyState();
      const userIds = identitiesAt(callerState, callArgs[0].name);
      for (const id of userIds) calleeEntryState = addIdentity(calleeEntryState, 'source.email', id);
      const r = analyzeFunctionFieldIdentity(calleeFn, calleeEntryState);
      const returnFlat = new Set();
      for (const f of r.returnFacts) for (const id of f.identities) returnFlat.add(id);
      return { returnFlat, returnByPath: new Map() };
    };
    const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    fixtures.push({ label: 'resolved call (C2 Task 1 new site)', fn: callerFn, entryState, extraCtx: { resolveCallSummary } });
  }

  // -----------------------------------------------------------------
  // C2 Task 2 additions: 3 more fixtures exercising THIS task's newly
  // instrumented step() sites, same "attaching a recorder must not change
  // the analysis result" discipline as every fixture above.
  // -----------------------------------------------------------------

  {
    // A wildcard-target assign (`bag[k] = user.email;`) — the exact site
    // Task 2 adds write-out/assign-weak hops for.
    const fn = parseFn(`
      function f(bag, k, user) {
        bag[k] = user.email;
        return bag;
      }
    `, 'f', '/x/wo9-wildcard-write.js');
    const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    fixtures.push({ label: 'wildcard-target assign (C2 Task 2 new site)', fn, entryState, extraCtx: {} });
  }

  {
    // Assignment-expression-form destructuring (`({x} = user);`) — the
    // exact site Task 2 adds the loss-marked write-out/assign hop for.
    const fn = parseFn(`
      function f(user) {
        var x;
        ({ x } = user);
        return x;
      }
    `, 'f', '/x/wo10-unsupported-target.js');
    const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    fixtures.push({ label: 'unsupported-target assign (C2 Task 2 new site)', fn, entryState, extraCtx: {} });
  }

  {
    // A bare call statement (`logEvent(user.email);`) — the exact site
    // Task 2 adds write-out/call-arg hops for.
    const fn = parseFn(`
      function f(user) {
        logEvent(user.email);
        return user.ssn;
      }
    `, 'f', '/x/wo11-bare-call.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
    entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
    fixtures.push({ label: 'bare call statement (C2 Task 2 new site)', fn, entryState, extraCtx: {} });
  }

  {
    // Sub-project C, increment 2, Task 2, Step 3's own comprehensive
    // coverage-proof fixture — exercises EVERY hop-emitting case from both
    // §10.1 and §10.2 together. Added here (not as a separate,
    // disconnected check) per the plan's own instruction: the
    // field-identity-observable output for this fixture must be identical
    // with/without a recorder attached, exactly like every fixture above.
    const { fn, entryState, resolveCallSummary } = buildComprehensiveFixture();
    fixtures.push({ label: 'comprehensive coverage-proof fixture (§10.1 + §10.2 together)', fn, entryState, extraCtx: { resolveCallSummary } });
  }

  // NOTE: the cache-side-effect regression case (real FieldIdentitySummaryCache
  // + low cap + the unsupported-target loss site) is deliberately NOT added
  // as a fixture in this shared loop — this loop reuses ONE `extraCtx` (and
  // therefore one cache instance) across BOTH the "without" and "with
  // recorder" sub-runs below, so the second sub-run would see a cache already
  // warmed by the first, masking exactly the divergence that regression needs
  // two INDEPENDENTLY FRESH caches to expose. See the dedicated test after
  // this one instead.

  for (const { label, fn, entryState, extraCtx } of fixtures) {
    const without = analyzeFunctionFieldIdentity(fn, entryState, extraCtx);
    const hops = [];
    const withRecorder = analyzeFunctionFieldIdentity(fn, entryState, { ...extraCtx, recordHop: (h) => hops.push(h) });

    assert.deepEqual(
      canonicalizeResult(withRecorder),
      canonicalizeResult(without),
      `${label}: attaching a recorder must not change exitState/returnFacts/mutatedParams/widenings (Decision 1's write-only invariant)`,
    );
    assert.ok(hops.length > 0, `${label}: sanity check — expected the recorder to have captured at least one hop`);
  }
});

// REGRESSION (final whole-branch review, Sub-project C increment 2): a real
// FieldIdentitySummaryCache at a LOW per-function distinct-context cap,
// combined with the `assign`/unsupported-target loss site (§10.2), exposed
// a genuine Decision-1 violation — attaching a recorder could silently
// change the analysis RESULT, not just add hops.
//
// `resolveExprIdentities` is not side-effect-free when `ctx.resolveCallSummary`
// is present: its `call` case can trigger `FieldIdentitySummaryCache.compute()`
// for a callee, which registers a context against that function's distinct-
// context cap. An earlier version of the unsupported-target loss site gated
// its resolve of `node.source` on `ctx?.recordHop` ("extra, discarded
// computation" per Decision 1) — but that resolve was NOT side-effect-free
// when the source was itself a resolvable call, so a recorder's mere
// PRESENCE could consume cap budget a no-recorder run never would, changing
// which of two calls to the SAME function "won" a tight cap and therefore
// changing the caller's own resolved identity.
//
// This needs TWO INDEPENDENTLY FRESH caches (one per sub-run) to expose —
// unlike the write-only-invariant test above, which deliberately shares one
// `extraCtx`/cache across its "without" and "with recorder" sub-runs (fine
// for every OTHER fixture there, since none of them have live, stateful
// cap-registration side effects to accidentally warm from one run to the
// next) — so this is its own dedicated test, not one more shared-loop entry.
test('REGRESSION: a real FieldIdentitySummaryCache + low cap + the unsupported-target loss site must not let recorder presence change which call context wins the cap', () => {
  const src = `
    function helper(x) {
      return { v: x.email };
    }
    function f(user, other) {
      var a;
      ({ a } = helper(user));
      const b = helper(other);
      return b;
    }
  `;
  const ir = parseJsFile('/x/wo12-cache-side-effect.js', src);
  const helperFn = ir.functions.find((fn) => fn.name === 'helper');
  const fFn = ir.functions.find((fn) => fn.name === 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'other.email', 'data:other-email');

  function run(withRecorder) {
    // cap=1: only the FIRST distinct context requested for `helper` computes
    // for real; the second one degrades to the (empty) fallback — this is
    // what makes "which call resolves first" observable in the result.
    const cache = new FieldIdentitySummaryCache(1);
    const lookupCallee = (calleeExpr) => (calleeExpr.kind === 'ident' && calleeExpr.name === 'helper' ? { qid: 'helper', fn: helperFn } : null);
    const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
    const ctx = withRecorder ? { resolveCallSummary, recordHop: () => {} } : { resolveCallSummary };
    return analyzeFunctionFieldIdentity(fFn, entryState, ctx);
  }

  const without = run(false);
  const withRecorder = run(true);

  assert.deepEqual(
    canonicalizeResult(without),
    canonicalizeResult(withRecorder),
    'attaching a recorder must not change which call context wins a tight cap, and therefore must not change the analysis result',
  );
});

// ---------------------------------------------------------------------
// Sub-project C, increment 3, Task 3, Step 4 (§13.7 item 16): extend the
// write-only invariant to cover the three NEW recorder-conditional
// branches C3 adds inside summaries.js — Task 2's items 6 (entryStateFromCall's
// recorder-only derivation) and 9 (createCallSummaryResolver's hole-3 fix,
// keeping the caller's recorder alive on the callee's own ctx), and this
// task's item 12 (the degradation loss hop). A multi-function fixture,
// through a REAL FieldIdentitySummaryCache at a tight cap, exercising all
// three in one run: `outer` calls `middle` twice (an argument-binding call
// each time, item 6/8), the FIRST call resolves all the way through to
// `inner` (a resolved multi-hop chain, item 9), and the SECOND call
// degrades past the cap (a context-cap-degraded call, item 12).
//
// Deliberately its OWN dedicated test, not one more entry in the shared
// `fixtures` loop above — that loop's own comment explains why: it reuses
// ONE extraCtx/cache instance across both the "without" and "with
// recorder" sub-runs, which would mask exactly the kind of cache-cap
// accounting divergence this fixture exists to catch (the same class as
// the dedicated REGRESSION test directly above this one). Two
// INDEPENDENTLY FRESH caches, one per sub-run, are required instead.
// ---------------------------------------------------------------------

test('write-only invariant, extended (§13.7 item 16): a multi-function fixture through a real FieldIdentitySummaryCache — argument-binding, a resolved multi-hop chain, AND a context-cap-degraded call, all in one run — must be unaffected by recorder presence', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const ir = parseJsFile('/x/wo13-c3-degraded.js', src);
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  const lookupCallee = (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');

  function run(withRecorder) {
    // cap=1 on `middle`: the FIRST distinct context requested (middle(a))
    // computes for real, resolving all the way through to inner (item 9);
    // the SECOND (middle(b)) degrades past the cap (item 11/12).
    const cache = new FieldIdentitySummaryCache(1);
    const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
    const ctx = withRecorder ? { resolveCallSummary, recordHop: () => {} } : { resolveCallSummary };
    return analyzeFunctionFieldIdentity(byName.outer, entryState, ctx);
  }

  const without = run(false);
  const withRecorder = run(true);

  assert.deepEqual(
    canonicalizeResult(without),
    canonicalizeResult(withRecorder),
    'attaching a recorder must not change the analysis result — even with all three of C3\'s new recorder-conditional summaries.js branches (items 6, 9, 12) exercised in one run',
  );
});

// ---------------------------------------------------------------------
// 2 & 3. A real parsed example exercising all four instrumented sites in
//    one function (DESIGN_PATH_PROVENANCE.md §6's own worked example),
//    asserting the recorded hops are correct and complete for exactly
//    those four sites, and that hops are genuinely PER-IDENTITY (Decision
//    4) — two distinct ids flowing through the same construct give two
//    separate records, never one carrying a Set.
// ---------------------------------------------------------------------

test('DESIGN_PATH_PROVENANCE.md §6 worked example, real parsed source: hops are correct and complete (C1\'s four sites + C2 Task 1\'s member/selection)', () => {
  const src = `
function f(user) {
  const u = user;
  const o = { email: u.email, ssn: u.ssn };
  return o;
}
`;
  const fn = parseFn(src, 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const rawHops = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => rawHops.push(h) });

  // Sanity: opt-in must not change the analysis result itself (Decision 1's
  // write-only invariant — recordHop's presence never changes `state`,
  // `returnFacts`, etc.).
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);

  const hops = dedupeHops(rawHops);

  // Every hop record has the full, stable shape (§3: every field always
  // present, nullable fields carry null, never undefined/omitted).
  const REQUIRED_FIELDS = [
    'kind', 'subKind', 'scope', 'dataElementId', 'fromPath', 'toPath',
    'syntacticPath', 'nodeId', 'line', 'widenReason', 'lossReason',
    // Sub-project C, increment 3, §13.0: three more fields, same
    // always-present/never-undefined contract as every field above —
    // absorbed from the PoC's own dedicated additivity test (scenario 6),
    // which this REQUIRED_FIELDS check now subsumes.
    'context', 'peerScope', 'peerContext',
  ];
  for (const h of hops) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(h, field), `hop record missing field "${field}": ${JSON.stringify(h)}`);
      assert.notEqual(h[field], undefined, `hop record field "${field}" must never be undefined: ${JSON.stringify(h)}`);
    }
  }

  // Only the shapes this fixture's cases actually produce ever appear —
  // C1's original four sites, plus C2 Task 1's `member`/`selection` (this
  // fixture's `u.email`/`u.ssn` reads inside the object literal are now
  // instrumented; `array`/`tpl`/`binary`/`logical`/`union`/`call`/
  // `assign-expr` don't appear because this fixture doesn't use them —
  // covered by their own dedicated tests below).
  const shapes = new Set(hops.map((h) => `${h.kind}/${h.subKind}`));
  for (const shape of shapes) {
    assert.ok(
      ['production/ident', 'production/object', 'selection/member', 'write-out/assign', 'write-out/return'].includes(shape),
      `unexpected hop shape emitted: ${shape}`,
    );
  }

  // --- n1: `const u = user;` ------------------------------------------
  // Decision 6: fromPath is the CONTRIBUTING state key ('user.email'/
  // 'user.ssn'), never the queried path ('user') — the exact distinction
  // this fixture exists to prove.
  const identHops = hops.filter((h) => h.kind === 'production' && h.subKind === 'ident');
  const uEmailIdent = identHops.find((h) => h.dataElementId === 'data:email' && h.toPath === null && h.fromPath === 'user.email');
  assert.ok(uEmailIdent, `expected a production/ident hop from 'user.email', got: ${JSON.stringify(identHops)}`);
  assert.equal(uEmailIdent.syntacticPath, 'user', 'syntacticPath must carry the QUERIED path when it differs from the contributing key');
  const uSsnIdent = identHops.find((h) => h.dataElementId === 'data:ssn' && h.fromPath === 'user.ssn');
  assert.ok(uSsnIdent, `expected a production/ident hop from 'user.ssn', got: ${JSON.stringify(identHops)}`);
  assert.equal(uSsnIdent.syntacticPath, 'user');

  const assignHops = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'assign');
  assert.ok(assignHops.some((h) => h.toPath === 'u.email' && h.dataElementId === 'data:email'), `expected write-out/assign to 'u.email', got: ${JSON.stringify(assignHops)}`);
  assert.ok(assignHops.some((h) => h.toPath === 'u.ssn' && h.dataElementId === 'data:ssn'), `expected write-out/assign to 'u.ssn', got: ${JSON.stringify(assignHops)}`);

  // --- n2: `const o = { email: u.email, ssn: u.ssn };` -----------------
  // `member` (path branch, no wildcard) is now instrumented (C2 Task 1,
  // §10.1) — one selection in-half per (contributing state key, id) pair,
  // Decision 6, exactly the same shape as `ident`'s in-halves above. Here
  // the queried path ('u.email'/'u.ssn') IS itself the contributing state
  // key (an exact match — it was written as its own key at n1), so
  // syntacticPath is null, not the queried path.
  const memberHops = hops.filter((h) => h.kind === 'selection' && h.subKind === 'member');
  const uEmailMember = memberHops.find((h) => h.dataElementId === 'data:email');
  assert.ok(uEmailMember, `expected a selection/member hop for data:email, got: ${JSON.stringify(memberHops)}`);
  assert.equal(uEmailMember.fromPath, 'u.email');
  assert.equal(uEmailMember.toPath, null);
  assert.equal(uEmailMember.syntacticPath, null, 'contributing key exactly matches the queried path here, so syntacticPath must be null');
  assert.equal(uEmailMember.widenReason, null);
  const uSsnMember = memberHops.find((h) => h.dataElementId === 'data:ssn');
  assert.ok(uSsnMember, `expected a selection/member hop for data:ssn, got: ${JSON.stringify(memberHops)}`);
  assert.equal(uSsnMember.fromPath, 'u.ssn');
  assert.equal(memberHops.length, 2, `expected exactly two per-identity selection/member hops, not one Set-valued record: ${JSON.stringify(memberHops)}`);

  // The object literal's own production/object annotation (fromPath: null,
  // per identity) and the write-out to o.*.
  const objectHops = hops.filter((h) => h.kind === 'production' && h.subKind === 'object');
  assert.ok(objectHops.some((h) => h.dataElementId === 'data:email' && h.fromPath === null && h.toPath === null), `expected production/object hop for data:email, got: ${JSON.stringify(objectHops)}`);
  assert.ok(objectHops.some((h) => h.dataElementId === 'data:ssn' && h.fromPath === null && h.toPath === null), `expected production/object hop for data:ssn, got: ${JSON.stringify(objectHops)}`);
  // Decision 4: PER identity, never one record carrying both ids in a Set.
  assert.equal(objectHops.length, 2, `object literal with two distinct fields must produce exactly two per-identity production/object hops, not one Set-valued record: ${JSON.stringify(objectHops)}`);
  for (const h of objectHops) {
    assert.equal(typeof h.dataElementId, 'string', 'dataElementId must be a scalar string, never an array/Set');
  }

  assert.ok(assignHops.some((h) => h.toPath === 'o.email' && h.dataElementId === 'data:email'), `expected write-out/assign to 'o.email', got: ${JSON.stringify(assignHops)}`);
  assert.ok(assignHops.some((h) => h.toPath === 'o.ssn' && h.dataElementId === 'data:ssn'), `expected write-out/assign to 'o.ssn', got: ${JSON.stringify(assignHops)}`);
  // No assign hop should ever carry the coarse `o`/`u` alone when a byPath
  // sub-path write happened instead (DESIGN_PATH_PROVENANCE.md §10.1's
  // named "most likely C2 mistake" — recording the coarser node.target).
  assert.ok(!assignHops.some((h) => h.toPath === 'o' || h.toPath === 'u'), `no assign hop should record the coarse container path when a byPath sub-write occurred: ${JSON.stringify(assignHops)}`);

  // --- n3: `return o;` --------------------------------------------------
  const oEmailIdent = identHops.find((h) => h.dataElementId === 'data:email' && h.fromPath === 'o.email');
  assert.ok(oEmailIdent, `expected a production/ident hop from 'o.email' at the return, got: ${JSON.stringify(identHops)}`);
  assert.equal(oEmailIdent.syntacticPath, 'o');
  const oSsnIdent = identHops.find((h) => h.dataElementId === 'data:ssn' && h.fromPath === 'o.ssn');
  assert.ok(oSsnIdent, `expected a production/ident hop from 'o.ssn' at the return, got: ${JSON.stringify(identHops)}`);
  assert.equal(oSsnIdent.syntacticPath, 'o');

  const returnHops = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'return');
  assert.equal(returnHops.length, 2, `return of a two-field object must produce exactly two per-identity write-out/return hops: ${JSON.stringify(returnHops)}`);
  assert.ok(returnHops.every((h) => h.toPath === null), 'a return hop must never carry a fabricated pseudo-path (e.g. "@return") as toPath — must be exactly null (Decision 5)');
  assert.deepEqual(returnHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:ssn']);

  // --- Joining the ends of the flow (Decision 6) — now complete for all
  // three nodes, now that C2 Task 1 instruments `member`:
  // n1's in-half + out-half join into a real edge at each id's own node:
  //   user.email -> u.email  (data:email)
  //   user.ssn   -> u.ssn    (data:ssn)
  // n2's in-half (selection/member) + out-half join into a real edge too:
  //   u.email -> o.email     (data:email)
  //   u.ssn   -> o.ssn       (data:ssn)
  // n3's in-half + out-half join into a real exit edge:
  //   o.email -> <return>    (data:email)
  //   o.ssn   -> <return>    (data:ssn)
  assert.equal(uEmailIdent.nodeId, assignHops.find((h) => h.toPath === 'u.email').nodeId, 'n1\'s in-half and out-half for data:email must share the same nodeId (the join key)');
  assert.equal(uEmailMember.nodeId, assignHops.find((h) => h.toPath === 'o.email').nodeId, 'n2\'s selection/member in-half and write-out/assign out-half for data:email must share the same nodeId (the join key)');
  assert.equal(oEmailIdent.nodeId, returnHops.find((h) => h.dataElementId === 'data:email').nodeId, 'n3\'s in-half and out-half for data:email must share the same nodeId (the join key)');

  // Total record count for this fixture, deduplicated: 4 hops at n1
  // (2 production/ident + 2 write-out/assign) + 6 hops at n2 (2
  // selection/member + 2 production/object + 2 write-out/assign — now that
  // C2 Task 1 instruments `member`, DESIGN_PATH_PROVENANCE.md §6's own
  // closing count of twelve records — which was explicit that it excluded
  // the two selection/member rows a FULL instrumentation would add — grows
  // by exactly those two rows) + 4 hops at n3 (2 production/ident + 2
  // write-out/return) = 14.
  assert.equal(hops.length, 14, `expected exactly 14 deduplicated hop records for this fixture now that member/selection is instrumented (C2 Task 1), got ${hops.length}: ${JSON.stringify(hops, null, 2)}`);
});

// ---------------------------------------------------------------------
// M1 fix-round addition: DESIGN_PATH_PROVENANCE.md §10.1's `object` table
// has three rows (plain / spread / `*`-keyed) that agree on kind/fromPath/
// toPath but NOT on widenReason — only the `*`-keyed row is
// 'dynamic-property-key'. A reviewer confirmed the shipped code's single
// unified emission point set `widenReason: null` unconditionally,
// contradicting the spec (and an in-code comment overstating "all three
// rows... agree on this shape"). Fixed by computing widenReason per
// property from `prop.key === '*'` at the emission site.
// ---------------------------------------------------------------------

test('M1: an object literal computed "*" key emits widenReason "dynamic-property-key"; a plain sibling property does not', () => {
  const src = `
    function h(user, k) {
      const c = { k: user.ssn, [k]: user.email };
      return c;
    }
  `;
  const fn = parseFn(src, 'h', '/x/m1-star.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });

  const objectHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'object');
  // '[k]: user.email' — the computed, statically-unknown key.
  const starHop = objectHops.find((h) => h.dataElementId === 'data:email');
  // 'k: user.ssn' — the literal, explicit key.
  const plainHop = objectHops.find((h) => h.dataElementId === 'data:ssn');

  assert.ok(starHop, `expected a production/object hop for data:email (the '[k]: user.email' property), got: ${JSON.stringify(objectHops)}`);
  assert.equal(starHop.widenReason, 'dynamic-property-key', 'a computed "*"-keyed object property must be graded widened per §10.1, not an explicit flow');

  assert.ok(plainHop, `expected a production/object hop for data:ssn (the literal "k" property), got: ${JSON.stringify(objectHops)}`);
  assert.equal(plainHop.widenReason, null, 'a plain, non-computed object property must remain an explicit flow (widenReason: null)');
});

// ---------------------------------------------------------------------
// M2 fix-round addition (recommended, not required): the §6 fixture is
// straight-line, so every shipped assertion above has `raw === deduped`
// and dedupeHops is exercised as a no-op wherever it's actually tested.
// This hand-built branch-join fixture forces the worklist to revisit the
// return node (n4, reached from both n2 and n3) — Decision 8's own
// re-emission case — closing that gap.
// ---------------------------------------------------------------------

test('M2: the worklist re-emits hops on revisit (Decision 8) — a branch-join fixture produces strictly more raw records than deduplicated ones', () => {
  // function f(user, flag) { let x; if (flag) { x = user.email; } else { x = user.name; } return x; }
  // n4 (return, pred: n2 AND n3) is visited twice: once when n2's branch
  // state first arrives, again once n3's branch state joins in and grows
  // inStates[n4] — each visit re-runs step() and re-records hops.
  const fn = {
    qid: 'test::branchJoinDedupe',
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

  const raw = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => raw.push(h) });
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:name']);

  const deduped = dedupeHops(raw);
  assert.ok(raw.length > deduped.length, `expected the worklist to re-emit at least one duplicate hop at the revisited return node (raw=${raw.length}, deduped=${deduped.length})`);

  // Per Decision 8: the deduplicated set is still complete and correct —
  // the return node's ident in-half and write-out/return out-half must
  // each carry BOTH ids exactly once, not the partial set an early,
  // un-deduplicated visit alone would show.
  const returnIdentHops = deduped.filter((h) => h.kind === 'production' && h.subKind === 'ident' && h.nodeId === 'n4');
  assert.deepEqual(returnIdentHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:name']);
  const returnWriteOutHops = deduped.filter((h) => h.kind === 'write-out' && h.subKind === 'return');
  assert.deepEqual(returnWriteOutHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:name']);
});

// ---------------------------------------------------------------------
// 4. `nodeId` comes from the worklist's map key, not `node.id` — assert
//    distinct nodeIds on a hand-built fixture whose nodes set no `id`
//    field at all (mirrors test/lineage/engine-walker.test.js's own
//    fixture shape).
// ---------------------------------------------------------------------

test('nodeId is sourced from the worklist map key, not node.id, on a hand-built fixture with no id field on any node', () => {
  // function f(user) { const email = user.email; return email; }
  const fn = {
    qid: 'test::f',
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n3',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: {
          kind: 'assign', line: 1, succ: ['n2'], pred: ['n0'],
          target: 'email', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' },
        },
        n2: { kind: 'return', line: 1, succ: ['n3'], pred: ['n1'], value: { kind: 'ident', name: 'email' } },
        n3: { kind: 'exit', line: 1, succ: [], pred: ['n2'] },
      },
    },
  };
  // None of these hand-built node objects sets an `id` field — confirming
  // the guard this test exists to prove (DESIGN_PATH_PROVENANCE.md §7.2's
  // warning: stamping from `node.id` instead of the worklist key `nid`
  // would collapse every node in a fixture like this one onto a single,
  // `undefined` join key).
  for (const node of Object.values(fn.cfg.nodes)) {
    assert.equal(node.id, undefined, 'fixture precondition: no node sets its own id field');
  }

  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const hops = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);

  const uniq = dedupeHops(hops);
  assert.ok(uniq.length > 0, 'expected at least one hop to have been recorded');
  for (const h of uniq) {
    assert.notEqual(h.nodeId, undefined, `nodeId must never be undefined: ${JSON.stringify(h)}`);
    assert.equal(typeof h.nodeId, 'string', `nodeId must be the worklist's string map key: ${JSON.stringify(h)}`);
    assert.equal(h.scope, 'test::f', 'scope must be stamped from fn.qid');
  }
  // The assign (n1) and return (n2) hops must carry DISTINCT nodeIds —
  // the exact failure mode a `node.id`-sourced stamp (all undefined on
  // this fixture) would have collapsed onto one shared key.
  const assignNodeIds = new Set(uniq.filter((h) => h.subKind === 'assign').map((h) => h.nodeId));
  const returnNodeIds = new Set(uniq.filter((h) => h.subKind === 'return').map((h) => h.nodeId));
  assert.deepEqual([...assignNodeIds], ['n1']);
  assert.deepEqual([...returnNodeIds], ['n2']);
});

test('scope is null when fn.qid is absent (hand-built fixture with no qid field)', () => {
  const fn = {
    params: ['user'],
    cfg: {
      entry: 'n0', exit: 'n2',
      nodes: {
        n0: { kind: 'entry', line: 1, succ: ['n1'], pred: [] },
        n1: { kind: 'return', line: 1, succ: ['n2'], pred: ['n0'], value: { kind: 'ident', name: 'user' } },
        n2: { kind: 'exit', line: 1, succ: [], pred: ['n1'] },
      },
    },
  };
  const entryState = addIdentity(emptyState(), 'user', 'data:email');
  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  assert.ok(hops.length > 0);
  for (const h of hops) assert.equal(h.scope, null);
});

// ---------------------------------------------------------------------
// Extra structural guard (design-review recommendation folded into Task
// 2, not itself in DESIGN_PATH_PROVENANCE.md): assert that unioning
// contributingKeys(state, path, id) over every id in identitiesAt(state,
// path) reconstructs that same identity set EXACTLY, over a small fixture
// set. This is cheaper and more robust than a comment: it fails loudly if
// field-identity.js's identitiesAt (its bidirectional prefix-coverage
// check, ~line 30) ever changes without engine.js's contributingKeys
// being updated to match — the exact silent-drift failure mode Decision 6
// depends on never happening.
// ---------------------------------------------------------------------

test('structural guard: contributingKeys reconstructs identitiesAt exactly, over a small fixture set', () => {
  function assertReconstructs(state, path, allCandidateIds, label) {
    const expected = identitiesAt(state, path);
    for (const id of allCandidateIds) {
      const keys = contributingKeys(state, path, id);
      const claimsToContribute = keys.size > 0;
      const actuallyIn = expected.has(id);
      assert.equal(claimsToContribute, actuallyIn, `${label}: contributingKeys(state, '${path}', '${id}') claims contribution=${claimsToContribute} but identitiesAt says membership=${actuallyIn}`);
    }
    // Round-trip: unioning contributingKeys' claimed ids across the
    // candidate set reconstructs identitiesAt(state, path) exactly.
    const reconstructed = new Set();
    for (const id of allCandidateIds) {
      if (contributingKeys(state, path, id).size > 0) reconstructed.add(id);
    }
    assert.deepEqual([...reconstructed].sort(), [...expected].sort(), `${label}: reconstructed set must equal identitiesAt(state, '${path}') exactly`);
  }

  // Fixture 1: exact match only.
  {
    const state = addIdentity(emptyState(), 'user', 'data:x');
    assertReconstructs(state, 'user', ['data:x', 'data:y'], 'exact match');
    assert.deepEqual([...contributingKeys(state, 'user', 'data:x')], ['user']);
  }

  // Fixture 2: ancestor coverage (querying a descendant sees the ancestor's fact).
  {
    const state = addIdentity(emptyState(), 'user', 'data:blob');
    assertReconstructs(state, 'user.email', ['data:blob', 'data:other'], 'ancestor coverage');
    assert.deepEqual([...contributingKeys(state, 'user.email', 'data:blob')], ['user']);
  }

  // Fixture 3: descendant aggregation (querying the container sees every field).
  {
    let state = addIdentity(emptyState(), 'user.email', 'data:email');
    state = addIdentity(state, 'user.ssn', 'data:ssn');
    assertReconstructs(state, 'user', ['data:email', 'data:ssn', 'data:unrelated'], 'descendant aggregation');
    assert.deepEqual([...contributingKeys(state, 'user', 'data:email')], ['user.email']);
    assert.deepEqual([...contributingKeys(state, 'user', 'data:ssn')], ['user.ssn']);
  }

  // Fixture 4: siblings never leak into each other (neither is a prefix of the other).
  {
    let state = addIdentity(emptyState(), 'user.email', 'data:email');
    state = addIdentity(state, 'user.ssn', 'data:ssn');
    assertReconstructs(state, 'user.email', ['data:email', 'data:ssn'], 'sibling non-leak');
    assert.deepEqual([...contributingKeys(state, 'user.email', 'data:ssn')], []);
  }

  // Fixture 5: ancestor AND descendant both carrying identity simultaneously
  // (the shape DESIGN_INTRAPROCEDURAL.md §3 explicitly allows to coexist).
  {
    let state = addIdentity(emptyState(), 'user', 'data:blob');
    state = addIdentity(state, 'user.email', 'data:email');
    assertReconstructs(state, 'user', ['data:blob', 'data:email', 'data:unrelated'], 'ancestor+descendant coexisting');
    assert.deepEqual([...contributingKeys(state, 'user', 'data:blob')], ['user']);
    assert.deepEqual([...contributingKeys(state, 'user', 'data:email')], ['user.email']);
  }
});

// ---------------------------------------------------------------------
// Sub-project C, increment 2, Task 1: dedicated correctness tests for
// every remaining `resolveExprIdentities` case per DESIGN_PATH_PROVENANCE
// .md §10.1's table. Each uses real parsed source (parseJsFile), matching
// the established style, and asserts the exact hop shape (kind/subKind/
// fromPath/toPath/syntacticPath/widenReason) the table's row specifies.
// ---------------------------------------------------------------------

test('member (path branch, wildcard): selection hop\'s fromPath is definitePrefixBeforeWildcard, NEVER the raw \'*\'-containing path (Decision 5)', () => {
  const fn = parseFn(`
    function f(store, k) {
      return store[k];
    }
  `, 'f', '/x/c2-member-wildcard.js');
  const entryState = addIdentity(emptyState(), 'store.email', 'data:email');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const memberHops = dedupeHops(hops).filter((h) => h.kind === 'selection' && h.subKind === 'member');

  assert.equal(memberHops.length, 1, `expected exactly one selection/member hop, got: ${JSON.stringify(memberHops)}`);
  const h = memberHops[0];
  assert.equal(h.dataElementId, 'data:email');
  assert.equal(h.fromPath, 'store', 'fromPath must be the definite prefix before the wildcard, never a \'*\'-containing path');
  assert.equal(h.toPath, null);
  assert.equal(h.syntacticPath, 'store.*', 'syntacticPath carries the raw wildcard-containing path the IR supplied');
  assert.equal(h.widenReason, 'dynamic-property-key');
  // No hop anywhere in this fixture may carry a fromPath/toPath/syntacticPath
  // containing a raw, unresolved wildcard segment (Decision 5's forbidden
  // bug class) except syntacticPath, which is explicitly the one field
  // allowed to carry that framing.
  for (const hop of dedupeHops(hops)) {
    assert.ok(hop.fromPath === null || !hop.fromPath.includes('*'), `fromPath must never contain a wildcard segment: ${JSON.stringify(hop)}`);
    assert.ok(hop.toPath === null || !hop.toPath.includes('*'), `toPath must never contain a wildcard segment: ${JSON.stringify(hop)}`);
  }
});

test('member (non-path base, prop !== "*"): selection hop annotates the selection with no state-backed fromPath', () => {
  const fn = parseFn(`
    function f(user, other, flag) {
      return (flag ? user : other).email;
    }
  `, 'f', '/x/c2-member-nonpath.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'other.email', 'data:other');

  const hops = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:other']);

  const deduped = dedupeHops(hops);
  const memberHops = deduped.filter((h) => h.kind === 'selection' && h.subKind === 'member');
  assert.deepEqual(memberHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:other']);
  for (const h of memberHops) {
    assert.equal(h.fromPath, null, 'the base is an in-flight value (a ternary), not itself a state key');
    assert.equal(h.toPath, null);
    assert.equal(h.widenReason, null, 'a known (non-computed) property selection is an explicit flow');
  }

  // The base's own recursion (the ternary) must ALSO have emitted its own
  // in-halves — this member hop is annotation-only, not a substitute.
  const unionHops = deduped.filter((h) => h.kind === 'production' && h.subKind === 'union');
  assert.deepEqual(unionHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:other']);
});

test('member (non-path base, prop === "*"): selection hop is widened, dynamic-property-key', () => {
  const fn = parseFn(`
    function f(user, other, flag, k) {
      return (flag ? user : other)[k];
    }
  `, 'f', '/x/c2-member-nonpath-star.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'other.email', 'data:other');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const memberHops = dedupeHops(hops).filter((h) => h.kind === 'selection' && h.subKind === 'member');

  assert.deepEqual(memberHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:other']);
  for (const h of memberHops) {
    assert.equal(h.fromPath, null);
    assert.equal(h.toPath, null);
    assert.equal(h.widenReason, 'dynamic-property-key', 'an unknown computed key on a non-path base must be graded widened');
  }
});

test('array/tpl/binary: structure-flattening production hops, per id, no widenReason', () => {
  const cases = [
    {
      subKind: 'array',
      src: `function f(user) { return [user.email, user.ssn]; }`,
      buildEntryState: () => {
        let s = addIdentity(emptyState(), 'user.email', 'data:email');
        return addIdentity(s, 'user.ssn', 'data:ssn');
      },
      ids: ['data:email', 'data:ssn'],
    },
    {
      subKind: 'tpl',
      src: `function f(user) { return \`hello \${user.email}\`; }`,
      buildEntryState: () => addIdentity(emptyState(), 'user.email', 'data:email'),
      ids: ['data:email'],
    },
    {
      subKind: 'binary',
      src: `function f(user) { return user.age + 1; }`,
      buildEntryState: () => addIdentity(emptyState(), 'user.age', 'data:age'),
      ids: ['data:age'],
    },
  ];
  for (const { src, subKind, buildEntryState, ids } of cases) {
    const fn = parseFn(src, 'f', `/x/c2-${subKind}.js`);
    const entryState = buildEntryState();
    const hops = [];
    analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
    const caseHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === subKind);
    assert.deepEqual(caseHops.map((h) => h.dataElementId).sort(), [...ids].sort(), `${subKind}: expected one production hop per id`);
    for (const h of caseHops) {
      assert.equal(h.fromPath, null, `${subKind}: fromPath must be null (structure-flattening)`);
      assert.equal(h.toPath, null);
      assert.equal(h.widenReason, null, `${subKind}: must be an explicit flow, not widened`);
    }
  }
});

test('logical/union: structure-preserving production hops, per id, no widenReason', () => {
  {
    const fn = parseFn(`
      function f(user, other) {
        return user.email || other.email;
      }
    `, 'f', '/x/c2-logical.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:x');
    entryState = addIdentity(entryState, 'other.email', 'data:y');
    const hops = [];
    analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
    const logicalHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'logical');
    assert.deepEqual(logicalHops.map((h) => h.dataElementId).sort(), ['data:x', 'data:y']);
    for (const h of logicalHops) {
      assert.equal(h.fromPath, null);
      assert.equal(h.toPath, null);
      assert.equal(h.widenReason, null, 'short-circuit evaluation returning an operand verbatim is an explicit flow');
    }
  }

  {
    const fn = parseFn(`
      function f(user, other, flag) {
        return flag ? user.email : other.email;
      }
    `, 'f', '/x/c2-union.js');
    let entryState = addIdentity(emptyState(), 'user.email', 'data:x');
    entryState = addIdentity(entryState, 'other.email', 'data:y');
    const hops = [];
    analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
    const unionHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'union');
    assert.deepEqual(unionHops.map((h) => h.dataElementId).sort(), ['data:x', 'data:y']);
    for (const h of unionHops) {
      assert.equal(h.fromPath, null);
      assert.equal(h.toPath, null);
      assert.equal(h.widenReason, null, 'a ternary selecting one branch verbatim is FR-305\'s genuine multiple-path case, not a widened flow');
    }
  }
});

test('call (unresolved): production/call hop is widened "unresolved-call"', () => {
  const fn = parseFn(`
    function f(user) {
      return helper(user.email);
    }
  `, 'f', '/x/c2-call-unresolved.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const callHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'call');

  assert.equal(callHops.length, 1);
  assert.equal(callHops[0].dataElementId, 'data:email');
  assert.equal(callHops[0].fromPath, null);
  assert.equal(callHops[0].toPath, null);
  assert.equal(callHops[0].widenReason, 'unresolved-call');
});

test('call (resolved via ctx.resolveCallSummary): production/call-resolved hop, widenReason null (the cross-function stitch itself is C3\'s job)', () => {
  const src = `
    function copyEmail(source) {
      return source.email;
    }
    function caller(user) {
      return copyEmail(user);
    }
  `;
  const ir = parseJsFile('/x/c2-call-resolved.js', src);
  const calleeFn = ir.functions.find((f) => f.name === 'copyEmail');
  const callerFn = ir.functions.find((f) => f.name === 'caller');
  const resolveCallSummary = (calleeExpr, callArgs, callerState) => {
    if (calleeExpr.kind !== 'ident' || calleeExpr.name !== 'copyEmail') return null;
    let calleeEntryState = emptyState();
    const userIds = identitiesAt(callerState, callArgs[0].name);
    for (const id of userIds) calleeEntryState = addIdentity(calleeEntryState, 'source.email', id);
    const r = analyzeFunctionFieldIdentity(calleeFn, calleeEntryState);
    const returnFlat = new Set();
    for (const f of r.returnFacts) for (const id of f.identities) returnFlat.add(id);
    return { returnFlat, returnByPath: new Map() };
  };

  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const hops = [];
  analyzeFunctionFieldIdentity(callerFn, entryState, { resolveCallSummary, recordHop: (h) => hops.push(h) });

  const resolvedHops = dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'call-resolved');
  assert.equal(resolvedHops.length, 1, `expected exactly one production/call-resolved hop, got: ${JSON.stringify(resolvedHops)}`);
  assert.equal(resolvedHops[0].dataElementId, 'data:email');
  assert.equal(resolvedHops[0].fromPath, null);
  assert.equal(resolvedHops[0].toPath, null);
  assert.equal(resolvedHops[0].widenReason, null, 'C2 records only that a resolved call contributed; the cross-function stitch itself is C3\'s job');
  // No generic unresolved production/call hop should also fire for the
  // same call site now that it resolved.
  assert.equal(dedupeHops(hops).filter((h) => h.kind === 'production' && h.subKind === 'call').length, 0);
});

test('assign-expr: production hop is a pure pass-through of the resolved source, per id, no write-out (documented limitation)', () => {
  const fn = parseFn(`
    function f(user) {
      return (x = user).email;
    }
  `, 'f', '/x/c2-assign-expr.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const hops = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);

  const deduped = dedupeHops(hops);
  const assignExprHops = deduped.filter((h) => h.kind === 'production' && h.subKind === 'assign-expr');
  assert.equal(assignExprHops.length, 1, `expected exactly one production/assign-expr hop, got: ${JSON.stringify(assignExprHops)}`);
  assert.equal(assignExprHops[0].dataElementId, 'data:email');
  assert.equal(assignExprHops[0].fromPath, null);
  assert.equal(assignExprHops[0].toPath, null);
  assert.equal(assignExprHops[0].widenReason, null, 'a plain, no-call source is not a widened flow');

  // The source's own recursion (the ident `user`) must have emitted its own
  // in-half — assign-expr is a pass-through annotation, not a substitute.
  const identHops = deduped.filter((h) => h.kind === 'production' && h.subKind === 'ident' && h.fromPath === 'user.email');
  assert.ok(identHops.length > 0, 'expected the assign-expr\'s source (a plain ident) to have emitted its own production/ident in-half');
});

test('literal / unknown / default: emit nothing, because no identity was resolved (§10.1\'s explicit "emits nothing" verdict)', () => {
  const hops = [];
  const ctx = { recordHop: (h) => hops.push(h) };
  const state = addIdentity(emptyState(), 'user.email', 'data:email');

  const litResult = resolveExprIdentities(state, { kind: 'literal', value: 42 }, ctx);
  assert.equal(litResult.flat.size, 0);

  const unknownResult = resolveExprIdentities(state, { kind: 'unknown' }, ctx);
  assert.equal(unknownResult.flat.size, 0);

  const defaultResult = resolveExprIdentities(state, { kind: 'some-future-unmodelled-node-kind' }, ctx);
  assert.equal(defaultResult.flat.size, 0);

  const nullExprResult = resolveExprIdentities(state, null, ctx);
  assert.equal(nullExprResult.flat.size, 0);

  assert.equal(hops.length, 0, `expected zero hops from literal/unknown/default/null, got: ${JSON.stringify(hops)}`);
});

// ---------------------------------------------------------------------
// Sub-project C, increment 2, Task 2: dedicated correctness tests for
// step()'s three remaining CFG-node cases per DESIGN_PATH_PROVENANCE.md
// §10.2's table. Each uses real parsed source (parseJsFile), matching the
// established style, and asserts the exact hop shape the table's row
// specifies.
// ---------------------------------------------------------------------

test('assign, wildcard target: write-out/assign-weak hop, toPath is definitePrefixBeforeWildcard, NEVER the raw wildcard target (Decision 5)', () => {
  const fn = parseFn(`
    function f(bag, k, user) {
      bag[k] = user.email;
    }
  `, 'f', '/x/c2t2-wildcard-write.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const weakHops = dedupeHops(hops).filter((h) => h.kind === 'write-out' && h.subKind === 'assign-weak');

  assert.equal(weakHops.length, 1, `expected exactly one write-out/assign-weak hop, got: ${JSON.stringify(weakHops)}`);
  const h = weakHops[0];
  assert.equal(h.dataElementId, 'data:email');
  assert.equal(h.fromPath, null);
  assert.equal(h.toPath, 'bag', 'toPath must be the definite prefix before the wildcard, never a \'*\'-containing path');
  assert.equal(h.syntacticPath, 'bag.*', 'syntacticPath carries the raw wildcard-containing target the IR supplied');
  assert.equal(h.widenReason, 'dynamic-property-key');
  assert.equal(h.lossReason, null, 'a weak update is not a loss');

  // One record per (containerPath, id) — a second, distinct id on the same
  // container must produce its own separate record, never a Set-valued one.
  const fn2 = parseFn(`
    function g(bag, k1, k2, user) {
      bag[k1] = user.email;
      bag[k2] = user.ssn;
    }
  `, 'g', '/x/c2t2-wildcard-write2.js');
  let entryState2 = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState2 = addIdentity(entryState2, 'user.ssn', 'data:ssn');
  const hops2 = [];
  analyzeFunctionFieldIdentity(fn2, entryState2, { recordHop: (h2) => hops2.push(h2) });
  const weakHops2 = dedupeHops(hops2).filter((hh) => hh.kind === 'write-out' && hh.subKind === 'assign-weak');
  assert.equal(weakHops2.length, 2, `expected exactly two per-identity write-out/assign-weak hops (one per id, same container), got: ${JSON.stringify(weakHops2)}`);
  assert.deepEqual(weakHops2.map((hh) => hh.toPath), ['bag', 'bag']);
  assert.deepEqual(weakHops2.map((hh) => hh.dataElementId).sort(), ['data:email', 'data:ssn']);
});

test('assign, target not a string (destructuring): write-out/assign hop is a loss (lossReason: unsupported-target), and node.source\'s own in-half hops still fire', () => {
  const fn = parseFn(`
    function f(user) {
      var x;
      ({ x } = user);
      return x;
    }
  `, 'f', '/x/c2t2-unsupported-target.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const deduped = dedupeHops(hops);

  const lossHops = deduped.filter((h) => h.lossReason === 'unsupported-target');
  assert.equal(lossHops.length, 1, `expected exactly one loss-marked hop, got: ${JSON.stringify(lossHops)}`);
  const h = lossHops[0];
  assert.equal(h.kind, 'write-out');
  assert.equal(h.subKind, 'assign');
  assert.equal(h.fromPath, null);
  assert.equal(h.toPath, null, 'no real target path exists to write — the whole point of this being a loss site');
  assert.equal(h.dataElementId, 'data:email');
  assert.equal(h.widenReason, null);

  // The design doc's own dated correction (§10.2): resolving node.source
  // purely to learn the ids GENUINELY emits real in-half hops for whatever
  // it reads — here, `user` is a plain ident, so a production/ident in-half
  // must have fired too, joining with the loss marker above at the same
  // nodeId.
  const identHops = deduped.filter((hh) => hh.kind === 'production' && hh.subKind === 'ident' && hh.dataElementId === 'data:email');
  assert.ok(identHops.length > 0, 'expected node.source (a plain ident) to have emitted its own production/ident in-half despite the write being lost');
  assert.equal(identHops[0].nodeId, h.nodeId, 'the source\'s in-half and the loss marker\'s out-half must share the same nodeId (the join key)');

  // The analysis result itself is unaffected by the destructuring being
  // unrepresentable — `x` never got a real binding either with or without
  // a recorder attached (this is the existing, pre-Task-2 behavior; Task 2
  // only adds provenance, it does not change what state gets written).
  const without = analyzeFunctionFieldIdentity(fn, entryState);
  const withRecorder = analyzeFunctionFieldIdentity(fn, entryState, { recordHop: () => {} });
  assert.deepEqual([...without.exitState.entries()], [...withRecorder.exitState.entries()]);
});

test('assign, target not a string: emits nothing when node.source resolves no identity at all', () => {
  const fn = parseFn(`
    function f(other) {
      var x;
      ({ x } = other);
      return x;
    }
  `, 'f', '/x/c2t2-unsupported-target-empty.js');
  const entryState = emptyState(); // 'other' carries no identity at all

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const lossHops = dedupeHops(hops).filter((h) => h.lossReason === 'unsupported-target');
  assert.equal(lossHops.length, 0, `expected zero loss hops when node.source resolves no identity, got: ${JSON.stringify(lossHops)}`);
});

test('call (bare statement): write-out/call-arg hop per id in the argument\'s resolved identity set', () => {
  const fn = parseFn(`
    function f(user) {
      logEvent(user.email);
    }
  `, 'f', '/x/c2t2-bare-call.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const callArgHops = dedupeHops(hops).filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg');

  assert.equal(callArgHops.length, 1, `expected exactly one write-out/call-arg hop, got: ${JSON.stringify(callArgHops)}`);
  const h = callArgHops[0];
  assert.equal(h.dataElementId, 'data:email');
  assert.equal(h.fromPath, null);
  assert.equal(h.toPath, null, 'the value escapes via an argument — not a loss, so no fabricated toPath either');
  assert.equal(h.widenReason, null);
  assert.equal(h.lossReason, null, 'an escape via a call argument is not a loss (§10.2)');
});

test('call (bare statement) with multiple arguments: one write-out/call-arg hop per (argument, id)', () => {
  const fn = parseFn(`
    function f(user) {
      logEvent(user.email, user.ssn);
    }
  `, 'f', '/x/c2t2-bare-call-multi.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const hops = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: (h) => hops.push(h) });
  const callArgHops = dedupeHops(hops).filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg');

  assert.deepEqual(callArgHops.map((h) => h.dataElementId).sort(), ['data:email', 'data:ssn']);
  assert.equal(callArgHops.length, 2, `Decision 4: per-identity, never a Set-valued record, got: ${JSON.stringify(callArgHops)}`);
});

// ---------------------------------------------------------------------
// Sub-project C, increment 2, Task 2, Step 3: the single comprehensive
// coverage-proof test. Uses buildComprehensiveFixture() (defined above,
// shared with the write-only invariant test) — a realistic function
// exercising EVERY hop-emitting case from both §10.1 (Task 1) and §10.2
// (this task) together: member reads (wildcard and non-wildcard, both
// non-path-base variants), array/tpl/binary/logical/union, a resolved and
// an unresolved call, an assign-expr, a wildcard write, an
// unsupported-target write, a bare call statement, plus C1's own
// ident/object/assign(normal)/return. Full intraprocedural instrumentation
// (§10.1 + §10.2) is complete exactly when every one of these fires at
// least once from a single, real-parser analysis.
// ---------------------------------------------------------------------

test('full intraprocedural coverage proof: every §10.1 + §10.2 hop-emitting (kind, subKind) pair fires at least once in one realistic function', () => {
  const { fn, entryState, resolveCallSummary } = buildComprehensiveFixture();

  const rawHops = [];
  const result = analyzeFunctionFieldIdentity(fn, entryState, { resolveCallSummary, recordHop: (h) => rawHops.push(h) });
  const hops = dedupeHops(rawHops);

  // Every hop record has the full, stable shape (§3), same guard the §6
  // worked-example test already pins.
  const REQUIRED_FIELDS = [
    'kind', 'subKind', 'scope', 'dataElementId', 'fromPath', 'toPath',
    'syntacticPath', 'nodeId', 'line', 'widenReason', 'lossReason',
    // Sub-project C, increment 3, §13.0: three more fields, same
    // always-present/never-undefined contract as every field above —
    // absorbed from the PoC's own dedicated additivity test (scenario 6),
    // which this REQUIRED_FIELDS check now subsumes.
    'context', 'peerScope', 'peerContext',
  ];
  for (const h of hops) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(h, field), `hop record missing field "${field}": ${JSON.stringify(h)}`);
      assert.notEqual(h[field], undefined, `hop record field "${field}" must never be undefined: ${JSON.stringify(h)}`);
    }
  }

  // (a) Every expected (kind, subKind) combination from §10.1 + §10.2 that
  // this fixture is designed to exercise appears at least once. This is
  // the FULL set of hop-emitting shapes across both tables (excluding
  // `object`'s spread/`*`-keyed sub-variants and `member`'s two non-path
  // sub-variants, which share their parent's (kind, subKind) pair and are
  // asserted individually below instead).
  const EXPECTED_SHAPES = [
    'production/ident',       // §10.1 ident
    'selection/member',       // §10.1 member (all four sub-cases)
    'production/object',      // §10.1 object
    'production/array',       // §10.1 array
    'production/tpl',         // §10.1 tpl
    'production/binary',      // §10.1 binary
    'production/logical',     // §10.1 logical
    'production/union',       // §10.1 union (ternary)
    'production/call',        // §10.1 call (unresolved)
    'production/call-resolved', // §10.1 call (resolved)
    'production/assign-expr', // §10.1 assign-expr
    'write-out/assign',       // §10.2 assign (normal AND the unsupported-target loss)
    'write-out/assign-weak',  // §10.2 assign (wildcard target)
    'write-out/call-arg',     // §10.2 call (bare statement)
    'write-out/return',       // §10.2 return (C1 site, present for completeness)
  ];
  const actualShapes = new Set(hops.map((h) => `${h.kind}/${h.subKind}`));
  for (const shape of EXPECTED_SHAPES) {
    assert.ok(actualShapes.has(shape), `expected shape "${shape}" to fire at least once, got shapes: ${JSON.stringify([...actualShapes].sort())}`);
  }
  // And no OTHER shape appeared — every hop this fixture produces is
  // accounted for in the expected set above (same discipline as the §6
  // worked-example test's own closed-shape-set assertion).
  for (const shape of actualShapes) {
    assert.ok(EXPECTED_SHAPES.includes(shape), `unexpected hop shape emitted: ${shape}`);
  }

  // --- Finer-grained assertions distinguishing the sub-cases that share a
  // (kind, subKind) pair with a sibling case ------------------------------

  // member: both a wildcard read (widened) and a non-wildcard read
  // (explicit) must be present.
  const memberHops = hops.filter((h) => h.kind === 'selection' && h.subKind === 'member');
  assert.ok(memberHops.some((h) => h.widenReason === 'dynamic-property-key'), 'expected at least one widened (wildcard/dynamic-key) selection/member hop');
  assert.ok(memberHops.some((h) => h.widenReason === null), 'expected at least one explicit (non-wildcard) selection/member hop');
  // The wildcard-read hop's fromPath must be the definite prefix, never a
  // raw '*'-containing path (Decision 5) — checked across every hop, not
  // just this one shape, since Decision 5 is a whole-DAG invariant.
  for (const h of hops) {
    assert.ok(h.fromPath === null || !h.fromPath.includes('*'), `fromPath must never contain a wildcard segment: ${JSON.stringify(h)}`);
    assert.ok(h.toPath === null || !h.toPath.includes('*'), `toPath must never contain a wildcard segment: ${JSON.stringify(h)}`);
  }

  // call: both the unresolved ('unresolved-call') and resolved (widenReason
  // null) production hops must be present, and distinguishable.
  const unresolvedCallHops = hops.filter((h) => h.kind === 'production' && h.subKind === 'call');
  assert.ok(unresolvedCallHops.length > 0 && unresolvedCallHops.every((h) => h.widenReason === 'unresolved-call'));
  const resolvedCallHops = hops.filter((h) => h.kind === 'production' && h.subKind === 'call-resolved');
  assert.ok(resolvedCallHops.length > 0 && resolvedCallHops.every((h) => h.widenReason === null));

  // assign: both the normal write-out (no lossReason) and the
  // unsupported-target loss (lossReason: 'unsupported-target') must be
  // present under the SAME (kind, subKind) pair.
  const assignHops = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'assign');
  assert.ok(assignHops.some((h) => h.lossReason === null && h.toPath !== null), 'expected at least one normal (non-loss) write-out/assign hop');
  const lossHops = assignHops.filter((h) => h.lossReason === 'unsupported-target');
  assert.ok(lossHops.length > 0, 'expected at least one write-out/assign hop with lossReason "unsupported-target" (the destructuring-assignment-expression write)');
  assert.ok(lossHops.every((h) => h.toPath === null), 'a loss-marked assign hop must never fabricate a toPath (Decision 5)');

  // assign-weak: the wildcard write's toPath must be the container
  // ('bag'), never the raw wildcard target.
  const assignWeakHops = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'assign-weak');
  assert.ok(assignWeakHops.length > 0);
  assert.ok(assignWeakHops.every((h) => h.toPath === 'bag' && h.widenReason === 'dynamic-property-key'));

  // call-arg: the bare `logEvent(user.auditField)` statement's escape hop.
  const callArgHops = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg');
  assert.ok(callArgHops.length > 0 && callArgHops.every((h) => h.toPath === null && h.lossReason === null));

  // (b) The "emits nothing" cases genuinely produce none — checked against
  // THIS SAME fixture's own exit state (not a disconnected fixture),
  // reusing the same recorder so a regression here would show up as growth
  // in the very hops array already asserted above.
  const hopsBeforeEmptyChecks = hops.length;
  const rawHopsSnapshotLength = rawHops.length;
  resolveExprIdentities(result.exitState, { kind: 'literal', value: 'no-identity-here' }, { recordHop: (h) => rawHops.push(h) });
  resolveExprIdentities(result.exitState, { kind: 'unknown' }, { recordHop: (h) => rawHops.push(h) });
  assert.equal(rawHops.length, rawHopsSnapshotLength, 'literal/unknown must emit zero additional hops, even against this fixture\'s own real exit state');
  assert.equal(dedupeHops(rawHops).length, hopsBeforeEmptyChecks, 'deduplicated hop count must be unaffected by the literal/unknown no-op probes');

  // (c) field-identity-observable output identity with/without a recorder
  // for this SAME fixture is proven by the write-only invariant test above
  // (this fixture is one of its entries) — not re-asserted here as a
  // separate, disconnected fact, per the plan's own instruction. Sanity
  // check only: the analysis itself still produced a real result.
  assert.equal(result.returnFacts.length, 1);
  assert.ok(result.returnFacts[0].identities.size > 0);
});
