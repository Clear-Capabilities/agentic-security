// Path provenance hop-recording proof of concept (Sub-project C, increment
// 1, Task 2). See scanner/src/lineage/DESIGN_PATH_PROVENANCE.md — the
// binding spec for the hop record shape and injection mechanism. This task
// instruments a deliberately small, representative FOUR-site subset only
// (resolveExprIdentities's `ident`/`object` cases, step()'s non-wildcard
// `assign` and `return` cases) — NOT full coverage (that's increment C2,
// see DESIGN_PATH_PROVENANCE.md §10). `member`/`selection` hops are
// therefore NEVER emitted by this task's code, which is why the hop set a
// real fixture produces here is a strict subset of DESIGN_PATH_PROVENANCE
// .md §6's full worked-example table (that table also includes two
// selection/member rows this increment does not instrument).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity, identitiesAt } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity, contributingKeys } from '../../src/lineage/engine.js';

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
// L1 fix-round addition: the three tests above never actually compared
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

// ---------------------------------------------------------------------
// 2 & 3. A real parsed example exercising all four instrumented sites in
//    one function (DESIGN_PATH_PROVENANCE.md §6's own worked example),
//    asserting the recorded hops are correct and complete for exactly
//    those four sites, and that hops are genuinely PER-IDENTITY (Decision
//    4) — two distinct ids flowing through the same construct give two
//    separate records, never one carrying a Set.
// ---------------------------------------------------------------------

test('DESIGN_PATH_PROVENANCE.md §6 worked example, real parsed source: hops for all four instrumented sites are correct and complete', () => {
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
  ];
  for (const h of hops) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(h, field), `hop record missing field "${field}": ${JSON.stringify(h)}`);
      assert.notEqual(h[field], undefined, `hop record field "${field}" must never be undefined: ${JSON.stringify(h)}`);
    }
  }

  // Only the four instrumented site (kind, subKind) shapes ever appear —
  // proof that no other resolveExprIdentities/step case was accidentally
  // instrumented too.
  const shapes = new Set(hops.map((h) => `${h.kind}/${h.subKind}`));
  for (const shape of shapes) {
    assert.ok(
      ['production/ident', 'production/object', 'write-out/assign', 'write-out/return'].includes(shape),
      `unexpected hop shape emitted: ${shape} (Task 2 instruments exactly four sites)`,
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
  // `member` is NOT instrumented by this task, so there is no selection
  // in-half here — only the object literal's own production/object
  // annotation (fromPath: null, per identity) and the write-out to o.*.
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

  // --- Joining the two INSTRUMENTED ends of the flow (Decision 6) ------
  // n1's in-half + out-half join into a real edge at each id's own node:
  //   user.email -> u.email  (data:email)
  //   user.ssn   -> u.ssn    (data:ssn)
  // n3's in-half + out-half join into a real exit edge:
  //   o.email -> <return>    (data:email)
  //   o.ssn   -> <return>    (data:ssn)
  // (n2's own join is intentionally partial in this increment — see the
  // module comment above; C2 closes it by instrumenting `member`.)
  assert.equal(uEmailIdent.nodeId, assignHops.find((h) => h.toPath === 'u.email').nodeId, 'n1\'s in-half and out-half for data:email must share the same nodeId (the join key)');
  assert.equal(oEmailIdent.nodeId, returnHops.find((h) => h.dataElementId === 'data:email').nodeId, 'n3\'s in-half and out-half for data:email must share the same nodeId (the join key)');

  // Total record count for this fixture, deduplicated: 4 hops at n1
  // (2 production/ident + 2 write-out/assign) + 4 hops at n2 (2
  // production/object + 2 write-out/assign; no selection/member since
  // that case is not instrumented by this task) + 4 hops at n3 (2
  // production/ident + 2 write-out/return) = 12. Matches
  // DESIGN_PATH_PROVENANCE.md §6's own closing count ("twelve deduplicated
  // records") for exactly this fixture under this increment's four-site
  // scope — see that document's note on the worked-example table
  // including two additional selection/member rows that only a FULL
  // (post-C2) instrumentation would actually emit.
  assert.equal(hops.length, 12, `expected exactly 12 deduplicated hop records for this fixture under Task 2's four-site scope, got ${hops.length}: ${JSON.stringify(hops, null, 2)}`);
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
