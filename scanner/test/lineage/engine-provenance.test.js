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
