// Sub-project C, increment C4 — `path-store.js` (the compact provenance
// DAG) and `ids.js`'s two new stable-ID functions, `provenanceNodeId`/
// `provenanceEdgeId`.
//
// Absorbed from the design task's throwaway-named PoC
// (`path-store-poc.test.js`, deleted in the same commit that absorbed it —
// §14.10 item 11), re-pointed at the SHIPPED `src/lineage/path-store.js`/
// `src/lineage/ids.js` rather than a local prototype. Every assertion from
// the PoC is kept, including `C4/Q2b` (§14.10 item 12) — it is the only
// guard that stops §14.4's correction to §2.2 being silently undone by a
// future refactor of `classifyIn`. Two new fixtures close Task 1's own
// review findings 2 and 3 (§14.7's rejected leg-based-pruning
// counter-example, and §14.11's headline compactness numbers) — see the
// bottom of this file.
//
// The two questions this design answers (both proven, not argued — see
// DESIGN_PATH_PROVENANCE.md §14.3/§14.4):
//
//   Q1  Cross-function node addressing: is a `write-out/call-arg-bind`
//       hop's DESTINATION node `(peerScope, peerContext, toPath, id)`,
//       rather than `(scope, context, toPath, id)`? Yes (test "C4/Q1").
//   Q2  Does the `call-resolved` hop's `fromPath: null` ever form a real
//       edge? Yes — a real CROSS-SCOPE edge from the callee's own
//       function-exit node — but only once §2.2's annotation rule is
//       corrected (test "C4/Q2", "C4/Q2b").

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import {
  FieldIdentitySummaryCache,
  createCallSummaryResolver,
} from '../../src/lineage/summaries.js';
import { provenanceNodeId, provenanceEdgeId } from '../../src/lineage/ids.js';
import { PathStore, classifyIn, classifyOut } from '../../src/lineage/path-store.js';

// =====================================================================
// §14.10 item 5: the isolation boundary is enforced by a test, not just
// documented. `path-store.js` must NEVER import engine.js/summaries.js/
// driver.js — it consumes their OUTPUT (a hop-record stream), never their
// internals.
// =====================================================================

test('boundary: path-store.js never imports engine.js, summaries.js, or driver.js (§14.1)', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/path-store.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  // Task 2 review finding 5: a line-anchored `/^import\s.*$/gm` only sees a
  // statement's FIRST physical line, so a multi-line specifier list (or a
  // `export { x } from '...'` re-export, or a dynamic `import('...')`) hides
  // the module path from this guard entirely — verified by injecting such a
  // violation and confirming it passed uncaught before this fix. Match every
  // module specifier string that follows `from`/`import(`/`export ... from`
  // ANYWHERE in the source instead, so the guard is order- and
  // line-layout-independent.
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.ok(specifiers.length > 0, 'sanity: the file does import something (ids.js)');
  for (const spec of specifiers) {
    assert.ok(!/\/(engine|summaries|driver)\.js$/.test(spec),
      `path-store.js must never import engine.js/summaries.js/driver.js — found: ${spec}`);
  }
  assert.ok(specifiers.some((s) => /\/ids\.js$/.test(s)), 'it must still import ids.js');
});

// =====================================================================
// Shared harness (the hand-seeding technique from
// engine-provenance-interprocedural.test.js). A real project-wide driver
// run still emits ZERO hops today (no source registry, Sub-project D/E),
// so every fixture below seeds an entry state by hand and drives
// `analyzeFunctionFieldIdentity` / the real `FieldIdentitySummaryCache` +
// `createCallSummaryResolver` machinery directly.
// =====================================================================

function parseFns(src, file) {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must parse this fixture source');
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  return byName;
}

function lookupCalleeFor(byName) {
  return (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };
}

/** Runs one function with a recorder and returns {raw, store, result}. */
function record(fn, entryState, { byName, cache } = {}) {
  const raw = [];
  const ctx = { recordHop: (h) => raw.push(h) };
  if (byName) {
    ctx.resolveCallSummary = createCallSummaryResolver(cache ?? new FieldIdentitySummaryCache(), lookupCalleeFor(byName));
  }
  const result = analyzeFunctionFieldIdentity(fn, entryState, ctx);
  const store = new PathStore();
  store.addHops(raw);
  return { raw, store, result };
}

const pathNode = (scope, context, path, dataElementId) => ({
  kind: 'path', scope, context, path, siteNodeId: null, dataElementId,
});
const returnNode = (scope, context, dataElementId) => ({
  kind: 'return', scope, context, path: null, siteNodeId: null, dataElementId,
});

// =====================================================================
// 1. The simple intraprocedural chain.
// =====================================================================

test('C4/1: `const b = a.email; return b;` builds exactly 3 nodes and 2 edges — no more, no fewer', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c4-chain.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const ctx = raw[0].context;
  const scope = byName.f.qid;
  assert.ok(typeof ctx === 'string' && ctx.length > 0);

  const nAEmail = store.nodeIdFor(pathNode(scope, ctx, 'a.email', 'data:email'));
  const nB = store.nodeIdFor(pathNode(scope, ctx, 'b', 'data:email'));
  const nExit = store.nodeIdFor(returnNode(scope, ctx, 'data:email'));

  assert.deepEqual(
    store.nodes().map((n) => n.id).sort(),
    [nAEmail, nB, nExit].sort(),
    `expected exactly the 3 nodes a.email / b / <exit>; got ${JSON.stringify(store.nodes().map((n) => `${n.kind}:${n.path}`))}`,
  );
  assert.equal(store.edges().length, 2, 'exactly two edges: a.email -> b, b -> <exit>');
  assert.ok(store.hasEdge(nAEmail, nB), 'a.email -> b');
  assert.ok(store.hasEdge(nB, nExit), 'b -> <exit>');
  assert.equal(store.edgesTo(nAEmail).length, 0, 'a.email is the origin of this path — nothing flows into it');
  assert.equal(store.edgesFrom(nExit).length, 0, 'the exit node is terminal');

  // Every edge is field-precise and carries its site for FR-305/§9.2.
  for (const e of store.edges()) {
    assert.equal(e.dataElementId, 'data:email');
    assert.equal(e.scope, scope);
    assert.equal(e.context, ctx);
    assert.equal(typeof e.siteNodeId, 'string');
    assert.equal(typeof e.line, 'number');
    assert.equal(e.ambiguousCorrelation, false);
    assert.equal(e.crossScope, false);
  }
  assert.deepEqual(store.diagnostics().unclassified, [], 'every hop shape in this fixture is classified');
  assert.deepEqual(store.diagnostics().malformed, [], 'every hop carries all 14 fields');
  assert.deepEqual(store.diagnostics().orphanedPeerSources, [], 'no peer-sourced hop in a plain intraprocedural fixture');
});

test('C4/1b: two identities through one construct stay field-distinct end to end (FR-301 carried into FR-303\'s structure) — and this IS §6\'s own worked example: 14 dedup records -> 8 nodes / 6 edges (§14.11)', () => {
  const src = `
    function f(user) {
      const u = user;
      const o = { email: u.email, ssn: u.ssn };
      return o;
    }
  `;
  const byName = parseFns(src, '/x/c4-six.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const { store, raw } = record(byName.f, entryState);
  const ctx = raw[0].context;
  const scope = byName.f.qid;

  // §6's own worked example: two ordered paths that never touch.
  for (const [field, id] of [['email', 'data:email'], ['ssn', 'data:ssn']]) {
    const chain = [
      pathNode(scope, ctx, `user.${field}`, id),
      pathNode(scope, ctx, `u.${field}`, id),
      pathNode(scope, ctx, `o.${field}`, id),
      returnNode(scope, ctx, id),
    ].map((d) => store.nodeIdFor(d));
    for (let i = 0; i < chain.length - 1; i++) {
      assert.ok(store.hasEdge(chain[i], chain[i + 1]), `${id}: hop ${i} -> ${i + 1} missing`);
    }
  }
  // The two elements never share a node.
  const byId = new Map();
  for (const n of store.nodes()) {
    assert.ok(!byId.has(n.id) || byId.get(n.id) === n.dataElementId);
    byId.set(n.id, n.dataElementId);
  }
  // The object literal is an EDGE annotation, never a node (§2.1).
  assert.ok(store.nodes().every((n) => n.kind !== 'origin'), 'the object literal produced no node of its own');
  const objAnnotated = store.edges().filter((e) => e.annotations.some((a) => a.subKind === 'object'));
  assert.ok(objAnnotated.length > 0, 'the production/object hop survives as an edge annotation');

  // (review finding 3, §14.10 item 10 / §14.11) — the FR-303 compactness
  // headline: 14 deduplicated records become 8 nodes and 6 edges, with
  // zero materialized paths. Pinned so a future refactor that silently
  // changes these published numbers fails a test rather than just leaving
  // CLAUDE.md/the design doc stale.
  const s = store.stats();
  assert.equal(s.hopsOffered, 14, 'raw records offered');
  assert.equal(s.hopsAccepted, 14, 'no re-visitation on this straight-line fixture, so dedup accepts all 14');
  assert.equal(s.nodes, 8, '§14.11: 14 dedup records -> 8 nodes');
  assert.equal(s.edges, 6, '§14.11: 14 dedup records -> 6 edges (FR-303\'s compactness proof)');
});

test('C4/1c: worklist re-emission (Decision 8) is collapsed at ingest — a loop fixture offers far more hops than it accepts, and the DAG is identical either way', () => {
  const src = `
    function f(user) {
      let a = user.email;
      let b = 0;
      while (b) { const t = a; a = t; }
      return a;
    }
  `;
  const byName = parseFns(src, '/x/c4-loop.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const s = store.stats();
  assert.ok(s.hopsOffered > s.hopsAccepted, `the worklist must re-emit on this loop fixture (offered ${s.hopsOffered}, accepted ${s.hopsAccepted})`);

  // Feeding the SAME stream twice must not change anything — the store is
  // idempotent under duplicate delivery, which is the property Decision 8
  // pushes onto the consumer.
  const before = { nodes: store.nodes().length, edges: store.edges().length };
  store.addHops(raw);
  store.addHops(raw);
  assert.deepEqual({ nodes: store.nodes().length, edges: store.edges().length }, before);
});

test('C4/1d: the two dedup boundaries are NOT equivalent — raw-hop dedup alone leaves duplicate edges that only node/edge-id dedup collapses', () => {
  // Two DIFFERENT hop records (different `syntacticPath`) describing the
  // SAME logical edge. Raw-hop content dedup keeps both; the edge-id map
  // collapses them, because `syntacticPath` is display material and is
  // deliberately not part of the edge discriminator.
  const base = {
    scope: 'S', nodeId: 'n1', context: 'C', dataElementId: 'data:e', line: 1,
    peerScope: null, peerContext: null, widenReason: null, lossReason: null,
  };
  const store = new PathStore();
  assert.equal(store.addHop({ ...base, kind: 'production', subKind: 'ident', fromPath: 'a.email', toPath: null, syntacticPath: 'a' }), true);
  assert.equal(store.addHop({ ...base, kind: 'production', subKind: 'ident', fromPath: 'a.email', toPath: null, syntacticPath: null }), true);
  store.addHop({ ...base, kind: 'write-out', subKind: 'assign', fromPath: null, toPath: 'b', syntacticPath: null });

  assert.equal(store.stats().hopsAccepted, 3, 'raw-hop dedup keeps both in-halves: they are not byte-identical');
  assert.equal(store.edges().length, 1, 'edge-id dedup collapses them into ONE edge — this is the correctness-bearing dedup');
});

// =====================================================================
// 2. Q1 — cross-function node addressing.
// =====================================================================

test('C4/Q1: a call-arg-bind hop\'s DESTINATION node is (peerScope, peerContext, toPath, id) — proven by it being byte-identical to the node the CALLEE\'s own hops independently create', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q1.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.ok(bind, 'the shipped resolver emits the binding hop');
  assert.equal(bind.scope, byName.caller.qid, 'stamped with the CALLER\'s scope (§13.2)');
  assert.equal(bind.peerScope, byName.helper.qid);
  assert.equal(bind.toPath, 'u.email');

  // The callee's OWN in-half for the same location, recorded independently
  // inside helper's own analysis run.
  const calleeRead = raw.find((h) => h.scope === byName.helper.qid && h.fromPath === 'u.email');
  assert.ok(calleeRead, 'helper\'s own selection/member from u.email is in the stream');

  const peerAddressed = store.nodeIdFor(pathNode(bind.peerScope, bind.peerContext, bind.toPath, bind.dataElementId));
  const calleeOwn = store.nodeIdFor(pathNode(calleeRead.scope, calleeRead.context, calleeRead.fromPath, calleeRead.dataElementId));
  assert.equal(peerAddressed, calleeOwn, 'ANSWER TO Q1: peer addressing lands on exactly the node the callee itself created');

  // And the naive alternative (the hop's own stamped scope/context) does not.
  const naive = store.nodeIdFor(pathNode(bind.scope, bind.context, bind.toPath, bind.dataElementId));
  assert.notEqual(naive, calleeOwn, 'naive (own-scope) addressing would create a DIFFERENT node');
  assert.equal(store.getNode(naive), null, 'and that node exists nowhere in the built store — it would be an orphan no hop can reach');

  // The store, built with peer addressing, really connects them.
  assert.ok(store.hasEdge(
    store.nodeIdFor(pathNode(bind.scope, bind.context, 'a.email', 'data:email')),
    calleeOwn,
  ), 'a.email (caller) -> u.email (callee) is a real cross-scope edge');
  const crossEdge = store.edgesTo(calleeOwn).find((e) => e.outSubKind === 'call-arg-bind');
  assert.ok(crossEdge.crossScope, 'and it is marked cross-scope');
});

test('C4/Q1b: naive own-scope addressing COLLIDES with a caller-local variable of the same name — Decision 5\'s bug class, avoided only by peerScope', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const u = a.email; const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q1b.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.equal(bind.toPath, 'u.email', 'the callee\'s parameter is also named `u`');
  const callerLocalU = raw.find((h) => h.scope === byName.caller.qid && h.kind === 'write-out' && h.toPath === 'u');
  assert.ok(callerLocalU, 'the caller has its OWN local `u`');

  const naive = store.nodeIdFor(pathNode(bind.scope, bind.context, 'u', bind.dataElementId));
  const callerU = store.nodeIdFor(pathNode(callerLocalU.scope, callerLocalU.context, 'u', callerLocalU.dataElementId));
  assert.equal(naive, callerU, 'PROOF OF THE HAZARD: own-scope addressing of the callee parameter `u` is the SAME id as the caller\'s local `u`');

  const correct = store.nodeIdFor(pathNode(bind.peerScope, bind.peerContext, 'u.email', bind.dataElementId));
  assert.notEqual(correct, callerU, 'peer addressing keeps the two namespaces apart');
  assert.ok(store.getNode(correct), 'and the peer-addressed node is real');
  // The caller's own `u` must not have acquired the callee's binding edge.
  assert.ok(!store.edgesTo(callerU).some((e) => e.outSubKind === 'call-arg-bind'),
    'no binding edge lands on the caller-local `u`');
});

// =====================================================================
// 3. Q2 — does `call-resolved`'s null fromPath stitch the return value?
// =====================================================================

test('C4/Q2: the callee\'s return value reaches the caller\'s variable — via a CROSS-SCOPE edge from the callee\'s own function-exit node, addressed by the call-resolved hop\'s peerScope/peerContext', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q2.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw, result } = record(byName.caller, entryState, { byName });
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the analysis really does carry the identity across the call');

  const callerCtx = raw.find((h) => h.scope === byName.caller.qid).context;
  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const cr = raw.find((h) => h.subKind === 'call-resolved');
  assert.equal(cr.fromPath, null, 'the call-resolved hop carries NO fromPath — this is the whole question');
  assert.equal(cr.peerScope, byName.helper.qid);
  assert.equal(cr.peerContext, calleeCtx, 'and its peerContext is byte-equal to the context the callee\'s own body was recorded under');

  const nArg = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'a.email', 'data:email'));
  const nParam = store.nodeIdFor(pathNode(byName.helper.qid, calleeCtx, 'u.email', 'data:email'));
  const nCalleeExit = store.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));
  const nOut = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'out', 'data:email'));
  const nCallerExit = store.nodeIdFor(returnNode(byName.caller.qid, callerCtx, 'data:email'));

  // ANSWER TO Q2: the full four-hop chain exists, and it goes THROUGH the
  // callee rather than around it.
  const chain = [nArg, nParam, nCalleeExit, nOut, nCallerExit];
  for (let i = 0; i < chain.length - 1; i++) {
    assert.ok(store.hasEdge(chain[i], chain[i + 1]),
      `missing hop ${i} -> ${i + 1} of the cross-function chain`);
  }
  const stitch = store.edgesFrom(nCalleeExit).find((e) => e.toNodeId === nOut);
  assert.equal(stitch.inSubKind, 'call-resolved', 'the stitch\'s in-half IS the call-resolved hop');
  assert.equal(stitch.crossScope, true);

  // The one remaining, honestly-disclosed artefact (§14.7): the argument's
  // in-half and the caller-local landing out-half are at the same join key,
  // so the cross product also contains a BYPASS edge a.email -> out that
  // skips the callee. It is kept (dropping it would need leg-based pruning,
  // which §14.7 shows drops REAL edges in a mixed group) and marked.
  const bypass = store.edgesFrom(nArg).find((e) => e.toNodeId === nOut);
  assert.ok(bypass, 'the bypass edge exists');
  assert.equal(bypass.ambiguousCorrelation, true, 'and is the ONLY edge here marked ambiguous');
  assert.equal(store.edges().filter((e) => e.ambiguousCorrelation).length, 1,
    'the per-pairing ambiguity measure (§14.7) leaves the four real chain edges unmarked — §9.1\'s group-level test marked three of five here');
  for (const e of [store.edgesFrom(nArg).find((x) => x.toNodeId === nParam), stitch]) {
    assert.equal(e.ambiguousCorrelation, false, 'the two genuine call-boundary edges are NOT devalued by the marker');
  }

  // §14.11's measured numbers for the plain 2-function resolved call.
  const s = store.stats();
  assert.equal(s.hopsOffered, 8);
  assert.equal(s.hopsAccepted, 8);
  assert.equal(s.nodes, 5);
  assert.equal(s.edges, 5);
});

test('C4/Q2b: §2.2\'s annotation rule, applied LITERALLY, silently deletes that stitch — this is the correction §14.4 makes', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q2b.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { raw } = record(byName.caller, entryState, { byName });

  // Reproduce §2.2 verbatim: "a null-fromPath in-half is an ANNOTATION on
  // the edges formed by any non-null in-half at the same key ... It forms
  // a real edge only when NO non-null in-half exists at that key."
  const callNodeHops = raw.filter((h) => h.subKind === 'call-resolved');
  const cr = callNodeHops[0];
  const sameKey = raw.filter((h) => h.scope === cr.scope && h.nodeId === cr.nodeId
    && h.dataElementId === cr.dataElementId && h.context === cr.context);
  const nonNullInHalves = sameKey.filter((h) => (h.kind === 'production' || h.kind === 'selection') && h.fromPath !== null);
  assert.ok(nonNullInHalves.length > 0,
    'THE DEFECT: the argument expression\'s own in-half sits at the SAME join key as the call-resolved hop, so §2.2 demotes call-resolved to an annotation');
  assert.deepEqual(nonNullInHalves.map((h) => h.fromPath), ['a.email']);

  // Under the literal rule the callee's exit node has no outgoing edge at
  // all: reconstruction from `out` would report the argument as its
  // immediate predecessor and the callee body would be unreachable.
  const strict = new PathStore();
  strict.addHops(raw.map((h) => (h.subKind === 'call-resolved' ? { ...h, peerScope: null, peerContext: null } : h)));
  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const nCalleeExit = strict.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));
  assert.equal(strict.edgesFrom(nCalleeExit).length, 0,
    'under the literal §2.2 reading the callee\'s exit is a dead end — the return value never reaches the caller');
});

test('C4/Q2c: the peer-addressed rule does NOT fire for a §13.6 context-cap-degraded call-resolved hop — that one really is an annotation, because its callee has no recorded body', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(src, '/x/c4-q2c.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');
  // Cap of 1 distinct entry context per function — the shipped B6
  // degradation path (`FieldIdentitySummaryCache(1)`, positional).
  const cache = new FieldIdentitySummaryCache(1);
  const { store, raw } = record(byName.outer, entryState, { byName, cache });

  const degraded = raw.find((h) => h.lossReason === 'context-cap-degraded');
  assert.ok(degraded, 'the shipped resolver emits the §13.6 loss hop under a cap-1 cache');
  assert.equal(degraded.fromPath, null);
  assert.equal(degraded.toPath, null);
  assert.ok(degraded.peerScope, 'it still names the callee');

  // It must NOT create an edge out of a fabricated callee exit node.
  const phantomExit = store.nodeIdFor(returnNode(degraded.peerScope, degraded.peerContext, degraded.dataElementId));
  assert.equal(store.getNode(phantomExit), null,
    'no exit node is fabricated for a callee whose body was never analyzed — that would be a path that begins in the middle of nothing');

  // But it is NEVER dropped: it survives as an annotation on the real
  // argument -> parameter edge at the same join key (§13.6's own
  // "C4 must surface it under both readings; what it must never do is
  // drop it").
  const annotated = store.edges().filter((e) => e.annotations.some((a) => a.lossReason === 'context-cap-degraded'));
  assert.ok(annotated.length > 0, 'the degradation is visible on a real edge');
  assert.ok(annotated.some((e) => e.outSubKind === 'call-arg-bind'),
    'specifically on the argument -> parameter binding edge, which is where the data actually went');
  assert.deepEqual(store.diagnostics().orphanedPeerSources, [], 'a degraded hop is classified as an annotation, never as peer-sourced — nothing to orphan here');
});

// =====================================================================
// 4. Cycles.
// =====================================================================

test('C4/4: a mutually-recursive call graph builds without recursing, stack-overflowing, or looping — and the store honestly contains a cycle (§14.11: 34 raw -> 19 dedup -> 8 nodes / 11 edges)', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c4-cycle.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.top, entryState, { byName });
  assert.ok(raw.length > 0);
  assert.deepEqual(store.diagnostics().unclassified, []);

  const s = store.stats();
  assert.ok(s.nodes > 0 && s.edges > 0, `built ${s.nodes} nodes / ${s.edges} edges without recursing`);

  // (review finding 3, §14.11) — the mutual-recursion fixture's own
  // published numbers, pinned so a future refactor cannot silently drift
  // them without failing a test.
  assert.equal(s.hopsOffered, 34, '§14.11: 34 raw records offered');
  assert.equal(s.hopsAccepted, 19, '§14.11: 19 accepted after ingest dedup');
  assert.equal(s.nodes, 8, '§14.11: 8 nodes');
  assert.equal(s.edges, 11, '§14.11: 11 edges');

  // The store's own construction never walks the graph, so it cannot spin.
  // Prove a cycle nonetheless EXISTS, with an explicitly bounded walk in
  // the TEST (never in path-store.js itself — §14.6/§9.3).
  const adjacency = new Map();
  for (const e of store.edges()) {
    if (!adjacency.has(e.fromNodeId)) adjacency.set(e.fromNodeId, []);
    adjacency.get(e.fromNodeId).push(e.toNodeId);
  }
  let cyclic = false;
  const BUDGET = 20000;
  let steps = 0;
  for (const start of adjacency.keys()) {
    const stack = [[start, new Set([start])]];
    while (stack.length && steps < BUDGET) {
      steps += 1;
      const [cur, seen] = stack.pop();
      for (const nxt of adjacency.get(cur) ?? []) {
        if (nxt === start) { cyclic = true; break; }
        if (!seen.has(nxt)) stack.push([nxt, new Set([...seen, nxt])]);
      }
      if (cyclic) break;
    }
    if (cyclic) break;
  }
  assert.ok(cyclic, 'a real cycle exists in this DAG — §9.3 is not hypothetical, and C5 must be cycle-safe by construction');
});

test('C4/4b: the peer x peer exclusion is load-bearing — without it, EVERY resolved call manufactures a callee-exit -> callee-parameter cycle that no program executed', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-peerpeer.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const nParam = store.nodeIdFor(pathNode(byName.helper.qid, calleeCtx, 'u.email', 'data:email'));
  const nExit = store.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));

  assert.ok(store.hasEdge(nParam, nExit), 'the callee\'s own body edge is present (recorded by the callee\'s own hops)');
  assert.equal(store.hasEdge(nExit, nParam), false,
    'and the reverse edge — which a naive full cross product of the call group WOULD create — is excluded');

  // Show the naive product really would create it: the call-resolved
  // in-half and the call-arg-bind out-half share a join key (same
  // scope/nodeId/dataElementId/context), so a naive cross product pairs
  // them, and both classify as crossScope.
  const cr = raw.find((h) => h.subKind === 'call-resolved');
  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.equal(cr.scope, bind.scope);
  assert.equal(cr.nodeId, bind.nodeId);
  assert.equal(cr.dataElementId, bind.dataElementId);
  assert.equal(cr.context, bind.context);
  assert.equal(classifyIn(cr).crossScope, true);
  assert.equal(classifyOut(bind).crossScope, true);
});

// =====================================================================
// 5. Stable-ID behaviour.
// =====================================================================

test('C4/5: provenanceEdgeId is idempotent for the same logical edge and never collides for a structurally different one', () => {
  const src = 'function f(a) { const b = a.email; return b; }';
  const byName = parseFns(src, '/x/c4-ids.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { raw } = record(byName.f, entryState);

  // Idempotence across two independent runs and across re-delivery.
  const s1 = new PathStore(); s1.addHops(raw);
  const s2 = new PathStore(); s2.addHops(raw); s2.addHops(raw);
  const { raw: raw2 } = record(byName.f, entryState);
  const s3 = new PathStore(); s3.addHops(raw2);
  const ids = (s) => s.edges().map((e) => e.id).sort();
  assert.deepEqual(ids(s1), ids(s2), 're-delivering the same stream yields identical edge ids');
  assert.deepEqual(ids(s1), ids(s3), 'a second independent analysis run yields identical edge ids (content hash, not a counter)');

  assert.match(s1.edges()[0].id, /^pedge:[0-9a-f]{12}$/);
  assert.match(s1.nodes()[0].id, /^pnode:[a-z]+:[0-9a-f]{12}$/);
});

// =====================================================================
// 6. Terminal nodes, §9.1 marking, §9.5 truncation, malformed hops.
// =====================================================================

test('C4/6: escape and loss terminals are real nodes, so a path that ends at one is reportable as ENDING there rather than as absent (§18.4)', () => {
  const src = `
    function f(user, k) {
      logEvent(user.email);
      ({ z } = user);
      return 1;
    }
  `;
  const byName = parseFns(src, '/x/c4-terminal.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const escapeHop = raw.find((h) => h.subKind === 'call-arg');
  assert.ok(escapeHop, 'the bare call statement emits a write-out/call-arg escape');
  const nEscape = store.nodeIdFor({ kind: 'escape', scope: escapeHop.scope, context: escapeHop.context, path: null, siteNodeId: escapeHop.nodeId, dataElementId: escapeHop.dataElementId });
  assert.ok(store.getNode(nEscape), 'the escape is a real terminal node');
  assert.ok(store.edgesTo(nEscape).length > 0, 'and something flows into it');

  const lossHop = raw.find((h) => h.lossReason === 'unsupported-target');
  assert.ok(lossHop, 'the assignment-expression destructuring is a loss site');
  const nLoss = store.nodeIdFor({ kind: 'loss', scope: lossHop.scope, context: lossHop.context, path: null, siteNodeId: lossHop.nodeId, dataElementId: lossHop.dataElementId });
  assert.ok(store.getNode(nLoss), 'the loss is a real terminal node, never a silently dropped hop');
  const lossEdge = store.edgesTo(nLoss)[0];
  assert.ok(lossEdge.lossReasons.includes('unsupported-target'), 'and the edge carries WHY it is a dead end');
  assert.deepEqual(store.diagnostics().unclassified, []);
});

test('C4/6b: §9.1 cross-join edges are marked, not prevented — at an object literal and, per §13.2, at a multi-argument call site', () => {
  const objSrc = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const objFns = parseFns(objSrc, '/x/c4-xjoin.js');
  let es = addIdentity(emptyState(), 'p.email', 'data:email');
  es = addIdentity(es, 'q.email', 'data:email');
  const { store: objStore } = record(objFns.f, es);
  const marked = objStore.edges().filter((e) => e.ambiguousCorrelation);
  assert.ok(marked.length >= 4, `expected the 2x2 cross product to be marked, got ${marked.length}`);

  const callSrc = `
    function two(p, q) { return { p, q }; }
    function caller(m, n) { const r = two(m, n); return r; }
  `;
  const callFns = parseFns(callSrc, '/x/c4-xjoin2.js');
  let es2 = addIdentity(emptyState(), 'm.email', 'data:email');
  es2 = addIdentity(es2, 'n.email', 'data:email');
  const { store: callStore } = record(callFns.caller, es2, { byName: callFns });
  const callMarked = callStore.edges().filter((e) => e.ambiguousCorrelation && e.outSubKind === 'call-arg-bind');
  assert.ok(callMarked.length >= 4,
    `§13.2's disclosed multi-argument cross-join must be marked, got ${callMarked.length}`);
});

test('C4/6c: §9.5\'s analysis-level truncation has a reserved, out-of-band channel — no new hop `kind` is invented', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c4-trunc.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  assert.ok(store.nodes().every((n) => !n.truncated));
  assert.ok(store.edges().every((e) => !e.truncated));

  store.markTruncated(byName.f.qid, raw[0].context, 'iter-budget');
  assert.ok(store.nodes().every((n) => n.truncated), 'every node in the truncated (scope, context) is marked');
  assert.ok(store.edges().every((e) => e.truncated), 'and every edge — the whole result set, per §9.5');
  assert.deepEqual(store.diagnostics().truncations.map(([, r]) => r), ['iter-budget']);
});

test('C4/6d: a hop with an ABSENT required key is recorded as malformed rather than silently dedup-splitting (§3\'s completeness guarantee, checked at the consumer)', () => {
  const store = new PathStore();
  const good = {
    kind: 'production', subKind: 'ident', scope: 'S', dataElementId: 'data:e',
    fromPath: 'a', toPath: null, syntacticPath: null, nodeId: 'n1', line: 1,
    widenReason: null, lossReason: null, context: 'C', peerScope: null, peerContext: null,
  };
  const { scope, ...missingScope } = good;
  store.addHop(good);
  store.addHop(missingScope);
  assert.equal(store.diagnostics().malformed.length, 1);
  assert.deepEqual(store.diagnostics().malformed[0].missing, ['scope']);
});

test('C4/6f: an unclassifiable hop is recorded in diagnostics().unclassified, never silently dropped (§14.3 rule 6) — Task 2 review finding 10', () => {
  // Every other assertion on `unclassified` elsewhere in this suite checks
  // it is EMPTY on a well-formed fixture — which would pass identically
  // whether the bucket genuinely records or the pusher were replaced with
  // a silent `continue`. This is the one positive test: two distinct ways
  // a hop reaches `classifyOut`'s rule-6 fallthrough / the bare-unknown-kind
  // branch, both of which must show up, not vanish.
  const base = {
    scope: 'S', nodeId: 'n1', context: 'C', dataElementId: 'data:e', line: 1,
    peerScope: null, peerContext: null, syntacticPath: null, lossReason: null,
    widenReason: null,
  };
  const store = new PathStore();
  // (a) a write-out hop matching none of classifyOut's 5 named rules:
  // toPath is null, subKind is neither 'return' nor 'call-arg', and
  // lossReason is null — classifyOut's own rule 6.
  store.addHop({ ...base, kind: 'write-out', subKind: 'mystery-write', toPath: null });
  // (b) a hop whose `kind` isn't in IN_KINDS and isn't 'write-out' at all —
  // the outer unclassified branch in `addHop`.
  store.addHop({ ...base, kind: 'mystery-kind', subKind: 'x', toPath: null });

  const { unclassified } = store.diagnostics();
  assert.equal(unclassified.length, 2, 'both unclassifiable hops must be recorded, not dropped');
  assert.ok(unclassified.some((h) => h.subKind === 'mystery-write'));
  assert.ok(unclassified.some((h) => h.kind === 'mystery-kind'));
  // Neither contributes a node or an edge — recorded as a diagnostic, not
  // silently promoted into graph structure either.
  assert.equal(store.nodes().length, 0);
  assert.equal(store.edges().length, 0);
});

test('C4/6e: an annotation-only group (no non-null in-half anywhere at the key) IS edge-forming, per §2.2\'s surviving half', () => {
  // Hand-built, and disclosed as such in §14.4: no real-parser fixture
  // found during this task produces a group whose ONLY in-half has a null
  // fromPath and a null peerScope, because every construct that carries an
  // identity at all inherits a contributing key from somewhere upstream.
  const base = {
    scope: 'S', nodeId: 'n1', context: 'C', dataElementId: 'data:e', line: 3,
    peerScope: null, peerContext: null, syntacticPath: null, lossReason: null,
  };
  const store = new PathStore();
  store.addHop({ ...base, kind: 'production', subKind: 'call', fromPath: null, toPath: null, widenReason: 'unresolved-call' });
  store.addHop({ ...base, kind: 'write-out', subKind: 'assign', fromPath: null, toPath: 'x', widenReason: 'unresolved-call' });

  assert.equal(store.edges().length, 1);
  const e = store.edges()[0];
  assert.equal(e.originated, true, 'the value originates at this construct — it has no prior aliasing source');
  const origin = store.getNode(e.fromNodeId);
  assert.equal(origin.kind, 'origin');
  assert.equal(origin.siteNodeId, 'n1');
  assert.equal(store.edgesTo(origin.id).length, 0);
});

// =====================================================================
// 7. §14.10 item 10 — the `orphanedPeerSources` diagnostic (Task 1's own
// review finding; the 4th diagnostics() bucket).
// =====================================================================

test('C4/diag: orphanedPeerSources fires for §14.4\'s disclosed stream-completeness gap — a cache warmed by a no-recorder run and reused by a later recorder-attached run leaves a genuinely peer-sourced hop\'s target node with zero real in-edges', () => {
  const src = `
    function helper(u) { return u.email; }
    function callerA(a) { const out = helper(a); return out; }
    function callerB(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-orphan.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const cache = new FieldIdentitySummaryCache();

  // Warm the cache with callerA's run, with NO recorder attached — helper's
  // own body hops never fire.
  const ctxA = { resolveCallSummary: createCallSummaryResolver(cache, lookupCalleeFor(byName)) };
  analyzeFunctionFieldIdentity(byName.callerA, entryState, ctxA);

  // Now analyze callerB against the SAME cache, WITH a recorder attached.
  // helper is a cache HIT for callerB, so helper's own body hops still
  // never fire a second time — yet the resolved summary still carries
  // lossReason: null (it was genuinely, precisely resolved; just not
  // resolved THIS run).
  const raw = [];
  const ctxB = {
    recordHop: (h) => raw.push(h),
    resolveCallSummary: createCallSummaryResolver(cache, lookupCalleeFor(byName)),
  };
  analyzeFunctionFieldIdentity(byName.callerB, entryState, ctxB);

  const cr = raw.find((h) => h.subKind === 'call-resolved');
  assert.ok(cr, 'callerB\'s call-resolved hop is in the stream');
  assert.equal(cr.lossReason, null, 'it is genuinely, precisely resolved — not degraded');
  assert.ok(cr.peerScope, 'and it names the callee');

  const store = new PathStore();
  store.addHops(raw);

  const returnNodeId = store.nodeIdFor(returnNode(cr.peerScope, cr.peerContext, cr.dataElementId));
  assert.ok(store.getNode(returnNodeId), 'the node is real — it IS peer-sourced (lossReason: null), not degraded, so it is never withheld');
  assert.equal(store.edgesTo(returnNodeId).length, 0,
    'but it has zero real in-edges: helper\'s own body hops never fired during THIS run to create them');

  const orphaned = store.diagnostics().orphanedPeerSources;
  assert.ok(orphaned.length > 0, 'the gap is recorded as a diagnostic — never fabricated, never silently dropped');
  assert.ok(orphaned.some((o) => o.nodeId === returnNodeId));
});

// =====================================================================
// 8. §14.7's rejected leg-based-pruning counter-example (Task 1's own
// review finding 2). Exists only as prose in the design doc and the task
// review's own report before this task — this is the fixture that makes
// it re-verifiable rather than merely asserted.
//
// §14.7: "Pruning [the bypass] would require a leg-based rule ('in a
// group containing a peer half, a non-peer x non-peer pair is not an
// edge') and that rule was tried and rejected on a counter-example: at
// `const o = { r: helper(a), s: b.email }` the group also contains a
// legitimate non-peer x non-peer pair (`b.email -> o.s`), which the rule
// deletes. Losing a real edge is a worse failure than keeping a marked
// extra one."
//
// Verified against the real engine (not hand-derived): this group has
// TWO non-peer in-halves (a.email, b.email) and TWO non-peer out-halves
// (o.r, o.s) — a genuine §9.1-style 2x2 cross-join that exists
// independently of the call boundary — so per-pairing ambiguity marks
// BOTH the bypass (a.email -> o.r) AND b.email -> o.s, matching §14.7's
// own "keeping a marked extra one" phrasing precisely: the shipped design
// never claims b.email -> o.s is unambiguous, only that it is KEPT.
// =====================================================================

test('C4/leg: the rejected leg-based-pruning rule would delete a genuine, purely-intraprocedural edge alongside the bypass it targets — the shipped per-pairing design keeps both', () => {
  const src = `
    function helper(u) { return u.email; }
    function f(a, b) { const o = { r: helper(a), s: b.email }; return o; }
  `;
  const byName = parseFns(src, '/x/c4-leg.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');
  const { store, raw } = record(byName.f, entryState, { byName });

  const scope = byName.f.qid;
  const ctx = raw.find((h) => h.subKind === 'call-resolved').context;
  const nAEmail = store.nodeIdFor(pathNode(scope, ctx, 'a.email', 'data:email'));
  const nBEmail = store.nodeIdFor(pathNode(scope, ctx, 'b.email', 'data:email'));
  const nOR = store.nodeIdFor(pathNode(scope, ctx, 'o.r', 'data:email'));
  const nOS = store.nodeIdFor(pathNode(scope, ctx, 'o.s', 'data:email'));

  // The bypass: real data flow that skips the callee, kept (not pruned)
  // and marked ambiguous.
  const bypass = store.edgesFrom(nAEmail).find((e) => e.toNodeId === nOR);
  assert.ok(bypass, 'the bypass edge a.email -> o.r is present');
  assert.equal(bypass.crossScope, false, 'it is a non-peer x non-peer pair — exactly what the rejected rule targets');
  assert.equal(bypass.ambiguousCorrelation, true, '§14.7: the bypass IS marked');

  // The genuine, purely-intraprocedural edge the rejected rule would have
  // deleted ALONGSIDE the bypass, since it is ALSO a non-peer x non-peer
  // pair in the same group.
  const genuine = store.edgesFrom(nBEmail).find((e) => e.toNodeId === nOS);
  assert.ok(genuine, 'b.email -> o.s is present — the SHIPPED per-pairing design never deletes it');
  assert.equal(genuine.crossScope, false, 'it too is a non-peer x non-peer pair — the rejected rule cannot distinguish it from the bypass');

  // The counter-example itself: this group also contains a peer half (the
  // call-resolved source, addressing helper's own exit node) — proven by
  // a real cross-scope edge landing on o.r from that source. A leg-based
  // rule keyed on "does this group contain a peer half" would therefore
  // have deleted BOTH bypass and genuine, since neither can be
  // distinguished by that rule alone.
  const stitch = store.edgesTo(nOR).find((e) => e.crossScope);
  assert.ok(stitch, 'the group contains a peer half — the real call-boundary stitch helper\'s <return> -> o.r');

  // Both surviving edges genuinely carry the correct data-element identity
  // end to end, proving neither is a fabrication of the store.
  assert.equal(bypass.dataElementId, 'data:email');
  assert.equal(genuine.dataElementId, 'data:email');
});
