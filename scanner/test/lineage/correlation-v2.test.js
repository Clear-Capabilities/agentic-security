// DAG-03: value-version and call-site correlation (provenance correlation
// version 2). Acceptance tests, the version 1 invariance guards, and the
// mutation tests that prove each discriminator is load-bearing.
//
// Every scenario is real parsed JS run through the real seeding, the real
// driver and the real store. A mutation test takes the hop stream the real
// engine emitted for a scenario, removes one discriminator from it, rebuilds
// the store and asserts that the scenario's own check now FAILS. A
// discriminator the checks do not depend on would leave the check passing and
// fail the mutation test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { buildProjectIR } from '../../src/ir/index.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore, HOP_FIELDS } from '../../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates, DEFAULT_MAX_CALL_DEPTH } from '../../src/lineage/path-query.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';
import {
  V2_HOP_FIELDS, DEFAULT_MAX_CALL_DEPTH as CORRELATION_MAX_CALL_DEPTH,
  resolveCorrelationVersion, scopeForSubPath, derivationCovers, pairCompatibility,
  invocationIdOf, relPathOf, buildCrosswalk,
} from '../../src/lineage/correlation.js';
import { computeReachingDefinitions, ENTRY_VERSION } from '../../src/lineage/value-versions.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_URL = pathToFileURL(path.join(__dirname, '..', '..', 'src') + path.sep).href;
const VULN_APP = path.join(__dirname, '..', 'fixtures', 'vulnerable-js', 'app.js');

// ---------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------

function build(src, { V = 2, maxContextsPerFn } = {}) {
  const { callGraph } = buildProjectIR({ 'app.js': src });
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  const analysis = runFieldIdentityAnalysis(callGraph, {
    recordHop: (h) => hops.push(h),
    seedEntryState: seedEntryStateFactory(seeds),
    correlationVersion: V,
    ...(maxContextsPerFn === undefined ? {} : { maxContextsPerFn }),
  });
  const store = new PathStore({}, { correlationVersion: V });
  store.addHops(hops);
  return { callGraph, hops, store, analysis };
}

function storeOf(hops, V = 2) {
  const store = new PathStore({}, { correlationVersion: V });
  store.addHops(hops);
  return store;
}

/** Every reconstructed path ending at a call-argument sink on source line `line`. */
function pathsToSink(store, line) {
  const out = [];
  for (const c of sinkCandidates(store)) {
    if (c.kind !== 'escape') continue;
    const into = store.edgesTo(c.id);
    if (!into.some((e) => e.line === line)) continue;
    out.push(...reconstructPaths(store, c.id).paths);
  }
  return out;
}

const lines = (p) => p.hops.map((h) => h.line);
const touches = (paths, line) => paths.some((p) => lines(p).includes(line));
const nodePaths = (store, p) => p.nodeIds.map((id) => store.getNode(id)?.path);

// Same hops, one discriminator removed.
function without(hops, ...fields) {
  return hops.map((h) => {
    const c = { ...h };
    for (const f of fields) delete c[f];
    return c;
  });
}

// ---------------------------------------------------------------------
// Scenarios. Each `check(store)` is the property the acceptance criterion
// states; `mutate` names the discriminator whose removal must break it.
// ---------------------------------------------------------------------

const SCENARIOS = {
  twoCalls: {
    src: [
      'function id(x) { return x; }',
      'function h(req) {',
      '  const r1 = id(req.body.email);',
      '  const r2 = id(req.body.email);',
      '  console.log(r1);',
      '  console.log(r2);',
      '}',
    ].join('\n'),
    check(store) {
      const a = pathsToSink(store, 5);
      const b = pathsToSink(store, 6);
      return a.length > 0 && b.length > 0
        && touches(a, 3) && !touches(a, 4)
        && touches(b, 4) && !touches(b, 3);
    },
    mutate: ['invocationId'],
  },
  positions: {
    src: [
      'function two(a, b) { return a; }',
      'function h(req) {',
      '  const e1 = req.body.email;',
      '  const e2 = req.body.email;',
      '  const r = two(e1, e2);',
      '  console.log(r);',
      '}',
    ].join('\n'),
    check(store) {
      const p = pathsToSink(store, 6);
      return p.length > 0 && touches(p, 3) && !touches(p, 4);
    },
    mutate: ['argPosition', 'formalPosition'],
  },
  versions: {
    src: [
      'function h(req) {',
      '  let x = req.body.email;',
      '  console.log(x);',
      "  x = 'lit';",
      '  if (req.flag) { x = req.body.email; }',
      '  console.log(x);',
      '}',
    ].join('\n'),
    check(store) {
      const first = pathsToSink(store, 3);
      const second = pathsToSink(store, 6);
      return touches(first, 2) && second.length > 0 && touches(second, 5) && !touches(second, 2);
    },
    mutate: ['fromVersions', 'toVersion'],
  },
  siblings: {
    src: [
      'function helper(x) { return x; }',
      'function h(req) {',
      '  const o = { left: helper(req.body.email), right: req.body.email };',
      '  console.log(o.left);',
      '  console.log(o.right);',
      '}',
    ].join('\n'),
    check(store) {
      const left = pathsToSink(store, 4);
      const right = pathsToSink(store, 5);
      if (left.length === 0 || right.length === 0) return false;
      const viaHelper = (p) => p.hops.some((h) => h.crossScope);
      const cross = (paths, other) => paths.some((p) => nodePaths(store, p).includes(other));
      return left.some(viaHelper) && !cross(left, 'o.right')
        && right.length > 0 && !right.some(viaHelper) && !cross(right, 'o.left')
        && [...left, ...right].every((p) => p.ambiguousHopCount === 0);
    },
    mutate: ['derivationId', 'derivationScope'],
  },
  aliasWrite: {
    src: [
      'function h(req) {',
      '  const o1 = { v: req.body.email };',
      '  const o2 = o1;',
      '  o2.v = req.body.email;',
      '  console.log(o1.v);',
      '  console.log(o2.v);',
      '}',
    ].join('\n'),
    check(store) {
      const viaOriginal = pathsToSink(store, 5);
      const viaAlias = pathsToSink(store, 6);
      return viaOriginal.length > 0 && touches(viaOriginal, 2) && !touches(viaOriginal, 4)
        && viaAlias.length > 0 && touches(viaAlias, 4) && !touches(viaAlias, 2) && !touches(viaAlias, 3);
    },
    mutate: ['fromVersions', 'toVersion'],
  },
};

// ---------------------------------------------------------------------
// R03.1, R03.4, R03.5: the acceptance scenarios, version 2 versus version 1.
// ---------------------------------------------------------------------

for (const [name, sc] of Object.entries(SCENARIOS)) {
  test(`DAG-03/${name}: version 2 satisfies the acceptance check and version 1 does not`, () => {
    const v2 = build(sc.src, { V: 2 });
    assert.equal(sc.check(v2.store), true, `${name}: version 2 must satisfy its check`);
    const v1 = build(sc.src, { V: 1 });
    assert.equal(sc.check(v1.store), false,
      `${name}: the scenario must be a real defect of version 1, or it proves nothing about version 2`);
  });

  test(`DAG-03/mutation/${name}: removing ${sc.mutate.join(' and ')} from the hop stream breaks the check`, () => {
    const v2 = build(sc.src, { V: 2 });
    const mutant = storeOf(without(v2.hops, ...sc.mutate));
    assert.equal(sc.check(mutant), false,
      `${name}: with ${sc.mutate.join('/')} ignored the check must fail, else that discriminator is not load-bearing`);
  });
}

test('DAG-03/mutation: ignoring the call-site id also changes the balanced traversal result, not only the pairing', () => {
  const v2 = build(SCENARIOS.twoCalls.src, { V: 2 });
  const callEdges = v2.store.edges().filter((e) => e.callBoundary === 'call');
  const returnEdges = v2.store.edges().filter((e) => e.callBoundary === 'return');
  assert.ok(callEdges.length >= 2 && returnEdges.length >= 2, 'two invocations produce call and return boundary edges');
  const baseline = v2.store.edges().filter((e) => e.callBoundary === 'call').map((e) => e.invocationId);
  assert.equal(new Set(baseline).size, 2, 'two call sites give two distinct invocation ids');
  const mutated = storeOf(without(v2.hops, 'invocationId'));
  const sinkPaths = pathsToSink(mutated, 5);
  assert.ok(touches(sinkPaths, 4), 'without invocation ids the walk can return through the other call site');
  assert.ok(mutated.edges().every((e) => e.invocationId === null), 'no invocation id left');
});

test('DAG-03: a call with a clean argument and one with a tainted argument do not exchange returns', () => {
  const src = [
    'function id(x) { return x; }',
    'function h(req) {',
    "  const clean = id('plain');",
    '  const dirty = id(req.body.email);',
    '  console.log(clean);',
    '  console.log(dirty);',
    '}',
  ].join('\n');
  for (const V of [1, 2]) {
    const { store } = build(src, { V });
    assert.equal(pathsToSink(store, 5).length, 0, `v${V}: the clean call's result carries nothing`);
    const dirty = pathsToSink(store, 6);
    assert.ok(dirty.length > 0 && touches(dirty, 4), `v${V}: the tainted call's result traces to its own argument`);
    assert.ok(!touches(dirty, 3), `v${V}: and never to the clean call`);
  }
});

test('DAG-03: the same-context shared callee body no longer yields a witness through the other call site (balanced traversal)', () => {
  const { store } = build(SCENARIOS.twoCalls.src, { V: 2 });
  const result = reconstructPaths(store, sinkCandidates(store).filter((c) => c.kind === 'escape')[0].id);
  assert.equal(result.correlationVersion, 2);
  assert.equal(result.balancing.enabled, true);
  assert.ok(result.balancing.unbalancedPruned >= 1, 'a mismatched return was pruned, and counted');
  assert.ok(result.balancing.prunedEdgeIds.length >= 1, 'with the edge id, not silently');
});

test('DAG-03: a witness that starts inside the callee is not constrained by a caller it was never entered from', () => {
  const { store } = build(SCENARIOS.twoCalls.src, { V: 2 });
  const ret = sinkCandidates(store).find((c) => c.kind === 'return');
  const r = reconstructPaths(store, ret.id);
  assert.equal(r.paths.length, 2, 'both call sites can reach the callee return when the query starts there');
});

// ---------------------------------------------------------------------
// R03.3: value versions.
// ---------------------------------------------------------------------

test('DAG-03: reassignment from a clean literal kills the obsolete value path in both modes (state-level kill)', () => {
  const src = [
    'function h(req) {',
    '  let x = req.body.email;',
    "  x = 'lit';",
    '  console.log(x);',
    '}',
  ].join('\n');
  for (const V of [1, 2]) {
    assert.equal(pathsToSink(build(src, { V }).store, 4).length, 0, `v${V}`);
  }
});

test('DAG-03: merge alternatives are preserved as separate paths, never as one co-occurring path', () => {
  const src = [
    'function h(req) {',
    '  let x;',
    '  if (req.flag) {',
    '    x = req.body.email;',
    '  } else {',
    '    x = req.body.email;',
    '  }',
    '  console.log(x);',
    '}',
  ].join('\n');
  const { store } = build(src, { V: 2 });
  const p = pathsToSink(store, 8);
  assert.equal(p.length, 2, 'two reaching definitions, two alternative paths');
  assert.ok(touches(p, 4) && touches(p, 6), 'both alternatives retained');
  assert.ok(!p.some((q) => lines(q).includes(4) && lines(q).includes(6)), 'no single path claims both');
});

test('DAG-03: a definition that never wrote the data element is not an alternative (no invented origin)', () => {
  const src = [
    'function h(req) {',
    '  let x;',
    '  if (req.flag) { x = req.body.email; } else { x = req.query.email; }',
    '  console.log(x);',
    '}',
  ].join('\n');
  const { store } = build(src, { V: 2 });
  assert.ok(store.diagnostics().versionPruned >= 1, 'the phantom alternatives are counted');
  const p = pathsToSink(store, 4);
  assert.ok(p.length > 0 && p.every((q) => q.complete && q.hopCount >= 2), 'every path is a real two-hop flow, none starts at a phantom definition');
});

test('DAG-03: alias read and separate instances, positive and negative', () => {
  const alias = [
    'function h(req) {',
    '  const o1 = { v: req.body.email };',
    '  const o2 = o1;',
    '  console.log(o2.v);',
    '}',
  ].join('\n');
  for (const V of [1, 2]) {
    const p = pathsToSink(build(alias, { V }).store, 4);
    assert.ok(p.length > 0 && touches(p, 2) && touches(p, 3), `v${V}: a read through the alias reaches the original value`);
  }
  const separate = [
    'function h(req) {',
    '  const o1 = { v: req.body.email };',
    "  const o2 = { v: 'clean' };",
    '  console.log(o2.v);',
    '  console.log(o1.v);',
    '}',
  ].join('\n');
  for (const V of [1, 2]) {
    const { store } = build(separate, { V });
    assert.equal(pathsToSink(store, 4).length, 0, `v${V}: the other instance carries nothing`);
    assert.ok(touches(pathsToSink(store, 5), 2), `v${V}: the tainted instance does`);
  }
});

test('DAG-03: a redefined instance does not keep the old instance reachable', () => {
  const src = [
    'function h(req) {',
    '  let o = { v: req.body.email };',
    '  console.log(o.v);',
    '  o = { v: req.body.email };',
    '  console.log(o.v);',
    '}',
  ].join('\n');
  const second = pathsToSink(build(src, { V: 2 }).store, 5);
  assert.ok(touches(second, 4) && !touches(second, 2), 'the second instance traces to the second allocation only');
  const secondV1 = pathsToSink(build(src, { V: 1 }).store, 5);
  assert.ok(touches(secondV1, 2), 'version 1 still reaches the first allocation (the defect version 2 fixes)');
});

// ---------------------------------------------------------------------
// R03.2: legacy unknown correlation stays explicit ambiguity.
// ---------------------------------------------------------------------

function hand(over) {
  return {
    kind: 'production', subKind: 'ident', scope: 'f', dataElementId: 'data:E', fromPath: null, toPath: null,
    syntacticPath: null, nodeId: 'n1', line: 1, widenReason: null, lossReason: null,
    context: 'c', peerScope: null, peerContext: null, ...over,
  };
}

test('DAG-03/R03.2: hops with no version 2 evidence pair exactly as in version 1 and stay marked ambiguous', () => {
  const hops = [
    hand({ fromPath: 'a' }), hand({ fromPath: 'b' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'x' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'y' }),
  ];
  const v1 = storeOf(hops, 1);
  const v2 = storeOf(hops, 2);
  assert.equal(v1.edges().length, 4);
  assert.equal(v2.edges().length, 4, 'nothing is pruned for lack of evidence');
  assert.ok(v1.edges().every((e) => e.ambiguousCorrelation));
  assert.ok(v2.edges().every((e) => e.ambiguousCorrelation), 'the marked edges are kept AND still marked');
  assert.ok(v2.edges().every((e) => e.correlation === 'legacy-unknown'));
  assert.equal(v2.diagnostics().correlationVersion, 2);
});

test('DAG-03/R03.2: with derivation evidence the same shape is paired and the ambiguity marking goes away, with the edge reporting how it was established', () => {
  const hops = [
    hand({ fromPath: 'a', derivationId: '/src/p:l', relPath: '' }),
    hand({ fromPath: 'b', derivationId: '/src/p:r', relPath: '' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'x', derivationScope: '/src/p:l', relPath: '' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'y', derivationScope: '/src/p:r', relPath: '' }),
  ];
  const v2 = storeOf(hops, 2);
  assert.equal(v2.edges().length, 2);
  assert.ok(v2.edges().every((e) => e.correlation === 'proven' && !e.ambiguousCorrelation));
});

test('DAG-03/R03.2: an edge reached by a proven and an unproven pairing is reported unproven, in any delivery order', () => {
  const a = hand({ fromPath: 'a', derivationId: '/src', relPath: '' });
  const b = hand({ fromPath: 'a' });
  const o = hand({ kind: 'write-out', subKind: 'assign', toPath: 'x', derivationScope: '/src', relPath: '' });
  const s1 = storeOf([a, b, o], 2).edges();
  const s2 = storeOf([o, b, a], 2).edges();
  assert.deepEqual(s1.map((e) => [e.id, e.correlation]).sort(), s2.map((e) => [e.id, e.correlation]).sort());
});

// ---------------------------------------------------------------------
// R03.5: bounded context abstraction with explicit widening.
// ---------------------------------------------------------------------

test('DAG-03/R03.5: the call-context bound is a documented constant shared by both modules', () => {
  assert.equal(DEFAULT_MAX_CALL_DEPTH, CORRELATION_MAX_CALL_DEPTH);
  assert.equal(DEFAULT_MAX_CALL_DEPTH, 8);
});

test('DAG-03/R03.5: within the bound the walk is exact and says so', () => {
  // top -> f0 -> f1 -> f2: walking back from the sink enters three invocations.
  const store = storeOf(nestedHops(2), 2);
  const sink = sinkCandidates(store).find((c) => c.kind === 'escape');
  const r = reconstructPaths(store, sink.id, { maxCallDepth: 3 });
  assert.equal(r.budget.maxCallDepth, 3);
  assert.ok(r.paths.length > 0);
  assert.ok(r.paths.every((p) => p.callContext && p.callContext.balanced === true && p.callContext.widened === false));
  assert.equal(r.balancing.contextWidenedPaths, 0);
  const tight = reconstructPaths(store, sink.id, { maxCallDepth: 2 });
  assert.ok(tight.paths.every((p) => p.callContext.widened === true), 'one entry too many and it is reported');
});

// Genuinely nested: f0 calls f1 which calls f2 ... each returning the callee's
// result, so walking back from the outermost sink enters one more invocation
// per level.
function nestedHops(depth) {
  const hops = [];
  const E = 'data:E';
  void E;
  for (let i = 0; i < depth; i += 1) {
    const inv = `inv:${i}`;
    hops.push(hand({ scope: `f${i}`, context: `c${i}`, nodeId: 'call', line: i + 1, kind: 'selection', subKind: 'member', fromPath: i === 0 ? 'src' : 'p', fromVersions: [ENTRY_VERSION], derivationId: '/src/a0', callRole: 'arg', invocationId: inv, argPosition: 0, relPath: '' }));
    hops.push(hand({ scope: `f${i}`, context: `c${i}`, nodeId: 'call', line: i + 1, kind: 'write-out', subKind: 'call-arg-bind', toPath: 'p', toVersion: ENTRY_VERSION, peerScope: `f${i + 1}`, peerContext: `c${i + 1}`, callRole: 'bind', invocationId: inv, formalPosition: 0, relPath: '' }));
    hops.push(hand({ scope: `f${i}`, context: `c${i}`, nodeId: 'call', line: i + 1, kind: 'production', subKind: 'call-resolved', peerScope: `f${i + 1}`, peerContext: `c${i + 1}`, callRole: 'return', invocationId: inv, derivationId: '/val', relPath: '' }));
    hops.push(hand({ scope: `f${i}`, context: `c${i}`, nodeId: 'call', line: i + 1, kind: 'write-out', subKind: 'return', derivationScope: '/val', relPath: '' }));
  }
  hops.push(hand({ scope: `f${depth}`, context: `c${depth}`, nodeId: 'leaf', line: 50, kind: 'production', subKind: 'ident', fromPath: 'p', fromVersions: [ENTRY_VERSION], derivationId: '/val', relPath: '' }));
  hops.push(hand({ scope: `f${depth}`, context: `c${depth}`, nodeId: 'leaf', line: 50, kind: 'write-out', subKind: 'return', derivationScope: '/val', relPath: '' }));
  hops.push(hand({ scope: 'top', context: 'ct', nodeId: 'top', line: 100, kind: 'production', subKind: 'call-resolved', peerScope: 'f0', peerContext: 'c0', callRole: 'return', invocationId: 'inv:top', derivationId: '/src', relPath: '' }));
  hops.push(hand({ scope: 'top', context: 'ct', nodeId: 'top', line: 100, kind: 'write-out', subKind: 'assign', toPath: 'out', toVersion: 'top', derivationScope: '/src', relPath: '' }));
  hops.push(hand({ scope: 'top', context: 'ct', nodeId: 'sink', line: 101, kind: 'production', subKind: 'ident', fromPath: 'out', fromVersions: ['top'], derivationId: '/a0', relPath: '' }));
  hops.push(hand({ scope: 'top', context: 'ct', nodeId: 'sink', line: 101, kind: 'write-out', subKind: 'call-arg', derivationScope: '/a0', relPath: '' }));
  return hops;
}

test('DAG-03/R03.5: past the context bound the abstraction is explicit, not silent', () => {
  const store = storeOf(nestedHops(6), 2);
  const sink = sinkCandidates(store).find((c) => c.kind === 'escape');
  const tight = reconstructPaths(store, sink.id, { maxCallDepth: 2 });
  assert.ok(tight.paths.length > 0, 'the flow is still found');
  assert.ok(tight.paths.every((p) => p.callContext.widened === true && p.callContext.balanced === false), 'every path says its call context was abstracted');
  assert.ok(tight.balancing.contextWidenedPaths >= 1);
  const roomy = reconstructPaths(store, sink.id, { maxCallDepth: 16 });
  assert.ok(roomy.paths.length > 0);
  assert.ok(roomy.paths.every((p) => p.callContext.widened === false && p.callContext.balanced === true), 'with room the same graph is exact');
  assert.equal(roomy.paths.length, tight.paths.length, 'widening changes the claim, not which flows exist');
});

test('DAG-03/R03.5: recursion terminates and each call keeps its own witness', () => {
  const src = [
    'function rec(n, x) { if (n) { return rec(n, x); } return x; }',
    'function h(req) {',
    '  const r = rec(1, req.body.email);',
    '  const s = rec(2, req.query.email);',
    '  console.log(r);',
    '  console.log(s);',
    '}',
  ].join('\n');
  const { store } = build(src, { V: 2 });
  const a = pathsToSink(store, 5);
  const b = pathsToSink(store, 6);
  assert.ok(a.length > 0 && touches(a, 3) && !touches(a, 4));
  assert.ok(b.length > 0 && touches(b, 4) && !touches(b, 3));
});

// ---------------------------------------------------------------------
// R03.6: versioned ids, crosswalk, and version 1 invariance.
// ---------------------------------------------------------------------

test('DAG-03/R03.6: version 2 ids are distinct from version 1 ids, and the crosswalk is total and exact', () => {
  const { hops, store } = build(SCENARIOS.versions.src, { V: 2 });
  const v1 = storeOf(hops, 1);
  const v1Nodes = new Set(v1.nodes().map((n) => n.id));
  const v1Edges = new Set(v1.edges().map((e) => e.id));
  for (const n of store.nodes()) assert.ok(!v1Nodes.has(n.id), `version 2 node id ${n.id} must not collide with a version 1 id`);
  for (const e of store.edges()) assert.ok(!v1Edges.has(e.id), 'nor an edge id');
  const cw = buildCrosswalk(store);
  assert.equal(cw.version, 2);
  assert.deepEqual(cw.unmapped, { nodes: [], edges: [] });
  const allV2 = cw.nodes.flatMap((r) => r.v2).sort();
  assert.deepEqual(allV2, store.nodes().map((n) => n.id).sort(), 'every version 2 node maps once');
  assert.equal(new Set(allV2).size, allV2.length);
  for (const row of cw.nodes) assert.ok(v1Nodes.has(row.v1), 'the version 1 side of a row is a real version 1 id');
  for (const row of cw.edges) assert.ok(v1Edges.has(row.v1), 'and so is an edge row');
  assert.equal(store.crosswalk() !== null, true);
  assert.equal(storeOf(hops, 1).crosswalk(), null, 'version 1 has nothing to cross');
});

test('DAG-03/R03.6: one version 1 location fans out to one version 2 node per value version', () => {
  const { store } = build(SCENARIOS.versions.src, { V: 2 });
  const cw = buildCrosswalk(store);
  assert.ok(cw.nodes.some((r) => r.v2.length >= 2), 'x has more than one value version in this function');
});

test('DAG-03/R03.6: version 1 mode emits no version 2 field anywhere and its output equals the pre-DAG-03 golden digests', () => {
  const files = {
    'app.js': fs.readFileSync(VULN_APP, 'utf8'),
    'x.js': ['',
      'function id(x) { return x; }',
      'function h(req) {',
      '  const r1 = id(req.body.email);',
      '  const r2 = id(req.body.email);',
      '  const o = { left: id(req.body.email), right: req.body.email };',
      '  console.log(r1, r2, o.left, o.right);',
      '}',
    ].join('\n'),
  };
  const { callGraph } = buildProjectIR(files);
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (x) => hops.push(x), seedEntryState: seedEntryStateFactory(seeds) });
  for (const h of hops) {
    for (const f of V2_HOP_FIELDS) assert.ok(!(f in h), `version 1 hop must not carry ${f}`);
    assert.deepEqual(Object.keys(h).filter((k) => !HOP_FIELDS.includes(k)), [], 'exactly the 14 version 1 fields');
  }
  // The digests below depend on CFG node ids, which are numbered by a
  // process-wide counter, so they are only comparable from a fresh process.
  // The child process runs the version 1 path with no option set at all.
  const script = `
    import fs from 'node:fs';
    import crypto from 'node:crypto';
    const S = ${JSON.stringify(SRC_URL)};
    const { buildProjectIR } = await import(S + 'ir/index.js');
    const { buildGraphWithCoverage } = await import(S + 'lineage/coverage.js');
    const { planSeeds, seedEntryStateFactory } = await import(S + 'lineage/source-seeding.js');
    const { runFieldIdentityAnalysis } = await import(S + 'lineage/driver.js');
    const { PathStore } = await import(S + 'lineage/path-store.js');
    const { reconstructPaths, sinkCandidates } = await import(S + 'lineage/path-query.js');
    const files = JSON.parse(process.argv[1]);
    const d = (x) => crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex').slice(0, 16);
    const { callGraph } = buildProjectIR(files);
    const { seeds } = planSeeds(callGraph, { repository: 'r' });
    const hops = [];
    runFieldIdentityAnalysis(callGraph, { recordHop: (x) => hops.push(x), seedEntryState: seedEntryStateFactory(seeds) });
    const store = new PathStore(); store.addHops(hops);
    const recon = sinkCandidates(store).map((c) => reconstructPaths(store, c.id));
    const g = buildGraphWithCoverage(callGraph, { repository: 'r' }).graph;
    console.log(JSON.stringify({
      hops: d(hops), nodes: d(store.nodes()), edges: d(store.edges()), diagnostics: d(store.diagnostics()), recon: d(recon),
      graph: d(g), stats: store.stats(),
      leaks: [
        'correlationVersion' in store.stats(), 'correlationVersion' in store.diagnostics(),
        recon.some((r) => 'correlationVersion' in r || 'balancing' in r),
        recon.some((r) => r.paths.some((p) => 'callContext' in p)),
        'correlationVersion' in g.coverage.provenance,
      ],
    }));
  `;
  const out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script, JSON.stringify(files)], {
    cwd: path.join(__dirname, '..', '..'), encoding: 'utf8',
  }));
  // Captured from the tree BEFORE DAG-03 (commit 12dce626), not from this one.
  assert.equal(out.hops, 'cccd4cc4164597ca');
  assert.equal(out.nodes, '4bf8c28dc4a7917c');
  assert.equal(out.edges, 'e1bbb29d908ba793');
  // diagnostics() gained limits.ambiguousSummaries (DAG-07 part 2); hops, nodes,
  // edges and recon digests above are still the pre-DAG-03 values.
  assert.equal(out.diagnostics, '721eb090addae09d');
  assert.equal(out.recon, '376c19e4e8d5e25a');
  assert.equal(out.graph, '9e85c3fb98f2efc7');
  assert.deepEqual(out.stats, { hopsOffered: 51, hopsAccepted: 45, groups: 15, nodes: 24, edges: 26 });
  assert.deepEqual(out.leaks, [false, false, false, false, false], 'no correlationVersion, balancing or callContext in any version 1 output');
});

test('DAG-03/R03.6: correlationVersion appears in version 2 outputs only', () => {
  const { callGraph } = buildProjectIR({ 'app.js': fs.readFileSync(VULN_APP, 'utf8') });
  const v2 = buildGraphWithCoverage(callGraph, { repository: 'r', correlationVersion: 2 }).graph;
  assert.equal(v2.coverage.provenance.correlationVersion, 2);
  assert.deepEqual(validateGraph(v2).errors, [], 'the version 2 graph is still a valid DataFlowGraph v1');
  const { store } = build(SCENARIOS.twoCalls.src, { V: 2 });
  assert.equal(store.stats().correlationVersion, 2);
  assert.equal(store.diagnostics().correlationVersion, 2);
  assert.equal(reconstructPaths(store, sinkCandidates(store)[0].id).correlationVersion, 2);
});

test('DAG-03/R03.6: version 2 loses no flow on the vulnerable-js fixture (parity with version 1)', () => {
  const { callGraph } = buildProjectIR({ 'app.js': fs.readFileSync(VULN_APP, 'utf8') });
  const g1 = buildGraphWithCoverage(callGraph, { repository: 'r' }).graph;
  const g2 = buildGraphWithCoverage(callGraph, { repository: 'r', correlationVersion: 2 }).graph;
  assert.deepEqual(g2.flows.map((f) => f.id).sort(), g1.flows.map((f) => f.id).sort());
  assert.equal(g2.edges.length, g1.edges.length);
  assert.equal(g2.nodes.length, g1.nodes.length);
});

test('DAG-03: switching correlation on changes labels, never the analysis result', () => {
  const src = fs.readFileSync(VULN_APP, 'utf8');
  const canon = (analysis) => JSON.stringify([...analysis.results.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([q, r]) => [
    q,
    [...r.exitState.entries()].map(([p, s]) => [p, [...s].sort()]).sort(),
    r.returnFacts.map((f) => [f.nodeId, [...f.identities].sort()]),
    [...r.mutatedParams.entries()].map(([p, s]) => [p, [...s].sort()]).sort(),
    r.widenings,
  ]));
  for (const source of [src, SCENARIOS.twoCalls.src, SCENARIOS.siblings.src, SCENARIOS.versions.src]) {
    assert.equal(canon(build(source, { V: 1 }).analysis), canon(build(source, { V: 2 }).analysis));
  }
});

test('DAG-03: the environment switch enables version 2 when no option is given, and an explicit option wins', () => {
  const prior = process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION;
  try {
    delete process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION;
    assert.equal(new PathStore().correlationVersion(), 1, 'default OFF');
    process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION = '2';
    assert.equal(new PathStore().correlationVersion(), 2);
    assert.equal(new PathStore({}, { correlationVersion: 1 }).correlationVersion(), 1);
    assert.equal(resolveCorrelationVersion(undefined), 2);
    assert.equal(resolveCorrelationVersion(1), 1);
    process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION = '1';
    assert.equal(resolveCorrelationVersion(undefined), 1);
    assert.equal(resolveCorrelationVersion('2'), 2);
    assert.equal(resolveCorrelationVersion(3), 1);
  } finally {
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION;
    else process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION = prior;
  }
});

// ---------------------------------------------------------------------
// Delivery order.
// ---------------------------------------------------------------------

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled(arr, rand) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function content(store) {
  const sorted = (xs) => [...xs].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const recon = sinkCandidates(store).map((c) => reconstructPaths(store, c.id)).sort((a, b) => (a.startNodeId < b.startNodeId ? -1 : 1));
  return JSON.stringify({
    nodes: sorted(store.nodes()), edges: sorted(store.edges()),
    diagnostics: store.diagnostics(),
    paths: recon.map((r) => ({ start: r.startNodeId, paths: r.paths.map((p) => p.id), balancing: r.balancing, truncated: r.truncated })),
  });
}

test('DAG-03: randomized hop delivery order (with re-deliveries) preserves the version 2 graph content', () => {
  for (const name of Object.keys(SCENARIOS)) {
    const { hops } = build(SCENARIOS[name].src, { V: 2 });
    const baseline = content(storeOf(hops, 2));
    for (let seed = 1; seed <= 12; seed += 1) {
      const rand = rng(seed * 7919);
      const order = shuffled([...hops, ...hops.filter(() => rand() < 0.3)], rand);
      assert.equal(content(storeOf(order, 2)), baseline, `${name}, seed ${seed}`);
    }
  }
});

test('DAG-03: delivery order also does not change the graph for a hand-built stream with merged proven and unproven pairings', () => {
  const hops = [
    hand({ fromPath: 'a', derivationId: '/src/p:l', relPath: '' }),
    hand({ fromPath: 'b' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'x', derivationScope: '/src/p:l', relPath: '' }),
    hand({ kind: 'write-out', subKind: 'assign', toPath: 'y' }),
    hand({ kind: 'production', subKind: 'object', widenReason: 'dynamic-property-key' }),
    hand({ kind: 'production', subKind: 'array', lossReason: 'unsupported-target' }),
  ];
  const baseline = content(storeOf(hops, 2));
  for (let seed = 1; seed <= 24; seed += 1) {
    assert.equal(content(storeOf(shuffled(hops, rng(seed)), 2)), baseline, `seed ${seed}`);
  }
});

// ---------------------------------------------------------------------
// Units: correlation.js and value-versions.js.
// ---------------------------------------------------------------------

test('correlation.js: derivationCovers is segment aligned', () => {
  assert.equal(derivationCovers('/src/p:left', '/src/p:left'), true);
  assert.equal(derivationCovers('/src/p:left', '/src/p:left/a0'), true);
  assert.equal(derivationCovers('/src/p:left', '/src/p:leftover'), false);
  assert.equal(derivationCovers('', '/anything'), true);
  assert.equal(derivationCovers('/src/p:left', '/src/p:right'), false);
});

test('correlation.js: scopeForSubPath descends only through unambiguous object properties', () => {
  const expr = { kind: 'object', props: [
    { key: 'a', value: { kind: 'object', props: [{ key: 'b', value: { kind: 'ident', name: 'x' } }] } },
    { key: 'dup', value: { kind: 'ident', name: 'p' } }, { key: 'dup', value: { kind: 'ident', name: 'q' } },
  ] };
  assert.deepEqual(scopeForSubPath(expr, 'a.b', '/src'), { scope: '/src/p:a/p:b', rest: '' });
  assert.deepEqual(scopeForSubPath(expr, 'a.c', '/src'), { scope: '/src/p:a', rest: 'c' });
  assert.deepEqual(scopeForSubPath(expr, 'dup', '/src'), { scope: '/src', rest: 'dup' }, 'a duplicated key keeps the wider scope');
  assert.deepEqual(scopeForSubPath({ kind: 'ident', name: 'u' }, 'f', '/src'), { scope: '/src', rest: 'f' });
});

test('correlation.js: relPathOf and invocationIdOf', () => {
  assert.equal(relPathOf('user.email', 'user'), 'email');
  assert.equal(relPathOf('user', 'user'), '');
  assert.equal(relPathOf('user', 'user.email'), '', 'an ancestor key is container level');
  const a = invocationIdOf({ scope: 's', nodeId: 'n', context: 'c', derivation: '/src' });
  assert.equal(a, invocationIdOf({ scope: 's', nodeId: 'n', context: 'c', derivation: '/src' }));
  assert.notEqual(a, invocationIdOf({ scope: 's', nodeId: 'n', context: 'c', derivation: '/src/a0' }));
  assert.notEqual(a, invocationIdOf({ scope: 's', nodeId: 'n2', context: 'c', derivation: '/src' }));
  assert.notEqual(a, invocationIdOf({ scope: 's', nodeId: 'n', context: 'c2', derivation: '/src' }));
  assert.match(a, /^inv:[0-9a-f]{12}$/);
});

test('correlation.js: pairCompatibility truth table', () => {
  const arg = (inv, pos, rel = '') => ({ callRole: 'arg', invocationId: inv, argPosition: pos, relPath: rel });
  const bind = (inv, pos, rel = '') => ({ callRole: 'bind', invocationId: inv, formalPosition: pos, relPath: rel });
  assert.equal(pairCompatibility(arg('i', 0), bind('i', 0)).compatible, true);
  assert.equal(pairCompatibility(arg('i', 0), bind('i', 1)).compatible, false, 'wrong formal position');
  assert.equal(pairCompatibility(arg('i', 0), bind('j', 0)).compatible, false, 'wrong invocation');
  assert.equal(pairCompatibility(arg('i', 0, 'email'), bind('i', 0, 'phone')).compatible, false, 'different field');
  assert.equal(pairCompatibility(arg('i', 0, ''), bind('i', 0, 'phone')).compatible, true, 'container level applies to every field');
  assert.equal(pairCompatibility(arg('i', 0), { derivationScope: '/src' }).compatible, false, 'an argument never reaches the result assignment');
  assert.equal(pairCompatibility({ derivationId: '/src' }, bind('i', 0)).compatible, false, 'only arguments feed a binding');
  assert.equal(pairCompatibility({ derivationId: '/src/p:l' }, { derivationScope: '/src/p:r' }).compatible, false);
  assert.deepEqual(pairCompatibility({}, {}), { compatible: true, proven: false });
});

test('value-versions.js: kills, merges, weak updates and entry values', () => {
  const node = (kind, succ, target) => ({ kind, succ, ...(target ? { target } : {}) });
  const fn = {
    params: ['p'],
    cfg: {
      entry: 'e',
      nodes: {
        e: node('entry', ['a1']),
        a1: node('assign', ['br'], 'x'),
        br: node('if', ['a2', 'a3']),
        a2: node('assign', ['j'], 'x'),
        a3: node('assign', ['j'], 'y'),
        j: node('noop', ['w']),
        w: node('assign', ['k'], 'bag.*'),
        k: node('assign', ['z'], 'x.f'),
        z: node('noop', []),
      },
    },
  };
  const rd = computeReachingDefinitions(fn);
  assert.deepEqual(rd.versionsAt('a2', 'x'), ['a1']);
  assert.deepEqual(rd.versionsAt('j', 'x'), ['a1', 'a2'], 'a merge keeps both alternatives');
  assert.deepEqual(rd.versionsAt('j', 'y'), ['a3', ENTRY_VERSION], 'a branch that never wrote y contributes the entry value');
  assert.deepEqual(rd.versionsAt('k', 'x'), ['a1', 'a2']);
  assert.deepEqual(rd.versionsAt('z', 'x.f'), ['k'], 'a strong write to x.f replaces only x.f');
  assert.deepEqual(rd.versionsAt('z', 'x.g'), ['a1', 'a2'], 'and leaves its siblings to the enclosing definition');
  assert.deepEqual(rd.versionsAt('z', 'bag'), [ENTRY_VERSION, 'w'], 'a computed-key write is weak: it adds, it kills nothing');
  assert.deepEqual(rd.versionsAt('a1', 'p'), [ENTRY_VERSION]);
});

test('value-versions.js: a loop reaches a fixed point', () => {
  const fn = {
    params: [],
    cfg: {
      entry: 'e',
      nodes: {
        e: { kind: 'entry', succ: ['a'] },
        a: { kind: 'assign', target: 'x', succ: ['h'] },
        h: { kind: 'loop-header', succ: ['b', 'out'] },
        b: { kind: 'assign', target: 'x', succ: ['h'] },
        out: { kind: 'noop', succ: [] },
      },
    },
  };
  assert.deepEqual(computeReachingDefinitions(fn).versionsAt('out', 'x'), ['a', 'b']);
});

test('DAG-03: the new modules respect the package import boundaries', () => {
  const dir = path.join(__dirname, '..', '..', 'src', 'lineage');
  const specs = (f) => [...fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specs('value-versions.js'), [], 'value-versions.js imports nothing');
  assert.deepEqual(specs('correlation.js').sort(), ['./ids.js', 'node:crypto']);
  assert.deepEqual(specs('path-query.js'), ['./ids.js'], 'path-query.js still imports ONLY ids.js');
});
