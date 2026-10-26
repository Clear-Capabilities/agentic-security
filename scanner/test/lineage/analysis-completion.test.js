// DAG-07 (R07.1/R07.2): a field-analysis unit that exhausts its iteration
// budget must say so, instead of returning an empty exit state that reads
// as "analyzed, nothing flows".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import { emptyState } from '../../src/lineage/field-identity.js';
import { PathStore } from '../../src/lineage/path-store.js';

function linearFn(n) {
  const nodes = {};
  for (let i = 0; i < n; i++) nodes[i] = { kind: 'noop', succ: i + 1 < n ? [i + 1] : [] };
  return { qid: 'f', params: [], cfg: { entry: 0, exit: n - 1, nodes } };
}

test('DAG07/1: a small CFG reports complete', () => {
  const r = analyzeFunctionFieldIdentity(linearFn(5), emptyState(), {});
  assert.equal(r.completion.status, 'complete');
  assert.equal(r.completion.exitReached, true);
  assert.deepEqual(r.completion.reasons, []);
});

test('DAG07/2: the 5,005-node probe is partial and names the iteration limit', () => {
  const r = analyzeFunctionFieldIdentity(linearFn(5005), emptyState(), {});
  assert.equal(r.completion.status, 'partial');
  assert.deepEqual(r.completion.reasons, ['analysis-iteration-budget']);
  assert.equal(r.completion.exitReached, false);
  assert.ok(r.completion.unfinishedWork > 0);
});

test('DAG07/3: ctx.maxIterations lowers the limit; invalid overrides are ignored', () => {
  const tight = analyzeFunctionFieldIdentity(linearFn(10), emptyState(), { maxIterations: 3 });
  assert.equal(tight.completion.status, 'partial');
  for (const bad of [NaN, Infinity, -1, 0, 1.5, '3']) {
    const r = analyzeFunctionFieldIdentity(linearFn(10), emptyState(), { maxIterations: bad });
    assert.equal(r.completion.status, 'complete', `override ${String(bad)} must be ignored`);
  }
});

test('DAG07/4: markTruncated marks nodes of the truncated unit', () => {
  const store = new PathStore();
  store.markTruncated('f', null, 'analysis-iteration-budget');
  assert.deepEqual(store.diagnostics().truncations.length, 1);
});

// --- end to end through the real builder ---
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';

function cgOf(files) {
  const perFile = {};
  for (const [f, src] of Object.entries(files)) perFile[f] = parseJsFile(f, src);
  return buildCallGraph(perFile);
}
const SRC = "function h(req){ const e = req.body.email; console.log(e); const f = e; console.log(f); }";

test('DAG07/5: builder surfaces a budget-limited unit even though it emits no flows', () => {
  const cg = cgOf({ 'a.js': SRC });
  const full = buildGraphWithCoverage(cg, {});
  assert.equal(full.graph.scanHealth.status, 'complete');
  assert.equal(full.graph.coverage.analysisCompletion, undefined, 'complete run ledger unchanged');

  const cut = buildGraphWithCoverage(cg, { maxIterations: 1 });
  assert.equal(cut.graph.scanHealth.status, 'partial');
  assert.equal(cut.graph.scanHealth.reason, 'analysis-incomplete');
  assert.equal(cut.graph.coverage.analysisCompletion.status, 'partial');
  assert.ok(cut.graph.coverage.analysisCompletion.incomplete.length >= 1);
  assert.ok(cut.graph.limitations.some((l) => /not evidence that none exists/.test(l)));
  assert.deepEqual(validateGraph(cut.graph), { valid: true, errors: [] });
});

// --- R07.4: budget validation ---
import { reconstructPaths, isIncompleteAnswer } from '../../src/lineage/path-query.js';

test('DAG07/6: invalid budgets give status invalid, never an empty or complete answer', () => {
  const store = new PathStore();
  for (const bad of [NaN, Infinity, -1, 1.5, '5', null, 1e12]) {
    const r = reconstructPaths(store, 'pnode:x', { maxExpansions: bad });
    assert.equal(r.status, 'invalid', String(bad));
    assert.equal(r.noPathReason, null);
    assert.equal(r.negativeClaimAllowed, false);
    assert.equal(isIncompleteAnswer(r), true);
    assert.ok(r.budgetErrors[0].includes('maxExpansions'));
  }
});

test('DAG07/7: zero is a valid budget and truncation forbids a negative claim', () => {
  const r = reconstructPaths(new PathStore(), 'pnode:missing', { maxPaths: 0 });
  assert.equal(r.status, 'partial'); // unknown start node
  assert.equal(r.negativeClaimAllowed, false);
});

// --- R07.3: context-cap and nonconverged recursion ---
import { FieldIdentitySummaryCache } from '../../src/lineage/summaries.js';
import { addIdentity } from '../../src/lineage/field-identity.js';

test('DAG07/8: a context-cap fallback is recorded as a completion note', () => {
  const cache = new FieldIdentitySummaryCache(0);
  const entry = addIdentity(emptyState(), 'p', 'data:x');
  const s = cache.compute('f', entry, () => { throw new Error('must not analyze past the cap'); });
  assert.equal(s.degradedReason, 'context-cap');
  assert.deepEqual(cache.completionNotes(), [{ qid: 'f', reason: 'context-cap' }]);
});

test('DAG07/9: recursion that keeps growing past the round cap is reported nonconverged', () => {
  const cache = new FieldIdentitySummaryCache(16);
  let n = 0;
  const analyze = () => {
    const nested = cache.compute('r', emptyState(), analyze); // hits the recursion guard
    const ids = new Set([...nested.returnFlat, `data:round${n++}`]);
    return { returnFlat: ids, returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
  };
  cache.compute('r', emptyState(), analyze);
  assert.ok(cache.completionNotes().some((x) => x.qid === 'r' && x.reason === 'recursion-nonconverged'));
});

test('DAG07/10: a converging recursion records no note', () => {
  const cache = new FieldIdentitySummaryCache(16);
  const analyze = () => {
    cache.compute('r', emptyState(), analyze);
    return { returnFlat: new Set(['data:a']), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
  };
  cache.compute('r', emptyState(), analyze);
  assert.deepEqual(cache.completionNotes(), []);
});

// --- R07.5: construction bounds ---
const hop = (o) => ({
  kind: 'production', subKind: 'ident', scope: 'f', nodeId: 1, line: 1, context: 'c',
  fromPath: 'a', toPath: null, dataElementId: 'data:x', syntacticPath: null,
  widenReason: null, lossReason: null, peerScope: null, peerContext: null, ...o,
});
const outHop = (o) => hop({ kind: 'write-out', subKind: 'assign', fromPath: null, ...o });

test('DAG07/11: maxHops refuses extra hops and reports it', () => {
  const st = new PathStore({ maxHops: 2 });
  assert.equal(st.addHop(hop({ fromPath: 'a' })), true);
  assert.equal(st.addHop(hop({ fromPath: 'b' })), true);
  assert.equal(st.addHop(hop({ fromPath: 'c' })), false);
  const lim = st.diagnostics().limits;
  assert.equal(lim.hit, true);
  assert.equal(lim.hopsRefused, 1);
});

test('DAG07/12: a fan-in x fan-out group above the cap is skipped, reported, and blocks a negative claim', () => {
  const st = new PathStore({ maxPairingsPerGroup: 4 });
  for (const p of ['a', 'b', 'c']) st.addHop(hop({ fromPath: p }));
  for (const p of ['x', 'y', 'z']) st.addHop(outHop({ toPath: p }));
  // R07.5: S+O typed summary edges instead of S*O pairings, none silently lost.
  assert.equal(st.edges().length, 6, 'three sources + three targets through one summary node');
  assert.ok(st.edges().every((e) => e.ambiguousSummary === true && e.ambiguousCorrelation === true));
  assert.equal(st.limitStatus().ambiguousSummaries, 1);
  const lim = st.limitStatus();
  assert.equal(lim.hit, true);
  assert.equal(lim.groupsSkipped[0].pairings, 9);
  const id = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: 'x', siteNodeId: null, dataElementId: 'data:x' });
  const r = reconstructPaths(st, id);
  assert.equal(r.truncated, true);
  assert.ok(r.truncationReasons.includes('store-limit'));
  assert.equal(r.negativeClaimAllowed, false);
});

test('DAG07/13: a store under every cap behaves as before', () => {
  const st = new PathStore();
  st.addHop(hop({})); st.addHop(outHop({ toPath: 'x' }));
  assert.equal(st.limitStatus().hit, false);
  assert.equal(st.edges().length, 1);
});

// --- R07.7: cancellation ---
test('DAG07/14: engine stops on shouldStop and reports cancelled, not complete', () => {
  const r = analyzeFunctionFieldIdentity(linearFn(1000), emptyState(), { shouldStop: () => true });
  assert.equal(r.completion.status, 'cancelled');
  assert.deepEqual(r.completion.reasons, ['cancelled']);
  assert.equal(r.completion.exitReached, false);
});

test('DAG07/15: an aborted signal cancels the builder run and the graph says so', () => {
  const cg = cgOf({ 'a.js': SRC, 'b.js': 'function g(){ return 1; }' });
  const ac = new AbortController();
  ac.abort();
  const { graph } = buildGraphWithCoverage(cg, { signal: ac.signal });
  assert.equal(graph.scanHealth.status, 'cancelled');
  assert.equal(graph.coverage.analysisCompletion.status, 'cancelled');
  assert.equal(graph.coverage.analysisCompletion.functionsAnalyzed, 0);
  assert.ok(graph.coverage.analysisCompletion.functionsNotAnalyzed >= 1);
  assert.ok(graph.limitations.some((l) => /cancelled/.test(l)));
});

test('DAG07/16: an expired deadline cancels; a far deadline does not', () => {
  const cg = cgOf({ 'a.js': SRC });
  assert.equal(buildGraphWithCoverage(cg, { deadline: Date.now() - 1 }).graph.scanHealth.status, 'cancelled');
  assert.equal(buildGraphWithCoverage(cg, { deadline: Date.now() + 60000 }).graph.scanHealth.status, 'complete');
});

// --- R07.6: deep chains are linear, not quadratic, and never recurse ---
test('DAG07/17: a 50,000-hop chain reconstructs completely without stack overflow', () => {
  const N = 50000;
  const st = new PathStore();
  const h = (i, k) => ({
    kind: k, subKind: k === 'write-out' ? 'assign' : 'ident', scope: 'f', nodeId: i, line: i, context: 'c',
    fromPath: k === 'write-out' ? null : `v${i}`, toPath: k === 'write-out' ? `v${i + 1}` : null,
    dataElementId: 'data:x', syntacticPath: null, widenReason: null, lossReason: null, peerScope: null, peerContext: null,
  });
  for (let i = 0; i < N; i++) { st.addHop(h(i, 'production')); st.addHop(h(i, 'write-out')); }
  const id = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: `v${N}`, siteNodeId: null, dataElementId: 'data:x' });
  const t = Date.now();
  const r = reconstructPaths(st, id, { maxDepth: N + 5, maxExpansions: N + 5 });
  assert.equal(r.paths.length, 1);
  assert.equal(r.paths[0].hopCount, N);
  assert.ok(Date.now() - t < 5000, 'quadratic path copying would take far longer');
});
