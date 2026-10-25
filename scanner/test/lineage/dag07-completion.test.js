// DAG-07 part 2: the shared completion envelope, seeding and reverse-selection
// records, incremental-reuse marking, typed ambiguous summaries, witness
// diversity, continuations, cancellation timing and the scale acceptance tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  makeCompletion, combineCompletions, fromAnalysisCompletion, fromQueryResult, completionOfGraph,
  describeCompletion, COMPLETION_STATUSES,
} from '../../src/lineage/completion.js';
import { planSeeds } from '../../src/lineage/source-seeding.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { exportGraphJSON } from '../../src/lineage/export-json.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths, comparePaths } from '../../src/lineage/path-query.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { reachabilitySliceWithCompletion, rhsReachableFunctions } from '../../src/dataflow/tabulation.js';
import { sliceBackwardWithCompletion, sliceBackward } from '../../src/dataflow/backward.js';
import { SummaryCache } from '../../src/dataflow/summaries.js';
import { serializeSummaries, seedSummaryCache } from '../../src/dataflow/incremental.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';
import { rankWitnesses, assessAllPathsProtected } from '../../src/lineage/witness-selection.js';
import { ContinuationStore, queryWithContinuation } from '../../src/lineage/continuation.js';
import { runOwnedWorker } from '../../src/lineage/owned-worker.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures', 'owned-worker-fixtures.mjs');

function cgOf(files) {
  const perFile = {};
  for (const [f, src] of Object.entries(files)) perFile[f] = parseJsFile(f, src);
  return buildCallGraph(perFile);
}
const SRC = "function h(req){ const e = req.body.email; console.log(e); const f = e; console.log(f); }";

// ---- the envelope ----
test('D7b/1: envelope vocabulary, derived negativeClaimAllowed, and worst-status combination', () => {
  assert.deepEqual([...COMPLETION_STATUSES], ['complete', 'partial', 'cancelled', 'unavailable', 'invalid']);
  const ok = makeCompletion({ status: 'complete' });
  assert.equal(ok.negativeClaimAllowed, true);
  assert.equal(ok.negativeClaimScope, 'modeled-graph-only');
  // A caller cannot talk its way into a negative claim.
  assert.equal(makeCompletion({ status: 'partial', negativeClaimAllowed: true }).negativeClaimAllowed, false);
  assert.equal(makeCompletion({ status: 'complete', unexploredFrontierCount: 3 }).negativeClaimAllowed, false);
  assert.equal(makeCompletion({ status: 'complete', reasons: ['x'] }).negativeClaimAllowed, false);
  assert.equal(makeCompletion({ status: 'bogus' }).status, 'invalid');
  const worst = combineCompletions([ok, makeCompletion({ status: 'partial', reasons: ['a'], unexploredFrontierCount: 2 }), makeCompletion({ status: 'cancelled' })]);
  assert.equal(worst.status, 'cancelled');
  assert.equal(worst.unexploredFrontierCount, 2);
  assert.equal(combineCompletions([]).status, 'unavailable');
  assert.deepEqual(describeCompletion(ok), []);
  assert.match(describeCompletion(makeCompletion({ status: 'partial', reasons: ['analysis-iteration-budget'] })).join('\n'), /iteration budget/);
});

// ---- R07.1: source seeding record ----
test('D7b/2: planSeeds returns a completion record and reports a seeding limit', () => {
  const cg = cgOf({ 'a.js': SRC, 'b.js': 'function g(req){ return req.query.q; }' });
  const full = planSeeds(cg, { repository: 'r' });
  assert.equal(full.completion.status, 'complete');
  assert.equal(full.completion.functionsNotScanned, 0);
  assert.ok(full.seeds.length >= 2);

  const capped = planSeeds(cg, { repository: 'r', maxSeeds: 1 });
  assert.equal(capped.completion.status, 'partial');
  assert.deepEqual(capped.completion.reasons, ['seeding-limit']);
  assert.equal(capped.seeds.length, 1);

  const ac = new AbortController(); ac.abort();
  const cancelled = planSeeds(cg, { repository: 'r', signal: ac.signal });
  assert.equal(cancelled.completion.status, 'cancelled');
  assert.equal(cancelled.completion.functionsScanned, 0);
});

test('D7b/3: a seeding limit reaches the graph, the export, and zero-flow projection still shows it', () => {
  const cg = cgOf({ 'a.js': SRC });
  const { graph } = buildGraphWithCoverage(cg, { seeding: { maxSeeds: 0 } });
  assert.equal(graph.flows.length, 0, 'no seeds, so no flows are projected');
  assert.equal(graph.scanHealth.status, 'partial');
  assert.equal(graph.coverage.analysisCompletion.seeding.status, 'partial');
  const env = completionOfGraph(graph);
  assert.equal(env.status, 'partial');
  assert.ok(env.reasons.includes('seeding-limit'));
  assert.ok(env.reasons.includes('zero-flows-with-incomplete-analysis'));
  assert.equal(env.negativeClaimAllowed, false);
  const exported = exportGraphJSON(graph);
  assert.equal(exported.completion.status, 'partial');
  assert.equal(exported.completion.limits.flowsProjected, 0);
  assert.ok(describeCompletion(exported.completion).some((l) => /not evidence/.test(l)));
});

test('D7b/4: a complete graph exports a complete envelope and its digests are untouched by it', () => {
  const cg = cgOf({ 'a.js': SRC });
  const { graph } = buildGraphWithCoverage(cg, {});
  const e1 = exportGraphJSON(graph, { generatedAt: 'x' });
  assert.equal(e1.completion.status, 'complete');
  assert.equal(e1.completion.negativeClaimAllowed, true);
  // The digest covers the graph, not the envelope.
  const { completion, exportedAt, ...rest } = e1;
  const e2 = exportGraphJSON(graph, { generatedAt: 'x' });
  assert.equal(e2.digest, rest.digest);
  assert.equal(e2.bodyDigest, rest.bodyDigest);
});

// ---- R07.1: reverse selection records ----
test('D7b/5: reverse selection reports depth and worklist limits with a frontier count', () => {
  // chain f0 <- f1 <- ... <- f20, sink in f0
  const files = { 'a.js': 'function f0(x){ eval(x); }\n' };
  for (let i = 1; i <= 20; i++) files['a.js'] += `function f${i}(x){ f${i - 1}(x); }\n`;
  const cg = cgOf(files);
  const sinks = [{ fnQid: [...cg.functions.keys()].find((q) => q.includes('f0@')), nodeId: '0', line: 1 }];
  const deep = reachabilitySliceWithCompletion(sinks, cg, 3);
  assert.equal(deep.completion.status, 'partial');
  assert.ok(deep.completion.reasons.includes('caller-depth-limit'));
  assert.ok(deep.completion.unexploredFrontierCount >= 1);
  assert.ok(deep.reachable instanceof Set);
  const full = reachabilitySliceWithCompletion(sinks, cg, 50);
  assert.equal(full.completion.status, 'complete');
  assert.ok(full.reachable.size >= 21);
  // The public runner keeps its shape and gains the additive record.
  const r = rhsReachableFunctions({}, cg);
  assert.ok('reachable' in r && 'sinks' in r && r.completion);
});

test('D7b/6: backward slice keeps its array shape and carries a completion record', () => {
  const cg = cgOf({ 'a.js': 'function h(req, db){ const a = req.body.id; const b = a; db.query(b); }' });
  const fn = [...cg.functions.values()].find((f) => f.name === 'h');
  const sinkNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call');
  const res = sliceBackwardWithCompletion(fn, sinkNode, 'b');
  assert.equal(res.completion.status, 'complete');
  assert.ok(Array.isArray(res.slice));
  const legacy = sliceBackward(fn, sinkNode, 'b');
  assert.ok(Array.isArray(legacy) && legacy.completion.status === 'complete');
  assert.equal(sliceBackwardWithCompletion(null, null, 'x').completion.status, 'unavailable');
});

// ---- R07.3: incremental reuse ----
test('D7b/7: a summary computed under a tainted entry is never restored as the empty-entry summary', () => {
  const cache = new SummaryCache();
  const q = 'a.js::<module>::helper@1';
  cache.set(q, new Set(), { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] });
  cache.set(q, new Set(['x']), { returnTainted: true, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] });
  const out = serializeSummaries(cache);
  assert.deepEqual(Object.keys(out), [q], 'keyed by the real qid, not the file');
  assert.equal(out[q].returnTainted, false, 'the tainted-entry result is not persisted as empty-entry');
  assert.equal(out[q].entryContext, 'empty');
  assert.equal(out[q].contextsNotPersisted, 1);
});

test('D7b/8: a restored empty-entry summary standing in for a tainted context is reported partial', () => {
  const cache = new SummaryCache();
  cache._maxContextsPerFn = 0; // every tainted context falls back to the empty-entry summary
  seedSummaryCache(cache, { Q: { returnTainted: false, mutatedParams: [], taintedGlobals: [], findings: [], entryContext: 'empty' } }, new Set(['Q']));
  const s = cache.compute('Q', new Set(['p']), () => { throw new Error('over the cap: must reuse'); });
  assert.equal(s.returnTainted, false);
  const notes = cache.completionNotes().map((n) => n.reason);
  assert.ok(notes.includes('context-cap-fallback'));
  assert.ok(notes.includes('incremental-empty-entry-reuse'));
});

test('D7b/9: a truncated persisted findings list is marked on reuse', () => {
  const cache = new SummaryCache();
  const findings = Array.from({ length: 60 }, (_, i) => ({ id: i }));
  cache.set('Q', new Set(), { returnTainted: true, mutatedParams: new Set(), taintedGlobals: new Set(), findings });
  const ser = serializeSummaries(cache);
  assert.equal(ser.Q.findings.length, 50);
  assert.equal(ser.Q.findingsTruncated, 10);
  const fresh = new SummaryCache();
  seedSummaryCache(fresh, ser, new Set(['Q']));
  assert.equal(fresh._incrementalFindingsTruncated, 1);
});

// ---- scan health ----
test('D7b/10: construction, seeding and cancellation conditions reach scan health, with zero flows projected', () => {
  const cg = cgOf({ 'a.js': SRC });
  const { graph } = buildGraphWithCoverage(cg, { seeding: { maxSeeds: 0 } });
  const env = completionOfGraph(graph);
  const health = computeScanHealth({
    lineageStatus: { requested: true, enabled: true, failure: null, completion: { status: env.status, reasons: env.reasons, unexploredFrontierCount: env.unexploredFrontierCount } },
  });
  assert.ok(health.conditions.some((c) => /seeding-limit/.test(c) && /not evidence/.test(c)));
  assert.equal(health.lineageAnalysis.completion.status, 'partial');
  assert.notEqual(health.status, 'complete');
});

// ---- R07.5: typed ambiguous summary + materialization bound ----
const hop = (o) => ({
  kind: 'production', subKind: 'ident', scope: 'f', nodeId: 1, line: 1, context: 'c',
  fromPath: 'a', toPath: null, dataElementId: 'data:x', syntacticPath: null,
  widenReason: null, lossReason: null, peerScope: null, peerContext: null, ...o,
});
const outHop = (o) => hop({ kind: 'write-out', subKind: 'assign', fromPath: null, ...o });

test('D7b/11: an oversize join keeps reachability through an ambiguous summary, never exceeds the output budget', () => {
  const S = 200; const O = 200;
  const st = new PathStore({ maxPairingsPerGroup: 1000, maxEdges: 10000 });
  for (let i = 0; i < S; i++) st.addHop(hop({ fromPath: `s${i}` }));
  for (let i = 0; i < O; i++) st.addHop(outHop({ toPath: `t${i}` }));
  assert.equal(st.edges().length, S + O, 'S + O summary edges, not S * O');
  const lim = st.limitStatus();
  assert.equal(lim.hit, true);
  assert.equal(lim.ambiguousSummaries, 1);
  assert.equal(lim.groupsSkipped[0].pairings, S * O);
  // Every target still reaches every source, through the summary node, marked ambiguous.
  const tid = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: 't7', siteNodeId: null, dataElementId: 'data:x' });
  const r = reconstructPaths(st, tid, { maxPaths: 1000, maxPathsPerTerminal: 1000 });
  assert.equal(r.paths.length, S);
  assert.ok(r.paths.every((p) => p.ambiguousHopCount === 2 && p.hopCount === 2));
  assert.equal(r.negativeClaimAllowed, false);
  assert.equal(r.status, 'partial');
  // A tight edge budget refuses and says so, instead of growing without bound.
  const tight = new PathStore({ maxPairingsPerGroup: 1000, maxEdges: 50 });
  for (let i = 0; i < S; i++) tight.addHop(hop({ fromPath: `s${i}` }));
  for (let i = 0; i < O; i++) tight.addHop(outHop({ toPath: `t${i}` }));
  assert.ok(tight.edges().length <= 50);
  assert.ok(tight.limitStatus().edgesRefused > 0);
});

test('D7b/12: path materialization is bounded and reports the reason', () => {
  const st = new PathStore();
  // a diamond ladder: 2^k paths
  const K = 12;
  for (let i = 0; i < K; i++) {
    for (const side of ['l', 'r']) {
      st.addHop(hop({ nodeId: `${i}${side}`, fromPath: `n${i}` }));
      st.addHop(outHop({ nodeId: `${i}${side}`, toPath: `n${i + 1}` }));
    }
  }
  const id = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: `n${K}`, siteNodeId: null, dataElementId: 'data:x' });
  const r = reconstructPaths(st, id, { maxMaterializedHops: 30, maxCandidatePaths: 100000, maxExpansions: 1e6 });
  assert.ok(r.truncationReasons.includes('materialization-budget'));
  assert.equal(r.status, 'partial');
  assert.ok(r.budget.materializedHops < 30 + K * 2 + 2);
  assert.ok(r.unexploredFrontierCount > 0);
  const bad = reconstructPaths(st, id, { maxMaterializedHops: -1 });
  assert.equal(bad.status, 'invalid');
});

// ---- acceptance: a sink beyond the budget cannot be complete-empty or "safe" ----
function chainStore(N) {
  const st = new PathStore({ maxHops: 1e9, maxEdges: 1e9 });
  for (let i = 0; i < N; i++) {
    st.addHop(hop({ nodeId: i, line: i, fromPath: `v${i}` }));
    st.addHop(outHop({ nodeId: i, line: i, toPath: `v${i + 1}` }));
  }
  return st;
}
const sinkOf = (st, N) => st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: `v${N}`, siteNodeId: null, dataElementId: 'data:x' });

test('D7b/13: a sink beyond the depth/expansion budget is partial and never licenses a negative claim or "safe"', () => {
  const N = 500;
  const st = chainStore(N);
  const id = sinkOf(st, N);
  const cut = reconstructPaths(st, id, { maxDepth: 50 });
  assert.equal(cut.status, 'partial');
  assert.equal(cut.negativeClaimAllowed, false);
  assert.ok(cut.paths.every((p) => p.complete === false), 'no path is presented as reaching a real origin');
  const env = fromQueryResult(cut);
  assert.equal(env.status, 'partial');
  assert.equal(env.negativeClaimAllowed, false);
  const starved = reconstructPaths(st, id, { maxExpansions: 5 });
  assert.equal(starved.status, 'partial');
  assert.equal(starved.negativeClaimAllowed, false);
  assert.ok(starved.unexploredFrontierCount > 0);
  const claim = assessAllPathsProtected({ result: cut, enumerated: cut.paths, attrsOf: () => ({ controlState: 'protected' }) });
  assert.equal(claim.allowed, false);
  assert.ok(claim.reasons.includes('query-not-complete'));
  // The same sink with a sufficient budget is complete.
  const full = reconstructPaths(st, id, { maxDepth: N + 10, maxExpansions: N + 10 });
  assert.equal(full.status, 'complete');
});

// ---- R07.8: witness diversity without changing truth ----
test('D7b/14: witness ranking spreads across dimensions and never changes which paths exist', () => {
  const mk = (id, o) => ({ id, sourceNodeId: 's1', sinkNodeId: 'k1', dataElementId: 'data:a', crossScopeCount: 0, ambiguousHopCount: 0, ...o });
  const paths = [
    mk('p1', {}), mk('p2', {}), mk('p3', {}),
    mk('p4', { sourceNodeId: 's2' }),
    mk('p5', { sinkNodeId: 'k2', crossScopeCount: 1 }),
    mk('p6', { ambiguousHopCount: 1 }),
  ];
  const attrs = { p1: 'protected', p2: 'protected', p3: 'protected', p4: 'protected', p5: 'unprotected', p6: 'protected' };
  const { ranked, displayed, hiddenCount, coverage } = rankWitnesses(paths, { limit: 3, attrsOf: (p) => ({ controlState: attrs[p.id] }) });
  assert.equal(ranked.length, paths.length);
  assert.deepEqual(new Set(ranked.map((p) => p.id)), new Set(paths.map((p) => p.id)));
  assert.equal(displayed.length, 3);
  assert.equal(hiddenCount, 3);
  assert.ok(coverage.source >= 2 && coverage.sink >= 2, 'the sample is not three copies of one shape');
  assert.deepEqual(rankWitnesses(paths, { limit: 3 }).displayed.map((p) => p.id), rankWitnesses([...paths].reverse(), { limit: 3 }).displayed.map((p) => p.id), 'deterministic');
});

test('D7b/15: "all paths protected" cannot be derived from a truncated sample; a hidden path refutes it', () => {
  const st = new PathStore();
  // two sources feeding one sink
  st.addHop(hop({ nodeId: 1, fromPath: 'a' })); st.addHop(outHop({ nodeId: 2, toPath: 'z', fromPath: null }));
  const id = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: 'z', siteNodeId: null, dataElementId: 'data:x' });
  const exhaustive = reconstructPaths(st, id);
  const allProtected = () => ({ controlState: 'protected' });
  const ok = assessAllPathsProtected({ result: exhaustive, enumerated: exhaustive.paths, attrsOf: allProtected });
  assert.equal(ok.allowed, exhaustive.status === 'complete' && exhaustive.paths.length > 0);

  // A truncated query whose displayed paths are all protected.
  const N = 200;
  const chain = chainStore(N);
  const cut = reconstructPaths(chain, sinkOf(chain, N), { maxDepth: 20 });
  const sample = assessAllPathsProtected({ result: cut, enumerated: cut.paths, attrsOf: allProtected });
  assert.equal(sample.allowed, false);
  assert.equal(sample.holds, null, 'unknown, not true');
  assert.ok(sample.reasons.includes('truncated-sample'));

  // A path that is NOT in the displayed sample still refutes the claim.
  const displayed = [{ id: 'shown', sourceNodeId: 's', sinkNodeId: 'k' }];
  const everything = [...displayed, { id: 'hidden', sourceNodeId: 's2', sinkNodeId: 'k' }];
  const refuted = assessAllPathsProtected({
    result: { status: 'complete' }, enumerated: everything,
    attrsOf: (p) => ({ controlState: p.id === 'hidden' ? 'unprotected' : 'protected' }),
  });
  assert.equal(refuted.holds, false);
  assert.equal(refuted.refutingPathId, 'hidden');
  assert.equal(refuted.allowed, false);
  // Unknown control state never counts as protected.
  const unk = assessAllPathsProtected({ result: { status: 'complete' }, enumerated: displayed, attrsOf: () => ({}) });
  assert.equal(unk.allowed, false);
  assert.ok(unk.reasons.includes('control-state-unknown'));
});

// ---- R07.9: continuations ----
test('D7b/16: a resumed query continues where it stopped and finds the same set as one big query', () => {
  const K = 8;
  const st = new PathStore();
  for (let i = 0; i < K; i++) {
    for (const side of ['l', 'r']) {
      st.addHop(hop({ nodeId: `${i}${side}`, fromPath: `n${i}` }));
      st.addHop(outHop({ nodeId: `${i}${side}`, toPath: `n${i + 1}` }));
    }
  }
  const id = st.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: `n${K}`, siteNodeId: null, dataElementId: 'data:x' });
  const big = reconstructPaths(st, id, { maxPaths: 100000, maxPathsPerTerminal: 100000, maxCandidatePaths: 100000, maxExpansions: 1e6 });
  assert.equal(big.status, 'complete');

  const cont = new ContinuationStore();
  const budget = { maxPaths: 100000, maxPathsPerTerminal: 100000, maxCandidatePaths: 40, maxExpansions: 1e6 };
  const seen = new Set();
  let page = queryWithContinuation(st, cont, id, budget);
  let pages = 1;
  assert.ok(page.continuation.token, 'first page stopped with work left');
  assert.equal(page.status, 'partial');
  page.paths.forEach((p) => seen.add(p.id));
  while (page.continuation.token && pages < 50) {
    page = queryWithContinuation(st, cont, id, { ...budget, continuationToken: page.continuation.token });
    assert.equal(page.resumed, true);
    assert.equal(page.negativeClaimAllowed, false);
    page.paths.forEach((p) => seen.add(p.id));
    pages += 1;
  }
  assert.ok(pages > 1);
  assert.deepEqual([...seen].sort(), big.paths.map((p) => p.id).sort());
  assert.equal(cont.size(), 0, 'tokens are one-shot and the store is empty afterwards');
});

test('D7b/17: a continuation from a changed graph or configuration is rejected; limits and TTL hold', () => {
  const mkStore = (extra) => {
    const st = new PathStore();
    for (let i = 0; i < 6; i++) { st.addHop(hop({ nodeId: i, fromPath: `n${i}` })); st.addHop(outHop({ nodeId: i, toPath: `n${i + 1}` })); st.addHop(hop({ nodeId: `${i}b`, fromPath: `n${i}` })); st.addHop(outHop({ nodeId: `${i}b`, toPath: `n${i + 1}` })); }
    if (extra) { st.addHop(hop({ nodeId: 'extra', fromPath: 'n3' })); st.addHop(outHop({ nodeId: 'extra', toPath: 'n3x' })); }
    return st;
  };
  const a = mkStore(false);
  const b = mkStore(true);
  assert.notEqual(a.digest(), b.digest());
  assert.equal(a.digest(), mkStore(false).digest(), 'digest is a function of content only');
  const id = a.nodeIdFor({ kind: 'path', scope: 'f', context: 'c', path: 'n6', siteNodeId: null, dataElementId: 'data:x' });
  const budget = { maxCandidatePaths: 3, maxExpansions: 1e6 };
  const cont = new ContinuationStore();
  const first = queryWithContinuation(a, cont, id, budget);
  assert.ok(first.continuation.token);
  // changed graph
  const rejected = queryWithContinuation(b, cont, id, { ...budget, continuationToken: first.continuation.token });
  assert.equal(rejected.status, 'invalid');
  assert.equal(rejected.continuation.rejected, 'graph-changed');
  assert.equal(rejected.paths.length, 0);
  // the rejection consumed nothing it should not: but a rejected token on the right graph still works only if untouched
  const first2 = queryWithContinuation(a, cont, id, budget);
  const cfgRejected = queryWithContinuation(a, cont, id, { ...budget, maxCandidatePaths: 4, continuationToken: first2.continuation.token });
  assert.equal(cfgRejected.continuation.rejected, 'config-changed');
  // unknown token
  assert.equal(queryWithContinuation(a, cont, id, { ...budget, continuationToken: 'cont:nope' }).continuation.rejected, 'unknown-or-expired');
  // malformed resumeState is invalid, not a silent restart
  assert.equal(reconstructPaths(a, id, { resumeState: { startNodeId: 'other' } }).status, 'invalid');

  // TTL
  let now = 1000;
  const ttl = new ContinuationStore({ ttlMs: 50, now: () => now });
  const t = ttl.issue({ graphDigest: 'g', configDigest: 'c', state: { stack: [], nodesRev: [1], edgesRev: [] } });
  now += 51;
  assert.equal(ttl.redeem(t.token, { graphDigest: 'g', configDigest: 'c' }).reason, 'unknown-or-expired');
  // entry bound evicts the oldest
  const small = new ContinuationStore({ maxEntries: 2 });
  const mk = () => small.issue({ graphDigest: 'g', configDigest: 'c', state: { stack: [], nodesRev: [1], edgesRev: [] } }).token;
  const t1 = mk(); mk(); mk();
  assert.equal(small.size(), 2);
  assert.equal(small.redeem(t1, { graphDigest: 'g', configDigest: 'c' }).reason, 'evicted');
  // byte bound refuses an oversize frontier instead of storing it
  const tiny = new ContinuationStore({ maxBytes: 1000 });
  assert.equal(tiny.issue({ graphDigest: 'g', configDigest: 'c', state: { stack: new Array(100).fill({}), nodesRev: [], edgesRev: [] } }).reason, 'too-large');
});

// ---- R07.7: cancellation acknowledgment and watchdog ----
test('D7b/18: cooperative cancellation is acknowledged in well under one second and the worker is released', async () => {
  const ac = new AbortController();
  const { done, exited } = runOwnedWorker({ modulePath: FIX, exportName: 'cooperative' }, { signal: ac.signal });
  await new Promise((r) => setTimeout(r, 100)); // let it start spinning
  const t0 = Date.now();
  ac.abort();
  const res = await done;
  const ackMs = Date.now() - t0;
  assert.equal(res.ok, true);
  assert.equal(res.cancelled, true);
  assert.equal(res.terminatedByWatchdog, undefined);
  assert.ok(ackMs < 1000, `acknowledged in ${ackMs}ms`);
  await exited;
  console.log(`# cooperative cancellation acknowledged in ${ackMs}ms`);
});

test('D7b/19: a worker that never polls is terminated by the watchdog inside one second of the cancel', async () => {
  const ac = new AbortController();
  const { done, exited } = runOwnedWorker({ modulePath: FIX, exportName: 'unresponsive' }, { signal: ac.signal, ackGraceMs: 300 });
  await new Promise((r) => setTimeout(r, 100));
  const t0 = Date.now();
  ac.abort();
  const res = await done;
  const ackMs = Date.now() - t0;
  assert.equal(res.ok, false);
  assert.equal(res.status, 'cancelled');
  assert.equal(res.terminatedByWatchdog, true);
  assert.ok(ackMs < 1000, `settled in ${ackMs}ms`);
  await exited; // the thread is really gone
  console.log(`# watchdog terminated unresponsive worker in ${ackMs}ms`);
});

test('D7b/20: a deadline cancels; a quick job completes untouched; bad specs fail structurally', async () => {
  const dl = runOwnedWorker({ modulePath: FIX, exportName: 'unresponsive' }, { timeoutMs: 100, ackGraceMs: 200 });
  const r = await dl.done;
  assert.equal(r.status, 'cancelled');
  assert.equal(r.reason, 'deadline');
  await dl.exited;
  const q = runOwnedWorker({ modulePath: FIX, exportName: 'quick', args: [21] });
  const qr = await q.done;
  assert.deepEqual(qr, { ok: true, result: { doubled: 42 }, cancelled: false });
  await q.exited;
  const bad = runOwnedWorker({});
  assert.equal((await bad.done).ok, false);
  const pre = new AbortController(); pre.abort();
  const early = runOwnedWorker({ modulePath: FIX, exportName: 'cooperative' }, { signal: pre.signal });
  assert.equal((await early.done).cancelled, true);
  await early.exited;
});

// ---- scale ----
test('D7b/21: a 200,000-edge chain reconstructs without stack overflow (million-node run is documented in the report)', () => {
  const N = Number(process.env.AGENTIC_SECURITY_DAG07_CHAIN || 200000);
  const st = chainStore(N);
  const id = sinkOf(st, N);
  const t = Date.now();
  const r = reconstructPaths(st, id, { maxDepth: Math.min(N + 5, 1e6), maxExpansions: N + 5 });
  assert.equal(r.status, 'complete');
  assert.equal(r.paths[0].hopCount, N);
  console.log(`# chain of ${N} edges (${N + 1} nodes): ${Date.now() - t}ms`);
});
