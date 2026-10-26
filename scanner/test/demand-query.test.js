// DAG-02: demand-driven reverse taint. Parity against full analysis on a
// fixture corpus of supported constructs, plus the adversarial "Reverse demand"
// family from PRD section 8.2: deep callers, callee-generated taint, argument
// swaps, callbacks, nested sinks, unresolved calls, multiple sink arguments.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { reachabilitySliceFromSinks, buildCallerQidIndex } from '../src/dataflow/tabulation.js';
import {
  demandEnabled, normalizeSinkQuery, sinkQueryKey, graphDigest, configDigest,
  runDemandSinkQuery, runFullSinkQuery, compareToFull, enumerateSinkQueries, findSinkSites,
  buildIncomingIndex, reconcileSelectors, clearDemandCache, runDemandQueries,
} from '../src/dataflow/demand-query.js';
import { loadFixtureProgram, listFixturePrograms, programFromFiles } from './helpers/demand-programs.js';

const programs = listFixturePrograms();

test('the corpus has at least twelve programs and each declares expectations', () => {
  assert.ok(programs.length >= 12, `only ${programs.length} programs`);
  for (const name of programs) {
    const p = loadFixtureProgram(name);
    assert.ok(p.manifest && Array.isArray(p.manifest.expect) && p.manifest.expect.length > 0, `${name}: manifest`);
  }
});

for (const name of programs) {
  test(`parity with full analysis: ${name}`, () => {
    clearDemandCache();
    const p = loadFixtureProgram(name);
    const queries = enumerateSinkQueries(p.callGraph);
    assert.ok(queries.length > 0, 'program has sink sites');
    for (const q of queries) {
      const demand = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, engineOpts: p.engineOpts });
      const full = runFullSinkQuery(p.perFileIR, p.callGraph, q, { engineOpts: p.engineOpts });
      const cmp = compareToFull(demand, full);
      assert.ok(cmp.equal, `${name} ${q.file}:${q.line} ${q.sinkId}: ${JSON.stringify(cmp)}`);
      assert.equal(demand.witness, demand.findings.length ? 'forward-engine-corroborated' : 'none');
      // the verdict vocabulary has no "safe", and a result states its selector coverage
      assert.ok(['flow-found', 'no-flow-in-modeled-scope', 'unknown'].includes(demand.verdict));
      assert.equal(demand.selectorCoverage.totalFunctions, p.callGraph.functions.size);
      assert.equal(demand.analyzedFunctions >= 1, true);
    }
  });

  test(`manifest expectations hold (not vacuous): ${name}`, () => {
    const p = loadFixtureProgram(name);
    const { expect: exp, expectFallback, maxRegion } = p.manifest;
    for (const e of exp) {
      const matches = enumerateSinkQueries(p.callGraph).filter((q) => q.file === e.file && q.line === e.line);
      assert.ok(matches.length > 0, `${name}: no sink at ${e.file}:${e.line}`);
      const results = matches.map((q) => runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, engineOpts: p.engineOpts }));
      const hit = results.some((r) => r.findings.length > 0);
      assert.equal(hit, e.flow, `${name} ${e.file}:${e.line} expected flow=${e.flow}`);
      if (maxRegion != null) for (const r of results) assert.ok(r.analyzedFunctions <= maxRegion, `${name}: region ${r.analyzedFunctions} > ${maxRegion}`);
      if (expectFallback) for (const r of results) assert.equal(r.fallback && r.fallback.reason, expectFallback);
      else for (const r of results) assert.equal(r.fallback, null, `${name}: unexpected fallback ${JSON.stringify(r.fallback)}`);
    }
  });
}

test('corpus covers every adversarial construct with a real flow', () => {
  const need = { '09-deep-callers': true, '03-producer-helper': true, '04-nested-sinks': true, '07-callbacks': true, '06-multi-sink-args': true };
  for (const name of Object.keys(need)) {
    const p = loadFixtureProgram(name);
    assert.ok(p.manifest.expect.some((e) => e.flow), `${name} has a tainted site`);
  }
});

test('tainted producer helper: the helper body is selected, a caller-only slice misses it', () => {
  const p = loadFixtureProgram('03-producer-helper');
  const q = { file: 'app.js', line: 5 };
  const r = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false });
  assert.equal(r.verdict, 'flow-found');
  assert.ok(r.selectorCoverage.byReason.producer >= 1, 'producer helper selected');
  // The pre-existing caller-only selector drops the producer, and the engine
  // over that region loses the flow: this is the defect the demand selector fixes.
  const sites = findSinkSites(p.callGraph, q);
  const tab = reachabilitySliceFromSinks(sites, p.callGraph);
  const regionGraph = { ...p.callGraph, functions: new Map([...p.callGraph.functions].filter(([id]) => tab.has(id))) };
  const raw = runTaintEngine(p.perFileIR, regionGraph, {});
  assert.equal(raw.filter((f) => f.line === 5).length, 0, 'caller-only region loses the producer flow');
  const rec = reconcileSelectors(p.callGraph, r);
  assert.ok(rec.onlyDemand.length >= 1, 'demand selects functions the tabulation slice lacks');
  assert.equal(rec.tabulationCompletion.status, 'complete');
});

test('20-level caller chain is followed, and a depth budget does not silently drop it', () => {
  const p = loadFixtureProgram('09-deep-callers');
  const q = { file: 'app.js', line: 3 };
  const ok = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false });
  assert.equal(ok.verdict, 'flow-found');
  assert.ok(ok.selectorCoverage.maxDepthReached >= 20);
  assert.equal(ok.fallback, null);
  // default policy: a hit depth limit expands to conservative full analysis
  const lim = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, maxCallerDepth: 3 });
  assert.equal(lim.verdict, 'flow-found');
  assert.equal(lim.fallback.reason, 'depth-limit');
  assert.equal(lim.analyzedFunctions, p.callGraph.functions.size);
  assert.equal(lim.selectorCoverage.limitHits[0].kind, 'depth-limit');
});

test('a limited reverse walk gives no negative verdict', () => {
  const p = loadFixtureProgram('09-deep-callers');
  const q = { file: 'app.js', line: 3 };
  const r = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, maxCallerDepth: 3, onLimit: 'partial' });
  assert.equal(r.findings.length, 0, 'the walk stopped before the source');
  assert.equal(r.negativeClaimAllowed, false);
  assert.equal(r.completion.negativeClaimAllowed, false);
  assert.equal(r.completion.status, 'partial');
  assert.ok(r.completion.reasons.includes('depth-limit'));
  assert.ok(r.completion.unexploredFrontierCount > 0);
  assert.equal(r.verdict, 'unknown');
  // work limit behaves the same way
  const w = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, maxWork: 5, onLimit: 'partial' });
  assert.equal(w.negativeClaimAllowed, false);
  assert.ok(w.completion.reasons.includes('work-limit'));
  assert.equal(w.verdict, 'unknown');
});

test('a complete walk may state a negative claim, scoped to the modeled graph, never "safe"', () => {
  const p = loadFixtureProgram('11-clean-constants');
  const r = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 7 }, { cache: false });
  assert.equal(r.verdict, 'no-flow-in-modeled-scope');
  assert.equal(r.completion.negativeClaimScope, 'modeled-graph-only');
  assert.ok(!JSON.stringify(r).includes('"safe"'));
});

test('nested sinks in return and assignment expressions are queried as sites', () => {
  const p = loadFixtureProgram('04-nested-sinks');
  for (const line of [4, 7, 11]) {
    const sites = findSinkSites(p.callGraph, { file: 'app.js', line });
    assert.equal(sites.length, 1, `line ${line}`);
    const r = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line }, { cache: false });
    assert.equal(r.verdict, 'flow-found');
  }
});

test('callbacks are analyzed or reported, never silently dropped', () => {
  const p = loadFixtureProgram('07-callbacks');
  const r = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 6 }, { cache: false });
  assert.equal(r.verdict, 'flow-found');
  assert.ok(r.selectorCoverage.followed.callers >= 1);
  assert.ok((r.selectorCoverage.byReason['callback-registrar'] || 0) >= 1, 'registrar of the callback selected');
  // a dynamic callee cannot be resolved: it is reported, and no negative claim follows
  const dyn = programFromFiles({ 'app.js': `const cp = require('child_process');
const handlers = {};
function run(req) {
  const t = handlers[req.query.k](req.query.v);
  cp.exec(t);
}
function clean(req) {
  const u = handlers['fixed']('lit');
  cp.exec(u);
}
` });
  const tainted = runDemandSinkQuery(dyn.perFileIR, dyn.callGraph, { file: 'app.js', line: 5 }, { cache: false });
  assert.equal(tainted.verdict, 'flow-found', 'taint passes through the unresolved dynamic call');
  assert.ok(tainted.selectorCoverage.unresolvedCallees.some((u) => /handlers/.test(u.callee)));
  const d = runDemandSinkQuery(dyn.perFileIR, dyn.callGraph, { file: 'app.js', line: 9 }, { cache: false });
  assert.ok(d.selectorCoverage.unresolvedCallees.length >= 1);
  assert.equal(d.negativeClaimAllowed, false);
  assert.equal(d.verdict, 'unknown');
  assert.ok(d.completion.reasons.includes('unresolved-callee'));
});

test('unresolved calls are reported and block a negative claim', () => {
  const p = loadFixtureProgram('08-unresolved-calls');
  const tainted = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 5 }, { cache: false });
  assert.equal(tainted.verdict, 'flow-found');
  const clean = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 7 }, { cache: false });
  assert.equal(clean.findings.length, 0);
  assert.equal(clean.negativeClaimAllowed, false);
  assert.equal(clean.verdict, 'unknown');
  assert.ok(clean.selectorCoverage.unresolvedCallees.some((u) => /transform/.test(u.callee)));
});

test('multiple sink arguments: the requested argument decides', () => {
  const p = loadFixtureProgram('06-multi-sink-args');
  const swapped = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 2 }, { cache: false });
  assert.equal(swapped.findings.length, 0, 'tainted argument 0 of a sink that reads argument 1');
  const right = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3 }, { cache: false });
  assert.equal(right.findings.length, 1);
  assert.equal(right.findings[0].argIndex, 1);
  // an explicit argument index narrows the query
  const a0 = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, argIndex: 0 }, { cache: false });
  assert.equal(a0.findings.length, 0);
  const a1 = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, argIndex: 1 }, { cache: false });
  assert.equal(a1.findings.length, 1);
});

test('a request for one object field does not attribute an unrelated sibling field', () => {
  const p = loadFixtureProgram('19-field-attribution');
  const whole = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, sinkId: 'js-express-res-send' }, { cache: false });
  assert.equal(whole.findings.length, 1, 'the whole object reaches the sink');
  const a = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, sinkId: 'js-express-res-send', accessPath: 'a' }, { cache: false });
  assert.equal(a.findings.length, 1, 'the tainted field is attributed');
  const b = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, sinkId: 'js-express-res-send', accessPath: 'b' }, { cache: false });
  assert.equal(b.findings.length, 0, 'the sibling field is not');
  assert.equal(b.siblingFieldSuppressed, 1, 'the suppression is reported, not hidden');
  // the full-analysis reference applies the same field rule
  const fullB = runFullSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 3, sinkId: 'js-express-res-send', accessPath: 'b' });
  assert.deepEqual(compareToFull(b, fullB), { equal: true, missing: [], extra: [] });
  // an unknown field of a wholly tainted container stays attributable
  const c = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 7, sinkId: 'js-express-res-send', accessPath: 'anything' }, { cache: false });
  assert.equal(c.findings.length, 1);
});

test('unsupported constructs expand to full analysis by default and report partial scope on request', () => {
  const p = loadFixtureProgram('13-instance-field');
  const q = { file: 'app.js', line: 5 };
  const full = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false });
  assert.equal(full.fallback.reason, 'unsupported:instance-field');
  assert.equal(full.analyzedFunctions, p.callGraph.functions.size);
  const partial = runDemandSinkQuery(p.perFileIR, p.callGraph, q, { cache: false, onUnsupported: 'partial' });
  assert.equal(partial.fallback, null);
  assert.equal(partial.completion.status, 'partial');
  assert.ok(partial.completion.reasons.includes('unsupported-construct:instance-field'));
  assert.equal(partial.negativeClaimAllowed, false);
});

test('selection is narrower than the function set for unrelated clusters, and reports coverage', () => {
  const p = loadFixtureProgram('18-unrelated-cluster');
  const r = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'reports.js', line: 4 }, { cache: false });
  assert.ok(r.analyzedFunctions < p.callGraph.functions.size);
  assert.ok(r.selectorCoverage.selectedFraction < 1);
  assert.equal(typeof r.selectorCoverage.workSteps, 'number');
  assert.ok(Array.isArray(r.selectorCoverage.terminals));
  assert.equal(r.candidateFilter.role, 'candidate-filter-only');
});

test('query keys cover site, argument, field, context, rule family and digests', () => {
  const base = { file: 'a.js', line: 3, argIndex: 0, accessPath: 'x', ruleFamily: 'CWE-78' };
  const k = (q, d) => sinkQueryKey(q, d);
  const d = { graphDigest: 'g1', configDigest: 'c1' };
  const same = k(base, d);
  assert.equal(same, k({ ...base }, { ...d }));
  for (const change of [{ line: 4 }, { argIndex: 1 }, { accessPath: 'y' }, { ruleFamily: 'CWE-79' }, { context: 'other' }, { file: 'b.js' }]) {
    assert.notEqual(same, k({ ...base, ...change }, d), JSON.stringify(change));
  }
  assert.notEqual(same, k(base, { graphDigest: 'g2', configDigest: 'c1' }));
  assert.notEqual(same, k(base, { graphDigest: 'g1', configDigest: 'c2' }));
  assert.equal(normalizeSinkQuery({ line: -1, argIndex: 'x' }).line, null);
});

test('digests move with the graph and the configuration; a changed graph does not hit the cache', () => {
  clearDemandCache();
  const a = programFromFiles({ 'app.js': "const cp = require('child_process');\nfunction h(req) {\n  cp.exec(req.query.c);\n}\n" });
  const b = programFromFiles({ 'app.js': "const cp = require('child_process');\nfunction h(req) {\n  cp.exec('fixed');\n}\n" });
  assert.notEqual(graphDigest(a.callGraph), graphDigest(b.callGraph));
  assert.notEqual(configDigest({}), configDigest({ maxCallerDepth: 2 }));
  const q = { file: 'app.js', line: 3 };
  const r1 = runDemandSinkQuery(a.perFileIR, a.callGraph, q);
  const r1b = runDemandSinkQuery(a.perFileIR, a.callGraph, q);
  assert.equal(r1b.cached, true);
  const r2 = runDemandSinkQuery(b.perFileIR, b.callGraph, q);
  assert.notEqual(r2.cached, true);
  assert.notEqual(r1.queryKey, r2.queryKey);
  assert.equal(r1.findings.length, 1);
  assert.equal(r2.findings.length, 0);
});

test('unanswerable queries return an unavailable completion rather than throwing', () => {
  const p = loadFixtureProgram('01-direct-flow');
  const missing = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 999 }, { cache: false });
  assert.equal(missing.completion.status, 'unavailable');
  assert.equal(missing.negativeClaimAllowed, false);
  assert.equal(missing.verdict, 'unknown');
  const ctx = runDemandSinkQuery(p.perFileIR, p.callGraph, { file: 'app.js', line: 4, context: 'caller-sensitive' }, { cache: false });
  assert.ok(ctx.completion.reasons.includes('unsupported-context'));
  assert.equal(runDemandSinkQuery(p.perFileIR, null, { line: 1 }).completion.status, 'unavailable');
});

test('demand mode is opt-in', () => {
  assert.equal(demandEnabled({}), false);
  assert.equal(demandEnabled({ AGENTIC_SECURITY_DEMAND: '0' }), false);
  assert.equal(demandEnabled({ AGENTIC_SECURITY_DEMAND: '1' }), true);
});

test('the incoming index extends the canonical caller index with embedded call sites', () => {
  const p = loadFixtureProgram('03-producer-helper');
  const base = buildCallerQidIndex(p.callGraph);
  const idx = buildIncomingIndex(p.callGraph);
  const readInput = [...p.callGraph.functions.keys()].find((k) => k.includes('readInput'));
  // `const taintedCmd = readInput(req)` is an assignment right-hand side; fn.calls does not record it
  assert.ok(!(base.get(readInput) || []).length, 'canonical index has no edge for an embedded call');
  assert.ok((idx.incoming.get(readInput) || []).length >= 1, 'extended index has it');
});

test('batch API runs a list of queries', () => {
  const p = loadFixtureProgram('01-direct-flow');
  const out = runDemandQueries(p.perFileIR, p.callGraph, [{ file: 'app.js', line: 4 }, { file: 'app.js', line: 5 }], { cache: false });
  assert.equal(out.length, 2);
  assert.equal(out[0].verdict, 'flow-found');
  assert.equal(out[1].findings.length, 0);
});

test('the deep-analysis hook is opt-in and additive: findings are unchanged, results ride along', async () => {
  const { runDeepAnalysis } = await import('../src/dataflow/index.js');
  const p = loadFixtureProgram('01-direct-flow');
  const queries = [{ file: 'app.js', line: 4 }];
  const prev = process.env.AGENTIC_SECURITY_DEMAND;
  try {
    delete process.env.AGENTIC_SECURITY_DEMAND;
    const off = runDeepAnalysis(p.perFileIR, p.callGraph, { demandQueries: queries });
    assert.equal(off._demandResults, undefined, 'env flag off: no demand work');
    process.env.AGENTIC_SECURITY_DEMAND = '1';
    const on = runDeepAnalysis(p.perFileIR, p.callGraph, { demandQueries: queries });
    assert.equal(on._demandResults.length, 1);
    assert.equal(on._demandResults[0].verdict, 'flow-found');
    assert.deepEqual(on.map((f) => f.id), off.map((f) => f.id), 'the primary findings are identical');
    const noQueries = runDeepAnalysis(p.perFileIR, p.callGraph, {});
    assert.equal(noQueries._demandResults, undefined, 'env flag alone does nothing without an explicit query list');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_DEMAND; else process.env.AGENTIC_SECURITY_DEMAND = prev;
  }
});

test('existing reverse implementations stay and report through the shared completion vocabulary', async () => {
  const { backwardSliceWithCompletion, backwardSlice } = await import('../src/dataflow/ifds-precise.js');
  const { reverseEdgesOf, sliceBackwardWithCompletion } = await import('../src/dataflow/backward.js');
  const chain = (n) => { let cur = { file: 'a.js', line: 0 }; for (let i = 1; i <= n; i++) cur = { file: 'a.js', line: i, predecessor: cur }; return { sink: cur, file: 'a.js' }; };
  const short = backwardSliceWithCompletion(null, chain(3));
  assert.equal(short.completion.status, 'complete');
  assert.equal(short.slice.length, backwardSlice(null, chain(3)).length, 'the original function is unchanged');
  const deep = backwardSliceWithCompletion(null, chain(40));
  assert.equal(deep.completion.status, 'partial');
  assert.deepEqual(deep.completion.reasons, ['slice-depth-limit']);
  const p = loadFixtureProgram('01-direct-flow');
  const fn = [...p.callGraph.functions.values()].find((f) => f.name === 'handler');
  const rev = reverseEdgesOf(fn.cfg);
  assert.ok(rev instanceof Map && rev.size > 0);
  const sinkNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call' && n.line === 4);
  const sl = sliceBackwardWithCompletion(fn, sinkNode, 'cmd');
  assert.equal(sl.completion.status, 'complete');
});
