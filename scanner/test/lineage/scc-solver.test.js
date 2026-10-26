import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  solveRecursiveComponent, joinFieldSummaries, bottomFieldSummary, fieldFacts,
} from '../../src/lineage/scc-solver.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState } from '../../src/lineage/field-identity.js';

// A six-function ring f1 -> f2 -> ... -> f6 -> f1. Each function's summary is
// its own base facts joined with its callee's summary. Only f6 starts with a
// fact, and members are visited in ascending order, so the fact walks back one
// function per round: it needs more than three rounds.
const RING = ['f1', 'f2', 'f3', 'f4', 'f5', 'f6'];
const calleeOf = (q) => RING[(RING.indexOf(q) + 1) % RING.length];
const BASE = { f6: ['seed'], f3: ['mid'] };

function transfer(q, read) {
  const s = bottomFieldSummary();
  for (const id of BASE[q] || []) s.returnFlat.add(id);
  const callee = read(calleeOf(q));
  for (const id of callee.returnFlat) s.returnFlat.add(id);
  // A mutated-parameter fact that also propagates around the ring.
  if (q === 'f2') s.mutatedParams.set('p.q', new Set(['m']));
  for (const [p, ids] of callee.mutatedParams) s.mutatedParams.set(p, new Set(ids));
  return s;
}

// Slow exhaustive reference: Jacobi iteration from bottom, recomputing every
// function from the previous full snapshot until nothing changes.
function referenceSolve() {
  let cur = new Map(RING.map(q => [q, bottomFieldSummary()]));
  for (let i = 0; i < 1000; i++) {
    const snap = cur;
    const next = new Map(RING.map(q => [q, transfer(q, (x) => snap.get(x))]));
    const same = RING.every(q => JSON.stringify(fieldFacts(next.get(q))) === JSON.stringify(fieldFacts(snap.get(q))));
    cur = next;
    if (same) return cur;
  }
  throw new Error('reference did not converge');
}

function runSolver(extra = {}) {
  const published = new Map();
  const out = solveRecursiveComponent({
    members: RING,
    publish: (q, s) => published.set(q, s),
    analyze: (q) => transfer(q, (x) => published.get(x)),
    ...extra,
  });
  return { out, published };
}

test('six-function ring needs more than three rounds and matches the exhaustive reference', () => {
  const { out } = runSolver();
  assert.equal(out.converged, true);
  assert.ok(out.rounds > 3, `expected more than 3 rounds, got ${out.rounds}`);
  assert.equal(out.rounds, 7);
  assert.deepEqual(out.remainingFrontier, []);
  const ref = referenceSolve();
  for (const q of RING) {
    assert.deepEqual(fieldFacts(out.summaries.get(q)), fieldFacts(ref.get(q)), `fixed point for ${q}`);
  }
  // The fixed point is non-trivial: every member sees both ring facts.
  assert.deepEqual(fieldFacts(ref.get('f1')).filter(f => f.startsWith('ret:')), ['ret:mid', 'ret:seed']);
  assert.ok(out.changedFactsTotal > 0);
  assert.ok(out.changedFacts.every(c => typeof c.round === 'number' && c.qid && c.fact));
});

test('result does not depend on member order given to the solver', () => {
  const a = runSolver().out;
  const b = runSolver({ members: [...RING].reverse() }).out;
  for (const q of RING) assert.deepEqual(fieldFacts(a.summaries.get(q)), fieldFacts(b.summaries.get(q)));
  assert.equal(a.rounds, b.rounds);
});

test('a tight work budget is partial, never converged', () => {
  let work = 0;
  const published = new Map();
  const r = solveRecursiveComponent({
    members: RING,
    publish: (q, s) => published.set(q, s),
    analyze: (q) => { work++; return transfer(q, (x) => published.get(x)); },
    shouldStop: () => (work >= 8 ? 'work-limit' : null),
  });
  assert.equal(r.converged, false);
  assert.equal(r.stoppedBy, 'work-limit');
  assert.deepEqual(r.remainingFrontier, RING);
});

test('a round cap below the needed rounds is partial and records round-cap', () => {
  const { out } = runSolver({ maxRounds: 3 });
  assert.equal(out.converged, false);
  assert.equal(out.stoppedBy, 'round-cap');
  assert.ok(out.wideningReasons.includes('round-cap'));
  assert.equal(out.rounds, 3);
  assert.deepEqual(out.remainingFrontier, RING);
});

test('a stable component still takes two rounds (the bottom seed is not an analysis result)', () => {
  const published = new Map();
  const r = solveRecursiveComponent({
    members: ['a', 'b'],
    publish: (q, s) => published.set(q, s),
    analyze: () => bottomFieldSummary(),
  });
  assert.equal(r.converged, true);
  assert.equal(r.rounds, 2);
});

test('join is union, monotone, and folds over-deep parameter paths with a reason', () => {
  const a = bottomFieldSummary(); a.returnFlat.add('x'); a.mutatedParams.set('p.a', new Set(['i']));
  const b = bottomFieldSummary(); b.returnFlat.add('y'); b.mutatedParams.set('p.a.b.c.d', new Set(['j']));
  const { summary, reasons } = joinFieldSummaries(a, b, { maxPathDepth: 3 });
  assert.deepEqual([...summary.returnFlat].sort(), ['x', 'y']);
  assert.deepEqual([...summary.mutatedParams.keys()].sort(), ['p.a', 'p.a.b']);
  assert.deepEqual(reasons, ['path-depth-cap']);
  // Join with itself is the identity.
  assert.deepEqual(fieldFacts(joinFieldSummaries(summary, summary, { maxPathDepth: 3 }).summary), fieldFacts(summary));
});

// ---- Driver integration (real parser, real engine) ----

function project(source, file = '/scc/a.js') {
  const ir = parseJsFile(file, source);
  assert.ok(ir);
  return buildCallGraph({ [file]: ir }, { [file]: source });
}

test('driver: acyclic project reports a complete, round-free convergence record', () => {
  const cg = project('function leaf(x){ return x; }\nfunction mid(x){ return leaf(x); }\nfunction top(x){ return mid(x); }\n');
  const { results, convergence } = runFieldIdentityAnalysis(cg);
  assert.equal(results.size, cg.functions.size);
  assert.ok(results.size >= 3);
  assert.equal(convergence.converged, true);
  assert.equal(convergence.status, 'complete');
  assert.equal(convergence.rounds, 0);
  assert.deepEqual(convergence.remainingFrontier, []);
  assert.deepEqual([...results.keys()], [...results.keys()].sort());
});

test('driver: mutual recursion converges with rounds >= 2 and a component record', () => {
  const cg = project('function ping(x,n){ if(n<=0) return {}; return { p: x.a, v: pong(x,n-1) }; }\nfunction pong(x,n){ if(n<=0) return {}; return { q: x.b, v: ping(x,n-1) }; }\n');
  const { convergence, cache } = runFieldIdentityAnalysis(cg);
  assert.equal(convergence.converged, true);
  assert.ok(convergence.rounds >= 2);
  assert.equal(convergence.components.length, 1);
  assert.equal(convergence.components[0].members.length, 2);
  assert.equal(cache._stack.size, 0);
  assert.equal(convergence.stoppedBy, null);
});

test('driver: callees are analyzed before callers (seed hook records analysis order)', () => {
  const cg = project('function c(){ return 1; }\nfunction b(){ return c(); }\nfunction a(){ return b(); }\n');
  const order = [];
  runFieldIdentityAnalysis(cg, { seedEntryState: (fn) => { order.push(fn.name); return undefined; } });
  assert.deepEqual(order.filter(n => n !== '<module>'), ['c', 'b', 'a']);
});

test('driver: a tight work budget yields partial with a non-empty frontier, never converged', () => {
  const cg = project('function ping(x,n){ return pong(x,n); }\nfunction pong(x,n){ return ping(x,n); }\nfunction other(){ return 1; }\n');
  const { convergence } = runFieldIdentityAnalysis(cg, { maxFunctionAnalyses: 1 });
  assert.equal(convergence.converged, false);
  assert.equal(convergence.status, 'partial');
  assert.equal(convergence.stoppedBy, 'work-limit');
  assert.ok(convergence.remainingFrontier.length > 0);
});

test('driver: an expired deadline is partial for acyclic code too', () => {
  const cg = project('function a(){ return 1; }\nfunction b(){ return 2; }\n');
  const { results, convergence } = runFieldIdentityAnalysis(cg, { deadlineMs: 10, now: () => 11 });
  assert.equal(convergence.converged, false);
  assert.equal(convergence.stoppedBy, 'deadline');
  assert.equal(results.size, 0);
  assert.equal(convergence.remainingFrontier.length, cg.functions.size);
});

test('driver: a round cap that cannot confirm convergence is partial', () => {
  const cg = project('function r(n){ return r(n-1); }\n');
  const { convergence } = runFieldIdentityAnalysis(cg, { maxRounds: 1 });
  assert.equal(convergence.converged, false);
  assert.ok(convergence.wideningReasons.includes('round-cap'));
});

test('driver: non-recursive results are identical to a legacy single pass (golden differential)', () => {
  const cg = project('function leaf(u){ return u.email; }\nfunction mid(u){ return { e: leaf(u) }; }\nfunction top(u){ const m = mid(u); return m; }\nfunction dead(u){ return u; }\n');
  const seed = (fn) => {
    if (fn.name !== 'top') return undefined;
    return new Map([['u', new Set(['data:email'])]]);
  };
  const neu = runFieldIdentityAnalysis(cg, { seedEntryState: seed });

  // Legacy loop, reproduced from the pre-SCC driver: sorted qids, one pass.
  const legacyCache = new (neu.cache.constructor)();
  const legacy = new Map();
  const fnList = [...cg.functions.values()].sort((a, b) => (a.qid < b.qid ? -1 : 1));
  return import('../../src/lineage/summaries.js').then(async (S) => {
    const { analyzeFunctionFieldIdentity } = await import('../../src/lineage/engine.js');
    for (const fn of fnList) {
      const ctx = { resolveCallSummary: S.createCallSummaryResolver(legacyCache, S.createCallGraphLookup(cg, fn.file)) };
      const es = seed(fn) || emptyState();
      const res = analyzeFunctionFieldIdentity(fn, es, ctx);
      legacy.set(fn.qid, res);
      legacyCache.set(fn.qid, es, S.summaryFromAnalysisResult(res));
    }
    const ser = (m) => JSON.stringify([...m].map(([k, v]) => [k, {
      exit: [...v.exitState].map(([p, s]) => [p, [...s].sort()]),
      ret: v.returnFacts.map(r => [...r.identities].sort()),
      mut: [...v.mutatedParams].map(([p, s]) => [p, [...s].sort()]),
      w: v.widenings,
    }]));
    assert.equal(ser(neu.results), ser(legacy));
    assert.deepEqual([...neu.results.keys()], [...legacy.keys()]);
  });
});
