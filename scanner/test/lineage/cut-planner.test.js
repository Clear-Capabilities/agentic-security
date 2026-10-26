import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  maxFlowMinCut, planCuts, validateCutSet, planSharedControls, buildCutNetwork, screenCandidates, UNCUTTABLE,
} from '../../src/lineage/cut-planner.js';
import { emptyProtection } from '../../src/lineage/protection.js';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { foldRemediationItem, validateTransition } from '../../src/lineage/remediation.js';

function node(id, kind = 'process', extra = {}) {
  return { id, kind, subtype: 'x', destination: null, storeDetail: null, coverageStatus: 'modeled', ...extra };
}
function edge(id, from, to) {
  return { id, from, to, relationship: 'flows_to', protection: emptyProtection() };
}
function graph(nodes, edges, extra = {}) {
  const sinks = nodes.filter((n) => n.kind === 'sink');
  const srcs = nodes.filter((n) => n.kind === 'source');
  return {
    graphId: 'graph:t', schemaVersion: '1.0.0', nodes, edges,
    dataElements: [{ id: 'de:1', name: 'email', dataClasses: ['PII'] }, { id: 'de:2', name: 'ssn', dataClasses: ['PII'] }],
    flows: srcs.flatMap((s) => sinks.map((k, i) => ({
      id: `flow:${s.id}:${k.id}`, dataElementIds: ['de:1'], source: s.id, sink: k.id, edgeIds: [], alternatePathCount: 0,
      protectionSummary: 'not_assessed',
    }))),
    evidence: [], coverage: { analysisCompletion: 'complete' }, ...extra,
  };
}
const cand = (type, id, cost, over = {}) => ({
  location: { type, id }, semantics: type === 'node' ? 'handling' : 'transit_protection', owner: 'team-a', cost, ...over,
});

// Diamond with a shared choke point m: src -> m -> {a,b} -> k -> sink
function diamond() {
  return graph(
    [node('src', 'source'), node('m'), node('a'), node('b'), node('k'), node('sink', 'sink')],
    [edge('e1', 'src', 'm'), edge('e2', 'm', 'a'), edge('e3', 'm', 'b'), edge('e4', 'a', 'k'), edge('e5', 'b', 'k'), edge('e6', 'k', 'sink')],
  );
}

test('diamond: shared choke point is chosen when cheaper than the branch controls', () => {
  const plan = planCuts(diamond(), {}, [cand('node', 'm', 8), cand('node', 'a', 5), cand('node', 'b', 5)]);
  assert.equal(plan.status, 'complete-cut');
  assert.deepEqual(plan.cut.controls.map((c) => c.location.id), ['m']);
  assert.equal(plan.cut.cost, 8);
  assert.equal(plan.validation.bypassFound, false);
  assert.equal(plan.verified, false);
  assert.equal(plan.hypothetical, true);
});

test('diamond: branch controls win when the choke point costs more', () => {
  const plan = planCuts(diamond(), {}, [cand('node', 'm', 12), cand('node', 'a', 5), cand('node', 'b', 5)]);
  assert.equal(plan.status, 'complete-cut');
  assert.deepEqual(plan.cut.controls.map((c) => c.location.id).sort(), ['a', 'b']);
  assert.equal(plan.cut.cost, 10);
});

test('a control on only one branch yields an explicit residual bypass', () => {
  const v = validateCutSet(diamond(), {}, [{ ...cand('node', 'a', 5), id: 'c-a' }]);
  assert.equal(v.bypassFound, true);
  assert.equal(v.residualSinkCount, 1);
  assert.ok(v.residualPaths[0].nodes.includes('b'));
  assert.ok(!v.residualPaths[0].nodes.includes('a'));
  assert.equal(v.certificate.allModeledPathsCut, false);
  assert.equal(v.verified, false);
});

test('only one branch controllable: partial plan with explicit residual bypass', () => {
  const plan = planCuts(diamond(), {}, [cand('node', 'a', 5)]);
  // m,b,k have no candidate: cannot cut b branch.
  assert.equal(plan.status, 'no-feasible-cut');
  assert.equal(plan.validation.bypassFound, true);
  assert.ok(plan.limitations.some((l) => /no complete cut/.test(l)));
});

test('cyclic network terminates and cuts correctly', () => {
  const g = graph(
    [node('src', 'source'), node('x'), node('y'), node('sink', 'sink')],
    [edge('e1', 'src', 'x'), edge('e2', 'x', 'y'), edge('e3', 'y', 'x'), edge('e4', 'y', 'sink'), edge('e5', 'x', 'sink')],
  );
  const plan = planCuts(g, {}, [cand('edge', 'e1', 3), cand('edge', 'e4', 2), cand('edge', 'e5', 2)]);
  assert.equal(plan.status, 'complete-cut');
  assert.equal(plan.cut.cost, 3);
  assert.deepEqual(plan.cut.controls.map((c) => c.location.id), ['e1']);
  assert.equal(plan.validation.bypassFound, false);
});

test('multiple sinks: joint cut separates all sinks, perSink reports each', () => {
  const g = graph(
    [node('src', 'source'), node('m'), node('s1', 'sink'), node('s2', 'sink')],
    [edge('e1', 'src', 'm'), edge('e2', 'm', 's1'), edge('e3', 'm', 's2')],
  );
  const both = planCuts(g, {}, [cand('edge', 'e1', 10), cand('edge', 'e2', 3), cand('edge', 'e3', 4)]);
  assert.equal(both.cut.cost, 7);
  assert.deepEqual(both.cut.controls.map((c) => c.location.id).sort(), ['e2', 'e3']);
  assert.equal(both.perSink.length, 2);
  assert.equal(both.validation.bypassFound, false);
  const only = planCuts(g, { sinks: ['s1'] }, [cand('edge', 'e1', 10), cand('edge', 'e2', 3)]);
  assert.deepEqual(only.cut.controls.map((c) => c.location.id), ['e2']);
});

test('incompatible sanitizer families are excluded and reported', () => {
  const cands = [cand('node', 'm', 1, { families: ['xss'] }), cand('node', 'a', 5, { families: ['sqli'] }), cand('node', 'b', 5, { families: ['sqli'] })];
  const plan = planCuts(diamond(), { family: 'sqli' }, cands);
  assert.deepEqual(plan.cut.controls.map((c) => c.location.id).sort(), ['a', 'b']);
  assert.ok(plan.excludedCandidates.some((e) => /does not support rule family/.test(e.reason)));
});

test('disallowed, infeasible and malformed sites are never selected', () => {
  const cands = [
    cand('node', 'm', 1, { disallowed: true }), cand('node', 'a', 5), cand('node', 'b', 5, { feasible: false }),
    cand('node', 'k', 0), cand('node', 'sink', 3, { owner: '' }),
  ];
  const plan = planCuts(diamond(), {}, cands);
  assert.equal(plan.status, 'no-feasible-cut');
  const reasons = plan.excludedCandidates.map((e) => e.reason).join('|');
  assert.match(reasons, /disallowed/);
  assert.match(reasons, /infeasible/);
  assert.match(reasons, /cost must be/);
  assert.match(reasons, /owner is required/);
  assert.equal(plan.cut.controls.some((c) => c.location.id === 'm'), false);
});

test('incomplete graph: scoped suggestion with unknown total coverage', () => {
  const g = diamond();
  g.coverage = { analysisCompletion: 'partial', unresolvedDestinations: 2 };
  g.nodes.find((n) => n.id === 'a').coverageStatus = 'partial';
  const plan = planCuts(g, {}, [cand('node', 'm', 8)]);
  assert.equal(plan.status, 'complete-cut'); // complete WITHIN the modeled subgraph
  assert.equal(plan.completeness.complete, false);
  assert.equal(plan.completeness.totalCoverage, 'unknown');
  assert.equal(plan.validation.certificate.totalCoverage, 'unknown');
  assert.equal(plan.validation.certificate.scope, 'modeled-subgraph-only');
  assert.ok(plan.limitations.some((l) => /not known complete/.test(l)));
  // absent field is also unknown, never assumed complete
  const g2 = diamond(); delete g2.coverage;
  assert.equal(planCuts(g2, {}, [cand('node', 'm', 8)]).completeness.totalCoverage, 'unknown');
});

test('certificate uses the full modeled edge set, not a capped path list', () => {
  const g = diamond();
  g.flows.forEach((f) => { f.edgeIds = ['e1']; f.alternatePathCount = 50; }); // display lists hide alternates
  const v = validateCutSet(g, {}, [cand('node', 'a', 5)]);
  assert.equal(v.certificate.usedDisplayPathList, false);
  assert.equal(v.bypassFound, true); // found via b even though flows list only e1
  const plan = planCuts(g, { dataElementIds: ['de:1'] }, [cand('node', 'm', 8)]);
  assert.ok(plan.limitations.some((l) => /full modeled edge set/.test(l)));
  assert.equal(plan.validation.bypassFound, false);
});

test('trust boundary and data element restrictions select endpoints', () => {
  const g = graph(
    [node('s1', 'source', { trustZone: 'internet' }), node('s2', 'source', { trustZone: 'internal' }), node('m'), node('k', 'sink', { trustZone: 'db' })],
    [edge('e1', 's1', 'm'), edge('e2', 's2', 'm'), edge('e3', 'm', 'k')],
  );
  const net = buildCutNetwork(g, { trustBoundary: { from: 'internet', to: 'db' } }, []);
  assert.deepEqual(net.sourceIds, ['s1']);
  assert.deepEqual(net.sinkIds, ['k']);
});

test('pre-existing protected edges are not part of the network', () => {
  const g = diamond();
  g.edges.find((e) => e.id === 'e2').protection.transit = { verdict: 'protected', evidenceGrade: 'code' };
  const net = buildCutNetwork(g, {}, []);
  assert.deepEqual(net.existingControls, ['e2']);
});

test('node control applied through the scenario engine blocks the node', () => {
  const g = diamond();
  const v = validateCutSet(g, {}, [cand('node', 'm', 8)]);
  assert.equal(v.bypassFound, false);
  assert.ok(v.appliedOperationCount >= 1);
});

test('shared multi-family planning is approximate and compatible-family aware', () => {
  const g = diamond();
  const queries = [{ id: 'q-sqli', family: 'sqli' }, { id: 'q-xss', family: 'xss' }];
  const cands = [
    cand('node', 'm', 6, { families: ['sqli', 'xss'] }),
    cand('node', 'a', 2, { families: ['sqli'] }), cand('node', 'b', 2, { families: ['sqli'] }),
  ];
  const r = planSharedControls(g, queries, cands);
  assert.equal(r.approximate, true);
  assert.match(r.optimalityClaim, /not claimed/);
  assert.equal(r.verified, false);
  assert.deepEqual(r.uncoveredElements, []);
  assert.ok(r.controls.some((c) => c.location.id === 'm')); // only m covers xss
  for (const p of r.perQueryValidation) assert.equal(p.validation.bypassFound, false);
  // a family nobody supports leaves an uncovered element, never silently covered
  const r2 = planSharedControls(g, [{ id: 'q-ssrf', family: 'ssrf' }], cands);
  assert.equal(r2.uncoveredElements.length, 1);
});

test('maxFlowMinCut matches brute-force min cut on randomized small graphs', () => {
  let seed = 12345;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  for (let iter = 0; iter < 300; iter++) {
    const n = 3 + Math.floor(rnd() * 4); // 3..6
    const m = 2 + Math.floor(rnd() * 9); // 2..10
    const arcs = [];
    for (let i = 0; i < m; i++) {
      const from = Math.floor(rnd() * n); const to = Math.floor(rnd() * n);
      if (from === to) continue;
      arcs.push({ from, to, cap: 1 + Math.floor(rnd() * 9) });
    }
    const s = 0; const t = n - 1;
    const { maxFlow, cutArcs } = maxFlowMinCut(n, arcs, s, t);
    // brute force: min total capacity of an arc subset whose removal disconnects s from t
    const connected = (removed) => {
      const seen = new Set([s]); const q = [s];
      for (let qi = 0; qi < q.length; qi++) {
        arcs.forEach((a, i) => { if (!removed.has(i) && a.from === q[qi] && !seen.has(a.to)) { seen.add(a.to); q.push(a.to); } });
      }
      return seen.has(t);
    };
    let best = Infinity;
    for (let mask = 0; mask < (1 << arcs.length); mask++) {
      const removed = new Set(); let cost = 0;
      for (let i = 0; i < arcs.length; i++) if (mask & (1 << i)) { removed.add(i); cost += arcs[i].cap; }
      if (cost < best && !connected(removed)) best = cost;
    }
    assert.equal(maxFlow, best, `iter ${iter}`);
    // the extracted cut is itself a valid cut of that capacity
    const cutSet = new Set(cutArcs);
    assert.equal(connected(cutSet), false, `cut disconnects, iter ${iter}`);
    assert.equal(cutArcs.reduce((a, i) => a + arcs[i].cap, 0), best, `cut capacity, iter ${iter}`);
  }
});

test('screenCandidates keeps the cheapest eligible candidate per location', () => {
  const { eligible } = screenCandidates([cand('node', 'm', 9), cand('node', 'm', 4, { id: 'cheap' })]);
  assert.equal(eligible.get('node:m').id, 'cheap');
  assert.ok(UNCUTTABLE > 1e9);
});

test('hypothetical plans never verify a remediation item', () => {
  const g = diamond();
  const plan = planCuts(g, {}, [cand('node', 'm', 8)]);
  assert.equal(plan.verified, false);
  assert.equal(plan.validation.verified, false);
  // The planner does not import remediation state.
  const src = readFileSync(new URL('../../src/lineage/cut-planner.js', import.meta.url), 'utf8');
  assert.equal(/from\s+['"]\.\/remediation\.js['"]/.test(src), false);
  // Applying the scenario the planner would use does not alter remediation outcomes: the gate still refuses.
  applyScenario(g, { operations: [{ kind: 'require_transit_protection', targetEdgeId: 'e1' }] });
  const item = foldRemediationItem([
    { type: 'opened', at: '2026-01-01', itemId: 'rem-1', payload: { assessment: { snapshotId: 'snapshot:a' }, affectedFlowIds: [], requiredEvidenceFlowIds: [], manualAttestationPermitted: false } },
  ]);
  const rejected = validateTransition(item, { type: 'state_changed', state: 'verified' });
  assert.equal(rejected.valid, false);
  assert.match(rejected.errors[0].message, /can never reach verified/);
  const rejectedNoItem = validateTransition(null, { type: 'state_changed', state: 'verified' });
  assert.equal(rejectedNoItem.valid, false);
});
