import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeScc, verifyScc } from '../../src/graph/scc.js';

function check(graph) {
  const r = computeScc(graph);
  const v = verifyScc(graph, r);
  assert.deepEqual(v.problems, []);
  assert.equal(v.ok, true);
  return r;
}

test('acyclic graph: every node is its own non-recursive component, order validates', () => {
  const g = { nodes: ['a', 'b', 'c', 'd'], edges: [['a', 'b'], ['a', 'c'], ['b', 'd'], ['c', 'd']] };
  const r = check(g);
  assert.equal(r.components.length, 4);
  assert.ok(r.components.every(c => c.members.length === 1 && c.recursive === false));
  const pos = new Map(r.order.map((c, i) => [c, i]));
  for (const [f, t] of g.edges) assert.ok(pos.get(r.componentOf.get(f)) < pos.get(r.componentOf.get(t)));
});

test('self-loop makes a single-member component recursive, with the loop as an internal edge', () => {
  const r = check({ nodes: ['a', 'b'], edges: [['a', 'a'], ['a', 'b']] });
  const ca = r.components[r.componentOf.get('a')];
  assert.deepEqual(ca.members, ['a']);
  assert.equal(ca.recursive, true);
  assert.deepEqual(ca.internalEdges, [['a', 'a']]);
  assert.equal(r.components[r.componentOf.get('b')].recursive, false);
  assert.equal(r.condensationEdges.length, 1);
});

test('mutual recursion collapses to one component with sorted members and internal edges', () => {
  const g = { nodes: ['ping', 'pong', 'main', 'leaf'], edges: [['main', 'ping'], ['ping', 'pong'], ['pong', 'ping'], ['pong', 'leaf']] };
  const r = check(g);
  const cid = r.componentOf.get('ping');
  assert.equal(cid, r.componentOf.get('pong'));
  assert.deepEqual(r.components[cid].members, ['ping', 'pong']);
  assert.deepEqual(r.components[cid].internalEdges, [['ping', 'pong'], ['pong', 'ping']]);
  assert.equal(r.components[cid].recursive, true);
  assert.equal(r.components.length, 3);
});

test('disconnected graph: isolated nodes and separate cycles are handled', () => {
  const g = { nodes: ['x', 'y', 'p', 'q', 'solo'], edges: [['p', 'q'], ['q', 'p']] };
  const r = check(g);
  assert.equal(r.components.length, 4);
  assert.equal(r.componentOf.get('p'), r.componentOf.get('q'));
  assert.equal(r.order.length, 4);
  assert.deepEqual(r.condensationEdges, []);
});

test('empty graph and duplicate nodes/edges', () => {
  assert.deepEqual(computeScc({ nodes: [], edges: [] }).components, []);
  const r = check({ nodes: ['a', 'a', 'b'], edges: [['a', 'b'], ['a', 'b'], { from: 'a', to: 'b' }] });
  assert.equal(r.components.length, 2);
  assert.equal(r.condensationEdges.length, 1);
});

test('an edge with an unknown endpoint is refused, not silently dropped', () => {
  assert.throws(() => computeScc({ nodes: ['a'], edges: [['a', 'ghost']] }), TypeError);
});

test('100,000-node chain, ring and wide graph run without recursion failure', () => {
  const n = 100000;
  const nodes = Array.from({ length: n }, (_, i) => `n${String(i).padStart(6, '0')}`);
  const chain = nodes.slice(1).map((v, i) => [nodes[i], v]);
  const rc = computeScc({ nodes, edges: chain });
  assert.equal(rc.components.length, n);
  assert.equal(verifyScc({ nodes, edges: chain }, rc).ok, true);

  const ring = [...chain, [nodes[n - 1], nodes[0]]];
  const rr = computeScc({ nodes, edges: ring });
  assert.equal(rr.components.length, 1);
  assert.equal(rr.components[0].members.length, n);
  assert.equal(rr.components[0].internalEdges.length, n);
  assert.equal(verifyScc({ nodes, edges: ring }, rr).ok, true);

  // Many small cycles hanging off a spine.
  const edges = [...chain];
  for (let i = 0; i + 1 < n; i += 3) edges.push([nodes[i + 1], nodes[i]]);
  const rw = computeScc({ nodes, edges });
  assert.equal(verifyScc({ nodes, edges }, rw).ok, true);
  assert.ok(rw.components.length < n);
});

test('reordered input nodes and edges give an identical normalized result', () => {
  const nodes = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
  const edges = [['a', 'b'], ['b', 'c'], ['c', 'a'], ['c', 'd'], ['d', 'e'], ['e', 'd'], ['f', 'g'], ['g', 'g'], ['a', 'f']];
  const base = computeScc({ nodes, edges });
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
  const shuffle = (arr) => { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = rnd() % (i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  for (let k = 0; k < 20; k++) {
    const r = computeScc({ nodes: shuffle(nodes), edges: shuffle(edges).map(e => (rnd() % 2 ? e : { from: e[0], to: e[1] })) });
    assert.deepEqual(r, base);
  }
});

test('verifyScc catches a corrupted order and a corrupted membership', () => {
  const g = { nodes: ['a', 'b'], edges: [['a', 'b']] };
  const r = computeScc(g);
  const bad = { ...r, order: [...r.order].reverse() };
  const v = verifyScc(g, bad);
  assert.equal(v.ok, false);
  assert.ok(v.problems.some(p => /topological/.test(p)));
  const bad2 = { ...r, components: r.components.map(c => ({ ...c, members: [] })) };
  assert.equal(verifyScc(g, bad2).ok, false);
});
