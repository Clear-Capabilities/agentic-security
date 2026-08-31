import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  graphId, nodeId, dataElementId, edgeId, flowId, transformationId, evidenceId,
  provenanceNodeId, provenanceEdgeId, pathId,
} from '../../src/lineage/ids.js';

test('graphId follows the dfg:<repo>:<commit>:<configHash> shape from PRD 10.2', () => {
  assert.equal(
    graphId({ repository: 'payments-platform', commit: 'abc123', configHash: 'cfg1' }),
    'dfg:payments-platform:abc123:cfg1',
  );
});

test('graphId degrades gracefully with missing parts', () => {
  const id = graphId({});
  assert.match(id, /^dfg:unknown-repo:uncommitted:default$/);
});

test('nodeId is deterministic for identical discriminators', () => {
  const a = nodeId('source', ['payments-platform', 'web-app', 'checkout']);
  const b = nodeId('source', ['payments-platform', 'web-app', 'checkout']);
  assert.equal(a, b);
  assert.match(a, /^node:source:[0-9a-f]{12}$/);
});

test('nodeId differs for differing discriminators', () => {
  const a = nodeId('source', ['payments-platform', 'web-app']);
  const b = nodeId('source', ['payments-platform', 'gateway']);
  assert.notEqual(a, b);
});

test('dataElementId distinguishes same field name in different services (PRD 10.4)', () => {
  const a = dataElementId('email', ['service-a']);
  const b = dataElementId('email', ['service-b']);
  assert.notEqual(a, b);
  assert.match(a, /^data:[0-9a-f]{12}$/);
});

test('edgeId is deterministic and order-sensitive on from/to', () => {
  const n1 = nodeId('source', ['a']);
  const n2 = nodeId('process', ['b']);
  const e1 = edgeId(n1, n2, 'data_flow');
  const e2 = edgeId(n1, n2, 'data_flow');
  const e3 = edgeId(n2, n1, 'data_flow');
  assert.equal(e1, e2);
  assert.notEqual(e1, e3);
  assert.match(e1, /^edge:[0-9a-f]{12}$/);
});

test('flowId is order-independent over dataElementIds (a set, not a sequence)', () => {
  const src = nodeId('source', ['a']);
  const sink = nodeId('sink', ['b']);
  const de1 = dataElementId('x', []);
  const de2 = dataElementId('y', []);
  const f1 = flowId(src, sink, [de1, de2]);
  const f2 = flowId(src, sink, [de2, de1]);
  assert.equal(f1, f2, 'dataElementIds are sorted before hashing');
  assert.match(f1, /^flow:[0-9a-f]{12}$/);
});

test('flowId differs when a discriminator is added (same source/sink/fields, different path)', () => {
  const src = nodeId('source', ['a']);
  const sink = nodeId('sink', ['b']);
  const de = dataElementId('x', []);
  const f1 = flowId(src, sink, [de], ['masked-branch']);
  const f2 = flowId(src, sink, [de], ['raw-branch']);
  assert.notEqual(f1, f2);
});

test('transformationId and evidenceId are deterministic and correctly prefixed', () => {
  assert.match(transformationId('node:x', 'maskCard'), /^transform:[0-9a-f]{12}$/);
  assert.equal(transformationId('node:x', 'maskCard'), transformationId('node:x', 'maskCard'));
  assert.match(evidenceId('claim-a', 'file.js:10'), /^evidence:[0-9a-f]{12}$/);
  assert.equal(evidenceId('claim-a', 'file.js:10'), evidenceId('claim-a', 'file.js:10'));
});

test('no collisions across 5000 distinct nodeId discriminators (PRD 21 scale target)', () => {
  const seen = new Set();
  for (let i = 0; i < 5000; i++) {
    const id = nodeId('process', ['payments-platform', `svc-${i}`, `fn-${i % 37}`]);
    assert.ok(!seen.has(id), `collision at i=${i}`);
    seen.add(id);
  }
});

// Sub-project C, increment 4 (DESIGN_PATH_PROVENANCE.md §14.5): the two
// provenance-DAG stable-ID functions. Ported from the design task's own
// C4/5 and C4/5b PoC tests (path-store-poc.test.js), not reinvented.

test('C4/5: provenanceEdgeId is deterministically prefixed pedge: and every discriminator field, changed alone, moves the id', () => {
  const base = {
    fromNodeId: 'pnode:path:aaa', toNodeId: 'pnode:path:bbb', dataElementId: 'data:e',
    scope: 'S', context: 'C', siteNodeId: 'n1',
    inKind: 'production', inSubKind: 'ident', outKind: 'write-out', outSubKind: 'assign',
    widenReasons: [], lossReasons: [],
  };
  assert.equal(provenanceEdgeId(base), provenanceEdgeId({ ...base }), 'deterministic, not a counter');
  assert.match(provenanceEdgeId(base), /^pedge:[0-9a-f]{12}$/);

  const seen = new Map([[provenanceEdgeId(base), 'base']]);
  const variants = {
    fromNodeId: 'pnode:path:zzz', toNodeId: 'pnode:path:zzz', dataElementId: 'data:x',
    scope: 'S2', context: 'C2', siteNodeId: 'n2',
    inKind: 'selection', inSubKind: 'member', outKind: 'write-out-x', outSubKind: 'return',
  };
  for (const [field, value] of Object.entries(variants)) {
    const id = provenanceEdgeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the edge id (collided with ${seen.get(id)})`);
    seen.set(id, field);
  }
  for (const [field, value] of [['widenReasons', ['unresolved-call']], ['lossReasons', ['unsupported-target']]]) {
    const id = provenanceEdgeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the edge id`);
    seen.set(id, field);
  }
  // Reason arrays are SETS — order must not matter.
  assert.equal(
    provenanceEdgeId({ ...base, widenReasons: ['a', 'b'] }),
    provenanceEdgeId({ ...base, widenReasons: ['b', 'a'] }),
  );
});

test('C4/5b: provenanceNodeId separates every discriminator, and 5000 distinct nodes never collide', () => {
  const base = { kind: 'path', scope: 'S', context: 'C', path: 'a.b', siteNodeId: null, dataElementId: 'data:e' };
  assert.match(provenanceNodeId(base), /^pnode:path:[0-9a-f]{12}$/);
  const seen = new Set([provenanceNodeId(base)]);
  for (const [field, value] of Object.entries({ kind: 'return', scope: 'S2', context: 'C2', path: 'a.c', siteNodeId: 'n1', dataElementId: 'data:f' })) {
    const id = provenanceNodeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the node id`);
    seen.add(id);
  }
  // The §9.4 case that motivates `context` being part of node identity.
  assert.notEqual(
    provenanceNodeId({ ...base, context: 'x.email=data:email' }),
    provenanceNodeId({ ...base, context: 'x=data:email' }),
    'two entry contexts of one function must not share a node',
  );
  const bulk = new Set();
  for (let i = 0; i < 5000; i++) {
    const id = provenanceNodeId({ kind: 'path', scope: `svc-${i % 41}`, context: `ctx-${i % 7}`, path: `p.${i}`, siteNodeId: null, dataElementId: `data:${i % 13}` });
    assert.ok(!bulk.has(id), `collision at i=${i}`);
    bulk.add(id);
  }
});

// Sub-project C, increment 5 (DESIGN_PATH_PROVENANCE.md §15.6/§15.10 item
// 1): `pathId`, ported from the design task's own C5/5c PoC test
// (path-query-poc.test.js), not reinvented.

test('C5/id-1: pathId is idempotent — the same logical path, reconstructed twice, produces the same id', () => {
  const startNodeId = 'pnode:path:aaa';
  const edgeIds = ['pedge:111', 'pedge:222', 'pedge:333'];
  const a = pathId({ startNodeId, edgeIds });
  const b = pathId({ startNodeId, edgeIds: [...edgeIds] });
  assert.equal(a, b, 'deterministic, not a counter');
  assert.match(a, /^ppath:[0-9a-f]{12}$/);
});

test('C5/id-2: a changed edge id ANYWHERE in the sequence moves the id', () => {
  const startNodeId = 'pnode:path:aaa';
  const base = pathId({ startNodeId, edgeIds: ['pedge:111', 'pedge:222', 'pedge:333'] });
  const changedFirst = pathId({ startNodeId, edgeIds: ['pedge:999', 'pedge:222', 'pedge:333'] });
  const changedMiddle = pathId({ startNodeId, edgeIds: ['pedge:111', 'pedge:999', 'pedge:333'] });
  const changedLast = pathId({ startNodeId, edgeIds: ['pedge:111', 'pedge:222', 'pedge:999'] });
  assert.notEqual(base, changedFirst, 'a changed FIRST edge id must move the id');
  assert.notEqual(base, changedMiddle, 'a changed MIDDLE edge id must move the id');
  assert.notEqual(base, changedLast, 'a changed LAST edge id must move the id');
});

test('C5/id-3: a REORDERED edge id sequence moves the id — order matters for a path, unlike a node/edge discriminator\'s set-like fields', () => {
  const startNodeId = 'pnode:path:aaa';
  const forward = pathId({ startNodeId, edgeIds: ['pedge:111', 'pedge:222', 'pedge:333'] });
  const reversed = pathId({ startNodeId, edgeIds: ['pedge:333', 'pedge:222', 'pedge:111'] });
  const swapped = pathId({ startNodeId, edgeIds: ['pedge:222', 'pedge:111', 'pedge:333'] });
  assert.notEqual(forward, reversed, 'a reversed edge sequence is a different path, not the same one re-hashed');
  assert.notEqual(forward, swapped, 'a swapped-adjacent-pair sequence is likewise a different path');
});

test('C5/id-4: startNodeId is also part of the discriminator, even though it is redundant given a non-empty edgeIds', () => {
  const edgeIds = ['pedge:111', 'pedge:222'];
  const a = pathId({ startNodeId: 'pnode:path:aaa', edgeIds });
  const b = pathId({ startNodeId: 'pnode:path:bbb', edgeIds });
  assert.notEqual(a, b, 'a changed startNodeId (same edges) must still move the id — over-specifying costs nothing');
});

test('C5/id-5: discriminatorParts moves the id (Task 2 review finding 6 — the parameter was spec\'d and implemented but had no test)', () => {
  const startNodeId = 'pnode:path:aaa';
  const edgeIds = ['pedge:111', 'pedge:222'];
  const bare = pathId({ startNodeId, edgeIds });
  const withPart = pathId({ startNodeId, edgeIds }, ['extra-discriminator']);
  assert.notEqual(bare, withPart, 'a non-empty discriminatorParts must move the id relative to the same path with none');
  const same = pathId({ startNodeId, edgeIds }, ['extra-discriminator']);
  assert.equal(withPart, same, 'the same discriminatorParts must still be idempotent');
});

test('C4/5c: pnode:/pedge: are distinct from node:/edge: and never match validate.js\'s id-prefix regexes for the other namespace', () => {
  const pn = provenanceNodeId({ kind: 'path', scope: 'S', context: 'C', path: 'a', siteNodeId: null, dataElementId: 'data:e' });
  const pe = provenanceEdgeId({
    fromNodeId: pn, toNodeId: pn, dataElementId: 'data:e', scope: 'S', context: 'C', siteNodeId: 'n1',
    inKind: 'production', inSubKind: 'ident', outKind: 'write-out', outSubKind: 'assign',
  });
  assert.ok(!/^node:/.test(pn), 'a provenance node id must never match the DataFlowGraph v1 node: prefix regex');
  assert.ok(!/^edge:/.test(pe), 'a provenance edge id must never match the DataFlowGraph v1 edge: prefix regex');
  assert.match(pn, /^pnode:/);
  assert.match(pe, /^pedge:/);
});
