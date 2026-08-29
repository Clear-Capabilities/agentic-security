import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  graphId, nodeId, dataElementId, edgeId, flowId, transformationId, evidenceId,
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
