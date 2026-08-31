//
// queue-detail.test.js — Milestone 2, Sub-project E, increment 3
// (`node.queueDetail` — queue/topic identity extraction).
//
// Own-file-per-feature, mirroring `handling-analyzer.test.js`'s own
// precedent — this is its own coherent property, not an extension of
// `test/catalog-orm-write.test.js`, which is specifically about the
// ORM-write catalog, a different feature. See `DESIGN_QUEUE_DETAIL.md`
// for the full field contract and the disclosed scope boundary this file
// pins.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { enumerateSinkSites, buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { validateGraph } from '../../src/lineage/validate.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

function queueSites(src) {
  const cg = irOf({ 'a.js': `function h(req) { ${src} }` });
  const { sites } = enumerateSinkSites(cg);
  return sites.filter((s) => s.entry.id.startsWith('privacy-js-queue-'));
}

// ── 1. sqs.sendMessage — the SQS-shaped, literal-QueueUrl case ─────────────

test('queueDetail: sqs.sendMessage({QueueUrl: <literal>, ...}) extracts topic + operation', () => {
  const sites = queueSites("sqs.sendMessage({ QueueUrl: 'https://sqs.us-east-1.amazonaws.com/123/my-queue', MessageBody: x });");
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'privacy-js-queue-sendMessage');
  assert.equal(sites[0].decision.category, 'queue');
  const { queueDetail } = sites[0];
  assert.equal(queueDetail.topic, 'https://sqs.us-east-1.amazonaws.com/123/my-queue');
  assert.equal(queueDetail.operation, 'publish');
  // provider is deferred to a later increment — always null here
  // (DESIGN_QUEUE_DETAIL.md §2).
  assert.equal(queueDetail.provider, null);
});

// ── 2. sqs.sendMessage — same shape, non-literal QueueUrl ──────────────────

test('queueDetail: sqs.sendMessage({QueueUrl: <variable>, ...}) leaves topic null — a non-literal value is never a guess, but the site is still a real, recognized queue sink', () => {
  const sites = queueSites('sqs.sendMessage({ QueueUrl: dynamicUrl, MessageBody: x });');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'privacy-js-queue-sendMessage');
  assert.equal(sites[0].queueDetail.topic, null);
  assert.equal(sites[0].queueDetail.operation, 'publish');
});

// ── 3. topic.publish(x) — the SNS/Kafka shape, honestly deferred ───────────

// The topic identity for this shape lives in a SEPARATE, earlier statement
// that constructed the receiver (e.g. `const topic = pubsub.topic('name');
// topic.publish(...)`) — a cross-statement lookup this package has no
// primitive for. `topic` staying `null` here is the EXPECTED, disclosed
// gap named in DESIGN_QUEUE_DETAIL.md §3.2, not a bug to "fix" later
// without updating this test and that document together.
test('queueDetail: topic.publish(x) — the SNS/Kafka constructed-topic shape — leaves topic null unconditionally (disclosed, deferred gap, not a bug)', () => {
  const sites = queueSites('topic.publish(x);');
  assert.equal(sites.length, 1);
  assert.equal(sites[0].entry.id, 'privacy-js-queue-publish');
  assert.equal(sites[0].decision.category, 'queue');
  assert.equal(sites[0].queueDetail.topic, null);
  assert.equal(sites[0].queueDetail.operation, 'publish');
});

// ── 4. validateGraph() end to end ───────────────────────────────────────

test('queueDetail: validateGraph() stays clean on a real graph containing a queue node with a populated queueDetail', () => {
  const cg = irOf({
    'a.js': `function h(req) { sqs.sendMessage({ QueueUrl: 'https://sqs.../my-queue', MessageBody: req.body.email }); }`,
  });
  const r = buildDataFlowGraph(cg, { repository: 'queue-detail' });
  assert.deepEqual(validateGraph(r.graph).errors, []);
  const queueNode = r.graph.nodes.find((n) => n.kind === 'queue' && n.queueDetail && n.queueDetail.topic);
  assert.ok(queueNode, 'expected a queue sink node carrying queueDetail');
  assert.equal(queueNode.queueDetail.topic, 'https://sqs.../my-queue');
  assert.equal(queueNode.queueDetail.operation, 'publish');
});
