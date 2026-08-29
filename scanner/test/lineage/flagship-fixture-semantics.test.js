import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const graph = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

function flowByKey(key) {
  const id = graph.extensions.fixtureFlowKeys[key];
  return graph.flows.find((f) => f.id === id);
}
function nodeByKey(key) {
  const id = graph.extensions.fixtureNodeKeys[key];
  return graph.nodes.find((n) => n.id === id);
}

// AC-01: PCI to multiple sinks, each with its own independent verdict.
test('AC-01: card_number reaches log, database, and payment API as three distinct flows', () => {
  const log = flowByKey('flow.pci.masked_log');
  const db = flowByKey('flow.pci.database');
  const api = flowByKey('flow.pci.payment_api');
  assert.equal(log.sink, nodeByKey('node.logs').id);
  assert.equal(db.sink, nodeByKey('node.postgres').id);
  assert.equal(api.sink, nodeByKey('node.payment_api').id);
  // Different verdicts prove these are independently evaluated, not one shared claim.
  assert.notEqual(log.protectionSummary, db.protectionSummary);
});

// AC-02: masked and raw log flows are visibly distinct; masking earns credit, raw does not.
test('AC-02: masked log flow is protected with a proven transform; raw log flow is unprotected', () => {
  const masked = flowByKey('flow.pci.masked_log');
  const raw = flowByKey('flow.pci.raw_log');
  assert.equal(masked.protectionSummary, 'protected');
  assert.ok(masked.transformationIds.length > 0);
  const transform = graph.transformations.find((t) => t.id === masked.transformationIds[0]);
  assert.equal(transform.kind, 'mask');
  assert.equal(transform.controlCredit, true);
  assert.equal(raw.protectionSummary, 'unprotected');
  assert.equal(raw.transformationIds.length, 0);
});

// AC-03: cleartext external call is unprotected in transit, with the exact edge visible.
test('AC-03: payment API flow is transit-unprotected over literal HTTP', () => {
  const api = flowByKey('flow.pci.payment_api');
  const edge = graph.edges.find((e) => e.id === api.edgeIds[api.edgeIds.length - 1]);
  assert.equal(edge.protocol.name, 'http');
  assert.equal(edge.protection.transit.verdict, 'unprotected');
  assert.ok(edge.boundaryCrossings.includes('trust-zone:external'));
});

// AC-05: a dynamic destination remains a visible, distinctly-kinded node.
test('AC-05: the unresolved flow terminates in a kind:unresolved node, not a dropped edge', () => {
  const unresolved = flowByKey('flow.pii.unresolved');
  const sinkNode = graph.nodes.find((n) => n.id === unresolved.sink);
  assert.equal(sinkNode.kind, 'unresolved');
  const edge = graph.edges.find((e) => e.id === unresolved.edgeIds[0]);
  assert.equal(edge.protocol.destinationResolution, 'dynamic');
});

// AC-07: AI x regulated-data intersection shows a real path with honest governance unknowns.
test('AC-07: PHI-plus-AI flow reaches the model provider and reports governance facts as manual/unknown, never guessed', () => {
  const phiAi = flowByKey('flow.phi.ai');
  assert.equal(phiAi.sink, nodeByKey('node.model').id);
  const de = graph.dataElements.find((d) => phiAi.dataElementIds.includes(d.id));
  assert.ok(de.dataClasses.includes('PHI'));
  assert.equal(phiAi.governanceRefs.lawfulBasis, 'manual_required');
  assert.equal(phiAi.governanceRefs.retention, 'unknown');
});

// Appendix A: the application-level summary must not claim overall "PCI protected"
// merely because one of several card_number paths is masked/encrypted.
test('Appendix A: not every card_number flow is protected — a mixed picture is preserved', () => {
  const cardFlows = graph.flows.filter((f) => {
    const de = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
    return de && de.dataClasses.includes('PCI');
  });
  const summaries = new Set(cardFlows.map((f) => f.protectionSummary));
  assert.ok(summaries.has('protected'));
  assert.ok(summaries.has('unprotected') || summaries.has('unknown'), 'at least one PCI flow must be non-protected — the fixture must not launder an overall-safe claim');
});

test('every node referenced by extensions.fixtureNodeKeys/fixtureFlowKeys actually resolves', () => {
  for (const [key, id] of Object.entries(graph.extensions.fixtureNodeKeys)) {
    assert.ok(graph.nodes.some((n) => n.id === id), `dangling fixtureNodeKeys entry ${key}`);
  }
  for (const [key, id] of Object.entries(graph.extensions.fixtureFlowKeys)) {
    assert.ok(graph.flows.some((f) => f.id === id), `dangling fixtureFlowKeys entry ${key}`);
  }
});
