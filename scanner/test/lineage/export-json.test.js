import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeGraphDigest, exportGraphJSON } from '../../src/lineage/export-json.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('computeGraphDigest: same graph in twice -> identical digest', () => {
  const d1 = computeGraphDigest(flagship);
  const d2 = computeGraphDigest(JSON.parse(JSON.stringify(flagship)));
  assert.equal(d1, d2);
  assert.match(d1, /^[0-9a-f]{64}$/);
});

test('computeGraphDigest: a changed node id changes the digest', () => {
  const mutated = JSON.parse(JSON.stringify(flagship));
  mutated.nodes[0].id = mutated.nodes[0].id + '-mutated';
  assert.notEqual(computeGraphDigest(flagship), computeGraphDigest(mutated));
});

test('computeGraphDigest: generatedAt does NOT affect the digest', () => {
  const a = { ...flagship, generatedAt: '2020-01-01T00:00:00.000Z' };
  const b = { ...flagship, generatedAt: '2099-01-01T00:00:00.000Z' };
  assert.equal(computeGraphDigest(a), computeGraphDigest(b));
});

test('exportGraphJSON: default redact:true, envelope shape', () => {
  const result = exportGraphJSON(flagship);
  assert.equal(typeof result.exportedAt, 'string');
  assert.equal(result.schemaVersion, flagship.schemaVersion);
  assert.equal(result.digest, computeGraphDigest(flagship));
  assert.deepEqual(result.scope, flagship.scope);
  assert.deepEqual(result.coverage, flagship.coverage);
  assert.deepEqual(result.limitations, flagship.limitations);
  assert.equal(result.confidential, true);
  assert.ok(result.graph);
  assert.equal(result.graph.nodes.length, flagship.nodes.length);
});

test('exportGraphJSON: AC-14 reproducibility, excluding exportedAt only', () => {
  const a = exportGraphJSON(flagship);
  const b = exportGraphJSON(flagship);
  const { exportedAt: _a, ...aRest } = a;
  const { exportedAt: _b, ...bRest } = b;
  assert.deepEqual(aRest, bRest);
});

// Real check, grounded in the real fixture (read directly before writing
// this test): NO flagship node has a non-null `destination` at all — every
// one of the 14 nodes carries `destination: null` (confirmed by reading
// every node in `flagship-graph.json`), so the brief's own literal
// suggestion ("find a real flagship node with a non-null destination") has
// no real data to ground it against in THIS fixture. The redaction pass
// (`redact-graph.js`) also covers a second, real, populated surface on
// this exact fixture: `graph.evidence[].claim` and
// `graph.evidence[].location.note`, both real, non-null, source-derived
// strings (e.g. "card_number reaches Application Logs via maskCard() on
// the masked branch" / "services/payment.js:55"). This test grounds
// `redact:false` against THAT real surface instead of an invented
// destination string.
test('exportGraphJSON: redact:false returns unredacted content, confidential stays true', () => {
  // Confirm the documented fact above before relying on it, so this test
  // fails loudly (not silently vacuously) if the fixture ever changes.
  assert.ok(flagship.nodes.every((n) => n.destination === null), 'expected every flagship node to have destination:null');
  assert.ok(flagship.evidence.length > 0, 'expected the flagship fixture to carry evidence entries');

  const result = exportGraphJSON(flagship, { redact: false });
  assert.equal(result.confidential, true);

  const realClaim = flagship.evidence[0].claim;
  const realNote = flagship.evidence[0].location.note;
  assert.equal(realClaim, 'card_number reaches Application Logs via maskCard() on the masked branch');
  assert.equal(realNote, 'services/payment.js:55');

  assert.equal(result.graph.evidence[0].claim, realClaim);
  assert.equal(result.graph.evidence[0].location.note, realNote);
  // The whole evidence array survives byte-for-byte under redact:false —
  // proves this path skips `_redactGraph` entirely rather than merely
  // happening to leave this particular content unchanged.
  assert.deepEqual(result.graph.evidence, flagship.evidence);
});

test('exportGraphJSON: filter narrows to the given nodeIds/edgeIds', () => {
  const oneNodeId = flagship.nodes[0].id;
  const result = exportGraphJSON(flagship, { filter: { nodeIds: [oneNodeId], edgeIds: [] } });
  assert.equal(result.graph.nodes.length, 1);
  assert.equal(result.graph.nodes[0].id, oneNodeId);

  // Real check against the real fixture (confirmed by reading
  // flagship-graph.json directly): flagship.nodes[0] is
  // 'node:source:4aa6d910c10e' (Web App), and every one of its outgoing
  // edges (edge:54d5b1db3415, edge:43c85eec3733, edge:106113ca2b45,
  // edge:116d8e384d78) and every flow starting from it has at least one
  // edge — since `filter.edgeIds` is the empty set here, no edge and,
  // per this module's flow rule (every edgeIds[] entry must survive),
  // no flow can survive either.
  assert.equal(oneNodeId, 'node:source:4aa6d910c10e');
  assert.equal(result.graph.edges.length, 0);
  assert.equal(result.graph.flows.length, 0);

  // dataElements narrow to the union of surviving nodes'/flows'
  // dataElementIds. Zero flows survive, but the one kept node
  // (Web App) still legitimately references all 3 of the fixture's
  // data elements (confirmed directly against the fixture) — proving
  // the union rule keeps a node's own references resolvable even when
  // every flow touching it was filtered out.
  const webAppNode = flagship.nodes.find((n) => n.id === oneNodeId);
  assert.deepEqual(new Set(webAppNode.dataElementIds), new Set(['data:f68cbbd8e123', 'data:c929a6c5128b', 'data:2eda79a2e73e']));
  assert.equal(result.graph.dataElements.length, 3);
  assert.deepEqual(
    new Set(result.graph.dataElements.map((d) => d.id)),
    new Set(['data:f68cbbd8e123', 'data:c929a6c5128b', 'data:2eda79a2e73e']),
  );
});

// The single most important proof of the flow-narrowing rule: two real
// flows in the fixture (flow:f7273b6e7b61, flow:154396169be8) share the
// IDENTICAL source/sink pair (Web App -> Application Logs — the masked-
// and raw-log branches of the same field) but diverge on their second
// edge (edge:d613505336aa vs edge:a6fb8d3fdecc). A filter admitting both
// endpoint nodes plus only ONE flow's full edge set must keep exactly
// that one flow and drop the other — proving the rule is genuinely
// "every edgeIds[] entry must survive" and not merely "source and sink
// node ids survive" (which cannot tell the two flows apart at all).
test('exportGraphJSON: flow narrowing requires the FULL edgeIds subset, not just source/sink membership', () => {
  const sourceId = 'node:source:4aa6d910c10e'; // Web App
  const processId = 'node:process:b3cd659d55dd'; // Payments Service
  const logId = 'node:log:608492464d54'; // Application Logs
  const keptEdgeIds = ['edge:54d5b1db3415', 'edge:d613505336aa']; // Web App -> Payments Service -> Application Logs (masked branch)

  // Ground every id used above against the real fixture before relying
  // on it.
  const flowKept = flagship.flows.find((f) => f.id === 'flow:f7273b6e7b61');
  const flowDropped = flagship.flows.find((f) => f.id === 'flow:154396169be8');
  assert.deepEqual(flowKept.edgeIds, keptEdgeIds);
  assert.equal(flowKept.source, sourceId);
  assert.equal(flowKept.sink, logId);
  assert.deepEqual(flowDropped.edgeIds, ['edge:54d5b1db3415', 'edge:a6fb8d3fdecc']);
  assert.equal(flowDropped.source, sourceId);
  assert.equal(flowDropped.sink, logId);

  const result = exportGraphJSON(flagship, {
    filter: { nodeIds: [sourceId, processId, logId], edgeIds: keptEdgeIds },
  });

  assert.deepEqual(new Set(result.graph.nodes.map((n) => n.id)), new Set([sourceId, processId, logId]));
  assert.deepEqual(new Set(result.graph.edges.map((e) => e.id)), new Set(keptEdgeIds));
  assert.equal(result.graph.flows.length, 1, 'both candidate flows share source+sink; only the one whose full edgeIds[] survives should remain');
  assert.equal(result.graph.flows[0].id, 'flow:f7273b6e7b61');
});
