import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { graphId } from '../../src/lineage/ids.js';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { exportGraphJSON, computeGraphDigest } from '../../src/lineage/export-json.js';
import { loadRemoteGraphExport } from '../../src/lineage/federation-loader.js';

function tmpFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-federation-loader-'));
  return path.join(dir, name);
}

function validEnvelopeFile() {
  const graph = emptyGraphEnvelope({ graphId: graphId({ repository: 'remote-svc' }) });
  const exported = exportGraphJSON(graph, { redact: false });
  const filePath = tmpFile('remote-export.json');
  fs.writeFileSync(filePath, JSON.stringify(exported, null, 2));
  return { filePath, graph, exported };
}

test('loadRemoteGraphExport: missing file — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(path.join(os.tmpdir(), 'this-file-does-not-exist-agsec-federation.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
  assert.equal(r.graph, null);
  assert.match(r.message, /No remote graph export found/);
});

test('loadRemoteGraphExport: no filePath at all — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(undefined);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
});

test('loadRemoteGraphExport: malformed JSON — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('bad.json');
  fs.writeFileSync(filePath, '{not valid json');
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: valid JSON but not an exportGraphJSON envelope — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('not-an-envelope.json');
  fs.writeFileSync(filePath, JSON.stringify({ hello: 'world' }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: envelope has digest+graph but graph fails validateGraph — ok:false, reason "invalid-graph"', () => {
  const filePath = tmpFile('invalid-graph.json');
  const badGraph = { nodes: [{ id: 'not-a-real-node-id-shape' }] }; // missing required fields, wrong id prefix
  fs.writeFileSync(filePath, JSON.stringify({ digest: computeGraphDigest(badGraph), graph: badGraph }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid-graph');
  assert.equal(r.graph, null);
});

test('loadRemoteGraphExport: digest mismatch — ok:true, digestMatches:false, reason "digest-mismatch", still returns the graph', () => {
  const { filePath, exported } = validEnvelopeFile();
  const tampered = { ...exported, digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
  fs.writeFileSync(filePath, JSON.stringify(tampered));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, false);
  assert.equal(r.reason, 'digest-mismatch');
  assert.ok(r.graph);
  assert.match(r.message, /NOT authentication/);
});

test('loadRemoteGraphExport: a genuinely valid, self-consistent export — ok:true, digestMatches:true, reason:null', () => {
  const { filePath, graph } = validEnvelopeFile();
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, true);
  assert.equal(r.reason, null);
  assert.deepEqual(r.graph, graph);
  assert.equal(r.digest, computeGraphDigest(graph));
});

test('federation-loader.js never reuses loadSignedGraph for the remote side — the per-install-HMAC-key trust model is deliberately the WRONG one for a cross-machine remote file', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/federation-loader.js', import.meta.url)), 'utf8');
  assert.ok(!src.includes('graph-loader'), 'must never import scanner/src/server/graph-loader.js\'s loadSignedGraph for the remote side');
});
