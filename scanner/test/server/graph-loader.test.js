import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadSignedGraph } from '../../src/server/graph-loader.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-explore-loader-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _writeGraph(root, graphObj, { sign = true } = {}) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(graphObj, null, 2);
  fs.writeFileSync(graphPath, body);
  if (sign) fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('loadSignedGraph: missing file -> ok:false, reason "missing"', () => {
  const root = _mkTmpProject();
  try {
    const r = loadSignedGraph(root);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'missing');
    assert.match(r.message, /No lineage graph found/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadSignedGraph: a real signed graph -> ok:true', () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { schemaVersion: '1.0.0', graphId: 'dfg:test', nodes: [], edges: [], flows: [] });
    const r = loadSignedGraph(root);
    assert.equal(r.ok, true);
    assert.equal(r.graph.graphId, 'dfg:test');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadSignedGraph: missing .sig -> ok:false, reason "unsigned"', () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { graphId: 'dfg:unsigned' }, { sign: false });
    const r = loadSignedGraph(root);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'unsigned');
    assert.match(r.message, /no signature file/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadSignedGraph: a tampered body (mutated after signing) -> ok:false, reason "tampered"', () => {
  const root = _mkTmpProject();
  try {
    const graphPath = _writeGraph(root, { graphId: 'dfg:tampered' });
    const body = fs.readFileSync(graphPath, 'utf8');
    fs.writeFileSync(graphPath, body.slice(0, -1) + ' ' + body.slice(-1)); // mutate one byte, keep valid JSON length-ish
    const r = loadSignedGraph(root);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'tampered');
    assert.match(r.message, /FAILED signature verification/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadSignedGraph: malformed JSON in an otherwise-signed body -> ok:false, reason "malformed"', () => {
  const root = _mkTmpProject();
  try {
    const graphPath = statePath(root, 'lineage-graph.json');
    fs.mkdirSync(path.dirname(graphPath), { recursive: true });
    const body = '{ this is not valid json';
    fs.writeFileSync(graphPath, body);
    fs.writeFileSync(graphPath + '.sig', signLastScan(body));
    const r = loadSignedGraph(root);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'malformed');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadSignedGraph: never throws on an unreadable directory-shaped path', () => {
  const root = _mkTmpProject();
  try {
    // Create lineage-graph.json AS A DIRECTORY, which fs.readFileSync will
    // reject with EISDIR — must degrade to a clean failure, never throw.
    const graphPath = statePath(root, 'lineage-graph.json');
    fs.mkdirSync(graphPath, { recursive: true });
    assert.doesNotThrow(() => loadSignedGraph(root));
    const r = loadSignedGraph(root);
    assert.equal(r.ok, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
