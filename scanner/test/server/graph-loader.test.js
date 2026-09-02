import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadSignedGraph, loadFreshLineageGraph } from '../../src/server/graph-loader.js';
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

// loadFreshLineageGraph — M4 sub-project 6c's final whole-branch review
// (F1, blocking): a signed graph existing on disk must never be trusted
// unless THIS scan's own scanHealth confirms lineage analysis genuinely
// ran and succeeded. Each case below builds a minimal `scan` object with
// just the scanHealth.lineageAnalysis shape engine.js really produces.

test('loadFreshLineageGraph: requested + enabled + no failure -> fresh, real graph returned', () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { graphId: 'dfg:fresh' });
    const scan = { scanHealth: { lineageAnalysis: { requested: true, enabled: true, failure: null } } };
    const r = loadFreshLineageGraph(root, scan);
    assert.equal(r.fresh, true);
    assert.equal(r.graph.graphId, 'dfg:fresh');
    assert.equal(r.loaded.ok, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadFreshLineageGraph: not requested this scan -> a stale graph on disk is ignored, never returned', () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { graphId: 'dfg:stale-not-requested' });
    const scan = { scanHealth: { lineageAnalysis: { requested: false, enabled: false, failure: null } } };
    const r = loadFreshLineageGraph(root, scan);
    assert.equal(r.fresh, false);
    assert.equal(r.graph, null);
    // The raw loader result is still exposed, so a caller can still tell
    // "a file exists but isn't fresh" apart from "no file at all".
    assert.equal(r.loaded.ok, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadFreshLineageGraph: requested + enabled:true + a real failure -> a stale graph is ignored (F1 regression guard)', () => {
  // The exact state engine.js's own lineage gate produces when the build
  // throws AFTER _lineageStatus.enabled is already set true — see
  // engine.js's own comment on why `enabled` alone never means "the build
  // succeeded", and test/lineage-fault-injection.test.js for the real,
  // already-shipped proof this state is reachable. A naive
  // `requested && enabled` check (the pre-F1-fix version of this
  // function) incorrectly accepted a stale graph here.
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { graphId: 'dfg:stale-after-failure' });
    const scan = { scanHealth: { lineageAnalysis: { requested: true, enabled: true, failure: 'simulated buildCallGraph throw' } } };
    const r = loadFreshLineageGraph(root, scan);
    assert.equal(r.fresh, false, 'a graph left over from a scan whose lineage build failed must never read as fresh');
    assert.equal(r.graph, null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadFreshLineageGraph: no scanHealth at all (a minimal/older scan object) -> honestly not fresh, never throws', () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, { graphId: 'dfg:no-scanhealth' });
    assert.doesNotThrow(() => loadFreshLineageGraph(root, {}));
    assert.doesNotThrow(() => loadFreshLineageGraph(root, null));
    assert.doesNotThrow(() => loadFreshLineageGraph(root, undefined));
    const r = loadFreshLineageGraph(root, {});
    assert.equal(r.fresh, false);
    assert.equal(r.graph, null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('loadFreshLineageGraph: a tampered graph is never fresh even if requested+enabled say the scan itself succeeded', () => {
  const root = _mkTmpProject();
  try {
    const graphPath = _writeGraph(root, { graphId: 'dfg:tampered-fresh-check' });
    const body = fs.readFileSync(graphPath, 'utf8');
    fs.writeFileSync(graphPath, body.slice(0, -1) + ' ' + body.slice(-1));
    const scan = { scanHealth: { lineageAnalysis: { requested: true, enabled: true, failure: null } } };
    const r = loadFreshLineageGraph(root, scan);
    assert.equal(r.fresh, false);
    assert.equal(r.graph, null);
    assert.equal(r.loaded.reason, 'tampered');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
