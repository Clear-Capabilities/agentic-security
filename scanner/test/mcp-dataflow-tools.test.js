import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { signLastScan } from '../src/posture/integrity.js';
import { statePath } from '../src/posture/state-dir.js';
import {
  dataflow_get_graph,
  dataflow_get_node,
  dataflow_get_edge,
  dataflow_get_flow,
} from '../src/mcp/dataflow-tools.js';

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-mcp-dataflow-'));
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

const SAMPLE_GRAPH = {
  schemaVersion: '1.0.0',
  graphId: 'dfg:test-sample',
  extensions: {},
  scope: { root: '/tmp/fixture' },
  coverage: null,
  limitations: [],
  nodes: [{ id: 'node:api', kind: 'source', subtype: 'http-endpoint' }],
  edges: [{ id: 'edge:api-db', from: 'node:api', to: 'node:store', protection: {} }],
  flows: [{ id: 'flow:1', source: 'node:api', sink: 'node:store', edgeIds: ['edge:api-db'] }],
};

const TOOLS = {
  dataflow_get_graph,
  dataflow_get_node,
  dataflow_get_edge,
  dataflow_get_flow,
};

for (const [toolName, tool] of Object.entries(TOOLS)) {
  test(`${toolName}: missing graph -> hasResult:false, reason "missing"`, async () => {
    const root = _mkTmpProject();
    try {
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'missing');
      assert.match(result.message, /No lineage graph found/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test(`${toolName}: unsigned graph -> hasResult:false, reason "unsigned"`, async () => {
    const root = _mkTmpProject();
    try {
      _writeGraph(root, SAMPLE_GRAPH, { sign: false });
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'unsigned');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test(`${toolName}: tampered graph -> hasResult:false, reason "tampered"`, async () => {
    const root = _mkTmpProject();
    try {
      _writeGraph(root, SAMPLE_GRAPH);
      // Tamper AFTER signing, matching graph-loader.test.js's own precedent.
      const graphPath = statePath(root, 'lineage-graph.json');
      fs.writeFileSync(graphPath, JSON.stringify({ ...SAMPLE_GRAPH, graphId: 'dfg:tampered' }, null, 2));
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'tampered');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}

test('dataflow_get_graph: real signed graph -> hasResult:true, full graph body', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result._meta.source, 'agentic-security-mcp');
    assert.equal(result.data.graphId, 'dfg:test-sample');
    assert.equal(result.data.nodes.length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_node: real signed graph, found -> the node', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_node.handler({ id: 'node:api' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'node:api');
    assert.deepEqual(result.canonicalIds, ['node:api']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_node: real signed graph, not found -> hasResult:true, 404-shaped body', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_node.handler({ id: 'node:does-not-exist' }, { sessionRoot: root });
    // The graph loaded and verified fine; the ID just wasn't found — this is
    // NOT a loadSignedGraph failure, so hasResult stays true (matching
    // routes.js's own handleNode, which returns status:404 with a body,
    // never throws). Distinguish via `.notFound`, set true only on this path.
    assert.equal(result.hasResult, true);
    assert.equal(result.notFound, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_edge: real signed graph, found -> the edge', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_edge.handler({ id: 'edge:api-db' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'edge:api-db');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_flow: real signed graph, found -> the flow with contributing canonicalIds', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_flow.handler({ id: 'flow:1' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'flow:1');
    // handleFlow's own contract: canonicalIds = [flow id, source, sink, ...edgeIds]
    assert.ok(result.canonicalIds.includes('node:api'));
    assert.ok(result.canonicalIds.includes('edge:api-db'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: inputSchema rejects unknown properties', () => {
  assert.equal(dataflow_get_graph.inputSchema.additionalProperties, false);
});

test('dataflow_get_node: inputSchema requires id', () => {
  assert.deepEqual(dataflow_get_node.inputSchema.required, ['id']);
});
