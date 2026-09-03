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

test('dataflow_get_graph: an optional filter narrows the returned graph via _filterGraph', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({ filter: { nodeIds: ['node:api'], edgeIds: [] } }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.nodes.length, 1);
    assert.equal(result.data.nodes[0].id, 'node:api');
    assert.equal(result.data.edges.length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: omitting filter still returns the whole graph, unchanged', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.nodes.length, 1);
    assert.equal(result.data.edges.length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: a malformed filter returns a clear tool-error result, never throws', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({ filter: { nodeIds: 'not-an-array' } }, { sessionRoot: root });
    assert.equal(result.hasResult, false);
    assert.equal(result.reason, 'invalid-filter');
    assert.match(result.message, /must be a JSON object/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: inputSchema accepts a well-formed filter and rejects an unknown top-level property', () => {
  assert.equal(dataflow_get_graph.inputSchema.properties.filter.type, 'object');
  assert.equal(dataflow_get_graph.inputSchema.additionalProperties, false);
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

// Real regression coverage for the security-review follow-up: node.destination
// (raw/literalValue) and evidence[].claim/.snippet/.location.note are all
// scanned-source-derived strings a secret pattern can appear in.
const SECRET_GRAPH = {
  schemaVersion: '1.0.0',
  graphId: 'dfg:test-secret',
  extensions: {},
  scope: { root: '/tmp/fixture' },
  coverage: null,
  limitations: [],
  nodes: [{
    id: 'node:webhook',
    kind: 'sink',
    subtype: 'external-webhook',
    destination: {
      resolutionStatus: 'literal',
      raw: `sendWebhook("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")`,
      literalValue: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
      blockingExpression: null,
    },
  }],
  edges: [],
  flows: [],
  evidence: [{
    id: 'evidence:1',
    claim: 'destination literal resolves to https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    evidenceType: 'destination-resolution',
    location: { note: 'password="hunter2hunter2" appears near this call' },
    snippet: 'const password = "hunter2hunter2";',
  }],
};

test('dataflow_get_graph: redacts node.destination and evidence secrets', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SECRET_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    const node = result.data.nodes[0];
    assert.doesNotMatch(node.destination.raw, /hooks\.slack\.com\/services\/T00000000/);
    assert.doesNotMatch(node.destination.literalValue, /hooks\.slack\.com\/services\/T00000000/);
    assert.match(node.destination.literalValue, /\[REDACTED:slack-webhook\]/);
    const ev = result.data.evidence[0];
    assert.doesNotMatch(ev.claim, /hooks\.slack\.com\/services\/T00000000/);
    assert.doesNotMatch(ev.snippet, /hunter2hunter2/);
    assert.doesNotMatch(ev.location.note, /hunter2hunter2/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// fix-round-1, B1: graph.recipientProfiles[].technicalEndpoint is a
// scanned-source-derived literal, the same shape node.destination.literalValue
// already redacts — this is the real, end-to-end reproduction that it
// reaches dataflow_get_graph redacted, through the MCP tool, not just via a
// direct _redactGraph unit call (see test/lineage/redact-graph.test.js for
// that).
const RECIPIENT_SECRET_GRAPH = {
  schemaVersion: '1.0.0',
  graphId: 'dfg:test-recipient-secret',
  extensions: {},
  scope: { root: '/tmp/fixture' },
  coverage: null,
  limitations: [],
  nodes: [],
  edges: [],
  flows: [],
  evidence: [],
  recipientProfiles: [{
    id: 'recipient:aws-s3:abc123',
    recipientKey: 'Amazon S3',
    technicalEndpoint: 'https://my-bucket.s3.amazonaws.com/?token=AKIAABCDEFGHIJKLMNOP',
    provider: 'Amazon S3',
    legalEntity: null,
    retentionCommitment: null,
    transferMechanism: null,
  }],
};

test('dataflow_get_graph: redacts recipientProfiles[].technicalEndpoint secrets', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, RECIPIENT_SECRET_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    const profile = result.data.recipientProfiles[0];
    assert.doesNotMatch(profile.technicalEndpoint, /AKIAABCDEFGHIJKLMNOP/);
    assert.match(profile.technicalEndpoint, /\[REDACTED:aws-access-key\]/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_node: redacts destination secrets on the single-node response', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SECRET_GRAPH);
    const result = await dataflow_get_node.handler({ id: 'node:webhook' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.doesNotMatch(result.data.destination.raw, /hooks\.slack\.com\/services\/T00000000/);
    assert.doesNotMatch(result.data.destination.literalValue, /hooks\.slack\.com\/services\/T00000000/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
