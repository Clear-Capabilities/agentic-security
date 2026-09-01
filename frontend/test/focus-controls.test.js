import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import {
  showUpstream, showDownstream, showAllPaths, showShortestPath,
  showExternalPathsOnly, showUnprotectedPathsOnly, showAliases, showDisconnected,
} from '../src/lib/focus-controls.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;

test('showDownstream: from Web App, includes every node reachable by following edges forward', () => {
  const result = showDownstream(FLAGSHIP_GRAPH, NODE_KEYS['node.web']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']));
  // Traced by hand against the real fixture's own edges: Web App fans out
  // to Payments Service, AI Assistant, Events Service, and Unresolved
  // Destination directly, and from there reaches every other node in the
  // graph transitively EXCEPT API Gateway (node.gateway), which the real
  // fixture never wires into any edge's `from`/`to` at all (confirmed by
  // grep — "node:api:02d844c7d1cd" appears only in the node list and the
  // fixtureNodeKeys map, never in `edges`). So Web App's real downstream
  // set is every node in the 14-node fixture except the Gateway.
  const expectedIncluded = [
    'node.web', 'node.payments', 'node.ai', 'node.events', 'node.unresolved',
    'node.postgres', 'node.logs', 'node.payment_api', 'node.model', 'node.vector',
    'node.analytics', 'node.retention', 'node.deletion',
  ];
  for (const key of expectedIncluded) {
    assert.ok(result.nodeIds.has(NODE_KEYS[key]), `expected downstream(Web App) to include ${key}`);
  }
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.gateway']), 'API Gateway has zero edges in the fixture, so it is unreachable from Web App');
  assert.equal(result.nodeIds.size, 13, 'downstream(Web App) is every one of the 14 fixture nodes except the disconnected Gateway');
});

test('showUpstream: from a deep sink, includes only nodes that can reach it', () => {
  const result = showUpstream(FLAGSHIP_GRAPH, NODE_KEYS['node.postgres']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.postgres']));
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.analytics']), 'a node with no path TO PostgreSQL must not appear in its upstream set — confirm this is real against the fixture\'s own topology first');
  // Traced by hand: PostgreSQL's only incoming edge is Payments Service ->
  // PostgreSQL (edge:fde2387ae333), and Payments Service's only incoming
  // edge is Web App -> Payments Service (edge:54d5b1db3415). Web App has
  // no incoming edges at all (it's the fixture's own entry point). So
  // PostgreSQL's real upstream set is exactly {PostgreSQL, Payments
  // Service, Web App} — nothing else in the fixture can reach it,
  // including the Analytics/Events/AI/Model branches, which are entirely
  // disjoint downstream-only paths off Web App that never loop back.
  assert.equal(result.nodeIds.size, 3);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.payments']));
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']));
});

test('showAllPaths: is the union of showUpstream and showDownstream from the same node', () => {
  const nodeId = NODE_KEYS['node.payments'];
  const up = showUpstream(FLAGSHIP_GRAPH, nodeId);
  const down = showDownstream(FLAGSHIP_GRAPH, nodeId);
  const all = showAllPaths(FLAGSHIP_GRAPH, nodeId);
  for (const id of up.nodeIds) assert.ok(all.nodeIds.has(id));
  for (const id of down.nodeIds) assert.ok(all.nodeIds.has(id));
  assert.equal(all.nodeIds.size, new Set([...up.nodeIds, ...down.nodeIds]).size);
});

test('showShortestPath: between two connected nodes, returns a real, connected path (each edge in the result genuinely links two nodes in the result)', () => {
  const result = showShortestPath(FLAGSHIP_GRAPH, NODE_KEYS['node.web'], NODE_KEYS['node.postgres']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']));
  assert.ok(result.nodeIds.has(NODE_KEYS['node.postgres']));
  for (const edgeId of result.edgeIds) {
    const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
    assert.ok(result.nodeIds.has(edge.from) && result.nodeIds.has(edge.to), 'every edge in a shortest-path result must connect two nodes also in the result');
  }
  // Traced by hand: the real shortest (and only) path from Web App to
  // PostgreSQL is the direct 2-hop Web App -> Payments Service ->
  // PostgreSQL, via edge:54d5b1db3415 and edge:fde2387ae333.
  assert.equal(result.nodeIds.size, 3);
  assert.equal(result.edgeIds.size, 2);
  assert.ok(result.edgeIds.has('edge:54d5b1db3415'));
  assert.ok(result.edgeIds.has('edge:fde2387ae333'));
});

test('showShortestPath: between two DISCONNECTED nodes, returns an empty (not crashing, not falsely-connected) result', () => {
  // A real disconnected pair exists in the flagship fixture itself: API
  // Gateway (node.gateway) has zero edges anywhere in the fixture (grep-
  // confirmed against the real committed data — it never appears as an
  // edge's `from` or `to`), so no forward path can ever reach it from Web
  // App, and no hand-built graph is needed for a genuine negative case.
  const result = showShortestPath(FLAGSHIP_GRAPH, NODE_KEYS['node.web'], NODE_KEYS['node.gateway']);
  assert.equal(result.nodeIds.size, 0);
  assert.equal(result.edgeIds.size, 0);
});

test('showExternalPathsOnly: includes only nodes/edges on a path that touches an external node', () => {
  const result = showExternalPathsOnly(FLAGSHIP_GRAPH);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.payment_api']), 'Payment API is external');
  // Traced by hand against the real fixture's flows: 4 of the 8 real flows
  // touch a node whose externality.value === 'external' (Payment API,
  // Analytics API, and Model Provider are the only 3 nodes marked
  // 'external' — Vector Store and Unresolved Destination are marked
  // 'unknown', which this control deliberately does NOT treat as
  // external): flow.pci.payment_api (payment_api), flow.pci.ai (model),
  // flow.phi.ai (model), flow.pii.analytics (analytics). The other 4 flows
  // (both log-write branches, the database write, and the unresolved-
  // destination flow) never touch an external node and must be excluded.
  const expectedIncludedNodes = ['node.web', 'node.payments', 'node.payment_api', 'node.ai', 'node.model', 'node.vector', 'node.events', 'node.analytics'];
  for (const key of expectedIncludedNodes) {
    assert.ok(result.nodeIds.has(NODE_KEYS[key]), `expected external-paths-only to include ${key}`);
  }
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.postgres']), 'the database-write flow never touches an external node');
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.logs']), 'neither log-write flow touches an external node');
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.unresolved']), 'Unresolved Destination is externality "unknown", not "external" — must not be swept in');
});

test('showUnprotectedPathsOnly: includes only edges whose worst verdict is unprotected or unknown', () => {
  const result = showUnprotectedPathsOnly(FLAGSHIP_GRAPH);
  // Traced by hand against the real fixture's own edge.protection blocks:
  // only 3 of the 15 real edges have any dimension whose verdict is
  // 'unprotected'/'mixed'/'unknown' — everything else is either
  // 'not_assessed' (never swept in by this control) or 'protected'.
  //   - edge:a6fb8d3fdecc (Payments Service -> Application Logs, the RAW
  //     PCI branch): handling verdict 'unprotected'.
  //   - edge:fde2387ae333 (Payments Service -> PostgreSQL): atRest
  //     verdict 'unknown'.
  //   - edge:b397f3640150 (Payments Service -> Payment API): transit
  //     verdict 'unprotected'.
  assert.ok(result.edgeIds.has('edge:a6fb8d3fdecc'), 'the raw (unmasked) PCI log-write edge is a real unprotected edge in the fixture');
  assert.ok(result.edgeIds.has('edge:fde2387ae333'));
  assert.ok(result.edgeIds.has('edge:b397f3640150'));
  assert.equal(result.edgeIds.size, 3);
  // A real, fully-protected-or-unassessed counterpart edge in the fixture
  // must be excluded: edge:d613505336aa is the MASKED PCI log-write
  // branch — its handling verdict is 'protected' (transit/atRest are
  // 'not_assessed', which never triggers inclusion on its own) — and it
  // shares the exact same (from, to) node pair as the raw branch above,
  // proving this control distinguishes them by real per-edge verdict, not
  // by endpoint.
  assert.ok(!result.edgeIds.has('edge:d613505336aa'), 'the masked (protected-handling) PCI log-write edge must be excluded');
});

test('showAliases: reads the real node.aliases field, honestly returns nothing extra today', () => {
  const result = showAliases(FLAGSHIP_GRAPH, NODE_KEYS['node.web']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']), 'the node itself is always included');
  // Real finding, grounded against the actual committed fixture (a
  // correction to this plan's own disclosed claim that node.aliases is
  // "confirmed always empty in real scan output" — that claim does NOT
  // hold here): Web App's own aliases array is ["Checkout Form",
  // "Registration Form"], not empty. Payment API (["Payment Processor"])
  // and Analytics API (["Analytics Provider", "Analytics DB"]) also carry
  // real, non-empty aliases. What IS true: every alias in the fixture is
  // an alternate DISPLAY NAME for the node itself, never a pointer to a
  // distinct sibling node record — no alias string here matches any other
  // real node's label or id — so the function still correctly returns
  // just the base node, for a different and more interesting reason than
  // "the array happens to be empty."
  const webNode = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.web']);
  assert.ok(webNode.aliases.length > 0, 'sanity check on the real fixture: Web App does have non-empty aliases');
  assert.equal(result.nodeIds.size, 1, 'none of Web App\'s real alias strings match another node\'s label or id, so nothing extra is added');
  assert.equal(result.edgeIds.size, 0);
});

test('showDisconnected: returns nodes with zero edges — confirm against the real fixture whether any exist, don\'t assume', () => {
  const result = showDisconnected(FLAGSHIP_GRAPH);
  for (const id of result.nodeIds) {
    const hasAnyEdge = FLAGSHIP_GRAPH.edges.some((e) => e.from === id || e.to === id);
    assert.ok(!hasAnyEdge, `node ${id} was returned as disconnected but has a real edge`);
  }
  // Confirmed by grep against the real fixture: exactly one node, API
  // Gateway (node.gateway), never appears in any edge's `from` or `to`.
  // Every other one of the 14 real nodes participates in at least one
  // real edge.
  assert.equal(result.nodeIds.size, 1);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.gateway']));
});
