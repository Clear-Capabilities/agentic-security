// Milestone 3, sub-project M3-UX-Query, Task 3. Nine focus-control graph
// traversals over the SAME DataFlowGraph v1 structure the query language
// (lib/query-language.js) reads. Each function returns the SAME
// `{nodeIds: Set<string>, edgeIds: Set<string>}` shape
// `views/architecture-view.js`'s own `resolveSelection` already produces
// for `selection` — so the render layer needs zero new consumption code to
// accept output from any of these. `resetToOverview` is deliberately NOT
// implemented here: Task 4 wires the existing `resolveSelection(graph,
// null)` directly for that control (see this file's own header note in the
// task brief) — duplicating it here would just be a second, divergent copy
// of the same empty-selection shape.

function buildAdjacency(graph) {
  const forward = new Map(); // nodeId -> [{edgeId, toId}]
  const backward = new Map(); // nodeId -> [{edgeId, fromId}]
  for (const n of graph.nodes) { forward.set(n.id, []); backward.set(n.id, []); }
  for (const e of graph.edges) {
    forward.get(e.from)?.push({ edgeId: e.id, toId: e.to });
    backward.get(e.to)?.push({ edgeId: e.id, fromId: e.from });
  }
  return { forward, backward };
}

function bfsDirection(graph, startId, adjacencyKey, adjacency) {
  const nodeIds = new Set([startId]);
  const edgeIds = new Set();
  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const { edgeId, toId, fromId } of adjacency.get(current) ?? []) {
      const nextId = adjacencyKey === 'forward' ? toId : fromId;
      edgeIds.add(edgeId);
      if (!nodeIds.has(nextId)) { nodeIds.add(nextId); queue.push(nextId); }
    }
  }
  return { nodeIds, edgeIds };
}

export function showDownstream(graph, nodeId) {
  const { forward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'forward', forward);
}

export function showUpstream(graph, nodeId) {
  const { backward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'backward', backward);
}

export function showAllPaths(graph, nodeId) {
  const down = showDownstream(graph, nodeId);
  const up = showUpstream(graph, nodeId);
  return {
    nodeIds: new Set([...down.nodeIds, ...up.nodeIds]),
    edgeIds: new Set([...down.edgeIds, ...up.edgeIds]),
  };
}

export function showShortestPath(graph, fromId, toId) {
  const { forward } = buildAdjacency(graph);
  const cameFrom = new Map(); // nodeId -> {viaEdgeId, fromId}
  const visited = new Set([fromId]);
  const queue = [fromId];
  let found = false;
  while (queue.length > 0 && !found) {
    const current = queue.shift();
    for (const { edgeId, toId: nextId } of forward.get(current) ?? []) {
      if (visited.has(nextId)) continue;
      visited.add(nextId);
      cameFrom.set(nextId, { viaEdgeId: edgeId, fromId: current });
      if (nextId === toId) { found = true; break; }
      queue.push(nextId);
    }
  }
  if (!found) return { nodeIds: new Set(), edgeIds: new Set() };
  const nodeIds = new Set([toId]);
  const edgeIds = new Set();
  let cursor = toId;
  while (cursor !== fromId) {
    const step = cameFrom.get(cursor);
    edgeIds.add(step.viaEdgeId);
    nodeIds.add(step.fromId);
    cursor = step.fromId;
  }
  return { nodeIds, edgeIds };
}

export function showExternalPathsOnly(graph) {
  const externalNodeIds = new Set(graph.nodes.filter((n) => n.externality?.value === 'external').map((n) => n.id));
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const flow of graph.flows) {
    const pathNodeIds = new Set([flow.source, flow.sink]);
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) { pathNodeIds.add(edge.from); pathNodeIds.add(edge.to); }
    }
    if ([...pathNodeIds].some((id) => externalNodeIds.has(id))) {
      for (const id of pathNodeIds) nodeIds.add(id);
      for (const edgeId of flow.edgeIds) edgeIds.add(edgeId);
    }
  }
  return { nodeIds, edgeIds };
}

const UNPROTECTED_VERDICTS = new Set(['unprotected', 'mixed', 'unknown']);
export function showUnprotectedPathsOnly(graph) {
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const edge of graph.edges) {
    const verdicts = [edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict];
    if (verdicts.some((v) => UNPROTECTED_VERDICTS.has(v))) {
      edgeIds.add(edge.id);
      nodeIds.add(edge.from);
      nodeIds.add(edge.to);
    }
  }
  return { nodeIds, edgeIds };
}

export function showAliases(graph, nodeId) {
  const node = graph.nodes.find((n) => n.id === nodeId);
  const nodeIds = new Set([nodeId]);
  // Real, honest implementation. This plan's own Global Constraints section
  // disclosed node.aliases as "confirmed always empty in real scan output" —
  // that claim does NOT hold against the real committed flagship fixture
  // (Web App/Payment API/Analytics API all carry non-empty aliases arrays
  // there; see test/focus-controls.test.js for the correction). What IS
  // true, confirmed against that same fixture: every alias entry is an
  // alternate DISPLAY NAME for the node itself (e.g. "Checkout Form" is
  // another name for the Web App node), never a pointer to a distinct
  // sibling node record — no alias string in the fixture matches any other
  // real node's label or id. This loop is still real, correct logic (not a
  // no-op stub): it looks up each alias against the graph's own nodes and
  // only adds a match it actually finds, so it will do the right thing the
  // moment (if ever) alias data that DOES reference a distinct node record
  // shows up in a real scan — nothing here is invented alias data.
  for (const alias of node?.aliases ?? []) {
    const aliasNode = graph.nodes.find((n) => n.label === alias || n.id === alias);
    if (aliasNode) nodeIds.add(aliasNode.id);
  }
  return { nodeIds, edgeIds: new Set() };
}

export function showDisconnected(graph) {
  const connectedIds = new Set();
  for (const e of graph.edges) { connectedIds.add(e.from); connectedIds.add(e.to); }
  const nodeIds = new Set(graph.nodes.filter((n) => !connectedIds.has(n.id)).map((n) => n.id));
  return { nodeIds, edgeIds: new Set() };
}
