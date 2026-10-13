// PRD 5 P0 §6 — Provenance Graph: Git Commit -> Build -> OCI Digest -> SBOM
// Component -> Finding -> Deployment.
//
// Naming: the exported field is `artifactProvenanceGraph` and the builder is
// `buildArtifactProvenanceGraph` — never a bare `.provenance`/`*Provenance`,
// per this repo's own naming discipline (5 unrelated existing uses of
// "provenance"; see docs/implementation-status/source-to-artifact-provenance.md).
//
// This function does no new detection — every node/edge is assembled from
// evidence `inventory.js`/`vuln-correlate.js` already computed. The one
// exception is the Git-Commit edge, whose only evidence source is the
// standard `org.opencontainers.image.revision` build label; when absent the
// commit node is explicitly `known: false`, never inferred from git history
// (an image's build label is the only trustworthy claim of "which commit
// built this" — matching it against local git history by heuristic would be
// a confident-looking guess, the exact failure mode PRD 5's signature-state
// discipline exists to prevent elsewhere in this same PRD).
const REVISION_LABEL = 'org.opencontainers.image.revision';

function componentId(c) {
  return c.purl || `${c.ecosystem}:${c.name}@${c.version}`;
}

/**
 * `inventory` is `inventory.js#buildImageInventory`'s `inventory`.
 * `vulnerabilities` is `vuln-correlate.js`'s `queryOSVFn` result (only
 * `type: 'vulnerable_dep'` entries become Finding nodes — the no_lockfile",
 * "unpinned_dep" structural checks don't bind to a specific component and
 * are not part of this graph). `deployment`, if supplied, is an
 * OPERATOR-DECLARED record (`{ id, environment, evidence }`) — this codebase
 * has no mechanism anywhere that discovers "which digest is running where"
 * on its own (`lineage/deployment/` models topology, not running digests),
 * so a missing `deployment` argument means the graph simply stops at the
 * OCI Digest / SBOM Component / Finding nodes, never a fabricated edge.
 */
export function buildArtifactProvenanceGraph({ inventory, vulnerabilities = [], deployment = null }) {
  if (!inventory || typeof inventory.digest !== 'string') {
    throw new TypeError('buildArtifactProvenanceGraph requires an inventory with a digest');
  }
  const nodes = [];
  const edges = [];

  const commitSha = inventory.buildLabels ? inventory.buildLabels[REVISION_LABEL] || null : null;
  const commitId = `commit:${commitSha || 'unknown'}`;
  const buildId = `build:${inventory.digest}`;
  const digestId = `digest:${inventory.digest}`;

  nodes.push({ id: commitId, kind: 'gitCommit', sha: commitSha, known: !!commitSha });
  nodes.push({ id: buildId, kind: 'build', digest: inventory.digest, labels: inventory.buildLabels || {} });
  nodes.push({ id: digestId, kind: 'ociDigest', digest: inventory.digest, digestKind: inventory.digestKind, repoTags: inventory.repoTags || [] });

  edges.push({
    from: commitId, to: buildId,
    evidence: commitSha ? `label:${REVISION_LABEL}` : 'none',
  });
  edges.push({ from: buildId, to: digestId, evidence: 'same-archive' });

  const components = [...(inventory.osPackages || []), ...(inventory.appPackages || [])];
  for (const c of components) {
    const compId = `component:${componentId(c)}`;
    nodes.push({ id: compId, kind: 'sbomComponent', purl: c.purl || null, name: c.name, version: c.version, ecosystem: c.ecosystem });
    edges.push({ from: digestId, to: compId, evidence: 'inventory' });
  }

  const vulnDeps = (vulnerabilities || []).filter((v) => v.type === 'vulnerable_dep');
  for (const v of vulnDeps) {
    const compId = `component:${v.purl || `${v.ecosystem}:${v.name}@${v.version}`}`;
    const findingId = `finding:${v.osvId}:${v.purl || `${v.ecosystem}:${v.name}@${v.version}`}`;
    nodes.push({ id: findingId, kind: 'finding', osvId: v.osvId, cveAliases: v.cveAliases || [], severity: v.severity });
    edges.push({ from: compId, to: findingId, evidence: 'osv' });
  }

  if (deployment) {
    if (typeof deployment.id !== 'string') throw new TypeError('a supplied deployment record requires an "id"');
    const deploymentId = `deployment:${deployment.id}`;
    nodes.push({ id: deploymentId, kind: 'deployment', environment: deployment.environment || null, declaredDigest: deployment.digest || null });
    edges.push({
      from: digestId, to: deploymentId,
      evidence: deployment.evidence || 'operator-declared',
      digestMatches: deployment.digest ? deployment.digest === inventory.digest : null,
    });
  }

  return { nodes, edges };
}

/**
 * Walks the graph from a commit or digest to every reachable Finding/Deployment
 * node — the `provenance trace` CLI command's query surface.
 */
export function traceArtifactProvenanceGraph(graph, fromId) {
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('traceArtifactProvenanceGraph requires a graph with nodes/edges arrays');
  }
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  if (!byId.has(fromId)) return { found: false, path: [] };
  const adjacency = new Map();
  for (const e of graph.edges) {
    if (!adjacency.has(e.from)) adjacency.set(e.from, []);
    adjacency.get(e.from).push(e);
  }
  const visited = new Set([fromId]);
  const queue = [fromId];
  const reached = [];
  while (queue.length) {
    const cur = queue.shift();
    for (const e of adjacency.get(cur) || []) {
      if (visited.has(e.to)) continue;
      visited.add(e.to);
      reached.push({ node: byId.get(e.to), via: e });
      queue.push(e.to);
    }
  }
  return { found: true, root: byId.get(fromId), reached };
}
