//
// adapters/artifact.js: read-only view over the artifact provenance graph
// (artifact/provenance-graph.js: commit -> build -> OCI digest -> SBOM
// component -> finding, plus an operator-declared deployment).
//
// The artifact graph has no repository identity of its own, so the caller names
// it (`repository`: the image repository or the source repository the artifact
// was built from). The graph digest is a canonical hash of the graph body.
//
// Relations: commit->build, build->digest and digest->deployment are
// `artifact_derivation`; digest->component and component->finding are
// `dependency`. An operator-declared deployment edge has origin `declared`; an
// edge with evidence 'none' (a commit that is not known) is kept, carries an
// `unknowns` entry, and has grade 'none'.
//
// The generator can list the same SBOM component or finding twice (an OS and an
// application package with one purl). Byte-identical duplicates are collapsed
// in the view and counted in metadata; duplicates that DIFFER are rejected,
// because choosing one would be a silent merge. `reconstruct()` returns the
// original graph, duplicates included.

import { digestOf, GraphViewError, canonicalJson } from '../refs.js';
import { IndexedGraphView, local } from '../view.js';

export const ARTIFACT_ADAPTER_VERSION = '1.0.0';

function relationFor(fromKind, toKind) {
  if (toKind === 'sbomComponent' || toKind === 'finding') return 'dependency';
  return 'artifact_derivation';
}

export function artifactView(graph, opts) {
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('artifactView requires a graph with nodes[] and edges[]');
  }
  const graphDigest = digestOf(graph);
  const byId = new Map();
  let duplicateNodes = 0;
  for (const n of graph.nodes) {
    const prev = byId.get(n.id);
    if (prev) {
      if (canonicalJson(prev) !== canonicalJson(n)) throw new GraphViewError('DUPLICATE_ID', `artifact graph has two different nodes with id ${n.id}`, { id: n.id });
      duplicateNodes += 1;
    } else byId.set(n.id, n);
  }
  const nodes = [...byId.values()].map((n) => ({ entityKind: n.kind, localId: n.id, native: n, summary: { kind: n.kind } }));
  const seenEdges = new Map();
  let duplicateEdges = 0;
  const edges = [];
  for (const e of graph.edges) {
    const id = `agedge:${e.from}->${e.to}`;
    const prev = seenEdges.get(id);
    if (prev) {
      if (canonicalJson(prev) !== canonicalJson(e)) throw new GraphViewError('DUPLICATE_ID', `artifact graph has two different edges ${e.from} -> ${e.to}`, { id });
      duplicateEdges += 1;
      continue;
    }
    seenEdges.set(id, e);
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (!from || !to) throw new GraphViewError('DANGLING_REF', `artifact edge ${e.from} -> ${e.to} points at a node that is not in the graph`, { id });
    const declared = e.evidence === 'operator-declared' || to.kind === 'deployment';
    const none = e.evidence === 'none';
    edges.push({
      id, relation: relationFor(from.kind, to.kind), origin: declared ? 'declared' : 'derived',
      from: local(from.kind, from.id), to: local(to.kind, to.id),
      evidence: { grade: e.evidence ?? 'none', source: 'artifact-provenance-graph' },
      unknowns: none ? [{ kind: 'unlinked', reason: 'no evidence links these two nodes' }] : (e.digestMatches === false ? [{ kind: 'digest-mismatch', reason: 'declared digest differs from the scanned artifact' }] : []),
      attrs: e.digestMatches === undefined ? {} : { digestMatches: e.digestMatches }, native: e,
    });
  }
  const unlinked = edges.filter((e) => e.unknowns.some((u) => u.kind === 'unlinked')).length;
  const reasons = unlinked ? [`unlinked-edges:${unlinked}`] : [];
  return new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: ARTIFACT_ADAPTER_VERSION, repository: opts?.repository, graphDigest,
    metadata: { nodes: graph.nodes.length, edges: graph.edges.length, duplicateNodes, duplicateEdges },
    completion: { status: reasons.length ? 'partial' : 'complete', reasons, coverage: null },
    nodes, edges,
    reconstruct: () => graph,
  });
}
