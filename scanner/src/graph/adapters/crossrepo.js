//
// adapters/crossrepo.js: read-only view over CrossRepoLink records
// (lineage/cross-repo-link.js), plus a small findings view.
//
// A cross-repository link is an operator DECLARATION. In this view it is an
// edge with origin `declared` and evidence grade `declared`, so the default
// query filter (code-derived and derived edges only) never walks it as if it
// were a code-derived data flow, and it can never be mistaken for observed
// telemetry (R06.4). Its endpoints live in OTHER graphs, so they are foreign
// references, each carrying that graph's repository and digest. An endpoint
// that no registered graph can resolve is reported by the registry as
// unresolved, not dropped.
//
// Both endpoints are `dataflow` node references: that is the only graph kind a
// CrossRepoLink record binds today.

import { validateCrossRepoLink } from '../../lineage/cross-repo-link.js';
import { digestOf, makeRef, GraphViewError } from '../refs.js';
import { IndexedGraphView, foreign } from '../view.js';

export const CROSSREPO_ADAPTER_VERSION = '1.0.0';
export const FINDINGS_ADAPTER_VERSION = '1.0.0';

/**
 * @param {object[]} links  CrossRepoLink records
 * @param {{localRepository:string}} opts  the repository the `local` side belongs to
 */
export function crossRepoLinkView(links, opts) {
  if (!Array.isArray(links)) throw new TypeError('crossRepoLinkView requires an array of links');
  const localRepository = opts?.localRepository;
  const nodes = [];
  const edges = [];
  for (const l of links) {
    const v = validateCrossRepoLink(l);
    if (!v.valid) throw new GraphViewError('INVALID_LINK', `cross-repo link ${l?.id ?? '?'} is invalid: ${v.errors[0].path} ${v.errors[0].message}`, { errors: v.errors });
    nodes.push({ entityKind: 'link', localId: l.id, native: l, summary: { declaredBy: l.declaredBy, declaredAt: l.declaredAt } });
    const from = makeRef({ graphKind: 'dataflow', repository: localRepository, graphDigest: l.local.graphDigest, entityKind: 'node', localId: l.local.nodeId });
    const to = makeRef({ graphKind: 'dataflow', repository: l.remote.repository, graphDigest: l.remote.graphDigest, entityKind: 'node', localId: l.remote.nodeId });
    edges.push({
      id: l.id, relation: 'data_flow', origin: 'declared',
      from: foreign(from), to: foreign(to),
      evidence: { grade: 'declared', source: 'operator', declaredBy: l.declaredBy },
      unknowns: [{ kind: 'not-observed', reason: 'a declared link is an assertion, not an observed data flow' }],
      attrs: { rationale: l.rationale ?? null, provenance: l.provenance }, native: l,
    });
  }
  return new IndexedGraphView({
    graphKind: 'cross-repo-links', adapterVersion: CROSSREPO_ADAPTER_VERSION, repository: localRepository, graphDigest: digestOf(links),
    metadata: { links: links.length },
    completion: { status: 'complete', reasons: [], coverage: null },
    nodes, edges, allowForeign: true,
    reconstruct: () => links,
  });
}

/**
 * Findings as referenceable entities (no edges): the starting point of a
 * finding -> call site -> witnesses -> flow join.
 * @param {object[]} findings scanner findings; localId is `stableId` when present, else `id`
 */
export function findingsView(findings, opts) {
  if (!Array.isArray(findings)) throw new TypeError('findingsView requires an array of findings');
  const nodes = findings.map((f) => {
    const id = f.stableId ?? f.id;
    if (typeof id !== 'string' || !id) throw new GraphViewError('BAD_REF', 'every finding needs a stableId or id');
    return { entityKind: 'finding', localId: id, native: f, summary: { file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity ?? null } };
  });
  return new IndexedGraphView({
    graphKind: 'findings', adapterVersion: FINDINGS_ADAPTER_VERSION, repository: opts?.repository, graphDigest: digestOf(findings),
    metadata: { findings: findings.length },
    completion: { status: 'unknown', reasons: ['a finding list says nothing about what was not scanned'], coverage: null },
    nodes, edges: [],
    reconstruct: () => findings,
  });
}
