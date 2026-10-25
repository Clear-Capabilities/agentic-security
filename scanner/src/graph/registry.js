//
// registry.js: the set of graph views a query may span (DAG-06 R06.6).
//
// What registration rejects, each with a typed GraphViewError:
//   INCOMPATIBLE_VERSION  an adapter whose major version this build cannot read
//   ID_COLLISION          the same (graph kind, repository, digest) registered
//                         twice with different content: a digest names ONE
//                         immutable graph
//   BAD_REF               a malformed view
//
// What lookups reject:
//   DANGLING_REF          the graph is not registered, or the entity is not in it
//   VERSION_INCOMPATIBLE  a reference written by a newer reference format
//   AMBIGUOUS_LOCAL_ID   a bare local id that exists in more than one graph; a
//                         local id is only meaningful inside its graph, so the
//                         registry will not pick one
//
// A reference never resolves across repositories: the repository is part of the
// reference, so `pnode:abc` in repository A and `pnode:abc` in repository B are
// two different entities.

import { GraphViewError, graphIdentityKey, validateRef, REF_VERSION } from './refs.js';
import { PROVENANCE_ADAPTER_VERSION } from './adapters/provenance.js';
import { DATAFLOW_ADAPTER_VERSION } from './adapters/dataflow.js';
import { SEMANTIC_ADAPTER_VERSION } from './adapters/semantic.js';
import { ARTIFACT_ADAPTER_VERSION } from './adapters/artifact.js';
import { CROSSREPO_ADAPTER_VERSION, FINDINGS_ADAPTER_VERSION } from './adapters/crossrepo.js';

const major = (v) => Number(String(v).split('.')[0]);

/** Adapter majors this build understands, per graph kind. */
export const SUPPORTED_ADAPTER_MAJORS = Object.freeze({
  provenance: [major(PROVENANCE_ADAPTER_VERSION)],
  dataflow: [major(DATAFLOW_ADAPTER_VERSION)],
  semantic: [major(SEMANTIC_ADAPTER_VERSION)],
  artifact: [major(ARTIFACT_ADAPTER_VERSION)],
  'cross-repo-links': [major(CROSSREPO_ADAPTER_VERSION)],
  findings: [major(FINDINGS_ADAPTER_VERSION)],
});

export function createGraphRegistry() {
  const views = new Map(); // identity key -> view

  function viewFor(ref) {
    const bad = validateRef(ref);
    if (bad) {
      throw new GraphViewError(ref && ref.v !== undefined && ref.v !== REF_VERSION ? 'VERSION_INCOMPATIBLE' : 'BAD_REF', bad, { ref });
    }
    const v = views.get(graphIdentityKey(ref));
    if (!v) throw new GraphViewError('DANGLING_REF', `no registered ${ref.graphKind} graph for repository ${ref.repository} with digest ${ref.graphDigest.slice(0, 12)}`, { ref });
    return v;
  }

  const foreignViews = () => [...views.values()].filter((v) => v._allowForeign);

  return {
    register(view) {
      const kinds = SUPPORTED_ADAPTER_MAJORS[view?.graphKind];
      if (!kinds) throw new GraphViewError('BAD_REF', `unknown graph kind ${view?.graphKind}`);
      if (!kinds.includes(major(view.adapterVersion))) {
        throw new GraphViewError('INCOMPATIBLE_VERSION', `${view.graphKind} adapter ${view.adapterVersion} is not readable by this build (supported majors: ${kinds.join(',')})`);
      }
      const key = graphIdentityKey(view);
      const prev = views.get(key);
      if (prev) {
        if (prev.fingerprint !== view.fingerprint) {
          throw new GraphViewError('ID_COLLISION', `${view.graphKind}/${view.repository} digest ${view.graphDigest.slice(0, 12)} is already registered with different content`, { key });
        }
        return prev;
      }
      views.set(key, view);
      return view;
    },

    views() { return [...views.values()]; },
    viewFor,

    has(ref) {
      const v = views.get(graphIdentityKey(ref));
      return !!v && v.has(ref);
    },

    node(ref) { return viewFor(ref).node(ref); },

    outgoing(ref, filter) {
      const out = viewFor(ref).outgoing(ref, filter);
      for (const fv of foreignViews()) if (fv.graphKind !== ref.graphKind || fv.repository !== ref.repository || fv.graphDigest !== ref.graphDigest) out.push(...fv.outgoing(ref, filter));
      return out;
    },

    incoming(ref, filter) {
      const inn = viewFor(ref).incoming(ref, filter);
      for (const fv of foreignViews()) if (fv.graphKind !== ref.graphKind || fv.repository !== ref.repository || fv.graphDigest !== ref.graphDigest) inn.push(...fv.incoming(ref, filter));
      return inn;
    },

    /** A bare local id is ambiguous when more than one registered graph has it. */
    resolveLocal(entityKind, localId, { graphKind } = {}) {
      const hits = [];
      for (const v of views.values()) {
        if (graphKind && v.graphKind !== graphKind) continue;
        try { hits.push(v.ref(entityKind, localId)); } catch { /* not in this graph */ }
      }
      if (hits.length === 0) throw new GraphViewError('DANGLING_REF', `no ${entityKind} ${localId} in any registered graph`);
      if (hits.length > 1) throw new GraphViewError('AMBIGUOUS_LOCAL_ID', `${entityKind} ${localId} exists in ${hits.length} registered graphs; use a full reference`, { candidates: hits });
      return hits[0];
    },

    /**
     * Classify a foreign endpoint (for example, a cross-repository link end):
     *   resolved             registered, and the entity exists
     *   unresolved           no registered graph with that identity (not an error:
     *                        the remote graph simply is not loaded)
     *   dangling             the graph is registered but the entity is not in it
     *   repository-mismatch  a graph with that digest is registered, but under a
     *                        different repository than the reference claims
     */
    classify(ref) {
      const bad = validateRef(ref);
      if (bad) throw new GraphViewError('BAD_REF', bad, { ref });
      const v = views.get(graphIdentityKey(ref));
      if (v) return v.has(ref) ? 'resolved' : 'dangling';
      for (const o of views.values()) {
        if (o.graphKind === ref.graphKind && o.graphDigest === ref.graphDigest && o.repository !== ref.repository) return 'repository-mismatch';
      }
      return 'unresolved';
    },
  };
}
