# scanner/src/graph/

Typed, read-only graph views and identity crosswalks (DAG-06). A lens over the
graph layers that already exist; it replaces none of them and changes none of
their schemas, exports or validators.

| Module | Responsibility |
|---|---|
| `refs.js` | Reference format `{v, graphKind, repository, graphDigest, entityKind, localId}`, `refKey`/`parseRef`, `GraphViewError` codes, canonical digest |
| `relations.js` | Relation kinds (data_flow, control_dependence, calls, returns, dependency, declaration, observation, artifact_derivation), edge origins (code, derived, schema, declared, observed), the traversal filter |
| `view.js` | `IndexedGraphView` (the view contract) and the adjacency index cache keyed by graph kind + digest + adapter version |
| `adapters/` | `provenance` (PathStore pnode/pedge), `dataflow` (DataFlowGraph v1), `semantic` (SemanticGraph v1), `artifact` (artifact provenance graph), `crossrepo` (CrossRepoLink records, findings) |
| `registry.js` | Registered views; rejects dangling refs, incompatible adapter versions, same-identity-different-content, ambiguous bare local ids |
| `crosswalk.js` | Versioned, evidence-bearing mappings; cardinality is explicit; cross-repository `identity` mappings are refused |
| `crosswalk-builders.js` | finding to call site to witnesses to flow; projected node to underlying sites |
| `observation.js` | Attributes a runtime observation to a projected node's sites without copying it onto every site |

## Rules

- **Read-only, pure, no network.** Adapters never mutate their source graph;
  `reconstruct()` returns the original object. `path-store.js` is duck-typed and
  never imported; no analysis engine is imported anywhere here.
- **A local id is never a key.** Every index and mapping is keyed by the full
  reference (kind, repository, digest, entity kind, local id).
- **Two axes.** A query filter chooses relations AND origins. The default
  traverses `code`, `derived` and `schema` edges only; a `declared` cross-repo
  link or an `observed` edge is walked only when the caller asks for that origin.
- **Coarsening is stated.** A mapping with several targets is `one-to-many`
  with `coarsens` and `unknowns`; nothing is attributed to "every" target.
- **Versions.** Adapter versions and `CROSSWALK_VERSION` are semver; the registry
  accepts only supported majors.
