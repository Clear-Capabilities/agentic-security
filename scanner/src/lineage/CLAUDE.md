# scanner/src/lineage/

Data Flow Explorer's canonical `DataFlowGraph v1` contract package
(PRD section 18.1 — an untracked root working document, per this repo's
convention of not committing in-progress PRDs; ask the maintainer for the
current copy if you need it).
Isolated by design from `scanner/src/dataflow/`'s taint engine — see that
package's own CLAUDE.md for why (D-0047's precedent: a second, independent
engine sharing only pure, stateless utilities, never mutable taint state —
e.g. `access-paths.js`'s `accessPathOf`/`pathIsCoveredByPrefix`/`isCoveredBy`,
never `engine.js`'s live taint state).

## What's here

**Milestone 0 (contract and fixture):**

| Module | Responsibility |
|---|---|
| `schema.js` | Envelope shape, `SCHEMA_VERSION`, node/mapping/transform/coverage/policy/evidence enums |
| `ids.js` | Deterministic stable-ID functions (`nodeId`, `edgeId`, `dataElementId`, `flowId`, `transformationId`, `evidenceId`, `graphId`) — sha256-over-canonicalized-material, same shape as `posture/stable-id.js`'s finding IDs |
| `protection.js` | Protection verdict model: `PROTECTION_VERDICTS` × `EVIDENCE_GRADES` per dimension (`transit`/`atRest`/`handling`), plus `aggregateVerdicts()`'s risk-precedence reduction (PRD 8.4) |
| `classification.js` | Data classes (reuses `dataflow/privacy-taxonomy.js` + adds `CONFIDENTIAL`) and the 15 AI processing contexts (PRD 9.2) — AI is modeled as orthogonal to data class, never a mutually-exclusive label |
| `validate.js` | Hand-rolled structural validator (`validateGraph`) — no new npm dependency; `dataflow-graph.schema.json` is the JSON-Schema-dialect twin, kept in parity by `test/lineage/json-schema-parity.test.js`. Checks id-prefix format (regex per entity kind), every risk-bearing enum (`node.kind`, `node.externality.value`, `node.coverageStatus`, `dataElement.dataClasses`/`.aiContexts` array *contents*, `edge.protocol.destinationResolution`, `flow.policyVerdict`/`.protectionSummary`, `transformation.kind`/`.reversibility`, `evidence.evidenceType`, `graph.scope.source`) against `schema.js`/`classification.js`, not just array/field presence — each gap was closed after an initial pass let a made-up value validate cleanly (see git history on `validate.js`). Also checks duplicate-id uniqueness across the four top-level entity arrays (nodes/edges/dataElements/flows) — a real gap until it was closed alongside the enum gaps above. |
| `dataflow-graph.schema.json` | Authoritative JSON Schema (2020-12) document for external interop/documentation |
| `fixtures/build-flagship-fixture.mjs` | Deterministic generator for the payments-platform reference fixture (PRD Appendix D.2/D.3) — re-run and re-commit `flagship-graph.json` if you change the generator; a diff test (`flagship-fixture.test.js`) enforces idempotence. Entity-id discriminators (see `ids.js`) must include every field that can vary between two otherwise-similar entities (e.g. an edge's `dataElementIds`) — two edges over the same node pair carrying different payloads collided on id once before this was tightened; `flagship-fixture-semantics.test.js` now pins uniqueness of every id array as a regression guard. |

**Milestone 1, Sub-project A (field-identity engine core — design spike + intraprocedural, single-function only):**

| Module | Responsibility |
|---|---|
| `DESIGN_INTRAPROCEDURAL.md` | Design record: the field-identity state shape (`Map<accessPath, Set<dataElementId>>`, replacing boolean taint so FR-301's multi-label requirement holds), the exact reuse boundary against `scanner/src/dataflow/` (what's pure-reusable vs. must-be-reimplemented), and per-construct handling rules (object literals attribute each property to its own sub-path; template literals/string concatenation propagate identity normally, not as a widened/implicit flow; unresolved calls ARE flagged as widened). Read this before touching `field-identity.js` or `engine.js` — it's the binding reference both were built against. |
| `field-identity.js` | Pure state module: `emptyState`/`identitiesAt`/`addIdentity`/`removeIdentitiesAt`/`joinStates`/`statesEqual`/`hashState` over the `Map<path, Set<dataElementId>>` shape. Ancestor/descendant asymmetry (an ancestor's identity is visible when querying a descendant path; the reverse is never true) mirrors `dataflow/access-paths.js`'s `isCoveredBy` semantics — see the ADR §3 for why. Imports `pathIsCoveredByPrefix` from `dataflow/access-paths.js` (the one function from that package currently reused in practice; see this file's header for the full allowed-reuse list). Unit-tested in `test/lineage/field-identity.test.js`, including the FR-301 "two distinct fields coexist without merging" case. |
| `engine.js` | `resolveExprIdentities(state, expr)`: recursively resolves which data-element identities a parsed JS/TS expression carries — object literals attribute each property to its own dotted sub-path (the direct mechanism proving FR-301), arrays/binary/logical/ternary flatten conservatively, unresolved function calls are flagged `widened: true` rather than silently dropped or silently trusted. `analyzeFunctionFieldIdentity(fn, entryState)`: a forward-worklist CFG analysis over a single function, structurally mirroring `dataflow/engine.js`'s `analyzeFunction` (same fixed-point/join algorithm, entirely different state type — never imports or touches that file's taint state) — returns `{exitState, returnFacts, mutatedParams, widenings}`. No interprocedural resolution, no path DAG, no registry/graph-output wiring yet — see the ADR §5 for the explicit scope line. Unit-tested against hand-built fixtures in `test/lineage/engine-expr-resolver.test.js` and `test/lineage/engine-walker.test.js`, and against real parsed JS/TS source (via `scanner/src/ir/parser-js.js`) in `test/lineage/engine-integration.test.js`. |

## What is NOT here yet (later milestones / later sub-projects)

- Interprocedural summaries, the path DAG, source/sink registries,
  transformation-kind recognition, and any `DataFlowGraph v1` graph
  output — Milestone 1, Sub-projects B through H (see
  `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`).
  Sub-project A (above) is intraprocedural-only, by design.
- External destination resolution, database/queue field mapping,
  transit/at-rest/handling ANALYZERS (this package only defines the
  verdict *model*, not what decides a verdict) — Milestone 2.
- The local API/server and any UI — Milestone 3.
- Decision-intelligence extensions (stories, scenarios, snapshots/diffs,
  obligations, runtime twin, recipients, impact/remediation) —
  Milestones 4/5.

## Conventions

- Every enum here is a single source of truth for its concept. If you add
  a new node kind, mapping type, transform kind, etc., you MUST update
  three places: `schema.js` (or `protection.js`/`classification.js`),
  `dataflow-graph.schema.json`'s matching `enum` array, and
  `validate.js` if the new value needs a structural check —
  `json-schema-parity.test.js` fails loudly if the first two drift apart.
- Stable IDs are content hashes, not counters — see `ids.js`'s header.
  Never construct an id string by hand; always call the exported
  function, so a discriminator-shape change only has one call site to fix.
  Include every field that distinguishes two entities in the discriminator
  — omitting one (e.g. `dataElementIds` on an edge) produces a silent
  collision that `validateGraph()` currently cannot catch on its own.
- The flagship fixture is the ONE place fixture-specific facts (node
  names like "Payments Service", synthetic commit hashes, etc.) are
  allowed to live. No other module in this package — and per PRD Appendix
  D.1, no UI code in a later milestone — may special-case a fixture name.
  The generic hook is `graph.scope.source === 'fixture'`.
