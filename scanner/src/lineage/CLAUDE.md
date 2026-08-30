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

## What's here (Milestone 0 — contract and fixture only)

| Module | Responsibility |
|---|---|
| `schema.js` | Envelope shape, `SCHEMA_VERSION`, node/mapping/transform/coverage/policy/evidence enums |
| `ids.js` | Deterministic stable-ID functions (`nodeId`, `edgeId`, `dataElementId`, `flowId`, `transformationId`, `evidenceId`, `graphId`) — sha256-over-canonicalized-material, same shape as `posture/stable-id.js`'s finding IDs |
| `protection.js` | Protection verdict model: `PROTECTION_VERDICTS` × `EVIDENCE_GRADES` per dimension (`transit`/`atRest`/`handling`), plus `aggregateVerdicts()`'s risk-precedence reduction (PRD 8.4) |
| `classification.js` | Data classes (reuses `dataflow/privacy-taxonomy.js` + adds `CONFIDENTIAL`) and the 15 AI processing contexts (PRD 9.2) — AI is modeled as orthogonal to data class, never a mutually-exclusive label |
| `validate.js` | Hand-rolled structural validator (`validateGraph`) — no new npm dependency; `dataflow-graph.schema.json` is the JSON-Schema-dialect twin, kept in parity by `test/lineage/json-schema-parity.test.js`. Checks id-prefix format (regex per entity kind), every risk-bearing enum (`node.kind`, `node.externality.value`, `node.coverageStatus`, `dataElement.dataClasses`/`.aiContexts` array *contents*, `edge.protocol.destinationResolution`, `flow.policyVerdict`/`.protectionSummary`, `transformation.kind`/`.reversibility`, `evidence.evidenceType`, `graph.scope.source`) against `schema.js`/`classification.js`, not just array/field presence — each gap was closed after an initial pass let a made-up value validate cleanly (see git history on `validate.js`). Also checks duplicate-id uniqueness across the four top-level entity arrays (nodes/edges/dataElements/flows) — a real gap until it was closed alongside the enum gaps above. |
| `dataflow-graph.schema.json` | Authoritative JSON Schema (2020-12) document for external interop/documentation |
| `fixtures/build-flagship-fixture.mjs` | Deterministic generator for the payments-platform reference fixture (PRD Appendix D.2/D.3) — re-run and re-commit `flagship-graph.json` if you change the generator; a diff test (`flagship-fixture.test.js`) enforces idempotence. Entity-id discriminators (see `ids.js`) must include every field that can vary between two otherwise-similar entities (e.g. an edge's `dataElementIds`) — two edges over the same node pair carrying different payloads collided on id once before this was tightened; `flagship-fixture-semantics.test.js` now pins uniqueness of every id array as a regression guard. |

## What is NOT here yet (later milestones)

- The actual lineage-tracking engine (source/sink registries, worklist,
  interprocedural summaries, path DAG) — Milestone 1 (DFG-004, DFG-005).
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
