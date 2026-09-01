# Milestone 2, Sub-project F scoping: cross-boundary normalization (FR-304)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row F: *"Reclassifies `cross-lang-openapi.js`/`cross-lang-grpc.js`/
`cross-lang-graphql.js`'s existing, conservative (ambiguous-match-abstains)
endpoint-correlation mechanism into edges carrying an explicit
code-derived/schema-derived/manually-declared/runtime-corroborated
provenance tag, per FR-304's own text."* FR-304's exact text (PRD §13):
*"Reuse and normalize evidence from OpenAPI, gRPC, GraphQL, ORM, queues,
and the declared service graph. Cross-repository or federated edges may be
declared or imported, but the graph must identify whether an edge is
code-derived, schema-derived, manually declared, or runtime-corroborated."*

**This document CORRECTS the parent scoping doc's framing, the same way
Sub-project E's and my own Sub-project B scoping did**: the "reclassifies
[...] existing [...] mechanism" language undersells what's actually
needed. Direct investigation (below) found the three `cross-lang-*`
modules produce SAST chain-`Finding` objects, structurally unrelated to
`DataFlowGraph v1` edges, and — more importantly — **all three abstain
entirely unless BOTH a code call site and a schema/contract match already
exist**, so none of them is a source of a genuinely schema-derived,
manually-declared, or runtime-corroborated EDGE (an edge with no backing
code call site at all). Bridging them into the lineage graph is real,
new, Large work, not a reclassification.

## What already exists (confirmed by direct read, this session, HEAD `1975a008`)

- `scanner/src/posture/cross-lang-openapi.js`, `cross-lang-grpc.js`,
  `cross-lang-graphql.js` are in `posture/`, entirely separate from
  `scanner/src/lineage/` — never imported by `graph-builder.js` or
  `schema.js`. Each requires BOTH sides of a correlation to already exist
  in code before emitting anything:
  - `cross-lang-openapi.js`: `scanCrossLangOpenAPI` returns `[]` when
    `callers.length === 0` or `handlers.length === 0`; additionally only
    fires when the matched server file already carries an existing
    high/critical SAST finding (`if (!fs.length) continue`).
  - `cross-lang-grpc.js`: same shape, `if (clients.length === 0) return
    []` / `if (servers.length === 0) return []`.
  - `cross-lang-graphql.js`: same shape for resolvers/client queries.
  - All three emit a chain-`Finding` (`id, file, line, vuln, severity,
    cwe, ..., cross_language: true, chain: [...]`) — never a graph
    node/edge. **None of them ever fires for a schema-declared endpoint
    with no code caller in this repo** — confirmed by the early-return
    guards above, re-verify against the current file before trusting line
    numbers.
- `schema.js` has **no field anywhere** representing "how was this
  edge/node discovered." `edge.protocol.destinationResolution`
  (`DESTINATION_RESOLUTION_VALUES`) is about whether the destination
  EXPRESSION resolved (literal/dynamic/unknown) — a different axis
  entirely, unrelated to provenance. `MAPPING_TYPES`
  (`edge.fieldMappings[].mappingType`) describes a data transformation
  SHAPE (identity/rename/projection/...) — also unrelated, confirmed by
  direct read.
- `graph.evidence[]` (`EVIDENCE_TYPES = ['code', 'ir', 'configuration',
  'iac', 'schema', 'service_declaration', 'policy', 'manual', 'runtime']`)
  is graph-level, referenced via `flow.evidenceRefs` — its only live
  producer today is Sub-project G1's `evidenceType: 'policy'` entries
  (just merged, commit `a1791c35`). It answers "why is this flow
  permitted," not "how was this edge discovered" — a graph-level array
  keyed off a FLOW is the wrong shape for a per-EDGE provenance tag
  anyway (an edge can be referenced by multiple flows).
- **Every edge `buildDataFlowGraph` mints today is code-derived, 100%,
  with no exception** — seeding is exclusively `planSeeds(callGraph,
  ...)` walking real parsed CFG expressions, sink enumeration is
  exclusively `enumerateSinkSites(callGraph)` walking real CFG call
  nodes. The `opts.resolveSiteDecision`/`opts.resolveDestination`/
  `opts.resolveTransitProtection`/`opts.privacySinkPolicy` hooks all
  operate on a `site` already discovered from real code — none can inject
  a node/edge with no backing call site. **No "declared", "manual", or
  "import a graph fragment" mechanism exists anywhere in
  `scanner/src/lineage/`** — confirmed by a full-tree grep for `service
  graph|service map|declared service|serviceGraph`.
- `SOURCE_CATEGORIES`/`SINK_CATEGORIES` already reserve a `'declared'`
  value, and `DESTINATION_RESOLUTION_VALUES` already reserves
  `'declared_service'`/`'runtime_corroborated'` — vocabulary-complete,
  mechanism-absent: `source-registry.js`/`sink-registry.js` map
  `'declared'` only as inert static table entries, never actually
  produced by anything.
- `DESIGN_DESTINATION_RESOLVER.md` already names this exact gap as
  foreseen-but-deferred: `resolved_from_schema`/`declared_service` need
  "schema correlation or an operator-declared service registry; plausibly
  a later Sub-project A increment, or Sub-projects E/F's own
  schema-correlation work" — confirming F's genuinely-new half was
  anticipated, not newly discovered here.
- `edge.boundaryCrossings` (always `[]` today, an honest Milestone-1
  default per `graph-builder.js:673`) is a DIFFERENT, unrelated field —
  the PRD's own worked example (`AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`
  line 848) shows `["trust-zone:external"]`, a trust-zone/boundary LABEL
  list, not a discovery-provenance tag. Out of scope for F, named here
  only so it is not confused with what F actually builds.
- **Naming collision, disclosed so it is never confused in later
  documents**: Milestone 1's own exit-gate table also has a "Sub-project
  F" (the JS/TS benchmark corpus under `bench/data-lineage/`, already
  shipped) — a completely different, already-complete piece of work. This
  document is Milestone 2's Sub-project F only.
- **No exit-gate AC exercises FR-304 directly.** The Milestone 2 exit gate
  (PRD §15, confirmed by direct read) is "AC-03 through AC-09 and AC-12;
  false-protected release gate passes" — FR-304/Sub-project F is real
  in-scope PRD work but not a blocker for the Milestone 2 exit gate the
  way G (AC-09) or B/C/D (AC-03/04/06/12) were. This lowers this
  sub-project's urgency relative to H/I (which DO gate the exit), not its
  legitimacy — the PRD still calls for it.

## Recommended split (mirrors the C1/C2/C3 precedent exactly)

FR-304 names four provenance categories. Only ONE of them
(`code-derived`) has a real, existing mechanism to wire up — the other
three (`schema-derived`, `manually-declared`, `runtime-corroborated`)
have zero producers anywhere in the codebase today. Splitting accordingly:

**F1 (Small, this document recommends starting here) — add the missing
vocabulary + tag every edge honestly.**
- New `EDGE_PROVENANCE_VALUES` in `schema.js` — a **small, dedicated
  4-value array** (`['code', 'schema', 'manual', 'runtime']`), documented
  as deliberately value-aligned with (but a distinct field from)
  `EVIDENCE_TYPES` — reusing the same four spellings avoids inventing a
  second, drifting vocabulary for the same four concepts, satisfying
  `CLAUDE.md`'s own "every enum is a single source of truth" convention
  as closely as two genuinely different fields (a per-edge tag vs. a
  graph-level evidence-record type) can. **Naming decision, not yet
  finalized — confirm before implementing**: `'manually declared'` in
  FR-304's prose maps most naturally to `EVIDENCE_TYPES`'s existing
  `'manual'` value, not `'service_declaration'` (which reads as a
  narrower, service-graph-specific case FR-304 itself distinguishes with
  "declared or imported" — worth a second look at F2 time, when a real
  declared-service-graph producer exists to test the distinction
  against; F1 only needs `'code'` to be reachable).
- `graph-builder.js`: at the same edge-construction block that already
  sets `edge.protocol` (`graph-builder.js:672`, re-verify against current
  line numbers), add `edge.provenance = 'code'` unconditionally — honest,
  since 100% of today's edges are code-derived, confirmed above.
- `validate.js`: `_validateEdge` gains an `EDGE_PROVENANCE_VALUES
  .includes(edge.provenance)` check, mirroring the existing
  `destinationResolution` check immediately above it.
- `dataflow-graph.schema.json`: matching `enum` addition on the edge
  `$defs`, kept in parity by the existing `json-schema-parity.test.js`
  pattern (extend it, following `destinationResolution`'s own pinned
  test as the template).
- Tests: every edge from a real fixture reads `provenance: 'code'`
  (positive proof); an explicit completeness-accounting test documenting
  `'schema'`/`'manual'`/`'runtime'` as valid-but-currently-unreachable
  from any real `graph-builder.js` output (mirroring Sub-project C1's own
  `'aggregated'`-is-unreachable precedent) — this is NOT a vacuous test,
  it is the honest disclosure that F2/F3 have not shipped yet, pinned so
  a future increment's own test suite must update this exact assertion
  when it changes that.
- This closes only the FIRST clause of FR-304 ("the graph must identify
  whether an edge is code-derived...") — it does NOT touch "reuse and
  normalize evidence from OpenAPI, gRPC, GraphQL... the declared service
  graph" or "cross-repository or federated edges may be declared or
  imported," both of which remain genuinely unbuilt after F1.

**F2 (Large, deferred, its own future scoping pass) — bridge
`cross-lang-openapi/grpc/graphql.js`'s already-parsed contract data into
real `schema`-provenance graph edges.** Real, new graph-building work: a
site that only matches a schema endpoint (no code caller in THIS repo, or
a caller in a different repo) needs a node/edge-minting path that doesn't
originate from `callGraph`/`PathStore` at all — the reuse boundary these
three parsers currently sit behind (SAST chain-finding) has never been
drawn toward the lineage package before. Sizing and staffing this
honestly requires its own scoping pass, not estimated further here.

**F3 (Large, deferred, its own future scoping pass) — an
operator-declared-service-graph ingestion mechanism**, closing FR-304's
"manually declared" and (partially) "cross-repository or federated"
clauses. No existing precedent inside `lineage/` — the closest analog is
`posture/provenance/repo-lineage.js`'s "operator-declared, locally
verified, no remote fetch" pattern (a DIFFERENT subsystem — Finding
Provenance, not Data Flow Explorer), worth reading as a design precedent
when this is scoped, not reused directly.

## What this does NOT do (F1's own boundary)

`edge.boundaryCrossings` (a different, still-unimplemented field, named
above only to avoid confusion). ORM/queue provenance — already
lineage-native via `orm-write-catalog.js`/`privacy-catalog.js`
(Sub-project E), not part of FR-304's remaining gap. `'declared_service'`/
`'runtime_corroborated'` on `edge.protocol.destinationResolution` — a
DIFFERENT field (destination-expression resolution, Sub-project A's own
territory), not this sub-project's to populate even though the strings
sound similar. Any language beyond JS/TS (unchanged, this package's
existing scope boundary throughout).

## Recommended next step

Write F1's implementation plan following this scoping — small, low-risk,
honest, and it unblocks F2/F3 by giving them a real field to populate
rather than requiring them to invent the schema addition too.
