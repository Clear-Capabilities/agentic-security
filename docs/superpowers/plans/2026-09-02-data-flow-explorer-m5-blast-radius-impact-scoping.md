# M5, Blast-Radius: Impact Assessment (FR-507, deliverable #4): scoping

Per the M5 top-level scoping doc's own deliverable #4 row: "Assess
impact" from a compromised entity, using already-shipped BFS traversal
plus already-shipped extension-contract aggregation. This document
grounds that claim against the real code before committing to a plan,
and draws the scope line explicitly against FR-507's own much larger
text (which also covers Remediation Command Center — this repo's own
M5 top-level doc splits that into a separate deliverable, #6, not
attempted here).

## What FR-507 actually asks for (full text, for the scope-line record)

> Provide "Assess impact" from a compromised or failing node, database,
> API, vendor, AI provider, credential, edge, control, finding, or data
> element. The impact engine traverses canonical graph relationships and
> reports: affected fields/classes, data subjects, applications,
> services, stores, logs, AI systems, recipients, subprocessors, and
> jurisdictions; upstream sources and downstream disclosures; affected
> policies and regulatory obligations; observed-versus-possible scope
> and coverage limitations; relevant owners, evidence, first/last
> observed times, and change provenance; configurable notification/
> contractual deadlines as planning prompts, never legal determinations.
>
> Impact views include a blast-radius graph, prioritized affected-flow
> table, executive summary, privacy/regulatory worksheet, and
> exportable evidence snapshot fixed to the incident graph digest.

This deliverable (#4) is the "impact engine" half only — the
computation, an extension contract, and a CLI/JSON export. The
"blast-radius graph"/"executive summary"/"privacy worksheet" VIEWS are
frontend rendering work, explicitly out of scope here, matching every
M4 decision-intelligence capability's own established backend-first
precedent (`dataflow diff`, `dataflow scenario apply` — both CLI/JSON/
Markdown only, no dedicated UI). "Remediation requirements" (work
items, verification, reopening, ticketing integrations) is FR-507's
OTHER half, split into the M5 top-level doc's own deliverable #6 —
untouched here. "Configurable notification/contractual deadlines" is
real, separate scope (a policy/config concern, not a graph-traversal
one) — disclosed as deferred, not built.

## What already exists (confirmed by direct read this session)

- **`frontend/src/lib/focus-controls.js`** — `showUpstream(graph,
  nodeId)`, `showDownstream(graph, nodeId)`, `showAllPaths(graph,
  nodeId)` (confirmed real, pure, already-tested BFS traversals,
  `frontend/test/focus-controls.test.js`) all return the identical
  `{nodeIds: Set<string>, edgeIds: Set<string>}` shape. `showAllPaths`
  is exactly "upstream sources and downstream disclosures" from a
  single starting node — FR-507's own first bullet. No taint-engine
  re-run, no IR access — pure graph-structure BFS over `graph.edges`.
- **The `scanner/src/` → `frontend/src/` cross-import precedent is
  real and already shipped**, confirmed by direct grep:
  `scanner/src/lineage/export-privacy.js:31` imports
  `computePrivacyViewModel` from
  `'../../../frontend/src/views/privacy-view.js'`. This deliverable's
  own new module reuses the identical pattern: import
  `showUpstream`/`showDownstream`/`showAllPaths` from
  `'../../../frontend/src/lib/focus-controls.js'`.
- **`RecipientProfile` (`recipient-profile.js`) carries a real
  `contributingGraphIds: string[]` field**, populated at graph-build
  time and already attached to the graph as `graph.recipientProfiles[]`
  (confirmed: `graph-builder.js:1011`). This is the exact membership-
  filter mechanic FR-507 needs for "affected recipients": given a
  traversal's `nodeIds` set, a `RecipientProfile` record is "affected"
  iff its own
  `contributingGraphIds` intersects that set. No new data acquisition,
  a pure array filter over already-shipped, already-populated arrays
  (when they exist on the graph — see the disclosed limitation below).
- **The `RecipientProfile` shape is the established extension-contract
  precedent this sub-project mirrors** (same as `Scenario` mirrored it
  for M5 3a): `validateX(record) -> {valid, errors}`, never throws;
  `xId(...)` object-argument ID minting in `ids.js`, mirroring
  `recipientProfileId`'s/`scenarioId`'s own pattern.
- **A real correction found this session, before writing the plan**:
  `ObligationMapping` (`obligation-mapping.js`) is NOT a stored
  `graph.obligationMappings[]` array the way `RecipientProfile` is.
  Confirmed by direct read of `obligation-predicates.js`: a record is
  built ON DEMAND per compliance-framework requirement via
  `buildObligationMappingFromGraphPredicate({framework,
  frameworkVersion, requirementId, ..., graph, evaluation})`, where
  `evaluation` itself comes from a separate
  `evaluateGraphFlowPredicate(spec, graph)` call keyed to one specific
  requirement's own declarative match spec — there is no "all
  obligations for this graph" array to filter by
  `contributingGraphIds`. Aggregating "affected policies and regulatory
  obligations" would require iterating every bundled compliance
  framework's own requirement specs and evaluating each one against the
  traversal's own subgraph — real, meaningfully larger integration work
  than a membership filter, not attempted in this first cut. **Ruling:
  `affectedObligationIds` is dropped from this sub-project's own scope
  entirely** — disclosed below under "Out of scope," not silently
  narrowed.
- **`dataElement.dataClasses`** (already real, already populated by
  `graph-builder.js`) is the source for "affected fields/classes" — a
  traversal's touched flows' own `dataElementIds` resolve to real
  `dataClasses` arrays, no new derivation needed.
- **`node.externality`/`node.subtype`/`node.kind`** are already real,
  already populated fields sufficient to bucket affected nodes into
  FR-507's own named categories ("applications, services, stores, logs,
  AI systems") — the same bucketing `inventory-view.js` (frontend,
  M3) already does over an identical node shape, confirmed by direct
  read of that file's own category dispatch table
  (`frontend/src/views/inventory-view.js`'s `TABLE_COMPUTE`).
- **"Data subjects" and "jurisdictions"** are NOT independently
  populated anywhere in this codebase today (confirmed: no
  `dataSubject`/`jurisdiction` field exists on any node/edge/flow in
  `dataflow-graph.schema.json`) — `RecipientProfile`'s own
  `processingCountries`/`dataResidencyCommitment` fields are the
  closest real proxy for "jurisdictions," reachable only via the same
  `contributingGraphIds` membership filter above. "Data subjects" has
  no real graph-level proxy at all — honestly reported as an empty/
  unavailable field, never fabricated, matching this codebase's
  own repeated "never fabricate an unmeasured number" discipline.
- **"Owners, evidence, first/last observed times, and change
  provenance"**: `graph.evidence[]` (already real, already populated,
  keyed by `evidenceRefs` on flows) supplies "evidence." No graph field
  today carries an "owner" or a "first/last observed" timestamp per
  node/edge (confirmed: not in `dataflow-graph.schema.json`) — both
  honestly reported as unavailable, not fabricated. "Change provenance"
  already exists as a SEPARATE, already-shipped capability
  (`posture/provenance/`, Finding Provenance) but is keyed to SAST
  findings, not graph entities — no real bridge exists between the two
  today; out of scope for this deliverable, named not built.

## The real design gap FR-507's own text creates: "observed-versus-possible scope"

FR-507 requires the impact report distinguish "observed" from
"possible" scope. This codebase's own real precedent for exactly this
distinction is `computeGraphDiff`'s `causeClassification` vocabulary
and — more directly on point — `OBLIGATION_FACT_TYPES`'s
`runtime_observed` value (real, cross-cutting, already real for
Digital Twin's own future deliverable #7). Since no runtime-
corroboration layer exists yet (Digital Twin, deliverable #7, is
unscoped), an Impact Assessment computed today has **no observed
data at all** — every result is `'possible'` by construction. This
mirrors FR-501's own documented precedent (Decision Story's factors
defaulted to a disclosed-limitation shape before their own
prerequisites shipped) — the same honest default applies here: the
`ImpactAssessment` record's own `scope` field is hardcoded
`'possible'` today, with a code comment naming Digital Twin (M5 #7) as
the future source of a real `'observed'` value, never silently
defaulted to a value implying more certainty than exists.

## Design

**The `ImpactAssessment` extension contract** (`impact-assessment.js`,
mirroring `recipient-profile.js`'s own file shape — schema/enums/
validator, zero graph access at construction time, matching every
prior M4/M5 extension-contract module):

```
{
  id, version, graphId, graphDigest,
  targetId,          // the canonical id the assessment starts from —
                      // node:*, edge:*, flow:*, data:* (a data element),
                      // or finding:* is explicitly OUT (findings are
                      // not graph entities — see Out of scope)
  targetKind,         // 'node' | 'edge' | 'flow' | 'dataElement'
  scope,              // always 'possible' today — see design gap above
  affectedNodeIds, affectedEdgeIds,      // from showAllPaths
  affectedDataClasses,                    // dataClasses touching the
                                            // affected flow set
  affectedRecipientProfileIds,            // contributingGraphIds
                                            // membership filter over
                                            // graph.recipientProfiles[]
                                            // (no affectedObligationIds
                                            // field — see the design
                                            // gap on ObligationMapping,
                                            // above, and Out of scope)
  coverageLimitations,                    // honest, non-empty when the
                                            // graph's own coverage
                                            // ledger shows gaps in the
                                            // affected subgraph
  generatedAt,
}
```

**`computeImpactAssessment(graph, targetId, opts)`**
(`impact-assessment.js`): resolves `targetId`'s kind, runs
`showAllPaths` (imported from `frontend/src/lib/focus-controls.js`,
the established cross-import precedent) from every node the target
kind resolves to (a `node:*` target is one node; an `edge:*`/`flow:*`
target resolves to its own `from`/`to` or `source`/`sink` node(s); a
`data:*` target resolves to every node any flow carrying that data
element touches), unions the results, then:
- filters `graph.dataElements` to those referenced by any flow whose
  `edgeIds` intersects the affected edge set → `affectedDataClasses`
  (deduplicated `dataClasses` union)
- filters `graph.recipientProfiles ?? []` by `contributingGraphIds`
  intersecting `affectedNodeIds` → `affectedRecipientProfileIds`
- pulls `coverageLimitations` from `graph.coverage` for only the
  affected node/edge subset (reusing `coverage.js`'s already-shipped
  per-language tier data, scoped down — a filter, not new
  computation)

**No new operation catalog, no clone-and-override.** Unlike Scenario
(3a), Impact Assessment never mutates or hypothesizes — it is a pure
read/aggregate over the REAL, already-scanned graph. This is a
materially simpler shape than 3a's own engine.

**CLI**: `agentic-security dataflow impact assess [path] --target
<canonical-id> --output <file> [--format json|markdown]`, mirroring
`dataflow scenario apply`'s own CLI shape and `loadSignedGraph`
loader/error-message contract exactly (0/1/2 exit codes).

## Global constraints for the implementation plan

- No frontend/UI work — CLI/JSON/Markdown export only, matching every
  M4/M5 backend-first precedent.
- `scope` is always `'possible'` — never fabricate an `'observed'`
  value; the field exists now so a future Digital Twin (M5 #7)
  increment can populate it without a breaking schema change.
- `targetKind` accepts `node`/`edge`/`flow`/`dataElement` only —
  `finding:*` targets are explicitly out (findings are SAST-layer
  objects with no stable graph-entity id; "compromised finding" from
  FR-507's own text is read as "the flow/node the finding's own sink
  resolves to," a mapping this deliverable does not attempt to build).
- `affectedRecipientProfileIds` degrades honestly to `[]` when
  `graph.recipientProfiles` doesn't exist on the graph at all (an
  optional extension array, not a core `DataFlowGraph v1` field) —
  never an error.
- No new npm dependency.
- Every new module follows this package's own established precedent:
  `validateImpactAssessment(record) -> {valid, errors}`, never throws;
  `impactAssessmentId(...)` object-argument ID minting in `ids.js`.

## Out of scope (disclosed, not built)

- The blast-radius GRAPH view, prioritized affected-flow TABLE,
  executive summary, and privacy/regulatory worksheet — all frontend
  rendering, FR-507's own §"Impact views" clause.
- Remediation Command Center (work items, verification, reopening,
  ticketing integrations) — M5 top-level deliverable #6, a separate
  sub-project.
- Configurable notification/contractual deadlines.
- `finding:*` targets (see constraint above).
- **"Affected policies and regulatory obligations"** — no
  `affectedObligationIds` field. `ObligationMapping` records are built
  on demand, per compliance-framework requirement, via
  `buildObligationMappingFromGraphPredicate`/
  `evaluateGraphFlowPredicate` — there is no stored
  `graph.obligationMappings[]` array to filter the way
  `graph.recipientProfiles[]` exists for recipients. Aggregating this
  would mean iterating every bundled framework's own requirement specs
  and evaluating each against the affected subgraph — real, separate,
  meaningfully larger integration work, not attempted here.
- "Data subjects" and "owner"/"first observed"/"last observed" per
  entity — no real graph field exists for any of these today; reported
  as absent, not fabricated, not built around.
- Change provenance bridging to `posture/provenance/` — no real
  connection between SAST-finding provenance and graph entities exists
  today; a real, separate future increment.
- Exportable evidence snapshot "fixed to the incident graph digest" —
  the JSON export IS fixed to the graph it was computed against (via
  `graphDigest`, reusing `computeGraphDigest` per this session's own
  established convention from M5 3a's own I4 finding/fix), but a
  dedicated signed "incident snapshot" artifact beyond the plain JSON
  export is not built — `agentic-security attest` already exists for
  signed evidence bundles generally; wiring impact assessments into it
  is real, separate, disclosed future scope.
