# Milestone 5 — Simulation, continuous corroboration, remediation, and scale: top-level scoping

Per PRD §26's own Milestone 5 deliverable list: every additional language
that passes the common gate; large-graph projections and performance
work; What-If Architecture Simulator (FR-502); Runtime-Corroborated
Digital Twin (FR-505); Blast-Radius and Remediation Command Center
(FR-507); cross-repository/federated graph import; governance editing
workflow with validated, reviewable writes. Exit gate: AC-26, AC-29, and
AC-31 plus all declared language/performance/accuracy/privacy thresholds
pass with published limitations.

**This document does not build anything.** It maps the 7 deliverables
into sized sub-projects with real dependencies, confirmed against the
actual current codebase (not assumed) via five parallel investigation
passes, so each sub-project can get its own scoping+plan via the same SDD
process used for M0-M4. This mirrors the M4 top-level scoping doc's own
method and rigor exactly.

## What already exists (confirmed by direct read this session)

- **Nine languages have real IR-to-lineage wiring** (JS/TS, Python, Java,
  Go, Ruby, PHP, C#, Kotlin, C/C++) — none from zero. Four more
  (rust/solidity/swift/dart) have tree-sitter grammar loading wired into
  SAST pattern-matching only (`sast/tree-sitter-sinks.js`), with **zero**
  lineage/taint wiring — genuinely new-language territory for the
  Explorer starts at these four, not at nine.
- **Large-graph client-side rendering is already built and measured**,
  not merely estimated: M3-Render (2026-09-01) proved 148ms first paint
  and ~53 FPS pan/zoom at the PRD's own 5,000-node/10,000-edge reference
  scale via `architecture-view.js`'s real clustering
  (`computeClusteredLayout`/`aggregateEdgesForClusters`), confirmed with
  real Chrome Performance-API measurements, not a JS-timer estimate.
- **No server- or worker-side graph pagination exists anywhere.**
  `server/routes.js`'s own comment ("No pagination/filtering in S1")
  and `mcp/dataflow-tools.js`'s own header comment both already disclose
  this gap in isolation; neither has been connected to M5's "large-graph
  projections" text before now. The whole graph is always transferred
  before any client-side clustering can help.
- **True semantic zoom (field/call-site-level detail) is CONFIRMED
  BLOCKED**, already investigated by the M3-Render/SemanticZoom
  sub-project: `node.location` is unconditionally `null` and no
  finer-grained-than-category node identity exists in the schema. This
  needs its own backend node-identity redesign before any UI work, and is
  explicitly out of this milestone's reasonable scope until that
  prerequisite is deliberately scoped on its own.
- **`protection.js`'s `aggregateVerdicts` and `privacy-sink-policy.js`'s
  `isSinkPermitted` are pure functions**, zero graph-pipeline
  entanglement — directly reusable for What-If Simulator's "recompute a
  verdict under a hypothetical" requirement via a clone-and-override
  design that mirrors an already-shipped precedent (`graph-builder.js`'s
  own Sub-project D2/C1 "mutate an already-minted entity in a later
  pass"). `handling-analyzer.js`'s `classifyHandling` is **not**
  similarly reusable — it needs a real reconstructed path, not a
  synthesizable one.
- **`OBLIGATION_FACT_TYPES` already includes `'hypothetical'`**, unused
  by any current producer — What-If Simulator would be the first real
  producer, the second cross-import of this §10.10 vocabulary after
  `RecipientProfile`. `EVIDENCE_GRADES` (a different, protection-specific
  enum) has **no** `'assumed'` value despite FR-502's own text requiring
  "assumed evidence" — a real, small gap needing a deliberate ruling
  (add `'assumed'`, or map onto the existing `'declared'` grade).
- **IaC scanning (`sast/iac-terraform.js`, `iac-cloud-templates.js`,
  `posture/iac-reachability.js`) and a real operator-declared
  service-topology file (`dataflow/cross-service-taint.js`'s
  `.agentic-security/services.yml`) both exist and work today, with
  zero bridge into `DataFlowGraph v1`** (confirmed by grep — no
  reference from `lineage/` to either). This is real, already-shipped
  signal for Digital Twin's CONFIG DECLARED layer, not a from-scratch
  data-acquisition problem.
- **`posture/runtime-correlation.js` is a real, working, offline
  JSONL-trace-file correlation module** — proof this codebase can and
  does ship "external evidence arrives as a file, never live ingestion"
  safely. It correlates against SAST finding qids in a code-execution
  shape, not canonical graph IDs in a destination/network shape — a
  pattern to adapt, not reuse verbatim, for Digital Twin's RUNTIME
  OBSERVED layer. Zero real OpenTelemetry integration exists anywhere.
- **`frontend/src/lib/focus-controls.js`'s nine traversal functions
  (`showUpstream`/`showDownstream`/`showAllPaths`/etc.) are pure,
  zero-DOM, already-tested BFS traversals** — exactly Blast-Radius's
  core "upstream sources and downstream disclosures" mechanic. A real,
  already-shipped precedent for a backend module importing directly from
  `frontend/src/` exists (`lineage/export-privacy.js`'s own
  `computePrivacyViewModel` import, DPIA/RoPA sub-project) — no porting
  needed.
- **`posture/provenance/lifecycle.js`'s append-only, per-key,
  file-locked event-log pattern is a strong, battle-tested structural
  precedent for `RemediationItem`'s own "state changes are append-only
  audit events" requirement** — a materially closer match than
  `posture/fix-history.js`'s flat mutable-status log.
- **Already-shipped `GraphDiff`/`drift-policy.js` (M4 #8) is directly
  reusable for remediation verification** ("did this flow actually get
  fixed, or did the analyzer just re-key it") — the same
  `causeClassification` machinery that made FR-501's `changeRecency`
  factor real.
- **Canonical IDs are deliberately repository-scoped, not
  cross-repo-safe.** `ids.js`'s own header states IDs are "stable within
  the repository/commit"; `nodeId`/`edgeId`/`flowId`/`dataElementId`
  never include `repository` in their discriminator. Two structurally
  identical nodes in two different repos mint the byte-identical id —
  naive graph-merging would silently collide. `graphId` itself IS
  repo-scoped, and `RecipientProfile`'s own id already prevents
  cross-graph collision (by design: same real-world recipient in two
  repos mints two separate, non-deduped records today — the safe
  failure mode, but zero automatic cross-org consolidation).
- **PRD backlog priorities are real signal the §26 bullet list doesn't
  show**: cross-repo federation is `DFG-025`, explicitly **P2** (lowest
  tier) and framed as "declared or imported" edges (FR-304), not
  automatic graph merging. Governance-editing-workflow is `DFG-023`,
  **P1**, and the PRD's own backlog names an undefined **"secure write
  service"** as a separate dependency — the PRD authors themselves
  flagged this as unresolved design, not settled. `DFG-041`
  (Blast-Radius) partially depends on `DFG-023` — a real cross-deliverable
  ordering signal.
- **Every existing product surface is read-only w.r.t. graph/governance
  data**, with exactly two exceptions (`apply_fix`/`apply_sca_upgrade`,
  both source-file writes validated by re-running tests — a pattern that
  does not transfer to governance data). `server/http-server.js`'s
  route table is 100% `GET` — zero POST/PUT/PATCH/DELETE routes exist
  anywhere. `recipient-profiles.json` (FR-506, just shipped) is
  today's only real governance-editing mechanism, and it's a hand-edited
  config file with no in-product UI, diff, review, or approval gate —
  real reusable validation logic, zero write-workflow infrastructure.

## The 7 deliverables, sized and ordered by real dependency

| # | Deliverable | Size | Depends on | Why |
|---|---|---|---|---|
| 1 | Language coverage — "every additional language passes the common gate" | Small–Medium — **COMPLETE, 2026-09-02** | none | Major scoping correction found this session: PRD §22.3 requires ≥85% field-to-sink recall to be "supported." Real current numbers (`docs/METRICS.md`) top out at Python 66%, down to C/C++ 18% — **zero of the 9 existing languages currently clear the bar**. Ruled (b): built the genuinely unbuilt, Explorer-specific per-language coverage-tier disclosure UI PRD §22.1 explicitly allows ("may display partial inventories... but must label the coverage tier"), rather than re-running the separately-tracked taint-recall initiative (cited, not duplicated). Shipped: `scanner/src/lineage/language-coverage-tiers.js` (13 curated entries — 9 lineage-wired languages at `tier: 'partial'` with real `docs/METRICS.md` recall numbers, 4 tree-sitter-pattern-only languages at `tier: 'pattern-only'` with no fabricated recall), a new `LANGUAGE_COVERAGE_TIER_VALUES` enum (`schema.js`), wiring into `coverage.js`'s already-real, already-populated `graph.coverage.languages[]` ledger, and a new `dataflow export --format coverage` CLI mode. The "never fabricate a number" property was traced end-to-end by the final whole-branch review with no gap found. A genuinely NEW language (rust/solidity/swift/dart, currently zero lineage wiring) remains **Large per language** based on the Go/Ruby/PHP/Kotlin build history and stays its own separate, ongoing initiative, not part of this deliverable's shipped scope. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-lang-coverage-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation and implementation detail. |
| 2 | Large-graph projections and performance work | **Medium — item (a) COMPLETE, 2026-09-02; (b) still open; (c) confirmed out of scope** | none | More mature than the PRD text suggests: the hardest, highest-uncertainty piece (does clustering/rendering hold at the reference scale) is already done and measured (148ms paint, ~53 FPS at 5,000/10,000). Three real pieces of remaining work were named, none speculative — status per piece: **(a) SHIPPED**: `POST /api/v1/query` on the `explore` server (the already-named-but-never-built S2 endpoint) plus the same filter capability added to the MCP `dataflow_get_graph` tool, both reusing one real, newly-extracted shared primitive (`export-json.js`'s `validateFilterShape` + the already-shipped `_filterGraph`) — closes the "whole graph always transferred" gap disclosed in two separate places in the code for a caller that supplies a filter; an unfiltered call still returns everything inline, disclosed as real, deferred scope, not a forced-offload backstop. A final whole-branch review found and a same-day fix round closed a real Important finding: `filter: {}` had been falsely documented (in three places, plus one vacuous test) as behaving like "no filter" — it actually narrows to an EMPTY graph, since `_filterGraph` defaults both `nodeIds`/`edgeIds` to empty Sets; the MCP tool's own agent-facing description now carries an explicit warning, the most trust-sensitive of the three surfaces. **(b) NOT YET DONE**: a stress-test pass (not necessarily a build) for Privacy/Trace/Inventory's HTML-table views at scale, explicitly never measured — deliberately out of this sub-project's own scope, a real, separate follow-up. **(c) confirmed OUT OF SCOPE**: true semantic zoom stays blocked on a backend node-identity redesign, not attempted here. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-graph-pagination-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation and fix-round detail. |
| 3 | What-If Architecture Simulator (FR-502) | **Large — split into 2 → 3a COMPLETE, 2026-09-02; 3b still deferred** | none (all reused machinery is already shipped: M2 protection/policy pure functions, `OBLIGATION_FACT_TYPES`) | **3a SHIPPED**: `scenario.js` (the `Scenario` §10.10 contract — `SCENARIO_OPERATION_KINDS`, `validateScenario`), `scenario-engine.js` (`applyScenario` — clone-and-override, 6 operation kinds: `require_transit_protection`, `apply_handling`, `remove_entity`, `replace_recipient_fact`, `change_storage_fact`, `change_governance_fact`), `scenario-diff.js` (`diffScenarioGraph`, deliberately NOT a reuse of `computeGraphDiff` — that function's reidentification/`causeClassification` machinery is shaped for a real rescan across commits, not a declared hypothetical, a real scoping correction found mid-implementation), and a CLI verb `dataflow scenario apply`. Ruled `EVIDENCE_GRADES` gains `'assumed'` (same axis as the existing grades, unlike `flow-grade.js`'s deliberately separate `FLOW_EVIDENCE_GRADES` vocabulary) rather than reusing `'declared'`. The final whole-branch review found and a same-day fix round closed a real Blocking finding: `replace_recipient_fact` overrode a node's `destination` but left the `edge.protection.transit` verdict DERIVED from that same field stale — a scenario swapping an `https://` destination for `http://` kept a real `code`-graded `'protected'` verdict, a false-protected result exactly the class `bench/protection-verdict/` gates. Fixed by resetting the derived verdict to an honest `not_assessed`/`none` rather than re-deriving (re-deriving needs IR-level data unavailable post-build) or leaving it stale. Three further Important findings (a `recipientProfiles[]` cascade gap on node removal, caller-object aliasing across 3 appliers, a CLI-minted scenario id/digest that carried no real content information) were also found and fixed the same pass, independently re-verified by a second review round. Two disclosed, not-fixed limitations remain, both cheap future scope: `flow.protectionSummary`'s cross-dimension aggregation can mask a per-edge demotion when a second dimension is also set `'protected'` in the same scenario (the per-edge field itself, and the delta report, both stay honest); and the `recipientProfiles[]` cascade is real mutation `diffScenarioGraph` doesn't yet report. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-whatif-simulator-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, fix-round, and re-review detail. **3b (synthetic node/edge insertion — "insert a gateway/trust boundary/DLP control/queue") remains NOT STARTED**: every node/edge in this codebase today derives from a real registry decision or real call site; synthesizing one has zero precedent anywhere, and 3a's own implementation confirmed no shortcut emerged — a real candidate for its own separately scoped investigation, possibly ending in an honest "not supported" deferral. |
| 4 | Blast-Radius: Impact Assessment half of FR-507 | **Medium** | none (reuses only already-shipped M3/M4 work) | `focus-controls.js`'s `showUpstream`/`showDownstream`/`showAllPaths` are real, pure, already-tested BFS traversals — exactly this deliverable's core mechanic — and there is already a real, proven precedent for a `scanner/src/` module importing directly from `frontend/src/` (`export-privacy.js`'s own `computePrivacyViewModel` import). Aggregating which `RecipientProfile`/`ObligationMapping` records attach to a traversal's result set is a membership-filter over already-shipped arrays, not new data acquisition. Real new work: the `ImpactAssessment` extension contract itself (mirror `RecipientProfile`'s shape), a new CLI verb, and an honestly `possible`-only observed/possible partition until FR-505 exists (same disclosed-limitation pattern FR-501's own factors used before their own prerequisites shipped). |
| 5 | Governance editing workflow with validated, reviewable writes | **Large, genuinely the riskiest single item in Milestone 5** | none directly, but should land BEFORE item 6's remediation half per a real PRD backlog signal (`DFG-041` partially depends on `DFG-023`) | The PRD's own backlog already flags this as unresolved design (`DFG-023`'s undefined "secure write service" dependency, not just an oversight in the FR-5xx prose). This is the FIRST genuinely interactive, human-in-the-loop write surface this entire product would ever have for governance/graph-shaped data — every existing write precedent (`apply_fix`/`apply_sca_upgrade`) is shaped around re-running tests as validation, which does not transfer. `server/http-server.js`'s route table is 100% GET today; a write path needs new routes, a new CSRF-safe-POST story beyond the existing (currently unused) request-size cap, and new audit logging — real, novel, security-sensitive engineering, not wiring existing pieces together. Real reuse opportunity for a first cut: `recipient-profiles.json` (FR-506) is already a crude, hand-edited governance-editing mechanism with real, tested validation logic (`validateRecipientProfile`/`_isValidRecipientConfigEntry`) — a first cut could plausibly be "add an in-product validate/diff/review/approve UI on top of this same config file and its own validators" rather than inventing a new data model from scratch. Recommend its own dedicated scoping investigation before any plan, and recommend splitting like FR-504's 6a/6b/6c given the real novelty here. |
| 6 | Blast-Radius: Remediation Command Center half of FR-507 | **Large** | item 4 (Impact Assessment — a remediation item's own "linked assessment" field needs it to exist first) + already-shipped `GraphDiff`/`drift-policy.js` (verification) + ideally item 5's write-service pattern, per the real `DFG-041`→`DFG-023` backlog dependency | `posture/provenance/lifecycle.js`'s append-only, per-key, file-locked event-log pattern is a strong structural precedent for `RemediationItem`'s own "state changes are append-only audit events" rule — a materially closer match than `fix-history.js`'s flat mutable-status log, though genuinely new fields (owner, due date, approvals/exceptions) still need inventing. Verification ("did this actually get fixed") should be built as a consumer of the already-shipped `GraphDiff`/`drift-policy.js` engine, not new comparison logic — the same reuse discipline that made FR-501's `changeRecency` factor real. FR-505 (Digital Twin) is a real but explicitly optional second verification input per AC-31's own "or" phrasing — not a hard prerequisite. External ticketing/GRC integration is explicitly optional per the PRD text; recommend deferring entirely for a first cut, local work items only, matching this session's established local-first pattern. `.agentic-security/`'s existing JSON-ledger conventions (`lifecycle.json`, `fix-history/log.json`) are the right storage precedent to mirror structurally, not literally. |
| 7 | Runtime-Corroborated Digital Twin (FR-505) | **Large — split into 2** | none directly; recommend landing near item 3 (What-If) to share the `OBLIGATION_FACT_TYPES` vocabulary (`runtime_observed` is FR-505's own fact type, already real/cross-cutting) with minimal churn — soft, not hard, dependency | Not blocked the way FR-506 initially looked — real underlying signal exists for both halves, just disconnected from the graph, closer to FR-501/FR-503's own shape than FR-506's "weakest data foundation" one. Split: **7a CONFIG DECLARED** (**Medium**) — bridges two already-shipped, already-tested parsers (IaC exposure facts, `services.yml` declared topology) into graph-attached facts; the work is connection, not new parsing. **7b RUNTIME OBSERVED** (**Large**) — `posture/runtime-correlation.js`'s offline-JSONL-file pattern and qid-then-file+line matching TECHNIQUE are directly reusable, but its schema (code-execution-shaped) and storage model (none — ad hoc JSONL) are not: needs a new `RuntimeObservation` extension contract, a new graph-ID-aware correlation function, at least one real adapter (OpenTelemetry span JSON is the PRD's own named starting point and has zero existing support), and a new append-only, multi-record-per-scope storage mechanism — `GraphSnapshot`'s commit-keyed, one-record-per-commit shape is a confirmed FALSE precedent here (the same kind of trap `ObligationMapping` was for `DecisionStory`), `posture/provenance/lifecycle.js`'s many-records-per-key shape is the closer structural fit. |
| 8 | Cross-repository/federated graph import | **Medium if scoped narrowly (recommended); Large if scoped as full graph-merge (not recommended)** | none | The PRD's own backlog priority (`DFG-025`, P2 — the lowest tier) is real signal this is meant to be deferred, not overlooked. `ids.js`'s own header states canonical IDs are deliberately "stable within the repository/commit" — `nodeId`/`edgeId`/`flowId`/`dataElementId` never include `repository`, so naively concatenating two repos' node arrays would silently id-collide (confirmed real, not theoretical — an extremely common node shape like a plain `file` sink would collide across almost any two repos). Recommend scoping narrowly to FR-304's own literal text — "cross-repository or federated edges may be **declared or imported**" — a new, explicitly-declared cross-repo EDGE type referencing two separately-scanned graphs' own node ids, with each repo's graph staying its own separate, unmodified artifact (no array-merge, no id-renamespacing redesign). This is architecturally much smaller and is what the PRD text actually asks for; a full graph-merge would be a materially different, riskier, unrequested redesign. `RecipientProfile`'s own id is already correctly graph-scoped (safe, no false collision) but has zero automatic cross-repo consolidation — a real, disclosed gap if this and FR-506's own "concentration view" are ever expected to compose. |

## Recommended sub-project order (this document's own conclusion)

This order reflects real dependencies found this session, not PRD
prose order, the same way the M4 doc's own order corrected several of
that milestone's assumed dependencies against real code:

1. **Language coverage ruling + coverage-tier disclosure UI** (#1) —
   COMPLETE, 2026-09-02. Ruled (b) and shipped it — smallest, no
   dependencies, resolved a real scope ambiguity before anything else in
   M5 references language support. See the row's own detail above.
2. **Large-graph server/worker-side pagination** (#2) — item (a) COMPLETE,
   2026-09-02. Shipped the foundational infrastructure work, closing the
   already-disclosed "whole graph always transferred" gap named in two
   separate places in the code but never connected to a deliverable
   before this document. Item (b) (an HTML-table stress-test pass) and
   item (c) (semantic zoom, confirmed out of scope) remain as described
   in the row's own detail above.
3. **What-If Architecture Simulator, split 3a** (#3) — **3a COMPLETE,
   2026-09-02**. Split 3b (synthetic node insertion) remains scoped and
   judged separately, still a real candidate for disclosed deferral —
   see the row's own detail above.
4. **Blast-Radius: Impact Assessment** (#4) — no hard M5 dependency,
   strong reuse story (`focus-controls.js`, already-shipped extension
   arrays).
5. **Governance editing workflow** (#5) — the riskiest item in M5;
   recommended here, before Remediation Command Center, per the real
   `DFG-041`→`DFG-023` backlog dependency signal — get its own dedicated
   scoping investigation before any implementation plan, likely split
   like FR-504's 6a/6b/6c.
6. **Blast-Radius: Remediation Command Center** (#6) — depends on #4 and
   ideally #5's write-service pattern; also reuses already-shipped
   `GraphDiff`/`drift-policy.js` for verification.
7. **Runtime-Corroborated Digital Twin, split 7a (CONFIG DECLARED) then
   7b (RUNTIME OBSERVED)** (#7) — no hard dependency on the above,
   recommended here to share the `hypothetical`/`runtime_observed`
   fact-type vocabulary rollout with What-If Simulator with minimal
   churn.
8. **Cross-repository/federated graph import** (#8) — explicitly P2 in
   the PRD's own priority scheme; recommend last, scoped narrowly to
   FR-304's own "declared/imported edges" reading.

This order is a recommendation, not a commitment — each sub-project
still gets its own scoping pass (which may revise size/order estimates
against real code, the same way every M4 sub-project's own scoping
corrected this document's counterpart's rougher assumptions) before any
implementation plan is written. Governance-editing-workflow in
particular deserves its own careful investigation before its position
in this order is treated as final, given how much of its real shape
(the "secure write service") the PRD itself leaves undefined.

## Explicitly out of scope for this document

- Any code change. This is scoping only.
- A decision on the language-coverage ruling ((a) vs. (b) in deliverable
  #1's own row) — that's a real product/priority call for whoever scopes
  that sub-project, not something this document should decide
  unilaterally.
- Milestone 6 or beyond, if the PRD is ever extended past §26's own
  5-milestone structure — none currently exists.
