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
| 4 | Blast-Radius: Impact Assessment half of FR-507 | **Medium — COMPLETE, 2026-09-02** | none (reused only already-shipped M3/M4 work) | **SHIPPED**: `impact-assessment.js` (the `ImpactAssessment` §10.10 contract — `IMPACT_TARGET_KINDS`, `IMPACT_TRACE_KINDS`, `validateImpactAssessment`) and `impact-engine.js` (`computeImpactAssessment` — reuses `frontend/src/lib/focus-controls.js`'s already-shipped `showAllPaths` BFS unmodified, the established cross-import precedent `export-privacy.js` set), plus a CLI verb `dataflow impact assess`. A real, corrected design finding from mid-implementation: `ObligationMapping` records are NOT a stored `graph.obligationMappings[]` array the way `RecipientProfile` is — they're built on demand per compliance-framework requirement — so `affectedObligationIds` was dropped from scope entirely rather than half-built; `affectedRecipientProfileIds` (the `RecipientProfile` half) shipped as originally scoped. A real, twice-found architecture defect, caught first at the task level for `dataElement` targets and then again at the final whole-branch review for `edge`/`flow` targets: seeding the topology-wide `showAllPaths` BFS from a target's own endpoint nodes silently swept in unrelated sibling flows sharing those nodes — reproduced with a concrete, decision-relevant harm (a payment-flow assessment naming an unrelated ad-network recipient). Fixed by giving `edge`/`flow`/`dataElement` targets their own direct flow-restricted trace (`traceKind: 'flow_restricted'`, now a real field on the record disclosing which of the two genuinely different semantics produced it), while `node` targets keep the topology-wide "everything reachable" trace (`traceKind: 'topology_reachable'`) — compromising a node really does put everything it can reach at risk; compromising one edge/flow/data-element does not. `scope` stays honestly `'possible'`-only, `IMPACT_SCOPE_VALUES` already reserving `'observed'` for a future Digital Twin (item 7) producer. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-blast-radius-impact-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, both fix rounds, and re-review detail. |
| 5 | Governance editing workflow with validated, reviewable writes | **Large, genuinely the riskiest single item in Milestone 5 — COMPLETE, 2026-09-03** | none directly, but should land BEFORE item 6's remediation half per a real PRD backlog signal (`DFG-041` partially depends on `DFG-023`) | The PRD's own backlog already flags this as unresolved design (`DFG-023`'s undefined "secure write service" dependency, not just an oversight in the FR-5xx prose). A dedicated scoping investigation found no PRD acceptance criterion actually gates this deliverable and that PRD line 1324's 5-part write contract (preview, validation, backup/version guard, confirmation, audit event) never mandates HTTP/interactivity — ruled **CLI-only first cut, HTTP write surface explicitly deferred** (new routes, CSRF protection, a write-authorization mechanism beyond the existing read-only session token remain real, unattempted, separately-scoped future work). **SHIPPED**: `governance-edit.js` (`proposeGovernanceEdit` — RFC-7396-style JSON merge-patch semantics against `recipient-profiles.json`'s existing, already-tested `isValidRecipientConfigEntry`) and a new top-level CLI command `governance propose-edit` (`cmdGovernancePropose` — version guard → validate → backup → atomic write → audit, reusing `src/mcp/audit.js`'s already-hardened `auditCall` unmodified). The final whole-branch review found and a same-day fix round closed a real Blocking finding: the write's merge base was a lossy config loader's SANITIZED view rather than the file's real bytes, so any entry or top-level key that loader silently dropped was permanently deleted by an unrelated edit, with the preview and the audit event both falsely reporting nothing removed — fixed by parsing the raw file directly as the sole merge base and adding real top-level container-shape validation to both the patch and the current config. Four further Important findings (a malformed patch silently accepted as a no-op success; array/empty-string/`__proto__` recipient keys accepted; the atomic write silently widening file permissions 0600→0644; unregistered backup files never swept by `reset`) and seven Minor findings were also found and fixed the same pass, independently re-verified by a second review round — this is now the fifth deliverable in a row this session where the final whole-branch review, not any task-level review, found the real Blocking bug. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-governance-editing-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, two fix rounds, and re-review detail. |
| 6 | Blast-Radius: Remediation Command Center half of FR-507 | **Large — COMPLETE, 2026-09-03** | item 4 (Impact Assessment — a remediation item's own "linked assessment" field needs it to exist first) + already-shipped `GraphDiff`/`drift-policy.js` (verification) + ideally item 5's write-service pattern, per the real `DFG-041`→`DFG-023` backlog dependency | **This is the ONE M5 deliverable actually gated by a named PRD acceptance criterion (AC-31, named in the Milestone 5 exit gate itself) — unlike #5, a narrower cut could not simply skip a clause.** A dedicated scoping investigation corrected the row's own framing in 5 places, most importantly: AC-31's own "or" is rescan-vs-manual-attestation, not rescan-vs-runtime, so FR-505 (Digital Twin) is not merely optional — it is absent from the gate, and nothing exists to be blocked on. **SHIPPED**: `remediation.js` (pure AC-31 state machine — `foldRemediationItem`/`validateTransition`/`evaluateVerificationEvidence`, zero imports) + `remediation-ledger.js` (an append-only, locked, hash-chained JSONL event log — the first ledger of this shape in the codebase, `posture/provenance/lifecycle.js`'s `withLock` ported locally since it isn't exported) + a 6-verb CLI (`open`/`update`/`verify`/`accept-risk`/`reopen-check`/`list`), reusing `computeGraphDiff`/`drift-policy.js` for verification and reopening exactly as scoped, plus already-shipped `fix/approver-registry.js` for approvals (a real reuse the row's own "genuinely new fields" framing missed). The final whole-branch review found and a same-day fix round closed **3 real Blocking bugs, each falsifying one of AC-31's own three clauses** despite every task-level review and the full green test suite: (B1) `remediation verify` could grant `verified` from a snapshot chronologically OLDER than the incident, since nothing checked diff direction and the pre-existing `loadSnapshots` sorts by file mtime, not `capturedAt` — closed by a direct `capturedAt` comparison before diffing. (B2) `reopen-check`'s regression-detection mechanism read the wrong diff bucket entirely — structurally DEAD for the canonical scan-verified regression (a required-evidence flow reappearing shows up only in `diff.added.flows`, which the original code never read) and fired INVERTED on successful remediation (reopening an item because its flow was successfully removed) — closed by rewriting the check against `diff.added.flows`, also closing a related reidentification gap. (B3) a permitted manual attestation was silently undone by the very next `reopen-check`, because attestation never recorded a baseline snapshot and a stale/null anchor kept being reused — closed by recording a real baseline on attestation and retiring it on reopen. Both fixes were independently reproduced live — broken, then fixed — by the coordinator AND by a separate scoped re-review, each building its own scratch-project repros rather than trusting the other's. Four Important findings (a torn-ledger-tail write silently lost while reporting success; the `--base-event` concurrency guard checked outside the lock, a real TOCTOU; the reidentification gap folded into B2; a tampered/truncated ledger silently showing a shorter history with no signal) and 7 Minor findings were fixed the same round. This is now the sixth deliverable in a row this session where the final whole-branch review — not any task-level review — found the real Blocking bug, and the first where the miss was on the deliverable's own literal gating acceptance criterion, not just a quality property. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-remediation-center-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, corrections, fix round, and both re-review passes. |
| 7 | Runtime-Corroborated Digital Twin (FR-505) | **Large — split into 2 → 7b COMPLETE, 2026-09-03; 7a descoped to M2 F2/F3 (not this deliverable's)** | none directly; landed after item 6 | A dedicated scoping investigation confirmed AC-29 (named in the Milestone 5 exit gate) gates this deliverable, and ruled 7a (CONFIG DECLARED — bridging IaC/`services.yml` facts into graph-attached edges) is properly M2 Sub-project F2/F3's own already-scoped job, not a fresh 7a increment — building it here would duplicate that backlog item. **SHIPPED (7b only)**: `runtime-observation.js` (the closed-world `RuntimeObservation` §10.10 contract — the ONE closed-world validator in the whole package, deliberately, since it validates OPERATOR-SUPPLIED telemetry this codebase never generated and cannot vouch for), `observation-correlation.js` (the graph-ID match ladder + three-valued `RUNTIME OBSERVED`/`not_observed_in_window`/`not_evaluated` layer, AC-29 clauses 1-4), `observation-adapters.js` (a native-JSONL adapter, closed-world wire shape), `observation-store.js` (an import-keyed, immutable, signed-and-encrypted observation store), an additive `graph-builder.js` hook (`opts.correlateObservations`, byte-identical when omitted), and the CLI proof surface (`dataflow observations import\|list`, `dataflow twin`). **AC-29 clause 5** ("no captured payload, prompt, response, record, log message, or sensitive value exists in the observation artifact") is the deliverable's own most consequential property, and it took THREE layers of adversarial review to genuinely close, continuing this session's now fully-established pattern that a task-level review and a green test suite are not sufficient scrutiny for an AC-gated finding: **(1)** the final whole-branch review found B1 — every scalar attribute value accepted almost any punctuation-containing string, so a PAN/SSN/SQL statement could be smuggled verbatim into `destination.path`/`schema.name` and persisted plaintext — closed by a per-scalar identifier grammar, a tightened max length, and (separately) B2, a concurrent-import id collision causing silent data loss, closed with a fresh random discriminator. **(2)** That fix round's OWN scoped re-review, explicitly instructed to probe adversarially beyond the original repros (this session's standing discipline after #6's AC-31 saga), found the B1 fix was NOT fully closed: the one array-valued attribute key, `schema.attributeNames`, let the identical class of secret be smuggled by splitting a colon-structured `key:value` pair (`"password:hunter2"`, `"ssn:123-45-6789"`, `"pan:4111111111111111"`) across separate array elements, each individually passing the per-element grammar the first fix round shipped — live-reproduced with a real CLI import, exit 0, secrets persisted plaintext. **(3)** A second, narrower fix round closed it for real: a dedicated, stricter grammar for `schema.attributeNames` elements specifically (letters/digits/underscore only — no `:`/`.`/`-`, since a real attribute name never needs any of the three, closing every key:value-shaped smuggling case completely) plus cutting the array's max length from 64 to 8. Independently re-verified by the coordinator directly (not the implementer's own fixtures): reproduced the pre-fix vulnerability live against the exact pre-fix commit (`validateObservationAttributes` returned `valid:true` on the malicious payload), then reproduced the post-fix refusal live through the real CLI (exit 1, nothing written), then confirmed a real, legitimate `schema.attributeNames` list still imports successfully — the fix closes the hole without being overly strict. **One residual gap remains, deliberately disclosed rather than chased further** (matching this session's own "close what's cheaply closable for real, disclose the rest honestly" precedent from #6's own B2 Mechanism-B fix): up to 8 short, individually-plausible single words can still be supplied as separate `schema.attributeNames` array elements (no colon, no structure) — an INHERENT limitation of any bounded, per-element, character-class-only grammar with no semantic/prose-detection layer, the same class of residual as a base64-encoded secret fitting the identifier grammar whole (also disclosed, also not attempted) — both are named explicitly in `runtime-observation.js`'s own header comment and in `commands/dataflow.md`. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-digital-twin-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, the two Blocking findings' fix round, the scoped re-review that found the residual gap, and its own fix round's independent verification. |
| 8 | Cross-repository/federated graph import | **Medium — COMPLETE, 2026-09-03. This closes out the M5 top-level scoping doc's own 8-deliverable list, and Milestone 5, in full.** | none | A dedicated scoping investigation independently re-verified the narrow, "declared"-half-only direction against the real code and found it correct, with one real sharpening: FR-304's "declared or imported" is TWO mechanisms with two different `DFG-025` dependency profiles (`DFG-002` alone vs. `DFG-002`+`DFG-007`+unbuilt M2 F2/F3), not one phrase to scope as a unit — this deliverable covers only the "declared" half; "imported"/auto-correlated stays a real, separately-scoped future increment. Also settled, via direct reading of `validate.js`'s `_validateEdge`, that a cross-repo entry can never be a core-schema `graph.edges[]` member at all (both endpoints must resolve against the ONE graph's own `nodeIds` set) — the id-collision risk this row originally named cannot actually occur under a correctly-scoped design, since a foreign node id is never looked up against a merged set. **SHIPPED**: `cross-repo-link.js` (the `CrossRepoLink` §10.10 extension contract — `crossRepoLinkId` in `ids.js` mirrors `recipientProfileId`'s own `(graphId, graphDigest, ...)` discriminator shape, doubled for both endpoints), `federation-loader.js` (`loadRemoteGraphExport` — reads a remote repo's `dataflow export --format json` artifact via a self-consistency digest check, never `loadSignedGraph`'s per-install-HMAC-keyed local mechanism, which is the wrong trust model for a file that crossed a repo/machine boundary), an additive SIXTH `graph-builder.js` hook (`graph.crossRepoLinks[]`, byte-identical when omitted), and a new top-level CLI dispatcher `federate declare\|list` (reusing `governance-edit.js`'s exact 5-part write contract). The final whole-branch review found **3 real bugs, all fixed the same day**: (B1, Blocking) the remote self-consistency digest check compared a recomputation over the REDACTED/FILTERED export body against a digest field that always identifies the SOURCE graph regardless of redaction — under the CLI's own DEFAULT (redacted) settings, a genuinely un-tampered export permanently read as mismatched, indistinguishable from a real tamper; closed by adding a separate `bodyDigest` field describing the emitted body itself. (B2, Important) `redact-graph.js` never covered `graph.crossRepoLinks[]` — the THIRD recurrence of this exact gap class in that file's own documented history — closed with a new `_redactCrossRepoLink` helper. (B3, Important) a declared link's own id was unstable across a declare→rescan→declare cycle, because `computeGraphDigest` (used to derive the id) has no exclusion for `crossRepoLinks`, creating a feedback loop where declaring a link changed the digest the NEXT declaration's own id was derived from; closed by stripping `crossRepoLinks` before hashing and deduping the write by record id. **This deliverable's own fix round then repeated the pattern one level deeper still**: a scoped, explicitly-adversarial re-review of that fix round — this session's now-standing discipline after a sibling M5 deliverable's own value-axis/array-splitting saga — found B2's fix was only HALF closed: `remote.sourceFile` (a real local filesystem path) and `declaredBy` (a real OS username) both still leaked verbatim, because the redaction mechanism used (`redactString`, a secret-PATTERN matcher) is structurally a no-op on an ordinary path or username with no embedded secret shape — the exact same "correct as far as it goes, wrong axis" bug class as the sibling deliverable's own residual. A second, small fix round closed it for real (unconditional `[REDACTED:local-path]`/`[REDACTED:username]` token replacement for the two structurally-PII fields, keeping the existing correct pattern-based treatment for the two genuinely-free-text fields), plus a small ordering cleanup the same re-review found. Both fix rounds were independently re-verified live by the coordinator, not trusted on faith — including reproducing the deeper B3 feedback-loop case (declare → real rescan that re-attaches `crossRepoLinks` onto the persisted graph → re-declare the identical fact → same id, still deduped to one entry) and the B1/B2 redaction fixes against real exported artifacts in a fresh two-repo scratch setup. `RecipientProfile`'s own "zero automatic cross-repo consolidation" gap, named by this row originally, is confirmed still real and not addressed here — a disclosed, separate future increment. See `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-cross-repo-scoping.md`/`-plan.md` and their own SDD ledger for the full investigation, both fix rounds, and the re-review detail. |

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
4. **Blast-Radius: Impact Assessment** (#4) — **COMPLETE, 2026-09-02**.
   See the row's own detail above.
5. **Governance editing workflow** (#5) — **COMPLETE, 2026-09-03**. CLI-
   only first cut (`governance propose-edit`), HTTP write surface
   explicitly deferred. See the row's own detail above.
6. **Blast-Radius: Remediation Command Center** (#6) — **COMPLETE,
   2026-09-03**. The one M5 deliverable actually gated by a named PRD
   acceptance criterion (AC-31); genuinely satisfies it after a final
   review found and a fix round closed 3 real Blocking bugs. See the
   row's own detail above.
7. **Runtime-Corroborated Digital Twin, 7b only** (#7) — **7b COMPLETE,
   2026-09-03**. AC-29 clause 5 took three adversarial review layers to
   genuinely close (a value-axis smuggling gap, then an array-splitting
   residual its own scoped re-review found); 7a ruled out of scope,
   already covered by M2 Sub-project F2/F3. See the row's own detail
   above.
8. **Cross-repository/federated graph import** (#8) — **COMPLETE,
   2026-09-03**, scoped to FR-304's "declared" half only, shipped as
   `federate declare|list`. The final whole-branch review found 3 real
   bugs (1 Blocking, 2 Important); the fix round's own scoped re-review
   then found a real residual gap in one of them, closed by a second,
   small fix round — the same two-layer-adversarial-review pattern
   that closed out #7's own AC-29 saga. See the row's own detail above.

**This is the last of the M5 top-level scoping doc's 8 deliverables — Milestone 5 is now COMPLETE, and with it, the entire Data Flow Explorer PRD (Milestones 0-5) is COMPLETE.**

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
