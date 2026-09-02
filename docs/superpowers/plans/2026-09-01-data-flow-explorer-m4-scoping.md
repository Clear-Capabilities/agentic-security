# Milestone 4 — Decision intelligence, exports, and workflow: top-level scoping

Per PRD §26's own Milestone 4 deliverable list (CLI/slash commands,
self-contained HTML report, deterministic PNG/SVG/PDF/JSON/CSV exports,
Executive Risk Story Mode, Data-Flow Time Machine, Regulatory Obligation
Overlay, Third-Party/Cross-Border Intelligence, graph-derived DPIA/RoPA,
MCP read-only tools, watch-mode deltas) and its exit gate (AC-13, AC-14,
AC-23 through AC-25, AC-27, AC-28, AC-30).

**This document does not build anything.** It maps the 9 deliverables
into sized sub-projects with real dependencies, confirmed against the
actual current codebase (not assumed), so each sub-project can get its
own scoping+plan via the same SDD process used for M1-M3/M3-UX. Milestone
5 (What-If Simulator FR-502, Digital Twin FR-505, Blast-Radius FR-507,
every other language, large-graph scale, cross-repo federation,
governance-editing) is explicitly out of scope here — a future top-level
scoping pass once M4 is underway.

## What already exists (confirmed by direct read this session)

- **`agentic-security explore`** (`scanner/bin/agentic-security.js`,
  `scanner/src/server/`) — a read-only, loopback-only HTTP server serving
  the already-scanned, already-signed `DataFlowGraph v1` artifact to the
  `frontend/` prototype. This is the ONLY existing CLI surface for the
  graph. No `agentic-security dataflow export`-shaped subcommand, no
  slash command, exists yet.
- **`scanner/src/mcp/tools.js`** — 17 registered MCP tools (`scan_diff`,
  `query_taint`, `explain_finding`, `apply_fix`, `verify_fix`,
  `synthesize_fix`, `find_rule_module`, memory/scratchpad tools,
  `lookup_cve`, `query_cache_telemetry`, `synthesize_sca_upgrade`,
  `apply_sca_upgrade`). **None of these touch the lineage graph at all**
  — confirmed by grep. `query_taint`/`explain_finding` are the closest
  existing analogues in shape (read-only, ID-scoped lookups) for the new
  dataflow-graph MCP tools this milestone needs.
- **`scanner/src/report/`** (`index.js`, `mascot.js`, `oscal.js`) — the
  existing SAST/SCA/compliance HTML report generator. It has NO knowledge
  of `DataFlowGraph v1` and is not reused directly (different data
  model), but its patterns (self-contained single-file HTML, deterministic
  templating) are the right precedent to follow for the new
  dataflow-specific report.
- **`scanner/src/lineage/`** — the graph contract/pipeline. Confirmed
  (this session, via direct grep) that **none of §10.10's 9
  decision-intelligence extension contracts** (`DecisionStory`,
  `Scenario`, `GraphSnapshot`, `GraphDiff`, `ObligationMapping`,
  `RuntimeObservation`, `RecipientProfile`, `ImpactAssessment`,
  `RemediationItem`) exist in code anywhere — no matching field, file, or
  schema. Every FR-5xx capability starts from zero on the backend.
- **`docs/compliance/`, `scripts/nist-compliance/`** — real, existing
  per-framework coverage maps and a NIST AI 600-1 catalog generator,
  entirely for the SAST/SCA compliance surface (NIST AI 600-1, OWASP
  ASVS/LLM Top 10, EU AI Act). Not wired to the lineage graph at all
  today, but real, reusable framework/control data for Regulatory
  Obligation Overlay (FR-504) to build on rather than inventing framework
  metadata from scratch.
- **`node.governanceRefs`-shaped data** — per this session's own
  M3-UX-Filters investigation, `flow.governanceRefs` (sparse, per-key:
  `recipient`/`purpose`/`lawfulBasis`/`retention`/`deletion`/`transfer`)
  is real and populated where declared, already deferred out of Filters
  as "needs its own design work." Real raw material for both Regulatory
  Overlay (FR-504) and DPIA/RoPA generation.
- **Frontend's own architecture-view.js SVG renderer** (M3-Render) — a
  hand-rolled, pure, DOM-independent-in-its-math SVG layout engine
  (`computeClusteredLayout`, `aggregateEdgesForClusters`, viewport math).
  Real starting point for deterministic SVG export, since its layout math
  is already pure functions over `(graph, state)` — the hard part
  (serializing to a static `<svg>` string without a live DOM) is *not*
  solved yet, but the layout math it would call is.

## The 9 deliverables, sized and ordered by real dependency

| # | Deliverable | Size | Depends on | Why |
|---|---|---|---|---|
| 1 | MCP read-only tools | Small **— COMPLETE (2026-09-01)** | none | Shipped: `scanner/src/mcp/dataflow-tools.js` — 4 new tools (`dataflow_get_graph`/`_node`/`_edge`/`_flow`) wrapping `scanner/src/server/`'s already-built `loadSignedGraph`/`handleGraph`/`handleNode`/`handleEdge`/`handleFlow`, unmodified, exactly as scoped. A final whole-branch security review (beyond the two per-task reviews) found the initial redaction covered only a fixture-only field (`evidence[].location.note`, never populated by the real graph-builder emitter) and missed the real source-derived surface (`node.destination.raw`/`.literalValue`, lifted verbatim from scanned call-site arguments) — fixed same day, with regression tests proving real secret shapes (a Slack webhook URL, a hardcoded password) are redacted. Also fixed: `dataflow-tools.js` was missing from the MCP server's `CODE_FINGERPRINT` file list. One requirement knowingly NOT shipped: `dataflow_get_graph` pagination/offload for very large graphs (the plan's own scope item 1) — disclosed as a known gap in the tool description and `mcp/CLAUDE.md` rather than rushed. Full writeup in `2026-09-01-data-flow-explorer-m4-mcp-tools-scoping.md` + `…-plan.md` and `scanner/src/mcp/CLAUDE.md`'s own "Dataflow-tools redaction scope" section. |
| 2 | JSON/CSV export | Small–Medium **— COMPLETE (2026-09-01)** | none | Shipped: `scanner/src/lineage/export-json.js` (`exportGraphJSON`/`computeGraphDigest`) and `export-csv.js` (`exportFlowsCSV`, one row per flow). Corrected the citation error above during detailed scoping — AC-23 is PNG/SVG-only (sub-project #4's concern); only AC-14 applies here. A final whole-branch review found and the same-day fix round closed three real redaction-bypass instances of the same bug class (`destination.blockingExpression`, `queueDetail.topic`, `node.coverageReason` all carried the identical unredacted secret as an already-redacted sibling field) and rebuilt `computeGraphDigest` from a narrow hand-enumerated allowlist (which silently excluded most risk-bearing content) into a comprehensive EXCLUDE_KEYS-based canonicalization. Redaction logic (`redact-graph.js`) was extracted from the M4 MCP-tools sub-project's own `dataflow-tools.js` and is now shared by both. Full writeup in `2026-09-01-data-flow-explorer-m4-json-csv-export-scoping.md` + `…-plan.md` and `scanner/src/lineage/CLAUDE.md`'s own "Milestone 4 (JSON/CSV export)" section. |
| 3 | Self-contained HTML report | Medium **— COMPLETE (2026-09-01)** | #2 (JSON export, COMPLETE) | Shipped: `scanner/scripts/bundle-frontend.mjs` (a minimal, hand-rolled, named-imports-only ES module bundler, no new npm dependency — option 1 from this sub-project's own scoping doc), `frontend/src/export-entry.js` (a dedicated offline entry point), and `scanner/scripts/generate-html-report.mjs` (inline CSS + bundled JS + the already-redacted `exportGraphJSON` payload into one offline `.html` file). The `file://` module-CORS constraint this sub-project exists to work around was empirically confirmed via a real, locally-invoked Chrome binary (`claude-in-chrome`'s own `navigate` tool refuses `file://` URLs); the FINAL deliverable's own real-Chrome acceptance proof (same technique) confirmed the generated report genuinely renders offline, with real fixture content visible in the dumped DOM. Three real bugs were found across this sub-project's own review rounds and fixed same-day: the bundler's circular-import detection was unreachable dead code (check-order bug); a real script-injection vulnerability (unescaped `<` in the embedded graph JSON breaking out of the data `<script>` tag) was live-reproduced and fixed using this codebase's own established mitigation; and the bundler's unsupported-ES-form detection had real gaps (`export async function` — already present in the live tree — `export {}` lists, `import {x as y}` renames all built silently and only failed later as a blank page), closed with both specific guards and a general syntax-validation safety net. Full writeup in `2026-09-01-data-flow-explorer-m4-html-report-scoping.md` + `…-plan.md`. |
| 4 | PNG/SVG/PDF export | Large **— COMPLETE (2026-09-01)** | #3 (self-contained HTML report, COMPLETE) | Shipped: `scanner/src/ir/chrome-probe.mjs` (Chrome/Chromium binary discovery, mirroring `parser-py-cst.js`'s own `probePythonAvailable()` pattern) and `scanner/scripts/export-image.mjs` (`exportPng`/`exportPdf`/`exportSvg`, driving a real, locally discovered Chrome binary's native headless flags against #3's own already-shipped self-contained HTML report — no new npm dependency, matching the sub-project's own scoping investigation). Multi-view capture uses the already-shipped `#view=<name>` URL-hash mechanism (`frontend/src/lib/state.js`/`shell.js`), zero new frontend code. This sub-project went through three review-and-fix rounds, each finding a real, previously-undetected bug — the highest review-to-defect ratio of any M4 sub-project so far: (1) a final whole-branch review found `_hashUrl`'s hand-built `file://` string concatenation truncated at a literal `#` in the OS temp path, causing Chrome to silently render its own internal error page (exit 0, correctly-dimensioned-but-wrong output) reported as `{ok:true}` — fixed with `pathToFileURL` plus a view-agnostic positive-render-verification check (`role="tablist"`, the shell's own view-switcher, present in every view — an initial version reused the architecture-only `<svg class="arch-view">` marker and broke on non-default views, caught by re-running the suite before committing); (2) a scoped re-review of that fix found the fix's own timeout-NaN guard let an empty/blank env var through as a real `timeout: 0` (spawnSync's "no timeout" value) — an unbounded-hang risk — and that the Linux Chrome-discovery candidate-path list was empty, making a companion PATH-vs-absolute-path security fix a no-op on the platform CI actually runs on; (3) a second scoped re-review of THAT fix found its own guard still admitted non-integer values (e.g. `"1.5"`), reproducing the exact original uncaught-throw symptom for a different malformed input — closed with `Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0)`, verified against a real `spawnSync` call across ~49 edge cases and a 200,000-case fuzz comparison confirming the fix strictly narrows (never regresses) the prior guard. A final scoped review returned MERGE-READY with one non-blocking test-quality note (outcome-based tests couldn't distinguish a silent `timeout:0` bug from correct behavior when the underlying command succeeds quickly either way) — closed with a direct input/output table test, A/B-verified against the exact gap. Full writeup in `2026-09-01-data-flow-explorer-m4-image-export-scoping.md` + `…-plan.md`. |
| 5 | CLI and Claude slash commands | Small–Medium **— COMPLETE (2026-09-01)** | #1–#4 (all COMPLETE) | Shipped: `scanner/bin/agentic-security.js`'s `cmdDataflowExport` CLI subcommand wiring `agentic-security dataflow export [path] --format <fmt> --output <file> [--view <name>] [--size standard|2x] [--width <n>] [--height <n>] [--no-redact] [--filter <path>]`, plus `commands/dataflow.md` slash dispatcher. Reconciled the six export/report functions' two failure conventions (async `{ok,reason}` for images vs. sync-throwing for JSON/CSV/HTML) into one consistent exit-code contract (0 success, 1 graph-load failure, 2 export-stage failure). Followed scoping rulings: kept `explore` as-is, added a separate `dataflow` verb; deferred semantic `--class` filtering via `--filter <path>`'s raw `{nodeIds,edgeIds}` shape instead; added `--size standard|2x` for AC-23's two pinned PNG sizes. Also fixed `explore`'s own missing `--help`/`USAGE` entry as a drive-by. This sub-project's own final whole-branch review found 2 blocking + 5 recommended gaps (a `--filter`-with-no-value crash escaping to a raw stack trace at exit 4; `--filter` silently a no-op for `--format csv`; `--view` silently a no-op for `json`/`csv`/`html`; `--width`/`--height` accepting a bare flag as `Number(true)===1` or an unbounded safe integer that made Chrome silently fall back to its own default size; `commands/secure.md`'s command index and `scanner/CLAUDE.md`'s `test:server` row both missing the new command) — all fixed and independently re-verified MERGE-READY same day. Two items were deliberately left open as disclosed, non-blocking follow-ups: `--view=` (empty string) still silently falls back to the default rather than erroring (lower-impact than the fixed cases, since the fallback IS the documented default); `--size`/`--width`/`--height` are silent no-ops for `pdf`/`json`/`csv`/`html` with no warning (materially milder than the fixed `--view` case, since neither the USAGE text nor `commands/dataflow.md` ever claimed these flags were universal — both already scope them to PNG). Full writeup in `2026-09-01-data-flow-explorer-m4-cli-slash-scoping.md` + `…-plan.md`. |
| 6 | Regulatory Obligation Overlay + evidence packs (FR-504, §7.12 — the PRD reuses "FR-504" for an unrelated §20 rule too, disambiguate by section) | Large **— split into 6a/6b/6c; ALL COMPLETE (2026-09-02) — sub-project #6 fully done** | `ObligationMapping` extension contract (new) | Detailed investigation (`2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`) found this row's own central claim false as stated: `flow.governanceRefs` is NOT populated by the real production graph-builder (hardcoded `{}` at both mint sites) — only the hand-authored demo fixture has real values. A materially stronger, previously-uncited real foundation exists instead (`flow.policyVerdict`, evidence-backed and fail-closed since Milestone 2), and a strong reusable architectural precedent (`auditor-walkthrough.js`'s typed-predicate `present`/`partial`/`absent`/`manual` engine + `oscal.js`'s "never claim decided for what wasn't" discipline) was undersold by this row. Also found: PCI DSS (one of 6 PRD-named "initial packs") has no existing catalog anywhere — deferred, not silently dropped. The PRD's own DFG-038 dependency table lists DPIA/RoPA (#10) as a PREREQUISITE of this sub-project — inverted from this doc's own order below; ruling: kept this doc's order (DPIA/RoPA has no independent data model in the PRD and must derive from this sub-project's output). Split into 6a (extension contract, small/mechanical), 6b (predicate engine, the real work), 6c (evidence-pack export, a new signed-bundle module — NOT a reuse of the finding-shaped `evidence-bundle.js`). **6a shipped**: `scanner/src/lineage/obligation-mapping.js` (the six-state record shape, zero imports, boundary-tested) + `ids.js`'s `obligationId` (discriminated by `framework`/`frameworkVersion`/`requirementId`/`graphId`/`graphDigest` — the final review found and fixed a real id-collision risk: `graphId` alone never distinguishes two same-commit graphs with different content in the real pipeline). Deliberately NOT a `DataFlowGraph v1` entity — never in `dataflow-graph.schema.json`, never routed through `validate.js`, per PRD §10.10's "associated with, but not required inside the immutable base graph" rule. Full writeup in `2026-09-01-data-flow-explorer-m4-obligation-contract-plan.md`. **6b shipped**: `scanner/src/lineage/obligation-predicates.js` (`evaluateGraphFlowPredicate` + `buildObligationMappingFromGraphPredicate`), wired into `auditor-walkthrough.js`'s `evaluateFramework` as a third, purely-additive `graph:` mapping type alongside `family:`/`module:`/`rule:`, with a real end-to-end case on HIPAA §164.312(e) (`"graph:transit-protection:PHI:external:transit:protected"`). The final whole-branch review — deliberately instructed to test against REAL pipeline-produced graphs via `bench/data-lineage/runner.mjs`'s `buildFixtureGraph`, not hand-built fixtures, since two prior task-level reviews using only hand-built fixtures had missed everything — found and a fix round closed two blocking false-compliance-signal bugs (an unassessed protection verdict reading as a genuine failure; an FR-203 `kind:'unresolved'` sink silently excluded from applicability), plus a scoped re-review of that fix round found and a second round closed a new regression the first round's own broadened sink-match introduced (an unresolved *store/queue* sink over-matching an external-scoped predicate). Full writeup in `2026-09-01-data-flow-explorer-m4-obligation-predicate-plan.md` and its SDD ledger. **6c shipped**: `scanner/src/posture/obligation-evidence-pack.js` (the fourth sibling in the `evidence-bundle.js` signed-artifact family, reusing its Ed25519 key infra + `EVIDENCE_GRADE_DISCLAIMER`), wired into `agentic-security attest --obligations <framework-id>` / `verify-attestation`, plus (real scope growth found mid-review, not merely disclosed) an identical fix to the already-merged 6b `compliance --walkthrough` command. The final whole-branch review and two scoped re-reviews of its own fix rounds found and closed, live-reproduced: two blocking bugs (`reproducibility.{engineVersion,rulesetVersion,bundleSha}` reading the wrong `scan.*` fields, always null; a stale `.agentic-security/lineage-graph.json` from an earlier deep scan surviving an ordinary rescan untouched, letting a signed pack assert a false, since-regressed compliance claim) and a deeper follow-up gap the first fix missed (`scanHealth.lineageAnalysis.enabled` is set `true` before the lineage build even starts and never clears on failure, so `requested && enabled` alone still admitted a stale graph after a failed rebuild — closed with a `failure === null` check, extracted into one shared, tested `loadFreshLineageGraph` helper rather than left duplicated per caller). Full writeup in `2026-09-01-data-flow-explorer-m4-evidence-pack-plan.md` and its SDD ledger. |
| 7 | Executive Risk Story Mode (FR-501) | Large **— COMPLETE (2026-09-02)** | `DecisionStory` extension contract (new) — did NOT end up benefiting from #6; see the row's own correction | A synthesis/ranking layer over EVERYTHING else in the graph (claims, chapters, ranking factors, evidence coverage) — genuinely new analysis logic, not a data-availability problem like SemanticZoom was. AC-25 requires it stay evidence-linked, which is checkable but adds real design constraints (can't fabricate a "chapter" with no underlying finding). Real investigation found this row's own "benefits from #6" claim false: #10's own `flow.governanceRefs`/`ObligationMapping` machinery answers a different question than FR-501's 9-factor ranking engine needs, so `decision-story.js` was built standalone (7 of 9 factors direct graph reads, 1 new small aggregation, 2 — `recipientJurisdiction`/`changeRecency` — honestly `unavailable`, needing capabilities #6 (Third-Party Intelligence) and #8 (Time Machine) respectively, neither built yet). Shipped: `scanner/src/lineage/decision-story.js` + `export-briefing.js`, wired into `dataflow export --format briefing --audience <mode>`. Final whole-branch review found 3 real cross-task bugs (a Chapter-3/FR-203 externality seam that silently dropped every AI-provider flow; a Chapter-4 policy-bucket collapse that made an unsupported compliance claim and contradicted Chapter 5 in the same document; a command-description lint regression invisible to `npm test`), all closed in a fix round, confirmed MERGE-READY by a scoped re-review. Interactive frontend Briefing view deliberately out of scope (CLI/Markdown export only), matching #10's own precedent. |
| 8 | Data-Flow Time Machine + drift detection (FR-503) | Large — **split into 8a/8b per real investigation; 8a COMPLETE (2026-09-02)** | `GraphSnapshot`/`GraphDiff` extension contracts (new) | Needs a real snapshot-storage mechanism (none exists today — `.agentic-security/last-scan.json` is a single current-state file, not a history), a diff algorithm over canonical IDs, and configurable drift policy. Directly overlaps deliverable #9 (watch-mode) — same diff engine, different trigger. Real investigation found this is genuinely LARGER than a single "Large" row — DFG-037 (Time Machine UI/drift policies) depends on DFG-022 (snapshot/diff foundation), which itself had zero code; realistically two dependent Large sub-projects, not one. Also found a real, load-bearing gap: `engine.js`'s own `buildLineageGraph` call site never passes a real git commit, so every graph's own `graphId` embeds the literal `uncommitted` — snapshot keying has to resolve the real git HEAD independently (mirroring `posture/sbom-diff.js`'s own proven persist-by-commit architecture, the one real precedent in this codebase for "compare two scans"). **8a shipped**: `scanner/src/lineage/graph-snapshot.js` — the `GraphSnapshot` contract, commit-keyed persistence (`.agentic-security/lineage-snapshots/<HEAD>.json`, additive alongside the existing single-current-graph artifact), and a comparability check (`schemaVersion` match only — the `configHash` gap is real and disclosed, not closed here). **8b (diff computation, change-cause classification, drift-policy DSL, CLI wiring) not started.** |
| 9 | Watch-mode graph delta updates | Medium | #8's diff engine | A file-watcher that reruns the scan and emits the same `GraphDiff` #8 produces, just triggered by filesystem events instead of an explicit "compare two snapshots" command. Real, but should NOT be scoped before #8's diff engine exists — building it first would mean redoing the diff logic twice. |
| 10 | DPIA/RoPA graph-derived export, behind migration flag | Medium–Large **— COMPLETE (2026-09-02)** | #6 (Regulatory Overlay) | This row's own "thin templating layer on top once #6 exists" framing was found false by real investigation: #10 does NOT reuse #6's `ObligationMapping`/predicate-engine output at all — it needed its own new `flow.governanceRefs` field (populated by a new `resolveGovernanceRefs` hook in `coverage.js`, worst-case-wins across a flow's own data classes) plus a first-in-repo live `scanner/` → `frontend/` import (`computePrivacyViewModel`, reused rather than re-derived) for row computation. Real, non-templating work: field-identity-precise row grouping (`_groupRowsByClass`, with a genuine "unclassified flow silently vanishes" bug found and fixed), Markdown-injection-safe escaping for operator-supplied governance prose, and a disclosure fix for a real cross-task bug (a flow spanning >1 data class merges its governance record at mint time, and both output documents were re-presenting that one merged record as if it were class-specific). Shipped: `scanner/src/lineage/export-privacy.js` (`emitGraphDpiaArtifact`/`emitGraphRopaArtifact`), wired into `dataflow export --format dpia|ropa`. Full writeup in `2026-09-02-data-flow-explorer-m4-dpia-ropa-scoping.md` / `-plan.md` and its SDD ledger. |
| — | Third-Party and Cross-Border Intelligence (FR-506) | Large, **weakest data foundation** | `RecipientProfile` extension contract (new) | The one deliverable most likely blocked on more than code: `RecipientProfile` needs provider/legal-entity/jurisdiction/subprocessor facts that nothing in this codebase currently discovers (no provider-name resolution, no jurisdiction database, no subprocessor registry). `node.destination.literalValue` (confirmed real in M3-UX-Filters' own audit) gives a raw hostname/endpoint at best — turning that into "which legal entity, which jurisdiction, which subprocessors" is a real data-acquisition problem, not just an engineering one. Recommend its own dedicated investigation before any implementation plan, likely the last of the 4 decision-intelligence FRs to attempt. |

## Recommended sub-project order (this document's own conclusion)

1. **MCP read-only tools** (#1) — COMPLETE. Smallest, most self-contained,
   matched an existing pattern exactly.
2. **JSON/CSV export** (#2) — COMPLETE. Small, foundational for #3/#4/#6/#10.
3. **Self-contained HTML report** (#3) — COMPLETE. Medium, high reuse of already-
   shipped `frontend/` work.
4. **PNG/SVG/PDF export** (#4) — COMPLETE. Large; a real, already-
   installed Chrome binary's own headless flags, no new dependency.
5. **CLI and Claude slash commands** (#5) — COMPLETE. Small–medium, shipped
   `agentic-security dataflow export` CLI subcommand and `commands/dataflow.md`
   slash dispatcher, reconciling six export functions' failure conventions into
   one exit-code contract.
6. **Regulatory Obligation Overlay + evidence packs** (#6) — large,
   split into 6a (extension contract — COMPLETE) / 6b (predicate
   engine, reusing `auditor-walkthrough.js`'s typed-predicate
   architecture — COMPLETE, 2026-09-01) / 6c (evidence-pack export —
   COMPLETE, 2026-09-02). Sub-project #6 is fully done.
   `governanceRefs` is NOT a real signal yet (see own
   doc) — `flow.policyVerdict` and edge protection are.
7. **DPIA/RoPA export** (#10) — COMPLETE, 2026-09-02. Not the "thin
   layer once #6 exists" this row originally assumed — see the row's own
   correction above.
8. **Executive Risk Story Mode** (#7) — COMPLETE, 2026-09-02. Did not
   end up benefiting from #6 as this doc originally assumed — see the
   row's own correction above.
9. **Data-Flow Time Machine + drift detection** (#8) — split into 8a
   (`GraphSnapshot` contract + persistence + comparability — COMPLETE,
   2026-09-02) / 8b (`GraphDiff` computation + change-cause
   classification + drift policies + CLI wiring — not started). See the
   row's own correction above and
   `2026-09-02-data-flow-explorer-m4-fr503-time-machine-scoping.md` for
   the full investigation.
10. **Watch-mode graph delta updates** (#9) — reuses #8's diff engine.
11. **Third-Party and Cross-Border Intelligence** (FR-506) — needs its
    own upfront data-availability investigation (same discipline as
    SemanticZoom) before committing to a build; may turn out to need
    real new data sources this repo doesn't have, which would make it a
    partial/disclosed-limitation deliverable rather than a full build,
    same honesty standard as every prior "confirmed blocked" finding
    this session.

This order is a recommendation, not a commitment — each sub-project still
gets its own scoping pass (which may revise size/order estimates against
real code, the same way M3-UX-Filters' own scoping corrected the parent
M3-UX doc's rougher grouping) before any implementation plan is written.

## Explicitly out of scope for this document

- Any code change. This is scoping only.
- Milestone 5 (FR-502 What-If Simulator, FR-505 Digital Twin, FR-507
  Blast-Radius/Remediation, additional languages, large-graph scale,
  cross-repo federation, governance-editing workflow) — its own future
  top-level scoping pass, after Milestone 4 sub-projects are underway.
- Detailed field-level design for any of the 9 `§10.10` extension
  contracts — each sub-project's own scoping doc works that out against
  its specific FR, not this cross-cutting document.
