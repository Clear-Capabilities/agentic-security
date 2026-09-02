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
| 4 | PNG/SVG/PDF export | Large | #3's SVG serialization groundwork | The one deliverable with a real, unsolved technical problem: serializing the live SVG DOM `architecture-view.js` builds in a browser into a static file with no browser present. Needs either a headless-DOM/SVG-string-builder path reusing the view's pure layout functions, or a real headless-browser dependency (new, heavier, needs the "no runtime cloud calls / opt-in network deps" convention respected — a local headless renderer, not a cloud rendering API). PDF composites multiple SVG/PNG pages — real but mechanical once SVG export exists. |
| 5 | CLI and Claude slash commands | Small | #1–#4 (thin wiring layer) | Once export/report/MCP surfaces exist, this is mostly argument parsing + dispatch, following `commands/`'s existing 10-dispatcher pattern and `scanner/bin/agentic-security.js`'s existing `explore` subcommand precedent. Scoped last so it wires real capabilities rather than stubbing them. |
| 6 | Regulatory Obligation Overlay + evidence packs (FR-504) | Large | `ObligationMapping` extension contract (new) | Most tractable of the 4 decision-intelligence FRs — real framework/control data already exists (`docs/compliance/`, NIST catalog generator) and real per-flow governance data already exists (`flow.governanceRefs`). The new work is the mapping/predicate logic connecting graph facts to framework requirements, plus the extension contract itself and its versioned evidence-pack export (depends on #2/#4 export machinery). |
| 7 | Executive Risk Story Mode (FR-501) | Large | `DecisionStory` extension contract (new); benefits from #6 | A synthesis/ranking layer over EVERYTHING else in the graph (claims, chapters, ranking factors, evidence coverage) — genuinely new analysis logic, not a data-availability problem like SemanticZoom was. AC-25 requires it stay evidence-linked, which is checkable but adds real design constraints (can't fabricate a "chapter" with no underlying finding). |
| 8 | Data-Flow Time Machine + drift detection (FR-503) | Large | `GraphSnapshot`/`GraphDiff` extension contracts (new) | Needs a real snapshot-storage mechanism (none exists today — `.agentic-security/last-scan.json` is a single current-state file, not a history), a diff algorithm over canonical IDs, and configurable drift policy. Directly overlaps deliverable #9 (watch-mode) — same diff engine, different trigger. |
| 9 | Watch-mode graph delta updates | Medium | #8's diff engine | A file-watcher that reruns the scan and emits the same `GraphDiff` #8 produces, just triggered by filesystem events instead of an explicit "compare two snapshots" command. Real, but should NOT be scoped before #8's diff engine exists — building it first would mean redoing the diff logic twice. |
| 10 | DPIA/RoPA graph-derived export, behind migration flag | Medium–Large | #6 (Regulatory Overlay) | Explicitly "behind a migration flag" per the PRD's own text — a real signal this is meant to ship cautiously. Depends on the same governance-fact-to-obligation mapping #6 builds; a thin templating layer on top once #6 exists, not a separate mapping problem. |
| — | Third-Party and Cross-Border Intelligence (FR-506) | Large, **weakest data foundation** | `RecipientProfile` extension contract (new) | The one deliverable most likely blocked on more than code: `RecipientProfile` needs provider/legal-entity/jurisdiction/subprocessor facts that nothing in this codebase currently discovers (no provider-name resolution, no jurisdiction database, no subprocessor registry). `node.destination.literalValue` (confirmed real in M3-UX-Filters' own audit) gives a raw hostname/endpoint at best — turning that into "which legal entity, which jurisdiction, which subprocessors" is a real data-acquisition problem, not just an engineering one. Recommend its own dedicated investigation before any implementation plan, likely the last of the 4 decision-intelligence FRs to attempt. |

## Recommended sub-project order (this document's own conclusion)

1. **MCP read-only tools** (#1) — COMPLETE. Smallest, most self-contained,
   matched an existing pattern exactly.
2. **JSON/CSV export** (#2) — COMPLETE. Small, foundational for #3/#4/#6/#10.
3. **Self-contained HTML report** (#3) — COMPLETE. Medium, high reuse of already-
   shipped `frontend/` work.
4. **PNG/SVG/PDF export** (#4) — large, the one genuinely open technical
   question (headless SVG serialization) worth its own investigation
   spike before a full plan is written.
5. **CLI and Claude slash commands** (#5) — thin, wires 1–4 together.
6. **Regulatory Obligation Overlay + evidence packs** (#6) — first of the
   4 decision-intelligence FRs; most real infra to build on.
7. **DPIA/RoPA export** (#10) — thin layer once #6 exists.
8. **Executive Risk Story Mode** (#7).
9. **Data-Flow Time Machine + drift detection** (#8).
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
