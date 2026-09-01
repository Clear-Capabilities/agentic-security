# Milestone 3, sub-project UX: semantic zoom, search, query language, focus controls, saved views

Per the M3 parent scoping doc's own Decision 7 (deliberately deferred
until after the Perf/Render stack question resolved — it now has):
*"semantic zoom, search, query language, focus controls, and saved
views (§7.2/§17.2's own 'and' list)... its own shape depends entirely
on Decision 1's own outcome... A future, dedicated scoping pass, after
M3-Perf resolves the stack question, is the honest way to handle this."*
M3-Render resolved that question (a narrow SVG fix, not a stack
migration) — this is that dedicated pass. Per the user's own explicit
choice (2026-09-01, over starting Milestone 4/5 instead).

## PRD text read verbatim this session

- **§15.1 (18 named filter dimensions)**: data class; exact field/access
  path; AI processing context; application/service/environment; source
  category; sink category; external/internal/unknown destination;
  provider/recipient/host/database/table/topic; trust-zone crossing;
  transit/at-rest/handling verdict; policy verdict; evidence grade and
  confidence; language/framework; finding severity; governance gap;
  introduced commit/author/date (provenance); new/changed/unchanged/
  removed flow between scans.
- **§15.2 (query language)**, exact examples: `class:PCI AND
  sink:(log,database,external_api)`, `class:PHI AND
  transit.verdict!=protected`, `ai:true AND class:(PII,PHI) AND
  destination.external:true`, `field:"card_number" AND (handling:raw OR
  at_rest:unknown)`, `policy:permitted AND destination:external`,
  `coverage:(partial,unsupported,unknown)`. *"The query parser must
  reject invalid syntax with an actionable error and may not silently
  broaden a malformed query."*
- **§15.3 (9 named focus controls)**: Show upstream; Show downstream;
  Show all paths; Show shortest path; Show external paths only; Show
  unprotected and unknown paths only; Show alternate names/aliases; Show
  disconnected sources/sinks; Reset to application overview.
- **§7.2/§7.8/§7.9** (saved views, named examples): `PCI Exposure`
  (Architecture View's own left rail), `AI + Regulated Data` (Privacy
  View's own left rail).
- **§21's own closing sentence** (already partly addressed by M3-Render):
  *"Large graphs must use semantic zoom, server-side or worker-side
  projections, clustering, and visible-element limits."* — semantic zoom
  here specifically means *"reveal endpoint, function, and field detail"*
  (§7.3, DFG-030) as a user zooms into ONE node — a DIFFERENT concept
  from M3-Render's own "reveal more NODES" clustering, not yet
  implemented.

## What already exists (confirmed by direct read this session)

- **`components/filter-rail.js`** has exactly 3 real filter dimensions
  today (`dataClass`, `protection`, `ai`) — a tiny fraction of §15.1's
  18. `computeFilterFacets`/`renderFilterRail` are pure/thin-render,
  matching every other component's split.
- **A per-dimension audit against REAL scan output (not just schema
  presence) found several §15.1 dimensions are honestly non-functional
  today**, confirmed by direct grep of `graph-builder.js`/
  `classification.js`, not assumed from the schema alone:
  - **Real, populated by real scan code**: data class
    (`dataElement.dataClasses`), source/sink category (`node.subtype`),
    external/internal/unknown destination (`node.externality.value`),
    provider/host (`node.destination.literalValue`,
    `node.storeDetail`/`node.queueDetail`, when resolved),
    transit/at-rest/handling verdict (`edge.protection.*.verdict`),
    policy verdict (`flow.policyVerdict`), evidence grade/confidence
    (`evidence.confidenceTier`, `protection.*.evidenceGrade`),
    governance gap (`flow.governanceRefs`), application
    (`node.system.application`), environment (`node.system.environment`
    — real when an operator supplies `opts.environment`/
    `AGENTIC_SECURITY_ENVIRONMENT`, `null` otherwise — same real
    mechanism Milestone 2's own Sub-project G already uses).
  - **Present in the schema but confirmed NEVER populated by real scan
    code, only cosmetically present in the hand-built flagship
    fixture**: AI processing context (`dataElement.aiContexts` — always
    `[]`, per `classification.js`'s own explicit comment, already
    established this session's Inventory sub-project); trust-zone
    crossing (`edge.boundaryCrossings` — always `[]`, confirmed by
    direct grep of `graph-builder.js`); introduced commit/author/date
    (`evidence.commit`/`evidence.timestamp` — always `null` in real
    scan output, confirmed by direct grep; only the fixture builder sets
    illustrative values).
  - **No backing data anywhere in the schema, confirmed absent**:
    language/framework (no such field on any node/edge); finding
    severity (findings are a SEPARATE SAST concept, not part of
    `DataFlowGraph v1` at all — a real, structural layering question,
    not a small gap); new/changed/unchanged/removed flow between scans
    (no scan-history/diff mechanism exists anywhere in this codebase).
  - **This changes what "expand the filter rail" honestly means**: of
    18 named dimensions, roughly 9 are real and buildable today, 3 are
    schema-present-but-inert (would show empty/inert facets against
    real data — misleading if shipped as-is), and 3 have no backing
    data at all (real, separately-scoped future work, likely spanning
    both the lineage engine AND the SAST-findings layer for severity).
- **`architecture-view.js`'s `resolveSelection`/dimming mechanism**
  (already real, already tested, extended by M3-Render this session)
  is the EXACT primitive focus controls need: `selection.nodeIds`/
  `edgeIds` already drive which content is "highlighted, not removed."
  §15.3's 9 controls are all real, well-defined GRAPH TRAVERSAL problems
  over `graph.edges` (upstream = walk `edge.to === X` backward,
  downstream = walk `edge.from === X` forward, shortest path = BFS,
  disconnected = nodes with no edges at all) — no new rendering
  paradigm, no new schema, a pure function over data this session
  already reads/writes constantly.
- **No query-language parser exists anywhere in `frontend/`** — confirmed
  by grep. §15.2's syntax (`field:value`, `AND`/`OR`, parenthesized
  groups, comparison operators `!=`) is a real, small, well-specified
  DSL — a hand-written recursive-descent parser is a reasonable, self-
  contained scope (no new dependency needed; this is exactly the kind of
  small grammar a hand-rolled tokenizer+parser handles well, and this
  codebase already avoids new dependencies on principle).
- **No saved-view concept exists anywhere** — confirmed by grep (no
  `PCI Exposure`/`AI + Regulated Data` string, no saved-view data
  structure). Once a query language exists, a "saved view" is a thin
  layer: a named `{label, query}` pair, computed against the REAL
  current graph rather than hardcoded — the two PRD-named examples
  (`PCI Exposure`, `AI + Regulated Data`) are the two natural first
  real saved views, expressible directly in the new query syntax
  (`class:PCI`, roughly `class:(PII,PHI) AND ai:true` respectively —
  exact query text is real implementation work, not decided here).
- **No search box exists anywhere.**
- **Semantic zoom (§7.3/DFG-030's own "reveal endpoint, function, field
  detail") has NO backing data investigated yet** — does any node carry
  function/field-level detail beyond what's already surfaced
  (`node.storeDetail.columns`, `node.queueDetail.topic`)? Not
  investigated this pass; a real, disclosed open question for a future,
  separate scoping increment (see Explicitly Deferred).

## Decisions this scoping makes explicitly

1. **This sub-project is split into its own sub-project table, mirroring
   the parent M3 scoping doc's own two-level pattern** — M3-UX itself is
   too large for one scoping+plan+implementation cycle, exactly the
   reasoning that made M3 itself need a sub-project breakdown.
2. **Priority order is Query Language + Focus Controls FIRST** — both
   are fully specified by the PRD's own exact text (§15.2's syntax
   examples, §15.3's exact 9 control names), both are pure functions
   over already-real graph data (no new schema, no new rendering
   paradigm), and Focus Controls directly reuses Architecture View's
   existing dimming mechanism. This is the highest-value, lowest-risk,
   most self-contained increment — real, immediately useful capability,
   not scaffolding for something else.
3. **Expanded filter dimensions (§15.1) are scoped to the 9 REAL,
   populated dimensions only** (decision area above) — never shipping a
   filter chip for a facet that's always empty against real scan data,
   which would be actively misleading (a user sees an "AI processing
   context" filter, tries it, gets zero results forever, and reasonably
   concludes something is broken rather than "this facet has no real
   producer yet"). The 3 inert-but-schema-present dimensions and the 3
   entirely-unbacked ones are named, not silently dropped — see
   Explicitly Deferred.
4. **Saved views ride along with Query Language** (decision area
   above) — a thin layer once the query parser exists, and the PRD's
   own two named examples are natural, real, concrete test cases for
   the parser itself, not separate scope.
5. **Search is bundled into the Query Language sub-project too** — the
   simplest real form of "search" (free-text match against node labels/
   dataElement names) is naturally a further clause type
   (`text:"card_number"` or similar) in the SAME query grammar, not a
   parallel, separately-architected feature.
6. **Semantic zoom is explicitly OUT of this pass** — its own data
   availability is unconfirmed (decision area above), and building UI
   for a detail level the graph may not carry would risk exactly the
   "misleading inert facet" problem decision 3 already rejects for
   filters. Gets its own future scoping pass once/if the data question
   is resolved.

## Scope for this increment (M3-UX sub-project table)

| # | Sub-project | Depends on | Size | What it delivers |
|---|---|---|---|---|
| Query | **Query language parser + Focus controls + Saved views + basic text search — COMPLETE (2026-09-01)** | Render | Large | Shipped: `lib/query-language.js` (tokenizer/parser/evaluator), `lib/focus-controls.js` (9 real traversals), `components/query-bar.js` (input/error/saved-view chips), wired into Privacy/Inventory filtering and Architecture View's selection via a new optional `computeArchitectureViewModel` 3rd parameter. Two real, disclosed data-vocabulary mismatches found by testing against the real fixture (sink category naming; node.aliases only non-empty in the hand-authored fixture, never in real scan output). Independently re-verified end-to-end in a real browser (query narrowing, malformed-query safety, focus-control dimming) beyond the committed unit-test suite. Full results in `frontend/CLAUDE.md`'s own Query section. |
| Filters | **Expand filter-rail.js to the real dimensions — COMPLETE (2026-09-01)** | Query | Medium | Shipped: `lib/row-filters.js` (shared, deduplicated matcher, closing a real pre-existing bug where Inventory's own filter logic never checked the AI toggle at all), 7 new chip groups (source/sink category, destination externality, transit/at-rest/handling verdict, policy verdict) wired into Privacy and Inventory's flow-shaped rows. A real surprise finding: the flagship fixture has zero `kind:'sink'` nodes, so that facet is genuinely empty against it. Provider/host, application, environment, and evidence-grade/governance-gap dimensions remain explicitly deferred. Full results in `frontend/CLAUDE.md`'s own Filters section. |
| SemanticZoom | **Endpoint/function/field-level detail on zoom — INVESTIGATED, CONFIRMED BLOCKED (2026-09-01)** | Filters | Unscoped (not attempted) | Not buildable this session. Confirmed by direct grep of `scanner/src/lineage/{schema,validate,graph-builder}.js`: `node.location` is unconditionally `null` on every node (nodes are category-granular, not call-site-granular), and no `functionName`/`fieldDetail`/`endpointDetail`/`symbolDetail` field exists anywhere in the schema — `storeDetail`/`queueDetail` are the only per-node detail objects and are already fully surfaced. §21's own "semantic zoom" (large-graph node reveal) is already satisfied by M3-Render's clustering. §7.3/DFG-030's richer "reveal endpoint/function/field on zoom" sense needs a real scanner-side schema change (a new per-node call-site array or per-call-site node minting) — genuinely backend work, not a frontend increment, so nothing was built to fake it. Full writeup: `2026-09-01-data-flow-explorer-m3-ux-semanticzoom-disposition.md`. |

**This document scopes Query only in detail below** — Filters and
SemanticZoom got their own follow-on passes once Query's own real
predicate-evaluation engine existed to build on (Filters, completed) or
the data question was answered (SemanticZoom, investigated and found
blocked on backend work), matching the parent M3 doc's own "don't
pre-scope what a prior increment's outcome should determine" discipline.

## Query language sub-project: what it delivers, in detail

1. **A tokenizer + recursive-descent parser** for the exact grammar
   §15.2 specifies: `field:value`, `field:!=value`, `field:(a,b,c)`
   (multi-value OR shorthand), boolean `AND`/`OR` (implicit precedence:
   `AND` binds tighter than `OR`, matching every common query-language
   convention and the PRD's own examples' implied grouping), parenthesized
   sub-expressions, and quoted string values (`field:"card_number"`).
2. **A field-name → real-graph-accessor mapping** — `class` →
   `dataElement.dataClasses`, `sink` → sink-kind node's own `subtype`,
   `transit.verdict`/`at_rest.verdict`/`handling.verdict` →
   `edge.protection.*.verdict`, `ai` → topology-based AI relevance
   (reusing `flow-path.js`'s own `isAiRelevantFlow`, NOT
   `dataElement.aiContexts`, which decision area above confirms is
   always empty), `field` → `dataElement.name`, `policy` →
   `flow.policyVerdict`, `destination.external` →
   `node.externality.value === 'external'`, `coverage` →
   `node.coverageStatus`. Each mapping's exact field/accessor is real
   implementation work for the plan, grounded in the schema fields this
   scoping pass already confirmed are real and populated.
3. **9 focus controls**, each a named graph-traversal producing a
   `{nodeIds, edgeIds}` set fed into the SAME `selection`-shaped object
   `resolveSelection`/`computeArchitectureViewModel` already consume —
   no new rendering path, only new ways to COMPUTE the selection:
   upstream/downstream (directed BFS from the selected node against
   `edge.from`/`edge.to`), all paths (union of both), shortest path
   (BFS with parent-tracking between two selected endpoints), external-
   only / unprotected-only (the query engine's own predicate, applied as
   a graph-wide filter rather than a from-one-node traversal), aliases
   (`node.aliases`, already a real schema field), disconnected (nodes
   with zero edges), reset (the existing `resolveSelection(graph, null)`
   empty case, already real).
4. **A real, actionable parse-error UI** — the query bar shows the
   malformed query's own real error (not a generic "invalid query"),
   and — the PRD's own explicit requirement — never silently broadens to
   "show everything" on a parse failure; the graph stays at its
   PREVIOUS valid filter state until a valid query replaces it.
5. **Saved views** (`PCI Exposure`, `AI + Regulated Data`) as two real,
   computed, selectable presets in the left rail, each just a stored
   query string run through the same parser/predicate engine.
6. **Basic text search** (`text:"..."` or a bare unquoted term,
   implementer's own exact grammar choice, disclosed) matching node
   labels and `dataElement.name` — the simplest real form of "search"
   the PRD's own §15 section groups alongside filtering, not a separate
   UI paradigm.

## Do NOT touch

- Any view's own rendering internals beyond wiring the new selection/
  filter predicate through the SAME `state.selectedId`/`state.filters`
  contract every view already consumes — this is a NEW predicate
  ENGINE, not a new state shape (though `lib/state.js`'s `filters`
  object likely needs a new key for the raw query string itself,
  alongside the existing `dataClass`/`protection`/`ai`/`table` keys —
  real, small, disclosed addition, not a redesign).
- `scanner/` — 100% frontend, no schema changes; the query engine reads
  fields that already exist.
- Semantic zoom, the 6 inert/unbacked filter dimensions, cross-scan
  diffing, finding-severity filtering (decisions 3/6 above).
- M3-Render's own clustering/pan-zoom code — Query's focus controls
  compute WHICH nodes are selected; M3-Render's own culling/clustering
  logic already handles rendering whatever is selected/visible
  correctly (a selected node already bypasses clustering, per that
  sub-project's own real correctness property) — no changes needed
  there.

## Explicitly deferred

- SemanticZoom sub-project (its own future scoping pass).
- Filters sub-project's own detailed scoping+plan (named here, not
  built yet — depends on Query's own predicate engine landing first).
- The 6 confirmed-inert/unbacked filter dimensions (decision 3) — real,
  disclosed, future backend/schema work (language/framework detection,
  boundaryCrossings population, evidence commit/timestamp population
  from real git-blame-style provenance, a findings↔lineage-graph
  bridge for severity, a scan-history/diff mechanism).
- Any UI beyond the query bar/saved-view chips/focus-control menu itself
  — e.g. a visual query-builder (drag-and-drop facets), autocomplete,
  or query history — real, disclosed, deferred polish.
