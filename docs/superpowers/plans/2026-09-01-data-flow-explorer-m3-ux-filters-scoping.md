# M3-UX, sub-project Filters: expand filter-rail.js to the real dimensions

Per the M3-UX parent scoping doc's own sub-project table: *"Expand
filter-rail.js to the 9 real dimensions... Explicitly does NOT add UI for
the 6 inert/unbacked dimensions."* Depends on Query (COMPLETE) — shares
its real-vs-inert audit and, where sensible, its value-extraction logic.

## What already exists (confirmed by direct read this session)

- **`components/filter-rail.js`** has exactly 3 facets today: `dataClass`
  (multi-select chips over `dataElement.dataClasses`), `protection`
  (multi-select chips over the flow-level `protectionSummary` aggregate —
  NOT the three separate transit/atRest/handling dimensions), `ai` (a
  single boolean toggle). `computeFilterFacets(graph)` is pure
  (`{dataClasses, protectionTiers}`); `renderFilterRail` is thin-render.
  `state.filters` is a plain object of simple keys (arrays or booleans) —
  NOT query-AST-based. `rowMatchesFilters` (duplicated per-view, in both
  `privacy-view.js` and `inventory-view.js`) ANDs every active filter key
  against a row's own precomputed properties.
- **Query's own `FIELD_ACCESSORS`** (`lib/query-language.js`) already
  computed the exact same "real, populated field" audit this sub-project
  needs, and already has real, tested accessor logic for: `class`,
  `field`, `sink`, `source`, `transit.verdict`, `at_rest.verdict`,
  `handling.verdict`, `policy`, `coverage`, `ai`, `destination.external`.
  **This sub-project reuses that audit's OWN CONCLUSIONS (which
  dimensions are real) but NOT its machinery** — chip-based filtering is
  deliberately kept as the SAME simple, non-query-syntax mechanism
  `dataClass`/`protection`/`ai` already use (plain arrays/booleans in
  `state.filters`, ANDed together), not built on top of the AST/predicate
  engine. This is a real, deliberate design decision (below), not an
  oversight — a chip-based rail exists specifically so a user who has
  never seen `class:PCI AND ai:true` syntax can still filter, and forcing
  every chip click to construct/parse a query string would defeat that.
- **`rowMatchesFilters` is duplicated, not shared**, between
  `privacy-view.js` and `inventory-view.js` — confirmed by reading both;
  each has its own near-identical function. Adding facets to BOTH without
  first deduplicating would triple the duplication. This sub-project
  extracts a SHARED `matchesFilters(row, filters)` into a new
  `lib/row-filters.js`, consumed by both views — a real, disclosed,
  in-scope refactor, not scope creep, since building 6 more facets twice
  over would be the actual creep.

## Decisions this scoping makes explicitly

1. **The 9 real dimensions, made concrete** (resolving the parent
   scoping doc's own rougher grouping into exact filter-rail facets,
   matching Query's own field granularity where the PRD groups multiple
   verdicts under one name):
   | # | PRD §15.1 name | New filter key | Real values source |
   |---|---|---|---|
   | 1 | data class | `dataClass` (existing) | `dataElement.dataClasses` |
   | 2 | source category | `sourceCategory` | `node.subtype` where `kind==='source'` |
   | 3 | sink category | `sinkCategory` | `node.subtype` where `kind==='sink'` |
   | 4 | external/internal/unknown destination | `destinationExternality` | `node.externality.value` |
   | 5 | transit verdict | `transitVerdict` | `edge.protection.transit.verdict` |
   | 6 | at-rest verdict | `atRestVerdict` | `edge.protection.atRest.verdict` |
   | 7 | handling verdict | `handlingVerdict` | `edge.protection.handling.verdict` |
   | 8 | policy verdict | `policyVerdict` | `flow.policyVerdict` |
   | 9 | AI processing context | `ai` (existing, unchanged) | topology-based, `flow-path.js`'s `isAiRelevantFlow` |

   This is 8 NEW facets plus the 1 already-shipped `ai` toggle — the
   parent doc's own "9 real dimensions" count folded `ai` in as
   already-done; this table makes the full real set explicit rather than
   leaving "9" ambiguous between "9 total" and "9 new."
2. **The existing `protection` (flow-level aggregate) facet is KEPT,
   unchanged, alongside the 3 new per-dimension verdict facets** — not
   replaced. `protectionSummary` (the flow's own worst-verdict rollup)
   answers a different, still-useful question ("is this flow's overall
   posture concerning") than `transitVerdict`/`atRestVerdict`/
   `handlingVerdict` (which edges to look at). Both stay.
3. **Provider/host/database/table/topic (PRD §15.1's own 4th named
   dimension) is explicitly NOT built** — re-confirmed this pass: the
   real data exists (`node.destination.literalValue`, `node.storeDetail`,
   `node.queueDetail.topic`) but only for a subset of nodes (destinations
   the resolver actually resolved, stores, queues) — a chip-based
   multi-select over these would need real design work to decide what
   "no value" means for a node this doesn't apply to, and the query
   language doesn't have an accessor for it yet either (Query's own
   `FIELD_ACCESSORS` never added a `provider`/`host` key — confirmed by
   re-reading that file this session). Deferred, not silently dropped —
   named here explicitly.
4. **Application/environment (PRD §15.1's 4th-named-group's own other
   two members) are ALSO explicitly deferred**, despite being real,
   populated fields (`node.system.application`,
   `node.system.environment`) — re-confirmed this pass they are real, but
   `node.system.application` is virtually always a SINGLE value across an
   entire scan (one repository), making it a low-value filter facet (a
   one-item, always-selected chip group), and `environment` is `null`
   unless an operator explicitly configures it, which the flagship
   fixture and most real scans do not — a facet that is usually
   unpopulated is the same "misleading inert chip" problem this whole
   sub-project exists to avoid. Real, disclosed, deferred — a future
   increment can revisit if multi-application/multi-environment scanning
   becomes common.
5. **Evidence grade/confidence and governance gap (2 more of the
   parent doc's "9 real dimensions") are ALSO deferred this increment** —
   re-confirmed real (`evidence.confidenceTier`, `edge.protection.*.
   evidenceGrade`, `flow.governanceRefs`) but structurally different from
   the other 8: confidence/evidence-grade are PER-CLAIM properties (an
   edge can have three different evidenceGrades across its three
   protection dimensions), and `governanceRefs` is a sparse, per-key
   object (`recipient`/`purpose`/`lawfulBasis`/`retention`/`deletion`/
   `transfer`), not a single enumerable value — both need real design
   work (which of several possible values does a chip represent?) beyond
   this increment's own time budget. Named, not silently dropped.
6. **`lib/row-filters.js` (new) deduplicates `rowMatchesFilters`** out of
   `privacy-view.js`/`inventory-view.js` into one shared, tested function
   — real, necessary, in-scope refactor (decision area above).

## Scope for this increment

1. `frontend/src/components/filter-rail.js` — `computeFilterFacets`
   gains the 5 new value-sets (source category, sink category,
   destination externality, transit/atRest/handling verdicts — computed
   directly from `graph.nodes`/`graph.edges`, same simple `[...new
   Set(...)].sort()` pattern `dataClasses` already uses, no dependency on
   `query-language.js`). `renderFilterRail` gains 7 new chip groups (the
   6 new facets — source/sink category, destination externality,
   transit/atRest/handling verdict — plus keeping `policyVerdict` as an
   8th; re-count exactly 7 new groups against the table in decision 1
   when implementing, since `ai`/`protection`/`dataClass` are pre-
   existing).
2. `frontend/src/lib/row-filters.js` (new) — the shared,
   deduplicated `matchesFilters(graph, row, filters)`, replacing both
   views' own private copies.
3. `frontend/src/views/privacy-view.js` / `inventory-view.js` — call the
   new shared function instead of their own private ones; extend
   `FILTERABLE_TABLES`-equivalent gating in `inventory-view.js` if a new
   facet needs row data a given table doesn't carry (real implementation
   judgment, disclosed).
4. Tests for every new facet's real-value computation and real filtering
   behavior against the flagship fixture.

## Do NOT touch

- Query's own `lib/query-language.js`/`lib/focus-controls.js` — reused
  only for their AUDIT CONCLUSIONS (which fields are real), never their
  code.
- Provider/host, application/environment, evidence grade/confidence,
  governance gap (decisions 3-5) — real, deferred, disclosed.
- `scanner/` — frontend-only, every field here is already real and
  populated.
- Architecture View — filter-rail was already deliberately not applied
  there (a pre-existing scoping decision from before this session), and
  this increment does not revisit that.

## Test plan

1. `computeFilterFacets` real-value tests for each of the 5-6 new facet
   value-sets against the flagship fixture (ground every expected set
   against the real committed data, not guessed).
2. `matchesFilters` real filtering-behavior tests, one per new facet,
   plus a multi-facet AND test.
3. Render-level tests confirming the new chip groups appear and toggle
   correctly.
4. Full `frontend/npm test` + `scanner/npm test`, both green.

## Explicitly deferred

- Provider/host/database/table/topic, application, environment, evidence
  grade/confidence, governance gap (decisions 3-5).
- SemanticZoom (the M3-UX sub-project table's own 3rd, still-fully-
  unscoped entry).
- Any UI beyond chip groups (a facet search box, a "clear all filters"
  button, filter presets beyond Query's own 2 saved views) — real,
  disclosed, future polish.
