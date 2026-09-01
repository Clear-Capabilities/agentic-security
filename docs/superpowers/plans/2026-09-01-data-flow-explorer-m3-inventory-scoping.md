# Milestone 3, sub-project Inventory: sortable table views

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
own Inventory row and PRD §7.6 (read verbatim this session): *"The
application must also provide sortable table views for users who cannot or
do not want to use a graph: All sources; All sinks; All fields/data
elements; All external destinations; All stores; All AI systems and
AI-processing contexts; All transformations; All unprotected or unknown
edges; All policy-permitted flows; All manual governance gaps; All
unsupported or unresolved candidates. The tables and graph must use the
same filters and canonical IDs."*

This is the fourth, currently-missing required view. `frontend/src/views/`
today has exactly three: `architecture-view.js`, `privacy-view.js`,
`trace-view.js`. No `inventory-view.js` exists.

## What already exists (confirmed by direct read this session)

- **The compute/render split every view already follows**:
  `compute<X>ViewModel(graph, state) -> plain object`, then
  `render<X>View(viewModel, canvasEl, onSelect)` appending real DOM via
  `lib/dom.js`'s `el()`/`clear()`. `privacy-view.js` is the closest
  precedent — it already renders an HTML `<table>` (not SVG), already
  reads `state.filters` to compute a per-row `visible` flag, and already
  wires row click/Enter/Space to `onSelectFlow` with `aria-label`/
  `tabindex`/`role="button"`. Inventory's own tables should follow this
  exact shape, not invent a new one.
- **`lib/state.js`** — `VALID_VIEWS = Set(['architecture','privacy','trace'])`,
  `DEFAULT_STATE = {view:'architecture', selectedId:null, filters:{}}`.
  `parseStateFromHash`/`serializeStateToHash` round-trip `view`/`selected`/
  `filters` through the URL hash only — no other state exists today.
- **`shell.js`** — `VIEWS = [{id:'architecture',...},{id:'privacy',...},
  {id:'trace',...}]` drives the tab bar (`buildViewTabs`). Adding a view is
  adding one entry here plus a `VALID_VIEWS` entry in `state.js`.
- **`app.js`** (`bootstrap`) — the only place that dispatches on
  `state.view` to pick a compute/render pair, and the only place that
  decides whether the filter rail renders (today: `if (state.view ===
  'privacy')`, else the rail shows literal text `'Filters apply to Privacy
  View.'`) and what the inspector receives (`computeInspectorViewModel(
  graph, state.selectedId)`, called unconditionally every rerender,
  independent of `state.view`).
- **`components/filter-rail.js`** — `computeFilterFacets(graph)` returns
  `{dataClasses, protectionTiers}` (a fixed `PROTECTION_TIERS` enum,
  `dataClasses` derived from `graph.dataElements`). `renderFilterRail`
  renders three chip groups: data class, protection, AI. Currently
  consumed only by Privacy View's own `rowMatchesFilters(row, filters)`,
  which reads `row.dataClasses`/`row.protectionSummary`/`row.isAiRelevant`
  — properties Privacy View's own `computePrivacyRow` computes per flow.
  **These three filter dimensions are not generic — they only mean
  something on a row that itself carries a data class, a protection
  verdict, and an AI-relevance flag.** Not every inventory category's rows
  will carry all three (see "Filter-rail integration" below).
- **`components/evidence-inspector.js`** — `computeInspectorViewModel(graph,
  selectedId)` looks up `selectedId` against `graph.flows`, then
  `graph.edges`, then `graph.nodes`, in that order, and returns `null` if
  none match. **It does NOT look up `graph.dataElements` or
  `graph.transformations`** — selecting a `data:*` or `transform:*` id
  today silently returns `null` (renders "Select a node, edge, or flow to
  see its evidence."), not a crash, but a real, currently-inert gap for
  two of the eleven inventory categories (fields, transformations).
- **`lib/protection-visual.js`**'s `worstVerdict(verdicts)` — already the
  PRD §8.4-precedence-correct way to collapse several protection verdicts
  into one, already used by `architecture-view.js:66` exactly for
  per-EDGE aggregation: `worstVerdict([edge.protection.transit.verdict,
  edge.protection.atRest.verdict, edge.protection.handling.verdict])`.
  This is the right tool for inventory category 8 ("unprotected or
  unknown edges") — reuse it verbatim, do not reimplement the backend's
  `protection.js#aggregateVerdicts` a second time (the frontend never
  imports `scanner/src/lineage/` at runtime, per this same file's own
  header comment, so a second hand-kept copy is the only option, and one
  already exists).
- **`lib/flow-path.js`**'s `AI_SUBTYPES = Set(['ai-assistant',
  'ai-model-provider','vector-store'])` and `isAiRelevantFlow` — a
  TOPOLOGY-based AI check (does a flow's path touch an AI-kind node),
  deliberately not `dataElement.aiContexts`-based, because
  `classification.js` never populates `aiContexts` from name-only
  classification. **This constant is stale against the real backend
  enum**: `scanner/src/lineage/schema.js`'s `SINK_CATEGORIES` has nine
  AI-flavored entries (`ai-model-provider, ai-local-model, ai-agent,
  ai-tool, ai-vector-store, ai-memory, ai-training, ai-evaluation,
  ai-telemetry`) and `SOURCE_CATEGORIES` has four
  (`ai-model-output, ai-tool-result, ai-retrieved-document, ai-memory`) —
  none of these is literally `'ai-assistant'` or `'vector-store'`, and the
  frontend's own `AI_SUBTYPES` set does not match the schema's own
  vocabulary. This is a pre-existing drift bug, not something this
  increment introduces, but Inventory's own "All AI systems" category
  needs the CORRECT node-subtype set to be useful, so this increment
  fixes `AI_SUBTYPES` to the real SINK/SOURCE AI categories rather than
  building a second, separately-wrong copy. `isAiRelevantFlow`'s own
  callers (Privacy/Trace views' AI badges) get this fix for free — this
  is a real bug fix, not a scope violation, and will be called out plainly
  in the ledger and `frontend/CLAUDE.md`.
- **Schema enums confirmed by direct read of `scanner/src/lineage/
  schema.js` and `validate.js`** (canonical, not guessed):
  - `NODE_KINDS = ['source','process','transform','api','store','queue',
    'log','sink','external','boundary','unresolved']`
  - `COVERAGE_STATUS_VALUES = ['modeled','partial','candidate',
    'unsupported','manual']`
  - `node.externality = {value: 'internal'|'external'|'unknown',
    evidenceRefs}` — a per-node object, separate from `node.kind`.
  - `node.destination` — non-null only on nodes `resolve-destination.js`
    resolved; `{resolutionStatus, literalValue}`,
    `DESTINATION_RESOLUTION_VALUES` has 8 values.
  - `POLICY_STATES = ['prohibited','permitted','conditionally_permitted',
    'manual_review_required','not_evaluated']` (flow-level).
  - `FLOW_SUMMARY_VALUES = ['protected','unprotected','mixed','unknown',
    'not_assessed']` (flow-level, already-aggregated).
  - `dataElement = {id, name, dataClasses[], aiContexts[]}` — no
    `evidenceRefs`, no `kind`.
  - `transformation = {id, kind, reversibility, ...}` (`TRANSFORM_KINDS`,
    `REVERSIBILITY_VALUES`).
- **The flagship fixture is 14 nodes** (confirmed this session during
  Perf's own measurement work). Table markup (no SVG-per-element cost)
  is not exposed to Perf's own finding (which was specifically about
  Architecture View's SVG rendering at 5,000+ node scale) — **this
  re-confirms the scoping table's own flagged assumption**: table-shaped
  views are not exposed to the same failure. No new performance
  measurement is warranted for this increment; if M3-Render later changes
  how large graphs are loaded client-side at all, Inventory's own table
  rendering would still need re-measurement only if row counts start
  approaching the thousands, which is exactly what virtualization
  (§17.2's own recommendation, explicitly out of scope below) would
  address.

## Decisions this scoping makes explicitly

1. **Inventory is a fourth top-level view**, not a mode of an existing
   view: `state.view === 'inventory'`, added to `VALID_VIEWS` (`lib/
   state.js`) and to `VIEWS` (`shell.js`).
2. **A new URL-state field, `table`**, selects which of the eleven
   categories is showing, mirroring `view`'s own validation shape exactly
   (a fixed enum, `parseStateFromHash` defaults an invalid/missing value
   to the first category rather than erroring). Persisted in the hash
   like `view`/`selected`/`filters` already are — bookmarkable, consistent
   with `state.js`'s own header comment on why this file exists (PRD
   §7.11, AC-16). The field is carried unconditionally (like `selectedId`
   already is across view switches) rather than only when
   `view==='inventory'` — simpler round-trip code, harmless when unused.
3. **The eleven categories, and exactly what each maps to in the real
   schema** (grounded in the enums confirmed above, not guessed):

   | # | PRD category | Row source | Filter/mapping |
   |---|---|---|---|
   | 1 | All sources | `graph.nodes` | `kind === 'source'` |
   | 2 | All sinks | `graph.nodes` | `kind === 'sink'` |
   | 3 | All fields/data elements | `graph.dataElements` | all |
   | 4 | All external destinations | `graph.nodes` | `externality.value === 'external'` |
   | 5 | All stores | `graph.nodes` | `kind === 'store'` |
   | 6 | All AI systems and AI-processing contexts | `graph.nodes` ∪ `graph.dataElements` | nodes whose `subtype` is in the corrected AI-subtype set (see above) ∪ dataElements with non-empty `aiContexts` — one table, rows tagged `subject: 'node'\|'dataElement'` so the two shapes coexist in one list without forcing a false shared column set |
   | 7 | All transformations | `graph.transformations` | all |
   | 8 | All unprotected or unknown edges | `graph.edges` | `worstVerdict([...3 dims]) !== 'protected' && !== 'not_assessed' && !== 'not_applicable'` (i.e. `unprotected`/`mixed`/`unknown` — reusing the exact `architecture-view.js:66` call) |
   | 9 | All policy-permitted flows | `graph.flows` | `policyVerdict === 'permitted'` (strict — `conditionally_permitted` is a materially different verdict and is deliberately excluded, not folded in; disclosed as a real, intentional boundary, not an oversight) |
   | 10 | All manual governance gaps | `graph.flows` ∪ `graph.nodes` ∪ `graph.edges` | `policyVerdict === 'manual_review_required'` (flows) **∪** `coverageStatus === 'manual'` (nodes/edges) — both are the schema's own literal "a human, not the analyzer, decided this" signal; a governance gap on a flow's `governanceRefs` completeness (e.g. missing `lawfulBasis`) is a DIFFERENT, real gap but not one this increment computes, because Privacy View's own per-stage completeness logic (`renderStageCell`'s `governanceKeysForStage`) is stage-conditional and copying it here risks a second, divergent copy — deliberately deferred, disclosed below |
   | 11 | All unsupported or unresolved candidates | `graph.nodes` | `kind === 'unresolved'` ∪ `coverageStatus` in `('unsupported','candidate')` |

4. **Filter-rail integration is category-scoped, not forced onto every
   table.** The rail's three chip groups (`dataClass`, `protection`, `ai`)
   are wired for the categories whose row shape genuinely carries the
   filtered property: **Fields** (`dataClasses`), **Policy-permitted
   flows** and **Manual governance gaps** where flow-shaped
   (`dataClasses`/`protectionSummary`/`isAiRelevant`, computed the same
   way `privacy-view.js#computePrivacyRow` already does). The other seven
   categories (sources/sinks/external-destinations/stores/AI/
   transformations/unprotected-edges/unsupported-candidates) render the
   rail (so the left rail is never blank/inconsistent when switching
   sub-tables — PRD's own "same filters" requirement is about a SHARED
   MECHANISM, not that every filter must have a visible effect
   everywhere) but the chips have no effect on those rows, exactly as
   `privacy-view.js` already has no effect when `state.view !== 'privacy'`
   today. This is the smallest change that satisfies "same filters and
   canonical IDs" honestly: same rail, same state shape, applied where it
   is semantically meaningful, not force-fit onto rows that don't carry
   the relevant property.
5. **`evidence-inspector.js` is extended** to also look up
   `graph.dataElements` and `graph.transformations` by id (two more
   branches in `computeInspectorViewModel`'s lookup chain and in
   `buildClaimText`), so selecting a Fields or Transformations row is not
   silently inert. This is a small, real, justified addition — without it,
   2 of 11 categories would have a clickable-looking but functionally
   dead row, which is worse than not having row selection at all.
6. **`lib/flow-path.js`'s `AI_SUBTYPES` constant is corrected** to the
   real backend AI categories (see "What already exists" above) as part
   of this increment, since Inventory's own AI category is the first
   consumer that would otherwise ship visibly wrong (empty on real data).
7. **One generic render function**, not eleven bespoke ones:
   `renderInventoryView(viewModel, canvasEl, onSelect)` renders whichever
   table `viewModel.activeTable` names, using `viewModel.columns` (header
   labels) and `viewModel.rows` (each row: `{id, selectableId, cells:
   string[]}`, `cells` already display-formatted by the per-category
   compute function) — mirroring `privacy-view.js`'s row-click/keyboard
   pattern exactly. A small sub-navigation strip (11 buttons/tabs, one per
   category, each showing its own row count) renders above the table,
   analogous to `shell.js`'s own `buildViewTabs`, and dispatches
   `onTableChange` back to `app.js` to update `state.table`.
8. **Sorting**: PRD says "sortable." Client-side, per-column, ascending/
   descending toggle on header click, string/lexicographic on the
   formatted cell text (every cell is already a string by the time it
   reaches the row) — no server-side sort, no secondary sort key. This is
   the minimum that satisfies "sortable" without inventing a query
   language (explicitly M3-UX's territory, not this increment's).

## Scope for this increment

1. `frontend/src/lib/state.js` — add `'inventory'` to `VALID_VIEWS`; add
   `INVENTORY_TABLES` (the 11 category ids, exported so `shell.js`/
   `inventory-view.js`/tests share one literal list) and a `table` field
   to `DEFAULT_STATE`/`parseStateFromHash`/`serializeStateToHash`,
   validated against `INVENTORY_TABLES` the same way `view` is validated
   against `VALID_VIEWS`.
2. `frontend/src/shell.js` — add `{id:'inventory', label:'Inventory'}` to
   `VIEWS`.
3. `frontend/src/lib/flow-path.js` — correct `AI_SUBTYPES` to match the
   real schema (see decision 6).
4. `frontend/src/components/evidence-inspector.js` — extend
   `computeInspectorViewModel`/`buildClaimText` for `data:`/`transform:`
   ids (see decision 5).
5. **New `frontend/src/views/inventory-view.js`** — `computeInventoryViewModel(graph,
   state)` (dispatches to 11 per-category compute functions per the table
   in decision 3, applies `state.filters` where decision 4 says to,
   returns `{tables: [{id,label,count}], activeTable, columns, rows}`) and
   `renderInventoryView(viewModel, canvasEl, onSelect, onTableChange)`
   (sub-nav strip + sortable `<table>`, reusing `privacy-view.js`'s
   row-click/`aria-label`/keyboard pattern).
6. `frontend/src/app.js` — add the `state.view === 'inventory'` branch
   (compute + render, same shape as the other three), extend the filter-
   rail conditional to `state.view === 'privacy' || state.view ===
   'inventory'`.
7. Tests: `frontend/test/inventory-view.test.js` (compute logic — one
   assertion block per category, using a small hand-built fixture that has
   at least one real row in every one of the 11 categories, including at
   least one manual-coverage node/edge and one `manual_review_required`
   flow, since the flagship fixture may not exercise every category),
   `frontend/test/inventory-view-render.test.js` (DOM assertions via
   `test/dom-shim.js`, mirroring `privacy-view-render.test.js`), a
   `state.test.js` addition for the new `table` field's round-trip and
   invalid-value default, and an `evidence-inspector.test.js` addition for
   the two new id namespaces. Every new test file added to
   `frontend/package.json`'s explicit `test` script list (not a glob —
   confirmed this session; a file left off the list silently never runs).
8. `xss-adversarial.test.js` — add Inventory to the views the adversarial
   fixture sweeps (the test's own DOM-sweep loop iterates a list of
   `{compute,render}` pairs; Inventory joins it since it renders
   graph-derived strings same as the other three views, and T1's own
   coverage should not silently exclude the newest view).

## Do NOT touch

- `privacy-view.js`/`trace-view.js`/`architecture-view.js`'s own rendering
  logic, beyond nothing (Inventory is additive).
- `protection.js`/`aggregateVerdicts` on the backend (`scanner/src/
  lineage/`) — this increment is 100% `frontend/`, no scanner changes.
- Privacy View's own per-stage governance-completeness logic
  (`governanceKeysForStage`) — category 10's flow-level gap detection
  deliberately does NOT reuse or duplicate this (see decision 3, row 10).
- `filter-rail.js`'s own three chip groups — no new filter dimension is
  added in this increment, even though a `kind`/`coverageStatus` filter
  would be useful for several of the node-shaped categories; that's real,
  disclosed, deferred scope (see below), not silently folded in here.
- Any server-side (`scanner/src/server/`) code — Inventory consumes the
  same `graph` object Wire already fetches; no new API route is needed.

## Test plan

1. `inventory-view.test.js` — pure compute assertions, one block per
   category, against a hand-built fixture (not the flagship graph, so
   every category — including the rarer manual/unresolved/AI ones — has
   at least one guaranteed real row).
2. `inventory-view-render.test.js` — DOM structure assertions (headers
   match `columns`, one `<tr>` per row, `aria-label`/`tabindex`/`role`
   present, sort toggles reorder rows) via `test/dom-shim.js`.
3. `state.test.js` addition — `table` round-trips through
   `serializeStateToHash`/`parseStateFromHash`; an invalid `table` value
   in the hash falls back to the first category, mirroring the existing
   `view` invalid-value test.
4. `evidence-inspector.test.js` addition — selecting a `data:*` id and a
   `transform:*` id both produce a non-null view model with the right
   `kind`.
5. `xss-adversarial.test.js` — Inventory added to the swept view list;
   run the SAME mutation-proof discipline used for XSS's own original
   suite (temporarily reintroduce a hypothetical unescaped render path in
   `inventory-view.js`, confirm the test fails, revert).
6. Full `frontend/npm test`, green, real captured exit code.
7. `scanner`'s own full gate (`npm test`) — confirm unaffected (this
   increment touches no scanner file); if `flow-path.js`'s `AI_SUBTYPES`
   fix (decision 6) has any scanner-side test that pins the OLD wrong
   values, that would be a real finding, not silently absorbed — check
   this specifically since it is the one change with any risk of a
   cross-tree assumption. (Confirmed unlikely: `flow-path.js` lives in
   `frontend/`, has no scanner-side test importing it, since `scanner/`
   never imports `frontend/`.)

## Explicitly deferred

- A `kind`/`coverageStatus`/table-specific filter chip group (useful for
  the seven categories the existing three filters don't reach) — real,
  disclosed, future work, not this increment's.
- Row virtualization (§17.2's own recommendation) — not needed at current
  fixture/graph scale; revisit if/when M3-Render changes how large graphs
  reach the client.
- Export (CSV/JSON) of an inventory table — not named in PRD §7.6 itself;
  Server's own `POST /api/v1/export` (S2, unscoped) is the more likely
  future home for this if it's ever requested.
- Flow-level governance-completeness detection for category 10 beyond the
  two literal "manual" signals already used (see decision 3, row 10, and
  "Do NOT touch").
- A11y-specific work (contrast, viewport reflow — Sub-project A11y's own
  scope, which explicitly depends on Inventory existing first).
