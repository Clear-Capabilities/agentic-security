# frontend/

Data Flow Explorer's clickable prototype. See `README.md` for the
zero-build-step rationale and how to run it.

**Milestone 3, sub-project Wire — COMPLETE (2026-09-01):** the prototype no
longer consumes `FLAGSHIP_GRAPH` via a static import — `index.html` now
loads `src/main.js`, which fetches the graph live from the `explore` server
(`scanner/src/server/`) over `GET /api/v1/graph`, authenticated via a
session token carried in the URL fragment (`#token=...`), and hands the
result to the SAME, UNCHANGED `bootstrap()`. `src/data/flagship-graph.js`
and its parity test are unaffected — they're still the fixture the backend
serves, just no longer imported directly by the page. See
`scanner/src/server/CLAUDE.md`'s own "Sub-project Wire" section for the
server-side half (the new static-asset allowlist, the deliberate
token-exemption on static routes) and this file's own `src/lib/api-client.js`
/ `src/main.js` rows below for the frontend-side half.

**Milestone 3, sub-project Perf — MEASURED, real result (2026-09-01):**
the zero-build-step deferral of PRD §17.2's conditional React/Cytoscape/
ELK recommendation was sound reasoning at Milestone 0 but untested until
now. A real Chrome measurement against a real, `validateGraph()`-clean
5,000-node/10,000-edge synthetic graph (PRD §21's own reference scale)
found the current renderer **fails first-meaningful-paint badly** — no
real `first-paint` entry after 20+ seconds, `Page.captureScreenshot`
timing out reproducibly, while the JS thread stayed fully responsive
(the harness's own `requestAnimationFrame`-based timer FALSELY reported
338ms "done" — a real, confirmed gap between "JS thinks it's finished"
and "the browser has actually painted anything," which is why this had
to be measured in a real browser with real paint-API verification, never
a JS-timer-only benchmark). Growth is clearly non-linear (1,000/2,000:
332ms real first-paint; 2,500/5,000: 920ms — already worse than linear).
Pan/zoom interaction (the SAME dimension's other P0 metric) does not
exist as a feature at all yet. See
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-perf-result.md`
for the full measurement. **This does NOT block work at the current
flagship-fixture scale** (14 nodes/15 edges, far below where the failure
manifests) — M3-Server and M3-Wire proceed unaffected — but a dedicated
rendering-architecture sub-project (M3-Render, its own future scoping
pass) is now real, necessary, disclosed work that must land before
Inventory/large-scale interactive features (semantic zoom, search) are
built on the current unclustered, hand-rolled-SVG-per-element renderer.
`frontend/scripts/generate-perf-graph-module.mjs` is kept as reusable
before/after measurement infrastructure for that future sub-project.

**Milestone 3, sub-project Inventory — COMPLETE (2026-09-01):** the fourth,
previously-missing required view (PRD §7.6) — sortable tables for all 11
named categories (sources, sinks, fields/data elements, external
destinations, stores, AI systems & processing contexts, transformations,
unprotected/unknown edges, policy-permitted flows, manual governance gaps,
unsupported/unresolved candidates), sharing filters and canonical IDs with
the graph views. Full design rationale, the exact category→schema mapping,
and every disclosed decision are in
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-inventory-scoping.md`
and its companion plan doc — see `src/views/inventory-view.js`'s own row
below for the module summary. Two small, real fixes rode along: `lib/
flow-path.js`'s `AI_SUBTYPES` constant was corrected (the previous set —
`'ai-assistant'`, `'vector-store'` — matched neither the real backend
`SOURCE_CATEGORIES`/`SINK_CATEGORIES` enum and silently never matched any
real node) and is now exported for `inventory-view.js` to reuse; `
components/evidence-inspector.js` now also resolves `data:*`/`transform:*`
canonical ids, not just `flow:*`/`edge:*`/`node:*`. Table-shaped rendering
was confirmed NOT exposed to Perf's own SVG-per-element scaling failure
(no new performance measurement was needed at current fixture scale).
**Table-shaped views are not fully mutually exclusive** — a node can
legitimately appear in more than one category (e.g. a `kind:'sink'` node
with an AI-flavored `subtype` appears in both Sinks and AI systems); this
was confirmed during implementation, not assumed. Filter-rail integration
is deliberately category-scoped, not forced onto every table — see
`FILTERABLE_TABLES` in `inventory-view.js`.

**Milestone 3, sub-project A11y — MEASURED, real result (2026-09-01):**
proves AC-20 (contrast/redundancy) and AC-21 (viewport reflow) with
automated tests plus a real CDP-driven measurement pass, and fixes two
real, disclosed bugs found along the way. Full rationale in
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-a11y-scoping.md`
and its companion plan.

- **AC-20 (automated, `test/tokens-contrast.test.js` +
  `test/protection-visual.test.js`)**: found and fixed a real, pre-existing
  WCAG AA violation — the light theme's `--status-protected` (#1E8A4C) and
  `--status-unknown` (#9A6B00) both failed 4.5:1 against `--surface-panel`
  (4.07:1 and 4.36:1). Darkened to `#1C8047`/`#956700` (verified via this
  repo's own `contrastRatio()`, now >=4.6:1 against both
  `--surface-canvas` and `--surface-panel`, comfortably above the exact
  boundary rather than sitting on it). The dark theme was already
  compliant on every pair. Every verdict's glyph/label/lineStyle
  redundancy is now a structural test, not a convention — and no two
  verdicts share a glyph (confirmed, not just asserted).
- **Keyboard-focus parity (`test/keyboard-focus-parity.test.js`)**: swept
  all four views' real rendered DOM. No gap found anywhere, including
  Architecture View's SVG nodes/edges (checked specifically, since they
  are not native `<button>`s) — every interactive element already had
  `tabindex`.
- **AC-21 (real CDP measurement, this session)**: served a real graph via
  `agentic-security explore` and drove Chrome directly at all four named
  viewports (1280×720, 1440×900, 1680×945, 2560×1440), confirming
  `window.innerWidth` matched the target at each size (screenshot pixel
  dimensions alone are not reliable evidence — they can be scaled for
  transport — so this was checked via `getComputedStyle`/`window.
  innerWidth`, not by eyeballing an image). Findings:
  - **PASS, all four viewports**: no console errors; all four views
    (Architecture, Privacy, Trace, Inventory) render and are reachable;
    `.shell`'s grid sizing matches §7.7's token-driven spec exactly at
    every width (left rail 248px/56px-collapsed, inspector fixed at the
    360px reference width even at 2560px — it does not stretch, canvas
    absorbs the extra space, which is correct per §7.7: only the canvas
    is fluid).
  - **PASS, the inspector-overlay fix (this sub-project's own CSS/JS
    change) verified working, not just shipped**: at 1280×720, selecting
    a node populated the inspector; clicking the new "Inspector" toggle
    made a REAL overlay slide in with real content (confirmed via
    `aria-expanded`/`data-overlay-open` both flipping to `"true"` and the
    Evidence Inspector panel becoming visually present, not just present
    in the DOM). Above 1280px the toggle is hidden and the inspector
    renders in-grid automatically, no click needed — confirmed at
    1440×900. The bug this sub-project set out to fix (inspector
    permanently unreachable via `display:none` at exactly the smallest
    required viewport) is closed and directly observed closed, not
    assumed from reading the CSS alone.
  - **Real, disclosed, NON-blocking finding**: at the collapsed 56px left
    rail (≤1280px), both the rail's plain-text fallback ("Filters apply
    to Privacy View and some Inventory tables.") and Inventory/Privacy's
    filter-rail chip labels wrap into a very narrow (~24px content-width,
    after the rail's own padding) column, becoming hard to read at a
    glance. This is NOT an AC-21 violation as literally written — no
    character is hidden (real wrapped text, not `overflow:hidden`/
    ellipsis-truncated), font-size stays at the real 13px `--font-size-
    body` token (>=12px), and every control remains genuinely clickable
    (confirmed, not assumed) — but it is a real, pre-existing UX rough
    edge, not introduced by this sub-project, worth a future increment's
    attention (the 56px collapsed width likely was designed for icon-only
    content; nothing currently switches to icons at that width — full
    sentence/label text renders unconditionally regardless of collapsed
    state).
  - Real graph used for this measurement was small (a scan of `frontend/`
    itself, 3 nodes/0 edges/0 flows) — sufficient to prove the SHELL-level
    layout property (regions, overlay, sizing) this sub-project exists to
    verify, but not a stress test of dense content at these viewports;
    that remains M3-Render's own, separately-scoped territory once it
    exists.

**Milestone 3, sub-project Golden — COMPLETE (2026-09-01):** golden-DOM
regression tests proving already-shipped view content still renders the
flagship fixture's PRD-named reference compositions, plus an honest
resolution of AC-22's §8.4 11-state visual matrix. Not new feature work —
see `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md`
for the scoping pass and its full reasoning.

- **AC-16/17/18/19 (real content, real regressions, `test/golden-*.test.js`,
  184 assertions in three prior commits under this sub-project plus this
  increment's 11)**: Architecture View's 9 named reference nodes and 5
  named trust zones, flow-selection dimming (present-but-dimmed, never
  removed from the DOM), and the raw/masked PCI-in-logs branches' distinct
  verdicts (`golden-architecture.test.js`); Privacy View's 3 named
  data-class fields preserving identity across all 6 lifecycle-stage
  columns and the real (lowercase, machine-value) `manual_required`/
  `unknown`/`review`/`not_found` governance signal text, not the PRD
  prose's `MANUAL REQUIRED` casing (`golden-privacy.test.js`); Trace View's
  real ordered steps, both field-rename mappings, the external HTTP hop's
  visibly-flagged unprotected trust-boundary crossing, and each alternate
  destination's own individual verdict — including two alternates that
  share a destination label (`Application Logs`) but render different
  verdicts, proving per-item verdicts rather than one shared verdict per
  destination (`golden-trace.test.js`); and AC-16's cross-view
  state-persistence — selection and filters survive a real, dispatched tab
  click from Architecture to Privacy, with the header/coverage-banner DOM
  content byte-identical before and after (`golden-shell-state.test.js`).
  **Real, disclosed finding**: the cleartext payment flow's real computed
  trace is **4 steps**, not the 5 named in PRD §7.10's own illustrative
  table — the table's separate SERIALIZATION step is not something the
  current `computeTraceSteps` output produces as its own step. Every
  assertion in `golden-trace.test.js` is grounded in the real function
  output, never the PRD table's own step count.
- **AC-22 (the §8.4 11-state visual matrix) — honestly split, not silently
  narrowed**: only 3 of the 11 named states have real, already-shipped UI.
  Those 3 get real golden-DOM tests in `test/golden-state-matrix.test.js`:
  **Error** (`main.js`'s real `showError` renders the real error title and
  message and never also renders a clean/protected summary alongside it —
  see that file's own disclosed note on why `showError` is now exported,
  below); **Selected** (the same real `data-selected="true"` mechanism
  `golden-architecture.test.js` already exercises, confirmed present on
  both Architecture View's and Privacy View's own selected elements for
  the same selection, not a new mechanism invented for this test);
  **Hovered** (a real `:hover` CSS rule confirmed present in
  `styles/privacy-view.css`, `styles/inventory-view.css`, and
  `styles/trace-view.css`, read as text — same "read the real stylesheet"
  pattern `test/tokens-contrast.test.js` already uses, since `:hover`
  cannot be triggered or observed via `dom-shim`). **The other 8 states
  have no dedicated visual treatment anywhere in `src/` or `styles/`
  today** (confirmed by direct grep during scoping) and are named, not
  invented: Loading/scanning, Partial, Truncated, Unsupported (a
  graph-level persistent banner, distinct from Inventory's own
  `unsupportedCandidates` table row), Unresolved destination's specific
  dashed-edge/question-mark glyph treatment (the node itself already
  renders — only that specific visual is unconfirmed), Zero filtered
  results, Error's own phase-2 retry/export-diagnostics action (only the
  base failed-state UI is real), and Stale artifact. Each is a visible
  `test.todo(...)` entry in `test/golden-state-matrix-gaps.test.js`, naming
  exactly what UI would need to exist first — real, permanent entries in
  `npm test`'s own summary (currently 8 `todo`), not a doc that can go
  stale silently. **AC-22 does not pass** — 8 of its 11 named states have
  no code to test, and no placeholder UI was built to force a pass.
- **One real, minimal, disclosed change to `main.js` rode along**:
  `showError` (previously module-internal) is now exported, purely so
  `golden-state-matrix.test.js` can call the exact function `init()`'s own
  fetch-catch path already calls, rather than a parallel test-only
  reimplementation. This repo's current Node version has no ESM
  module-mocking primitive in stable `node:test` (confirmed this session —
  `mock` has no `.module` method), so exercising the real fetch-failure
  path end-to-end would have needed either a new test dependency or this
  export; the export is the smaller footprint. A second, real fix rode
  along with it: `main.js`'s top-level `init()` call is now guarded on
  `document.getElementById('app-root')` actually resolving to something,
  since importing `main.js` for its `showError` export runs the module's
  own top-level statements (including the unconditional `init()` call) as
  a side effect — under `dom-shim.js`'s bare virtual document (no
  `#app-root` element exists), the unguarded call crashed with an
  unhandled rejection. The guard is also a real defensive property outside
  of tests: this script was never meant to run against a page lacking its
  own mount point. `dom-shim.js` gained a matching `getElementById()`
  (always `null` — there is no element registry in this shim, only
  whatever an individual test builds by hand).

| Module | Responsibility |
|---|---|
| `src/lib/escape-html.js` | Escapes text for the rare case of building a raw HTML/attribute STRING outside of `el()` (e.g. a future `document.title` assignment, or serializing to an SVG attribute string). Quote-complete (escapes `&<>"'`) — neither existing in-repo escaper (`scanner/src/posture/fleet.js`, `scanner/src/badge.js`) is. **Never combine with `el()`'s text-child insertion** — `el()` already escapes via `createTextNode` (see `src/lib/dom.js` below), and pre-escaping on top of that double-escapes (a real repo name like `Acme & Sons' <repo>` would render on screen as the literal text `Acme &amp; Sons&#39; &lt;repo&gt;`). This exact bug shipped in `shell.js` and was fixed by dropping the `escapeHtml()` calls there, not by touching this module. |
| `src/lib/contrast.js` | WCAG relative-luminance contrast ratio, from first principles — no existing contrast tooling anywhere in this repo. |
| `src/lib/dom.js` | Safe DOM element builder (`el()`) — never `innerHTML`. Text children go through `document.createTextNode`, which never interprets its argument as markup — this is full XSS safety on its own, so a text child passed to `el()` must be the raw, unescaped string. Unit-tested in `test/dom.test.js` via a minimal dependency-free `document` shim (`test/dom-shim.js`), not `jsdom`. |
| `src/lib/state.js` | Cross-view selection/filter state, persisted in the URL hash (AC-16). Pure functions, fully unit-tested. |
| `src/data/flagship-graph.js` | **Generated** — do not hand-edit. Run `npm run generate-fixture` after any change to `scanner/src/lineage/fixtures/flagship-graph.json`. `test/fixture-module-parity.test.js` enforces this file stays byte-identical to the backend fixture and passes the real `validateGraph()`. |
| `src/shell.js` | The `AppShell` — header, view tabs, left rail, canvas, inspector, context rail (PRD §7.7). Owns the canonical `{view, selectedId, filters}` state (AC-16) and is `mountShell()`'s single source of truth for it: the returned object exposes `getState()`, `setSelection(id)`, `setFilters(filters)`, `setActiveView(viewName)` (all three sync the URL hash and notify subscribers), `onStateChange(listener)` (returns an unsubscribe function), and `destroy()` (removes the `hashchange` listener and clears subscribers). A future view module reads/writes shared state through this contract rather than re-parsing `window.location.hash` on its own. Unit-tested in `test/shell.test.js` via the same `test/dom-shim.js` shim. |
| `src/lib/protection-visual.js` | Verdict-to-visual mapping (`protectionVisual()` and `worstVerdict()`). Returns `{verdict, label, glyph, lineStyle, colorVar}` for a given verdict string, enabling AC-20 (verdicts distinguishable without color). **Verdict strings must be hand-kept-in-sync with the backend's enum in `scanner/src/lineage/`** — the browser cannot import that module at runtime, and the visual mapping is a pure function that takes only a string, so mis-matches silently produce wrong labels/glyphs. Consumed identically by `architecture-view.js`, `evidence-inspector.js`, and `app.js`. |
| `src/lib/flow-path.js` | Shared per-flow path/topology helpers: `flowPathNodeIds(graph, flow)` (every node ID a flow's path touches — its own source/sink plus every `edge.from`/`edge.to` for its `edgeIds`) and `isAiRelevantFlow(graph, flow)` (true if that path touches an AI-subtype node, per the exported `AI_SUBTYPES` set). Extracted from Architecture View's `computeFlowSummary`, which had reimplemented the node-collection logic inline, to give Privacy View and the filter rail one shared implementation instead of a third divergent copy. **AI relevance is topology-based, never `dataElement.aiContexts`-based** — that field is never populated by name-only classification (`scanner/src/lineage`'s `classification.js`), so an aiContexts-based filter would show zero AI relevance despite real AI-processing flows existing in the graph. `AI_SUBTYPES` (exported — Milestone 3, sub-project Inventory) is hand-kept in sync with `scanner/src/lineage/schema.js`'s real `SOURCE_CATEGORIES`/`SINK_CATEGORIES` AI-flavored entries (`ai-model-provider`, `ai-local-model`, `ai-agent`, `ai-tool`, `ai-vector-store`, `ai-memory`, `ai-training`, `ai-evaluation`, `ai-telemetry`, `ai-model-output`, `ai-tool-result`, `ai-retrieved-document`) — **corrected this sub-project**: the previous set (`'ai-assistant'`, `'vector-store'`) matched neither real enum and silently never matched any real node's `subtype`. Unit-tested in `test/flow-path.test.js`. |
| `src/views/architecture-view.js` | Architecture View: trust-zone columns (`zoneForNode()`), node positioning, edge routing, and flow-selection dimming. Split into pure `computeArchitectureViewModel()` (returns `{zones, nodes, edges, flowSummary}`, fully unit-tested, no DOM dependency) and thin `renderArchitectureView()` (consumes the model to build DOM). Trust-zone-column mapping logic lives in `zoneForNode()` — `ZONE_ORDER` constant defines the five PRD-named zones, and `zoneForNode()` maps each fixture node kind to one. `computeFlowSummary()`'s per-flow path-node collection is `lib/flow-path.js`'s `flowPathNodeIds()` — do not reimplement it inline here again. DOM elements are built via `svgEl()` (createElementNS), never `el()` from `lib/dom.js` — an HTML-namespaced element inside an `<svg>` tree is a foreign element that never paints (see the SVG-namespace regression test below). Consumed by `app.js`. `computeFlowSummary()`'s output is rendered by `renderFlowSummary()` — built via plain `el()`/`clear()` (NOT `svgEl()`; it's an HTML panel outside the `<svg>` canvas) — and wired by `app.js` into the shell's context rail (`shell.js`'s `getContextRailEl()`) whenever a flow is selected on Architecture View; every other state falls back to `shell.js`'s `buildContextRailText()`. Unit-tested in `test/architecture-view.test.js` and `test/architecture-view-render.test.js` (the latter asserts every rendered node/edge is SVG-namespaced with a non-zero-shaped tree, walking the real fixture through a dependency-free `document` shim); `renderFlowSummary()` itself has its own dedicated coverage in `test/flow-summary-render.test.js`. |
| `src/views/privacy-view.js` | Privacy View: table of flows organized into six lifecycle stages (collection, processing, storage, sharing, retention, deletion), with row data showing source/sink nodes, AI relevance, data classes, and governance facts (especially MANUAL REQUIRED markers). Split into pure `computePrivacyViewModel()` (returns `{stages, rows}`, fully unit-tested, no DOM dependency) and thin `renderPrivacyView()` (consumes the model to build DOM). **Renders via `el()` (HTML), NOT `svgEl()`/SVG — a deliberate departure from `architecture-view.js`, made specifically to avoid the namespace-mismatch bug class that shipped there.** A row's cell content is derived from `flowPathNodeIds()` and `isAiRelevantFlow()` (both from `lib/flow-path.js`). Every row's flow-level protection verdict (`row.protectionSummary`) renders in its own dedicated `Protection` column, independent of which lifecycle-stage cells happen to be populated — it is never attached to a specific stage cell (a prior version attached it only inside the sharing-stage cell, which meant any flow whose path skipped a sharing-stage node showed no protection verdict at all). `renderStageCell()`'s governance-badge loop (recipient/purpose/lawfulBasis/transfer for `sharing`, `retention` for `retention`, `deletion` for `deletion`) runs unconditionally, independent of whether the cell's `nodeLabels` is empty — a governance fact in `row.governanceRefs` must never become structurally unreachable just because a flow's path doesn't touch that lifecycle stage's node. Consumed by `app.js`. Unit-tested in `test/privacy-view.test.js` (pure) and `test/privacy-view-render.test.js` (render-level, both regressions above). |
| `src/views/trace-view.js` | Trace View: numbered step-by-step journey of a single selected flow, showing node transformations at each hop, evidence-level detail per edge (a rendered evidence-reference count per step, from `step.evidenceRefs`), trust-boundary crossings, and alternate destination flows for the same data element. Split into pure `computeTraceViewModel()` (returns `{flow, steps, alternatePaths} | null`, fully unit-tested, no DOM dependency) and thin `renderTraceView()` (consumes the model to build DOM). **Renders via `el()` (HTML), NOT `svgEl()`/SVG — a deliberate departure from `architecture-view.js`, made specifically to avoid the namespace-mismatch bug class that shipped there.** Each step with `step.protection` renders all three dimensions (transit, atRest, handling) explicitly through `protectionVisual()`, never just `handling` — a step whose transit is unprotected but handling is `not_assessed` (e.g. the real Payments Service → Payment API edge) must show the real unprotected verdict, not a contradictory "not assessed" claim for the whole step. A flow that genuinely fans out (one node with more than one outgoing edge within the same flow) is never numbered as a false linear sequence: `computeTraceSteps`'s hop/transformation/propagation steps each carry `fromNodeId` (the edge's `from` node), and pure `computeTraceStepGroups(steps)` groups same-`fromNodeId` steps into one `{type: 'branch', steps}` group, rendered by `renderTraceBranchGroup()` as one `.trace-branch-group` with lettered sub-step numbers (e.g. "3a"/"3b") sharing a base step number, instead of the two branch destinations being numbered as separate sequential steps implying data visited one destination and then the other. Real fixture example: `flow.phi.ai`, where the Web App → AI Assistant hop stays a plain sequential step, then AI Assistant fans out to both Model Provider and Vector Store as one lettered branch group. Consumed by `app.js`. Unit-tested in `test/trace-view.test.js` (pure) and `test/trace-view-render.test.js` (render-level, both this and the Fix-1 regression above). |
| `src/views/inventory-view.js` | **Milestone 3, sub-project Inventory.** The fourth required view (PRD §7.6): sortable tables for all 11 named categories. Split into pure `computeInventoryViewModel(graph, state)` (dispatches to one per-category compute function in the `TABLE_COMPUTE` map, keyed by `lib/state.js`'s `INVENTORY_TABLES` — the single canonical id list; adding/renaming a category means updating both) and thin `renderInventoryView()` (a sub-nav strip of 11 buttons, one per category with its own live row count, plus a sortable `<table>` — click a `<th>` to sort by that column ascending/descending; each `renderInventoryView` call gets its own fresh closure-local sort state, confirmed not to leak between separate calls). Row selection feeds the SAME `onSelect`/evidence-inspector wiring every other view uses. **Categories are not mutually exclusive** — a node can legitimately appear in more than one table (e.g. a `kind:'sink'` node with an AI-flavored `subtype` is a row in both Sinks and AI systems); this is by design, not a bug, confirmed during implementation via a real fixture. Filter-rail integration (`FILTERABLE_TABLES`) is deliberately scoped to the categories whose rows carry `dataClasses`/`protectionSummary` (Fields, Policy-permitted flows, Manual governance gaps) — the other eight categories render the rail (so it's never blank when switching sub-tables) but its chips have no effect there, same as Privacy View already has no effect outside `view==='privacy'`. `unprotectedEdges` reuses `lib/protection-visual.js`'s existing `worstVerdict()` aggregator (the same call `architecture-view.js` already makes per-edge) rather than a second implementation. Full design rationale in `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-inventory-scoping.md`. Unit-tested in `test/inventory-view.test.js` (pure) and `test/inventory-view-render.test.js` (render-level, dom-shim). |
| `src/components/evidence-inspector.js` | Evidence Inspector: the four-question flow inspector (PRD §16, AC-20). Split into pure `computeInspectorViewModel()` (returns `{...} | null`, fully unit-tested, no DOM dependency) and thin `renderInspector()` (consumes the model to build DOM). Resolves `flow:*`/`edge:*`/`node:*` ids and, **since Milestone 3 sub-project Inventory**, also `data:*` (dataElement) and `transform:*` (transformation) canonical ids — needed so Inventory's Fields and Transformations tables' row selection isn't silently inert. `dataElement`/`transformation` have no `evidenceRefs` in the real schema, so their supporting/conflicting evidence lists are honestly always empty, not a bug. Consumed by `app.js`. Unit-tested in `test/evidence-inspector.test.js`. |
| `src/components/filter-rail.js` | Filter rail: the left-side control panel offering data-class and protection-tier facets derived from the graph, consumed by Privacy View to hide/show rows matching the filter set. Split into pure `computeFilterFacets()` (returns `{dataClasses, protectionTiers}`, fully unit-tested, no DOM dependency) and thin `renderFilterRail()` (consumes the facets to build the control UI). **Deliberately NOT applied to Architecture View's node/edge dimming** (a scoping decision, not a gap). **Since Milestone 3, sub-project Inventory, also wired for Inventory View** — but only for the categories whose rows carry the filtered properties (`inventory-view.js`'s `FILTERABLE_TABLES`); the other categories render the rail with no visible effect, same as it always had none outside Privacy View before Inventory existed. Consumed by `app.js`. Unit-tested in `test/filter-rail.test.js`. |
| `src/lib/api-client.js` | **Milestone 3, sub-project Wire.** The frontend's entire integration surface with the `explore` server (`scanner/src/server/`). `extractTokenFromFragment()` parses `location.hash` for `#token=<64-hex-char>` (tolerant of other hash params — `shell.js` starts writing `view`/`selected`/`filters` into the same hash after the first render, overwriting the token there, which is a deliberate, welcome side effect: the token disappears from the visible URL after first paint). `fetchGraph({token, baseUrl})` calls `GET /api/v1/graph` with the token as the `x-agentic-security-token` header (never a query string) and unwraps the response envelope's `.data` field. `baseUrl` defaults to `''` (a same-origin relative fetch — the only thing the shipped page itself ever passes); it exists so a test can point this at a real running server without a headless browser. Unit-tested (mocked fetch) in `test/api-client.test.js`; proven against a REAL running `explore` server in `test/live-fetch-parity.test.js`. |
| `src/main.js` | **Milestone 3, sub-project Wire.** The page's real entry point, external to `index.html` (a strict `script-src 'self'` CSP on the explore server's static routes cannot permit an inline `<script>` block without `'unsafe-inline'`, which this repo deliberately never adds — see `scanner/src/server/static-assets.js`'s `STATIC_CSP_HEADER_VALUE`). Extracts the token via `api-client.js`, calls `fetchGraph`, and calls the EXISTING, UNCHANGED `bootstrap(root, graph)` — on a fetch failure it shows a plain, visible error in `#app-root` via `el()`, never a silent blank page. `index.html` is now a single `<script type="module" src="./src/main.js">` tag. |
| `src/app.js` | Main entry point. Orchestrates `mountShell()`, the four views' `compute*ViewModel()`/`render*View()` pairs (Architecture, Privacy, Trace, Inventory), `computeInspectorViewModel()`/`renderInspector()`, and `computeFilterFacets()`/`renderFilterRail()` to wire up view switching, cross-view flow selection (AC-16 — Privacy View rows, Trace View's "Alternate destinations" entries, and Inventory View's rows are all click-driven selection sources), filter-rail-driven row visibility (rendered for `privacy`/`inventory`, inert text otherwise), and inspector redraw on selection change. The render path is covered by `test/architecture-view-render.test.js`'s SVG-namespace regression test plus manual/CDP verification — an earlier manual-only browser check (Task 5 Step 6) missed a rendering bug (elements built in the wrong DOM namespace, silently invisible) that only actual bounding-box/namespace inspection catches; don't treat a manual check alone as a rendering guarantee. Task 7's own CDP check hit an analogous methodology trap: Trace View's "Alternate destinations" list can render below the fold, and a real coordinate click at those off-screen coordinates lands on nothing (`document.elementFromPoint` there returns `null`) — silently a no-op rather than an error. Size the CDP viewport tall enough (or scroll the target into view) before dispatching a coordinate click, and confirm `elementFromPoint` at the click coordinates resolves to the intended element first. |
| `test/adversarial-fixture.js` / `test/xss-adversarial.test.js` | **Milestone 3, sub-project XSS — closes `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s T1 entry.** A hand-built adversarial `DataFlowGraph v1`-shaped fixture (a raw `<script>` tag, an SVG `onload`/`onbegin` payload — genuinely relevant since `architecture-view.js` renders into a real `<svg>` tree, an `<img onerror>` payload, a `javascript:` URL string, real control characters via `\x` escapes — never a literal raw byte in the source file, which proved fragile/invisible in a diff during this increment's own authoring — and a 10,000-char identifier) placed in every user-influenceable string field a view actually renders. `xss-adversarial.test.js` renders it through all three real views via the SAME `compute*ViewModel()`/`render*View()` pairs and dom-shim every other render-level test already uses, then walks the FULL resulting tree asserting no live `<script>` element, no `on*` event-handler attribute anywhere (a generic sweep, not a hand-picked payload list), and no `javascript:`-prefixed value on a genuine URL-BEARING attribute (`href`/`src`/`xlink:href`/`action`/`formaction`/`data` — **narrowed deliberately after a real false positive found this session**: a first-draft version swept EVERY attribute, including `aria-label`, which legitimately contains descriptive text a browser never interprets as a URL; sweeping it flagged Architecture View's own real, harmless `aria-label` usage). Proven non-vacuous two ways: a hand-built-tree mutation-proof test (in the same file) AND a real, temporary mutation of `architecture-view.js` itself (an `onclick` attribute set from raw `node.label` — reverted before commit, confirmed via `git diff` showing the file byte-identical to `HEAD` afterward) — both confirmed the suite genuinely fails against a real regression, not just a synthetic one. **CSP hardening (T1's other mitigation clause) was already shipped** in prior increments (`scanner/src/server/security.js`'s `CSP_HEADER_VALUE`, `static-assets.js`'s `STATIC_CSP_HEADER_VALUE`) — this increment's own scope was the fixture + DOM proof only. **Disclosed, deliberately deferred**: no view currently bounds rendered label length (confirmed by grep: no `slice`/`substring`/`truncat`/`maxLength` anywhere in `src/views/*.js`/`src/lib/*.js` touches user-controlled text) — an unbounded label is a display/DoS-adjacent UX nuisance, not itself an XSS vector, since `el()`'s own escaping already makes any length of hostile string inert as markup; truncation is real, disclosed, deferred UX work for a later increment, not silently treated as covered by this one. Also disclosed: the `javascript:`-URL category is currently testing an ABSENCE, not an active defense — no view renders any value as `href`/`src` today (confirmed by grep across `src/views`, `src/components`, `src/app.js`) — the test case is a regression trip-wire for whenever a future view adds a link/image, not proof of a currently-exercised defense. |

## Conventions

- **No `innerHTML` with graph-derived content, ever.** Use `el()` (`lib/dom.js`) or `document.createTextNode`/`textContent`. `el()`'s text-child path already provides full escaping via `createTextNode` — `escapeHtml()` (`lib/escape-html.js`) is for the separate case of building a raw HTML/attribute STRING outside of `el()`, and must never be combined with `el()`'s text-child insertion, since `createTextNode` does not interpret HTML entities and the result double-escapes. The formal adversarial-fixture XSS test suite is Milestone 3's (per `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s T1 entry), but this hygiene rule is not optional now that rendering code exists.
- **No new runtime dependency without updating this file's own "why no build step" reasoning first** — the zero-build-step decision is deliberate, not an oversight; see `README.md`.
- **The prototype consumes the real fixture shape, not the PRD's abstract prose.** Field names like `flow.source`/`flow.sink`, `evidence.evidenceType`, and `dataElement.dataClasses` being UPPERCASE were confirmed against the actual committed JSON — if the backend fixture's shape changes, re-run `npm run generate-fixture`, re-run `npm test`, and update any view code that assumed the old shape.
