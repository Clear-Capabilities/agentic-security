# Milestone 3, sub-project Render: pan/zoom + level-of-detail clustering + viewport culling

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-perf-result.md`'s
own recommendation and the user's own explicit direction (2026-09-01,
choosing "narrow SVG fix" over a full React/Cytoscape/ELK stack
migration or a Canvas/WebGL renderer): add real clustering/level-of-
detail/virtualization to the CURRENT hand-rolled SVG Architecture View,
keeping zero build step, all 4 views' existing code, and the whole
dom-shim test suite intact. Per §21's own closing sentence: *"Large
graphs must use semantic zoom, server-side or worker-side projections,
clustering, and visible-element limits."*

## What Perf measured (read verbatim this session)

- First-meaningful-paint **fails badly** at the PRD's own 5,000-node/
  10,000-edge reference scale — no real paint after 20+s, growth clearly
  non-linear (332ms → 920ms → never-completes as node count goes
  1,000 → 2,500 → 5,000).
- Pan/zoom **does not exist as a feature at all** — confirmed again this
  session by reading `architecture-view.js` in full: the `<svg>` has a
  static `viewBox="0 0 ${width} ${height}"` sized to fit ALL content, no
  transform group, no wheel/drag handlers anywhere.
- §21's own P0 targets this sub-project must satisfy: first-meaningful-
  paint under 2s at 5,000/10,000 scale; pan/zoom at ≥45fps with **≤2,000
  visible elements after level-of-detail clustering**; focused-path
  render under 500ms for a 100-hop path (already satisfied — Trace View
  is a linear list, not graph-scale-dependent, confirmed by reading
  `trace-view.js`, no change needed here).

## What already exists (confirmed by direct read this session)

- `computeArchitectureViewModel(graph, state)` / `renderArchitectureView
  (viewModel, canvasEl, onSelect)` — the existing pure-compute/thin-render
  split every view in this codebase uses. `computeArchitectureViewModel`
  returns `{zones, nodes, edges, flowSummary}` — EVERY node/edge in the
  graph, unconditionally, no filtering.
- `renderArchitectureView` lays out zones in fixed X columns
  (`ZONE_WIDTH = 220`), nodes in a fixed vertical stack within their zone
  column (`NODE_HEIGHT = 44`, `NODE_GAP = 16`), computes `height` from
  `maxNodesInAZone` — the whole SVG grows unboundedly tall as node count
  grows, with **zero clustering, zero culling, zero pan/zoom**. Each node
  is 3 SVG elements (`<g><rect/><text/><text/></g>`); each edge is 2
  (`<g><path/><text/></g>`) — this matches Perf's own measured "10,010
  elements at 1,000 nodes" almost exactly (1,000×3 + ~1,003×2 + 10 zone
  chrome elements ≈ 5,006... actually the real fixture at Perf's own
  1,000/2,000 scale produced 10,010 — re-verify the exact per-element
  count at implementation time rather than trust this arithmetic).
- `svgEl(tag, attrs)` — the SVG-namespace element builder (never `el()`
  — a real, load-bearing distinction this codebase already fixed a bug
  over; re-use it for every new SVG element this sub-project adds).
- `edgeVerdict(edge)` (module-private, uses `worstVerdict`) — already
  exactly the aggregation primitive §7.8's own interaction #6 requires
  for clustered/aggregated edges: *"Aggregated edges display the
  highest-risk selected verdict and expose the full verdict distribution
  on selection."* **This sub-project's own edge-aggregation work is not
  new invention — it is applying an aggregation primitive this codebase
  already has, to a new case (an edge whose endpoint is now a cluster,
  not an individual node) the PRD itself already anticipated by name.**
- `frontend/scripts/generate-perf-graph-module.mjs` — real,
  `validateGraph()`-clean 5,000-node/10,000-edge synthetic graph
  generator, deliberately kept as reusable before/after measurement
  infrastructure by Perf's own sub-project. `frontend/perf-large.html`
  (the throwaway measurement harness) is real but git-ignored — it does
  not exist in this checkout and must be recreated (a small, disclosed,
  expected step, not a gap) to re-run Perf's own exact measurement
  methodology against this sub-project's fix.
- Real, established precedent for "transient, per-view UI state that is
  NOT persisted to the URL hash": A11y's `inspectorOverlayOpen` (a
  `shell.js`-closure-local boolean, never written to `lib/state.js`'s
  hash-persisted `{view, selectedId, filters, table}`). Pan/zoom position
  is the same shape of concern — real UI state, not meaningfully
  shareable/bookmarkable, and AC-16 itself only requires selection/
  filters/coverage to survive a view switch, never mentions viewport
  position.
- `test/architecture-view.test.js` (18 tests, pure compute) and
  `test/architecture-view-render.test.js` (7 tests... re-verify exact
  count, SVG-namespace + structure assertions) — both must stay green;
  neither currently exercises viewport/clustering concepts, since neither
  concept exists yet.

## Decisions this scoping makes explicitly

1. **Clustering is per-zone, count-threshold-based — not spatial/
   geometric.** The current layout is already a simple per-zone vertical
   list (no x/y spatial freedom within a zone); a k-means/quadtree-style
   spatial clustering algorithm would be solving a layout-freedom problem
   this renderer doesn't have. Instead: each zone gets an individual-node
   budget (`ZONE_NODE_BUDGET`, a real, disclosed, tunable constant — see
   decision 2 for how it's derived). Nodes beyond the budget (by graph
   order — a defensible, simple tie-break; NOT sorted by anything
   PRD-significant like severity, since no such node-level severity
   exists in the schema) collapse into ONE cluster glyph per zone: a
   node-shaped element showing a real count (`"+312 more"`) and the
   zone's own kind-mix (e.g., `"312 more (store/log/sink)"` — real,
   useful, not decorative). Clicking a cluster glyph EXPANDS that zone
   (its budget becomes "unlimited" for the rest of this render session)
   — see decision 4 for why this does not attempt dynamic global
   rebalancing.
2. **The global visible-element budget is §21's own literal number:
   2,000** ("no more than 2,000 visible elements after level-of-detail
   clustering"). `ZONE_NODE_BUDGET` is DERIVED from it, not a separately
   guessed constant: `(2000 - zone-chrome-elements - cluster-glyph-
   elements) / (5 zones × ~3 elements/node)`, computed as a real formula
   in code (not a hardcoded magic number that silently drifts from the
   2,000 target if per-element counts ever change) — leaving real,
   disclosed headroom for edges (a separate budget, decision 3) and for
   the flow-summary/legend chrome that already exists. The EXACT
   arithmetic is real implementation work (Task 1), not decided here —
   the decision made here is that it is DERIVED from 2,000, not chosen
   by feel.
3. **Edges to/from a clustered zone's collapsed nodes are redirected to
   the cluster glyph's own position and aggregated**, reusing the
   existing `edgeVerdict`/`worstVerdict` primitive per §7.8's own
   interaction #6 (quoted above) — multiple real edges that would now
   share the same (visible-endpoint, visible-endpoint) pair collapse
   into ONE rendered edge showing the worst verdict among them.
   `renderEdge`'s existing verdict-badge rendering is reused unmodified;
   only the SOURCE of `{from, to}` positions and `edge.verdict` changes
   (now possibly an aggregate of several real edges, not a 1:1 mapping).
   Full per-edge distribution ("expose the full verdict distribution on
   selection," same PRD sentence) is real, disclosed, deferred work —
   see "Explicitly deferred."
4. **No dynamic global rebalancing when a cluster is expanded.** Once a
   user expands zone X's cluster, zone X's own element count grows and
   the GLOBAL 2,000 budget may be exceeded — this sub-project does NOT
   automatically re-collapse a DIFFERENT zone to compensate. This is a
   deliberately simple, disclosed design choice (matching "narrow fix,
   minimize new complexity" from the user's own chosen direction): a
   user who deliberately expands a dense cluster accepts a heavier DOM
   for that interaction, the same way zooming into a dense area of any
   diagramming tool costs more to render — this is bounded per-expansion,
   not unbounded, and the DEFAULT (nothing expanded) always honors the
   2,000-element target, which is what §21's own text actually requires
   ("no more than 2,000 visible elements" is a steady-state property,
   not a hard ceiling on every possible user interaction).
5. **Pan/zoom is real `viewBox` transform manipulation** — wheel-to-zoom
   (scaled around the cursor position, clamped to a real min/max zoom
   range), click-and-drag-to-pan (clamped so the viewport can't be
   dragged fully off content). State (`{x, y, width, height}` — i.e. the
   SVG's own `viewBox` numbers directly, not a separate transform-matrix
   abstraction) lives as **module-local, closure-scoped state in
   `architecture-view.js` itself** (mirroring `inventory-view.js`'s own
   closure-local `sortState` precedent, decision above) — NOT persisted
   to `lib/state.js`'s URL hash. Resets to a computed "fit all currently-
   visible content" default whenever the view is freshly mounted (first
   render after switching TO Architecture View) — not on every
   selection-change rerender within the same view session, matching
   AC-16's own "only the center projection... change[s]" language (a
   view switch is a real re-entry, a selection change within the same
   view is not).
6. **Viewport culling filters which nodes/edges get real DOM elements**,
   computed from the current pan/zoom viewport rect expanded by a real
   margin (avoids visible pop-in at the viewport edge during a pan). This
   is the mechanism that makes pan/zoom itself performant once a user
   has zoomed into a dense, expanded cluster — clustering alone (decision
   1) bounds the DEFAULT view; culling bounds what a deliberately-
   expanded, deliberately-zoomed-in session actually forces the browser
   to paint at once. Implemented as a pure function
   (`visibleNodeIds(nodePositions, viewportRect, margin)`), fully unit-
   testable without a real browser — the INTERACTION that produces a
   `viewportRect` (mouse events) is what needs real-browser verification
   (see Test plan).
7. **This sub-project is Architecture View only.** Privacy View,
   Trace View, and Inventory View are all `el()`-based HTML tables, not
   per-node SVG layouts — Perf's own measurement never exercised them,
   and none has the same per-element scaling shape (a table with 5,000
   rows is a very different, and generally cheaper, browser rendering
   problem than 50,010 individually-positioned SVG shapes; if a future
   measurement finds a REAL problem there, that's separately-scoped
   work, not assumed covered here).
8. **Testing splits into two real, honest halves**, same discipline A11y
   established: pure compute logic (clustering math, culling math, the
   viewport-transform REDUCER function taking a wheel/drag delta and
   returning new viewport numbers) is unit-tested via `dom-shim.js`,
   fully deterministic, no real browser needed. The ACTUAL performance
   claim (does this fix genuinely get first-meaningful-paint under 2s at
   5,000/10,000 scale, does pan/zoom actually hit ≥45fps) can ONLY be
   proven by re-running Perf's own real-Chrome measurement methodology
   against the fixed code — a real, required final step, not a nice-to-
   have (see Test plan).

## Scope for this increment

1. `frontend/src/views/architecture-view.js` — new pure functions:
   `computeClusteredLayout(zones, nodes, budget)` (decision 1/2, returns
   per-zone `{visibleNodeIds, clusterGlyph: {id, count, kindSummary} |
   null}`), `aggregateEdgesForClusters(edges, clusterAssignments)`
   (decision 3), `visibleNodeIds(nodePositions, viewportRect, margin)`
   (decision 6), `applyWheelZoom(viewport, wheelEvent, svgBounds)` /
   `applyDragPan(viewport, dragDelta)` (decision 5, pure reducers over
   plain numbers — no DOM access, fully unit-testable). `renderArchitectureView`
   gains real wheel/mousedown/mousemove/mouseup event wiring that calls
   these reducers and re-renders with the new viewport; cluster-glyph
   click handling (expand-in-place, decision 4).
2. New keyboard equivalents for pan/zoom (A11y's own established
   keyboard-parity bar applies here too — this is real, new interactive
   surface, not exempt from it): a real, disclosed key mapping (e.g.
   arrow keys pan, `+`/`-` zoom, `0` resets to fit-all) added to the SVG
   canvas's own container, with a visible focus target and `aria-label`
   describing the controls — exact keys are real implementation
   judgment, not prescribed here, but MUST exist and be tested, not
   silently deferred as "mouse only."
3. `frontend/test/architecture-view.test.js` (extend) — unit tests for
   all 4 new pure functions from item 1, deterministic, no real browser.
4. `frontend/test/architecture-view-render.test.js` (extend) — DOM-
   structure assertions: a dense zone renders a cluster glyph, not N
   individual nodes; clicking it (`.dispatch('click')`) expands it;
   aggregate edges render with the worst verdict among their real
   constituent edges (a real, non-trivial fixture proof, matching Golden's
   own "same destination, distinct verdicts, prove the aggregation is
   real" pattern).
5. A real Perf-methodology re-measurement (regenerate `perf-large.html`
   + `src/data/perf-large-graph.js` via the existing, kept generator
   scripts; drive real Chrome via the same tools/technique Perf's own
   sub-project used) confirming first-meaningful-paint now meets the
   under-2s target at 5,000/10,000 scale, and a real, driven pan/zoom
   interaction stays responsive (a real FPS/frame-timing measurement, not
   a JS-timer-only claim — Perf's own methodology note about the
   `requestAnimationFrame`-false-PASS trap applies with full force here
   too). Findings — pass or fail, honestly — recorded in `frontend/
   CLAUDE.md`, mirroring Perf's own and A11y's own measured-result
   precedent.
6. Update `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
   own Render row (currently "Large, unscoped") with the real outcome.

## Do NOT touch

- Privacy/Trace/Inventory views (decision 7).
- The graph-build/data layer (`scanner/`) — this is 100% a rendering
  concern, the canonical graph schema does not change (matching §17.2's
  own "the canonical graph schema must not depend on the renderer").
- `computeArchitectureViewModel`'s own existing return shape
  (`{zones, nodes, edges, flowSummary}`) — the new clustering/culling
  logic is a layer ON TOP of it (a second pass a caller can opt into),
  not a breaking change to its existing contract, so every one of the 18
  existing `architecture-view.test.js` tests keeps passing unmodified.
- `lib/state.js`'s hash-persisted state shape (decision 5 — no new hash
  field).
- Any of §7.8/7.9/7.10's still-unimplemented richer blueprint claims
  (saved views, `Escape` interaction, 200% zoom, export mode) — Golden's
  own scoping pass already found and disclosed these; this sub-project
  does not revisit or attempt any of them.

## Test plan

1. Pure-function unit tests (item 3 above) — deterministic, `node --test`.
2. DOM-structure/interaction tests (item 4 above) — dom-shim, including a
   real non-trivial aggregate-edge-verdict proof.
3. **A real Perf-methodology re-measurement is a required, non-optional
   part of this sub-project's own Test plan** — a "narrow SVG fix" that
   is never actually re-measured against the real 5,000/10,000 graph
   would be exactly the mistake this whole sub-project exists to correct
   (Milestone 0's own untested deferral). If the re-measurement still
   fails the 2s/45fps targets, that is a real, disclosed, honestly-
   reported finding (same discipline as every prior measured-result
   sub-project this session) — not something to soften or declare
   "close enough."
4. Full `frontend/npm test`, green, real captured exit code.
5. `scanner`'s own full gate, confirmed unaffected (this sub-project
   touches `frontend/` only).

## Explicitly deferred

- Full per-edge verdict distribution UI on an aggregate edge's own
  selection (§7.8's own "expose the full verdict distribution on
  selection" clause) — the aggregate edge shows the worst verdict
  (decision 3) but a rich distribution breakdown (e.g. "3 protected / 1
  unprotected / 2 unknown" on click) is real, disclosed, deferred UX
  work, not silently claimed covered.
- Semantic zoom in the richer PRD sense (progressively revealing more
  DETAIL — sub-fields, endpoint paths — as a user zooms into one node,
  as opposed to this sub-project's "reveal more NODES as you zoom/expand
  clusters") — that is M3-UX's own, still-unscoped territory.
- Server-side or worker-side graph projections (§21's own text names
  these as one of several valid mechanisms; this sub-project implements
  client-side clustering/culling only, the smallest change consistent
  with "narrow fix, keep zero build step").
- Any performance work on Privacy/Trace/Inventory views (decision 7).
- A dynamic global-rebalancing mechanism for cluster expansion (decision
  4) — real, deferred future work if the simple per-expansion cost proves
  unacceptable in practice.
