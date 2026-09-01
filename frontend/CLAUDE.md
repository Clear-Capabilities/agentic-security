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

**Milestone 3, sub-project I ("exit-gate closure," agent-closable half
only) — COMPLETE (2026-09-01):** per the PRD's own Milestone 3 exit gate
(line ~1823): *"representative architect and privacy-officer usability
tests complete their core questions without source-code assistance, and
AC-16 through AC-22 pass at every supported desktop viewport."* Two
genuinely different halves, exactly as `docs/superpowers/plans/
2026-09-01-data-flow-explorer-m3-scoping.md`'s own §0 named at the start
of this milestone: the usability-testing clause needs real human
sessions and **cannot be closed by an agent** — it is named here as
permanently open, not attempted, not worked around. The AC-16–22 clause
is code-testable and is closed as follows, re-verified fresh this session
(`frontend && npm test`: 195 tests, 187 pass, 0 fail, 8 todo, exit 0;
`scanner && npm test`: 5,917 + 26 JS tests, 0 fail, exit 0):

| AC | Proof | Where |
|---|---|---|
| AC-16 (shared shell across views) | selection and filters survive a real, dispatched tab-click view switch; header/coverage-banner DOM content is byte-identical before and after | `test/golden-shell-state.test.js`; underlying mechanism in `test/state.test.js`/`test/shell.test.js` |
| AC-17 (Architecture reference composition) | all 9 named reference nodes, all 5 named trust zones, flow-selection dimming (present-but-dimmed, never removed), and the raw/masked PCI-in-logs branches' distinct verdicts, against the real flagship fixture | `test/golden-architecture.test.js` |
| AC-18 (Privacy lifecycle reference composition) | the 3 named data-class fields preserve identity across all 6 lifecycle-stage columns; the real (lowercase, machine-value) `manual_required`/`unknown`/`review`/`not_found` governance-gap signal renders | `test/golden-privacy.test.js` |
| AC-19 (Trace/evidence reference composition) | the cleartext payment flow's real ordered steps, both field-rename mappings, the external HTTP hop's visibly-flagged unprotected trust-boundary crossing, and each alternate destination's own individual verdict (including two alternates sharing a destination label but rendering different verdicts) | `test/golden-trace.test.js` |
| AC-20 (verdicts distinguishable without color) | every verdict has a non-empty, structurally-required glyph/label/lineStyle, no two verdicts share a glyph; the real light-theme color tokens meet WCAG AA (a real violation was found and fixed this session, not merely tested) | `test/protection-visual.test.js`, `test/tokens-contrast.test.js` |
| AC-21 (desktop viewport reflow) | the shell's regions/collapse/overlay behavior verified via REAL Chrome at all 4 named viewports (1280×720/1440×900/1680×945/2560×1440) — a real bug found and fixed (inspector was unreachable via `display:none` below 1280px) and its fix directly observed working, not assumed from the CSS | `test/shell.test.js`'s overlay-toggle test (structural); the real CDP measurement recorded in this file's own A11y section (visual/layout) |
| AC-22 (non-clean states cannot mimic success) | 3 of 11 named states (Error, Selected, Hovered) have real UI and real tests; the other 8 are named, not invented, as permanent `test.todo` entries | `test/golden-state-matrix.test.js` (real), `test/golden-state-matrix-gaps.test.js` (8 disclosed gaps) |

**What this does NOT mean:**

- **The usability-testing clause is not attempted.** No agent session can
  recruit or observe a real architect/privacy-officer completing tasks
  "without source-code assistance." A real usability-test session would
  need: 2+ representative participants per persona (architect,
  privacy-officer), a written task script exercising each of AC-17/18/19's
  own reference compositions plus at least one AC-22 non-clean state (an
  Error state, since it's the only one with real UI), a real running
  `agentic-security explore` instance (not a mock), and a facilitator
  scoring "core questions completed without being shown source code" —
  none of which this document creates or schedules.
- **AC-22 itself does not pass** — 8 of its 11 named states have no code
  to test, honestly disclosed in Golden's own section above, not silently
  narrowed here.
- **"At every supported desktop viewport" is only literally true for
  AC-20/21.** AC-16/17/18/19's own golden-DOM tests run via `dom-shim.js`,
  which has no CSSOM/layout engine at all — they prove the CONTENT is
  correct, not that it stays correct at 4 different viewport sizes. Only
  A11y's own real CDP measurement (this file's A11y section) verified
  actual layout at all 4 viewports, and that measurement checked
  SHELL-level structure (regions, overlay, sizing), not AC-17/18/19's own
  specific reference-composition content at each size. Verifying, say,
  Architecture View's 9 named nodes render "without overlapping labels"
  (AC-17's own clause) at all 4 viewports would need a further real-
  browser pass — real, disclosed, not attempted here.
- **AC-19's "highlighted code evidence... only when supplied by scanner
  evidence" clause** is not directly exercised by `golden-trace.test.js`
  — the closest existing proof is `test/evidence-inspector.test.js`'s
  pre-existing (Milestone 2) assertion that no conflicting/invented
  evidence is ever fabricated. A dedicated golden test for evidence
  highlighting specifically was not written this sub-project.
- **§7.8/7.9/7.10's richer blueprint claims** (saved views, zoom/focus/
  layout controls, the `Lifecycle | Data map` toggle, `Escape`
  interaction, 200% zoom, DPIA/RoPA export, §8.5 presentation/export
  mode) remain unimplemented, confirmed absent by direct grep during
  Golden's own scoping pass — real, disclosed, unscoped M3-UX/M4
  territory, not part of AC-16–22's own text.
- **M3-Render** (the large-graph rendering-architecture fix Perf's own
  measurement made necessary) remains unscoped — nothing in this
  sub-project's own verification touched graph scale beyond the 14-node
  flagship fixture.
- **M3-Server's own S2** (`POST /api/v1/query`/`POST /api/v1/export`),
  C2/C3 (Milestone 2's deferred at-rest detection), F2/F3 (Milestone 2's
  deferred cross-boundary work), and Milestones 4/5 in their entirety
  remain exactly as unscoped as every prior sub-project's own CLAUDE.md
  section already disclosed — restated here only for completeness, not
  newly found.

**Milestone 3's own exit gate (PRD line ~1823) is therefore NOT fully
satisfied** — the usability-testing clause is permanently outside an
agent's reach, and AC-22 itself does not pass. What IS true, and real:
every agent-closable requirement named in AC-16 through AC-22 has been
either implemented, tested, or — where genuinely absent — named
explicitly rather than silently claimed. This is the same "what this
does NOT mean" disclosure discipline Milestone 2's own Sub-project I
established (`scanner/src/lineage/CLAUDE.md`'s own "Milestone 2
exit-gate status" section).

**Milestone 3, sub-project Render — MEASURED, real result (2026-09-01):**
per the user's own explicit direction (choosing a "narrow SVG fix" over
a full React/Cytoscape/ELK migration or a Canvas/WebGL renderer), adds
level-of-detail clustering, edge aggregation, real pan/zoom, and
viewport culling to Architecture View — the same hand-rolled SVG
renderer, zero build step, zero new dependency. Full design rationale in
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-render-scoping.md`
and its companion plan.

- **Level-of-detail clustering (`computeClusteredLayout`) + edge
  aggregation (`aggregateEdgesForClusters`)**: per-zone, count-threshold-
  based (not spatial), with the threshold derived from PRD §21's own
  literal "no more than 2,000 visible elements" target
  (`computeZoneNodeBudget()`, currently evaluating to 106 nodes/zone — a
  real, disclosed, non-guessed formula in `architecture-view.js`, not a
  hardcoded magic number). **A currently-selected node always stays
  individually visible, bypassing the budget entirely** — clustering
  must never hide the thing the user is looking at, a real correctness
  requirement found during planning, not in the original scoping doc.
  Edges into a collapsed cluster redirect to the cluster glyph and
  aggregate via the SAME `worstVerdict` primitive `edgeVerdict()` already
  used per-edge, per PRD §7.8's own interaction #6 ("aggregated edges
  display the highest-risk selected verdict"). **A real regression was
  found and fixed during implementation**: naively aggregating ALL edges
  (not just clustering-affected ones) would have silently merged two
  genuinely distinct real edges in the flagship fixture (the masked-log
  vs. raw-log branches, same `(from,to)` node pair, different verdicts)
  into one, regressing the already-shipped AC-17 golden test
  (`golden-architecture.test.js`) — fixed by only routing clustering-
  touched edges through aggregation; every other edge renders exactly as
  before.
- **Real pan/zoom** (previously entirely absent — Perf's own finding):
  wheel-to-zoom (algebraically centered on the cursor position, verified
  by hand that the cursor's fractional position in the viewport is
  identical before and after for any clamped width), click-and-drag pan,
  and keyboard equivalents (arrow keys pan, `+`/`-` zoom, `0` resets),
  all via real `viewBox` manipulation — no new dependency. Viewport state
  is module-local, not persisted to the URL hash (a deliberate,
  disclosed simplification of the original scoping doc's own "reset on
  fresh view-mount" idea, which had no real signal to detect a fresh
  mount without also modifying `app.js` — pan/zoom position is instead
  preserved across ordinary view switches, which does not violate AC-16).
  **A real focus-loss bug was found and fixed during a manual browser
  smoke check**: every pan/zoom rerender tears down and rebuilds the
  entire `<svg>`, and a real browser does not transfer keyboard focus to
  the replacement element — a rapid second keystroke would have silently
  done nothing. Fixed by detecting focus before teardown and restoring it
  on the new element.
- **Viewport culling** (`visibleNodeIds`): filters which nodes/edges get
  real DOM elements to the current viewport rect plus a real margin
  (avoids pop-in at the edge) — the mechanism that keeps a deliberately-
  expanded, deliberately-zoomed-in session performant, complementing
  clustering's own steady-state budget.
- **Real re-measurement against Perf's own exact methodology** (the
  same 5,000-node/10,000-edge `validateGraph()`-clean synthetic graph,
  regenerated via the kept `scripts/generate-perf-graph-module.mjs`, a
  real Chrome tab, real Performance API entries — never a JS-timer-only
  claim, matching Perf's own documented false-PASS trap):
  - **First meaningful paint: PASSES, dramatically.** Real
    `first-contentful-paint` entry at **148ms** (real `first-paint` at
    76ms) — well under the 2-second §21 budget, versus Perf's own
    original measurement of "no paint after 20+ seconds" at this exact
    scale. Confirmed via the DOM, not just the paint API: of 5,000 real
    nodes, only **420 individually-rendered node groups + a small number
    of cluster glyphs** ever reached the DOM — clustering visibly
    engaged and did the intended work. No console errors.
  - **Pan/zoom: PASSES.** A real wheel-zoom interaction (dispatched via
    real `WheelEvent`s at realistic ~16ms intervals, mirroring a fast
    scroll gesture) shrank the viewport from the full 1100×1100 content
    bounds to 226×226 across 15 zoom-in ticks — the exact value
    `1100 × 0.9^15` predicts, confirming the zoom math holds correctly in
    a real browser, not just in unit tests. Sustained **~53 frames/
    second** (rAF-counted during the real interaction burst, 34 frames
    over 637ms) while triggering 15 full rerenders of the clustered
    graph — above the 45fps §21 target. **Disclosed honestly**: this is
    a real, script-driven rAF frame count during an actual dispatched
    interaction, not a DevTools-traced/GPU-compositor-authoritative FPS
    number — the tooling available for this measurement does not expose
    Chrome's own internal frame-timing trace, so the number is real but
    not the most rigorous instrument possible.
  - The small, 14-node flagship fixture is confirmed unaffected — no
    clustering engages at that scale (well under the 106-per-zone
    budget), and the full render-level test suite (including the
    pre-existing SVG-namespace regression test and every golden-DOM AC-17
    test) passes unmodified.
- **What this does NOT mean**: this sub-project touches Architecture
  View only (Privacy/Trace/Inventory are `el()`-based HTML tables, a
  different and generally cheaper rendering problem, never measured as
  failing by Perf in the first place). The "without overlapping labels"
  clause of AC-17 and any dense-content behavior at all 4 required
  viewports (A11y's own real CDP measurement used only the tiny flagship
  fixture) remain real, disclosed, unmeasured territory. No dynamic
  global rebalancing exists if a user expands many clusters at once (a
  deliberate, disclosed simplicity choice, not a bug). Full per-edge
  verdict distribution on an aggregate edge's own selection (vs. just
  the worst verdict) remains deferred. Semantic zoom in the richer PRD
  sense (revealing more FIELD-level detail, not just more nodes),
  server/worker-side projections, and M3-UX's own still-unscoped
  territory (search, query language, saved views) are all untouched.

**M3-UX, sub-project Query — COMPLETE (2026-09-01):** PRD §15.2's query
language, §15.3's 9 focus controls, 2 real saved views, and basic text
search, all as pure functions over graph fields a real audit confirmed
are genuinely populated by real scan code (not just schema-present).
Full rationale in `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-scoping.md`
and its companion Query plan — M3-UX itself has its own sub-project
table (Query done; Filters and SemanticZoom remain future, separately-
scoped work).

- **`lib/query-language.js`**: a hand-written tokenizer + recursive-
  descent parser (`tokenize`/`parseQuery`, never throws — a malformed
  query returns a structured `{error: {message, pos}}`) for §15.2's exact
  grammar (`field:value`, `field:(a,b,c)`, `field!=value`, `AND`/`OR` with
  `AND` binding tighter, parenthesized groups, quoted strings, bare TEXT
  terms for basic search), plus `compileQuery(ast, graph) -> (flow) ->
  boolean`, a field-name → real-graph-accessor predicate evaluator. Field
  mappings (`class`, `field`, `sink`, `source`, `transit.verdict`,
  `at_rest.verdict`, `handling.verdict`, `policy`, `coverage`, `ai`,
  `destination.external`) each read a schema field the parent M3-UX
  scoping doc's own audit confirmed is real. An unrecognized field name
  throws from the returned predicate (not at compile time) — a real,
  actionable, caught condition, never a silent always-false.
  **Two real, disclosed findings from testing against the actual flagship
  fixture** (not assumed): PRD §15.2's own illustrative example
  (`sink:(log,database,external_api)`) does NOT match this fixture — the
  `sink` accessor reads the real `node.subtype` value verbatim
  (`"application-logs"`, not the coarser `"log"` category the PRD's
  prose implies), a genuine vocabulary mismatch for a future increment
  to reconcile. And the fixture has NO flow with `policyVerdict:
  "permitted"` or any edge with `transit.verdict: "protected"` — both
  confirmed by reading every real value, not guessed.
- **`lib/focus-controls.js`**: 9 pure graph-traversal functions
  (`showUpstream`/`showDownstream`/`showAllPaths` — BFS;
  `showShortestPath` — BFS with parent-tracking;
  `showExternalPathsOnly`/`showUnprotectedPathsOnly` — graph-wide
  predicate filters; `showAliases`; `showDisconnected`), each returning
  the SAME `{nodeIds, edgeIds}` shape `architecture-view.js`'s own
  `resolveSelection` already produces, so the render layer needed zero
  new consumption code. `resetToOverview` (the PRD's 9th control)
  deliberately lives in `app.js` instead — it's just clearing state, not
  a traversal. **A real correction to this sub-project's own planning
  doc**: `node.aliases` is NOT always empty — that claim held only for
  REAL SCAN OUTPUT (`graph-builder.js` unconditionally sets `aliases:
  []`, independently reconfirmed); the hand-authored flagship FIXTURE
  has real, non-empty illustrative aliases on 3 nodes (alternate display
  names for the SAME node, never pointers to a distinct node record) —
  `showAliases` is a real, honest implementation either way, disclosed in
  both code and tests, no alias data invented.
- **`components/query-bar.js`**: `computeQueryBarViewModel(state)`
  (pure, syntax-only) / `renderQueryBar()` (text input + error area + 2
  saved-view chips: `PCI Exposure` → `class:PCI`, real-fixture-spot-
  checked at 5/8 flows; `AI + Regulated Data` → `class:(PII,PHI) AND
  ai:true`, spot-checked at 1/8) / `compileQuerySafely(graph, queryText)`
  — the graph-aware superset `app.js` actually calls: parses, compiles,
  and does a trial evaluation against every real flow so an
  unrecognized-field-name error (which only throws at evaluation time)
  is caught upfront rather than mid-render. **A malformed query NEVER
  changes the active filter** (PRD §15.2's own explicit requirement) —
  verified two ways: unit tests, AND an independent real-browser smoke
  check this session (typing `class:` after `class:PCI` left Privacy
  View's visible-row count unchanged at 5, with a real error shown).
- **`app.js`'s own real architectural decision** (this task's one
  genuinely open design question, resolved before implementation): a
  focus control's `{nodeIds, edgeIds}` result has no single canonical
  `selectedId` to thread through the existing selection mechanism, so
  `computeArchitectureViewModel` gained a third, OPTIONAL parameter
  (`focusSelection = null`) — when present it's used directly as the
  `selection`, bypassing `resolveSelection` entirely; when omitted
  (every pre-existing caller), behavior is unchanged. The focus result
  itself lives as module-local state in `app.js` (`currentFocusSelection`
  — real but transient/non-shareable, same precedent A11y's
  `inspectorOverlayOpen` and M3-Render's `currentViewport` both already
  established), cleared automatically whenever the user makes any NEW
  plain selection through an existing path. **Independently verified
  end-to-end in a real browser this session** (not just unit-tested):
  clicking "Show downstream" from Web App un-dimmed 13 of 14 real nodes,
  leaving only the real orphan node (API Gateway, confirmed by Task 3's
  own fixture analysis) dimmed; "Reset to application overview" cleared
  it back to zero dimmed and removed the focus-control menu. No console
  errors.
- **Privacy View and Inventory View both gained an optional 3rd
  `queryPredicate` parameter**, applied as an ADDITIONAL condition
  alongside their existing dataClass/protection filters (a row must pass
  both). **Inventory's own query wiring is honestly flow-scoped only** —
  the DSL is fundamentally about flows, so only `policyPermittedFlows`
  rows and `manualGovernanceGaps`' "Flow"-subject rows (both of which use
  a real flow id) are affected; every other category's rows have no flow
  to test the query against and are unaffected by it, by design, not a
  bug — disclosed in `inventory-view.js`'s own code comment.
- **What this does NOT mean**: Trace View does not receive the query
  predicate (it shows one selected flow's own detail, not a filterable
  list — the query has nothing to narrow there). No dedicated render-
  level test file exists for the focus-control MENU itself (only its
  underlying 9 functions and the real end-to-end browser check above).
  `app.js` itself still has no dedicated unit-test file (none existed
  before this sub-project either) — its own new orchestration logic was
  verified via a manual smoke script plus this session's own independent
  real-browser check, not a committed automated suite. The Filters
  sub-project (expanding `filter-rail.js` from 3 to the real dimensions
  this scoping pass' own audit found) is now COMPLETE (below);
  SemanticZoom remains entirely unscoped, named but not started.

**M3-UX, sub-project Filters — COMPLETE (2026-09-01):** expands
`components/filter-rail.js` from 3 to 10 real facets (data class,
protection aggregate, source category, sink category, destination
externality, transit/at-rest/handling verdict, policy verdict, AI),
reusing Query's own real-vs-inert field audit for which dimensions are
genuinely populated. Full rationale in `docs/superpowers/plans/
2026-09-01-data-flow-explorer-m3-ux-filters-scoping.md` and its
companion plan.

- **`lib/row-filters.js`** (new): `matchesFilters(row, filters)`, a
  shared, deduplicated replacement for two near-identical private
  `rowMatchesFilters` copies that used to live separately in
  `privacy-view.js` and `inventory-view.js`. **Found and fixed a real,
  pre-existing bug while deduplicating**: Inventory's own private copy
  never checked the `ai` filter at all — Privacy's did — so the AI-
  processing chip had literally zero effect anywhere in Inventory View.
  The shared function checks `ai` for every row that carries
  `isAiRelevant`. A filter facet whose property a given row shape
  doesn't carry at all is SKIPPED (the row is unaffected), never treated
  as a hide — the real design property that lets one shared function
  safely serve row shapes as different as a Privacy flow-row and an
  Inventory dataElement-row.
- **7 new chip groups** in `filter-rail.js` (source/sink category,
  destination externality, transit/at-rest/handling verdict, policy
  verdict), computed the same simple `[...new Set(...)].sort()` way
  `dataClasses` already was. **A real surprise finding, confirmed by
  reading the actual fixture rather than assumed**: the flagship fixture
  has ZERO `kind:'sink'` nodes at all — `sinkCategories` is genuinely
  empty against it, so that chip group correctly renders with no chips
  until a fixture gains one.
- **Privacy View and Inventory View both attach the 7 new properties at
  row-computation time** (never looked up fresh inside the shared
  matcher) — Privacy for every row (it's exclusively flow-based);
  Inventory only for `policyPermittedFlows` rows and
  `manualGovernanceGaps`' "Flow"-subject rows (its own only two flow-
  shaped categories), via a new shared `computeFlowFilterProperties`
  helper in `inventory-view.js`. The three verdict properties
  (`transitVerdict`/`atRestVerdict`/`handlingVerdict`) are always set —
  `worstVerdict()` never returns `null`/`undefined`, even for an empty
  edge list, falling back to `'not_assessed'`. `sourceCategory`/
  `sinkCategory`/`destinationExternality` are only set when a real,
  non-null value exists (a conditional spread, not `null`), keeping
  `matchesFilters`'s own "property absent = unaffected" semantics clean
  rather than introducing a third state.
- **What this does NOT mean**: provider/host/database/table/topic,
  application, environment, evidence grade/confidence, and governance
  gap (5 more of the PRD's own §15.1-named dimensions, all confirmed
  real and populated during the parent M3-UX scoping pass) remain
  explicitly deferred — each needs its own real design work (sparse
  per-key objects, per-claim rather than per-row properties, or facets
  that are usually a single always-selected value) beyond this
  increment's own scope. Architecture View still has no filter-rail
  integration at all (a pre-existing scoping decision, unchanged).
  SemanticZoom (M3-UX's own 3rd sub-project) is investigated below —
  confirmed blocked, not built.

**M3-UX, sub-project SemanticZoom — INVESTIGATED, CONFIRMED BLOCKED
(2026-09-01):** not a build. Full writeup in `docs/superpowers/plans/
2026-09-01-data-flow-explorer-m3-ux-semanticzoom-disposition.md`. PRD
§21's "semantic zoom" (reveal more nodes as a dense area is zoomed) is
already satisfied by M3-Render's own clustering — a distinct, lesser,
already-shipped mechanism, as that sub-project's own section above
already discloses. PRD §7.3/DFG-030's richer sense (reveal endpoint/
function/field-level detail on zooming into ONE node) is genuinely not
buildable on the frontend today: direct grep of `scanner/src/lineage/
{schema,validate,graph-builder}.js` confirms `node.location` is
unconditionally `null` on every node (nodes are category-granular — one
"PostgreSQL" node represents an entire store target, not one call site)
and no `functionName`/`fieldDetail`/`endpointDetail`/`symbolDetail`
field exists anywhere in the schema; `storeDetail`/`queueDetail` are the
only per-node detail objects and both are already fully surfaced. Real
per-call-site detail exists only on `graph.evidence[]`, keyed to
edges/flows, already surfaced via the Evidence Inspector (a
select-and-inspect interaction, not a zoom one). Building the richer
sense would require a real scanner-side schema change (a new per-node
call-site array, or minting one node per real call site instead of per
category) — substantial backend work outside `frontend/`'s own scope,
so no UI was built to gesture at a capability with no real data behind
it. M3-UX's own 3-sub-project table is closed out: Query and Filters
shipped; SemanticZoom investigated and honestly deferred to a future
scanner-side increment.

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
