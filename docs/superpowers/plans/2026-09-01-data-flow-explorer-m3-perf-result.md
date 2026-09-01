# Milestone 3, sub-project Perf: measured result

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-perf-plan.md`.
Measured in a real Chrome tab (this session's browser automation tools),
against `frontend/`'s current, unmodified rendering code, using a real
`validateGraph()`-clean synthetic graph
(`bench/data-lineage/perf/generate-synthetic-graph.mjs`) served from a
throwaway harness (`frontend/perf-large.html`, gitignored, not committed).

## First meaningful paint (PRD §21: under 2 seconds at 5,000 nodes/10,000 edges)

Three real, browser-measured data points (Architecture View, the default
view, the more expensive SVG-per-element render):

| Scale | SVG elements | Real `first-paint` (Performance API) | vs. 2s budget |
|---|---|---|---|
| 1,000 nodes / 2,000 edges | 10,010 | **332 ms** | 17% of budget |
| 2,500 nodes / 5,000 edges | 25,010 | **920 ms** | 46% of budget |
| 5,000 nodes / 10,000 edges (the actual §21 reference scale) | 50,010 | **no `first-paint` entry ever recorded** (waited 20+ s; `Page.captureScreenshot` timed out reproducibly at 30 s, twice, while JS execution in the same tab remained fully responsive — confirmed via a live `Date.now()` eval) | **FAIL, by a wide, unbounded margin** |

**Growth is clearly non-linear**: 2.5× the node count (1,000→2,500) cost
2.8× the paint time (332→920 ms) — already worse than linear — and going
from 2,500→5,000 nodes (another 2× ) did not merely double again; it blew
past the point of ever completing a real paint. This is the textbook
scaling failure of one live SVG DOM node per graph element with no
level-of-detail clustering, spatial batching, or virtualization — exactly
what §21's own closing sentence names as required and what §17.2's
Cytoscape.js/ELK/Web-Worker-layout recommendation exists to solve. The
current renderer has none of those mechanisms.

**A methodology note worth keeping**: the harness's own JS-side timer
(waiting two `requestAnimationFrame` callbacks after `bootstrap()`
returns) reported the FULL 5,000/10,000 case as "done" in 338 ms —
i.e., **the JS-thread-visible signal said PASS while the browser's own
real paint/composite pipeline never actually completed**. Had this
measurement been done with a Node-side or JS-timer-only benchmark (no
real browser, no real screenshot/paint-API verification), it would have
reported a false PASS. This is exactly why the plan required a real
browser and a real, independently-verified paint signal rather than
trusting `requestAnimationFrame` alone — confirmed necessary, not
paranoia.

## Pan/zoom interaction (PRD §21: at least 45 FPS with ≤2,000 visible elements after clustering)

**Cannot be measured — the feature does not exist yet.** Confirmed by
direct code read before attempting any measurement: no `wheel`/`zoom`/
`pan`-handling code exists anywhere in `frontend/src/views/
architecture-view.js`, `frontend/src/app.js`, or `frontend/src/shell.js`
— a `grep` for interaction/event-listener wiring beyond simple
click-to-select handlers returns nothing. This is a missing feature, not
a number to report as passing or failing; it is also explicitly load-
bearing for the FMP failure above, since level-of-detail clustering
(§21's own closing sentence) is the mechanism that would make BOTH
metrics tractable, and it does not exist either.

## Recommendation

**The current zero-build-step, hand-rolled-SVG architecture does NOT
meet the P0 performance gates measured against a real 5,000-node/
10,000-edge graph.** `frontend/README.md`'s own Milestone-0-era deferral
reasoning ("solving a problem this milestone doesn't have... belongs to
Milestone 3, against the real performance budgets, with real graphs")
was sound methodology, honestly disclosed as untested — this measurement
is that test, and the result is a clear, real failure, not a marginal
one. **A stack migration (or, at minimum, adding real clustering/level-
of-detail/virtualization to the current SVG renderer before the graph
even reaches the DOM) is real, necessary, separately-scoped work that
must land before Inventory/live-API work is built on the current
renderer unchanged** — building more views/features on an architecture
that cannot paint the PRD's own reference-scale graph would only grow
the amount of code a future migration has to carry across.

This does NOT block M3-Server (the local API is architecture-neutral —
Cytoscape/ELK or a hardened SVG renderer both consume the same `/api/v1/
graph` shape) or M3-Wire's own live-API-wiring work for the THREE
EXISTING views at the CURRENT flagship-fixture scale (14 nodes/15 edges
— nowhere near where this failure manifests). It DOES mean: before
M3-Inventory and the large-scale interactive features named in the
scoping doc's own M3-UX (semantic zoom, search, focus controls — Decision
7, deliberately unscoped there pending exactly this measurement), a
dedicated rendering-architecture sub-project (call it M3-Render,
following this document's own naming convention) needs its own scoping
pass: does §17.2's full React+Cytoscape+ELK recommendation get adopted
wholesale, or does a narrower fix (canvas/WebGL rendering, or SVG +
real clustering/virtualization) meet the budget for less migration cost?
That decision needs its own investigation, grounded in these real
numbers — not decided here.

## Measurement artifacts (not committed — regenerate to reproduce)

- `bench/data-lineage/perf/generate-synthetic-graph.mjs` — fixed a real,
  pre-existing drift bug found while using it for this measurement:
  generated edges were missing `provenance` (required since Sub-project
  F1, this session, before this generator was last touched) and failed
  `validateGraph()` outright. One-line fix, committed as part of this
  sub-project — this also fixes the EXISTING Milestone 1 Sub-project G
  graph-build-overhead perf harness that already depended on this same
  generator, not just this measurement.
- `frontend/scripts/generate-perf-graph-module.mjs` (new, committed) —
  generates a throwaway, gitignored browser module from the synthetic
  graph generator above, mirroring `generate-fixture-module.mjs`'s own
  real-`validateGraph()`-before-writing discipline. Kept as reusable
  infrastructure for a future M3-Render sub-project's own before/after
  measurements, not thrown away after this one run.
- `frontend/perf-large.html` (new, committed) — the throwaway measurement
  harness (real Performance-API marks, no fabricated numbers). Gitignored
  data file it imports (`frontend/src/data/perf-large-graph.js`) is
  regenerated by the script above, never committed.
