# Milestone 3, sub-project Perf: performance-gate measurement

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`
Decision 1. Resolves, by measurement, whether `frontend/`'s deliberate
zero-build-step deferral of the PRD's own conditional React/Cytoscape/ELK
recommendation (§17.2) still holds, or whether a stack migration is real,
larger, separately-scoped work that must happen before Inventory/live-API
work proceeds.

## The exact target (PRD §21, verified this session)

| Metric | P0 target |
|---|---|
| First meaningful paint | Under 2 seconds for a graph with 5,000 nodes/10,000 edges on a reference laptop |
| Pan/zoom interaction | At least 45 FPS with no more than 2,000 visible elements after level-of-detail clustering |

Both require a real browser to measure honestly (JS execution + paint
timing; FPS during interaction) — not a synthetic Node-side benchmark.
This increment uses the Chrome browser automation tools available in
this session (`mcp__claude-in-chrome__*`).

## What already exists (confirmed by direct read, this session)

- `frontend/index.html` statically imports `FLAGSHIP_GRAPH` from
  `frontend/src/data/flagship-graph.js` (a generated module, 14 nodes/15
  edges) and calls `bootstrap(root, FLAGSHIP_GRAPH)`.
- `frontend/scripts/generate-fixture-module.mjs` is the REAL generator
  that reads a `DataFlowGraph v1` JSON, validates it with `validateGraph`
  (imported from `scanner/src/lineage/validate.js`), and writes the
  generated module — the exact mechanism to reuse for a synthetic large
  graph, not a hand-rolled second generator.
- `frontend/README.md`/`CLAUDE.md` name the current renderer as
  hand-rolled (no Cytoscape/ELK) — re-verify the EXACT rendering
  mechanism (SVG? Canvas? plain DOM nodes?) by reading `frontend/src/
  views/architecture-view.js` and whatever shared graph-rendering module
  it imports, before writing the synthetic-graph test, since the
  measurement's own methodology depends on knowing this.
- `frontend/package.json`'s `serve` script (`python3 -m http.server
  8420`) is the existing dev-server mechanism.

## Scope for this increment

1. **A synthetic large-graph generator**, new file (likely `bench/
   data-lineage/perf/generate-large-graph.mjs` or under `frontend/
   scripts/` — implementer's judgment, but it must produce a REAL,
   `validateGraph()`-clean `DataFlowGraph v1` document, not a shape that
   merely looks plausible): 5,000 nodes, 10,000 edges, a realistic mix of
   `NODE_KINDS` (source/sink/store/external/queue/log/process/
   unresolved), real stable IDs via `ids.js`'s own functions (never
   hand-constructed id strings — this package's own established
   convention), enough dataElements/flows to exercise Architecture/
   Privacy/Trace's own real code paths, not just node/edge counts. Run
   it through `validateGraph()` and confirm zero errors before using it
   for anything.
2. **Feed it through `frontend/scripts/generate-fixture-module.mjs`**
   (or a small variant, if the real script's own CLI doesn't accept an
   arbitrary input path — check first) to produce a large-graph module,
   loaded into a throwaway/temp HTML harness (a copy of `index.html`
   pointed at the large module, not a permanent change to the shipped
   `flagship-graph.js` — never overwrite the real fixture).
3. **Measure first meaningful paint**: serve the harness (`python3 -m
   http.server` or equivalent), load it in a real Chrome tab via the
   `mcp__claude-in-chrome__*` tools, and measure real paint/load timing
   (the Performance API's own `paint`/`largest-contentful-paint` entries,
   read via `javascript_tool`, or the browser's own Performance panel if
   more direct — implementer's judgment on the exact measurement
   mechanism, but it must be a REAL number read from a REAL loaded page,
   never estimated).
4. **Measure pan/zoom interaction FPS**: whatever pan/zoom interaction
   the CURRENT renderer actually supports (confirm this exists at all
   before measuring it — if the current implementation has no pan/zoom
   interaction yet, this is itself a finding, not a number to fabricate)
   under real user-driven interaction (via `computer` tool drag/scroll
   actions), reading frame timing via `requestAnimationFrame` sampling
   injected via `javascript_tool`, or the browser's own performance
   trace — real measured FPS, not assumed.
5. **Write up the finding** as a new short doc,
   `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-perf-result.md`:
   the exact measured numbers, whether they meet or miss each P0 target,
   and the resulting recommendation — EITHER "the current zero-build
   architecture meets the P0 performance gates measured against a real
   5,000/10,000 graph; proceed with it unchanged for M3-Server/Wire/
   Inventory" OR "the current architecture misses [specific target] by
   [specific measured margin]; a stack migration is real, scoped,
   separate work — do not proceed with Inventory/live-API work on the
   current renderer until that migration lands." Either answer is a
   valid, complete result for this increment — this is a measurement
   task, not a task with a predetermined correct outcome.

## Do NOT touch

`frontend/src/data/flagship-graph.js` (the real, committed, small
fixture — never overwritten by the large synthetic one). Any view
rendering code (this increment measures, it does not optimize — if the
measurement fails a target, the FIX is separately-scoped future work,
named in the write-up, not attempted here). The local server (Server
sub-project's own territory, not needed for this — the existing static
`http.server` dev harness is sufficient for a client-side rendering
measurement).

## Test plan

This IS the test — the write-up doc with real measured numbers is the
deliverable. No permanent automated test suite entry is expected from
this increment (a measurement, not a regression-guarded behavior) unless
the write-up's own recommendation is "stack unchanged," in which case
consider whether a lightweight perf-regression check belongs in `bench/`
— a judgment call for the write-up itself, not decided here.

## Explicitly deferred

Whatever the measurement recommends as follow-up work (a stack migration,
or specific renderer optimizations) — this increment measures and
recommends, it does not implement either.
