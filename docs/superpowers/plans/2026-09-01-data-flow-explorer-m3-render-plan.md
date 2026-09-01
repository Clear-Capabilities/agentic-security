# Milestone 3, sub-project Render: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Perf's own measured first-meaningful-paint failure at
the PRD's 5,000-node/10,000-edge reference scale, and add real pan/zoom
(currently entirely absent), via level-of-detail clustering + viewport
culling on the EXISTING hand-rolled SVG Architecture View — no build
step, no new dependency, per the user's own explicit direction.

**Architecture:** New pure functions in `architecture-view.js` (clustering,
edge aggregation, viewport culling, pan/zoom reducers) — all deterministic,
DOM-free, fully unit-testable. `renderArchitectureView` gains real
wheel/mouse event wiring that calls these reducers and a keyboard
equivalent. A final, required real-Chrome re-measurement (Perf's own
methodology, reused) proves the fix, rather than assuming it from the
math alone.

**Tech Stack:** Plain SVG DOM manipulation (`svgEl()`), `node --test` +
`test/dom-shim.js` for pure-function/structure tests, real Chrome via
`mcp__claude-in-chrome__*` for the final performance re-measurement.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-render-scoping.md`
(read this first — the full derivation of the 2,000-element budget, the
per-zone clustering design, why no dynamic rebalancing, and why pan/zoom
state stays module-local rather than URL-hash-persisted).

## Global Constraints

- `frontend/` only, Architecture View only (scoping decision 7) — no
  `scanner/` changes, no other view touched.
- No new dependency, no build step.
- `computeArchitectureViewModel`'s existing `{zones, nodes, edges,
  flowSummary}` return shape is UNCHANGED — new logic is a layer on top,
  consumed by `renderArchitectureView`, never a breaking change to the
  existing 18 `architecture-view.test.js` tests.
- **A currently-selected node/edge must NEVER become invisible due to
  clustering** — this is a real correctness requirement found during
  planning (not explicit in the scoping doc's own decision 1, which only
  addressed the tie-break for UNSELECTED nodes): a selected node bypasses
  the per-zone budget entirely and is always in the visible set; the
  budget applies only to the remaining, unselected nodes in that zone.
- Every new test file/extension added to `frontend/package.json`'s test
  script list if a new file is created (extensions to existing files
  need no package.json change).

---

### Task 1: Clustering + edge-aggregation pure functions

**Files:**
- Modify: `frontend/src/views/architecture-view.js` (add pure functions
  only — no `renderArchitectureView` changes yet)
- Test: `frontend/test/architecture-view.test.js` (extend)

**Interfaces:**
- Produces: `computeClusteredLayout(zones, nodes, budget) ->
  Array<{name, visibleNodeIds: string[], cluster: {id, count,
  kindSummary: string} | null}>` — one entry per zone, in `zones`' own
  order.
- Produces: `aggregateEdgesForClusters(edges, clusteredZones) ->
  Array<{id, from, to, verdict, selected, dimmed, constituentCount}>` —
  `constituentCount` is 1 for a real, unaggregated edge and >1 for an
  aggregate; `id`/`from`/`to` for an aggregate edge use a stable,
  deterministic synthetic id (see code below) so re-renders don't
  regenerate a new id for the same logical aggregate every time.

- [ ] **Step 1: Write failing tests for `computeClusteredLayout`**

Read `frontend/src/views/architecture-view.js` in full first (already
read this session for scoping — re-verify current content, since this is
production code others may have touched). Add to
`frontend/test/architecture-view.test.js`:

```js
import { computeClusteredLayout, aggregateEdgesForClusters } from '../src/views/architecture-view.js';

function makeNode(id, kind, zone, overrides = {}) {
  return { id, label: id, kind, subtype: null, zone, selected: false, dimmed: false, ...overrides };
}

test('computeClusteredLayout: a zone under budget has no cluster', () => {
  const zones = [{ name: 'Data Layer', nodeIds: ['n1', 'n2', 'n3'] }];
  const nodes = [makeNode('n1', 'store', 'Data Layer'), makeNode('n2', 'store', 'Data Layer'), makeNode('n3', 'log', 'Data Layer')];
  const result = computeClusteredLayout(zones, nodes, 10);
  assert.equal(result.length, 1);
  assert.deepEqual(result[0].visibleNodeIds, ['n1', 'n2', 'n3']);
  assert.equal(result[0].cluster, null);
});

test('computeClusteredLayout: a zone over budget clusters the overflow, budget-1 stay individually visible', () => {
  const nodeIds = Array.from({ length: 10 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id, i) => makeNode(id, i % 2 === 0 ? 'store' : 'log', 'Data Layer'));
  const result = computeClusteredLayout(zones, nodes, 4);
  assert.equal(result[0].visibleNodeIds.length, 3, 'budget of 4 leaves room for 1 cluster glyph slot: 3 individual + 1 cluster');
  assert.ok(result[0].cluster, 'expected a cluster for the overflow');
  assert.equal(result[0].cluster.count, 7, '10 total - 3 individually visible = 7 clustered');
  assert.ok(result[0].cluster.kindSummary.includes('store'));
  assert.ok(result[0].cluster.kindSummary.includes('log'));
});

test('computeClusteredLayout: a SELECTED node is always visible, bypassing the budget, even beyond the cutoff', () => {
  const nodeIds = Array.from({ length: 10 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id, i) => makeNode(id, 'store', 'Data Layer', { selected: id === 'n9' }));
  const result = computeClusteredLayout(zones, nodes, 4);
  assert.ok(result[0].visibleNodeIds.includes('n9'), 'the selected node (last in graph order, would normally be clustered) must stay visible');
  assert.equal(result[0].cluster.count, 6, '10 total - 3 unselected-individual - 1 selected = 6 clustered (one fewer than the unselected-only case, since n9 no longer competes for a budget slot but also is not counted as clustered)');
});

test('computeClusteredLayout: cluster kindSummary is deduplicated and sorted (deterministic across renders)', () => {
  const nodeIds = Array.from({ length: 6 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id) => makeNode(id, 'store', 'Data Layer'));
  const result = computeClusteredLayout(zones, nodes, 2);
  assert.equal(result[0].cluster.kindSummary, 'store', 'all-same-kind overflow should not repeat "store, store, store"');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: FAIL — `computeClusteredLayout` is not exported yet.

- [ ] **Step 3: Implement `computeClusteredLayout`**

Add to `frontend/src/views/architecture-view.js`, near
`computeArchitectureViewModel` (after it, before the SVG-rendering
section):

```js
/**
 * Per-zone level-of-detail clustering (PRD §21: "no more than 2,000
 * visible elements after level-of-detail clustering"). A currently-
 * SELECTED node always stays individually visible, bypassing `budget`
 * entirely — clustering must never hide the thing the user is looking
 * at. `budget` is the max number of individually-visible node SLOTS for
 * a zone, INCLUDING the cluster glyph's own slot when clustering is
 * needed (so `budget=4` with 10 nodes shows 3 real nodes + 1 cluster
 * glyph, never 4 real nodes + a cluster that would then be a 5th
 * element). Node order (for which unselected nodes stay visible) is
 * graph order — a defensible, simple tie-break, not sorted by anything
 * PRD-significant.
 *
 * @param {Array<{name: string, nodeIds: string[]}>} zones
 * @param {Array<{id: string, kind: string, zone: string, selected: boolean}>} nodes
 * @param {number} budget
 */
export function computeClusteredLayout(zones, nodes, budget) {
  const nodesById = new Map(nodes.map((n) => [n.id, n]));

  return zones.map((zone) => {
    const selectedIds = zone.nodeIds.filter((id) => nodesById.get(id)?.selected);
    const unselectedIds = zone.nodeIds.filter((id) => !nodesById.get(id)?.selected);

    if (zone.nodeIds.length <= budget) {
      return { name: zone.name, visibleNodeIds: [...zone.nodeIds], cluster: null };
    }

    // Selected nodes never count against the budget or get clustered.
    // The remaining budget (after reserving 1 slot for the cluster
    // glyph itself) goes to unselected nodes in graph order.
    const slotsForUnselected = Math.max(0, budget - 1);
    const visibleUnselected = unselectedIds.slice(0, slotsForUnselected);
    const clusteredIds = unselectedIds.slice(slotsForUnselected);

    if (clusteredIds.length === 0) {
      // Selected nodes alone pushed us over budget, or the unselected
      // set fit exactly — no real overflow to cluster.
      return { name: zone.name, visibleNodeIds: [...selectedIds, ...visibleUnselected], cluster: null };
    }

    const kindSummary = [...new Set(clusteredIds.map((id) => nodesById.get(id)?.kind).filter(Boolean))].sort().join(', ');

    return {
      name: zone.name,
      visibleNodeIds: [...selectedIds, ...visibleUnselected],
      cluster: {
        id: `cluster:${zone.name}`,
        count: clusteredIds.length,
        kindSummary,
        memberIds: clusteredIds,
      },
    };
  });
}
```

- [ ] **Step 4: Run to verify Step 1's tests pass**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: PASS for the 4 new tests (existing 18 must also still pass —
this file's full suite, not just the new tests).

- [ ] **Step 5: Write failing tests for `aggregateEdgesForClusters`**

```js
function makeEdge(id, from, to, verdict, overrides = {}) {
  return { id, from, to, verdict, selected: false, dimmed: false, ...overrides };
}

test('aggregateEdgesForClusters: an edge between two individually-visible nodes passes through unchanged', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a', 'b'], cluster: null }];
  const edges = [makeEdge('e1', 'a', 'b', 'protected')];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.deepEqual(result, [{ ...edges[0], constituentCount: 1 }]);
});

test('aggregateEdgesForClusters: multiple edges into the same cluster aggregate into one, worst verdict wins', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [
    makeEdge('e1', 'a', 'b', 'protected'),
    makeEdge('e2', 'a', 'c', 'unprotected'),
  ];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result.length, 1, 'both edges target the same cluster, from the same source — must aggregate to 1');
  assert.equal(result[0].from, 'a');
  assert.equal(result[0].to, 'cluster:Z');
  assert.equal(result[0].verdict, 'unprotected', 'worst of protected/unprotected is unprotected');
  assert.equal(result[0].constituentCount, 2);
});

test('aggregateEdgesForClusters: an edge selected if ANY constituent is selected', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [
    makeEdge('e1', 'a', 'b', 'protected', { selected: true }),
    makeEdge('e2', 'a', 'c', 'unprotected', { selected: false }),
  ];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result[0].selected, true);
});

test('aggregateEdgesForClusters: an edge entirely within one cluster (both endpoints clustered into the SAME cluster) is dropped, not rendered as a self-loop', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: [], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [makeEdge('e1', 'b', 'c', 'protected')];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result.length, 0);
});

test('aggregateEdgesForClusters: aggregate edge id is stable/deterministic across two calls with the same input (no re-render churn)', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [makeEdge('e1', 'a', 'b', 'protected'), makeEdge('e2', 'a', 'c', 'unprotected')];
  const result1 = aggregateEdgesForClusters(edges, clusteredZones);
  const result2 = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result1[0].id, result2[0].id);
});
```

- [ ] **Step 6: Implement `aggregateEdgesForClusters`**

```js
/**
 * Redirects an edge's endpoint to its zone's cluster glyph when that
 * endpoint's node was clustered away (computeClusteredLayout), then
 * groups edges sharing the same real (from, to) VISIBLE-endpoint pair
 * into one aggregate, reusing worstVerdict — the SAME aggregation
 * primitive edgeVerdict() already uses per-edge, applied here per-group.
 * An edge whose both endpoints resolve to the SAME cluster (entirely
 * "inside" one collapsed group) is dropped — it adds no information a
 * single cluster glyph doesn't already summarize.
 *
 * @param {Array<{id,from,to,verdict,selected,dimmed}>} edges
 * @param {ReturnType<typeof computeClusteredLayout>} clusteredZones
 */
export function aggregateEdgesForClusters(edges, clusteredZones) {
  const visibleIdFor = new Map();
  for (const zone of clusteredZones) {
    for (const id of zone.visibleNodeIds) visibleIdFor.set(id, id);
    if (zone.cluster) {
      for (const memberId of zone.cluster.memberIds) visibleIdFor.set(memberId, zone.cluster.id);
    }
  }

  const groups = new Map(); // key: `${visibleFrom}->${visibleTo}` -> edges[]
  for (const edge of edges) {
    const visibleFrom = visibleIdFor.get(edge.from) ?? edge.from;
    const visibleTo = visibleIdFor.get(edge.to) ?? edge.to;
    if (visibleFrom === visibleTo) continue; // dropped: collapsed self-loop
    const key = `${visibleFrom}->${visibleTo}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(edge);
  }

  return [...groups.entries()].map(([key, group]) => {
    const [from, to] = key.split('->');
    if (group.length === 1) return { ...group[0], from, to, constituentCount: 1 };
    return {
      id: `agg:${key}`, // deterministic — same (from,to) pair always yields the same id
      from,
      to,
      verdict: worstVerdict(group.map((e) => e.verdict)),
      selected: group.some((e) => e.selected),
      dimmed: group.every((e) => e.dimmed),
      constituentCount: group.length,
    };
  });
}
```

Note: `worstVerdict` is already imported at the top of this file — no new
import needed.

- [ ] **Step 7: Run full test file, commit**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: PASS, all tests (18 pre-existing + 9 new = 27).

```bash
git add frontend/src/views/architecture-view.js frontend/test/architecture-view.test.js
git commit -m "feat(frontend): level-of-detail clustering + edge aggregation for Architecture View (pure functions)"
```

---

### Task 2: Pan/zoom reducers + viewport culling (pure functions)

**Files:**
- Modify: `frontend/src/views/architecture-view.js` (add pure functions
  only — no `renderArchitectureView` wiring yet)
- Test: `frontend/test/architecture-view.test.js` (extend)

**Interfaces:**
- Produces: `applyWheelZoom(viewport, {deltaY, svgX, svgY}, bounds) ->
  {x, y, width, height}` — `viewport` and the return value are both
  `{x, y, width, height}` in the SAME shape as an SVG `viewBox`. Zooms
  centered on `(svgX, svgY)` (a point already in the SVG's own coordinate
  space — the CALLER converts a real mouse event's screen pixels to SVG
  coordinates, this function never touches the DOM). `bounds` is
  `{minWidth, maxWidth}` — clamps zoom level.
- Produces: `applyDragPan(viewport, {dxSvg, dySvg}, contentBounds) ->
  {x, y, width, height}` — pans by an SVG-space delta, clamped so the
  viewport cannot be dragged entirely off `contentBounds` (the full
  content's own `{x, y, width, height}`, i.e. `0,0,totalWidth,totalHeight`
  from the existing render function).
- Produces: `computeFitAllViewport(contentBounds) -> {x, y, width,
  height}` — the default viewport on first mount (decision 5: reset only
  on a fresh view-mount, not every rerender).
- Produces: `visibleNodeIds(nodePositions, viewportRect, margin) ->
  Set<string>` — `nodePositions` is a `Map<id, {x, y}>` (the SAME shape
  `renderArchitectureView`'s existing `nodePositions` local variable
  already builds — reuse it, don't rebuild).

- [ ] **Step 1: Write failing tests**

```js
test('computeFitAllViewport: returns the content bounds unchanged (default zoom = show everything)', () => {
  const result = computeFitAllViewport({ x: 0, y: 0, width: 1000, height: 2000 });
  assert.deepEqual(result, { x: 0, y: 0, width: 1000, height: 2000 });
});

test('applyWheelZoom: a negative deltaY (scroll up / zoom in) shrinks the viewport width/height', () => {
  const viewport = { x: 0, y: 0, width: 1000, height: 1000 };
  const result = applyWheelZoom(viewport, { deltaY: -100, svgX: 500, svgY: 500 }, { minWidth: 100, maxWidth: 5000 });
  assert.ok(result.width < 1000, 'zooming in should shrink the visible width');
});

test('applyWheelZoom: a positive deltaY (scroll down / zoom out) grows the viewport, clamped to maxWidth', () => {
  const viewport = { x: 0, y: 0, width: 4900, height: 4900 };
  const result = applyWheelZoom(viewport, { deltaY: 500, svgX: 2450, svgY: 2450 }, { minWidth: 100, maxWidth: 5000 });
  assert.ok(result.width <= 5000, 'must clamp to maxWidth, never exceed it');
});

test('applyWheelZoom: zooming in stays clamped at minWidth, never inverts/goes negative', () => {
  const viewport = { x: 0, y: 0, width: 150, height: 150 };
  const result = applyWheelZoom(viewport, { deltaY: -1000, svgX: 75, svgY: 75 }, { minWidth: 100, maxWidth: 5000 });
  assert.ok(result.width >= 100);
});

test('applyWheelZoom: zoom is centered on the cursor position, not the viewport origin', () => {
  const viewport = { x: 0, y: 0, width: 1000, height: 1000 };
  const zoomedAtCorner = applyWheelZoom(viewport, { deltaY: -200, svgX: 0, svgY: 0 }, { minWidth: 100, maxWidth: 5000 });
  const zoomedAtCenter = applyWheelZoom(viewport, { deltaY: -200, svgX: 500, svgY: 500 }, { minWidth: 100, maxWidth: 5000 });
  assert.notDeepEqual(zoomedAtCorner, zoomedAtCenter, 'zooming at different cursor positions must produce different viewports');
  assert.equal(zoomedAtCorner.x, 0, 'zooming at the top-left corner should keep that corner fixed (x does not go negative)');
});

test('applyDragPan: pans by the given SVG-space delta', () => {
  const viewport = { x: 100, y: 100, width: 500, height: 500 };
  const result = applyDragPan(viewport, { dxSvg: 50, dySvg: -30 }, { x: 0, y: 0, width: 5000, height: 5000 });
  assert.equal(result.x, 50);
  assert.equal(result.y, 70);
});

test('applyDragPan: clamps so the viewport cannot be dragged fully off content', () => {
  const viewport = { x: 0, y: 0, width: 500, height: 500 };
  const result = applyDragPan(viewport, { dxSvg: -10000, dySvg: -10000 }, { x: 0, y: 0, width: 5000, height: 5000 });
  assert.ok(result.x > -500, 'should not allow dragging the viewport entirely past the left edge of content');
  assert.ok(result.y > -500, 'should not allow dragging the viewport entirely past the top edge of content');
});

test('visibleNodeIds: returns only nodes within the viewport rect plus margin', () => {
  const nodePositions = new Map([['a', { x: 10, y: 10 }], ['b', { x: 1000, y: 1000 }]]);
  const viewportRect = { x: 0, y: 0, width: 100, height: 100 };
  const result = visibleNodeIds(nodePositions, viewportRect, 20);
  assert.ok(result.has('a'));
  assert.ok(!result.has('b'));
});

test('visibleNodeIds: the margin extends the culling boundary (avoids pop-in)', () => {
  const nodePositions = new Map([['a', { x: 110, y: 10 }]]); // just outside a 0,0,100,100 viewport
  const viewportRect = { x: 0, y: 0, width: 100, height: 100 };
  assert.ok(!visibleNodeIds(nodePositions, viewportRect, 5).has('a'), 'margin of 5 should not reach x=110');
  assert.ok(visibleNodeIds(nodePositions, viewportRect, 20).has('a'), 'margin of 20 should reach x=110 (100+20=120 > 110)');
});
```

- [ ] **Step 2: Run to verify it fails, then implement**

```js
export function computeFitAllViewport(contentBounds) {
  return { ...contentBounds };
}

/**
 * Pure zoom reducer — no DOM access. `svgX`/`svgY` are the cursor
 * position already converted to SVG-coordinate space by the caller
 * (real browser code, using getScreenCTM()/getBoundingClientRect() —
 * see Task 3). Zoom factor is a fixed, disclosed constant per wheel
 * "tick" rather than proportional to raw deltaY magnitude (real trackpad/
 * mouse-wheel deltaY values vary wildly across devices/browsers — a
 * fixed-step zoom avoids over- or under-reacting to a single event).
 */
const ZOOM_STEP = 0.1; // 10% per wheel tick

export function applyWheelZoom(viewport, { deltaY, svgX, svgY }, bounds) {
  const factor = deltaY < 0 ? 1 - ZOOM_STEP : 1 + ZOOM_STEP;
  const newWidth = Math.min(bounds.maxWidth, Math.max(bounds.minWidth, viewport.width * factor));
  const newHeight = Math.min(bounds.maxWidth, Math.max(bounds.minWidth, viewport.height * factor)); // aspect-locked to width's own clamp, since this view's aspect ratio is fixed by zone-column layout
  const actualFactor = newWidth / viewport.width;
  // Keep (svgX, svgY) fixed under the cursor: the point's own relative
  // position within the viewport (0..1 fraction) must be identical
  // before and after.
  const fracX = (svgX - viewport.x) / viewport.width;
  const fracY = (svgY - viewport.y) / viewport.height;
  return {
    x: svgX - fracX * newWidth,
    y: svgY - fracY * newHeight,
    width: newWidth,
    height: newHeight,
  };
}

export function applyDragPan(viewport, { dxSvg, dySvg }, contentBounds) {
  const minX = contentBounds.x - viewport.width; // allow dragging until only a sliver of content remains visible, never fully past it
  const maxX = contentBounds.x + contentBounds.width;
  const minY = contentBounds.y - viewport.height;
  const maxY = contentBounds.y + contentBounds.height;
  return {
    x: Math.min(maxX, Math.max(minX, viewport.x + dxSvg)),
    y: Math.min(maxY, Math.max(minY, viewport.y + dySvg)),
    width: viewport.width,
    height: viewport.height,
  };
}

export function visibleNodeIds(nodePositions, viewportRect, margin) {
  const minX = viewportRect.x - margin;
  const maxX = viewportRect.x + viewportRect.width + margin;
  const minY = viewportRect.y - margin;
  const maxY = viewportRect.y + viewportRect.height + margin;
  const result = new Set();
  for (const [id, pos] of nodePositions) {
    if (pos.x >= minX && pos.x <= maxX && pos.y >= minY && pos.y <= maxY) result.add(id);
  }
  return result;
}
```

Run each new test as written, fix any real off-by-one before moving on
(the drag-pan clamp test in particular — verify the exact clamp bounds
behave as asserted; adjust the assertion or the implementation, whichever
is actually wrong, and disclose which).

- [ ] **Step 3: Run full test file, commit**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: PASS, all tests (27 from Task 1 + 9 new = 36).

```bash
git add frontend/src/views/architecture-view.js frontend/test/architecture-view.test.js
git commit -m "feat(frontend): pan/zoom reducers + viewport culling (pure functions) for Architecture View"
```

---

### Task 3: Wire clustering/pan/zoom/culling into `renderArchitectureView`

**Files:**
- Modify: `frontend/src/views/architecture-view.js` (the render half)
- Test: `frontend/test/architecture-view-render.test.js` (extend)

This task is real DOM/event-wiring work with genuine implementation
latitude (exact key bindings, exact wheel-to-SVG-coordinate conversion)
— read `renderArchitectureView`'s CURRENT full body first (Tasks 1/2 may
have landed just above it in the file; re-read the whole file, don't
assume only your own prior diffs changed) before touching it.

- [ ] **Step 1: Compute a per-render node budget from the 2,000-element target**

Add a real, derived (not guessed) constant near the existing
`ZONE_WIDTH`/`NODE_HEIGHT` constants:

```js
// PRD §21: "no more than 2,000 visible elements after level-of-detail
// clustering." Each node is 3 SVG elements (rect+2 text, see renderNode);
// each rendered edge is ~2 (path+text, see renderEdge); 5 zones contribute
// 2 chrome elements each (bg rect + label text) = 10; a cluster glyph
// itself costs the same 3 elements as a real node. Budget conservatively:
// reserve 20% of the 2,000 target for edges/chrome, split the rest evenly
// across 5 zones.
const VISIBLE_ELEMENT_BUDGET = 2000;
const ZONE_CHROME_ELEMENTS = ZONE_ORDER.length * 2;
const EDGE_ELEMENT_RESERVE_FRACTION = 0.2;
const NODE_ELEMENTS_PER_NODE = 3;
function computeZoneNodeBudget() {
  const budgetForNodes = (VISIBLE_ELEMENT_BUDGET - ZONE_CHROME_ELEMENTS) * (1 - EDGE_ELEMENT_RESERVE_FRACTION);
  return Math.max(3, Math.floor(budgetForNodes / ZONE_ORDER.length / NODE_ELEMENTS_PER_NODE));
}
```

Confirm the resulting number is sane (print it, sanity-check it's neither
absurdly small (<10, which would clutter every real-sized zone with a
cluster even for a modest fixture) nor so large it never triggers on a
5,000-node graph split across 5 zones — 5,000/5 = 1,000 average per zone,
so the computed budget MUST be well under 1,000 for clustering to
actually engage at reference scale; if the formula above doesn't produce
that, fix the formula, don't fudge a constant).

- [ ] **Step 2: Add module-local pan/zoom state**

```js
// Module-local, NOT persisted to lib/state.js's URL hash — real UI state,
// not meaningfully shareable (scoping doc decision 5). Reset to fit-all
// only on a fresh view mount (Step 3), not on every selection-driven
// rerender within the same Architecture View session.
let currentViewport = null;
let lastRenderedContentBounds = null;
```

- [ ] **Step 3: Rewrite `renderArchitectureView`'s body**

Read the CURRENT full function before editing. The new body must:
1. Compute `zoneNodeBudget` (Step 1's function).
2. Call `computeClusteredLayout(viewModel.zones, viewModel.nodes, zoneNodeBudget)`.
3. Compute node positions EXACTLY as today (the existing per-zone
   vertical-stack loop), but only for each zone's `visibleNodeIds` PLUS
   one extra slot per zone for its `cluster` glyph (if any) — the cluster
   glyph occupies the position the first clustered node WOULD have had,
   so the layout math barely changes (fewer nodes in the loop, one
   optional cluster row appended at the end of each zone's own stack).
4. Compute `contentBounds = {x: 0, y: 0, width, height}` from the
   resulting layout (same `width`/`height` computation the current code
   already does, just based on the now-possibly-smaller per-zone counts).
5. If `currentViewport === null` OR `contentBounds` differs from
   `lastRenderedContentBounds` in a way that suggests a fresh mount
   (implementer's own judgment on the exact freshness check — e.g. track
   a separate `mountToken` the caller bumps on a real view switch, since
   comparing `contentBounds` alone would also reset zoom on every
   selection change that happens to alter clustering, which decision 5
   says should NOT happen): compute `currentViewport =
   computeFitAllViewport(contentBounds)`.
6. Set `svg`'s `viewBox` from `currentViewport`, not from `0 0 width
   height` as today.
7. Call `aggregateEdgesForClusters(viewModel.edges, clusteredZones)` and
   render the result instead of `viewModel.edges` directly.
8. Call `visibleNodeIds(nodePositions, currentViewport, margin)` (a real,
   disclosed margin constant, e.g. 100 SVG units) and skip creating DOM
   elements for nodes/edges outside it — BUT always still create elements
   for anything `selected` (same "never hide the selected thing"
   principle as clustering).
9. Render each zone's `cluster` glyph (if any) as a real, clickable
   `<g>` (mirroring `renderNode`'s own structure/pattern) showing the
   real count and kindSummary text; clicking it should re-render with
   that zone's budget effectively lifted (implementer's own mechanism —
   e.g. a module-local `Set` of "expanded zone names," checked by
   `computeClusteredLayout`'s caller before invoking it, passing
   `Infinity` as that zone's own effective budget — pick a clean way to
   thread this through without changing `computeClusteredLayout`'s own
   pure signature, since Task 1 already tested it against a plain
   number).
10. Wire real `wheel`, `mousedown`/`mousemove`/`mouseup` (or `pointerdown`/
    `pointermove`/`pointerup`, implementer's judgment — either is fine,
    pick whichever composes more simply with the existing `svgEl()`
    helper's event-wiring convention) handlers on the `<svg>` element
    itself, converting real screen coordinates to SVG-space via the
    SVG element's own `getScreenCTM()`/`createSVGPoint()` (standard DOM
    APIs — confirm `test/dom-shim.js` has SOME stub for these, or that
    the render function degrades gracefully — e.g. skip wiring if
    unavailable — under the shim; real interaction is only provable in a
    real browser regardless, per the scoping doc's own Test plan) calling
    `applyWheelZoom`/`applyDragPan` and re-rendering with the updated
    `currentViewport`.
11. Add a keyboard equivalent (scoping doc item 2): arrow keys pan by a
    fixed SVG-space step, `+`/`-` (or `=`/`-`) zoom by one `ZOOM_STEP`
    tick centered on the current viewport's own center, `0` resets to
    `computeFitAllViewport(contentBounds)`. Wire this as a `keydown`
    handler on the `<svg>` element (needs `tabindex` on the `<svg>` itself
    for it to receive keyboard focus — add one, with a real `aria-label`
    describing the controls, e.g. "Architecture view. Arrow keys pan,
    plus/minus zoom, 0 resets.").

- [ ] **Step 4: Extend `architecture-view-render.test.js`**

Read the file's current full content first. Add:

```js
test('a dense zone (over budget) renders exactly one cluster glyph, not one <g class="arch-node"> per overflow node', () => {
  const denseGraph = { /* build a small synthetic graph with e.g. 50 store-kind nodes in one zone — reuse this file's own existing fixture-building convention if one exists, otherwise construct minimally */ };
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(denseGraph, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const nodeGroups = canvasEl.querySelectorAll('[class="arch-node"]');
  const clusterGroups = canvasEl.querySelectorAll('[class="arch-node-cluster"]'); // or whichever real class name Step 3 actually used — confirm and use it here
  assert.ok(clusterGroups.length > 0, 'expected at least one cluster glyph for the dense zone');
  assert.ok(nodeGroups.length < denseGraph.nodes.length, 'far fewer individual node groups than raw node count');
});

test('clicking a cluster glyph expands it — the previously-clustered nodes now render individually', () => {
  // real, non-trivial: render once, confirm N is clustered; dispatch a
  // click on the cluster glyph; re-render (or confirm the render function
  // itself re-renders on click, per whatever Step 3's real click handler
  // does); confirm the same nodes now render as individual arch-node
  // groups, not folded into the cluster anymore.
});

test('an edge to a clustered node renders as a real, aggregated edge to the cluster glyph, with the worst constituent verdict', () => {
  // mirrors golden-architecture.test.js's own "raw vs masked" non-trivial
  // proof pattern: build a small fixture where 2 edges of DIFFERENT
  // verdicts both target nodes that end up in the same cluster, confirm
  // exactly 1 rendered edge group results, and its own aria-label/glyph
  // shows the WORSE of the two verdicts, never the better one.
});
```

Fill in the fixture/assertion details against the REAL render output
from Step 3's own implementation (read what class names/attributes it
actually produced — do not guess).

- [ ] **Step 5: Run full frontend test suite**

Run: `cd frontend && npm test`
Expected: PASS, real captured exit code 0.

- [ ] **Step 6: Manual smoke check**

Serve the app (`agentic-security explore` against a real scan, or
`npm run serve` against the existing flagship fixture) and confirm by
eye: Architecture View still renders correctly at the small flagship-
fixture scale (14 nodes — should show NO clustering, since 14 is far
under any zone's real budget); wheel-zoom and drag-pan both work; arrow-
key/+/-/0 keyboard controls work. Report exactly what was and wasn't
manually verified.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/views/architecture-view.js frontend/test/architecture-view-render.test.js
git commit -m "feat(frontend): wire clustering/pan-zoom/culling into Architecture View's real render + keyboard controls"
```

---

### Task 4: Real Perf-methodology re-measurement + docs

**Files:**
- Create (git-ignored, not committed): `frontend/perf-large.html`,
  `frontend/src/data/perf-large-graph.js` (regenerated via the existing
  `frontend/scripts/generate-perf-graph-module.mjs`)
- Modify: `frontend/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`

Performed directly by the coordinator (or a subagent with
`mcp__claude-in-chrome__*` access) — this is a real measurement requiring
judgment at each step, not a blind implementer dispatch, mirroring A11y's
own Task 3 precedent.

- [ ] **Step 1: Regenerate the measurement harness**

```bash
cd frontend && node scripts/generate-perf-graph-module.mjs
```

Confirm it reports the real 5,000-node/10,000-edge count and passed
`validateGraph()` (the script itself exits non-zero and prints validation
errors if not — read its real output, don't assume success).

`frontend/perf-large.html` itself needs to be recreated (git-ignored,
per `.gitignore`'s own `perf-large.html` entry — Perf's own result doc
claimed it was "committed," which was inaccurate; it never is). Build a
minimal page that imports `PERF_LARGE_GRAPH` from the regenerated module,
calls `bootstrap()` against a real `#app-root` div, and marks
`performance.mark('first-paint-check')` after two
`requestAnimationFrame` callbacks — mirroring Perf's own described
methodology exactly (real Performance API marks, verified against a real
paint/screenshot signal, never a JS-timer-only claim per Perf's own
documented false-PASS trap).

- [ ] **Step 2: Serve and measure first-meaningful-paint**

Serve `frontend/` (`npm run serve` or equivalent), navigate real Chrome
to `perf-large.html`, and measure first meaningful paint the SAME way
Perf's own sub-project did (real Performance API `first-paint`/
`first-contentful-paint` entries, cross-checked against a real
`Page.captureScreenshot`-style signal if the available tools support it —
use `mcp__claude-in-chrome__javascript_tool` to read
`performance.getEntriesByType('paint')` directly from the real page after
letting it settle a few seconds).

Record the real number. If it does NOT meet the 2s target, this is a
real, disclosed finding — do not soften it. If clustering did engage
(check the DOM: are cluster glyphs actually present, or did something in
Task 3's wiring silently fail to trigger at this scale?) but paint is
still slow, diagnose which part of the pipeline is the actual bottleneck
before reporting a final number.

- [ ] **Step 3: Measure pan/zoom responsiveness**

Interact with the page for real (via `mcp__claude-in-chrome__computer`'s
`scroll`/drag actions) at the large-graph scale — confirm no long janks,
and if the browser tooling available exposes a real frame-timing signal,
use it; otherwise report honestly that FPS was not independently
instrument-measured and describe what WAS observed (responsiveness by
feel is real information, clearly labeled as such, never dressed up as a
measured FPS number it isn't).

- [ ] **Step 4: Write up the real findings**

Add a "Milestone 3, sub-project Render — MEASURED, real result" section
to `frontend/CLAUDE.md`, mirroring Perf's own and A11y's own precedent
exactly: the real before/after numbers, whether the 2s/45fps targets are
now met, and any remaining gap honestly named (e.g. if clustering closes
most but not all of the gap, or if a specific interaction still janks).

- [ ] **Step 5: Update the M3 scoping table**

Mark Render's row in
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`
with the real outcome (COMPLETE only if the real re-measurement actually
passes; otherwise report the honest partial state).

- [ ] **Step 6: Full test suite + scanner gate, final commit**

```bash
cd frontend && npm test   # must still be green
cd scanner && npm test    # confirm unaffected
```

```bash
git add frontend/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md
git commit -m "docs(frontend): record M3-Render's real before/after performance measurement"
```

---

## Final integration checklist (coordinator, after all 4 tasks)

- Re-read every changed file in full.
- `cd frontend && npm test` green, real captured exit code.
- `cd scanner && npm test` green, real captured exit code.
- Confirm the flagship-fixture-scale (14 nodes) rendering is visually
  unchanged from before this sub-project (no clustering should ever
  engage at this tiny scale) — a real regression risk given how central
  `renderArchitectureView` is to every existing test/screenshot.
- Confirm `frontend/perf-large.html` / `src/data/perf-large-graph.js`
  are NOT accidentally staged for commit (`.gitignore` already covers
  them — verify `git status` shows them absent, not just ignored-and-
  forgotten).
