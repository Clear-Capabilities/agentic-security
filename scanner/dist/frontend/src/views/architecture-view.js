import { worstVerdict, protectionVisual } from '../lib/protection-visual.js';
import { el, clear } from '../lib/dom.js';
import { flowPathNodeIds } from '../lib/flow-path.js';

export const ZONE_ORDER = Object.freeze(['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone']);

export function zoneForNode(node) {
  switch (node.kind) {
    case 'source':
      return 'Public Internet';
    case 'api':
      return 'Application Layer';
    case 'process':
    case 'transform':
      return 'Service Layer';
    case 'store':
    case 'log':
    case 'queue':
    case 'sink':
      return 'Data Layer';
    case 'external':
    case 'unresolved':
      return 'External Zone';
    default:
      // boundary, or any future kind not yet mapped: a safe internal default
      // rather than silently dropping the node from every zone.
      return 'Service Layer';
  }
}

export function resolveSelection(graph, selectedId) {
  const empty = { active: false, nodeIds: new Set(), edgeIds: new Set(), flow: null };
  if (!selectedId) return empty;

  const flow = graph.flows.find((f) => f.id === selectedId);
  if (flow) {
    const edgeIds = new Set(flow.edgeIds);
    const nodeIds = new Set();
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) {
        nodeIds.add(edge.from);
        nodeIds.add(edge.to);
      }
    }
    nodeIds.add(flow.source);
    nodeIds.add(flow.sink);
    return { active: true, nodeIds, edgeIds, flow };
  }

  const node = graph.nodes.find((n) => n.id === selectedId);
  if (node) {
    const edgeIds = new Set(graph.edges.filter((e) => e.from === selectedId || e.to === selectedId).map((e) => e.id));
    return { active: true, nodeIds: new Set([selectedId]), edgeIds, flow: null };
  }

  const edge = graph.edges.find((e) => e.id === selectedId);
  if (edge) {
    return { active: true, nodeIds: new Set([edge.from, edge.to]), edgeIds: new Set([selectedId]), flow: null };
  }

  return empty;
}

function edgeVerdict(edge) {
  return worstVerdict([edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict]);
}

export function computeFlowSummary(graph, flow) {
  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);

  const pathNodeIds = flowPathNodeIds(graph, flow);
  const externalRecipients = graph.nodes
    .filter((n) => pathNodeIds.has(n.id) && n.externality?.value === 'external')
    .map((n) => n.label);
  // 'unknown' externality is NOT safe to fold into "no external recipients" —
  // it means the scanner could not resolve the destination (e.g. a dynamic
  // URL expression), which is a distinct risk from a confirmed-internal
  // recipient. Tracked separately so callers can't mistake "we don't know"
  // for "we checked and it's fine" (I4, final whole-branch review).
  const unknownRecipients = graph.nodes
    .filter((n) => pathNodeIds.has(n.id) && n.externality?.value === 'unknown')
    .map((n) => n.label);

  let protectedCount = 0;
  let unprotectedCount = 0;
  let unknownCount = 0;
  for (const e of edges) {
    const v = edgeVerdict(e);
    if (v === 'protected') protectedCount += 1;
    else if (v === 'unprotected' || v === 'mixed') unprotectedCount += 1;
    else unknownCount += 1;
  }

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    sourceLabel: sourceNode?.label ?? 'unknown source',
    destinationLabel: sinkNode?.label ?? 'unknown destination',
    protectedCount,
    unprotectedCount,
    unknownCount,
    externalRecipients,
    unknownRecipients,
    transitVerdict: worstVerdict(edges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(edges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(edges.map((e) => e.protection.handling.verdict)),
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
  };
}

/**
 * @param {object} graph
 * @param {object} state
 * @param {{nodeIds: Set<string>, edgeIds: Set<string>} | null} [focusSelection] -
 *   Milestone 3, sub-project M3-UX-Query, Task 4. An optional pre-computed
 *   selection override — the SAME `{nodeIds, edgeIds}` shape every
 *   `lib/focus-controls.js` function already returns. When present (non-
 *   null), it is used AS the `selection` variable directly, bypassing
 *   `resolveSelection(graph, state.selectedId)` entirely for this render —
 *   a focus control's own multi-node result has no single canonical
 *   `selectedId` to look up. When omitted/null (the default, and what every
 *   pre-existing caller/test already passes), behavior is unchanged:
 *   `resolveSelection` runs exactly as it always has.
 */
export function computeArchitectureViewModel(graph, state, focusSelection = null) {
  const selection = focusSelection
    ? { active: true, nodeIds: focusSelection.nodeIds, edgeIds: focusSelection.edgeIds, flow: null }
    : resolveSelection(graph, state.selectedId);

  const zones = ZONE_ORDER.map((name) => ({
    name,
    nodeIds: graph.nodes.filter((n) => zoneForNode(n) === name).map((n) => n.id),
  }));

  const nodes = graph.nodes.map((n) => ({
    id: n.id,
    label: n.label,
    kind: n.kind,
    subtype: n.subtype,
    zone: zoneForNode(n),
    selected: selection.nodeIds.has(n.id),
    dimmed: selection.active && !selection.nodeIds.has(n.id),
  }));

  const edges = graph.edges.map((e) => ({
    id: e.id,
    from: e.from,
    to: e.to,
    verdict: edgeVerdict(e),
    selected: selection.edgeIds.has(e.id),
    dimmed: selection.active && !selection.edgeIds.has(e.id),
  }));

  const flowSummary = selection.flow ? computeFlowSummary(graph, selection.flow) : null;

  return { zones, nodes, edges, flowSummary };
}

// Renders computeFlowSummary()'s output into the shell's context rail
// (frontend/src/shell.js's getContextRailEl()). This is a plain HTML panel,
// not part of the SVG canvas, so it's built via el() (lib/dom.js) — NOT
// svgEl() — matching Privacy View / Trace View's convention of using el()
// for anything outside the <svg> tree.
export function renderFlowSummary(flowSummary, contextRailEl) {
  clear(contextRailEl);
  if (!flowSummary) return;

  const dims = [
    ['Transit', flowSummary.transitVerdict],
    ['At rest', flowSummary.atRestVerdict],
    ['Handling', flowSummary.handlingVerdict],
  ].map(([label, verdict]) => {
    const v = protectionVisual(verdict);
    return el('div', {}, `${v.glyph} ${label}: ${v.label}`);
  });

  const recipientsLine = (label, names) => (names.length > 0 ? el('div', {}, `${label}: ${names.join(', ')}`) : null);

  contextRailEl.appendChild(
    el('div', { class: 'flow-summary' }, [
      el('h4', {}, flowSummary.dataElementName),
      el('div', {}, flowSummary.dataClasses.join(', ')),
      el('div', {}, `${flowSummary.sourceLabel} → ${flowSummary.destinationLabel}`),
      el('div', {}, `${flowSummary.protectedCount} protected · ${flowSummary.unprotectedCount} unprotected · ${flowSummary.unknownCount} unknown`),
      recipientsLine('External recipients', flowSummary.externalRecipients),
      recipientsLine('Unknown-externality recipients', flowSummary.unknownRecipients),
      ...dims,
    ].filter(Boolean)),
  );
}

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

/**
 * Default viewport on first mount: show the entire content bounds
 * unchanged (decision 5: reset only on a fresh view-mount, not every
 * rerender — the caller owns when this gets called again).
 *
 * @param {{x: number, y: number, width: number, height: number}} contentBounds
 */
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
 *
 * The centered-on-cursor property is algebraic, not approximate: `newX`
 * is derived by solving `(svgX - newX) / newWidth === fracX` for `newX`,
 * so the cursor's fractional position within the viewport is IDENTICAL
 * before and after the zoom, for any resulting `newWidth`/`newHeight`
 * (including after clamping) — not just for the unclamped case.
 */
const ZOOM_STEP = 0.1; // 10% per wheel tick

export function applyWheelZoom(viewport, { deltaY, svgX, svgY }, bounds) {
  const factor = deltaY < 0 ? 1 - ZOOM_STEP : 1 + ZOOM_STEP;
  const newWidth = Math.min(bounds.maxWidth, Math.max(bounds.minWidth, viewport.width * factor));
  const newHeight = Math.min(bounds.maxWidth, Math.max(bounds.minWidth, viewport.height * factor)); // aspect-locked to width's own clamp, since this view's aspect ratio is fixed by zone-column layout
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

/**
 * Pans by an SVG-space delta, clamped so the viewport cannot be dragged
 * entirely off `contentBounds` — a sliver of content always remains
 * visible at the boundary, rather than the viewport being allowed to
 * drift into empty space with nothing on screen.
 */
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

/**
 * Viewport-culling predicate for level-of-detail rendering at scale:
 * which node ids fall within `viewportRect` expanded by `margin` on all
 * sides (the margin avoids visible pop-in as a node crosses the exact
 * edge). `nodePositions` is the SAME `Map<id, {x, y}>` shape
 * `renderArchitectureView` already builds locally — reuse it there,
 * don't rebuild it.
 */
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

const SVG_NS = 'http://www.w3.org/2000/svg';
const ZONE_WIDTH = 220;
const ZONE_PADDING = 12;
const NODE_HEIGHT = 44;
const NODE_GAP = 16;
const NODE_WIDTH = ZONE_WIDTH - ZONE_PADDING * 2;

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
// Sanity-checked (this session, real numbers): with the constants above this
// evaluates to 106 — well under the ~1,000-per-zone average a 5,000-node
// graph split across 5 zones would produce (so clustering actually engages
// at PRD reference scale), and far above the <10 floor that would clutter
// every modest fixture with a cluster glyph.

// Module-local, NOT persisted to lib/state.js's URL hash — real UI state,
// not meaningfully shareable (scoping doc decision 5).
//
// Simplification of the brief's own Step 3.5 (documented in the task-3
// context, not just here): `renderArchitectureView`'s caller (app.js) has
// no "this is a fresh view mount, not a same-view rerender" signal today,
// and adding one is out of this task's file list (architecture-view.js
// only). Instead: currentViewport starts null and is set to a fit-all
// viewport ONLY the very first time this module ever renders. It is never
// auto-reset again afterward — only via the user's own "0" key, a cluster
// expansion (see expandedZones' onClick below — re-fitting there is a
// deliberate, real necessity, not a copy-paste of the mount rule: without
// it, newly-revealed nodes from an expanded cluster could land outside the
// still-small pre-expansion viewport and be viewport-culled right back out
// of the DOM, silently undoing the click), or a page reload. This means
// pan/zoom position is preserved across ordinary view switches away from
// and back to Architecture View — simpler, fully local to this file, and
// does not violate AC-16 (which requires selection/filters/header/coverage
// state to survive a view switch, and says nothing about pan/zoom).
let currentViewport = null;
// Module-local set of zone names whose per-zone budget is lifted to
// Infinity by a user click on that zone's cluster glyph (see
// computeEffectiveClusteredLayout below). Kept as a Set, not folded into
// currentViewport, so it survives independently of pan/zoom resets.
const expandedZones = new Set();
// Module-local, keyed the same way `currentViewport` is: drag state must
// survive a rerender (renderArchitectureView tears down and rebuilds the
// entire <svg> tree on every pan/zoom-driven rerender, including the ones
// fired mid-drag from `mousemove`), or a real mouse-drag gesture would
// silently stop after its first `mousemove` event — the old <svg> (and any
// per-render-closure-local drag state) is gone, and no second `mousedown`
// ever fires to restart it.
let dragState = null;

const CULL_MARGIN = 100; // SVG units; see visibleNodeIds' own margin param
const KEYBOARD_PAN_STEP = 40; // SVG units per arrow-key press
const MIN_VIEWPORT_WIDTH = 150; // SVG units; deepest zoom-in via wheel/keyboard

// computeClusteredLayout (Task 1) intentionally takes one `budget` number
// applied uniformly to every zone — already tested against a plain number,
// and Task 3 must not change that signature. To let ONE zone's budget be
// lifted (cluster-glyph click, "show me everything in this zone"), split
// the zones into "expanded" (budget=Infinity) and "everyone else" (the
// real zoneNodeBudget), call computeClusteredLayout once per group, and
// merge back in the original zone order.
function computeEffectiveClusteredLayout(zones, nodes, budget, expandedZoneNames) {
  const expanded = zones.filter((z) => expandedZoneNames.has(z.name));
  const collapsed = zones.filter((z) => !expandedZoneNames.has(z.name));
  const expandedResult = expanded.length > 0 ? computeClusteredLayout(expanded, nodes, Infinity) : [];
  const collapsedResult = collapsed.length > 0 ? computeClusteredLayout(collapsed, nodes, budget) : [];
  const byName = new Map([...expandedResult, ...collapsedResult].map((z) => [z.name, z]));
  return zones.map((z) => byName.get(z.name));
}

// Real screen-to-SVG-space coordinate conversion, via the standard
// getScreenCTM()/createSVGPoint() DOM APIs — NOT available on test/dom-
// shim.js's FakeElement (it has no CSSOM/layout engine to compute a CTM
// against), so every call site guards with `supportsPointerConversion`
// first and skips wiring entirely when it's false. Real interaction is
// only provable in a real browser regardless (Step 6).
function screenToSvgPoint(svgElement, clientX, clientY) {
  const pt = svgElement.createSVGPoint();
  pt.x = clientX;
  pt.y = clientY;
  return pt.matrixTransform(svgElement.getScreenCTM().inverse());
}

function zoomBoundsFor(contentBounds) {
  return { minWidth: MIN_VIEWPORT_WIDTH, maxWidth: Math.max(contentBounds.width, MIN_VIEWPORT_WIDTH) };
}

// Builds an element in the SVG namespace (createElementNS), unlike `el()`
// (lib/dom.js) which always calls createElement and produces an HTML-
// namespaced element — a foreign element inside an <svg> tree that neither
// paints nor paints its children (C1, final whole-branch review). Event
// handlers are wired the same way `el()` does (addEventListener, not
// setAttribute); everything else — including `class` — goes through plain
// setAttribute, which is correct for SVG elements. Do NOT set `.className`
// here: it's a read-only SVGAnimatedString on SVG elements, and assigning to
// it is a silent no-op that would drop every CSS class.
export function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      node.setAttribute(key, String(value));
    }
  }
  return node;
}

/**
 * @param {ReturnType<typeof computeArchitectureViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(id: string) => void} onSelect
 */
export function renderArchitectureView(viewModel, canvasEl, onSelect) {
  // Real, disclosed finding from this session's own manual browser smoke
  // check (Step 6): every pan/zoom-driven rerender tears down and rebuilds
  // the ENTIRE <svg> from scratch. A real browser does NOT transfer focus
  // to a freshly-inserted replacement element, so without this, a single
  // keyboard-driven zoom/pan keystroke would work but a SECOND rapid one
  // (e.g. holding "-") would silently do nothing — the old, focused <svg>
  // is already gone, and nothing ever refocuses the new one. Recorded here
  // (not just observed and left alone) because this is exactly the class
  // of bug a manual-only check without direct focus inspection would miss
  // (see app.js's own comment on the analogous Task-5/Task-7 lesson).
  const previouslyFocusedSvg = typeof document !== 'undefined' && document.activeElement === canvasEl.firstChild ? canvasEl.firstChild : null;
  clear(canvasEl);

  function rerender() {
    renderArchitectureView(viewModel, canvasEl, onSelect);
  }

  const zoneNodeBudget = computeZoneNodeBudget();
  const clusteredZones = computeEffectiveClusteredLayout(viewModel.zones, viewModel.nodes, zoneNodeBudget, expandedZones);
  const nodesById = new Map(viewModel.nodes.map((n) => [n.id, n]));

  const zoneCount = clusteredZones.length;
  const maxRowsInAZone = Math.max(1, ...clusteredZones.map((z) => z.visibleNodeIds.length + (z.cluster ? 1 : 0)));
  const height = Math.max(480, maxRowsInAZone * (NODE_HEIGHT + NODE_GAP) + 80);
  const width = zoneCount * ZONE_WIDTH;
  const contentBounds = { x: 0, y: 0, width, height };

  if (currentViewport === null) {
    currentViewport = computeFitAllViewport(contentBounds);
  }

  const svg = svgEl('svg', {
    class: 'arch-view',
    viewBox: `${currentViewport.x} ${currentViewport.y} ${currentViewport.width} ${currentViewport.height}`,
    role: 'img',
    tabindex: '0',
    'aria-label': 'Architecture view: trust zones, nodes, and data-flow edges. Arrow keys pan, plus/minus zoom, 0 resets.',
  });

  // Pass 1: lay out every INDIVIDUALLY-VISIBLE node (post-clustering) and
  // each zone's own cluster glyph, recording positions for all of them —
  // viewport culling (pass 2 below) needs every position up front, since
  // an edge's endpoint may resolve to either a node or a cluster glyph.
  const nodePositions = new Map();
  const pendingNodes = []; // {node, x, y}
  const pendingClusters = []; // {zone, x, y}
  clusteredZones.forEach((zone, zoneIndex) => {
    const zoneX = zoneIndex * ZONE_WIDTH;
    svg.appendChild(svgEl('rect', { class: 'arch-zone-bg', x: zoneX, y: 0, width: ZONE_WIDTH, height, rx: 4 }));
    const zoneLabel = svgEl('text', { class: 'arch-zone-label', x: zoneX + ZONE_PADDING, y: 24 });
    zoneLabel.textContent = zone.name;
    svg.appendChild(zoneLabel);

    let row = 0;
    for (const nodeId of zone.visibleNodeIds) {
      const node = nodesById.get(nodeId);
      const y = 48 + row * (NODE_HEIGHT + NODE_GAP);
      const x = zoneX + ZONE_PADDING;
      nodePositions.set(nodeId, { x: x + NODE_WIDTH / 2, y: y + NODE_HEIGHT / 2 });
      pendingNodes.push({ node, x, y });
      row += 1;
    }
    if (zone.cluster) {
      const y = 48 + row * (NODE_HEIGHT + NODE_GAP);
      const x = zoneX + ZONE_PADDING;
      nodePositions.set(zone.cluster.id, { x: x + NODE_WIDTH / 2, y: y + NODE_HEIGHT / 2 });
      pendingClusters.push({ zone, x, y });
    }
  });

  // Pass 2: viewport culling. A currently-selected node always renders
  // regardless of the viewport, same "never hide the thing the user is
  // looking at" principle clustering already applies to the budget.
  const visible = visibleNodeIds(nodePositions, currentViewport, CULL_MARGIN);
  for (const { node, x, y } of pendingNodes) {
    if (!visible.has(node.id) && !node.selected) continue;
    svg.appendChild(renderNode(node, x, y, onSelect));
  }
  for (const { zone, x, y } of pendingClusters) {
    if (!visible.has(zone.cluster.id)) continue;
    svg.appendChild(renderClusterGlyph(zone.cluster, x, y, () => {
      expandedZones.add(zone.name);
      // A just-expanded cluster's newly-individual nodes can land outside
      // the current (pre-expansion) viewport; re-fit so the user actually
      // sees what they just asked to see, rather than having it culled
      // straight back out of the DOM. See currentViewport's own comment.
      currentViewport = null;
      rerender();
    }));
  }

  // Edges: only edges actually touched by clustering (an endpoint that got
  // folded into a cluster glyph) go through aggregateEdgesForClusters.
  // Real, disclosed finding this session: aggregateEdgesForClusters groups
  // PURELY by post-redirect (from, to) pair — with NO clustering involved
  // at all, feeding it every edge unconditionally would ALSO merge two
  // genuinely distinct real edges that happen to share the same (from, to)
  // node pair (the flagship fixture has exactly this: masked_log's and
  // raw_log's own log-write edges both run process->log with different
  // verdicts), silently collapsing them to one worst-verdict edge and
  // regressing AC-17's "raw vs masked render distinct verdicts" golden
  // test. Splitting the input here (not touching aggregateEdgesForClusters
  // itself, which Task 1 already shipped and tested) keeps every
  // untouched edge exactly as before, and only reroutes+aggregates the
  // ones clustering actually affected.
  const clusteredMemberIds = new Set();
  for (const zone of clusteredZones) {
    if (zone.cluster) for (const memberId of zone.cluster.memberIds) clusteredMemberIds.add(memberId);
  }
  const edgesTouchedByClustering = viewModel.edges.filter((e) => clusteredMemberIds.has(e.from) || clusteredMemberIds.has(e.to));
  const edgesUntouchedByClustering = viewModel.edges.filter((e) => !clusteredMemberIds.has(e.from) && !clusteredMemberIds.has(e.to));
  const aggregatedEdges = edgesTouchedByClustering.length > 0 ? aggregateEdgesForClusters(edgesTouchedByClustering, clusteredZones) : [];
  const allRenderableEdges = [...edgesUntouchedByClustering, ...aggregatedEdges];

  // Culled the same way as nodes — an edge with either endpoint visible
  // (or itself selected) still renders; dimmed edges are drawn first so a
  // highlighted edge always renders on top.
  const sortedEdges = [...allRenderableEdges].sort((a, b) => Number(a.selected) - Number(b.selected));
  for (const edge of sortedEdges) {
    const from = nodePositions.get(edge.from);
    const to = nodePositions.get(edge.to);
    if (!from || !to) continue; // an edge whose endpoint isn't rendered (shouldn't happen) is safely skipped, not a crash
    if (!edge.selected && !visible.has(edge.from) && !visible.has(edge.to)) continue;
    svg.appendChild(renderEdge(edge, from, to, onSelect));
  }

  const supportsPointerConversion = typeof svg.getScreenCTM === 'function' && typeof svg.createSVGPoint === 'function';
  if (supportsPointerConversion) {
    svg.addEventListener('wheel', (evt) => {
      evt.preventDefault();
      const { x: svgX, y: svgY } = screenToSvgPoint(svg, evt.clientX, evt.clientY);
      currentViewport = applyWheelZoom(currentViewport, { deltaY: evt.deltaY, svgX, svgY }, zoomBoundsFor(contentBounds));
      rerender();
    });
    svg.addEventListener('mousedown', (evt) => {
      const p = screenToSvgPoint(svg, evt.clientX, evt.clientY);
      dragState = { lastX: p.x, lastY: p.y };
    });
    svg.addEventListener('mousemove', (evt) => {
      if (!dragState) return;
      const p = screenToSvgPoint(svg, evt.clientX, evt.clientY);
      // Content under the cursor should stay under the cursor: shift the
      // viewport by the NEGATIVE of the cursor's own SVG-space delta.
      const dxSvg = dragState.lastX - p.x;
      const dySvg = dragState.lastY - p.y;
      dragState = { lastX: p.x, lastY: p.y };
      currentViewport = applyDragPan(currentViewport, { dxSvg, dySvg }, contentBounds);
      rerender();
    });
    svg.addEventListener('mouseup', () => { dragState = null; });
    svg.addEventListener('mouseleave', () => { dragState = null; });
  }

  svg.addEventListener('keydown', (evt) => {
    switch (evt.key) {
      case 'ArrowUp':
        evt.preventDefault();
        currentViewport = applyDragPan(currentViewport, { dxSvg: 0, dySvg: -KEYBOARD_PAN_STEP }, contentBounds);
        break;
      case 'ArrowDown':
        evt.preventDefault();
        currentViewport = applyDragPan(currentViewport, { dxSvg: 0, dySvg: KEYBOARD_PAN_STEP }, contentBounds);
        break;
      case 'ArrowLeft':
        evt.preventDefault();
        currentViewport = applyDragPan(currentViewport, { dxSvg: -KEYBOARD_PAN_STEP, dySvg: 0 }, contentBounds);
        break;
      case 'ArrowRight':
        evt.preventDefault();
        currentViewport = applyDragPan(currentViewport, { dxSvg: KEYBOARD_PAN_STEP, dySvg: 0 }, contentBounds);
        break;
      case '+':
      case '=':
        evt.preventDefault();
        currentViewport = applyWheelZoom(
          currentViewport,
          { deltaY: -1, svgX: currentViewport.x + currentViewport.width / 2, svgY: currentViewport.y + currentViewport.height / 2 },
          zoomBoundsFor(contentBounds),
        );
        break;
      case '-':
        evt.preventDefault();
        currentViewport = applyWheelZoom(
          currentViewport,
          { deltaY: 1, svgX: currentViewport.x + currentViewport.width / 2, svgY: currentViewport.y + currentViewport.height / 2 },
          zoomBoundsFor(contentBounds),
        );
        break;
      case '0':
        evt.preventDefault();
        currentViewport = computeFitAllViewport(contentBounds);
        break;
      default:
        return;
    }
    rerender();
  });

  canvasEl.appendChild(svg);
  if (previouslyFocusedSvg && typeof svg.focus === 'function') svg.focus();
}

function renderNode(node, x, y, onSelect) {
  const group = svgEl('g', {
    class: 'arch-node',
    'data-selected': String(node.selected),
    'data-dimmed': String(node.dimmed),
    tabindex: '0',
    role: 'button',
    'aria-label': `${node.label}, ${node.kind}${node.selected ? ', selected' : ''}`,
    onClick: () => onSelect(node.id),
    onKeydown: (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        onSelect(node.id);
      }
    },
  });
  group.appendChild(svgEl('rect', { class: 'arch-node-box', x, y, width: NODE_WIDTH, height: NODE_HEIGHT }));
  const glyph = svgEl('text', { class: 'arch-node-glyph', x: x + 8, y: y + 16 });
  glyph.textContent = node.kind.slice(0, 3).toUpperCase();
  group.appendChild(glyph);
  const label = svgEl('text', { class: 'arch-node-label', x: x + 8, y: y + 34 });
  label.textContent = node.label;
  group.appendChild(label);
  return group;
}

function renderEdge(edge, from, to, onSelect) {
  const visual = protectionVisual(edge.verdict);
  const midX = (from.x + to.x) / 2;
  const midY = (from.y + to.y) / 2;
  const path = svgEl('path', {
    d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`,
    style: `stroke: var(${visual.colorVar})`,
  });
  const group = svgEl('g', {
    class: 'arch-edge',
    'data-selected': String(edge.selected),
    'data-dimmed': String(edge.dimmed),
    tabindex: '0',
    role: 'button',
    'aria-label': `Edge, protection ${visual.label}${edge.selected ? ', selected' : ''}`,
    onClick: () => onSelect(edge.id),
    onKeydown: (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        onSelect(edge.id);
      }
    },
  });
  path.classList.add(`arch-edge-linestyle-${visual.lineStyle === 'solid' ? 'solid' : visual.lineStyle}`);
  group.appendChild(path);
  const glyph = svgEl('text', { class: 'arch-edge-glyph', x: midX, y: midY - 4, fill: `var(${visual.colorVar})` });
  glyph.textContent = visual.glyph;
  group.appendChild(glyph);
  return group;
}

// The cluster glyph mirrors renderNode()'s own structure/pattern (a
// clickable <g> with a box + two text children) so it reads as "one more
// node-shaped thing" rather than a visually distinct control. `onExpand`
// is renderArchitectureView's own closure — adds this zone to
// `expandedZones` and re-renders.
function renderClusterGlyph(cluster, x, y, onExpand) {
  const group = svgEl('g', {
    class: 'arch-node-cluster',
    tabindex: '0',
    role: 'button',
    'aria-label': `${cluster.count} more ${cluster.kindSummary || 'nodes'} folded into this cluster. Activate to expand.`,
    onClick: onExpand,
    onKeydown: (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        onExpand();
      }
    },
  });
  group.appendChild(svgEl('rect', { class: 'arch-node-cluster-box', x, y, width: NODE_WIDTH, height: NODE_HEIGHT }));
  const count = svgEl('text', { class: 'arch-node-cluster-count', x: x + 8, y: y + 20 });
  count.textContent = `+${cluster.count}`;
  group.appendChild(count);
  const kind = svgEl('text', { class: 'arch-node-cluster-kind', x: x + 8, y: y + 36 });
  kind.textContent = cluster.kindSummary;
  group.appendChild(kind);
  return group;
}
