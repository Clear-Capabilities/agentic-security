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

export function computeArchitectureViewModel(graph, state) {
  const selection = resolveSelection(graph, state.selectedId);

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
  clear(canvasEl);

  const zoneCount = viewModel.zones.length;
  const maxNodesInAZone = Math.max(1, ...viewModel.zones.map((z) => z.nodeIds.length));
  const height = Math.max(480, maxNodesInAZone * (NODE_HEIGHT + NODE_GAP) + 80);
  const width = zoneCount * ZONE_WIDTH;

  const svg = svgEl('svg', { class: 'arch-view', viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Architecture view: trust zones, nodes, and data-flow edges' });

  const nodePositions = new Map();
  viewModel.zones.forEach((zone, zoneIndex) => {
    const zoneX = zoneIndex * ZONE_WIDTH;
    svg.appendChild(svgEl('rect', { class: 'arch-zone-bg', x: zoneX, y: 0, width: ZONE_WIDTH, height, rx: 4 }));
    const zoneLabel = svgEl('text', { class: 'arch-zone-label', x: zoneX + ZONE_PADDING, y: 24 });
    zoneLabel.textContent = zone.name;
    svg.appendChild(zoneLabel);

    zone.nodeIds.forEach((nodeId, i) => {
      const node = viewModel.nodes.find((n) => n.id === nodeId);
      const y = 48 + i * (NODE_HEIGHT + NODE_GAP);
      const x = zoneX + ZONE_PADDING;
      nodePositions.set(nodeId, { x: x + NODE_WIDTH / 2, y: y + NODE_HEIGHT / 2 });
      svg.appendChild(renderNode(node, x, y, onSelect));
    });
  });

  // Edges drawn after nodes so they can reference final positions; dimmed
  // edges are drawn first so a highlighted edge always renders on top.
  const sortedEdges = [...viewModel.edges].sort((a, b) => Number(a.selected) - Number(b.selected));
  for (const edge of sortedEdges) {
    const from = nodePositions.get(edge.from);
    const to = nodePositions.get(edge.to);
    if (!from || !to) continue; // an edge whose endpoint isn't rendered (shouldn't happen with this fixture) is safely skipped, not a crash
    svg.appendChild(renderEdge(edge, from, to, onSelect));
  }

  canvasEl.appendChild(svg);
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
