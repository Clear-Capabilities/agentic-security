import { worstVerdict, protectionVisual } from '../lib/protection-visual.js';
import { clear } from '../lib/dom.js';

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

  const pathNodeIds = new Set([flow.source, flow.sink]);
  for (const e of edges) {
    pathNodeIds.add(e.from);
    pathNodeIds.add(e.to);
  }
  const externalRecipients = graph.nodes
    .filter((n) => pathNodeIds.has(n.id) && n.externality?.value === 'external')
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
    totalDestinations: 1,
    protectedCount,
    unprotectedCount,
    unknownCount,
    externalRecipients,
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
