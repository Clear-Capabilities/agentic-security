// Inventory View: PRD §7.6's 11 required inventory categories. Split into
// pure computeInventoryViewModel() (each per-category compute function
// producing {columns, rows}) and thin renderInventoryView() (DOM-building
// via el()/clear()), mirroring every other view in src/views/.

import { worstVerdict } from '../lib/protection-visual.js';
import { AI_SUBTYPES } from '../lib/flow-path.js';
import { INVENTORY_TABLES } from '../lib/state.js';
import { el, clear } from '../lib/dom.js';
import { matchesFilters } from '../lib/row-filters.js';

const TABLE_LABELS = {
  sources: 'Sources',
  sinks: 'Sinks',
  fields: 'Fields / data elements',
  externalDestinations: 'External destinations',
  stores: 'Stores',
  aiSystems: 'AI systems & processing contexts',
  transformations: 'Transformations',
  unprotectedEdges: 'Unprotected or unknown edges',
  policyPermittedFlows: 'Policy-permitted flows',
  manualGovernanceGaps: 'Manual governance gaps',
  unsupportedCandidates: 'Unsupported or unresolved candidates',
};

const UNPROTECTED_TIERS = new Set(['unprotected', 'mixed', 'unknown']);

function edgeWorstVerdict(edge) {
  return worstVerdict([edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict]);
}

function nodeLabelFor(graph, nodeId) {
  return graph.nodes.find((n) => n.id === nodeId)?.label ?? 'unknown';
}

// The same per-flow filter-facet properties privacy-view.js's
// computePrivacyRow() attaches, computed the same way (this flow's own
// resolved edges, aggregated per-dimension via worstVerdict()), for
// Inventory's two flow-shaped categories (policyPermittedFlows,
// manualGovernanceGaps' "Flow"-subject rows) only. worstVerdict() always
// returns a real verdict string (never null/undefined, even for an empty
// edge list), so the three verdict properties are always set
// unconditionally; sourceCategory/sinkCategory/destinationExternality are
// only set when a real, non-null value exists, per the same rule
// computePrivacyRow() follows.
function computeFlowFilterProperties(graph, flow) {
  const pathEdges = flow.edgeIds.map((edgeId) => graph.edges.find((e) => e.id === edgeId)).filter(Boolean);
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  return {
    transitVerdict: worstVerdict(pathEdges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(pathEdges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(pathEdges.map((e) => e.protection.handling.verdict)),
    policyVerdict: flow.policyVerdict,
    ...(sourceNode?.subtype ? { sourceCategory: sourceNode.subtype } : {}),
    ...(sinkNode?.subtype ? { sinkCategory: sinkNode.subtype } : {}),
    ...(sinkNode?.externality?.value ? { destinationExternality: sinkNode.externality.value } : {}),
  };
}

const TABLE_COMPUTE = {
  sources: (graph) => ({
    columns: ['Label', 'Category', 'Coverage', 'Externality'],
    rows: graph.nodes.filter((n) => n.kind === 'source').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.subtype ?? '—', n.coverageStatus, n.externality?.value ?? 'unknown'],
    })),
  }),
  sinks: (graph) => ({
    columns: ['Label', 'Category', 'Coverage', 'Externality'],
    rows: graph.nodes.filter((n) => n.kind === 'sink').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.subtype ?? '—', n.coverageStatus, n.externality?.value ?? 'unknown'],
    })),
  }),
  fields: (graph) => ({
    columns: ['Name', 'Data classes', 'AI contexts'],
    rows: graph.dataElements.map((d) => ({
      id: d.id, selectableId: d.id,
      cells: [d.name, (d.dataClasses ?? []).join(', ') || '—', (d.aiContexts ?? []).join(', ') || '—'],
      dataClasses: d.dataClasses ?? [],
    })),
  }),
  externalDestinations: (graph) => ({
    columns: ['Label', 'Kind', 'Resolution status', 'Literal value'],
    rows: graph.nodes.filter((n) => n.externality?.value === 'external').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.kind, n.destination?.resolutionStatus ?? 'unknown', n.destination?.literalValue ?? '—'],
    })),
  }),
  stores: (graph) => ({
    columns: ['Label', 'Operation', 'Columns'],
    rows: graph.nodes.filter((n) => n.kind === 'store').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.storeDetail?.operation ?? 'unknown', (n.storeDetail?.columns ?? []).join(', ') || '—'],
    })),
  }),
  aiSystems: (graph) => {
    const aiNodes = graph.nodes.filter((n) => n.subtype && AI_SUBTYPES.has(n.subtype)).map((n) => ({
      id: n.id, selectableId: n.id,
      cells: ['Node', n.label, n.subtype],
    }));
    const aiDataElements = graph.dataElements.filter((d) => (d.aiContexts ?? []).length > 0).map((d) => ({
      id: d.id, selectableId: d.id,
      cells: ['Data element', d.name, (d.aiContexts ?? []).join(', ')],
    }));
    return { columns: ['Subject', 'Label', 'Category / context'], rows: [...aiNodes, ...aiDataElements] };
  },
  transformations: (graph) => ({
    columns: ['Kind', 'Reversibility'],
    rows: graph.transformations.map((t) => ({
      id: t.id, selectableId: t.id,
      cells: [t.kind, t.reversibility],
    })),
  }),
  unprotectedEdges: (graph) => ({
    columns: ['From', 'To', 'Transit', 'At rest', 'Handling', 'Worst verdict'],
    rows: graph.edges.filter((e) => UNPROTECTED_TIERS.has(edgeWorstVerdict(e))).map((e) => ({
      id: e.id, selectableId: e.id,
      cells: [nodeLabelFor(graph, e.from), nodeLabelFor(graph, e.to), e.protection.transit.verdict, e.protection.atRest.verdict, e.protection.handling.verdict, edgeWorstVerdict(e)],
    })),
  }),
  policyPermittedFlows: (graph) => ({
    columns: ['Field', 'Source', 'Sink', 'Policy verdict'],
    rows: graph.flows.filter((f) => f.policyVerdict === 'permitted').map((f) => {
      const dataElement = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
      return {
        id: f.id, selectableId: f.id,
        cells: [dataElement?.name ?? 'unknown field', nodeLabelFor(graph, f.source), nodeLabelFor(graph, f.sink), f.policyVerdict],
        dataClasses: dataElement?.dataClasses ?? [],
        protectionSummary: f.protectionSummary,
        ...computeFlowFilterProperties(graph, f),
      };
    }),
  }),
  manualGovernanceGaps: (graph) => {
    const manualFlows = graph.flows.filter((f) => f.policyVerdict === 'manual_review_required').map((f) => {
      const dataElement = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
      return {
        id: f.id, selectableId: f.id,
        cells: ['Flow', dataElement?.name ?? 'unknown field', 'policyVerdict: manual_review_required'],
        dataClasses: dataElement?.dataClasses ?? [],
        protectionSummary: f.protectionSummary,
        ...computeFlowFilterProperties(graph, f),
      };
    });
    const manualNodes = graph.nodes.filter((n) => n.coverageStatus === 'manual').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: ['Node', n.label, 'coverageStatus: manual'],
    }));
    const manualEdges = graph.edges.filter((e) => e.coverageStatus === 'manual').map((e) => ({
      id: e.id, selectableId: e.id,
      cells: ['Edge', `${nodeLabelFor(graph, e.from)} → ${nodeLabelFor(graph, e.to)}`, 'coverageStatus: manual'],
    }));
    return { columns: ['Subject', 'Label', 'Reason'], rows: [...manualFlows, ...manualNodes, ...manualEdges] };
  },
  unsupportedCandidates: (graph) => ({
    columns: ['Label', 'Kind', 'Coverage status', 'Reason'],
    rows: graph.nodes.filter((n) => n.kind === 'unresolved' || n.coverageStatus === 'unsupported' || n.coverageStatus === 'candidate').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.kind, n.coverageStatus, n.coverageReason ?? '—'],
    })),
  }),
};

// Categories whose rows carry the properties filter-rail.js's three chip
// groups filter on (dataClasses / protectionSummary / AI relevance). Wired
// per docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-inventory-scoping.md's
// decision 4 — deliberately not every category; see that doc before
// changing this set.
const FILTERABLE_TABLES = new Set(['fields', 'policyPermittedFlows', 'manualGovernanceGaps']);

// Milestone 3, sub-project M3-UX-Query, Task 4. The query language's
// compileQuery predicate is fundamentally FLOW-scoped (query-language.js's
// own header comment: "the predicate operates on a FLOW"), but Inventory's
// 11 categories are a mix of flow/node/edge/dataElement/transformation rows.
// Rather than special-case each category, this looks up a real flow by the
// row's own id — which only resolves for rows whose `id` genuinely IS a
// flow id (policyPermittedFlows' rows, and manualGovernanceGaps' "Flow"-
// subject rows, both of which use `id: f.id`). A row with no corresponding
// flow (a source/sink/store/dataElement/transformation/node/edge row) has
// nothing for the query predicate to test against, so the query has no
// effect there and the row's visibility is governed only by the existing
// dataClass/protection filters — an honest, disclosed scope limitation, not
// a bug: this DSL was never designed to describe a bare node or edge.
function rowMatchesQuery(graph, row, queryPredicate) {
  if (!queryPredicate) return true;
  const flow = graph.flows.find((f) => f.id === row.id);
  if (!flow) return true;
  return queryPredicate(flow);
}

/**
 * @param {object} graph
 * @param {object} state
 * @param {((flow: object) => boolean) | null} [queryPredicate] - see
 *   rowMatchesQuery's own comment above. Applied as an ADDITIONAL condition
 *   alongside the existing dataClass/protection filters, independent of
 *   whether the active table is in FILTERABLE_TABLES (query narrowing is
 *   orthogonal to the filter-rail's own chip-based facets). Omitted/null
 *   (every pre-existing caller/test) matches every row, so behavior is
 *   unchanged for anyone not passing it.
 */
export function computeInventoryViewModel(graph, state, queryPredicate = null) {
  const activeTable = INVENTORY_TABLES.includes(state.table) ? state.table : INVENTORY_TABLES[0];
  const tables = INVENTORY_TABLES.map((id) => ({
    id, label: TABLE_LABELS[id],
    count: TABLE_COMPUTE[id](graph).rows.length,
  }));

  const { columns, rows: rawRows } = TABLE_COMPUTE[activeTable](graph);
  const filterable = FILTERABLE_TABLES.has(activeTable);
  const rows = rawRows.map((row) => ({
    ...row,
    selected: row.id === state.selectedId,
    visible: (filterable ? matchesFilters(row, state.filters ?? {}) : true) && rowMatchesQuery(graph, row, queryPredicate),
  }));

  return { tables, activeTable, columns, rows, filterable };
}

function renderSubNav(viewModel, onTableChange) {
  const buttons = viewModel.tables.map((t) =>
    el(
      'button',
      {
        class: 'inventory-subnav-button',
        'data-table-id': t.id,
        'data-active': String(t.id === viewModel.activeTable),
        'aria-pressed': String(t.id === viewModel.activeTable),
        onClick: () => onTableChange(t.id),
      },
      `${t.label} (${t.count})`,
    ),
  );
  return el('div', { class: 'inventory-subnav' }, buttons);
}

function renderRow(row, onSelect) {
  return el(
    'tr',
    {
      class: 'inventory-row',
      'data-selected': String(row.selected),
      'data-visible': String(row.visible),
      tabindex: '0',
      role: 'button',
      'aria-label': `${row.cells[0]}${row.selected ? ', selected' : ''}`,
      onClick: () => row.selectableId && onSelect(row.selectableId),
      onKeydown: (evt) => {
        if ((evt.key === 'Enter' || evt.key === ' ') && row.selectableId) {
          evt.preventDefault();
          onSelect(row.selectableId);
        }
      },
    },
    row.cells.map((cellText) => el('td', {}, cellText)),
  );
}

function sortRows(rows, columnIndex, direction) {
  const sorted = [...rows].sort((a, b) => {
    const cmp = String(a.cells[columnIndex]).localeCompare(String(b.cells[columnIndex]));
    return direction === 'asc' ? cmp : -cmp;
  });
  return sorted;
}

/**
 * @param {ReturnType<typeof computeInventoryViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(selectableId: string) => void} onSelect
 * @param {(tableId: string) => void} onTableChange
 */
export function renderInventoryView(viewModel, canvasEl, onSelect, onTableChange) {
  clear(canvasEl);

  const subNav = renderSubNav(viewModel, onTableChange);

  let sortState = { columnIndex: null, direction: 'asc' };
  const headerRow = el('tr', {}, viewModel.columns.map((col, i) =>
    el('th', { onClick: () => {
      sortState = sortState.columnIndex === i ? { columnIndex: i, direction: sortState.direction === 'asc' ? 'desc' : 'asc' } : { columnIndex: i, direction: 'asc' };
      const sortedRows = sortRows(viewModel.rows, sortState.columnIndex, sortState.direction);
      renderInventoryView({ ...viewModel, rows: sortedRows }, canvasEl, onSelect, onTableChange);
    } }, col),
  ));
  const bodyRows = viewModel.rows.map((row) => renderRow(row, onSelect));
  const table = el('table', { class: 'inventory-table' }, [el('thead', {}, headerRow), el('tbody', {}, bodyRows)]);

  canvasEl.appendChild(el('div', { class: 'inventory-view' }, [subNav, table]));
}
