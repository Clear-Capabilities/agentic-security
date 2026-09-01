// Inventory View: compute half only. PRD §7.6's 11 required inventory
// categories, each with its own per-category compute function producing
// {columns, rows}. The render half (renderInventoryView, DOM-building via
// el()/clear()) is Task 3 — this file intentionally ends after
// computeInventoryViewModel and its helpers.

import { worstVerdict } from '../lib/protection-visual.js';
import { AI_SUBTYPES } from '../lib/flow-path.js';
import { INVENTORY_TABLES } from '../lib/state.js';

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

function rowMatchesFilters(row, filters) {
  if (filters.dataClass?.length && !(row.dataClasses ?? []).some((c) => filters.dataClass.includes(c))) return false;
  if (filters.protection?.length && row.protectionSummary && !filters.protection.includes(row.protectionSummary)) return false;
  return true;
}

export function computeInventoryViewModel(graph, state) {
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
    visible: filterable ? rowMatchesFilters(row, state.filters ?? {}) : true,
  }));

  return { tables, activeTable, columns, rows, filterable };
}

import { el, clear } from '../lib/dom.js';

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
