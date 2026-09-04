import { flowPathNodeIds, isAiRelevantFlow } from '../lib/flow-path.js';
import { el, clear } from '../lib/dom.js';
import { protectionVisual, worstVerdict } from '../lib/protection-visual.js';
import { matchesFilters } from '../lib/row-filters.js';

export const LIFECYCLE_STAGES = Object.freeze(['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);

export function stageForNode(node) {
  return LIFECYCLE_STAGES.includes(node.lifecycleStages?.[0]) ? node.lifecycleStages[0] : 'processing';
}

export function computePrivacyRow(graph, flow) {
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const pathNodeIds = flowPathNodeIds(graph, flow);
  const pathNodes = graph.nodes.filter((n) => pathNodeIds.has(n.id));
  // This flow's own resolved edges — the same per-edgeId lookup
  // flowPathNodeIds() already performs internally, applied here to keep the
  // edge objects (rather than just the node ids) so the three protection
  // dimensions below can be aggregated per-flow via worstVerdict().
  const pathEdges = flow.edgeIds.map((edgeId) => graph.edges.find((e) => e.id === edgeId)).filter(Boolean);

  const stageCells = LIFECYCLE_STAGES.map((stage) => ({
    stage,
    nodeLabels: pathNodes.filter((n) => stageForNode(n) === stage).map((n) => n.label),
  }));

  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    stageCells,
    governanceRefs: flow.governanceRefs ?? {},
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
    isAiRelevant: isAiRelevantFlow(graph, flow),
    // worstVerdict() always returns a real verdict string (falling back to
    // 'not_assessed', never null/undefined) even for an empty edge list, so
    // these three are always set unconditionally — unlike sourceCategory/
    // sinkCategory/destinationExternality below, there is no genuinely-absent
    // case to guard against.
    transitVerdict: worstVerdict(pathEdges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(pathEdges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(pathEdges.map((e) => e.protection.handling.verdict)),
    // Only set when a real, non-null value exists — keeps matchesFilters's
    // own "property absent = unaffected, never a hide" semantics clean
    // rather than introducing a third (present-but-null) state.
    ...(sourceNode?.subtype ? { sourceCategory: sourceNode.subtype } : {}),
    ...(sinkNode?.subtype ? { sinkCategory: sinkNode.subtype } : {}),
    ...(sinkNode?.externality?.value ? { destinationExternality: sinkNode.externality.value } : {}),
  };
}

/**
 * @param {object} graph
 * @param {object} state
 * @param {((flow: object) => boolean) | null} [queryPredicate] - Milestone 3,
 *   sub-project M3-UX-Query, Task 4: the query language's compiled predicate
 *   (lib/query-language.js's `compileQuery`), applied here as an ADDITIONAL
 *   condition alongside the existing dataClass/protection/ai filters — a row
 *   must pass BOTH to stay visible. Omitted/null (every pre-existing
 *   caller/test) means "no query active," matching every row, so behavior
 *   is unchanged for anyone not passing it.
 */
export function computePrivacyViewModel(graph, state, queryPredicate = null) {
  const matchesQuery = queryPredicate ?? (() => true);
  const rows = graph.flows.map((flow) => {
    const row = computePrivacyRow(graph, flow);
    return {
      ...row,
      selected: row.flowId === state.selectedId,
      visible: matchesFilters(row, state.filters ?? {}) && matchesQuery(flow),
    };
  });
  return { stages: LIFECYCLE_STAGES, rows };
}

const CLASS_BADGE_COLOR_VAR = { PII: '--class-pii', PHI: '--class-phi', PCI: '--class-pci' };

/**
 * @param {ReturnType<typeof computePrivacyViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(flowId: string) => void} onSelectFlow
 */
export function renderPrivacyView(viewModel, canvasEl, onSelectFlow) {
  clear(canvasEl);

  const headerRow = el('tr', {}, [
    el('th', {}, 'Field'),
    el('th', {}, 'Protection'),
    ...viewModel.stages.map((stage) => el('th', {}, stage.charAt(0).toUpperCase() + stage.slice(1))),
  ]);

  const bodyRows = viewModel.rows.map((row) => renderPrivacyRow(row, onSelectFlow));

  const table = el('table', { class: 'privacy-table' }, [el('thead', {}, headerRow), el('tbody', {}, bodyRows)]);

  canvasEl.appendChild(el('div', { class: 'privacy-view' }, table));
}

function renderPrivacyRow(row, onSelectFlow) {
  const classBadges = row.dataClasses.map((cls) =>
    el('span', { class: 'privacy-class-badge', style: `color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--text-secondary'}); border-color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--border-default'})` }, cls),
  );

  const fieldCell = el('td', { class: 'privacy-field-cell' }, [
    el('div', {}, row.dataElementName),
    el('div', {}, classBadges),
    row.isAiRelevant ? el('span', { class: 'privacy-governance-badge', style: 'border-color: var(--context-ai); color: var(--context-ai)' }, 'AI processing') : null,
  ]);

  const visual = protectionVisual(row.protectionSummary);
  const protectionCell = el(
    'td',
    { class: 'privacy-protection-cell' },
    el('span', { style: `border-color: var(${visual.colorVar}); color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`),
  );

  const stageCells = row.stageCells.map((cell) => renderStageCell(cell, row));

  return el(
    'tr',
    {
      class: 'privacy-row',
      'data-selected': String(row.selected),
      'data-visible': String(row.visible),
      tabindex: '0',
      role: 'button',
      'aria-label': `${row.dataElementName} lifecycle, ${row.protectionSummary}${row.selected ? ', selected' : ''}`,
      onClick: () => onSelectFlow(row.flowId),
      onKeydown: (evt) => {
        if (evt.key === 'Enter' || evt.key === ' ') {
          evt.preventDefault();
          onSelectFlow(row.flowId);
        }
      },
    },
    [fieldCell, protectionCell, ...stageCells],
  );
}

function renderStageCell(cell, row) {
  const children = [];
  if (cell.nodeLabels.length > 0) {
    children.push(el('div', {}, cell.nodeLabels.join(', ')));
  } else {
    children.push(el('div', { class: 'privacy-stage-cell-empty-label' }, '—'));
  }

  // Governance facts are shown once, on whichever stage cell is the most
  // relevant home for them — sharing (recipient/purpose/lawfulBasis/transfer)
  // or retention/deletion — rather than repeating them on every cell. This
  // loop runs unconditionally (independent of whether nodeLabels is empty)
  // so a fact like deletion:not_found is never structurally unreachable just
  // because a flow's path happens not to touch a deletion-stage node.
  const governanceKeysForStage = {
    sharing: ['recipient', 'purpose', 'lawfulBasis', 'transfer'],
    retention: ['retention'],
    deletion: ['deletion'],
  };
  const relevantKeys = governanceKeysForStage[cell.stage] ?? [];
  for (const key of relevantKeys) {
    if (key in row.governanceRefs) {
      const value = row.governanceRefs[key];
      children.push(el('div', { class: 'privacy-governance-badge' }, `${key}: ${value}`));
    }
  }

  return el('td', { class: cell.nodeLabels.length === 0 ? 'privacy-stage-cell privacy-stage-cell-empty' : 'privacy-stage-cell' }, children);
}
