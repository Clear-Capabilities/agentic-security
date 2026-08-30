import { flowPathNodeIds, isAiRelevantFlow } from '../lib/flow-path.js';
import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';

export const LIFECYCLE_STAGES = Object.freeze(['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);

export function stageForNode(node) {
  return LIFECYCLE_STAGES.includes(node.lifecycleStages?.[0]) ? node.lifecycleStages[0] : 'processing';
}

export function computePrivacyRow(graph, flow) {
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const pathNodeIds = flowPathNodeIds(graph, flow);
  const pathNodes = graph.nodes.filter((n) => pathNodeIds.has(n.id));

  const stageCells = LIFECYCLE_STAGES.map((stage) => ({
    stage,
    nodeLabels: pathNodes.filter((n) => stageForNode(n) === stage).map((n) => n.label),
  }));

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    stageCells,
    governanceRefs: flow.governanceRefs ?? {},
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
    isAiRelevant: isAiRelevantFlow(graph, flow),
  };
}

function rowMatchesFilters(row, filters) {
  if (filters.dataClass?.length && !filters.dataClass.some((c) => row.dataClasses.includes(c))) return false;
  if (filters.protection?.length && !filters.protection.includes(row.protectionSummary)) return false;
  if (filters.ai && !row.isAiRelevant) return false;
  return true;
}

export function computePrivacyViewModel(graph, state) {
  const rows = graph.flows.map((flow) => {
    const row = computePrivacyRow(graph, flow);
    return {
      ...row,
      selected: row.flowId === state.selectedId,
      visible: rowMatchesFilters(row, state.filters ?? {}),
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
    [fieldCell, ...stageCells],
  );
}

function renderStageCell(cell, row) {
  if (cell.nodeLabels.length === 0) {
    return el('td', { class: 'privacy-stage-cell privacy-stage-cell-empty' }, '—');
  }
  const children = [el('div', {}, cell.nodeLabels.join(', '))];

  // Governance facts are shown once, on whichever stage cell is the most
  // relevant home for them — sharing (recipient/purpose/lawfulBasis/transfer)
  // or retention/deletion — rather than repeating them on every cell.
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

  if (cell.stage === 'sharing' && row.protectionSummary) {
    const visual = protectionVisual(row.protectionSummary === 'unknown' ? 'unknown' : row.protectionSummary);
    children.push(el('div', { class: 'privacy-governance-badge', style: `border-color: var(${visual.colorVar}); color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`));
  }

  return el('td', { class: 'privacy-stage-cell' }, children);
}
