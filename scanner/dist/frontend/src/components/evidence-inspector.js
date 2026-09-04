import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';

export function computeInspectorViewModel(graph, selectedId) {
  if (!selectedId) return null;

  const flow = graph.flows.find((f) => f.id === selectedId);
  const edge = !flow && graph.edges.find((e) => e.id === selectedId);
  const node = !flow && !edge && graph.nodes.find((n) => n.id === selectedId);
  const dataElement = !flow && !edge && !node && graph.dataElements.find((d) => d.id === selectedId);
  const transformation = !flow && !edge && !node && !dataElement && graph.transformations.find((t) => t.id === selectedId);
  const target = flow || edge || node || dataElement || transformation;
  if (!target) return null;

  const kind = flow ? 'flow' : edge ? 'edge' : node ? 'node' : dataElement ? 'dataElement' : 'transformation';
  const evidenceRefs = target.evidenceRefs ?? [];
  const evidenceItems = evidenceRefs
    .map((id) => graph.evidence.find((ev) => ev.id === id))
    .filter(Boolean);
  const supporting = evidenceItems.filter((e) => !e.conflict);
  const conflicting = evidenceItems.filter((e) => e.conflict);

  return {
    kind,
    id: target.id,
    claim: buildClaimText(graph, kind, target),
    supporting,
    conflicting,
    limitations: target.limitations ?? [],
    target,
  };
}

function buildClaimText(graph, kind, target) {
  if (kind === 'flow') {
    const dataElement = graph.dataElements.find((d) => target.dataElementIds.includes(d.id));
    const source = graph.nodes.find((n) => n.id === target.source);
    const sink = graph.nodes.find((n) => n.id === target.sink);
    return `${dataElement?.name ?? 'field'} flows from ${source?.label ?? 'unknown source'} to ${sink?.label ?? 'unknown destination'}: ${target.protectionSummary}`;
  }
  if (kind === 'edge') {
    const from = graph.nodes.find((n) => n.id === target.from);
    const to = graph.nodes.find((n) => n.id === target.to);
    return `${from?.label ?? '?'} → ${to?.label ?? '?'}: handling ${target.protection.handling.verdict}, transit ${target.protection.transit.verdict}, at rest ${target.protection.atRest.verdict}`;
  }
  if (kind === 'dataElement') {
    return `${target.name}: ${(target.dataClasses ?? []).join(', ') || 'no data classes recorded'}`;
  }
  if (kind === 'transformation') {
    return `${target.kind} transformation (${target.reversibility})`;
  }
  return `${target.label} (${target.kind}/${target.subtype})`;
}

/** @param {ReturnType<typeof computeInspectorViewModel>} viewModel */
export function renderInspector(viewModel, inspectorEl) {
  clear(inspectorEl);
  if (!viewModel) {
    inspectorEl.appendChild(el('p', { class: 'inspector-empty' }, 'Select a node, edge, or flow to see its evidence.'));
    return;
  }

  const container = el('div', { class: 'inspector' });
  container.appendChild(el('h3', { class: 'inspector-title' }, 'Evidence inspector'));

  container.appendChild(el('p', { class: 'inspector-claim' }, viewModel.claim));

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'Supporting evidence'));
  if (viewModel.supporting.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'No supporting evidence recorded.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-evidence-list' },
        viewModel.supporting.map((ev) => renderEvidenceItem(ev)),
      ),
    );
  }

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'Conflicting evidence'));
  if (viewModel.conflicting.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'None recorded.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-evidence-list' },
        viewModel.conflicting.map((ev) => renderEvidenceItem(ev)),
      ),
    );
  }

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'What the scanner does not know'));
  if (viewModel.limitations.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'No limitations recorded for this claim.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-limitations-list' },
        viewModel.limitations.map((text) => el('li', {}, text)),
      ),
    );
  }

  if (viewModel.kind === 'edge' || viewModel.kind === 'flow') {
    container.appendChild(renderVerdictBadges(viewModel));
  }

  inspectorEl.appendChild(container);
}

function renderEvidenceItem(evidence) {
  return el('li', { class: 'inspector-evidence-item' }, [
    el('span', { class: 'inspector-evidence-claim' }, evidence.claim),
    el('span', { class: 'inspector-evidence-location' }, evidence.location?.note ?? 'location unknown'),
  ]);
}

function renderVerdictBadges(viewModel) {
  const target = viewModel.target;
  const dims = viewModel.kind === 'edge'
    ? [
        ['Transit', target.protection.transit.verdict],
        ['At rest', target.protection.atRest.verdict],
        ['Handling', target.protection.handling.verdict],
      ]
    : [['Protection summary', target.protectionSummary]];
  return el(
    'div',
    { class: 'inspector-verdicts' },
    dims.map(([label, verdict]) => {
      const visual = protectionVisual(verdict);
      return el('div', { class: 'inspector-verdict-row' }, [
        el('span', { class: 'inspector-verdict-dim-label' }, `${label}: `),
        el('span', { class: 'inspector-verdict-badge', style: `border-color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`),
      ]);
    }),
  );
}
