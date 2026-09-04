import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';

export function computeTraceSteps(graph, flow) {
  const steps = [];
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));

  steps.push({
    kind: 'source',
    fieldName: dataElement?.name ?? 'unknown field',
    node: sourceNode?.label ?? 'unknown source',
  });

  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  for (const edge of edges) {
    const toNode = graph.nodes.find((n) => n.id === edge.to);
    const mappings = edge.fieldMappings ?? [];

    if (mappings.length === 0) {
      steps.push({
        kind: 'hop',
        node: toNode?.label ?? 'unknown',
        fromNodeId: edge.from,
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
      continue;
    }

    for (const mapping of mappings) {
      const transformations = (mapping.transformationIds ?? [])
        .map((tid) => graph.transformations.find((t) => t.id === tid))
        .filter(Boolean);
      steps.push({
        kind: transformations.length > 0 ? 'transformation' : 'propagation',
        fromPath: mapping.fromPath,
        toPath: mapping.toPath,
        mappingType: mapping.mappingType,
        transformations,
        node: toNode?.label ?? 'unknown',
        fromNodeId: edge.from,
        boundaryCrossing: (edge.boundaryCrossings ?? []).length > 0,
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
    }
  }

  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  steps.push({
    kind: 'sink',
    node: sinkNode?.label ?? 'unknown destination',
    externality: sinkNode?.externality?.value ?? 'unknown',
    protectionSummary: flow.protectionSummary,
  });

  return steps;
}

export function computeTraceStepGroups(steps) {
  const middleSteps = steps.filter((s) => s.kind !== 'source' && s.kind !== 'sink');
  const sourceStep = steps.find((s) => s.kind === 'source');
  const sinkStep = steps.find((s) => s.kind === 'sink');

  const groupsByFrom = new Map();
  for (const step of middleSteps) {
    if (!groupsByFrom.has(step.fromNodeId)) groupsByFrom.set(step.fromNodeId, []);
    groupsByFrom.get(step.fromNodeId).push(step);
  }

  const groups = [];
  if (sourceStep) groups.push({ type: 'source', step: sourceStep });
  for (const groupSteps of groupsByFrom.values()) {
    if (groupSteps.length > 1) {
      groups.push({ type: 'branch', steps: groupSteps });
    } else {
      groups.push({ type: 'sequential', step: groupSteps[0] });
    }
  }
  if (sinkStep) groups.push({ type: 'sink', step: sinkStep });
  return groups;
}

export function computeAlternatePaths(graph, flow) {
  return graph.flows
    .filter((f) => f.id !== flow.id && f.dataElementIds.some((id) => flow.dataElementIds.includes(id)))
    .map((f) => ({
      flowId: f.id,
      destinationLabel: graph.nodes.find((n) => n.id === f.sink)?.label ?? 'unknown',
      protectionSummary: f.protectionSummary,
    }));
}

export function computeTraceViewModel(graph, state) {
  if (!state.selectedId) return null;
  const flow = graph.flows.find((f) => f.id === state.selectedId);
  if (!flow) return null;
  return {
    flow,
    steps: computeTraceSteps(graph, flow),
    alternatePaths: computeAlternatePaths(graph, flow),
  };
}

/**
 * @param {ReturnType<typeof computeTraceViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(flowId: string) => void} onSelectAlternate
 */
export function renderTraceView(viewModel, canvasEl, onSelectAlternate) {
  clear(canvasEl);

  if (!viewModel) {
    canvasEl.appendChild(el('p', { class: 'trace-empty' }, 'Select a flow from Privacy View (or click a node/edge in Architecture View that resolves to a flow) to trace it.'));
    return;
  }

  const container = el('div', { class: 'trace-view' });
  const groups = computeTraceStepGroups(viewModel.steps);
  let stepNumber = 0;
  for (const group of groups) {
    stepNumber += 1;
    if (group.type === 'branch') {
      container.appendChild(renderTraceBranchGroup(group.steps, stepNumber));
    } else {
      container.appendChild(renderTraceStep(group.step, String(stepNumber)));
    }
  }

  if (viewModel.alternatePaths.length > 0) {
    const items = viewModel.alternatePaths.map((alt) => {
      const visual = protectionVisual(alt.protectionSummary);
      return el(
        'div',
        {
          class: 'trace-alternate-item',
          tabindex: '0',
          role: 'button',
          onClick: () => onSelectAlternate(alt.flowId),
          onKeydown: (evt) => {
            if (evt.key === 'Enter' || evt.key === ' ') {
              evt.preventDefault();
              onSelectAlternate(alt.flowId);
            }
          },
        },
        `${visual.glyph} ${alt.destinationLabel} — ${visual.label}`,
      );
    });
    container.appendChild(el('div', { class: 'trace-alternates' }, [el('h4', {}, 'Alternate destinations'), ...items]));
  }

  canvasEl.appendChild(container);
}

function renderTraceBranchGroup(steps, number) {
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  const items = steps.map((step, i) => renderTraceStep(step, `${number}${letters[i]}`));
  return el('div', { class: 'trace-branch-group' }, [
    el('div', { class: 'trace-branch-label' }, `${steps.length} branches from here`),
    ...items,
  ]);
}

function renderTraceStep(step, label) {
  const bodyChildren = [el('div', { class: 'trace-step-kind' }, step.kind)];

  if (step.kind === 'source') {
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, step.fieldName));
  } else if (step.kind === 'transformation' || step.kind === 'propagation') {
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${step.fromPath} → ${step.toPath} (${step.mappingType})`));
    for (const t of step.transformations) {
      bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${t.callee}() — ${t.kind}, ${t.reversibility}`));
    }
  }

  bodyChildren.push(el('div', { class: 'trace-step-node' }, step.node));

  if (step.boundaryCrossing) {
    bodyChildren.push(el('span', { class: 'trace-step-boundary' }, 'Trust boundary crossing'));
  }

  if (step.protection) {
    const dims = [
      ['Transit', step.protection.transit.verdict],
      ['At rest', step.protection.atRest.verdict],
      ['Handling', step.protection.handling.verdict],
    ];
    for (const [label, verdict] of dims) {
      const visual = protectionVisual(verdict);
      bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${visual.glyph} ${label}: ${visual.label}`));
    }
  }

  if (step.evidenceRefs?.length > 0) {
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${step.evidenceRefs.length} evidence reference(s)`));
  }

  if (step.kind === 'sink') {
    const visual = protectionVisual(step.protectionSummary);
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${visual.glyph} Overall: ${visual.label} · ${step.externality} destination`));
  }

  return el('div', { class: 'trace-step' }, [el('div', { class: 'trace-step-number' }, label), el('div', { class: 'trace-step-body' }, bodyChildren)]);
}
