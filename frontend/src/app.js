import { mountShell, buildContextRailText } from './shell.js';
import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';
import { computeArchitectureViewModel, renderArchitectureView, renderFlowSummary } from './views/architecture-view.js';
import { computePrivacyViewModel, renderPrivacyView } from './views/privacy-view.js';
import { computeTraceViewModel, renderTraceView } from './views/trace-view.js';
import { computeInspectorViewModel, renderInspector } from './components/evidence-inspector.js';
import { computeFilterFacets, renderFilterRail } from './components/filter-rail.js';

export function bootstrap(rootEl, graph) {
  const shellApi = mountShell(rootEl, graph);
  const filterFacets = computeFilterFacets(graph);

  function rerender() {
    const state = shellApi.getState();

    if (state.view === 'architecture') {
      const viewModel = computeArchitectureViewModel(graph, state);
      renderArchitectureView(viewModel, shellApi.getCanvasEl(), (id) => shellApi.setSelection(id));
      if (viewModel.flowSummary) {
        renderFlowSummary(viewModel.flowSummary, shellApi.getContextRailEl());
      } else {
        shellApi.getContextRailEl().textContent = buildContextRailText(graph);
      }
    } else if (state.view === 'privacy') {
      const viewModel = computePrivacyViewModel(graph, state);
      renderPrivacyView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    } else if (state.view === 'trace') {
      const viewModel = computeTraceViewModel(graph, state);
      renderTraceView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());

    if (state.view === 'privacy') {
      renderFilterRail(filterFacets, state.filters ?? {}, shellApi.getLeftRailEl(), (nextFilters) => shellApi.setFilters(nextFilters));
    } else {
      const railEl = shellApi.getLeftRailEl();
      railEl.textContent = 'Filters apply to Privacy View.';
    }
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
