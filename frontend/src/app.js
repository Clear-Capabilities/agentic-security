import { mountShell } from './shell.js';
import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';
import { computeArchitectureViewModel, renderArchitectureView } from './views/architecture-view.js';
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
    } else if (state.view === 'privacy') {
      const viewModel = computePrivacyViewModel(graph, state);
      renderPrivacyView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
    } else if (state.view === 'trace') {
      const viewModel = computeTraceViewModel(graph, state);
      renderTraceView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());

    renderFilterRail(filterFacets, state.filters ?? {}, shellApi.getLeftRailEl(), (nextFilters) => shellApi.setFilters(nextFilters));
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
