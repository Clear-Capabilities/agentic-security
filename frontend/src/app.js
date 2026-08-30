import { mountShell } from './shell.js';
import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';
import { computeArchitectureViewModel, renderArchitectureView } from './views/architecture-view.js';
import { computeInspectorViewModel, renderInspector } from './components/evidence-inspector.js';

export function bootstrap(rootEl, graph) {
  const shellApi = mountShell(rootEl, graph);

  function rerender() {
    const state = shellApi.getState();

    if (state.view === 'architecture') {
      const viewModel = computeArchitectureViewModel(graph, state);
      renderArchitectureView(viewModel, shellApi.getCanvasEl(), (id) => shellApi.setSelection(id));
    } else {
      // Privacy and Trace views are a follow-up plan — show an honest
      // placeholder rather than silently rendering nothing or reusing
      // Architecture View's content under a different tab.
      shellApi.getCanvasEl().textContent = `${state.view} view is not implemented yet.`;
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
