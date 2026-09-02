import { mountShell, buildContextRailText } from './shell.js';
import { computeArchitectureViewModel, renderArchitectureView, renderFlowSummary } from './views/architecture-view.js';
import { computePrivacyViewModel, renderPrivacyView } from './views/privacy-view.js';
import { computeTraceViewModel, renderTraceView } from './views/trace-view.js';
import { computeInventoryViewModel, renderInventoryView } from './views/inventory-view.js';
import { computeInspectorViewModel, renderInspector } from './components/evidence-inspector.js';
import { computeFilterFacets, renderFilterRail } from './components/filter-rail.js';
import { computeQueryBarViewModel, renderQueryBar, compileQuerySafely } from './components/query-bar.js';
import {
  showUpstream, showDownstream, showAllPaths, showShortestPath,
  showExternalPathsOnly, showUnprotectedPathsOnly, showAliases, showDisconnected,
} from './lib/focus-controls.js';
import { el, clear } from './lib/dom.js';

// Milestone 3, sub-project M3-UX-Query, Task 4's own resolution of the task
// brief's Step 4 open design question: a focus control's own {nodeIds,
// edgeIds} result (from lib/focus-controls.js) has no single canonical
// `selectedId` to thread through the existing shell.js state mechanism, and
// is real-but-transient UI state (not meaningfully shareable — it holds
// Sets, which don't serialize to the URL hash cleanly), matching the same
// precedent A11y's own `inspectorOverlayOpen` and M3-Render's own
// `currentViewport` already established: module-local state, not persisted.
// Lives here (app.js), the one place that already orchestrates every view's
// own compute/render call, rather than inside architecture-view.js itself.
let currentFocusSelection = null;

const FOCUS_CONTROLS = [
  { id: 'upstream', label: 'Show upstream', needsNode: true, run: (graph, anchor) => showUpstream(graph, anchor.nodeId) },
  { id: 'downstream', label: 'Show downstream', needsNode: true, run: (graph, anchor) => showDownstream(graph, anchor.nodeId) },
  { id: 'all-paths', label: 'Show all paths', needsNode: true, run: (graph, anchor) => showAllPaths(graph, anchor.nodeId) },
  { id: 'shortest-path', label: 'Show shortest path', needsEdge: true, run: (graph, anchor) => showShortestPath(graph, anchor.edge.from, anchor.edge.to) },
  { id: 'external-only', label: 'Show external paths only', run: (graph) => showExternalPathsOnly(graph) },
  { id: 'unprotected-only', label: 'Show unprotected paths only', run: (graph) => showUnprotectedPathsOnly(graph) },
  { id: 'aliases', label: 'Show aliases', needsNode: true, run: (graph, anchor) => showAliases(graph, anchor.nodeId) },
  { id: 'disconnected', label: 'Show disconnected', run: (graph) => showDisconnected(graph) },
  // resetToOverview is deliberately NOT a lib/focus-controls.js function
  // (per that file's own header note) — it is implemented here directly:
  // clear the focus override AND the underlying single selection.
  { id: 'reset', label: 'Reset to application overview', isReset: true },
];

// Determines which node/edge a focus control acts on for the CURRENT
// selection. A directly-selected NODE is its own anchor. A directly-
// selected EDGE carries both endpoints, used only by "Show shortest path"
// (the one control that genuinely needs two nodes). A directly-selected
// FLOW has no single node id of its own, so its own source node is used as
// a reasonable "origin" anchor — a real, disclosed scoping choice, not an
// oversight (the query language and focus controls are both real DSLs over
// this graph, but a flow selection's own node-shaped controls have to pick
// SOME node, and the flow's source is the least arbitrary choice available).
function resolveFocusAnchor(graph, state) {
  if (!state.selectedId) return null;
  const node = graph.nodes.find((n) => n.id === state.selectedId);
  if (node) return { nodeId: node.id, edge: null };
  const edge = graph.edges.find((e) => e.id === state.selectedId);
  if (edge) return { nodeId: edge.from, edge };
  const flow = graph.flows.find((f) => f.id === state.selectedId);
  if (flow) return { nodeId: flow.source, edge: null };
  return null;
}

// Appends the focus-control button group into an already-populated context
// rail (the architecture-view.js's own renderFlowSummary(), or the shell's
// plain textContent fallback, has already run and populated it — this
// APPENDS, it never clears). Only rendered on Architecture View, since a
// focus selection's {nodeIds, edgeIds} only has a visible effect there
// (computeArchitectureViewModel's own new 3rd parameter). Gated on there
// being an active selection at all, matching the task brief's own wording
// ("offering the 9 named controls when a node/flow is selected").
function renderFocusControlMenu(graph, state, contextRailEl, shellApi, rerender) {
  const anchor = resolveFocusAnchor(graph, state);
  if (!anchor && !currentFocusSelection) return;

  const buttons = FOCUS_CONTROLS.filter((control) => {
    if (control.isReset) return true;
    if (control.needsEdge) return Boolean(anchor?.edge);
    if (control.needsNode) return Boolean(anchor?.nodeId);
    return true; // graph-wide controls (external/unprotected/disconnected) need no anchor
  }).map((control) =>
    el(
      'button',
      {
        class: 'focus-control-menu__button',
        type: 'button',
        'data-focus-control': control.id,
        onClick: () => {
          if (control.isReset) {
            currentFocusSelection = null;
            shellApi.setSelection(null); // notifies onStateChange, which re-invokes rerender itself
            return;
          }
          currentFocusSelection = control.run(graph, anchor);
          rerender();
        },
      },
      control.label,
    ),
  );

  contextRailEl.appendChild(el('div', { class: 'focus-control-menu' }, buttons));
}

export function bootstrap(rootEl, graph) {
  const shellApi = mountShell(rootEl, graph);
  const filterFacets = computeFilterFacets(graph);

  // Any NEW single-item selection made through an EXISTING selection path
  // (a node/edge click on Architecture View, a Privacy/Trace/Inventory row
  // click) must clear a stale focus-control override — otherwise a user
  // could click "Show upstream" and then click an unrelated node, and see
  // the OLD focus set still applied instead of the new plain selection.
  function selectAndClearFocus(id) {
    currentFocusSelection = null;
    shellApi.setSelection(id);
  }

  function rerender() {
    const state = shellApi.getState();

    const queryBarViewModel = computeQueryBarViewModel(state);
    let queryPredicate = () => true;
    if (!queryBarViewModel.error) {
      const compiled = compileQuerySafely(graph, state.filters?.query ?? '');
      queryPredicate = compiled.predicate;
      // A syntax-clean query can still fail at evaluation time (an
      // unrecognized field name, thrown by query-language.js's own
      // evaluateNode — see compileQuerySafely's own comment). Surface that
      // the same way a syntax error is surfaced, rather than silently
      // falling back to "no filter" with no visible explanation.
      if (compiled.error) queryBarViewModel.error = compiled.error;
    }
    renderQueryBar(queryBarViewModel, shellApi.getQueryBarEl(), (nextQuery) => {
      shellApi.setFilters({ ...(state.filters ?? {}), query: nextQuery });
    });

    if (state.view === 'architecture') {
      const viewModel = computeArchitectureViewModel(graph, state, currentFocusSelection);
      renderArchitectureView(viewModel, shellApi.getCanvasEl(), selectAndClearFocus);
      const contextRailEl = shellApi.getContextRailEl();
      if (viewModel.flowSummary) {
        renderFlowSummary(viewModel.flowSummary, contextRailEl);
      } else {
        clear(contextRailEl);
        contextRailEl.textContent = buildContextRailText(graph);
      }
      renderFocusControlMenu(graph, state, contextRailEl, shellApi, rerender);
    } else if (state.view === 'privacy') {
      const viewModel = computePrivacyViewModel(graph, state, queryPredicate);
      renderPrivacyView(viewModel, shellApi.getCanvasEl(), selectAndClearFocus);
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    } else if (state.view === 'trace') {
      const viewModel = computeTraceViewModel(graph, state);
      renderTraceView(viewModel, shellApi.getCanvasEl(), selectAndClearFocus);
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    } else if (state.view === 'inventory') {
      const viewModel = computeInventoryViewModel(graph, state, queryPredicate);
      renderInventoryView(viewModel, shellApi.getCanvasEl(), selectAndClearFocus, (tableId) => shellApi.setTable(tableId));
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());

    if (state.view === 'privacy' || state.view === 'inventory') {
      renderFilterRail(filterFacets, state.filters ?? {}, shellApi.getLeftRailEl(), (nextFilters) => shellApi.setFilters(nextFilters));
    } else {
      const railEl = shellApi.getLeftRailEl();
      railEl.textContent = 'Filters apply to Privacy View and some Inventory tables.';
    }
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
