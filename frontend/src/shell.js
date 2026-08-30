import { el, clear } from './lib/dom.js';
import { parseStateFromHash, serializeStateToHash } from './lib/state.js';

const VIEWS = [
  { id: 'architecture', label: 'Architecture' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'trace', label: 'Trace' },
];

/**
 * @param {HTMLElement} rootEl
 * @param {object} graph - a DataFlowGraph v1 envelope (already validated at build time)
 * @returns {{
 *   setActiveView: (viewName: string) => void,
 *   getState: () => {view: string, selectedId: string|null, filters: object},
 *   setSelection: (selectedId: string|null) => void,
 *   setFilters: (filters: object) => void,
 *   onStateChange: (listener: (state: object) => void) => (() => void),
 *   getCanvasEl: () => HTMLElement,
 *   getInspectorEl: () => HTMLElement,
 *   getContextRailEl: () => HTMLElement,
 *   getLeftRailEl: () => HTMLElement,
 *   destroy: () => void,
 * }}
 */
export function mountShell(rootEl, graph) {
  let state = parseStateFromHash(window.location.hash);
  let stateChangeListeners = [];

  const shell = el('div', { class: 'shell' });
  const header = buildHeader(graph);
  const coverageBanner = buildCoverageBanner(graph);
  const tabs = buildViewTabs(state.view, (nextView) => {
    updateState({ ...state, view: nextView });
  });
  const leftRail = el('div', { class: 'shell__left-rail' }, 'Filters (wired by the next plan)');
  const canvas = el('div', { class: 'shell__canvas' });
  const inspector = el('div', { class: 'shell__inspector' }, 'Evidence inspector (wired by the next plan)');
  const contextRail = el('div', { class: 'shell__context-rail' }, buildContextRailText(graph));

  shell.appendChild(header);
  shell.appendChild(coverageBanner);
  shell.appendChild(tabs);
  shell.appendChild(leftRail);
  shell.appendChild(canvas);
  shell.appendChild(inspector);
  shell.appendChild(contextRail);

  clear(rootEl);
  rootEl.appendChild(shell);

  function notifyStateChange() {
    const snapshot = { ...state };
    for (const listener of stateChangeListeners) listener(snapshot);
  }

  // Shared by setActiveView/setSelection/setFilters/the tab-click handler:
  // update the closure state, sync the URL hash, refresh the tab UI, notify.
  function updateState(nextState) {
    state = nextState;
    window.location.hash = serializeStateToHash(state);
    applyActiveTab(tabs, state.view);
    notifyStateChange();
  }

  function handleHashChange() {
    state = parseStateFromHash(window.location.hash);
    applyActiveTab(tabs, state.view);
    notifyStateChange();
  }

  window.addEventListener('hashchange', handleHashChange);

  return {
    setActiveView(viewName) {
      updateState({ ...state, view: viewName });
    },
    getState() {
      return { ...state };
    },
    setSelection(selectedId) {
      updateState({ ...state, selectedId });
    },
    setFilters(filters) {
      updateState({ ...state, filters });
    },
    onStateChange(listener) {
      stateChangeListeners.push(listener);
      return () => {
        stateChangeListeners = stateChangeListeners.filter((l) => l !== listener);
      };
    },
    getCanvasEl: () => canvas,
    getInspectorEl: () => inspector,
    getContextRailEl: () => contextRail,
    getLeftRailEl: () => leftRail,
    destroy() {
      window.removeEventListener('hashchange', handleHashChange);
      stateChangeListeners = [];
    },
  };
}

function buildHeader(graph) {
  const repo = graph.scope?.repository ?? 'unknown repository';
  const env = graph.scope?.environment ?? 'unknown environment';
  const scanStatus = graph.scanHealth?.status ?? 'unknown';
  const isFixture = graph.scope?.source === 'fixture';
  return el('div', { class: 'shell__header' }, [
    el('div', { class: 'shell__header-title' }, 'Data Flow Explorer'),
    el('div', { class: 'shell__header-meta' }, `${repo} · ${env} · Scan ${scanStatus}`),
    isFixture ? el('div', { class: 'shell__header-meta', 'data-illustrative': 'true' }, 'Illustrative demo data') : null,
  ]);
}

function buildCoverageBanner(graph) {
  const status = graph.coverage?.status ?? graph.scanHealth?.status;
  const banner = el('div', { class: 'shell__coverage-banner' }, `Coverage: ${status ?? 'unknown'} — not a complete assessment`);
  if (status && status !== 'complete') banner.setAttribute('data-visible', 'true');
  return banner;
}

function buildViewTabs(activeView, onSelect) {
  const tabs = el(
    'div',
    { class: 'shell__view-tabs', role: 'tablist' },
    VIEWS.map((v) =>
      el(
        'button',
        {
          class: 'shell__view-tab',
          role: 'tab',
          'aria-selected': String(v.id === activeView),
          'data-view-id': v.id,
          onClick: () => onSelect(v.id),
        },
        v.label,
      ),
    ),
  );
  return tabs;
}

function applyActiveTab(tabsEl, activeView) {
  for (const btn of tabsEl.querySelectorAll('[data-view-id]')) {
    btn.setAttribute('aria-selected', String(btn.getAttribute('data-view-id') === activeView));
  }
}

export function buildContextRailText(graph) {
  return `${graph.nodes.length} nodes · ${graph.edges.length} edges · ${graph.flows.length} flows`;
}
