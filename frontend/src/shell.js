import { el, clear } from './lib/dom.js';
import { escapeHtml } from './lib/escape-html.js';
import { parseStateFromHash, serializeStateToHash } from './lib/state.js';

const VIEWS = [
  { id: 'architecture', label: 'Architecture' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'trace', label: 'Trace' },
];

/**
 * @param {HTMLElement} rootEl
 * @param {object} graph - a DataFlowGraph v1 envelope (already validated at build time)
 * @returns {{ setActiveView: (viewName: string) => void, getCanvasEl: () => HTMLElement, getInspectorEl: () => HTMLElement }}
 */
export function mountShell(rootEl, graph) {
  let state = parseStateFromHash(window.location.hash);

  const shell = el('div', { class: 'shell' });
  const header = buildHeader(graph);
  const coverageBanner = buildCoverageBanner(graph);
  const tabs = buildViewTabs(state.view, (nextView) => {
    state = { ...state, view: nextView };
    window.location.hash = serializeStateToHash(state);
    applyActiveTab(tabs, state.view);
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

  window.addEventListener('hashchange', () => {
    state = parseStateFromHash(window.location.hash);
    applyActiveTab(tabs, state.view);
  });

  return {
    setActiveView(viewName) {
      state = { ...state, view: viewName };
      window.location.hash = serializeStateToHash(state);
      applyActiveTab(tabs, state.view);
    },
    getCanvasEl: () => canvas,
    getInspectorEl: () => inspector,
  };
}

function buildHeader(graph) {
  const repo = graph.scope?.repository ?? 'unknown repository';
  const env = graph.scope?.environment ?? 'unknown environment';
  const scanStatus = graph.scanHealth?.status ?? 'unknown';
  const isFixture = graph.scope?.source === 'fixture';
  return el('div', { class: 'shell__header' }, [
    el('div', { class: 'shell__header-title' }, 'Data Flow Explorer'),
    el('div', { class: 'shell__header-meta' }, `${escapeHtml(repo)} · ${escapeHtml(env)} · Scan ${escapeHtml(scanStatus)}`),
    isFixture ? el('div', { class: 'shell__header-meta', 'data-illustrative': 'true' }, 'Illustrative demo data') : null,
  ]);
}

function buildCoverageBanner(graph) {
  const status = graph.coverage?.status ?? graph.scanHealth?.status;
  const banner = el('div', { class: 'shell__coverage-banner' }, `Coverage: ${escapeHtml(status ?? 'unknown')} — not a complete assessment`);
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

function buildContextRailText(graph) {
  return `${graph.nodes.length} nodes · ${graph.edges.length} edges · ${graph.flows.length} flows`;
}
