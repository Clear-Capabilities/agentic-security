// export-entry.js — Milestone 4, sub-project Self-contained HTML report.
//
// The entry point for a bundled, offline, self-contained export — NOT
// main.js, which is the `explore`-server-specific entry point (token
// extraction + authenticated fetch, both irrelevant and unavailable
// offline). This file's only job: read the graph the report generator
// embedded as a global, and call the SAME, UNCHANGED bootstrap() every
// other entry point uses.
//
// `window.__AGENTIC_SECURITY_EXPORTED_GRAPH__` is set by an inline
// <script> the report generator writes BEFORE this bundled script in the
// emitted HTML — see scanner/scripts/generate-html-report.mjs.
import { bootstrap } from './app.js';
import { el, clear } from './lib/dom.js';

function showError(rootEl, message) {
  clear(rootEl);
  rootEl.appendChild(el('div', { class: 'app-error' }, [
    el('div', { class: 'app-error__title' }, 'Data Flow Explorer report could not load'),
    el('div', { class: 'app-error__message' }, message),
  ]));
}

function init() {
  const rootEl = document.getElementById('app-root');
  const graph = typeof window !== 'undefined' ? window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ : undefined;
  if (!graph) {
    showError(rootEl, 'No embedded graph data found in this report file. It may be corrupted — regenerate it with `agentic-security` and open the new file.');
    return;
  }
  bootstrap(rootEl, graph);
}

if (typeof document !== 'undefined' && typeof document.getElementById === 'function' && document.getElementById('app-root')) {
  init();
}
