// main.js — Milestone 3, sub-project Wire.
//
// The page's real entry point, external to index.html for one reason:
// index.html's own inline <script type="module"> block would need
// `script-src 'unsafe-inline'` under the explore server's static-asset CSP
// (scanner/src/server/static-assets.js's STATIC_CSP_HEADER_VALUE). Moving
// this logic into its own file, loaded via
// `<script type="module" src="./src/main.js">`, lets that CSP stay a
// strict `script-src 'self'` with no exception — see the M3-Wire plan's own
// "load-bearing correction" on this point.
//
// Replaces the old static import of FLAGSHIP_GRAPH with a live fetch
// against the explore server's own /api/v1/graph endpoint, authenticated
// via the token carried in the page's own URL fragment. bootstrap() itself
// is UNCHANGED — it already takes a plain graph object with no assumption
// about where it came from.

import { bootstrap } from './app.js';
import { el, clear } from './lib/dom.js';
import { extractTokenFromFragment, fetchGraph } from './lib/api-client.js';

function showError(rootEl, message) {
  clear(rootEl);
  rootEl.appendChild(
    el('div', { class: 'app-error' }, [
      el('div', { class: 'app-error__title' }, 'Data Flow Explorer could not load'),
      el('div', { class: 'app-error__message' }, message),
    ]),
  );
}

async function init() {
  const rootEl = document.getElementById('app-root');

  const token = extractTokenFromFragment();
  if (!token) {
    showError(
      rootEl,
      'No session token found in this page’s URL. Start a new session with `agentic-security explore` and open the URL it prints (including the "#token=..." part).',
    );
    return;
  }

  let graph;
  try {
    graph = await fetchGraph({ token });
  } catch (err) {
    showError(rootEl, `Failed to load the data flow graph: ${err && err.message ? err.message : String(err)}`);
    return;
  }

  bootstrap(rootEl, graph);
}

init();
