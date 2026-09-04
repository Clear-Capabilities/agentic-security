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

// Exported for test/golden-state-matrix.test.js (AC-22's "Error" state row)
// only. This is a disclosed, deliberate choice, not an oversight: Node's
// stable `node:test` in this repo's Node version (confirmed this session —
// `node:test`'s `mock` object has no `.module` method here) has no ESM
// module-mocking primitive, so there is no way to make main.js's real
// `init()`/fetch-catch path exercise a REAL failing `fetchGraph` without
// either (a) a network-mocking dependency this repo doesn't otherwise carry,
// or (b) exporting the real render function and calling it directly with the
// same message shape `init()`'s own catch block already builds. (b) is the
// smaller footprint — it adds one keyword to an existing function instead of
// a parallel test-only reimplementation or a new dependency, and it matches
// this sub-project's own golden-DOM pattern elsewhere (golden-architecture.
// test.js / golden-privacy.test.js call the real compute/render functions
// directly rather than a test double). The exported symbol is the exact
// function `init()` calls on a fetch failure — no test-only duplicate logic.
export function showError(rootEl, message) {
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

// Guarded on the mount point actually existing before auto-invoking, rather
// than calling init() unconditionally: this file's ONLY export
// (`showError`, above) is imported directly by test/golden-state-matrix.
// test.js, and importing an ES module always runs its top-level statements
// — including this one — as a side effect. Without this guard, importing
// main.js under test/dom-shim.js's minimal document (no `#app-root` element
// exists, since dom-shim builds a bare virtual tree, not a full page)
// crashed with an unhandled rejection from `document.getElementById`
// returning something the rest of init() can't use. The guard is also a
// real, sensible defensive property outside of tests — this script is never
// meant to run against a page lacking its own mount point.
if (typeof document !== 'undefined' && typeof document.getElementById === 'function' && document.getElementById('app-root')) {
  init();
}
