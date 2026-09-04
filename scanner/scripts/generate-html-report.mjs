// generate-html-report.mjs — Milestone 4, sub-project Self-contained
// HTML report. Assembles ONE offline-safe HTML document: inline CSS,
// one bundled inline <script> (Task 1's bundler over Task 2's
// export-entry.js), and the graph embedded via exportGraphJSON
// (redacted by default) as a global the bundled script reads.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundleFrontendModules } from './bundle-frontend.mjs';
import { exportGraphJSON } from '../src/lineage/export-json.js';
import { resolveFrontendRoot } from '../src/shared/frontend-root.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// See src/shared/frontend-root.js: a hardcoded `../../frontend` resolved
// correctly for this file's unbundled dev location (scanner/scripts/) but
// broke for the published package, whose build now copies frontend/ into
// scanner/dist/frontend/ — a different relative depth from this same
// module once ncc bundles it into a dist/ chunk.
const FRONTEND_ROOT = resolveFrontendRoot(HERE);
const STYLES_DIR = path.join(FRONTEND_ROOT, 'styles');
const ENTRY_PATH = path.join(FRONTEND_ROOT, 'src', 'export-entry.js');

// NOT alphabetical — confirmed this session by reading the real
// frontend/index.html directly: its own <link> order is
// tokens.css, shell.css, architecture-view.css, inspector.css,
// privacy-view.css, trace-view.css, filter-rail.css, inventory-view.css,
// query-bar.css. `tokens.css` first is load-bearing (CSS custom
// properties the other 8 files consume via `var(--...)` — an alphabetical
// sort would put it 8th, after 7 files that reference undefined custom
// properties on first paint). Matching real cascade order avoids a real
// specificity/undefined-custom-property regression alphabetical sorting
// would introduce silently. Re-confirmed against the real index.html
// directly at implementation time (unchanged from the task-3 brief's own
// citation).
const CSS_LOAD_ORDER = [
  'tokens.css', 'shell.css', 'architecture-view.css', 'inspector.css',
  'privacy-view.css', 'trace-view.css', 'filter-rail.css',
  'inventory-view.css', 'query-bar.css',
];

function _inlineCss() {
  const onDisk = new Set(fs.readdirSync(STYLES_DIR).filter((f) => f.endsWith('.css')));
  const missing = CSS_LOAD_ORDER.filter((f) => !onDisk.has(f));
  if (missing.length) throw new Error(`generate-html-report: CSS_LOAD_ORDER names files not found in ${STYLES_DIR}: ${missing.join(', ')} — frontend/index.html's own <link> list may have changed; re-sync CSS_LOAD_ORDER with it`);
  const extra = [...onDisk].filter((f) => !CSS_LOAD_ORDER.includes(f));
  if (extra.length) throw new Error(`generate-html-report: real CSS files not in CSS_LOAD_ORDER: ${extra.join(', ')} — a new stylesheet was added to frontend/styles/ without updating this list's load order`);
  return CSS_LOAD_ORDER.map((f) => fs.readFileSync(path.join(STYLES_DIR, f), 'utf8')).join('\n');
}

export function generateHtmlReport(graph, opts = {}) {
  const exported = exportGraphJSON(graph, opts);
  const css = _inlineCss();
  const bundledJs = bundleFrontendModules(ENTRY_PATH);
  // Escape `<` so scanned-source-derived content (a node/flow/data-element
  // label — none of which _redactGraph covers, since labels aren't a
  // secret-shaped surface, but CAN carry arbitrary scanned identifier
  // text) can never contain a literal `</script>` that breaks out of this
  // inline data script and injects a second one. Same mitigation, same
  // reasoning, as the existing SAST/SCA HTML report's own precedent
  // (scanner/src/report/index.js's toHTML) — found missing here and
  // fixed by this sub-project's own final task review, which reproduced
  // the injection live before this fix landed.
  const envelopeJson = JSON.stringify(exported).replace(/</g, '\\u003c');
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Data Flow Explorer — self-contained report</title>
<style>
${css}
</style>
</head>
<body>
<div id="app-root"></div>
<script>
// The full exportGraphJSON envelope (digest/scope/coverage/limitations/
// confidential + the redacted graph body) is embedded whole here, under
// its own name, so this report carries the same tamper-evident/disclosure
// metadata the JSON exporter produces (PRD §17.5) — never dropped just
// because this is an HTML report rather than a .json file.
//
// __AGENTIC_SECURITY_EXPORTED_GRAPH__ is then bound to the envelope's own
// \`.graph\` body, NOT the envelope itself — this is a deliberate,
// necessary departure from an earlier draft of this generator (which
// assigned the whole envelope directly to that name). frontend/src/
// export-entry.js (Task 2, already shipped and covered by its own golden
// DOM-equivalence test, test/bundle-frontend-golden.test.js) reads this
// EXACT global and passes it straight through to bootstrap(rootEl, graph)
// -> mountShell(rootEl, graph)/computeFilterFacets(graph), both of which
// expect a real DataFlowGraph v1 document (top-level nodes/edges/flows/...),
// never the exportGraphJSON envelope shape (which nests the graph one
// level down, under .graph, alongside digest/scope/confidential). Handing
// bootstrap() the envelope instead of the graph would silently break real
// rendering — exactly what this sub-project's own real-Chrome acceptance
// proof (task-3 brief, Step 5) exists to catch. Confirmed against
// export-entry.js's and Task 2's golden test's real source before this
// generator was written, not assumed.
window.__AGENTIC_SECURITY_EXPORT_ENVELOPE__ = ${envelopeJson};
window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ = window.__AGENTIC_SECURITY_EXPORT_ENVELOPE__.graph;
</script>
<script>
${bundledJs}
</script>
</body>
</html>`;
}
