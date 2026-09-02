# Milestone 4, sub-project Self-contained HTML report — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `agentic-security`-side script that produces ONE fully
self-contained `.html` file — embedding the (already-redacted, digested)
`DataFlowGraph v1` export, `frontend/`'s entire interactive explorer UI
(bundled into one script, no external `import`), and all 9 CSS files
inline — that a user can double-click and open offline with zero server,
zero network requests, in any modern browser including via `file://`.

**Architecture commits to Option 1** from this sub-project's own scoping
doc (`2026-09-01-data-flow-explorer-m4-html-report-scoping.md`): a small,
hand-rolled, regex-based module bundler — no new npm dependency. This is
viable specifically BECAUSE `frontend/src/`'s real 21-file module graph
(confirmed this session, `grep`-enumerated in full) uses ONLY named
imports/exports (`import { a, b } from './x.js'`, `export function foo`/
`export const foo`/`export class Foo`) — zero default exports, zero
`export *`, zero namespace (`import * as`) or side-effect-only imports,
confirmed by a full-tree grep. A general bundler is not needed to correctly
handle a module graph this simple and fully enumerated.

**Tech Stack:** Node ESM, `node:fs`/`node:path` only (no new dependency).
Reuses `frontend/test/dom-shim.js`'s existing DOM-shim test harness for
bundling-equivalence proofs, and `scanner/src/lineage/export-json.js`'s
`exportGraphJSON` (COMPLETE) for the embedded graph payload.

**Spec:** `2026-09-01-data-flow-explorer-m4-html-report-scoping.md` (this
sub-project's own scoping doc — the `file://` module-CORS constraint this
plan builds around was EMPIRICALLY confirmed there via a real, locally
invoked Chrome binary, not merely cited) and
`2026-09-01-data-flow-explorer-m4-scoping.md` (M4 top-level doc). PRD
§17.5 ("Self-contained export").

## Global Constraints

- **No new npm dependency.** `node:fs`/`node:path`/`node:crypto` only.
- **No network request, no external resource reference, of any kind** in
  the emitted HTML — no CDN script/font/stylesheet, matching §17.5's own
  "avoid any remote scripts or tracking" requirement exactly.
- **The bundler must exactly preserve behavior** — the bundled, IIFE-
  wrapped code must produce output structurally identical to calling the
  same functions unbundled, proven by a real DOM-shim comparison test
  (Task 2), not asserted by construction.
- **Real-fixture grounding**: every test assertion about bundled output
  shape is checked against the real, current `frontend/src/` file list —
  re-`grep` it at implementation time rather than trusting this plan's own
  enumeration, since a file could be added/removed between scoping and
  implementation.
- **Confidential-by-default**: the embedded graph uses
  `exportGraphJSON`'s own `redact: true` default (COMPLETE, Task 2's own
  sub-project) — never pass `redact: false` from this report generator
  without an explicit, separate caller opt-in (out of scope for v1; no
  such opt-in is built this increment).

---

## Task 1: The module bundler (`bundle-frontend.mjs`)

**Files:**
- Create: `scanner/scripts/bundle-frontend.mjs`
- Test: `scanner/test/bundle-frontend.test.js`

**Interfaces:**
- Consumes: nothing from `scanner/src/` — pure filesystem input (a
  `frontend/src/` directory tree) and string processing.
- Produces: `bundleFrontendModules(entryAbsPath) -> string` (exported for
  direct testing) — one JS string with zero remaining `import`/`export`
  statements, safe to inline into a single `<script>` tag.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/bundle-frontend.test.js`. Ground every assertion in
a small, hand-built temp-directory fixture (2-3 files, a real import
chain, a real name that must NOT collide) rather than the real
`frontend/src/` tree for the unit-level tests — the real tree is exercised
separately in Task 3's own end-to-end golden test.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { bundleFrontendModules } from '../scripts/bundle-frontend.mjs';

function _mkTmpTree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-bundle-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

test('bundleFrontendModules: single file, no imports, no rewriting needed', () => {
  const root = _mkTmpTree({ 'a.js': 'export function greet() { return "hi"; }' });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  assert.doesNotMatch(out, /\bimport\b/);
  assert.doesNotMatch(out, /\bexport\b/);
  const fn = new Function(`${out}\nreturn typeof greet === 'function' ? greet() : 'MISSING';`);
  assert.equal(fn(), 'hi');
});

test('bundleFrontendModules: two-file import chain resolves correctly', () => {
  const root = _mkTmpTree({
    'a.js': `import { greet } from './b.js';\nexport function hello() { return greet() + '!'; }`,
    'b.js': `export function greet() { return 'hi'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn hello();`);
  assert.equal(fn(), 'hi!');
});

test('bundleFrontendModules: two files independently declaring the same local name do not collide', () => {
  // Both files use `helper` as a PRIVATE (non-exported) top-level name.
  // The bundler's own IIFE-per-module wrapping must keep these in separate
  // scopes — a naive flat-concatenation bundler would collide them.
  const root = _mkTmpTree({
    'a.js': `import { fromB } from './b.js';\nfunction helper() { return 'A'; }\nexport function fromA() { return helper() + fromB(); }`,
    'b.js': `function helper() { return 'B'; }\nexport function fromB() { return helper(); }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn fromA();`);
  assert.equal(fn(), 'AB');
});

test('bundleFrontendModules: diamond dependency (two importers, one shared module) is not duplicated/broken', () => {
  const root = _mkTmpTree({
    'entry.js': `import { x } from './a.js';\nimport { y } from './b.js';\nexport function run() { return x() + y(); }`,
    'a.js': `import { shared } from './shared.js';\nexport function x() { return 'A' + shared(); }`,
    'b.js': `import { shared } from './shared.js';\nexport function y() { return 'B' + shared(); }`,
    'shared.js': `export function shared() { return 'S'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'entry.js'));
  const fn = new Function(`${out}\nreturn run();`);
  assert.equal(fn(), 'ASBS');
});

test('bundleFrontendModules: a multi-line import statement is parsed correctly', () => {
  const root = _mkTmpTree({
    'a.js': `import {\n  x,\n  y,\n} from './b.js';\nexport function run() { return x() + y(); }`,
    'b.js': `export function x() { return 'X'; }\nexport function y() { return 'Y'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn run();`);
  assert.equal(fn(), 'XY');
});

test('bundleFrontendModules: throws a clear error on an unsupported import form (default/namespace/side-effect)', () => {
  const root = _mkTmpTree({ 'a.js': `import foo from './b.js';\nexport function run() {}`, 'b.js': 'export default 1;' });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /unsupported import/i);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/bundle-frontend.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `bundle-frontend.mjs`**

```js
// bundle-frontend.mjs — Milestone 4, sub-project Self-contained HTML
// report. A minimal, hand-rolled ES-module bundler, deliberately NOT a
// general one — see this sub-project's own scoping doc for why a real
// bundler dependency (esbuild etc.) was considered and NOT chosen:
// frontend/src/'s real module graph (confirmed by a full-tree grep before
// this file was written) uses ONLY named imports/exports, no default
// exports, no `export *`, no namespace or side-effect-only imports. This
// bundler supports exactly that subset and throws a clear error on
// anything else, rather than silently mishandling an unsupported form.
//
// Algorithm: parse each file's own import specifiers + exported top-level
// names via regex (safe here because the supported subset's syntax is
// simple and unambiguous — a full parser is not needed for this bounded,
// fully-enumerated 21-file input); topologically order every reachable
// module; wrap EACH module in its own IIFE (this is what prevents two
// files' same-named PRIVATE top-level bindings from colliding when
// concatenated — a real risk with naive flat concatenation, proven by
// this file's own test suite); each module's IIFE destructures its own
// imports from its dependencies' already-evaluated namespace objects
// (`const { a, b } = __NS_shared;`) and returns its own exports as a
// plain object; the entry module's own IIFE result is discarded (its
// side effects, e.g. calling `bootstrap()`, are what the caller wants).

import * as fs from 'node:fs';
import * as path from 'node:path';

const IMPORT_RE = /import\s*\{([\s\S]*?)\}\s*from\s*['"](\.[^'"]+)['"];?/g;
const UNSUPPORTED_IMPORT_RE = /^import\s+(?!\{)/m;
const EXPORT_STAR_RE = /^export\s*\*/m;
const EXPORT_DEFAULT_RE = /^export\s+default\b/m;
const EXPORT_NAMED_RE = /^export\s+(?:function\*?|class|const|let|var)\s+([A-Za-z0-9_$]+)/gm;

function _nsName(absPath, seen) {
  // A stable, collision-free JS identifier per module, derived from its
  // path. seen is a Map<absPath, name> shared across the whole bundle run.
  if (seen.has(absPath)) return seen.get(absPath);
  const base = absPath.replace(/[^A-Za-z0-9_$]/g, '_');
  const name = `__NS_${base}`;
  seen.set(absPath, name);
  return name;
}

function _parseModule(absPath) {
  const src = fs.readFileSync(absPath, 'utf8');
  if (UNSUPPORTED_IMPORT_RE.test(src) || EXPORT_STAR_RE.test(src) || EXPORT_DEFAULT_RE.test(src)) {
    throw new Error(`bundleFrontendModules: unsupported import/export form in ${absPath} — only named imports/exports are supported`);
  }
  const imports = [];
  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(src))) {
    const names = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    const resolved = path.resolve(path.dirname(absPath), m[2]);
    imports.push({ names, resolved });
  }
  const exportNames = [];
  EXPORT_NAMED_RE.lastIndex = 0;
  while ((m = EXPORT_NAMED_RE.exec(src))) exportNames.push(m[1]);
  // Strip import lines entirely; strip the leading `export ` keyword from
  // each exported declaration (the declaration itself — function/const/
  // class — is kept verbatim, so the body is otherwise untouched).
  const body = src
    .replace(IMPORT_RE, '')
    .replace(/^export\s+(?=(?:function\*?|class|const|let|var)\s)/gm, '');
  return { absPath, body, imports, exportNames };
}

export function bundleFrontendModules(entryAbsPath) {
  const nsNames = new Map();
  const parsed = new Map(); // absPath -> parsed module
  const order = []; // topological, dependency-first
  const visiting = new Set();

  function visit(absPath) {
    if (parsed.has(absPath)) return;
    if (visiting.has(absPath)) {
      throw new Error(`bundleFrontendModules: circular import detected at ${absPath} — this bundler does not support cycles`);
    }
    visiting.add(absPath);
    const mod = _parseModule(absPath);
    parsed.set(absPath, mod);
    for (const imp of mod.imports) visit(imp.resolved);
    visiting.delete(absPath);
    order.push(absPath);
  }
  visit(entryAbsPath);

  const chunks = [];
  for (const absPath of order) {
    const mod = parsed.get(absPath);
    const ns = _nsName(absPath, nsNames);
    const destructures = mod.imports
      .map((imp) => `  const { ${imp.names.join(', ')} } = ${_nsName(imp.resolved, nsNames)};`)
      .join('\n');
    const returnObj = mod.exportNames.length ? `  return { ${mod.exportNames.join(', ')} };` : '  return {};';
    chunks.push(`const ${ns} = (function() {\n${destructures}\n${mod.body}\n${returnObj}\n})();`);
  }
  return chunks.join('\n\n');
}
```

**Re-verification note for the implementer:** the regexes above were
designed against the REAL `frontend/src/` file shapes enumerated during
this sub-project's own scoping pass (all named imports/exports, one
confirmed multi-line import in `app.js`) — re-run the same greps
(`grep -rn "^import " frontend/src --include="*.js"`,
`grep -rn "export default\|export \*" frontend/src --include="*.js"`)
yourself before trusting this file list is still accurate, since
`frontend/src/` could have changed since scoping.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/bundle-frontend.test.js` (from `scanner/`)
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scanner/scripts/bundle-frontend.mjs scanner/test/bundle-frontend.test.js
git commit -m "feat(scripts): add bundle-frontend.mjs, a minimal named-imports-only ES module bundler"
```

---

## Task 2: Export entry point + bundling-equivalence proof against the real frontend

**Files:**
- Create: `frontend/src/export-entry.js`
- Modify: `frontend/src/app.js` (remove one dead import — see below)
- Test: `scanner/test/bundle-frontend-golden.test.js`

**Interfaces:**
- Consumes: `bootstrap` from `frontend/src/app.js` (already shipped,
  already takes a plain graph object with no assumption about its
  source — confirmed this session by reading `main.js`'s own header
  comment documenting this exact property for the `explore`-server case).
- Produces: `frontend/src/export-entry.js`'s own top-level side effect —
  reads an embedded graph global and calls `bootstrap`.

- [ ] **Step 1: Remove the dead `FLAGSHIP_GRAPH` import from `app.js`**

Confirmed this session by direct grep (`grep -n "FLAGSHIP_GRAPH" frontend/src/app.js`
returns only the import line itself, line 2 — the binding is never
referenced anywhere else in the file): `app.js`'s own
`import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';` is dead code.
Remove this one line. This is real, safe, disclosed cleanup — not
speculative — and matters for THIS sub-project specifically: without it,
`data/flagship-graph.js`'s own illustrative fixture content (a payments-
platform demo graph, per its own generator's header) would be pulled into
every real customer's self-contained export bundle for no reason,
alongside a real risk this session has repeatedly guarded against
elsewhere (AC-24, "fixture content is never represented as observed
evidence" — this isn't quite that failure mode since it's inert dead
code, never rendered, but shipping it silently bloats every real export
with irrelevant demo data). Re-run `frontend/npm test` after removing it
to confirm zero regressions (expected — it was unused).

- [ ] **Step 2: Write `export-entry.js`**

```js
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
```

This mirrors `main.js`'s own existing structure/guard pattern exactly
(confirmed against the real file this session) — same defensive
`document.getElementById` guard for the same reason (importability under
`test/dom-shim.js`'s minimal document, per `main.js`'s own comment on
this).

- [ ] **Step 3: Write the golden bundling-equivalence test**

This is the load-bearing proof for Task 1's whole approach: bundled code
must behave identically to unbundled code. Ground it in the REAL
`frontend/src/` tree (not a synthetic fixture — Task 1's own tests already
cover the bundler algorithm's correctness in isolation; this test proves
it holds for the real, full app).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bundleFrontendModules } from '../scripts/bundle-frontend.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, '../../frontend/src');
const DOM_SHIM_PATH = path.resolve(__dirname, '../../frontend/test/dom-shim.js');
const FLAGSHIP_PATH = path.resolve(__dirname, '../src/lineage/fixtures/flagship-graph.json');

test('bundle-frontend-golden: bundled export-entry.js renders the same DOM as the unbundled app.js bootstrap()', async () => {
  const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

  // Unbundled baseline: import the real, unmodified app.js directly.
  const { createDomShim } = await import(DOM_SHIM_PATH);
  const shimA = createDomShim();
  globalThis.document = shimA.document;
  const { bootstrap } = await import(path.join(FRONTEND_SRC, 'app.js'));
  const rootA = shimA.document.createElement('div');
  rootA.id = 'app-root';
  bootstrap(rootA, flagship);
  const baselineHtml = rootA.outerHTML ?? rootA.toString();

  // Bundled: run bundleFrontendModules over the real export-entry.js,
  // execute it against a FRESH dom-shim instance with the graph global
  // set first (mirroring exactly what the emitted HTML does), and diff.
  const bundled = bundleFrontendModules(path.join(FRONTEND_SRC, 'export-entry.js'));
  const shimB = createDomShim();
  const rootB = shimB.document.createElement('div');
  rootB.id = 'app-root';
  shimB.document.body ? shimB.document.body.appendChild(rootB) : null;
  const fakeWindow = { __AGENTIC_SECURITY_EXPORTED_GRAPH__: flagship };
  // Real, careful sandboxing: the bundled code references bare
  // `document`/`window` as globals (matching what a real <script> tag in
  // the emitted HTML sees) — construct via `new Function` with explicit
  // parameters rather than mutating globalThis a second time mid-test.
  const runBundled = new Function('document', 'window', bundled);
  runBundled(shimB.document, fakeWindow);
  const bundledHtml = rootB.outerHTML ?? rootB.toString();

  assert.equal(bundledHtml, baselineHtml, 'bundled export-entry.js must render byte-identical DOM to the unbundled bootstrap() call');
});
```

**Re-verification note:** `dom-shim.js`'s own exact API (`createDomShim()`'s
return shape, whether `document.body` exists, how `outerHTML`/serialization
works) must be confirmed by reading the real file before trusting the
sketch above — this plan's own author read only its exported function
list, not its full body, during scoping. Adjust the harness wiring to
match the real shim's actual API; the PROPERTY being proven (bundled ==
unbundled DOM output) is what matters, not this exact code.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/bundle-frontend-golden.test.js` (from `scanner/`)
and `npm test` (from `frontend/`, confirming Step 1's removal broke
nothing)
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/export-entry.js frontend/src/app.js scanner/test/bundle-frontend-golden.test.js
git commit -m "feat(frontend): add export-entry.js; prove bundled output matches unbundled bootstrap()"
```

---

## Task 3: The report generator (CSS inlining + graph embedding + final HTML assembly)

**Files:**
- Create: `scanner/scripts/generate-html-report.mjs`
- Test: `scanner/test/generate-html-report.test.js`

**Interfaces:**
- Consumes: `bundleFrontendModules` (Task 1), `exportGraphJSON` (COMPLETE,
  prior sub-project, `scanner/src/lineage/export-json.js`).
- Produces: `generateHtmlReport(graph, opts) -> string` (one complete,
  self-contained HTML document as a string), exported for direct testing.
  A thin CLI wrapper is explicitly OUT of scope here — sub-project #5
  (CLI/slash-command wiring) owns invoking this from `agentic-security`
  itself; this task ships the generator function only.

- [ ] **Step 1: Write the failing tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateHtmlReport } from '../scripts/generate-html-report.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.resolve(__dirname, '../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('generateHtmlReport: produces one HTML document with no external references', () => {
  const html = generateHtmlReport(flagship);
  assert.match(html, /<!DOCTYPE html>/i);
  // §17.5's own "avoid any remote scripts or tracking" — no http(s):// src/href
  // anywhere except inside the embedded graph JSON's own data values (a
  // destination.literalValue string is not a resource reference).
  assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i);
  assert.doesNotMatch(html, /<link[^>]+href=["']https?:/i);
});

test('generateHtmlReport: embeds the graph via exportGraphJSON (redacted by default)', () => {
  const html = generateHtmlReport(flagship);
  assert.match(html, /__AGENTIC_SECURITY_EXPORTED_GRAPH__/);
  // The exported envelope's own digest/scope/confidential fields must be
  // present in the embedded payload, not just the bare graph — confirming
  // this generator calls exportGraphJSON's full envelope, not graph alone.
  assert.match(html, /"confidential"\s*:\s*true/);
  assert.match(html, /"digest"\s*:/);
});

test('generateHtmlReport: inlines all 9 real CSS files', () => {
  const html = generateHtmlReport(flagship);
  const stylesDir = path.resolve(__dirname, '../../frontend/styles');
  const realCssFiles = fs.readdirSync(stylesDir).filter((f) => f.endsWith('.css'));
  assert.ok(realCssFiles.length > 0, 'sanity: frontend/styles must have real CSS files to inline');
  for (const f of realCssFiles) {
    const content = fs.readFileSync(path.join(stylesDir, f), 'utf8').trim();
    if (content) assert.ok(html.includes(content.slice(0, 50)), `expected ${f}'s own content to appear inlined`);
  }
});

test('generateHtmlReport: inlines tokens.css BEFORE the files that consume its custom properties', () => {
  // Real regression this session's own frontend/index.html read caught:
  // an alphabetical inline order would put tokens.css 8th, after 7 files
  // that reference its var(--...) custom properties on first paint.
  const html = generateHtmlReport(flagship);
  const stylesDir = path.resolve(__dirname, '../../frontend/styles');
  const tokensContent = fs.readFileSync(path.join(stylesDir, 'tokens.css'), 'utf8').trim().slice(0, 30);
  const shellContent = fs.readFileSync(path.join(stylesDir, 'shell.css'), 'utf8').trim().slice(0, 30);
  assert.ok(html.indexOf(tokensContent) < html.indexOf(shellContent), 'tokens.css must appear before shell.css in the inlined <style> block');
});

test('generateHtmlReport: AC-14 reproducibility — same graph in twice, byte-identical except a documented timestamp', () => {
  const a = generateHtmlReport(flagship);
  const b = generateHtmlReport(flagship);
  // The embedded exportGraphJSON envelope carries its own exportedAt
  // timestamp (real, expected difference) — strip ONLY that documented
  // field before comparing, matching export-json.test.js's own AC-14
  // proof pattern.
  const strip = (h) => h.replace(/"exportedAt"\s*:\s*"[^"]*"/, '"exportedAt":"STRIPPED"');
  assert.equal(strip(a), strip(b));
});

test('generateHtmlReport: redact:false is never the default — opts must be explicit to unredact', () => {
  const html = generateHtmlReport(flagship);
  assert.doesNotMatch(html, /"confidential"\s*:\s*false/);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/generate-html-report.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `generate-html-report.mjs`**

```js
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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_ROOT = path.resolve(HERE, '../../frontend');
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
// would introduce silently. Re-confirm this literal list against the real
// index.html at implementation time — this plan's own citation could
// drift if a new view/stylesheet is added later.
const CSS_LOAD_ORDER = [
  'tokens.css', 'shell.css', 'architecture-view.css', 'inspector.css',
  'privacy-view.css', 'trace-view.css', 'filter-rail.css',
  'inventory-view.css', 'query-bar.css',
];

function _inlineCss() {
  const onDisk = new Set(fs.readdirSync(STYLES_DIR).filter((f) => f.endsWith('.css')));
  const missing = CSS_LOAD_ORDER.filter((f) => !onDisk.has(f));
  if (missing.length) throw new Error(`bundle-frontend: CSS_LOAD_ORDER names files not found in ${STYLES_DIR}: ${missing.join(', ')} — frontend/index.html's own <link> list may have changed; re-sync CSS_LOAD_ORDER with it`);
  const extra = [...onDisk].filter((f) => !CSS_LOAD_ORDER.includes(f));
  if (extra.length) throw new Error(`bundle-frontend: real CSS files not in CSS_LOAD_ORDER: ${extra.join(', ')} — a new stylesheet was added to frontend/styles/ without updating this list's load order`);
  return CSS_LOAD_ORDER.map((f) => fs.readFileSync(path.join(STYLES_DIR, f), 'utf8')).join('\n');
}

export function generateHtmlReport(graph, opts = {}) {
  const exported = exportGraphJSON(graph, opts);
  const css = _inlineCss();
  const bundledJs = bundleFrontendModules(ENTRY_PATH);
  const graphJson = JSON.stringify(exported);
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
window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ = ${graphJson};
</script>
<script>
${bundledJs}
</script>
</body>
</html>`;
}
```

**Re-verification note:** `CSS_LOAD_ORDER` above is copied from a direct
read of `frontend/index.html`'s real `<link>` list earlier this session —
re-confirm it's still current before implementing (a new view/stylesheet
added to `frontend/` after this plan was written would need a matching
`CSS_LOAD_ORDER` entry, which `_inlineCss`'s own `extra`/`missing` guards
above will catch loudly rather than silently mis-ordering the cascade).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/generate-html-report.test.js` (from `scanner/`)
Expected: PASS.

- [ ] **Step 5: Real-browser proof (not just DOM-shim)**

Beyond the automated suite: write the generated HTML to a real file and
open it via the SAME real-Chrome-headless-CLI technique this sub-project's
own scoping doc used to confirm the `file://` constraint in the first
place (`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
--headless=new --virtual-time-budget=<enough> --dump-dom
"file://<path>"`) — confirm the dumped DOM shows the real app rendered
(e.g. a real node label from the flagship fixture appears in the output),
not a blank `#app-root` or a `FAILURE:` error string. This is the actual
acceptance proof for this whole sub-project's own reason to exist — do
not skip it in favor of the DOM-shim tests alone, which prove bundling
correctness but not real-browser `file://` loading.

- [ ] **Step 6: Wire the new test file into `test:lineage`, full gate**

Add `test/bundle-frontend.test.js`, `test/bundle-frontend-golden.test.js`,
and `test/generate-html-report.test.js` to `scanner/package.json`'s
`test:lineage` script (confirmed this session to be an explicit file
list). Run `npm test` (from `scanner/`) and `npm test` (from `frontend/`).
Expected: both PASS, exit code 0.

- [ ] **Step 7: Commit**

```bash
git add scanner/scripts/generate-html-report.mjs scanner/test/generate-html-report.test.js scanner/package.json
git commit -m "feat(scripts): add generate-html-report.mjs — self-contained offline HTML export"
```

---

## Explicitly deferred (not this plan's job)

- CLI/slash-command wiring (`agentic-security report --html` or similar)
  — sub-project #5, once #2/#3/#4 all exist to wire together.
- PNG/SVG/PDF embedding inside the report — sub-project #4's own separate
  open technical question (deterministic SVG serialization).
- DPIA/RoPA embedding — depends on sub-project #6, not started.
- An explicit `redact: false` / "include confidential content" opt-in for
  the report generator — real, disclosed future work; this increment
  never emits unredacted content.
- Minifying/compressing the bundled JS or inlined CSS — a real, disclosed
  polish item; correctness over size this increment.
