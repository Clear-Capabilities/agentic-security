export const id = 122;
export const ids = [122,180];
export const modules = {

/***/ 1122:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  exportPdf: () => (/* binding */ exportPdf),
  exportPng: () => (/* binding */ exportPng),
  exportSvg: () => (/* binding */ exportSvg)
});

// UNUSED EXPORTS: _validTimeoutMs

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(8161);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(1421);
// EXTERNAL MODULE: external "node:url"
var external_node_url_ = __webpack_require__(3136);
// EXTERNAL MODULE: ./scripts/generate-html-report.mjs + 1 modules
var generate_html_report = __webpack_require__(3180);
;// CONCATENATED MODULE: ./src/ir/chrome-probe.mjs
// chrome-probe.mjs — Milestone 4, sub-project PNG/SVG/PDF export.
//
// Chrome/Chromium binary discovery, mirroring parser-py-cst.js's own
// already-proven probePythonAvailable() pattern exactly — this
// codebase's established convention for "optional local tool, detect
// and degrade gracefully" (see that file's own header comment for the
// full rationale this file inherits without repeating).




let _capability = null;

// A malformed env var (e.g. AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS=oops)
// must fall back to the default, never reach spawnSync as NaN — found by
// the final whole-branch review: `Number('oops')` is NaN, and NaN as a
// spawnSync `timeout` option throws ERR_OUT_OF_RANGE synchronously.
// _tryBinary's own try/catch swallows that throw and returns null for
// EVERY candidate, so probeChromeAvailable would misreport
// `no-chrome-found` on a machine with a perfectly working Chrome install.
//
// Blank/whitespace-only is treated as unset (falls back), not as `0` —
// found by this fix's own scoped re-review: `Number('')` is `0`, and a
// naive `n >= 0` guard let an empty-but-exported env var (a blanked
// .env line, an unset-but-exported CI var) through as a real `timeout:
// 0`, which spawnSync treats as NO timeout at all — an unbounded hang
// risk inside this exact capability probe, the failure class
// parser-py-cst.js's own probePythonAvailable() is already careful
// about. An explicit `"0"` is still honored (matches this file's
// pre-fix behavior for that literal value).
//
// Must be a safe INTEGER, not merely finite — found by a second scoped
// re-review, reproduced live: `Number.isFinite(1.5)` is true, so a
// fractional env var (e.g. "1.5") passed this guard unchanged and then
// hit spawnSync's own `timeout` option, which throws ERR_OUT_OF_RANGE
// for any non-integer — the exact class of uncaught throw this whole
// function exists to prevent, just for a different malformed input
// than the original NaN case. `-0` is rejected too (Object.is check):
// it is a safe integer and `-0 >= 0`, so without the explicit check it
// would silently mean "no timeout", one character away from the "0"
// this function deliberately allows.
// Exported test-only — the outcome-based integration tests (a real
// probe/export succeeding or not) can't distinguish `timeout: 0` from
// `timeout: <default>` when the underlying command finishes quickly
// either way, so a direct table of this function's own input/output
// pairs is the only thing that actually pins the "0"-vs-default
// boundary — found by a third scoped re-review: the blank-env-var
// integration test below passed even with the round-2 blank-handling
// bug fully reintroduced, for exactly this reason.
function _validTimeoutMs(raw, fallback) {
  const s = String(raw ?? '').trim();
  if (!s) return fallback;
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < 0 || Object.is(n, -0)) return fallback;
  return n;
}
const PROBE_TIMEOUT_MS = _validTimeoutMs(process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS, 5000);

// Real, common install locations, per platform. Deliberately excludes
// AGENTIC_SECURITY_CHROME_PATH — that override is handled separately in
// probeChromeAvailable() as an authoritative, non-fallback choice (see
// the comment there for why).
//
// KNOWN-GOOD ABSOLUTE PATHS ARE TRIED FIRST, PATH-resolvable bare names
// LAST — found by the final whole-branch review, reproduced live: with
// bare names tried first, a `chrome` shell script anywhere earlier on
// PATH than the real browser is silently preferred and then executed
// with this process's own render arguments. The `--version` output
// check (`_tryBinary` below) is a functional smoke test, not a security
// gate — it cannot distinguish a real Chrome/Chromium binary from any
// script that echoes a matching string. Preferring the well-known
// install locations narrows, though does not eliminate, this exposure
// (a compromised PATH entry named exactly `chrome`/`google-chrome`/etc.
// is still tried if no absolute-path candidate exists on this machine —
// this feature already assumes local machine trust, same as every other
// "optional local tool" this codebase shells out to). The `linux` list
// below was empty in this fix's first pass — found by the scoped
// re-review to make the whole reordering a no-op on the platform CI
// images actually run on, since every Linux candidate was a bare PATH
// name. Package-manager and snap install locations are now included.
function _candidatePaths() {
  const onPath = ['google-chrome-stable', 'google-chrome', 'chromium-browser', 'chromium', 'chrome'];
  const platformPaths = {
    darwin: [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      `${process.env.HOME || ''}/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
    ],
    win32: [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      `${process.env.LOCALAPPDATA || ''}\\Google\\Chrome\\Application\\chrome.exe`,
    ],
    linux: [
      '/usr/bin/google-chrome-stable',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
      '/opt/google/chrome/chrome',
      '/snap/bin/chromium',
    ],
  };
  const platformSpecific = platformPaths[process.platform] || [];
  return [...platformSpecific, ...onPath];
}

// Tries one candidate binary. Returns {ok:true, chrome:bin} on a real,
// working Chrome/Chromium, or null on any failure (missing binary, spawn
// error, non-zero exit, unrecognized --version output) — never throws.
function _tryBinary(bin) {
  if (!bin) return null;
  // An absolute-path candidate that doesn't exist can't spawn — skip the
  // spawnSync call entirely rather than let it throw ENOENT.
  if (bin.includes('/') || bin.includes('\\')) {
    if (!external_node_fs_.existsSync(bin)) return null;
  }
  let r;
  try {
    r = external_node_child_process_.spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
  } catch { return null; }
  if (r.error || r.status !== 0) return null;
  const out = (r.stdout || r.stderr || '');
  if (!/Chrom(e|ium)/i.test(out)) return null;
  return { ok: true, chrome: bin };
}

function resetChromeProbe() { _capability = null; }

function probeChromeAvailable() {
  if (_capability) return _capability;

  // An explicit override is authoritative, not just "try this one first
  // then fall back": an operator (or CI environment) who deliberately
  // pointed AGENTIC_SECURITY_CHROME_PATH at a binary wants a failure
  // reported when that binary doesn't work — not a silent switch to
  // whatever else this process happens to auto-detect on the machine.
  const fromEnv = process.env.AGENTIC_SECURITY_CHROME_PATH;
  if (fromEnv) {
    const hit = _tryBinary(fromEnv);
    _capability = hit || { ok: false, reason: 'chrome-path-invalid' };
    return _capability;
  }

  for (const bin of _candidatePaths()) {
    const hit = _tryBinary(bin);
    if (hit) { _capability = hit; return _capability; }
  }
  _capability = { ok: false, reason: 'no-chrome-found' };
  return _capability;
}

;// CONCATENATED MODULE: ./scripts/export-image.mjs
// export-image.mjs — Milestone 4, sub-project PNG/SVG/PDF export.
//
// Builds on the already-shipped self-contained HTML report
// (generate-html-report.mjs) and a real, locally discovered Chrome
// binary's own native headless flags — empirically confirmed this
// sub-project's own scoping investigation to produce deterministic PNG
// (byte-identical across repeated runs), valid PDF, and (via DOM
// extraction) valid SVG, with zero new code needed to render anything
// and zero new npm dependency.









// A malformed env var (e.g. AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS=oops)
// must fall back to the default, never reach spawnSync as NaN — NaN as a
// spawnSync `timeout` option throws ERR_OUT_OF_RANGE synchronously, which
// none of the three export functions below catch (their try/finally only
// guards cleanup, not this construction-time computation).
//
// Blank/whitespace-only is treated as unset (falls back), not as `0` —
// found by this fix's own scoped re-review: `Number('')` is `0`, and a
// naive `n >= 0` guard let an empty-but-exported env var through as a
// real `timeout: 0`, which spawnSync treats as NO timeout at all — an
// unbounded-hang risk on a wedged Chrome. An explicit `"0"` is still
// honored (matches this file's pre-fix behavior for that literal
// value).
//
// Must be a safe INTEGER, not merely finite — found by a second scoped
// re-review, reproduced live: `Number.isFinite(1.5)` is true, so a
// fractional env var (e.g. "1.5") passed this guard unchanged and then
// hit spawnSync's own `timeout` option, which throws ERR_OUT_OF_RANGE
// for any non-integer. `-0` is rejected too (Object.is check): it is a
// safe integer and `-0 >= 0`, so it would otherwise silently mean "no
// timeout", one character away from the "0" this function deliberately
// allows. Kept identical to chrome-probe.mjs's own copy of this
// function rather than factored into a shared module — two small
// functions, not worth a new shared file for.
// Exported test-only — see chrome-probe.mjs's own copy of this
// function for why a direct input/output table, not an integration
// test, is what actually pins the "0"-vs-default boundary.
function export_image_validTimeoutMs(raw, fallback) {
  const s = String(raw ?? '').trim();
  if (!s) return fallback;
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < 0 || Object.is(n, -0)) return fallback;
  return n;
}
const RENDER_TIMEOUT_MS = export_image_validTimeoutMs(process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS, 15000);

function _writeTempHtml(graph, opts) {
  const html = (0,generate_html_report.generateHtmlReport)(graph, opts);
  const dir = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'agsec-export-'));
  const file = external_node_path_.join(dir, 'report.html');
  external_node_fs_.writeFileSync(file, html);
  return { dir, file };
}

function _hashUrl(file, opts) {
  // #view=<name> — the shell's own already-shipped hash-state mechanism
  // (frontend/src/lib/state.js's parseStateFromHash, read at mount time
  // by shell.js) — confirmed empirically this sub-project's own scoping
  // investigation to select the initial active view with zero new
  // frontend code. No `#` fragment when no view is requested (the shell
  // defaults to 'architecture' on its own).
  //
  // pathToFileURL, never hand-built string concatenation: the temp
  // directory comes from os.tmpdir(), which on some machines/CI images
  // contains a literal `#` (found live by the final whole-branch
  // review) — `file://${file}` truncates at that character, and Chrome
  // silently renders its own internal error page for the broken URL
  // instead of failing. pathToFileURL percent-encodes it correctly.
  // Also the only correct way to build a file: URL on Windows, whose
  // paths are never valid appended directly after `file://`.
  const hash = opts.view ? `#view=${encodeURIComponent(opts.view)}` : '';
  return (0,external_node_url_.pathToFileURL)(file).href + hash;
}

function _cleanup(dir) {
  try { external_node_fs_.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

// Confirmed this sub-project's own scoping investigation: exactly ONE
// real `<svg>` element exists in the whole rendered page
// (architecture-view.js's own root, class="arch-view") — a direct
// source grep confirms svgEl()/createElementNS is used nowhere else.
// Only present when the Architecture View is the active view, though
// (see _verifyRealRender below for the view-agnostic check used for
// PNG/PDF, which can capture any view).
function _extractArchSvg(dom) {
  const start = dom.indexOf('<svg class="arch-view"');
  if (start === -1) return { ok: false, reason: 'no <svg class="arch-view"> element found in the rendered page' };
  const end = dom.indexOf('</svg>', start);
  if (end === -1) return { ok: false, reason: 'found <svg class="arch-view"> but no matching </svg> close tag' };
  return { ok: true, markup: dom.slice(start, end + '</svg>'.length) };
}

// role="tablist" — shell.js's own view-switcher tab bar (frontend/src/shell.js),
// present in EVERY view (unlike the architecture-only <svg class="arch-view">
// _extractArchSvg looks for), and part of the shell chrome, not
// view-specific content. Its presence in a --dump-dom capture is this
// module's positive signal that Chrome actually rendered the real
// report and not its own internal error page (which exits 0 and still
// writes a screenshot/PDF file — found live by the final whole-branch
// review: a `#` in the temp path broke the URL, and the resulting
// correctly-dimensioned-but-wrong PNG was Chrome's own error page).
function _hasRealShellChrome(dom) {
  return dom.includes('role="tablist"');
}

function _dumpDom(chrome, url, opts) {
  const r = external_node_child_process_.spawnSync(chrome.chrome, [
    '--headless=new', '--disable-gpu',
    `--window-size=${opts.width || 1680},${opts.height || 945}`,
    '--virtual-time-budget=5000',
    '--dump-dom',
    url,
  ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 });
  if (r.error || r.status !== 0) {
    return { ok: false, reason: `chrome dump-dom failed: ${r.error?.message || r.stderr || 'unknown error'}` };
  }
  return { ok: true, dom: r.stdout };
}

// Verifies the page actually rendered the real report (not Chrome's own
// error page for a broken URL) before PNG/PDF capture is trusted. Costs
// one extra Chrome invocation per PNG/PDF export — deliberate: a
// screenshot/PDF file gives no positive signal of its own content, and
// Chrome exits 0 with a written output file for its own error page too.
function _verifyRealRender(chrome, url, opts) {
  const dumped = _dumpDom(chrome, url, opts);
  if (!dumped.ok) return dumped;
  if (!_hasRealShellChrome(dumped.dom)) {
    return { ok: false, reason: 'rendered page has no real report shell (role="tablist") — likely a broken URL or a Chrome error page' };
  }
  return { ok: true };
}

async function exportPng(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  const width = opts.width || 1680;
  const height = opts.height || 945;
  const outPng = external_node_path_.join(dir, 'out.png');
  try {
    const url = _hashUrl(file, opts);
    const verified = _verifyRealRender(chrome, url, opts);
    if (!verified.ok) return verified;
    const r = external_node_child_process_.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      `--window-size=${width},${height}`,
      '--force-device-scale-factor=1',
      '--virtual-time-budget=5000',
      `--screenshot=${outPng}`,
      url,
    ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8' });
    if (r.error || r.status !== 0 || !external_node_fs_.existsSync(outPng)) {
      return { ok: false, reason: `chrome screenshot failed: ${r.error?.message || r.stderr || 'unknown error'}` };
    }
    return { ok: true, data: external_node_fs_.readFileSync(outPng) };
  } finally {
    _cleanup(dir);
  }
}

async function exportPdf(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  const outPdf = external_node_path_.join(dir, 'out.pdf');
  try {
    const url = _hashUrl(file, opts);
    const verified = _verifyRealRender(chrome, url, opts);
    if (!verified.ok) return verified;
    const r = external_node_child_process_.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      '--virtual-time-budget=5000',
      `--print-to-pdf=${outPdf}`,
      url,
    ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8' });
    if (r.error || r.status !== 0 || !external_node_fs_.existsSync(outPdf)) {
      return { ok: false, reason: `chrome print-to-pdf failed: ${r.error?.message || r.stderr || 'unknown error'}` };
    }
    return { ok: true, data: external_node_fs_.readFileSync(outPdf) };
  } finally {
    _cleanup(dir);
  }
}

async function exportSvg(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  try {
    const url = _hashUrl(file, opts);
    const dumped = _dumpDom(chrome, url, opts);
    if (!dumped.ok) return dumped;
    const extracted = _extractArchSvg(dumped.dom);
    if (!extracted.ok) return extracted;
    // Real, standalone SVG documents need an explicit xmlns — the
    // in-page element inherits it implicitly from its HTML parent
    // document, which a standalone .svg file does not have.
    const standalone = extracted.markup.replace('<svg class="arch-view"', '<svg xmlns="http://www.w3.org/2000/svg" class="arch-view"');
    return { ok: true, data: Buffer.from(standalone, 'utf8') };
  } finally {
    _cleanup(dir);
  }
}


/***/ }),

/***/ 3180:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  generateHtmlReport: () => (/* binding */ generateHtmlReport)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: external "node:url"
var external_node_url_ = __webpack_require__(3136);
;// CONCATENATED MODULE: ./scripts/bundle-frontend.mjs
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
// module; wrap EVERY NON-ENTRY module in its own IIFE (this is what
// prevents two dependency files' same-named PRIVATE top-level bindings
// from colliding when concatenated — a real risk with naive flat
// concatenation, proven by this file's own test suite); each module's
// IIFE destructures its own imports from its dependencies' already-
// evaluated namespace objects (`const { a, b } = __NS_shared;`) and
// returns its own exports as a plain object.
//
// The ENTRY module is deliberately NOT wrapped in an IIFE: its body is
// emitted directly at the top level of the output (after its own
// destructured imports), so its top-level declarations — functions the
// caller needs to invoke directly, e.g. `bootstrap()` in a `<script>`
// tag, or (as this file's own tests require) a bare exported name called
// straight off the bundled output — become real top-level bindings
// rather than being trapped inside a closure whose return value is
// discarded. Wrapping the entry in an IIFE too (as an earlier draft of
// this algorithm did) type-checks and looks symmetrical, but it is a
// correctness bug: it makes every exported name of the entry module
// unreachable from outside the bundle, which is never what a bundle's
// caller wants. Only the entry is unwrapped — every other module is
// still fully IIFE-isolated, so the collision guarantee above is
// unaffected (there is exactly one unwrapped scope per bundle, by
// construction, since the entry is the unique DFS root and cannot be
// re-entered — a cycle back to it is rejected below as a circular
// import).




const IMPORT_RE = /import\s*\{([\s\S]*?)\}\s*from\s*['"](\.[^'"]+)['"];?/g;
const UNSUPPORTED_IMPORT_RE = /^import\s+(?!\{)/m;
const EXPORT_STAR_RE = /^export\s*\*/m;
const EXPORT_DEFAULT_RE = /^export\s+default\b/m;
// Three more real, unsupported forms — added after the final whole-branch
// review found each builds with NO error (`EXPORT_NAMED_RE` below requires
// `function`/`class`/`const`/`let`/`var` immediately after `export `, so
// `export async function` matches none of these guards OR the named-export
// extractor, and is silently dropped as neither a caught error nor a real
// export) and only fails later as a page-load SyntaxError, blanking the
// whole page with no visible error — `export async function` already
// exists in the real tree today (frontend/src/lib/api-client.js), outside
// today's bundled entry point's own reachable graph only by luck.
const EXPORT_ASYNC_RE = /^export\s+async\s+function/m;
const EXPORT_LIST_RE = /^export\s*\{/m;
const IMPORT_RENAME_RE = /\bas\b/;
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
  const src = external_node_fs_.readFileSync(absPath, 'utf8');
  if (UNSUPPORTED_IMPORT_RE.test(src) || EXPORT_STAR_RE.test(src) || EXPORT_DEFAULT_RE.test(src) || EXPORT_ASYNC_RE.test(src) || EXPORT_LIST_RE.test(src)) {
    throw new Error(`bundleFrontendModules: unsupported import/export form in ${absPath} — only named imports/exports are supported (no default/namespace/side-effect imports, no export */export default/export {}-list/export async function)`);
  }
  const imports = [];
  let m;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(src))) {
    if (IMPORT_RENAME_RE.test(m[1])) {
      throw new Error(`bundleFrontendModules: unsupported \`import { x as y }\` rename in ${absPath} — only bare named imports are supported`);
    }
    const names = m[1].split(',').map((s) => s.trim()).filter(Boolean);
    const resolved = external_node_path_.resolve(external_node_path_.dirname(absPath), m[2]);
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

function bundleFrontendModules(entryAbsPath) {
  const nsNames = new Map();
  const parsed = new Map(); // absPath -> parsed module
  const order = []; // topological, dependency-first
  const visiting = new Set();

  function visit(absPath) {
    // `visiting` (currently-on-the-DFS-stack) must be checked BEFORE
    // `parsed` (fully-resolved, safe to skip) — found by this task's own
    // review: the original ordering set `parsed` before recursing into a
    // module's own imports, so a cycle back to an ancestor hit the
    // `parsed.has()` check first and returned silently, making the
    // `visiting`-based throw below unreachable for ANY cycle. Reproduced
    // live: a real entry<->b.js cycle built successfully at bundle time
    // and only failed later, as a confusing `ReferenceError` (TDZ) when
    // the broken output was executed, instead of this function's own
    // clear build-time error.
    if (visiting.has(absPath)) {
      throw new Error(`bundleFrontendModules: circular import detected at ${absPath} — this bundler does not support cycles`);
    }
    if (parsed.has(absPath)) return;
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
    const destructures = mod.imports
      .map((imp) => `  const { ${imp.names.join(', ')} } = ${_nsName(imp.resolved, nsNames)};`)
      .join('\n');

    if (absPath === entryAbsPath) {
      // Entry: emit unwrapped at top level so its declarations become
      // real top-level bindings the caller can invoke — see the header
      // comment for why this must not be an IIFE like every other module.
      chunks.push(`${destructures}\n${mod.body}`);
      continue;
    }

    const ns = _nsName(absPath, nsNames);
    const returnObj = mod.exportNames.length ? `  return { ${mod.exportNames.join(', ')} };` : '  return {};';
    chunks.push(`const ${ns} = (function() {\n${destructures}\n${mod.body}\n${returnObj}\n})();`);
  }
  const bundled = chunks.join('\n\n');

  // Real gap found by the final whole-branch review, live-reproduced: the
  // UNSUPPORTED_IMPORT_RE/EXPORT_STAR_RE/EXPORT_DEFAULT_RE guards above
  // only cover THREE specific unsupported forms — real ES syntax this
  // bundler doesn't handle (`export async function`, `export { g };`
  // re-export lists, `import { h as hh }` renames) builds with NO error
  // and only fails later, as a page-load-time SyntaxError that silently
  // blanks the whole page (export-entry.js's own showError() never runs,
  // since the entire inline <script> fails to parse before any of its
  // code executes) — directly contradicting this file's own documented
  // "throws a clear error on anything else" promise. `export async
  // function` already exists in the real tree today
  // (frontend/src/lib/api-client.js) — outside today's bundled entry
  // point's own reachable graph only by luck. Rather than enumerating
  // every unsupported form by name (the exact approach that missed these
  // three), validate the FINAL bundle is syntactically valid JS before
  // returning it — this converts any parse failure, including forms not
  // yet imagined, into a clear build-time error. `new Function` compiles
  // without executing (measured ~1ms on the real ~131KB bundle — cheap).
  try {
    // eslint-disable-next-line no-new-func
    new Function(bundled);
  } catch (e) {
    throw new Error(`bundleFrontendModules: the assembled bundle is not valid JavaScript (${e.message}) — one of the ${order.length} modules likely uses an ES form this bundler doesn't support (only named imports/exports, no async/generator export shorthand ambiguity, no \`export { x };\` lists, no \`import { x as y }\` renames)`);
  }
  return bundled;
}

// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(859);
;// CONCATENATED MODULE: ./scripts/generate-html-report.mjs
// generate-html-report.mjs — Milestone 4, sub-project Self-contained
// HTML report. Assembles ONE offline-safe HTML document: inline CSS,
// one bundled inline <script> (Task 1's bundler over Task 2's
// export-entry.js), and the graph embedded via exportGraphJSON
// (redacted by default) as a global the bundled script reads.







const HERE = external_node_path_.dirname((0,external_node_url_.fileURLToPath)(import.meta.url));
const FRONTEND_ROOT = external_node_path_.resolve(HERE, '../../frontend');
const STYLES_DIR = external_node_path_.join(FRONTEND_ROOT, 'styles');
const ENTRY_PATH = external_node_path_.join(FRONTEND_ROOT, 'src', 'export-entry.js');

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
  const onDisk = new Set(external_node_fs_.readdirSync(STYLES_DIR).filter((f) => f.endsWith('.css')));
  const missing = CSS_LOAD_ORDER.filter((f) => !onDisk.has(f));
  if (missing.length) throw new Error(`generate-html-report: CSS_LOAD_ORDER names files not found in ${STYLES_DIR}: ${missing.join(', ')} — frontend/index.html's own <link> list may have changed; re-sync CSS_LOAD_ORDER with it`);
  const extra = [...onDisk].filter((f) => !CSS_LOAD_ORDER.includes(f));
  if (extra.length) throw new Error(`generate-html-report: real CSS files not in CSS_LOAD_ORDER: ${extra.join(', ')} — a new stylesheet was added to frontend/styles/ without updating this list's load order`);
  return CSS_LOAD_ORDER.map((f) => external_node_fs_.readFileSync(external_node_path_.join(STYLES_DIR, f), 'utf8')).join('\n');
}

function generateHtmlReport(graph, opts = {}) {
  const exported = (0,export_json.exportGraphJSON)(graph, opts);
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


/***/ })

};
