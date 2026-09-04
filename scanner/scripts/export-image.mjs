// export-image.mjs — Milestone 4, sub-project PNG/SVG/PDF export.
//
// Builds on the already-shipped self-contained HTML report
// (generate-html-report.mjs) and a real, locally discovered Chrome
// binary's own native headless flags — empirically confirmed this
// sub-project's own scoping investigation to produce deterministic PNG
// (byte-identical across repeated runs), valid PDF, and (via DOM
// extraction) valid SVG, with zero new code needed to render anything
// and zero new npm dependency.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { generateHtmlReport } from './generate-html-report.mjs';
import { probeChromeAvailable } from '../src/ir/chrome-probe.mjs';

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
export function _validTimeoutMs(raw, fallback) {
  const s = String(raw ?? '').trim();
  if (!s) return fallback;
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < 0 || Object.is(n, -0)) return fallback;
  return n;
}
// 15000 (the original default) left no headroom: the v0.147.0 release run
// took 7983ms for this same render on a good draw of the CI runner, and the
// v0.147.1 run timed out at ~15000ms on a slower draw — a 2x runner-speed
// swing entirely within normal GitHub Actions variance, not a regression.
// 30000 gives ~4x headroom over the observed good-case time.
const RENDER_TIMEOUT_MS = _validTimeoutMs(process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS, 30000);

function _writeTempHtml(graph, opts) {
  const html = generateHtmlReport(graph, opts);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-export-'));
  const file = path.join(dir, 'report.html');
  fs.writeFileSync(file, html);
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
  return pathToFileURL(file).href + hash;
}

function _cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
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
  const r = cp.spawnSync(chrome.chrome, [
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

export async function exportPng(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  const width = opts.width || 1680;
  const height = opts.height || 945;
  const outPng = path.join(dir, 'out.png');
  try {
    const url = _hashUrl(file, opts);
    const verified = _verifyRealRender(chrome, url, opts);
    if (!verified.ok) return verified;
    const r = cp.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      `--window-size=${width},${height}`,
      '--force-device-scale-factor=1',
      '--virtual-time-budget=5000',
      `--screenshot=${outPng}`,
      url,
    ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8' });
    if (r.error || r.status !== 0 || !fs.existsSync(outPng)) {
      return { ok: false, reason: `chrome screenshot failed: ${r.error?.message || r.stderr || 'unknown error'}` };
    }
    return { ok: true, data: fs.readFileSync(outPng) };
  } finally {
    _cleanup(dir);
  }
}

export async function exportPdf(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  const outPdf = path.join(dir, 'out.pdf');
  try {
    const url = _hashUrl(file, opts);
    const verified = _verifyRealRender(chrome, url, opts);
    if (!verified.ok) return verified;
    const r = cp.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      '--virtual-time-budget=5000',
      `--print-to-pdf=${outPdf}`,
      url,
    ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8' });
    if (r.error || r.status !== 0 || !fs.existsSync(outPdf)) {
      return { ok: false, reason: `chrome print-to-pdf failed: ${r.error?.message || r.stderr || 'unknown error'}` };
    }
    return { ok: true, data: fs.readFileSync(outPdf) };
  } finally {
    _cleanup(dir);
  }
}

export async function exportSvg(graph, opts = {}) {
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
