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
import { generateHtmlReport } from './generate-html-report.mjs';
import { probeChromeAvailable } from '../src/ir/chrome-probe.mjs';

const RENDER_TIMEOUT_MS = Number(process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS || 15000);

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
  const hash = opts.view ? `#view=${encodeURIComponent(opts.view)}` : '';
  return `file://${file}${hash}`;
}

function _cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

export async function exportPng(graph, opts = {}) {
  const chrome = probeChromeAvailable();
  if (!chrome.ok) return { ok: false, reason: `chrome not available: ${chrome.reason}` };
  const { dir, file } = _writeTempHtml(graph, opts);
  const width = opts.width || 1680;
  const height = opts.height || 945;
  const outPng = path.join(dir, 'out.png');
  try {
    const r = cp.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      `--window-size=${width},${height}`,
      '--force-device-scale-factor=1',
      '--virtual-time-budget=5000',
      `--screenshot=${outPng}`,
      _hashUrl(file, opts),
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
    const r = cp.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      '--virtual-time-budget=5000',
      `--print-to-pdf=${outPdf}`,
      _hashUrl(file, opts),
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
    const r = cp.spawnSync(chrome.chrome, [
      '--headless=new', '--disable-gpu',
      `--window-size=${opts.width || 1680},${opts.height || 945}`,
      '--virtual-time-budget=5000',
      '--dump-dom',
      _hashUrl(file, opts),
    ], { timeout: RENDER_TIMEOUT_MS, encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 });
    if (r.error || r.status !== 0) {
      return { ok: false, reason: `chrome dump-dom failed: ${r.error?.message || r.stderr || 'unknown error'}` };
    }
    const dom = r.stdout;
    // Confirmed this sub-project's own scoping investigation: exactly
    // ONE real `<svg>` element exists in the whole rendered page
    // (architecture-view.js's own root, class="arch-view") — a direct
    // source grep confirms svgEl()/createElementNS is used nowhere
    // else. Find its start, then its OWN matching close tag (the
    // element has no nested `<svg>` children, so a plain string search
    // for the first `</svg>` after the start is correct — re-verify
    // this assumption is still true before trusting it if
    // architecture-view.js's own SVG structure ever changes).
    const start = dom.indexOf('<svg class="arch-view"');
    if (start === -1) return { ok: false, reason: 'no <svg class="arch-view"> element found in the rendered page' };
    const end = dom.indexOf('</svg>', start);
    if (end === -1) return { ok: false, reason: 'found <svg class="arch-view"> but no matching </svg> close tag' };
    const svgMarkup = dom.slice(start, end + '</svg>'.length);
    // Real, standalone SVG documents need an explicit xmlns — the
    // in-page element inherits it implicitly from its HTML parent
    // document, which a standalone .svg file does not have.
    const standalone = svgMarkup.replace('<svg class="arch-view"', '<svg xmlns="http://www.w3.org/2000/svg" class="arch-view"');
    return { ok: true, data: Buffer.from(standalone, 'utf8') };
  } finally {
    _cleanup(dir);
  }
}
