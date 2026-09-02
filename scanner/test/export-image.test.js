import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportPng, exportPdf, exportSvg, _validTimeoutMs } from '../scripts/export-image.mjs';
import { probeChromeAvailable } from '../src/ir/chrome-probe.mjs';

test('_validTimeoutMs: direct input/output table pinning the 0-vs-default boundary', () => {
  // Found by a third scoped re-review: the outcome-based itChrome tests
  // below (exporting with a malformed env var) can't distinguish
  // `timeout: 0` from `timeout: <default>` when the real render
  // finishes quickly either way. A direct table of this function's own
  // input/output pairs is what actually pins every boundary all three
  // rounds fixed. Not itChrome-gated — no Chrome invocation involved.
  const DEFAULT = 15000;
  const cases = [
    [undefined, DEFAULT], [null, DEFAULT], ['', DEFAULT], ['   ', DEFAULT], ['\t\n ', DEFAULT],
    ['0', 0], ['00', 0], [' 0 ', 0],
    ['-0', DEFAULT],
    ['-1', DEFAULT], ['-1.5', DEFAULT],
    ['oops', DEFAULT], ['NaN', DEFAULT], ['Infinity', DEFAULT], ['-Infinity', DEFAULT],
    ['1.5', DEFAULT], ['0.5', DEFAULT], ['1e-3', DEFAULT],
    ['1e400', DEFAULT], [String(Number.MAX_SAFE_INTEGER + 1), DEFAULT],
    ['1500', 1500], [' 250 ', 250], ['1e3', 1000],
  ];
  for (const [input, expected] of cases) {
    assert.equal(_validTimeoutMs(input, DEFAULT), expected, `input ${JSON.stringify(input)}`);
  }
});

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.resolve(__dirname, '../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

// Every test in this file needs a real Chrome — skip cleanly (not fail)
// when this environment doesn't have one, matching the probe's own
// contract. This session's own machine IS confirmed to have Chrome; a
// CI image without one should see honest skips, not false failures.
const chrome = probeChromeAvailable();
const itChrome = chrome.ok ? test : test.skip;

itChrome('exportPng: produces a real PNG at the requested dimensions', async () => {
  const r = await exportPng(flagship, { width: 1680, height: 945 });
  assert.equal(r.ok, true);
  // PNG magic bytes + IHDR width/height (big-endian u32 at fixed offsets)
  // — confirms real dimensions without needing an image-decoding library.
  assert.equal(r.data.readUInt32BE(16), 1680);
  assert.equal(r.data.readUInt32BE(20), 945);
});

itChrome('exportPng: is deterministic — same graph in twice, byte-identical output', async () => {
  const a = await exportPng(flagship, { width: 1680, height: 945 });
  const b = await exportPng(flagship, { width: 1680, height: 945 });
  assert.ok(a.data.equals(b.data));
});

itChrome('exportPng: honors the view option to capture a non-default view', async () => {
  const arch = await exportPng(flagship, { width: 1680, height: 945, view: 'architecture' });
  const privacy = await exportPng(flagship, { width: 1680, height: 945, view: 'privacy' });
  assert.equal(arch.ok, true);
  assert.equal(privacy.ok, true);
  assert.ok(!arch.data.equals(privacy.data), 'different views must render visibly different content');
});

itChrome('exportPdf: produces a real, valid PDF', async () => {
  const r = await exportPdf(flagship);
  assert.equal(r.ok, true);
  assert.equal(r.data.slice(0, 5).toString('utf8'), '%PDF-');
});

itChrome('exportSvg: produces a real, valid SVG containing real flagship content', async () => {
  const r = await exportSvg(flagship);
  assert.equal(r.ok, true);
  const svgText = r.data.toString('utf8');
  assert.match(svgText, /^<svg[\s>]/);
  assert.match(svgText, /<\/svg>\s*$/);
  assert.match(svgText, /class="arch-view"/);
  // Real content, not an empty shell — ground against the real fixture's
  // own known node label.
  assert.match(svgText, /Payments Service/);
});

itChrome('exportPng: a temp dir containing "#" does not silently render Chrome\'s own error page', async () => {
  // Found live by the final whole-branch review: `file://${file}${hash}`
  // string concatenation truncates at a literal `#` in the temp path
  // (real on some machines/CI images whose TMPDIR contains one), and
  // Chrome renders its own internal error page for the broken URL —
  // exiting 0 and writing a correctly-dimensioned-but-wrong PNG, which
  // the old code returned as {ok:true}. pathToFileURL percent-encodes
  // the `#` correctly; _verifyRealRender is the second line of defense
  // if this ever regresses.
  //
  // ok:true + correct dimensions alone do NOT prove this — found by
  // this fix's own scoped re-review: Chrome's own error page renders at
  // the exact requested --window-size too, so a reverted _hashUrl with
  // _verifyRealRender also reverted still satisfies those two
  // assertions on a 19KB screenshot of "ERR_FILE_NOT_FOUND". Also
  // export the SVG in the same broken-path environment and assert real
  // rendered CONTENT (matching the flagship-content assertion in the
  // exportSvg test above) — exportSvg shares the same _hashUrl and its
  // own _extractArchSvg fails closed on Chrome's error DOM, so this
  // genuinely fails if the URL-truncation bug is reintroduced.
  const hashDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-hash-#-'));
  const prevTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = hashDir;
  try {
    const r = await exportPng(flagship, { width: 1680, height: 945 });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.data.readUInt32BE(16), 1680);
    assert.equal(r.data.readUInt32BE(20), 945);

    const svg = await exportSvg(flagship);
    assert.equal(svg.ok, true, svg.reason);
    assert.match(svg.data.toString('utf8'), /Payments Service/);
  } finally {
    if (prevTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = prevTmpdir;
    fs.rmSync(hashDir, { recursive: true, force: true });
  }
});

// Shared by every malformed-timeout-env-var case below. A fresh module
// instance (cache-busted query string) is required because the timeout
// is computed once, at module load.
async function _assertMalformedRenderTimeoutDegradesToDefault(envValue) {
  const prev = process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS;
  process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS = envValue;
  try {
    const mod = await import(`../scripts/export-image.mjs?bustcache=${Date.now()}-${Math.random()}`);
    const r = await mod.exportPng(flagship, { width: 1680, height: 945 });
    assert.equal(r.ok, true, r.reason);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS;
    else process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS = prev;
  }
}

itChrome('exportPng: a malformed (non-numeric) AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS degrades to the default, never throws', async () => {
  // Number('oops') is NaN, and NaN as spawnSync's `timeout` option
  // throws ERR_OUT_OF_RANGE synchronously.
  await _assertMalformedRenderTimeoutDegradesToDefault('oops');
});

itChrome('exportPng: a blank AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS degrades to the default, not to a real 0 (no timeout)', async () => {
  // Number('') is 0, and a naive `n >= 0` guard let an empty-but-exported
  // env var through as a real `timeout: 0` — which spawnSync treats as
  // NO timeout at all, an unbounded-hang risk — found by a scoped
  // re-review of this file's first attempt at this guard.
  await _assertMalformedRenderTimeoutDegradesToDefault('');
});

itChrome('exportPng: a fractional AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS degrades to the default, never throws', async () => {
  // Number.isFinite(1.5) is true, so a naive finite-number guard passed
  // a fractional value straight through to spawnSync's `timeout` option,
  // which requires a safe INTEGER and throws ERR_OUT_OF_RANGE for any
  // non-integer — found live by a second scoped re-review, reproducing
  // the exact original NaN-throw symptom for a different malformed
  // input.
  await _assertMalformedRenderTimeoutDegradesToDefault('1.5');
});

test('exportPng: a clear, non-throwing error when Chrome is genuinely unavailable', async () => {
  // Simulate unavailability via the probe's own override mechanism
  // rather than assuming this machine lacks Chrome (it doesn't) —
  // import resetChromeProbe and a bogus AGENTIC_SECURITY_CHROME_PATH,
  // matching chrome-probe.test.js's own pattern for this exact case.
  const { resetChromeProbe } = await import('../src/ir/chrome-probe.mjs');
  const prev = process.env.AGENTIC_SECURITY_CHROME_PATH;
  process.env.AGENTIC_SECURITY_CHROME_PATH = '/definitely/not/a/real/binary/anywhere';
  resetChromeProbe();
  try {
    const r = await exportPng(flagship, {});
    assert.equal(r.ok, false);
    assert.match(r.reason, /chrome/i);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PATH;
    else process.env.AGENTIC_SECURITY_CHROME_PATH = prev;
    resetChromeProbe();
  }
});
