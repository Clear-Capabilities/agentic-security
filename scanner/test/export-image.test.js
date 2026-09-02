import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportPng, exportPdf, exportSvg } from '../scripts/export-image.mjs';
import { probeChromeAvailable } from '../src/ir/chrome-probe.mjs';

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
  // if this ever regresses (it would see no real report DOM and fail
  // clearly instead of silently succeeding).
  const hashDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-hash-#-'));
  const prevTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = hashDir;
  try {
    const r = await exportPng(flagship, { width: 1680, height: 945 });
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.data.readUInt32BE(16), 1680);
    assert.equal(r.data.readUInt32BE(20), 945);
  } finally {
    if (prevTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = prevTmpdir;
    fs.rmSync(hashDir, { recursive: true, force: true });
  }
});

itChrome('exportPng: a malformed AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS degrades to the default, never throws', async () => {
  // Number('oops') is NaN, and NaN as spawnSync's `timeout` option
  // throws ERR_OUT_OF_RANGE synchronously — a fresh module instance
  // (cache-busted query string) is required because the timeout is
  // computed once, at module load.
  const prev = process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS;
  process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS = 'oops';
  try {
    const mod = await import(`../scripts/export-image.mjs?bustcache=${Date.now()}-${Math.random()}`);
    const r = await mod.exportPng(flagship, { width: 1680, height: 945 });
    assert.equal(r.ok, true, r.reason);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS;
    else process.env.AGENTIC_SECURITY_CHROME_RENDER_TIMEOUT_MS = prev;
  }
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
