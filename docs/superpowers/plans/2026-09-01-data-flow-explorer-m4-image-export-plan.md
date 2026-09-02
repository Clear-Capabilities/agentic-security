# Milestone 4, sub-project PNG/SVG/PDF export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deterministic PNG, PDF, and SVG export of the Data Flow Explorer,
built on the already-shipped self-contained HTML report
(`scanner/scripts/generate-html-report.mjs`) and a real, already-installed
Chrome/Chromium binary's own native headless CLI flags — no new npm
dependency, no hand-written SVG serializer.

**Architecture:** Task 1 adds Chrome-binary discovery
(`scanner/src/ir/chrome-probe.mjs`), mirroring
`scanner/src/ir/parser-py-cst.js`'s own already-proven
`probePythonAvailable()` pattern exactly (a cached capability probe,
graceful `{ok:false, reason}` degradation, never throws, an env-var
override) — this codebase's own established convention for "optional
local tool, detect and degrade" rather than a new pattern. Task 2 adds
the three export functions, each: generate the HTML report (already
shipped), write it to a real temp file, invoke the discovered Chrome
binary via `node:child_process`, read back the produced artifact, clean
up. Task 3 adds the real-Chrome acceptance tests (mirroring the HTML
report sub-project's own real-Chrome-headless discipline, not just
DOM-shim tests) and wires everything in.

**Tech Stack:** Node ESM, `node:child_process`/`node:fs`/`node:os`/
`node:path` only. No new npm dependency.

**Spec:** `2026-09-01-data-flow-explorer-m4-image-export-scoping.md` (this
sub-project's own scoping doc — every claim about Chrome's real headless
flag behavior, determinism, and the single-`<svg>`-element structure was
empirically confirmed there via a real, locally-invoked Chrome binary,
including a self-correction of an initial false lead about needing SVG
disambiguation) and `2026-09-01-data-flow-explorer-m4-scoping.md` (M4
top-level doc). PRD §17.5, AC-23.

## Global Constraints

- **No new npm dependency.** Chrome itself is a real, pre-existing local
  binary the OPERATOR already has (or doesn't) — never bundled, never
  installed by this project. A machine without Chrome/Chromium cannot use
  this export path; every export function must degrade to a clear,
  actionable error (naming what's missing and where to get it), never a
  crash or a silent empty/corrupt file.
- **No network request of any kind.** Chrome is invoked purely locally
  against a `file://` path this process itself wrote; nothing is
  downloaded, nothing is uploaded.
- **Determinism**: repeated exports of the SAME graph, on the SAME
  machine, must produce identical bytes (proven for PNG in the scoping
  doc's own investigation — Task 3's own tests re-prove it against the
  shipped code, not just the investigation's throwaway script).
- **Confidential-by-default**: every export goes through
  `generateHtmlReport` (already redacted by default) — never bypass it to
  render an unredacted graph.
- **Real-fixture grounding**: every test assertion about rendered content
  is checked against the real flagship fixture's own real data, not
  guessed.

---

## Task 1: Chrome binary discovery (`chrome-probe.mjs`)

**Files:**
- Create: `scanner/src/ir/chrome-probe.mjs`
- Test: `scanner/test/chrome-probe.test.js`

**Interfaces:**
- Consumes: nothing from this codebase — pure `node:child_process`/
  `node:fs`/`process.platform` probing.
- Produces: `probeChromeAvailable() -> {ok:true, chrome:'<path>'} |
  {ok:false, reason}` (cached per-process, mirroring
  `probePythonAvailable`'s exact contract), `resetChromeProbe()` (for
  tests — mirrors `resetPythonParserDegradation`'s own test-support
  role).

- [ ] **Step 1: Write the failing tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probeChromeAvailable, resetChromeProbe } from '../src/ir/chrome-probe.mjs';

test('probeChromeAvailable: finds a real Chrome on this machine (environment-dependent, skip if absent)', () => {
  resetChromeProbe();
  const r = probeChromeAvailable();
  // This test runs on the maintainer's own machine, which is confirmed
  // (this session) to have a real Chrome install — assert the REAL
  // contract shape either way rather than assuming ok:true, since CI
  // environments may genuinely lack Chrome.
  if (r.ok) {
    assert.equal(typeof r.chrome, 'string');
    assert.ok(r.chrome.length > 0);
  } else {
    assert.equal(typeof r.reason, 'string');
  }
});

test('probeChromeAvailable: result is cached — a second call does not re-probe', () => {
  resetChromeProbe();
  const a = probeChromeAvailable();
  const b = probeChromeAvailable();
  assert.equal(a, b, 'same object reference — proves no re-probe happened');
});

test('probeChromeAvailable: AGENTIC_SECURITY_CHROME_PATH override is honored when it points at a real, working binary', () => {
  resetChromeProbe();
  const real = probeChromeAvailable();
  if (!real.ok) return; // nothing real to point the override at on this machine
  resetChromeProbe();
  const prev = process.env.AGENTIC_SECURITY_CHROME_PATH;
  process.env.AGENTIC_SECURITY_CHROME_PATH = real.chrome;
  try {
    const r = probeChromeAvailable();
    assert.equal(r.ok, true);
    assert.equal(r.chrome, real.chrome);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PATH;
    else process.env.AGENTIC_SECURITY_CHROME_PATH = prev;
    resetChromeProbe();
  }
});

test('probeChromeAvailable: a bogus AGENTIC_SECURITY_CHROME_PATH degrades cleanly, never throws', () => {
  resetChromeProbe();
  const prev = process.env.AGENTIC_SECURITY_CHROME_PATH;
  process.env.AGENTIC_SECURITY_CHROME_PATH = '/definitely/not/a/real/binary/anywhere';
  try {
    const r = probeChromeAvailable();
    assert.equal(r.ok, false);
    assert.equal(typeof r.reason, 'string');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PATH;
    else process.env.AGENTIC_SECURITY_CHROME_PATH = prev;
    resetChromeProbe();
  }
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/chrome-probe.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `chrome-probe.mjs`**

Mirror `scanner/src/ir/parser-py-cst.js`'s `probePythonAvailable`
(lines ~40-93 as of this plan's writing — re-locate before copying the
pattern, don't assume the line numbers still match) exactly in shape:
cached `_capability`, a candidate list tried in order, `cp.spawnSync`
with a timeout, graceful `{ok:false, reason}` on every failure path,
`--version`-style capability check.

```js
// chrome-probe.mjs — Milestone 4, sub-project PNG/SVG/PDF export.
//
// Chrome/Chromium binary discovery, mirroring parser-py-cst.js's own
// already-proven probePythonAvailable() pattern exactly — this
// codebase's established convention for "optional local tool, detect
// and degrade gracefully" (see that file's own header comment for the
// full rationale this file inherits without repeating).

import * as cp from 'node:child_process';
import * as fs from 'node:fs';

let _capability = null;

const PROBE_TIMEOUT_MS = Number(process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS || 5000);

// Real, common install locations, per platform — checked only if the
// binary isn't already resolvable on PATH (the common case on Linux CI
// images and most dev machines with Chrome installed via a package
// manager). macOS's own Chrome.app does NOT put its binary on PATH by
// default, hence the explicit path search there.
function _candidatePaths() {
  const fromEnv = process.env.AGENTIC_SECURITY_CHROME_PATH;
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
    linux: [],
  };
  const platformSpecific = platformPaths[process.platform] || [];
  return [...(fromEnv ? [fromEnv] : []), ...onPath, ...platformSpecific];
}

export function resetChromeProbe() { _capability = null; }

export function probeChromeAvailable() {
  if (_capability) return _capability;
  for (const bin of _candidatePaths()) {
    if (!bin) continue;
    // An absolute-path candidate that doesn't exist can't spawn — skip
    // the spawnSync call entirely rather than let it throw ENOENT.
    if (bin.includes('/') || bin.includes('\\')) {
      if (!fs.existsSync(bin)) continue;
    }
    let r;
    try {
      r = cp.spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: PROBE_TIMEOUT_MS });
    } catch { continue; }
    if (r.error || r.status !== 0) continue;
    const out = (r.stdout || r.stderr || '');
    if (!/Chrom(e|ium)/i.test(out)) continue;
    _capability = { ok: true, chrome: bin };
    return _capability;
  }
  _capability = { ok: false, reason: 'no-chrome-found' };
  return _capability;
}
```

**Re-verification note:** this is a first cut at real-world install
paths, not exhaustive — re-check against the implementer's own machine
and, if available, a Linux CI image, before considering this task done.
The `AGENTIC_SECURITY_CHROME_PATH` env override exists specifically so a
CI environment or an operator with a nonstandard install can always work
around an incomplete candidate list.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/chrome-probe.test.js` (from `scanner/`)
Expected: PASS (the environment-dependent test passes either branch, but
on this session's own machine, which is confirmed to have Chrome
installed, it should take the `ok:true` branch — verify it actually
does, don't just accept a pass via the `else` branch by accident).

- [ ] **Step 5: Commit**

```bash
git add scanner/src/ir/chrome-probe.mjs scanner/test/chrome-probe.test.js
git commit -m "feat(ir): add chrome-probe.mjs, mirroring parser-py-cst.js's own capability-probe pattern"
```

---

## Task 2: PNG/SVG/PDF export functions

**Files:**
- Create: `scanner/scripts/export-image.mjs`
- Test: `scanner/test/export-image.test.js`

**Interfaces:**
- Consumes: `probeChromeAvailable` (Task 1), `generateHtmlReport`
  (already shipped, `scanner/src/lineage/../../scripts/generate-html-report.mjs`
  — confirm the real relative import path from this new file's own
  location before writing the import statement).
- Produces: `exportPng(graph, opts)`, `exportPdf(graph, opts)`,
  `exportSvg(graph, opts)`, each `-> Promise<{ok:true, data:Buffer} |
  {ok:false, reason}`. `opts` forwards to `generateHtmlReport` (so
  `redact`/`filter` both work) plus export-specific options below.

- [ ] **Step 1: Write the failing tests**

Ground every rendered-content assertion in the real flagship fixture.
Use `node:os`'s `tmpdir()` for scratch files, clean up in a `finally`.

```js
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
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/export-image.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `export-image.mjs`**

```js
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
import * as crypto from 'node:crypto';
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
```

**Re-verification note:** the `readUInt32BE(16)`/`readUInt32BE(20)` PNG
IHDR-offset trick in the test above assumes the standard PNG signature
layout (8-byte signature + 4-byte length + 4-byte "IHDR" + 4-byte width +
4-byte height) — real and stable per the PNG spec, but confirm against
the actual bytes Chrome's `--screenshot` produces before trusting it
blindly (a quick `Buffer` inspection in a scratch script, not guessed).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/export-image.test.js` (from `scanner/`)
Expected: PASS on a machine with Chrome (this session's own machine
qualifies — confirm the Chrome-dependent tests actually RAN, not
skipped, by checking the real test count).

- [ ] **Step 5: Commit**

```bash
git add scanner/scripts/export-image.mjs scanner/test/export-image.test.js
git commit -m "feat(scripts): add export-image.mjs — PNG/PDF/SVG export via real Chrome headless"
```

---

## Task 3: Wiring, docs, full gate

**Files:**
- Modify: `scanner/package.json` (`test:lineage` script)
- Modify: `scanner/src/lineage/CLAUDE.md` (Milestone 4 table)
- Modify: `scanner/src/ir/CLAUDE.md` (one new row for `chrome-probe.mjs`,
  matching the existing per-parser table's own format)

- [ ] **Step 1: Wire the two new test files**

Add `test/chrome-probe.test.js` and `test/export-image.test.js` to
`scanner/package.json`'s `test:lineage` script (confirmed this session to
be an explicit space-separated file list, not a glob — re-confirm the
current exact string before editing).

- [ ] **Step 2: Document in `scanner/src/lineage/CLAUDE.md`**

Add two rows to the existing "## Milestone 4 (JSON/CSV export)" table
(rename its own heading to cover this sub-project too, or add a sibling
table — implementer's judgment, matching the file's own established
density) for `chrome-probe.mjs`/`export-image.mjs`, mirroring the
existing `redact-graph.js`/`export-json.js`/`export-csv.js` rows' own
level of detail.

- [ ] **Step 3: One dedicated real-Chrome acceptance check, beyond the automated suite**

Matching the HTML report sub-project's own established discipline
(`2026-09-01-data-flow-explorer-m4-html-report-plan.md`'s own Task 3
Step 5): generate a real PNG, PDF, and SVG from the real flagship
fixture via the shipped functions, and independently confirm each with a
real, non-Node tool — `file <path>.png`/`file <path>.pdf` for format
confirmation, and open the `.svg` file's own text to confirm it's
well-formed XML with real visible content (not just that the Node test
suite's own assertions passed, which could share a blind spot with the
implementation).

- [ ] **Step 4: Full gate**

Run: `npm test` (from `scanner/`)
Expected: PASS, exit code 0. Capture and report the real exit code.

- [ ] **Step 5: Commit**

```bash
git add scanner/package.json scanner/src/lineage/CLAUDE.md scanner/src/ir/CLAUDE.md
git commit -m "docs(dataflow): wire and document M4 PNG/SVG/PDF export"
```

---

## Explicitly deferred (not this plan's job)

- CLI/slash-command wiring — sub-project #5.
- Multi-page PDF (currently single-page, whatever Chrome's own default
  print layout produces) and any `@media print` styling — real,
  disclosed future polish, not attempted.
- DPIA/RoPA embedding — depends on sub-project #6, not started.
- Capturing MULTIPLE views into one combined export artifact (today: one
  `view` option per call, one artifact per call) — real, disclosed,
  deferred scope.
