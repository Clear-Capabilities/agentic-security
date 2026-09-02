# Milestone 4, sub-project #5 (CLI + Claude slash commands) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `agentic-security dataflow export` CLI subcommand that wires
the six already-shipped M4 export/report functions (PNG/PDF/SVG/JSON/
CSV/HTML) into one consistent command, plus a `commands/dataflow.md` slash
dispatcher exposing it to Claude Code.

**Architecture:** A new `cmdDataflowExport(args)` function in
`scanner/bin/agentic-security.js`, following `cmdExplore`'s exact
established shape (load the signed lineage graph via `loadSignedGraph`,
fail loud and early with one of its four messages, never proceed past a
failure). Dispatches to one of the six export functions by `--format`,
reconciling their two different failure conventions (async `{ok,reason}`
for images vs. sync-throwing for JSON/CSV/HTML) into one exit-code
contract, then writes the result to `--output <path>`.

**Tech Stack:** Node ≥ 24, no new dependency (this sub-project only calls
already-shipped functions).

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-cli-slash-scoping.md`
(the scoping doc — read it first; the rulings there, especially the
`explore`-vs-`visualize` naming decision, the `--class` deferral, and the
`--size` convenience flag, are binding on this plan).

## Global Constraints

- No new npm dependency (repo-wide convention; re-affirmed by every prior
  M4 sub-project this session).
- ESM throughout `scanner/src/`; `scanner/bin/agentic-security.js` is also
  ESM (confirmed: it uses `import`, not `require`).
- After any change to `scanner/bin/` or `scanner/src/`, `npm run build`
  must be re-run before the bundle (`dist/agentic-security.mjs`) reflects
  it — required before this sub-project's own final full-gate run, since
  `npm run smoke` and the bundle-vs-sidecar pre-push check both exercise
  the built bundle, not `bin/` directly.
- New `--format svg` + `--view <not architecture>` MUST be rejected with a
  clear CLI-level error before any Chrome invocation (spec Decision, "Real
  gaps" item 1's SVG constraint) — never let Chrome's own dump-failure
  reason leak through raw.
- `--no-redact` MUST be honored for `json`/`html` and MUST print an
  explicit warning (not silently do nothing) for `csv`, since
  `exportFlowsCSV` has no redaction parameter at all (spec, "What already
  exists" bullet 3).
- Exit codes: `0` success (file written). `1` graph-load failure
  (`loadSignedGraph`'s four reasons, message passed through verbatim,
  exactly matching `cmdExplore`'s own contract at
  `scanner/bin/agentic-security.js:3025-3028`). `2` export-stage failure
  (bad flags, unsupported format/view combination, Chrome unavailable, or
  a caught throw from a sync exporter).
- The new `dataflow` verb MUST NOT collide with the existing bare
  `export` subcommand (`cmdExport`, `scanner/bin/agentic-security.js:2003`,
  an unrelated feature — copies `.agentic-security/` artifacts for
  migration/legal-preservation).

---

### Task 1: `cmdDataflowExport` CLI command + USAGE entries + dispatch wiring

**Files:**
- Modify: `scanner/bin/agentic-security.js` (add the new function near
  `cmdExplore`, at the end of that function around line 3076; add a
  `case 'dataflow':` dispatch arm in `main()`'s switch, around line 3149
  right after `case 'explore':`; add USAGE entries, see Step 3 below)
- Test: `scanner/test/server/cmd-dataflow-export.test.js`

**Interfaces:**
- Consumes: `loadSignedGraph(scanRoot)` from `scanner/src/server/graph-loader.js`
  (already shipped — returns `{ok:false, reason, message}` or
  `{ok:true, graph}`); `exportPng`/`exportPdf`/`exportSvg` from
  `scanner/scripts/export-image.mjs` (async, `{ok:true,data:Buffer}` or
  `{ok:false,reason}`); `exportGraphJSON`/`computeGraphDigest` from
  `scanner/src/lineage/export-json.js` (sync, can throw); `exportFlowsCSV`
  from `scanner/src/lineage/export-csv.js` (sync, `graph` only, no opts,
  can throw); `generateHtmlReport` from `scanner/scripts/generate-html-report.mjs`
  (sync, can throw).
- Produces: `cmdDataflowExport(args)` — an `async function` returning a
  `Promise<number>` exit code, matching every other `cmdX(args)` in this
  file. Later tasks (the slash dispatcher) only need to know the CLI
  invocation shape (`agentic-security dataflow export [path] --format
  <fmt> --output <path> [--view <name>] [--size standard|2x] [--width <n>]
  [--height <n>] [--no-redact] [--filter <path>]`) and the three exit
  codes (0/1/2) — not this function's internals.

- [ ] **Step 1: Write the failing e2e tests**

Create `scanner/test/server/cmd-dataflow-export.test.js`:

```js
// End-to-end tests of `agentic-security dataflow export` as a real CLI
// subcommand — spawns the real bin/agentic-security.js, mirroring
// cmd-explore.test.js's own established pattern (real spawned process,
// real exit codes, real files on disk) rather than calling the export
// functions directly (already covered by export-image.test.js,
// export-json's/export-csv's own test files, generate-html-report.test.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';
import { probeChromeAvailable } from '../../src/ir/chrome-probe.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

// Every format needs a real Chrome EXCEPT json/csv — image formats and
// html (html itself doesn't need Chrome to GENERATE, only png/pdf/svg
// do) are gated the same way export-image.test.js gates its own tests.
const chrome = probeChromeAvailable();
const itChrome = chrome.ok ? test : test.skip;

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-export-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

// A minimal but real graph — same shape cmd-explore.test.js's own
// _writeSignedGraph uses. png/pdf/svg/html all render a real shell even
// with zero nodes/edges (the report chrome — coverage banner, header,
// view tabs — is not conditional on graph content); json/csv need only
// the object/array shape, not populated content.
function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-dataflow-export-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [], edges: [], dataElements: [], transformations: [],
      flows: [], controls: [], policies: [], evidence: [],
      coverage: {}, limitations: [], extensions: {},
    },
    null, 2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('dataflow export: missing graph -> one of loadSignedGraph\'s own messages, exit 1, no output file', () => {
  const root = _mkTmpProject();
  const outFile = path.join(root, 'out.json');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /No lineage graph found/);
    assert.ok(!fs.existsSync(outFile), 'must not write an output file on graph-load failure');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --format json writes a real, parseable envelope with digest + graph', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.json');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(outFile));
    const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.equal(typeof parsed.digest, 'string');
    assert.ok(parsed.graph);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --format csv writes a real CSV with a header row, and --no-redact prints a warning (no-op for csv)', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.csv');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'csv', '--output', outFile, '--no-redact'], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 0, r.stderr);
    const csv = fs.readFileSync(outFile, 'utf8');
    assert.ok(csv.split('\n')[0].length > 0, 'must have a header row');
    assert.match(r.stderr, /--no-redact.*csv|csv.*no.?redact/i, 'must warn that --no-redact has no effect on csv');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --format html writes a real, self-contained HTML file', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.html');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'html', '--output', outFile], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    const html = fs.readFileSync(outFile, 'utf8');
    assert.match(html, /<!doctype html>/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --format svg --view privacy is rejected before any Chrome invocation, exit 2, clear reason', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.svg');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'svg', '--view', 'privacy', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /architecture/i);
    assert.ok(!fs.existsSync(outFile));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --size and --width together is a clear argument error, exit 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.png');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'png', '--size', 'standard', '--width', '999', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--size.*--width|--width.*--size/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

itChrome('dataflow export: --format png --size 2x writes a real 3360x1890 PNG (AC-23)', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.png');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'png', '--size', '2x', '--output', outFile], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    const data = fs.readFileSync(outFile);
    assert.equal(data.readUInt32BE(16), 3360);
    assert.equal(data.readUInt32BE(20), 1890);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

itChrome('dataflow export: --format png default size is the AC-23 standard 1680x945', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.png');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'png', '--output', outFile], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    const data = fs.readFileSync(outFile);
    assert.equal(data.readUInt32BE(16), 1680);
    assert.equal(data.readUInt32BE(20), 945);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

itChrome('dataflow export: --format pdf writes a real PDF', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.pdf');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'pdf', '--output', outFile], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readFileSync(outFile).subarray(0, 5).toString('utf8'), '%PDF-');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: an unknown --format is a clear argument error, exit 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'out.bogus');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'bogus', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--format/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: missing --output is a clear argument error, exit 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--output/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: --output with a non-existent parent directory creates it', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'nested', 'dir', 'out.json');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(outFile));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/server/cmd-dataflow-export.test.js`
Expected: every test FAILS — `dataflow` is not a recognized subcommand yet
(the `switch` in `main()` has no `case 'dataflow':`, so `cmd` falls through
to the `default:` arm, which prints the usage string and exits 1 — every
test above expects exit 0 or 2, so all assertions on `r.status` fail).

- [ ] **Step 3: Add the USAGE entries**

In `scanner/bin/agentic-security.js`, insert two new lines into the
`Commands:` block of the `USAGE` template string, right after the
`scan-baseline` entry (currently the last entry before the blank line and
`Options:` — see lines 139-142 in the current file; insert BEFORE that
blank line):

```
  explore [path] [--port <n>] [--keep-open]
                               Start a local, read-only server over an
                               already-scanned lineage graph (run
                               AGENTIC_SECURITY_LINEAGE_DEEP=1 scan first)
  dataflow export [path] --format png|pdf|svg|json|csv|html --output <file>
                               Export the already-scanned lineage graph.
                               --view architecture|privacy|trace|inventory  (default: architecture)
                               --size standard|2x    AC-23 pinned PNG sizes (default: standard)
                               --width <n> --height <n>   custom PNG size (mutually exclusive with --size)
                               --no-redact            include unredacted content (json/html only; no-op + warning for csv)
                               --filter <path.json>   {nodeIds,edgeIds} to scope the export
```

`explore` was previously undocumented here — this is a real, disclosed
drive-by fix (see the scoping doc's "Real gaps" item 5), not new scope.

- [ ] **Step 4: Implement `cmdDataflowExport`**

Insert this new function immediately after `cmdExplore` (after its closing
`}` on the current line 3076, before `async function main() {`):

```js
// `agentic-security dataflow export [path] --format <fmt> --output <file>
// [--view <name>] [--size standard|2x] [--width <n>] [--height <n>]
// [--no-redact] [--filter <path>]` — Milestone 4, sub-project 5 (CLI +
// slash commands). Wires the six already-shipped M4 export/report
// functions (scanner/scripts/export-image.mjs's exportPng/exportPdf/
// exportSvg, scanner/src/lineage/export-json.js's exportGraphJSON,
// scanner/src/lineage/export-csv.js's exportFlowsCSV, and
// scanner/scripts/generate-html-report.mjs's generateHtmlReport) into
// one consistent CLI surface.
//
// Argument shape mirrors cmdExplore's own: scan root from args._[2]
// (args._[0]='dataflow', args._[1]='export', so the path — if given —
// is the THIRD positional), defaulting to cwd. Uses the identical
// loadSignedGraph contract and error-message pass-through as cmdExplore
// (scoping doc's own binding decision: never proceed past a graph-load
// failure).
//
// Exit codes: 0 success. 1 graph-load failure (loadSignedGraph's own
// four reasons). 2 export-stage failure — bad/missing flags, an
// unsupported format+view combination (svg + non-architecture view,
// rejected BEFORE any Chrome invocation — Chrome's own dump-failure
// reason for this case is confusing, not a good user-facing error), or
// a caught throw/{ok:false} from the underlying export function.
const DATAFLOW_EXPORT_FORMATS = new Set(['png', 'pdf', 'svg', 'json', 'csv', 'html']);
const DATAFLOW_EXPORT_VIEWS = new Set(['architecture', 'privacy', 'trace', 'inventory']);
const DATAFLOW_EXPORT_SIZES = { standard: { width: 1680, height: 945 }, '2x': { width: 3360, height: 1890 } };

async function cmdDataflowExport(args) {
  const target = args._[2] || '.';
  const targetAbs = path.resolve(target);

  const format = args.flags.format;
  if (!format || !DATAFLOW_EXPORT_FORMATS.has(format)) {
    process.stderr.write(`agentic-security dataflow export: --format must be one of ${[...DATAFLOW_EXPORT_FORMATS].join('|')} (got ${JSON.stringify(format)}).\n`);
    return 2;
  }
  const outputPath = args.flags.output;
  if (!outputPath || typeof outputPath !== 'string') {
    process.stderr.write('agentic-security dataflow export: --output <file> is required.\n');
    return 2;
  }
  const view = args.flags.view || 'architecture';
  if (!DATAFLOW_EXPORT_VIEWS.has(view)) {
    process.stderr.write(`agentic-security dataflow export: --view must be one of ${[...DATAFLOW_EXPORT_VIEWS].join('|')} (got ${JSON.stringify(view)}).\n`);
    return 2;
  }
  if (format === 'svg' && view !== 'architecture') {
    process.stderr.write('agentic-security dataflow export: --format svg only supports --view architecture — only the Architecture View renders a real <svg> element.\n');
    return 2;
  }

  const sizeFlag = args.flags.size;
  const hasWidthHeight = args.flags.width !== undefined || args.flags.height !== undefined;
  if (sizeFlag !== undefined && hasWidthHeight) {
    process.stderr.write('agentic-security dataflow export: --size and --width/--height are mutually exclusive — pick one.\n');
    return 2;
  }
  let width, height;
  if (sizeFlag !== undefined) {
    if (!Object.prototype.hasOwnProperty.call(DATAFLOW_EXPORT_SIZES, sizeFlag)) {
      process.stderr.write(`agentic-security dataflow export: --size must be one of ${Object.keys(DATAFLOW_EXPORT_SIZES).join('|')} (got ${JSON.stringify(sizeFlag)}).\n`);
      return 2;
    }
    ({ width, height } = DATAFLOW_EXPORT_SIZES[sizeFlag]);
  } else if (hasWidthHeight) {
    width = Number(args.flags.width);
    height = Number(args.flags.height);
    if (!Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(height) || height <= 0) {
      process.stderr.write('agentic-security dataflow export: --width/--height must both be positive integers.\n');
      return 2;
    }
  } else {
    ({ width, height } = DATAFLOW_EXPORT_SIZES.standard);
  }

  const redact = args.flags['no-redact'] ? false : true;
  if (!redact && format === 'csv') {
    process.stderr.write('agentic-security dataflow export: --no-redact has no effect on --format csv — CSV export does not support redaction yet.\n');
  }

  let filter;
  if (args.flags.filter) {
    const filterPath = path.resolve(args.flags.filter);
    try {
      filter = JSON.parse(fs.readFileSync(filterPath, 'utf8'));
    } catch (e) {
      process.stderr.write(`agentic-security dataflow export: could not read/parse --filter file "${args.flags.filter}": ${e.message}\n`);
      return 2;
    }
  }

  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const loaded = loadSignedGraph(targetAbs);
  if (!loaded.ok) {
    process.stderr.write(`agentic-security dataflow export: ${loaded.message}\n`);
    return 1;
  }
  const graph = loaded.graph;
  const opts = { view, width, height, redact, filter };

  let data;
  try {
    if (format === 'png' || format === 'pdf' || format === 'svg') {
      const { exportPng, exportPdf, exportSvg } = await import('../scripts/export-image.mjs');
      const fn = { png: exportPng, pdf: exportPdf, svg: exportSvg }[format];
      const result = await fn(graph, opts);
      if (!result.ok) {
        process.stderr.write(`agentic-security dataflow export: ${result.reason}\n`);
        return 2;
      }
      data = result.data;
    } else if (format === 'json') {
      const { exportGraphJSON } = await import('../src/lineage/export-json.js');
      data = JSON.stringify(exportGraphJSON(graph, opts), null, 2);
    } else if (format === 'csv') {
      const { exportFlowsCSV } = await import('../src/lineage/export-csv.js');
      data = exportFlowsCSV(graph);
    } else if (format === 'html') {
      const { generateHtmlReport } = await import('../scripts/generate-html-report.mjs');
      data = generateHtmlReport(graph, opts);
    }
  } catch (e) {
    process.stderr.write(`agentic-security dataflow export: export failed: ${e && e.message ? e.message : e}\n`);
    return 2;
  }

  const outAbs = path.resolve(outputPath);
  await fsp.mkdir(path.dirname(outAbs), { recursive: true });
  await fsp.writeFile(outAbs, data);
  process.stdout.write(`agentic-security dataflow export: wrote ${format} to ${outAbs}\n`);
  return 0;
}
```

Confirm `path`, `fs`, `fsp` are already imported at the top of
`bin/agentic-security.js` (they are — used by `cmdExport` and others in
the same file; do not re-import).

- [ ] **Step 5: Wire the dispatch**

In `main()`'s `switch (cmd)`, add a case right after `case 'explore':`
(current line 3149):

```js
      case 'explore':  process.exit(await cmdExplore(args));
      case 'dataflow': {
        const sub = args._[1];
        if (sub === 'export') { process.exit(await cmdDataflowExport(args)); }
        process.stderr.write(`agentic-security dataflow: unknown subcommand "${sub}" — only "export" is supported.\n`);
        process.exit(2);
      }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd scanner && node --test test/server/cmd-dataflow-export.test.js`
Expected: PASS (Chrome-gated tests pass if this machine has Chrome,
otherwise `test.skip` — matching `export-image.test.js`'s own established
pattern; do not treat a skip as a failure).

- [ ] **Step 7: Wire into the test:server npm script**

Modify `scanner/package.json`'s `test:server` script (currently ends
`...test/server/cmd-explore.test.js test/server/static-assets.test.js`) to
insert `test/server/cmd-dataflow-export.test.js` after
`test/server/cmd-explore.test.js`:

```json
"test:server": "node --test test/server/graph-loader.test.js test/server/security.test.js test/server/routes.test.js test/server/http-server.test.js test/server/cmd-explore.test.js test/server/cmd-dataflow-export.test.js test/server/static-assets.test.js",
```

- [ ] **Step 8: Run the full test:server scope, then rebuild**

Run: `cd scanner && npm run test:server`
Expected: all PASS (including the pre-existing `cmd-explore.test.js` and
other `test/server/*` files, unaffected by this change).

Run: `cd scanner && npm run build`
Expected: succeeds, `dist/agentic-security.mjs` + its `.sha256` sidecar
are regenerated. Then re-run `npm run smoke` to confirm the bundle still
works end-to-end.

- [ ] **Step 9: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/package.json scanner/test/server/cmd-dataflow-export.test.js scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(cli): add 'agentic-security dataflow export' subcommand"
```

---

### Task 2: `commands/dataflow.md` slash-command dispatcher

**Files:**
- Create: `commands/dataflow.md`

**Interfaces:**
- Consumes: the CLI shape Task 1 shipped —
  `agentic-security dataflow export [path] --format <fmt> --output <file>
  [--view <name>] [--size standard|2x] [--width <n>] [--height <n>]
  [--no-redact] [--filter <path>]`, exit codes 0/1/2 (no verdict-style
  0-3 translation needed — this is not a security-verdict command, unlike
  `scan`/`ci`).
- Produces: a new slash command `/dataflow` (auto-discovered by Claude
  Code from this file's presence in `commands/`; no manifest edit needed —
  confirmed neither `.claude-plugin/plugin.json` nor `marketplace.json`
  lists individual command files).

- [ ] **Step 1: Write the dispatcher file**

```markdown
---
description: Export the Data Flow Explorer graph — PNG/PDF/SVG images, JSON/CSV data, or a self-contained HTML report.
argument-hint: "[path] --format png|pdf|svg|json|csv|html --output <file> [--view <name>] [--size standard|2x]"
---

## Data Flow Explorer export

Exports the already-scanned lineage graph (run
`AGENTIC_SECURITY_LINEAGE_DEEP=1` with `/scan` first if none exists yet —
this command never triggers a scan itself, matching `/dataflow`'s sibling
`explore` command).

## Formats

| `--format` | Output | Notes |
|---|---|---|
| `png` | Raster image | `--size standard` (1680×945, default) or `--size 2x` (3360×1890) — the two AC-23 pinned sizes. `--width`/`--height` for custom sizes (mutually exclusive with `--size`). Requires a local Chrome/Chromium install. |
| `pdf` | PDF document | Requires Chrome. |
| `svg` | Vector image | Requires Chrome. Only supports `--view architecture` (the default) — other views have no real `<svg>` element to extract. |
| `json` | Data envelope with digest + graph | No Chrome needed. |
| `csv` | One row per flow | No Chrome needed. **Does not support redaction** — `--no-redact` is a no-op for this format (a printed warning explains why). |
| `html` | Self-contained, offline-viewable report | No Chrome needed to generate (only to raster it afterward, if you also want a png/pdf). |

## Options

- `--view architecture|privacy|trace|inventory` — which view to capture (default: `architecture`).
- `--no-redact` — include unredacted content. Honored for `json`/`html`; a no-op (with warning) for `csv`.
- `--filter <path-to-json>` — scope the export to a `{"nodeIds":[...],"edgeIds":[...]}` file.

## Examples

```
/dataflow --format png --output report.png
/dataflow --format png --size 2x --output report-2x.png
/dataflow --format svg --output architecture.svg
/dataflow --format json --output graph.json --no-redact
/dataflow --format html --output report.html
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs dataflow export "$@"
exit $?
```
```

- [ ] **Step 2: Manual smoke check**

Run the same invocation the dispatcher's bash script would run, directly,
against a project with a real signed graph (reuse the fixture-writing
approach from `cmd-dataflow-export.test.js`, or run a real
`AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan` first):

```bash
cd scanner && node bin/agentic-security.js dataflow export /path/to/scanned/project --format json --output /tmp/check.json
cat /tmp/check.json | head -5
```

Expected: exits 0, `/tmp/check.json` contains a real envelope with a
`digest` field.

- [ ] **Step 3: Commit**

```bash
git add commands/dataflow.md
git commit -m "feat(commands): add /dataflow slash command for graph export"
```

---

### Task 3: Docs — CLAUDE.md rows, M4 top-level scoping doc completion

**Files:**
- Modify: `scanner/CLAUDE.md` (the `commands/` row already documents
  "10 dispatchers" — this sub-project adds an 11th; the root `CLAUDE.md`'s
  own `commands/` row also states "10 dispatchers")
- Modify: `/Users/ross/code/agentic-security/CLAUDE.md` (root — the
  `commands/` row's dispatcher count)
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md`
  (mark sub-project #5 COMPLETE, mirroring how #1-#4's rows were updated)

**Interfaces:**
- Consumes: nothing new — this task is documentation only, describing
  what Tasks 1-2 shipped.
- Produces: nothing consumed by later tasks (this is the final task).

- [ ] **Step 1: Update the root CLAUDE.md's `commands/` row**

In `/Users/ross/code/agentic-security/CLAUDE.md`, find the `commands/` row
in the "Repository layout" table (currently reads "10 dispatchers:
`secure`, `find-and-fix-everything`, `scan`, `triage`, `fix`, `posture`,
`compliance`, `supply`, `setup`, `labs`."). Update the count and list to
include `dataflow`:

```
| `commands/` | Slash-command markdown files. 11 dispatchers: `secure`, `find-and-fix-everything`, `scan`, `triage`, `fix`, `posture`, `compliance`, `supply`, `setup`, `labs`, `dataflow`. Every capability is a mode of a dispatcher (e.g. CI gates live at `/setup --ci`, the red/blue/auditor deep-dive at `/triage --deep`); the legacy single-purpose aliases redirect via `hooks/legacy-alias-redirect.js`. |  |
```

(Verify the exact current row text with `grep -n "10 dispatchers" CLAUDE.md`
before editing — the plan's quoted text above may drift if the row was
touched by unrelated work since this plan was written; match against the
real current text, don't blind-replace.)

- [ ] **Step 2: Update `scanner/CLAUDE.md` if it independently states the dispatcher count**

Run `grep -n "dispatcher" scanner/CLAUDE.md` — if it has its own
independent count (rather than just referencing the root doc), update it
the same way as Step 1. If it doesn't mention a count, skip this step (no
edit needed).

- [ ] **Step 3: Mark M4 sub-project #5 COMPLETE in the top-level scoping doc**

In `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md`,
update row 5's Size column from `Small–Medium **— scoped (2026-09-01), see
own doc**` to `Small–Medium **— COMPLETE (2026-09-01)**`, and update the
Why cell to state what shipped: `agentic-security dataflow export` CLI
subcommand (`scanner/bin/agentic-security.js`'s `cmdDataflowExport`) and
`commands/dataflow.md` slash dispatcher, wiring all six #1-#4 export/
report functions into one consistent exit-code contract, plus the rulings
from the sub-project's own scoping doc (kept `explore` as-is, added a
separate `dataflow` verb; deferred semantic `--class` filtering; added
`--size standard|2x` for AC-23's two pinned sizes). Also update the
"Recommended sub-project order" section's #5 line the same way #1-#4's
lines were updated (COMPLETE, one-line summary).

- [ ] **Step 4: Run the doc-drift checker**

Run: `cd scanner && npm run test:lifecycle` (this scope includes the
doc-drift check per `scanner/CLAUDE.md`'s own test-command table — confirm
by checking `package.json`'s `test:lifecycle` script content if unsure).
Expected: PASS — no new file introduced without a doc mention (Task 1's
new function lives inside an already-documented file,
`bin/agentic-security.js`, so this should be a non-issue, but run it to
confirm rather than assume).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md scanner/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md
git commit -m "docs(dataflow): document the dataflow CLI/slash command, mark M4 #5 COMPLETE"
```
