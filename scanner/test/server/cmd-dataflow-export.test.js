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

test('dataflow export: --output pointing at an existing directory is a clean exit-2 error, not a raw stack trace', () => {
  // Found by Task 1's own review, reproduced live: the write-stage
  // mkdir/writeFile originally sat outside the function's try/catch, so
  // this escaped to main()'s generic top-level handler — a raw stack
  // trace and exit 4, breaking the documented 0/1/2 contract.
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outDir = path.join(root, 'already-a-directory');
  fs.mkdirSync(outDir);
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outDir], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /could not write --output/);
    assert.ok(!/at async|at Object|node:internal/.test(r.stderr), 'must not leak a raw Node stack trace to the user');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: a malformed --filter shape (nodeIds not an array) is a clear exit-2 error, not silent data loss', () => {
  // Found by Task 1's own review, reproduced live: exportGraphJSON's own
  // _filterGraph does `new Set(filter.nodeIds ?? [])`, and
  // `new Set("not-an-array")` iterates the string as characters instead
  // of throwing — a malformed-but-valid-JSON --filter file silently
  // produced an empty graph (exit 0) instead of a clear error.
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const filterFile = path.join(root, 'bad-filter.json');
  fs.writeFileSync(filterFile, JSON.stringify({ nodeIds: 'not-an-array' }));
  const outFile = path.join(root, 'out.json');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outFile, '--filter', filterFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--filter file/);
    assert.ok(!fs.existsSync(outFile), 'must not silently write a data-lossy export');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow export: a well-formed --filter is honored (positive control for the shape-validation guard)', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const filterFile = path.join(root, 'good-filter.json');
  fs.writeFileSync(filterFile, JSON.stringify({ nodeIds: [] }));
  const outFile = path.join(root, 'out.json');
  try {
    const r = spawnSync(process.execPath, [CLI, 'dataflow', 'export', root, '--format', 'json', '--output', outFile, '--filter', filterFile], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(outFile));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
