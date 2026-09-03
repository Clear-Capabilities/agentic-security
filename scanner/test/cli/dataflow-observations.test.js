// dataflow-observations.test.js — M5 deliverable #7 (Runtime-Corroborated
// Digital Twin, "7b" — runtime-observed only), Task 6: CLI subprocess tests
// for `agentic-security dataflow observations import|list` and
// `agentic-security dataflow twin`. This is the AC-29 proof surface — the
// first place a human operator can actually see and act on the whole
// deliverable — so every one of AC-29's five `then` clauses is exercised
// here at the real CLI/subprocess layer, not just at the pure-module layer.
//
// Mirrors test/cli/governance-propose-edit.test.js's own subprocess shape
// (spawn the real bin/agentic-security.js with node, in a real temp project
// with a package.json marker) and test/cli/dataflow-diff.test.js's own
// real-scan-then-CLI pattern (a real AGENTIC_SECURITY_LINEAGE_DEEP=1 scan
// produces the real, signed lineage-graph.json this whole suite correlates
// against).
//
// The fixture is deliberately AC-01's own already-proven three-sink shape
// (test/lineage/ac01-multi-sink.test.js): one PCI field (`req.body
// .card_number`) reaching a log sink, a database sink, and a literal
// `https://payments.example/charge` external-api sink, as three distinct
// flows to three distinct graph nodes. The external-api flow is the one
// this suite corroborates via `destination.host: 'payments.example'` —
// the other two stay honestly unobserved, which is exactly the two-flow
// AC-29 scenario ("one statically possible external flow has correlated
// runtime metadata and another has no observation in the selected window").

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { statePath, stateDir } from '../../src/posture/state-dir.js';
import { loadObservationImports, loadObservations } from '../../src/lineage/observation-store.js';
import { validateRuntimeObservation } from '../../src/lineage/runtime-observation.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

const WINDOW_START = '2026-01-01T00:00:00.000Z';
const WINDOW_END = '2026-01-02T00:00:00.000Z';

const FIXTURE_SOURCE = `
function handleCheckout(req, logger, db) {
  const cardNumber = req.body.card_number;
  logger.info('processing payment', cardNumber);
  const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
  db.query(sql);
  fetch('https://payments.example/charge', { body: cardNumber });
}
`;

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-observations-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

// Writes app.js and runs a real, signed AGENTIC_SECURITY_LINEAGE_DEEP=1
// scan — the same real-subprocess pattern test/cli/dataflow-diff.test.js
// already established. `scan`'s own exit code is severity-based, never a
// pass/fail signal — only `run.status < 4` (an engine error) is checked.
function _scanFixture(root) {
  fs.writeFileSync(path.join(root, 'app.js'), FIXTURE_SOURCE);
  const run = spawnSync(process.execPath, [CLI, 'scan', root, '--format', 'json'], {
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
    encoding: 'utf8',
    timeout: 30_000,
  });
  assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
  assert.ok(run.status < 4, `scan reported an engine error (exit ${run.status}): stderr=${run.stderr}`);
  return run;
}

function _readGraph(root) {
  return JSON.parse(fs.readFileSync(statePath(root, 'lineage-graph.json'), 'utf8'));
}

function _flowFor(graph, sinkKind) {
  const node = graph.nodes.find((n) => n.kind === sinkKind);
  assert.ok(node, `fixture assumption: a "${sinkKind}"-kind node must exist`);
  const flow = graph.flows.find((f) => f.sink === node.id);
  assert.ok(flow, `fixture assumption: a flow ending at the "${sinkKind}" node must exist`);
  return flow;
}

function _writeObsFile(root, records, name = 'obs.jsonl') {
  const p = path.join(root, name);
  fs.writeFileSync(p, records.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return p;
}

function _listFilesRecursive(dir) {
  const out = [];
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else out.push(full);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return out.sort();
}

function _snapshotDir(dir) {
  return _listFilesRecursive(dir).map((f) => `${f}:${fs.statSync(f).mtimeMs}:${fs.statSync(f).size}`);
}

function runImport(argsList) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'observations', 'import', ...argsList], { encoding: 'utf8', timeout: 15_000 });
}
function runList(argsList) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'observations', 'list', ...argsList], { encoding: 'utf8', timeout: 15_000 });
}
function runTwin(argsList) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'twin', ...argsList], { encoding: 'utf8', timeout: 15_000 });
}

// A single record whose destination.host matches the fixture's own
// literal `https://payments.example/charge` external-api sink.
function _matchingObsRecord(overrides = {}) {
  return {
    environment: 'production',
    attributes: { 'destination.host': 'payments.example', 'destination.scheme': 'https' },
    eventCountBand: '11-100',
    firstObservedAt: WINDOW_START,
    lastObservedAt: WINDOW_END,
    ...overrides,
  };
}

// --- dataflow observations import ------------------------------------------

test('CLI/import-1: dry run (no --yes) previews the import and writes nothing, no audit event', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END]);
  assert.equal(r.status, 0, r.stderr);
  const preview = JSON.parse(r.stdout);
  assert.equal(preview.adapter, 'native-jsonl');
  assert.equal(preview.recordCount, 1);
  assert.equal(preview.environment, 'production');
  assert.equal(preview.windowStart, WINDOW_START);
  assert.equal(preview.windowEnd, WINDOW_END);
  assert.equal(preview.written, false);
  assert.equal(loadObservationImports(root).length, 0, 'the store must be genuinely unchanged after a dry run');
  const auditLogPath = statePath(root, 'mcp-audit.log');
  const auditContent = fs.existsSync(auditLogPath) ? fs.readFileSync(auditLogPath, 'utf8') : '';
  assert.ok(!auditContent.includes('dataflow_observations_import'), 'mcp-audit.log must gain no entry on a dry run');
});

test('CLI/import-2: --yes writes exactly one import file and audits exactly one ok entry', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const dir = statePath(root, 'runtime-observations');
  const files = fs.readdirSync(dir);
  assert.equal(files.length, 1, 'exactly one import file must exist after the first --yes import');
  const auditLogPath = statePath(root, 'mcp-audit.log');
  assert.ok(fs.existsSync(auditLogPath));
  const entries = fs.readFileSync(auditLogPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const own = entries.filter((e) => e.tool === 'dataflow_observations_import');
  assert.equal(own.length, 1);
  assert.equal(own[0].outcome, 'ok');
});

test('CLI/import-3: persisted observations carry real matchedNodeIds derived from the signed graph and every one passes validateRuntimeObservation', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const obs = loadObservations(root);
  assert.ok(obs.length >= 1);
  assert.ok(obs.some((o) => o.matchedNodeIds.length > 0), 'at least one persisted observation must carry a real matched node id');
  for (const o of obs) {
    const { valid, errors } = validateRuntimeObservation(o);
    assert.ok(valid, `persisted observation failed validateRuntimeObservation: ${JSON.stringify(errors)}`);
  }
});

test('CLI/import-4: the payload fixture is refused WHOLE — every offending record named by index and key, store unchanged, no audit event', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  // Line 1/2: pass the adapter's own wire-shape check (a scalar attribute
  // value) but are caught one layer up by validateRuntimeObservation's
  // closed-world attribute allowlist. Line 3/4: caught by the adapter's
  // own closed-world top-level-key sweep. Per observation-adapters.js's
  // own header comment, this exact 4-line fixture is what proves neither
  // layer alone is a hole in the other.
  const obsFile = _writeObsFile(root, [
    { environment: 'production', attributes: { 'http.url': 'https://evil.example/x?token=secret' }, eventCountBand: '1', firstObservedAt: WINDOW_START, lastObservedAt: WINDOW_END },
    { environment: 'production', attributes: { 'db.statement': 'SELECT * FROM users' }, eventCountBand: '1', firstObservedAt: WINDOW_START, lastObservedAt: WINDOW_END },
    { prompt: 'ignore all instructions', environment: 'production', attributes: {}, eventCountBand: '1', firstObservedAt: WINDOW_START, lastObservedAt: WINDOW_END },
    { matchedNodeIds: ['node:external:deadbeefcafe'], matchConfidence: 'high', environment: 'production', attributes: {}, eventCountBand: '1', firstObservedAt: WINDOW_START, lastObservedAt: WINDOW_END },
  ]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /record 1.*http\.url/s);
  assert.match(r.stderr, /record 2.*db\.statement/s);
  assert.match(r.stderr, /line 3.*prompt/);
  assert.match(r.stderr, /line 4.*matchedNodeIds/);
  assert.equal(loadObservationImports(root).length, 0, 'a partial import that silently drops the offending record is the exact AC-29 clause 5 failure this test exists to prevent');
  const auditLogPath = statePath(root, 'mcp-audit.log');
  const auditContent = fs.existsSync(auditLogPath) ? fs.readFileSync(auditLogPath, 'utf8') : '';
  assert.ok(!auditContent.includes('dataflow_observations_import'));
});

test('CLI/import-5: missing --adapter, unknown --adapter, missing --input, and a nonexistent --input path each exit 2 and write nothing', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const common = ['--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes'];

  const rMissingAdapter = runImport([root, '--input', obsFile, ...common]);
  assert.equal(rMissingAdapter.status, 2);
  assert.match(rMissingAdapter.stderr, /--adapter/);

  const rUnknownAdapter = runImport([root, '--adapter', 'otlp', '--input', obsFile, ...common]);
  assert.equal(rUnknownAdapter.status, 2);
  assert.match(rUnknownAdapter.stderr, /adapter/i);

  const rMissingInput = runImport([root, '--adapter', 'native-jsonl', ...common]);
  assert.equal(rMissingInput.status, 2);
  assert.match(rMissingInput.stderr, /--input/);

  const rBadInput = runImport([root, '--adapter', 'native-jsonl', '--input', path.join(root, 'nope.jsonl'), ...common]);
  assert.equal(rBadInput.status, 2);
  assert.match(rBadInput.stderr, /not found/i);

  assert.equal(loadObservationImports(root).length, 0);
});

test('CLI/import-6: --window-start after --window-end exits 2', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_END, '--window-end', WINDOW_START, '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /window/i);
});

test('CLI/import-7: no lineage-graph.json on disk exits 1 with loadSignedGraph\'s own "missing" message', () => {
  const root = _mkTmpProject(); // never scanned
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /No lineage graph found/);
});

test('CLI/import-8: re-running the same import with --yes writes a SECOND import file, and loadObservations dedupes to the original count', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const common = [root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes'];
  const r1 = runImport(common);
  assert.equal(r1.status, 0, r1.stderr);
  const r2 = runImport(common);
  assert.equal(r2.status, 0, r2.stderr);

  const dir = statePath(root, 'runtime-observations');
  assert.equal(fs.readdirSync(dir).length, 2, 'immutable store: a second import must write a SECOND file, never overwrite the first');
  const preview1 = JSON.parse(r1.stdout);
  const preview2 = JSON.parse(r2.stdout);
  assert.notEqual(preview1.importId, preview2.importId, 'importedAt is part of the import id, so re-importing must mint a new import id');
  assert.equal(loadObservations(root).length, 1, 'the two imports carry the identical observation (same adapter/environment/window/attributes), so it must dedupe to one');
});

// --- dataflow observations list ---------------------------------------------

test('CLI/list-1: an empty store prints an honest "no imports" line; two imports print one row each naming adapter/source/environment/window/count/importedAt', () => {
  const root = _mkTmpProject();
  _scanFixture(root);

  const rEmpty = runList([root]);
  assert.equal(rEmpty.status, 0, rEmpty.stderr);
  assert.match(rEmpty.stdout, /no.*import/i);

  const obsFile1 = _writeObsFile(root, [_matchingObsRecord()], 'obs-1.jsonl');
  const r1 = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile1, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r1.status, 0, r1.stderr);
  const obsFile2 = _writeObsFile(root, [_matchingObsRecord({ environment: 'staging' })], 'obs-2.jsonl');
  const r2 = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile2, '--environment', 'staging', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r2.status, 0, r2.stderr);

  const rTwo = runList([root]);
  assert.equal(rTwo.status, 0, rTwo.stderr);
  const lines = rTwo.stdout.trim().split('\n');
  assert.equal(lines.length, 2, 'one row per import');
  assert.match(rTwo.stdout, /adapter=native-jsonl/);
  assert.match(rTwo.stdout, /source=obs-1\.jsonl/);
  assert.match(rTwo.stdout, /source=obs-2\.jsonl/);
  assert.match(rTwo.stdout, /environment=production/);
  assert.match(rTwo.stdout, /environment=staging/);
  assert.match(rTwo.stdout, /window=/);
  assert.match(rTwo.stdout, /observations=1/);
  assert.match(rTwo.stdout, /importedAt=/);
});

test('CLI/list-2: observations list NEVER prints an attribute VALUE', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord({ attributes: { 'destination.host': 'sentinel-host.example' } })]);
  const rImport = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(rImport.status, 0, rImport.stderr);

  const rText = runList([root]);
  assert.equal(rText.status, 0, rText.stderr);
  assert.ok(!rText.stdout.includes('sentinel-host.example'), 'plain-text list must not leak an attribute value');

  const rJson = runList([root, '--json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  assert.ok(!rJson.stdout.includes('sentinel-host.example'), '--json list must not leak an attribute value either');

  // Non-vacuous: the sentinel really is in the raw store file, so the two
  // assertions above are proving something real.
  const dir = statePath(root, 'runtime-observations');
  const files = fs.readdirSync(dir);
  const raw = fs.readFileSync(path.join(dir, files[0]), 'utf8');
  assert.ok(raw.includes('sentinel-host.example'), 'sanity check: the raw store file must actually contain the sentinel');
});

// --- dataflow twin -----------------------------------------------------------

test('CLI/twin-1 (AC-29 clause 3): every flow in the graph appears in the twin output regardless of layer', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const graph = _readGraph(root);
  const outFile = path.join(root, 'twin.json');
  const r = runTwin([root, '--output', outFile, '--format', 'json']);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.equal(Object.keys(out.byFlow).length, graph.flows.length);
});

test('CLI/twin-2 (AC-29 clauses 1 and 4): the observed flow reads layer runtime_observed, and the markdown shows RUNTIME OBSERVED plus match method/confidence/environment/window', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const rImport = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(rImport.status, 0, rImport.stderr);

  const graph = _readGraph(root);
  const externalFlow = _flowFor(graph, 'external');

  const jsonOut = path.join(root, 'twin.json');
  const rJson = runTwin([root, '--output', jsonOut, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  const result = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
  assert.equal(result.byFlow[externalFlow.id].layer, 'runtime_observed');
  assert.equal(result.byFlow[externalFlow.id].matchMethod, 'destination_literal');
  assert.equal(result.byFlow[externalFlow.id].matchConfidence, 'high');
  assert.equal(result.byFlow[externalFlow.id].environment, 'production');

  const mdOut = path.join(root, 'twin.md');
  const rMd = runTwin([root, '--output', mdOut, '--format', 'markdown']);
  assert.equal(rMd.status, 0, rMd.stderr);
  const md = fs.readFileSync(mdOut, 'utf8');
  assert.match(md, /RUNTIME OBSERVED/);
  assert.match(md, /destination_literal/);
  assert.match(md, /\bhigh\b/);
  assert.match(md, /production/);
  assert.ok(md.includes(WINDOW_START) && md.includes(WINDOW_END), 'the window must be printed');
});

test('CLI/twin-3 (AC-29 clause 2): the unobserved flow reads not_observed_in_window, and the markdown states this is not evidence of non-occurrence', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const rImport = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(rImport.status, 0, rImport.stderr);

  const graph = _readGraph(root);
  const logFlow = _flowFor(graph, 'log');

  const jsonOut = path.join(root, 'twin.json');
  const rJson = runTwin([root, '--output', jsonOut, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  const result = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
  assert.equal(result.byFlow[logFlow.id].layer, 'not_observed_in_window');

  const mdOut = path.join(root, 'twin.md');
  const rMd = runTwin([root, '--output', mdOut, '--format', 'markdown']);
  assert.equal(rMd.status, 0, rMd.stderr);
  const md = fs.readFileSync(mdOut, 'utf8');
  assert.match(md, /not_observed_in_window[\s\S]*was not observed in the selected[\s\S]*does NOT mean the flow does not occur/);
});

test('CLI/twin-4: with no observation store on disk at all, every flow reads not_evaluated, the markdown discloses no store was consulted, and this differs from the not_observed_in_window case', () => {
  const rootA = _mkTmpProject();
  _scanFixture(rootA);

  const jsonOutA = path.join(rootA, 'twin.json');
  const rJsonA = runTwin([rootA, '--output', jsonOutA, '--format', 'json']);
  assert.equal(rJsonA.status, 0, rJsonA.stderr);
  const resultA = JSON.parse(fs.readFileSync(jsonOutA, 'utf8'));
  assert.equal(resultA.evaluated, false);
  for (const fid of Object.keys(resultA.byFlow)) {
    assert.equal(resultA.byFlow[fid].layer, 'not_evaluated');
  }

  const mdOutA = path.join(rootA, 'twin.md');
  const rMdA = runTwin([rootA, '--output', mdOutA, '--format', 'markdown']);
  assert.equal(rMdA.status, 0, rMdA.stderr);
  const mdA = fs.readFileSync(mdOutA, 'utf8');
  assert.match(mdA, /not_evaluated/);
  assert.match(mdA, /no runtime observation store was consulted/i);

  // Contrast: a second project WHOSE store WAS consulted but matched
  // nothing produces a genuinely different markdown body (not_evaluated
  // vs. not_observed_in_window are two different answers, PRD line 2098).
  const rootB = _mkTmpProject();
  _scanFixture(rootB);
  const obsFile = _writeObsFile(rootB, [_matchingObsRecord({ attributes: { 'destination.host': 'nowhere.example' } })]);
  const rImportB = runImport([rootB, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(rImportB.status, 0, rImportB.stderr);
  const mdOutB = path.join(rootB, 'twin.md');
  const rMdB = runTwin([rootB, '--output', mdOutB, '--format', 'markdown']);
  assert.equal(rMdB.status, 0, rMdB.stderr);
  const mdB = fs.readFileSync(mdOutB, 'utf8');
  assert.match(mdB, /not_observed_in_window/);

  assert.notEqual(mdA, mdB);
});

test('CLI/twin-5: --environment staging narrows — a production-only observation no longer marks its flow observed, and the result echoes environment staging', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const rImport = runImport([root, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(rImport.status, 0, rImport.stderr);

  const graph = _readGraph(root);
  const externalFlow = _flowFor(graph, 'external');

  const outFile = path.join(root, 'twin.json');
  const r = runTwin([root, '--output', outFile, '--format', 'json', '--environment', 'staging']);
  assert.equal(r.status, 0, r.stderr);
  const result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.equal(result.environment, 'staging');
  assert.notEqual(result.byFlow[externalFlow.id].layer, 'runtime_observed');
});

test('CLI/twin-6: exit codes — missing --output -> 2, unknown --format -> 2, no lineage-graph.json -> 1, success -> 0', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const outFile = path.join(root, 'twin.json');

  const rNoOutput = runTwin([root, '--format', 'json']);
  assert.equal(rNoOutput.status, 2);

  const rBadFormat = runTwin([root, '--output', outFile, '--format', 'yaml']);
  assert.equal(rBadFormat.status, 2);

  const emptyRoot = _mkTmpProject();
  const rNoGraph = runTwin([emptyRoot, '--output', path.join(emptyRoot, 'twin.json'), '--format', 'json']);
  assert.equal(rNoGraph.status, 1);

  const rOk = runTwin([root, '--output', outFile, '--format', 'json']);
  assert.equal(rOk.status, 0, rOk.stderr);
});

test('CLI/twin-7: dataflow twin writes NOTHING into .agentic-security/ — it is a read-only report', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  const dir = stateDir(root);
  const before = _snapshotDir(dir);
  const outFile = path.join(root, 'twin-readonly.md');
  const r = runTwin([root, '--output', outFile, '--format', 'markdown']);
  assert.equal(r.status, 0, r.stderr);
  const after = _snapshotDir(dir);
  assert.deepEqual(after, before, 'dataflow twin must not create, modify, or touch any file under .agentic-security/');
});

// --- isSafeStateDir guard ----------------------------------------------------

test('CLI/isSafe-1: observations import --yes pointed at a directory with no project marker exits 2 and creates no runtime-observations directory', () => {
  const root = _mkTmpProject();
  _scanFixture(root);
  // A bare directory holding a copy of a real, validly-SIGNED
  // lineage-graph.json (so loadSignedGraph succeeds — there is a real
  // graph to correlate against) but with NO other project marker in its
  // parent — isSafeStateDir must still refuse the write.
  const bareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-observations-unsafe-'));
  const bareStateDir = path.join(bareDir, '.agentic-security');
  fs.mkdirSync(bareStateDir, { recursive: true });
  fs.copyFileSync(statePath(root, 'lineage-graph.json'), path.join(bareStateDir, 'lineage-graph.json'));
  fs.copyFileSync(statePath(root, 'lineage-graph.json.sig'), path.join(bareStateDir, 'lineage-graph.json.sig'));

  const obsFile = _writeObsFile(root, [_matchingObsRecord()]);
  const r = runImport([bareDir, '--adapter', 'native-jsonl', '--input', obsFile, '--environment', 'production', '--window-start', WINDOW_START, '--window-end', WINDOW_END, '--yes']);
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.ok(!fs.existsSync(path.join(bareStateDir, 'runtime-observations')), 'no runtime-observations directory must be created');
});
