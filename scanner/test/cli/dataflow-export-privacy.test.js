// dataflow-export-privacy.test.js — M4 deliverable #10 (DFG-020), Task 3:
// real CLI integration tests for `agentic-security dataflow export
// --format dpia|ropa`.
//
// Mirrors test/cli/attest-obligations.test.js's own real-git-fixture +
// real-deep-scan + real-CLI-subprocess pattern (not
// test/server/cmd-dataflow-export.test.js's synthetic-empty-graph
// pattern) — dpia/ropa need REAL classified flows/governanceRefs to
// produce meaningful content, the same reason attest --obligations
// needs a real scan rather than a hand-built envelope.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// Same real, proven PHI-to-model-provider shape used throughout this
// branch's own M4 sub-projects (bench/data-lineage/fixtures/
// js-ai-model-output-to-ai-model-provider-phi), and copied verbatim from
// test/cli/attest-obligations.test.js's own PHI_SOURCE.
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// A real multi-sink shape (mirrors test/lineage/export-privacy.test.js's
// own MULTI_SINK_SOURCE): one PCI field reaching two distinct sinks (log,
// database) as two distinct, independently identifiable flows — used for
// the --filter narrowing test below.
const MULTI_SINK_SOURCE = `
function handleCheckout(req, logger, db) {
  const cardNumber = req.body.card_number;
  logger.info('processing payment', cardNumber);
  const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
  db.query(sql);
}
`;

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _exportCli(fx, args) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', ...args], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
}

test('dataflow export --format dpia: real PHI scan produces a real, non-empty DPIA scaffold', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'dpia.md');
  const exportR = _exportCli(fx, ['--format', 'dpia', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format dpia failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected dpia.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Data Protection Impact Assessment \(DPIA\)/);
  assert.match(md, /PHI/, 'expected the real PHI data class to be mentioned');
});

test('dataflow export --format ropa: real PHI scan produces a real Markdown register table', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'ropa.md');
  const exportR = _exportCli(fx, ['--format', 'ropa', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format ropa failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected ropa.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Record of Processing Activities \(RoPA\)/);
  // A real Markdown table: a header row starting with "| Data class |"
  // plus at least one real data row beneath it.
  assert.match(md, /\| Data class \|/);
  const lines = md.split('\n');
  const headerIdx = lines.findIndex((l) => l.startsWith('| Data class |'));
  assert.ok(headerIdx >= 0, 'RoPA table header must be present');
  assert.ok(lines[headerIdx + 2]?.startsWith('|'), 'expected at least one real data row under the table header');
});

test('dataflow export --format dpia|ropa: --filter genuinely narrows the output to the selected flow', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-two-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const graphPath = path.join(fx.root, '.agentic-security', 'lineage-graph.json');
  assert.ok(fs.existsSync(graphPath), 'expected a real persisted lineage graph after a deep scan');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(graph.flows.length >= 2, `fixture assumption drifted: expected at least two real flows (log + database sinks), got ${graph.flows.length}`);

  // Unfiltered baseline first.
  const unfilteredOut = path.join(fx.root, 'ropa-unfiltered.md');
  const unfilteredR = _exportCli(fx, ['--format', 'ropa', '--output', unfilteredOut]);
  assert.equal(unfilteredR.status, 0, `unfiltered export failed: ${unfilteredR.stderr}`);
  const unfilteredMd = fs.readFileSync(unfilteredOut, 'utf8');
  const unfilteredRowCount = unfilteredMd.split('\n')
    .filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| Data class')).length;
  assert.ok(unfilteredRowCount >= 2, 'unfiltered RoPA must have at least 2 data rows for this to be a meaningful narrowing test');

  // Narrow to exactly ONE flow's own node/edge ids — the real
  // {nodeIds, edgeIds} shape every `dataflow export --filter` format
  // consumes (export-json.js's own convention).
  const targetFlow = graph.flows[0];
  const filterPath = path.join(fx.root, 'filter.json');
  fs.writeFileSync(filterPath, JSON.stringify({
    nodeIds: [targetFlow.source, targetFlow.sink],
    edgeIds: [...targetFlow.edgeIds],
  }));

  const filteredOut = path.join(fx.root, 'ropa-filtered.md');
  const filteredR = _exportCli(fx, ['--format', 'ropa', '--output', filteredOut, '--filter', filterPath]);
  assert.equal(filteredR.status, 0, `filtered export failed: ${filteredR.stderr}`);
  const filteredMd = fs.readFileSync(filteredOut, 'utf8');
  const filteredRowCount = filteredMd.split('\n')
    .filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| Data class')).length;
  assert.ok(filteredRowCount < unfilteredRowCount, `expected filtered RoPA (${filteredRowCount} rows) to have fewer rows than unfiltered (${unfilteredRowCount} rows)`);
  assert.ok(filteredRowCount >= 1, 'the targeted flow itself must still be represented');

  // Same narrowing property for dpia — filtered output must genuinely
  // differ from the unfiltered one.
  const dpiaUnfilteredOut = path.join(fx.root, 'dpia-unfiltered.md');
  const dpiaFilteredOut = path.join(fx.root, 'dpia-filtered.md');
  assert.equal(_exportCli(fx, ['--format', 'dpia', '--output', dpiaUnfilteredOut]).status, 0);
  assert.equal(_exportCli(fx, ['--format', 'dpia', '--output', dpiaFilteredOut, '--filter', filterPath]).status, 0);
  const dpiaUnfiltered = fs.readFileSync(dpiaUnfilteredOut, 'utf8');
  const dpiaFiltered = fs.readFileSync(dpiaFilteredOut, 'utf8');
  assert.notEqual(dpiaFiltered, dpiaUnfiltered, 'filtered DPIA must genuinely differ from the unfiltered one');
});

test('dataflow export --format dpia: --view is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'dpia.md');
  const exportR = _exportCli(fx, ['--format', 'dpia', '--view', 'privacy', '--output', outFile]);
  assert.equal(exportR.status, 0, exportR.stderr);
  assert.match(exportR.stderr, /--view has no effect on --format dpia/);
  assert.ok(fs.existsSync(outFile));
});

test('dataflow export --format ropa: --no-redact is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'ropa.md');
  const exportR = _exportCli(fx, ['--format', 'ropa', '--no-redact', '--output', outFile]);
  assert.equal(exportR.status, 0, exportR.stderr);
  assert.match(exportR.stderr, /--no-redact has no effect on --format ropa/);
  assert.ok(fs.existsSync(outFile));
});
