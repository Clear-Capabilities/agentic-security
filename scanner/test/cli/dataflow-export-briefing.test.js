// dataflow-export-briefing.test.js — FR-501 (DFG-035), Task 3: real CLI
// integration tests for `agentic-security dataflow export --format
// briefing`.
//
// Mirrors test/cli/dataflow-export-privacy.test.js's own structure closely
// (real-git-fixture + real-deep-scan + real-CLI-subprocess pattern, not a
// synthetic/hand-built graph) — the briefing needs REAL ranked flows to
// produce meaningful, audience-differentiated content, the same reason
// dpia/ropa need a real scan rather than a hand-built envelope.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// A real multi-sink shape (test/lineage/export-briefing.test.js's own
// MULTI_SINK_SOURCE, copied verbatim): one PCI field reaching a log sink
// (raw, no dimension protected), a database sink (raw SQL, at-rest
// unknown), and an https:// external-api sink (real transit-protected
// evidence) — one field, three genuinely different chapter-4 shapes, and
// (via the raw-logging gap) a real, board-vs-technical wording contrast in
// Chapter 4's policy-state labels.
const MULTI_SINK_SOURCE = `
function handleCheckout(req, logger, db) {
  const cardNumber = req.body.card_number;
  logger.info('processing payment', cardNumber);
  const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
  db.query(sql);
  fetch('https://payments.example/charge', { method: 'POST', body: cardNumber });
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

test('dataflow export --format briefing: real scan produces a real, non-empty 5-chapter briefing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'briefing.md');
  const exportR = _exportCli(fx, ['--format', 'briefing', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format briefing failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected briefing.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Executive Risk Story — Technical Briefing/, 'default --audience must be technical');
  assert.match(md, /## Chapter 1: Scope & Confidence/);
  assert.match(md, /## Chapter 2: Sensitive-Data Footprint/);
  assert.match(md, /## Chapter 3: External Exposure/);
  assert.match(md, /## Chapter 4: Control & Governance Gaps/);
  assert.match(md, /## Chapter 5: Change & Decisions Needed/);
  assert.match(md, /audience mode `technical`/);
});

test('dataflow export --format briefing: --audience board produces genuinely different wording than --audience technical', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const boardOut = path.join(fx.root, 'briefing-board.md');
  const technicalOut = path.join(fx.root, 'briefing-technical.md');
  assert.equal(_exportCli(fx, ['--format', 'briefing', '--output', boardOut, '--audience', 'board']).status, 0);
  assert.equal(_exportCli(fx, ['--format', 'briefing', '--output', technicalOut, '--audience', 'technical']).status, 0);

  const board = fs.readFileSync(boardOut, 'utf8');
  const technical = fs.readFileSync(technicalOut, 'utf8');
  assert.notEqual(board, technical, 'board and technical briefings must genuinely differ');

  // The audience-mode label and register note appear verbatim, and differ.
  assert.match(board, /# Executive Risk Story — Board Briefing/);
  assert.match(technical, /# Executive Risk Story — Technical Briefing/);
  assert.match(board, /audience mode `board`/);
  assert.match(technical, /audience mode `technical`/);

  // A real, content-level wording difference (not just the title/label):
  // export-briefing.js's own audience-wording table renders a policy-state
  // label as plain language in non-verbose (board) mode and as a raw
  // backtick-quoted enum value in verbose (technical) mode — the same
  // contrast test/lineage/export-briefing.test.js's own unit test pins.
  assert.doesNotMatch(board, /`not_evaluated`/);
  assert.match(technical, /`not_evaluated`/);
});

test('dataflow export --format briefing: an unrecognized --audience value is a clear exit-2 error', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'briefing.md');
  const exportR = _exportCli(fx, ['--format', 'briefing', '--output', outFile, '--audience', 'nope']);
  assert.equal(exportR.status, 2, `expected a clean exit-2, got ${exportR.status}: ${exportR.stderr}`);
  assert.match(exportR.stderr, /--audience must be one of/);
  assert.match(exportR.stderr, /board/);
  assert.match(exportR.stderr, /technical/);
  assert.ok(!fs.existsSync(outFile), 'must not write a file on a validation failure');
});

test('dataflow export --format briefing: --view is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'briefing.md');
  const exportR = _exportCli(fx, ['--format', 'briefing', '--view', 'privacy', '--output', outFile]);
  assert.equal(exportR.status, 0, exportR.stderr);
  assert.match(exportR.stderr, /--view has no effect on --format briefing/);
  assert.ok(fs.existsSync(outFile));
});

test('dataflow export --format briefing: --no-redact is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'briefing.md');
  const exportR = _exportCli(fx, ['--format', 'briefing', '--no-redact', '--output', outFile]);
  assert.equal(exportR.status, 0, exportR.stderr);
  assert.match(exportR.stderr, /--no-redact has no effect on --format briefing/);
  assert.ok(fs.existsSync(outFile));
});

// Final whole-branch review finding (NITPICK, fixed): every other
// format-conditional flag (--view/--no-redact/--filter) warns when given
// for a format that ignores it; --audience silently no-op'd with no
// warning at all on a non-briefing format.
test('dataflow export --format json: --audience is a documented no-op with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'graph.json');
  const exportR = _exportCli(fx, ['--format', 'json', '--audience', 'board', '--output', outFile]);
  assert.equal(exportR.status, 0, exportR.stderr);
  assert.match(exportR.stderr, /--audience has no effect on --format json/);
  assert.ok(fs.existsSync(outFile));
});

test('dataflow export --format briefing: --filter genuinely narrows the output to the selected flow', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', MULTI_SINK_SOURCE);
  fx.commit('add PCI-to-three-sinks flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const graphPath = path.join(fx.root, '.agentic-security', 'lineage-graph.json');
  assert.ok(fs.existsSync(graphPath), 'expected a real persisted lineage graph after a deep scan');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(graph.flows.length >= 3, `fixture assumption drifted: expected at least three real flows (log + database + external-api sinks), got ${graph.flows.length}`);

  const unfilteredOut = path.join(fx.root, 'briefing-unfiltered.md');
  const unfilteredR = _exportCli(fx, ['--format', 'briefing', '--output', unfilteredOut]);
  assert.equal(unfilteredR.status, 0, `unfiltered export failed: ${unfilteredR.stderr}`);
  const unfilteredMd = fs.readFileSync(unfilteredOut, 'utf8');

  // Narrow to exactly ONE flow's own node/edge ids — the real
  // {nodeIds, edgeIds} shape every `dataflow export --filter` format
  // consumes (export-json.js's own convention).
  const targetFlow = graph.flows[0];
  const filterPath = path.join(fx.root, 'filter.json');
  fs.writeFileSync(filterPath, JSON.stringify({
    nodeIds: [targetFlow.source, targetFlow.sink],
    edgeIds: [...targetFlow.edgeIds],
  }));

  const filteredOut = path.join(fx.root, 'briefing-filtered.md');
  const filteredR = _exportCli(fx, ['--format', 'briefing', '--output', filteredOut, '--filter', filterPath]);
  assert.equal(filteredR.status, 0, `filtered export failed: ${filteredR.stderr}`);
  const filteredMd = fs.readFileSync(filteredOut, 'utf8');

  assert.notEqual(filteredMd, unfilteredMd, 'filtered briefing must genuinely differ from the unfiltered one');
  // Chapter 2's own group-summary line ("N flow(s)") is a real, easy-to-check
  // narrowing signal: the filtered doc must report fewer flows than the
  // unfiltered one.
  const flowCount = (md) => {
    const m = md.match(/### \S.*\((\d+) flow\(s\)\)/);
    return m ? Number(m[1]) : null;
  };
  const unfilteredCount = flowCount(unfilteredMd);
  const filteredCount = flowCount(filteredMd);
  assert.ok(unfilteredCount !== null, 'expected a real Chapter 2 sensitivity-tier group in the unfiltered doc');
  assert.ok(filteredCount !== null, 'expected a real Chapter 2 sensitivity-tier group in the filtered doc');
  assert.ok(filteredCount < unfilteredCount, `expected filtered briefing (${filteredCount} flow(s)) to report fewer than unfiltered (${unfilteredCount} flow(s))`);
});
