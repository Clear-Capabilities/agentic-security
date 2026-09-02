// export-privacy.test.js — M4 deliverable #10 (DFG-020, graph-derived
// DPIA/RoPA migration), Task 2: emitGraphDpiaArtifact/emitGraphRopaArtifact.
//
// Proves both emit functions are populated from real DataFlowGraph v1
// output via computePrivacyViewModel (frontend/src/views/privacy-view.js),
// never fabricate a governance fact, and that opts.filter genuinely narrows
// the GRAPH (via export-json.js's _filterGraph) before rows are computed —
// not silently no-op'd through computePrivacyViewModel's own
// state.filters, which expects a different, per-facet shape.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { MANUAL_REQUIRED, GOVERNANCE_FIELDS } from '../../src/dataflow/privacy-governance.js';
import { emitGraphDpiaArtifact, emitGraphRopaArtifact } from '../../src/lineage/export-privacy.js';
import { computePrivacyViewModel } from '../../../frontend/src/views/privacy-view.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'export-privacy-'));
}

function _writeGovernanceConfig(scanRoot, config) {
  fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
  fs.writeFileSync(
    path.join(scanRoot, '.agentic-security', 'privacy-governance.json'),
    JSON.stringify(config),
  );
}

// Same real, proven PHI-to-model-provider shape used throughout M4
// sub-projects 6b/6c/Task-1 (bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi).
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// A field name matching TWO real taxonomy classes at once (PII's \bssn\b
// AND CREDENTIALS's \bpassword\b — bracket-notation access so the literal
// string can carry the hyphen neither identifier form allows), the same
// fixture governance-refs.test.js uses for its own multi-data-class
// tie-break tests. Verified live: classifies as
// dataClasses: ['PII', 'CREDENTIALS'].
const MULTI_CLASS_SOURCE = `function summarizePatient(anthropic, params) {
  const val = params.arguments['ssn-password'];
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: val }],
  });
}
`;

// A real multi-sink shape (mirrors ac01-multi-sink.test.js): one PCI field
// reaching two distinct sinks (log, database) as two distinct, independently
// identifiable flows — used for the opts.filter narrowing test below.
const MULTI_SINK_SOURCE = `
  function handleCheckout(req, logger, db) {
    const cardNumber = req.body.card_number;
    logger.info('processing payment', cardNumber);
    const sql = \`SELECT * FROM cards WHERE number = '\${cardNumber}'\`;
    db.query(sql);
  }
`;

function _buildRealGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

// Governance-config loading only happens via index.js#buildLineageGraph
// (it pre-loads opts.privacyGovernanceConfig from opts.scanRoot once per
// call) — buildGraphWithCoverage alone does NOT read privacy-governance.json
// off scanRoot, matching governance-refs.test.js's own established
// end-to-end pattern for proving the real operator-config wiring.
function _buildRealGraphViaScan(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  const r = buildLineageGraph(callGraph, { repository: 'test-repo', deterministic: true, ...opts });
  assert.equal(r.status, 'complete', `buildLineageGraph did not complete: ${JSON.stringify(r.failure)}`);
  return r.graph;
}

function _emptyGraph() {
  // No sources/sinks matched anywhere — a genuinely empty flows[] array.
  return _buildRealGraph('function noop() { return 1 + 1; }');
}

test('emitGraphDpiaArtifact: a real PHI flow + real operator-supplied privacy-governance.json shows the operator value, not MANUAL_REQUIRED', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, { byClass: { PHI: { purpose: 'Clinical summarization', lawfulBasis: 'Consent' } } });
    const graph = _buildRealGraphViaScan(PHI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected at least one real PHI flow');
    const md = emitGraphDpiaArtifact(graph, {});
    assert.match(md, /# Data Protection Impact Assessment \(DPIA\)/);
    assert.match(md, /PHI/);
    assert.match(md, /purpose: `Clinical summarization` \(operator-provided\)/);
    assert.match(md, /lawfulBasis: `Consent` \(operator-provided\)/);
    assert.doesNotMatch(md.split('purpose:')[1] ?? '', /^\s*`manual_required`/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('emitGraphDpiaArtifact: the SAME graph with no config produces the honest all-MANUAL_REQUIRED answer', () => {
  const scanRoot = _mkScanRoot();
  try {
    const graph = _buildRealGraphViaScan(PHI_SOURCE, { scanRoot });
    const md = emitGraphDpiaArtifact(graph, {});
    assert.match(md, /PHI/);
    for (const field of GOVERNANCE_FIELDS) {
      assert.match(md, new RegExp(`${field}: \`${MANUAL_REQUIRED}\`(?!\\s*\\(operator-provided\\))`));
    }
    assert.doesNotMatch(md, /operator-provided/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('emitGraphRopaArtifact: table row count matches the real flow/dataClass count exactly', () => {
  const scanRoot = _mkScanRoot();
  try {
    const graph = _buildRealGraph(MULTI_SINK_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 2, 'fixture assumption drifted: expected at least two real flows (log + database sinks)');

    // Independently derive the expected row count the same way
    // computePrivacyViewModel/emitGraphRopaArtifact does: one row per
    // (visible row x max(dataClasses.length, 1)).
    const viewModel = computePrivacyViewModel(graph, { selectedId: null }, null);
    const visibleRows = viewModel.rows.filter((r) => r.visible !== false);
    const expectedRowCount = visibleRows.reduce((n, r) => n + Math.max(r.dataClasses.length, 1), 0);
    assert.ok(expectedRowCount > 0, 'test setup must produce at least one expected row');

    const md = emitGraphRopaArtifact(graph, {});
    const lines = md.split('\n');
    const headerIdx = lines.findIndex((l) => l.startsWith('| Data class |'));
    assert.ok(headerIdx >= 0, 'RoPA table header must be present');
    // Table rows: from headerIdx + 2 (skip header + separator) until the
    // first blank line.
    let i = headerIdx + 2;
    let rowCount = 0;
    while (i < lines.length && lines[i].startsWith('|')) {
      rowCount++;
      i++;
    }
    assert.equal(rowCount, expectedRowCount);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('opts.filter genuinely narrows the DPIA/RoPA output to the selected flow only', () => {
  const scanRoot = _mkScanRoot();
  try {
    const graph = _buildRealGraph(MULTI_SINK_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 2, 'fixture assumption drifted: expected at least two real flows');

    const unfilteredRopa = emitGraphRopaArtifact(graph, {});
    const unfilteredLineCount = unfilteredRopa.split('\n').filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| Data class')).length;
    assert.ok(unfilteredLineCount >= 2, 'unfiltered output must have at least 2 data rows for this to be a meaningful narrowing test');

    // Narrow to exactly ONE flow's own nodes/edges — the real
    // {nodeIds, edgeIds} shape export-json.js's _filterGraph consumes.
    const targetFlow = graph.flows[0];
    const filter = { nodeIds: [targetFlow.source, targetFlow.sink], edgeIds: [...targetFlow.edgeIds] };

    const filteredRopa = emitGraphRopaArtifact(graph, { filter });
    const filteredLineCount = filteredRopa.split('\n').filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| Data class')).length;
    assert.ok(filteredLineCount < unfilteredLineCount, `expected filtered RoPA (${filteredLineCount} rows) to have fewer rows than unfiltered (${unfilteredLineCount} rows)`);
    assert.ok(filteredLineCount >= 1, 'the targeted flow itself must still be represented');

    const filteredDpia = emitGraphDpiaArtifact(graph, { filter });
    const unfilteredDpia = emitGraphDpiaArtifact(graph, {});
    assert.notEqual(filteredDpia, unfilteredDpia, 'filtered DPIA must genuinely differ from the unfiltered one');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

// A real PII field (req.body.email -> classifies as PII) alongside a
// real, genuinely UNCLASSIFIED field (req.query.page -> classifies to
// [], the same real shape as
// bench/data-lineage/fixtures/js-http-query-to-log-unclassified-clean),
// both reaching the same log sink as two distinct flows. Verified live.
const MIXED_CLASS_SOURCE = `
  function handleList(req, logger) {
    const email = req.body.email;
    logger.info('collected', email);
    const page = req.query.page;
    logger.info('listing page', page);
  }
`;

test('emitGraphDpiaArtifact: a flow with NO classified data class is still disclosed, never silently dropped from the whole document', () => {
  // Task-2 review finding (non-blocking, fixed): _groupRowsByClass's bare
  // `for (const cls of row.dataClasses)` never iterated for an empty
  // array, so an unclassified flow contributed NOTHING to the DPIA —
  // not merely ungrouped, genuinely invisible, no count, no mention —
  // for a document whose entire purpose is a complete inventory. Fixed
  // to fall back to the same '(unclassified)' bucket RoPA's own sibling
  // loop already used. Mutation-verified: reverting the fallback
  // reproduces the flow vanishing from BOTH the DPIA's text and its own
  // flow count here.
  const graph = _buildRealGraph(MIXED_CLASS_SOURCE);
  assert.equal(graph.flows.length, 2, 'fixture assumption drifted: expected one PII flow + one unclassified flow');
  const unclassifiedFlow = graph.flows.find((f) => {
    const de = graph.dataElements.find((d) => d.id === f.dataElementIds[0]);
    return (de?.dataClasses ?? []).length === 0;
  });
  assert.ok(unclassifiedFlow, 'fixture assumption drifted: expected a real unclassified flow');

  const dpia = emitGraphDpiaArtifact(graph, {});
  assert.match(dpia, /PII/);
  assert.match(dpia, /\(unclassified\)/, 'the unclassified flow must be disclosed somewhere in the DPIA, not silently dropped');

  const ropa = emitGraphRopaArtifact(graph, {});
  // Both documents must agree on how many real flows exist in scope —
  // the review's own repro found the DPIA and RoPA disagreeing here
  // pre-fix (RoPA already counted 2, the DPIA counted/mentioned only 1).
  assert.match(ropa, /2 flow\(s\)/);
});

test('an empty graph (no flows) produces the honest "no regulated data" message for both functions, never a crash', () => {
  const graph = _emptyGraph();
  assert.equal(graph.flows.length, 0, 'test setup must genuinely produce zero flows');

  const dpia = emitGraphDpiaArtifact(graph, {});
  assert.match(dpia, /No regulated data classes were identified in this graph scope\./);

  const ropa = emitGraphRopaArtifact(graph, {});
  assert.match(ropa, /No regulated data flows were identified in this graph scope\./);
});

// Final whole-branch review, BLOCKING 1 (fixed): an unescaped `|` or
// embedded newline in an operator-supplied governance value corrupted the
// RoPA table's own column alignment and could inject arbitrary Markdown
// (a fake heading) into the DPIA — reproduced live with the reviewer's own
// exact repro values below, mutation-verified against the pre-fix code.
test('emitGraphRopaArtifact: a governance value containing a literal "|" and an embedded newline does not corrupt the table', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, {
      byClass: {
        PHI: {
          recipient: 'Acme Payments | Ltd',
          subject: 'Row A\n## INJECTED HEADING\nRow B',
        },
      },
    });
    const graph = _buildRealGraphViaScan(PHI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected at least one real PHI flow');

    const ropa = emitGraphRopaArtifact(graph, {});
    const lines = ropa.split('\n');
    const headerIdx = lines.findIndex((l) => l.startsWith('| Data class |'));
    assert.ok(headerIdx >= 0, 'RoPA table header must be present');
    const headerCellCount = lines[headerIdx].split(' | ').length;
    assert.ok(headerCellCount > 1);

    let i = headerIdx + 2;
    let dataRowsChecked = 0;
    while (i < lines.length && lines[i].startsWith('|')) {
      const cellCount = lines[i].split(' | ').length;
      assert.equal(cellCount, headerCellCount, `row ${i} column count drifted from the header — a "|"-containing value broke the table: ${JSON.stringify(lines[i])}`);
      dataRowsChecked++;
      i++;
    }
    assert.ok(dataRowsChecked > 0, 'test setup must produce at least one real data row');

    // The escaped pipe survives as literal text (never silently dropped),
    // and the embedded newline was collapsed rather than injecting a real
    // Markdown heading mid-table.
    assert.match(ropa, /Acme Payments \\\| Ltd/);
    assert.doesNotMatch(ropa, /^## INJECTED HEADING$/m);
    assert.match(ropa, /Row A ## INJECTED HEADING Row B/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('emitGraphDpiaArtifact: a governance value with a backtick and an embedded newline stays a single, well-formed inline code span', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, {
      byClass: {
        PHI: {
          purpose: 'Weird `backtick` value\n## INJECTED HEADING',
        },
      },
    });
    const graph = _buildRealGraphViaScan(PHI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1, 'fixture assumption drifted: expected at least one real PHI flow');

    const dpia = emitGraphDpiaArtifact(graph, {});
    assert.doesNotMatch(dpia, /^## INJECTED HEADING$/m, 'an embedded newline in a governance value must never inject a real Markdown heading');
    // Backtick-containing values fall back to a padded double-backtick
    // fence — the standard Markdown escape — rather than a single
    // backtick span that would terminate early on the value's own
    // backtick.
    assert.match(dpia, /`` Weird `backtick` value ## INJECTED HEADING ``/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

// Final whole-branch review, RECOMMENDED 2 (fixed via disclosure): a flow
// spanning more than one data class carries a SINGLE governanceRefs record
// already merged (worst-case-wins) across ALL of its own classes back at
// mint time (coverage.js#resolveGovernanceRefs) — re-presenting that one
// merged record under each class's own heading/row, with no indication it
// isn't class-specific, silently loses a real per-class operator override.
test('a flow spanning two data classes discloses that its governance values are merged, not class-specific', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, {
      byClass: {
        PII: { purpose: 'PII-specific purpose' },
        CREDENTIALS: { purpose: 'CREDENTIALS-specific purpose' },
      },
    });
    const graph = _buildRealGraphViaScan(MULTI_CLASS_SOURCE, { scanRoot });
    const de = graph.dataElements.find((d) => (d.dataClasses ?? []).length > 1);
    assert.ok(de, 'fixture assumption drifted: expected a real multi-class dataElement');
    assert.deepEqual(de.dataClasses, ['PII', 'CREDENTIALS']);

    const dpia = emitGraphDpiaArtifact(graph, {});
    assert.match(dpia, /### PII/);
    assert.match(dpia, /### CREDENTIALS/);
    assert.match(dpia, /merged across ALL of its classes/);

    const ropa = emitGraphRopaArtifact(graph, {});
    assert.match(ropa, /\| PII\* \|/);
    assert.match(ropa, /\| CREDENTIALS\* \|/);
    assert.match(ropa, /merged across ALL of its classes/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws building the DPIA or RoPA artifact, with and without a governance config on disk', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const FIXTURES_ROOT = path.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs.readdirSync(FIXTURES_ROOT).filter((f) => fs.statSync(path.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);

  let graphsChecked = 0;
  for (const fixtureId of fixtureIds) {
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs.existsSync(srcPath)) continue;
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);

    assert.doesNotThrow(() => emitGraphDpiaArtifact(graph, {}), `${fixtureId}: emitGraphDpiaArtifact threw with no config`);
    assert.doesNotThrow(() => emitGraphRopaArtifact(graph, {}), `${fixtureId}: emitGraphRopaArtifact threw with no config`);
    graphsChecked++;
  }
  assert.ok(graphsChecked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');

  // Separately, with a real governance config on disk (rebuilt through the
  // full scanRoot-aware pipeline for one representative fixture, since
  // buildFixtureGraph itself has no scanRoot parameter).
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, { default: { purpose: 'Corpus sweep test purpose' } });
    const fixtureId = 'js-http-body-to-database-pci';
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = _buildRealGraphViaScan(source, { scanRoot, repository: fixtureId });
    assert.doesNotThrow(() => emitGraphDpiaArtifact(graph, {}), `${fixtureId}: emitGraphDpiaArtifact threw with a governance config on disk`);
    assert.doesNotThrow(() => emitGraphRopaArtifact(graph, {}), `${fixtureId}: emitGraphRopaArtifact threw with a governance config on disk`);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
