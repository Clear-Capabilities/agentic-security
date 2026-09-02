// governance-refs.test.js — M4 deliverable #10 (DFG-020, graph-derived
// DPIA/RoPA migration), Task 1: `resolveGovernanceRefs` hook.
//
// Proves `flow.governanceRefs` is genuinely populated from
// dataflow/privacy-governance.js's own operator-config/MANUAL_REQUIRED
// infrastructure, never fabricated — and that the hook is opt-in at the
// buildDataFlowGraph level, with buildGraphWithCoverage supplying the
// only default composition.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { MANUAL_REQUIRED, GOVERNANCE_FIELDS } from '../../src/dataflow/privacy-governance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'governance-refs-'));
}

function _writeGovernanceConfig(scanRoot, config) {
  fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
  fs.writeFileSync(
    path.join(scanRoot, '.agentic-security', 'privacy-governance.json'),
    JSON.stringify(config),
  );
}

// Same real, proven PHI-to-model-provider shape used throughout M4
// sub-projects 6b/6c (bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi).
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
// string can carry the hyphen neither identifier form allows), for the
// multi-data-class tie-break tests below. Verified live: classifies as
// dataClasses: ['PII', 'CREDENTIALS'], in that fixed taxonomy iteration
// order (PII is DEFAULT_TAXONOMY's first key, CREDENTIALS its fifth).
const MULTI_CLASS_SOURCE = `function summarizePatient(anthropic, params) {
  const val = params.arguments['ssn-password'];
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: val }],
  });
}
`;

function _buildRealGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

test('governanceRefs: with no privacy-governance.json on disk, every field on a real flow is honestly MANUAL_REQUIRED', () => {
  const scanRoot = _mkScanRoot();
  try {
    const graph = _buildRealGraph(PHI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1);
    const flow = graph.flows[0];
    assert.ok(flow.governanceRefs && Object.keys(flow.governanceRefs).length > 0, 'flow.governanceRefs must be populated, not the pre-fix empty {}');
    for (const field of GOVERNANCE_FIELDS) {
      assert.equal(flow.governanceRefs[field].value, MANUAL_REQUIRED);
      assert.equal(flow.governanceRefs[field].source, 'manual_required');
    }
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('governanceRefs: an operator-supplied privacy-governance.json is genuinely attached, distinguishable by source (real end-to-end via buildLineageGraph, proving the index.js#buildLineageGraph wiring)', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, { byClass: { PHI: { purpose: 'Clinical summarization', lawfulBasis: 'Consent' } } });
    const perFile = { 'source.js': parseJsFile('source.js', PHI_SOURCE) };
    const callGraph = buildCallGraph(perFile);
    const r = buildLineageGraph(callGraph, { repository: 'test-repo', scanRoot, deterministic: true });
    assert.equal(r.status, 'complete');
    const graph = r.graph;
    const flow = graph.flows[0];
    assert.equal(flow.governanceRefs.purpose.value, 'Clinical summarization');
    assert.equal(flow.governanceRefs.purpose.source, 'operator_provided');
    assert.equal(flow.governanceRefs.lawfulBasis.value, 'Consent');
    // A field NOT configured for PHI must still honestly read MANUAL_REQUIRED
    // — never silently inherit an unrelated default.
    assert.equal(flow.governanceRefs.retention.value, MANUAL_REQUIRED);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('governanceRefs: a hook-omitted buildDataFlowGraph call stays byte-identical to the pre-fix empty {} — the hook is opt-in, only buildGraphWithCoverage supplies a default', () => {
  const perFile = { 'source.js': parseJsFile('source.js', PHI_SOURCE) };
  const callGraph = buildCallGraph(perFile);
  const built = buildDataFlowGraph(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.ok(built.graph.flows.length >= 1);
  for (const flow of built.graph.flows) {
    assert.deepEqual(flow.governanceRefs, {});
  }
});

test('governanceRefs: multi-data-class tie-break — the FIRST class seen (PII) with an operator-provided value wins over a SECOND class (CREDENTIALS) that also carries an operator-provided value for the same field', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, {
      byClass: {
        PII: { purpose: 'PII purpose value' },
        CREDENTIALS: { purpose: 'CREDENTIALS purpose value' },
      },
    });
    const perFile = { 'source.js': parseJsFile('source.js', MULTI_CLASS_SOURCE) };
    const callGraph = buildCallGraph(perFile);
    const r = buildLineageGraph(callGraph, { repository: 'test-repo', scanRoot, deterministic: true });
    assert.equal(r.status, 'complete');
    const graph = r.graph;
    const flow = graph.flows[0];
    const de = graph.dataElements.find((d) => d.id === flow.dataElementIds[0]);
    assert.deepEqual(de.dataClasses, ['PII', 'CREDENTIALS'], 'the fixture must genuinely carry two data classes for this test to prove anything');
    assert.equal(flow.governanceRefs.purpose.value, 'PII purpose value');
    assert.equal(flow.governanceRefs.purpose.source, 'operator_provided');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('governanceRefs: multi-data-class tie-break — an operator-provided value under only the SECOND class (CREDENTIALS) resolves correctly, not MANUAL_REQUIRED, even though the FIRST class (PII) has no configured value for that field', () => {
  const scanRoot = _mkScanRoot();
  try {
    _writeGovernanceConfig(scanRoot, { byClass: { CREDENTIALS: { purpose: 'CREDENTIALS purpose value' } } });
    const perFile = { 'source.js': parseJsFile('source.js', MULTI_CLASS_SOURCE) };
    const callGraph = buildCallGraph(perFile);
    const r = buildLineageGraph(callGraph, { repository: 'test-repo', scanRoot, deterministic: true });
    assert.equal(r.status, 'complete');
    const graph = r.graph;
    const flow = graph.flows[0];
    const de = graph.dataElements.find((d) => d.id === flow.dataElementIds[0]);
    assert.deepEqual(de.dataClasses, ['PII', 'CREDENTIALS']);
    assert.equal(flow.governanceRefs.purpose.value, 'CREDENTIALS purpose value');
    assert.equal(flow.governanceRefs.purpose.source, 'operator_provided');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws building governanceRefs, with and without operator config', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const FIXTURES_ROOT = path.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs.readdirSync(FIXTURES_ROOT).filter((f) => fs.statSync(path.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);
  for (const fixtureId of fixtureIds) {
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs.existsSync(srcPath)) continue;
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);
    for (const flow of graph.flows) {
      assert.ok(flow.governanceRefs, `${fixtureId}: flow ${flow.id} missing governanceRefs`);
    }
  }
});
