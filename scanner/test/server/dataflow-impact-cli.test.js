import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-impact-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-dataflow-impact-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [
        { id: 'node:source', kind: 'source', subtype: 'user-input' },
        { id: 'node:sink', kind: 'sink', subtype: 'external-api' },
      ],
      edges: [{ id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to' }],
      dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
      transformations: [],
      flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
      recipientProfiles: [{ id: 'recipient:vendor', provider: 'vendor', contributingGraphIds: ['node:sink'] }],
      controls: [], policies: [], evidence: [],
      coverage: { languages: [{ language: 'js', tier: 'partial', filesAnalyzed: 1, filesExpected: 1 }] },
      limitations: [], extensions: {},
    },
    null, 2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('dataflow impact assess: writes a JSON assessment and exits 0', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'impact.json');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', outFile, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.ok(report.affectedNodeIds.includes('node:sink'));
  assert.deepEqual(report.affectedRecipientProfileIds, ['recipient:vendor']);
  assert.equal(report.scope, 'possible');
});

test('dataflow impact assess: --format markdown writes a real Markdown report', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'impact.md');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', outFile, '--format', 'markdown'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Impact assessment/);
  assert.match(md, /node:sink/);
  // N4 (final-review re-review): the header must tie the report back
  // to the graph/moment it was computed — these three assertions would
  // fail if id/graphId/graphDigest were ever dropped from the Markdown
  // branch (the pre-M3 shape), unlike the two assertions above, which
  // would still pass with the whole header removed.
  assert.match(md, /^id: `impact:[0-9a-f]+`$/m);
  assert.match(md, /^graphId: `dfg:cli-dataflow-impact-test`$/m);
  assert.match(md, /^graphDigest: `[0-9a-f]+`$/m);
});

test('dataflow impact assess: a malformed --target (no recognized prefix) exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'bogus-id', '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /recognized/);
});

test('dataflow impact assess: missing --target exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow impact assess: missing --output exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow impact assess: missing graph -> exit 1, one of loadSignedGraph\'s own messages', () => {
  const root = _mkTmpProject();
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
});

// M4 (final-review fix round): a signed-but-structurally-malformed graph
// (loadSignedGraph verifies only the SIGNATURE, never the schema — see
// graph-loader.js) must be classified as a graph-content problem (exit 1),
// never as a CLI argument problem (exit 2) — the two are structurally
// distinct and computeImpactAssessment's own malformed-graph guard exists
// specifically so this CLI boundary can tell them apart. A malformed
// --target (already covered above) is the real exit-2 case; this is its
// exit-1 sibling, not a duplicate of the "missing graph file entirely"
// test above.
test('dataflow impact assess: a signed but structurally malformed graph (missing edges array) exits 1, not 2', () => {
  const root = _mkTmpProject();
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify({
    schemaVersion: '1.0.0', graphId: 'dfg:cli-dataflow-impact-malformed-test',
    generatedAt: '1970-01-01T00:00:00.000Z', scope: { source: 'fixture' }, scanHealth: {},
    nodes: [{ id: 'node:source', kind: 'source', subtype: 'user-input' }],
    // edges deliberately omitted entirely — a structurally malformed graph
    // that still verifies as SIGNED (loadSignedGraph checks the signature
    // only, never the schema).
    dataElements: [], transformations: [], flows: [], recipientProfiles: [],
    controls: [], policies: [], evidence: [], coverage: {}, limitations: [], extensions: {},
  }, null, 2);
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /malformed graph/);
});
