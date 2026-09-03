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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-scenario-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

// Mirrors cmd-dataflow-export.test.js's own _writeSignedGraph exactly
// (same statePath key, same signLastScan call), extended with one real
// source->sink edge/flow so a scenario operation has a real id to target.
function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-dataflow-scenario-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [
        { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
        { id: 'node:sink', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.example.com' }, storeDetail: null },
      ],
      edges: [
        { id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to', protection: { transit: { verdict: 'not_assessed', evidenceGrade: 'none' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } } },
      ],
      dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
      transformations: [],
      flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
      controls: [], policies: [], evidence: [],
      coverage: {}, limitations: [], extensions: {},
    },
    null, 2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('dataflow scenario apply: writes a JSON delta report and exits 0', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }],
  }));
  const outFile = path.join(root, 'delta.json');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', outFile, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.ok(Array.isArray(report.changedEntities));
  assert.ok(Array.isArray(report.appliedOperations));
  assert.equal(report.appliedOperations.length, 1);
  assert.ok(report.changedEntities.some((c) => c.id === 'edge:1'));
  assert.ok(report.changedEntities.some((c) => c.id === 'flow:1'));
});

// I4 (final-review.md): the synthetic scenario record's id/baseGraphDigest
// must be real, not the literal placeholder 'scenario:cli-draft' and not
// baseGraphId reused as the digest (which carries no content information).
test('dataflow scenario apply: report.scenarioId is a real scenario:<hash> id, not the literal placeholder', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }],
  }));
  const outFile = path.join(root, 'delta.json');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', outFile, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.notEqual(report.scenarioId, 'scenario:cli-draft');
  assert.match(report.scenarioId, /^scenario:[0-9a-f]+$/);
});

// AC-26 ("What-if changes cannot masquerade as implementation"): the
// PRD's own worked example ("simulates TLS on a cleartext... edge")
// through the REAL CLI, both output formats — proving the fix end to
// end, not just at the library-function level scenario-diff.test.js
// already covers.
test('dataflow scenario apply: AC-26 — require_transit_protection is labeled HYPOTHETICAL in both JSON and Markdown output', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }],
  }));

  const jsonOut = path.join(root, 'delta.json');
  const rJson = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', jsonOut, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(rJson.status, 0, rJson.stderr);
  const report = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
  const edgeChange = report.changedEntities.find((c) => c.id === 'edge:1');
  assert.ok(edgeChange, 'edge:1 must be present in changedEntities');
  assert.equal(edgeChange.label, 'HYPOTHETICAL');

  const mdOut = path.join(root, 'delta.md');
  const rMd = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', mdOut, '--format', 'markdown'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(rMd.status, 0, rMd.stderr);
  const md = fs.readFileSync(mdOut, 'utf8');
  assert.match(md, /HYPOTHETICAL/);
  assert.match(md, /edge:1.*HYPOTHETICAL/);
});

test('dataflow scenario apply: an operation with an unrecognized kind exits 2 with a validateScenario error on stderr', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [{ kind: 'not_a_real_kind' }] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unrecognized operation kind/);
});

test('dataflow scenario apply: missing --output exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow scenario apply: missing graph -> exit 1, one of loadSignedGraph\'s own messages', () => {
  const root = _mkTmpProject();
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
});
