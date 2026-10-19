// Contract test for blast-radius assessment (docs/security-graph/blast-radius.md, "Contract").
//
// The page is the contract. This test reads its tables and holds the record and the command to them in both directions: a field or
// value the output has that the page does not list fails, and one the page lists that the output lacks fails. It also pins the
// differential bench that gates the capability, and proves the bench can fail by showing that a perturbed record is caught.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { computeImpactAssessment } from '../../src/lineage/impact-engine.js';
import { validateImpactAssessment, IMPACT_TARGET_KINDS, IMPACT_SCOPE_VALUES, IMPACT_TRACE_KINDS } from '../../src/lineage/impact-assessment.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';
import { mkTestTmp } from '../helpers/tmp.js';
import { makeGraph, reference, compare, measure } from '../../../bench/blast-radius/runner.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const REPO = path.resolve(SCANNER, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const PAGE = fs.readFileSync(path.join(REPO, 'docs', 'security-graph', 'blast-radius.md'), 'utf8');
const BASELINE = JSON.parse(fs.readFileSync(path.join(REPO, 'bench', 'blast-radius', 'BASELINE.json'), 'utf8'));

function rowsUnder(heading) {
  const lines = PAGE.split('\n');
  const at = lines.findIndex(l => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, `the page has no "${heading}" table`);
  const rows = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('## ')) break;
    const m = /^\| `([^`]+)` \| (.*) \|$/.exec(lines[i]);
    if (m) rows.push([m[1], m[2]]);
  }
  assert.ok(rows.length, `the "${heading}" table is empty`);
  return rows;
}
const DOC_FIELDS = rowsUnder('Record fields').map(r => r[0]);
const DOC_EXITS = rowsUnder('Exit codes').map(r => r[0]);

const g = makeGraph(7);
const rec = (t) => computeImpactAssessment(g, t, { generatedAt: '2026-01-01T00:00:00.000Z' });

test('contract: the record has exactly the documented fields, for every target kind', () => {
  for (const t of [g.nodes[0].id, g.edges[0].id, g.flows[0].id, g.dataElements[0].id]) {
    assert.deepEqual(Object.keys(rec(t)).sort(), [...DOC_FIELDS].sort(), t);
  }
});

test('contract: a field added to or dropped from the record is caught by the same comparison', () => {
  const r = rec(g.nodes[0].id);
  assert.notDeepEqual(Object.keys({ ...r, extra: 1 }).sort(), [...DOC_FIELDS].sort());
  const { scope, ...rest } = r;
  assert.notDeepEqual(Object.keys(rest).sort(), [...DOC_FIELDS].sort());
  assert.equal(scope, 'possible');
});

test('contract: the documented enums are the implementation\'s enums, and node targets are topology_reachable, the rest flow_restricted', () => {
  assert.deepEqual(IMPACT_TARGET_KINDS, ['node', 'edge', 'flow', 'dataElement']);
  assert.deepEqual(IMPACT_SCOPE_VALUES, ['possible', 'observed']);
  assert.deepEqual(IMPACT_TRACE_KINDS, ['topology_reachable', 'flow_restricted']);
  for (const w of [...IMPACT_TARGET_KINDS, ...IMPACT_SCOPE_VALUES, ...IMPACT_TRACE_KINDS]) assert.ok(PAGE.includes(`\`${w}\``), `${w} is on the page`);
  assert.equal(rec(g.nodes[0].id).traceKind, 'topology_reachable');
  for (const t of [g.edges[0].id, g.flows[0].id, g.dataElements[0].id]) assert.equal(rec(t).traceKind, 'flow_restricted');
  assert.equal(rec(g.nodes[0].id).scope, 'possible');
});

test('contract: every record passes the schema validator, and an invalid one does not', () => {
  assert.equal(validateImpactAssessment(rec(g.nodes[0].id)).valid, true);
  assert.equal(validateImpactAssessment({ ...rec(g.nodes[0].id), scope: 'certain' }).valid, false);
  assert.equal(validateImpactAssessment({ ...rec(g.nodes[0].id), affectedNodeIds: 'n1' }).valid, false);
});

test('contract: an id that is well formed but absent returns empty arrays, never a phantom node', () => {
  for (const t of ['node:missing', 'edge:missing', 'flow:missing', 'data:missing']) {
    const r = rec(t);
    assert.deepEqual([r.affectedNodeIds, r.affectedEdgeIds, r.affectedDataClasses], [[], [], []], t);
  }
});

test('contract: a target with no recognized prefix, and a malformed graph, throw distinguishable errors', () => {
  assert.throws(() => computeImpactAssessment(g, 'banana'), /no recognized prefix/);
  assert.throws(() => computeImpactAssessment({ nodes: [] }, 'node:a'), /malformed graph/);
});

test('contract: the independent reference agrees on every target of a seeded graph, and a perturbed record is caught', () => {
  for (const t of [...g.nodes.map(n => n.id), ...g.edges.map(e => e.id), ...g.flows.map(f => f.id), ...g.dataElements.map(d => d.id)]) {
    const ok = compare(rec(t), reference(g, t));
    assert.deepEqual(ok, { nodes: true, edges: true, classes: true, recipients: true }, t);
  }
  const t = g.nodes.find(n => rec(n.id).affectedNodeIds.length > 1).id;
  const good = rec(t);
  assert.equal(compare({ ...good, affectedNodeIds: good.affectedNodeIds.slice(1) }, reference(g, t)).nodes, false, 'a dropped node is caught');
  assert.equal(compare({ ...good, affectedNodeIds: [...good.affectedNodeIds, 'node:phantom'] }, reference(g, t)).nodes, false, 'a phantom node is caught');
  assert.equal(compare({ ...good, affectedDataClasses: [...good.affectedDataClasses, 'NOT_A_CLASS'] }, reference(g, t)).classes, false, 'a spurious data class is caught');
});

test('contract: the bench result is the recorded baseline, and the page quotes its figures', () => {
  const m = measure();
  const strip = JSON.parse(JSON.stringify({ ...m, disagreements: undefined }));
  assert.deepEqual(strip, BASELINE);
  assert.ok(PAGE.includes(`${BASELINE.total.graphs} seeded graphs (${BASELINE.total.targets} targets)`), 'the page states the bench size');
  assert.equal(BASELINE.total.nodesAgree, BASELINE.total.targets);
  assert.equal(BASELINE.total.phantomNodes, 0);
});

// ----------------------------------------------------------------------------------------------- the command
function project() {
  const root = mkTestTmp('agsec-blast-contract-');
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  const graph = { schemaVersion: '1.0.0', generatedAt: '1970-01-01T00:00:00.000Z', scope: { source: 'fixture' }, scanHealth: {}, controls: [], policies: [], evidence: [], limitations: [], extensions: {}, transformations: [], ...g };
  const p = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const body = JSON.stringify(graph, null, 2);
  fs.writeFileSync(p, body);
  fs.writeFileSync(p + '.sig', signLastScan(body));
  return { root, p, body };
}
const cli = (root, ...a) => spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, ...a], { encoding: 'utf8' });

test('contract: the command exits with exactly the documented codes (0, 1, 2) and writes the documented record', () => {
  assert.deepEqual(DOC_EXITS.sort(), ['0', '1', '2']);
  const { root, p } = project();
  const out = path.join(root, 'out.json');
  const ok = cli(root, '--target', g.nodes[0].id, '--output', out);
  assert.equal(ok.status, 0, ok.stderr);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(out, 'utf8'))).sort(), [...DOC_FIELDS].sort());
  assert.equal(cli(root, '--output', out).status, 2, 'missing --target');
  assert.equal(cli(root, '--target', g.nodes[0].id).status, 2, 'missing --output');
  assert.equal(cli(root, '--target', 'banana', '--output', out).status, 2, 'unrecognized prefix');
  assert.equal(cli(root, '--target', g.nodes[0].id, '--output', out, '--format', 'xml').status, 2, 'bad format');
  fs.rmSync(p);
  assert.equal(cli(root, '--target', g.nodes[0].id, '--output', out).status, 1, 'no graph');
});
