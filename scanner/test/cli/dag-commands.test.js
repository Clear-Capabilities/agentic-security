// DAG capabilities reachable from the real CLI: dataflow view / contracts / sink-query / plan-cuts and witness build|verify.
// Every case runs the real bin against a fixture project in a child process. The completion contract is asserted
// alongside the happy path: partial and unavailable stay what they are, and no output ever allows a negative claim
// that the engine did not earn.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';
import { createBoundaryContract } from '../../src/lineage/boundary-contract.js';
import { mkTestTmp } from '../helpers/tmp.js';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, { env = {}, cwd } = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60_000, cwd, env: { ...process.env, ...env } });
}
function project(files) {
  const root = mkTestTmp('agsec-dag-cli-');
  for (const [f, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    fs.writeFileSync(path.join(root, f), text);
  }
  return root;
}
const json = (r) => JSON.parse(r.stdout);

// ---- signed graph fixture (diamond with a choke point and a cycle) ---------------------------------------------------
const prot = { transit: { verdict: 'not_assessed', evidenceGrade: 'none' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } };
const gnode = (id, kind = 'process') => ({ id, kind, subtype: 'x', destination: null, storeDetail: null, coverageStatus: 'modeled' });
const gedge = (id, from, to) => ({ id, from, to, relationship: 'flows_to', protection: prot });
function writeSignedGraph(root, { complete = true } = {}) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify({
    schemaVersion: '1.0.0', graphId: 'dfg:dag-cli-test', generatedAt: '1970-01-01T00:00:00.000Z',
    scope: { source: 'fixture', repository: 'fixture' }, scanHealth: complete ? { status: 'complete' } : {},
    nodes: [gnode('src', 'source'), gnode('m'), gnode('a'), gnode('b'), gnode('k'), gnode('sink', 'sink')],
    edges: [gedge('e1', 'src', 'm'), gedge('e2', 'm', 'a'), gedge('e3', 'm', 'b'), gedge('e4', 'a', 'k'), gedge('e5', 'b', 'k'), gedge('e6', 'k', 'sink'), gedge('e7', 'k', 'm')],
    dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
    transformations: [],
    flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'src', sink: 'sink', edgeIds: ['e1', 'e2', 'e4', 'e6'], transformationIds: [], alternatePathCount: 1, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
    controls: [], policies: [], evidence: [], coverage: complete ? { analysisCompletion: 'complete' } : {}, limitations: [], extensions: {},
  }, null, 2);
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
}

// ---- dataflow view ---------------------------------------------------------------------------------------------------
test('dataflow view: reports identity, completion and a condensation that keeps the cycle', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root);
  const r = run(['dataflow', 'view', root]);
  assert.equal(r.status, 0, r.stderr);
  const rep = json(r);
  assert.equal(rep.schema, 'agentic-security/graph-view-report@1');
  assert.equal(rep.maturity, 'preview');
  assert.equal(rep.identity.graphKind, 'dataflow');
  assert.equal(rep.condensation.verified, true);
  assert.equal(rep.condensation.isAcyclic, false,'the k <-> m cycle is reported, not removed');
  assert.ok(rep.condensation.cyclicComponentCount >= 1);
  assert.ok(rep.condensation.cyclicComponents.some((c) => c.includes('k') && c.includes('m')));
  assert.equal(rep.completion.negativeClaimAllowed, false);
});

test('dataflow view --node: lists neighbours; a dangling id is invalid, not empty', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root);
  const ok = run(['dataflow', 'view', root, '--node', 'm', '--direction', 'out']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.deepEqual(json(ok).query.outgoing.map((e) => e.to).sort(), ['a', 'b']);
  const bad = run(['dataflow', 'view', root, '--node', 'nope']);
  assert.equal(bad.status, 1);
  assert.equal(json(bad).completion.status, 'invalid');
  const usage = run(['dataflow', 'view', root, '--direction', 'sideways', '--node', 'm']);
  assert.equal(usage.status, 2);
});

test('dataflow view: no signed graph is unavailable (exit 1) with the loader message', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  const r = run(['dataflow', 'view', root]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /No lineage graph found/);
});

// ---- dataflow plan-cuts completion contract --------------------------------------------------------------------------
const cand = (type, id, cost) => ({ location: { type, id }, semantics: type === 'node' ? 'handling' : 'transit_protection', owner: 'team-a', cost });

test('dataflow plan-cuts: a finite cut over a complete graph is complete, hypothetical and never a negative claim', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root);
  const cf = path.join(root, 'cand.json'); const out = path.join(root, 'plan.json');
  fs.writeFileSync(cf, JSON.stringify([cand('node', 'm', 8), cand('node', 'k', 9)]));
  const r = run(['dataflow', 'plan-cuts', root, '--candidates', cf, '--output', out]);
  assert.equal(r.status, 0, r.stderr);
  const plan = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(plan.status, 'complete-cut');
  assert.equal(plan.hypothetical, true);
  assert.equal(plan.verified, false);
  assert.equal(plan.contract.status, 'complete');
  assert.equal(plan.contract.negativeClaimAllowed, false);
  assert.equal(plan.contract.verified, false);
});

test('dataflow plan-cuts: no controllable location is partial; an unknown-completeness graph is partial', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root);
  const cf = path.join(root, 'cand.json'); const out = path.join(root, 'plan.json');
  fs.writeFileSync(cf, JSON.stringify([cand('node', 'a', 5)]));
  assert.equal(run(['dataflow', 'plan-cuts', root, '--candidates', cf, '--output', out]).status, 0);
  const partial = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(partial.contract.status, 'partial');
  assert.ok(partial.contract.reasons.some((x) => /plan-/.test(x)));
  assert.equal(partial.contract.negativeClaimAllowed, false);

  const root2 = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root2, { complete: false });
  fs.writeFileSync(cf, JSON.stringify([cand('node', 'm', 8), cand('node', 'k', 9)]));
  assert.equal(run(['dataflow', 'plan-cuts', root2, '--candidates', cf, '--output', out]).status, 0);
  const unknown = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(unknown.contract.status, 'partial', 'a graph not known complete never yields a complete plan');
});

test('dataflow plan-cuts: a query selecting nothing is no-flow and stays partial (no path is not safety)', () => {
  const root = project({ 'package.json': '{"name":"t"}' });
  writeSignedGraph(root);
  const cf = path.join(root, 'cand.json'); const qf = path.join(root, 'q.json'); const out = path.join(root, 'plan.json');
  fs.writeFileSync(cf, JSON.stringify([cand('node', 'm', 8)]));
  fs.writeFileSync(qf, JSON.stringify({ sources: ['sink'], sinks: ['src'] }));
  assert.equal(run(['dataflow', 'plan-cuts', root, '--candidates', cf, '--query', qf, '--output', out]).status, 0);
  const plan = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(plan.status, 'no-flow');
  assert.equal(plan.contract.status, 'partial');
  assert.ok(plan.contract.reasons.includes('no-modeled-path'));
  assert.equal(plan.contract.negativeClaimAllowed, false);
});

// ---- dataflow contracts ----------------------------------------------------------------------------------------------
const SERVICE_FILES = {
  'gateway/routes.js': `
const express = require('express');
const app = express();
app.post('/orders', (req, res) => {
  producer.send({ topic: 'orders.created', messages: [{ value: JSON.stringify({ customer_id: req.body.customer_id, display_name: req.body.display_name }) }] });
  res.send('ok');
});
`,
  'worker/consumer.js': `
const db = require('./db');
async function handleOrder(evt) {
  const q = "SELECT * FROM orders WHERE customer = '" + evt.customerId + "'";
  db.query(q);
}
async function logName(evt) {
  const label = "SELECT '" + evt.displayName + "'";
  db.query(label);
}
module.exports = { handleOrder, logName };
`,
};
const queueContract = (over = {}) => createBoundaryContract({
  id: 'boundary:orders-created', kind: 'queue', persistence: 'persisted',
  channel: { topic: 'orders.created' }, schema: { name: 'OrderCreated', version: '2' },
  producer: { service: 'gateway', site: { file: 'gateway/routes.js', function: '<module>' }, untrustedFields: ['customer_id', 'display_name'] },
  consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'handleOrder', param: 'evt' } },
  fieldMappings: [{ from: 'customer_id', to: 'customerId' }],
  declaredBy: 'ross@example.test', ...over,
});

test('dataflow contracts: a bound consumer is seeded; the finding is a modeled input, never observed or exploited', () => {
  const root = project(SERVICE_FILES);
  const cf = path.join(root, 'contracts.json');
  fs.writeFileSync(cf, JSON.stringify([queueContract()]));
  const r = run(['dataflow', 'contracts', root, '--contracts', cf]);
  assert.equal(r.status, 0, r.stderr);
  const rep = json(r);
  assert.equal(rep.schema, 'agentic-security/boundary-contracts-report@1');
  assert.ok(['complete', 'partial'].includes(rep.completion.status));
  assert.equal(rep.completion.negativeClaimAllowed, false);
  assert.equal(rep.findings.length, 1);
  const b = rep.findings[0].boundary;
  assert.equal(b.modeledInput, true);
  assert.equal(b.observed, false);
  assert.equal(b.exploited, false);
  assert.ok(rep.findings.every((f) => !/displayName/.test(JSON.stringify(f.boundary.fields))), 'the unmapped sibling field is not attributed');
  assert.equal(rep.coverage.bound, 1);
});

test('dataflow contracts: an unbindable contract is a coverage gap, never a finding, and the run is partial', () => {
  const root = project(SERVICE_FILES);
  const cf = path.join(root, 'contracts.json');
  const ghost = queueContract({ id: 'boundary:ghost', consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'noSuchHandler', param: 'evt' } } });
  fs.writeFileSync(cf, JSON.stringify({ contracts: [ghost] }));
  const r = run(['dataflow', 'contracts', root, '--contracts', cf]);
  const rep = json(r);
  assert.equal(rep.findings.length, 0);
  assert.ok(rep.gaps.some((g) => g.contractId === 'boundary:ghost' && g.side === 'consumer'));
  assert.notEqual(rep.completion.status, 'complete');
  assert.equal(rep.completion.negativeClaimAllowed, false, 'no finding from an unbound contract is not a clean bill');
});

test('dataflow contracts: no contracts file is unavailable (exit 1); a malformed file is a usage error (exit 2)', () => {
  const root = project(SERVICE_FILES);
  const none = run(['dataflow', 'contracts', root]);
  assert.equal(none.status, 1);
  assert.equal(json(none).completion.status, 'unavailable');
  const bad = path.join(root, 'bad.json'); fs.writeFileSync(bad, '{"not":"contracts"}');
  assert.equal(run(['dataflow', 'contracts', root, '--contracts', bad]).status, 2);
});

test('dataflow contracts: reads the default state-dir file when --contracts is omitted', () => {
  const root = project(SERVICE_FILES);
  const fp = statePath(root, 'boundary-contracts.json');
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify([queueContract()]));
  const r = run(['dataflow', 'contracts', root]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(json(r).findings.length, 1);
});

// ---- dataflow sink-query ---------------------------------------------------------------------------------------------
const DIRECT = `const cp = require('child_process');
function handler(req, res) {
  const cmd = req.query.cmd;
  cp.exec(cmd);
  cp.exec('ls -la');
}
function other(req, res) {
  cp.exec('uptime');
}
`;

test('dataflow sink-query: --list enumerates sites, demand finds the tainted one, compare matches full analysis', () => {
  const root = project({ 'app.js': DIRECT });
  const list = run(['dataflow', 'sink-query', root, '--list']);
  assert.equal(list.status, 0, list.stderr);
  assert.ok(json(list).sites.some((s) => s.file === 'app.js' && s.line === 4));

  const hit = run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '4']);
  assert.equal(hit.status, 0, hit.stderr);
  const rep = json(hit);
  assert.equal(rep.mode, 'demand');
  assert.equal(rep.verdict, 'flow-found');
  assert.equal(rep.demand.witness, 'forward-engine-corroborated');
  assert.ok(rep.demand.analyzedFunctions >= 1);
  assert.ok(rep.demand.selectorCoverage.totalFunctions >= 2);

  const cmp = run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '4', '--mode', 'compare']);
  assert.equal(cmp.status, 0, cmp.stderr);
  assert.equal(json(cmp).comparison.equal, true);
});

test('dataflow sink-query: a constant sink never reports "safe"; the verdict vocabulary and negative claim follow the completion', () => {
  const root = project({ 'app.js': DIRECT });
  const r = run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '5']);
  assert.equal(r.status, 0, r.stderr);
  const rep = json(r);
  assert.ok(['no-flow-in-modeled-scope', 'unknown'].includes(rep.verdict), rep.verdict);
  assert.equal(rep.completion.negativeClaimAllowed, rep.verdict === 'no-flow-in-modeled-scope');
  if (rep.completion.negativeClaimAllowed) assert.equal(rep.completion.negativeClaimScope, 'modeled-graph-only');
  assert.doesNotMatch(r.stdout, /"verdict":\s*"safe"/);
});

test('dataflow sink-query: a depth stop with --on-limit partial is partial and never allows a negative claim', () => {
  const lines = ["const cp = require('child_process');", 'function level0(c) {', '  cp.exec(c);', '}'];
  for (let i = 1; i <= 12; i++) lines.push(`function level${i}(c) {`, `  level${i - 1}(c);`, '}');
  const root = project({ 'app.js': lines.join('\n') + '\n' });
  const r = run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '3', '--max-caller-depth', '2', '--on-limit', 'partial']);
  assert.equal(r.status, 0, r.stderr);
  const rep = json(r);
  assert.equal(rep.completion.status, 'partial');
  assert.equal(rep.completion.negativeClaimAllowed, false);
  assert.notEqual(rep.verdict, 'no-flow-in-modeled-scope');
  // the default policy widens to the full function set instead of dropping callers
  const wide = json(run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '3', '--max-caller-depth', '2']));
  assert.ok(wide.demand.fallback && wide.demand.fallback.expandedToFull === true);
});

test('dataflow sink-query: an unknown site is unavailable (exit 1); bad flags are usage errors (exit 2)', () => {
  const root = project({ 'app.js': DIRECT });
  const miss = run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', '999']);
  assert.equal(miss.status, 1);
  const rep = json(miss);
  assert.equal(rep.completion.status, 'unavailable');
  assert.equal(rep.verdict, 'unknown');
  assert.equal(rep.completion.negativeClaimAllowed, false);
  assert.equal(run(['dataflow', 'sink-query', root, '--file', 'app.js']).status, 2);
  assert.equal(run(['dataflow', 'sink-query', root, '--file', 'app.js', '--line', 'x']).status, 2);
  assert.equal(run(['dataflow', 'sink-query', root, '--mode', 'nope', '--list']).status, 2);
});

// ---- witness build | verify ------------------------------------------------------------------------------------------
const WITNESS_SRC = `
function helper(x) { return x; }
function handler(req, res) {
  const e = req.body.email;
  const y = helper(e);
  console.log(y);
  res.send(y);
}
`;

test('witness build then verify: replays offline, and each tamper is rejected', () => {
  const root = project({ 'app.js': WITNESS_SRC });
  const xdg = mkTestTmp('agsec-dag-xdg-');
  const out = path.join(mkTestTmp('agsec-dag-out-'), 'w');
  const env = { XDG_CONFIG_HOME: xdg };
  const b = run(['witness', 'build', root, '--out', out], { env });
  assert.equal(b.status, 0, b.stderr + b.stdout);
  assert.ok(fs.existsSync(path.join(out, 'witness.json')));
  assert.ok(!fs.existsSync(path.join(root, '.agentic-security')), 'building a witness writes nothing into the project');
  const pub = path.join(xdg, 'agentic-security', 'attest-key.pub.pem');
  const base = ['witness', 'verify', path.join(out, 'witness.json'), '--public-key', pub];

  const integrity = run([...base, '--json'], { env });
  assert.equal(integrity.status, 0, integrity.stderr);
  assert.equal(json(integrity).verdict, 'integrity-only');

  const replay = run([...base, '--artifacts', path.join(out, 'artifacts'), '--root', root, '--json'], { env });
  assert.equal(replay.status, 0, replay.stderr + replay.stdout);
  const v = json(replay);
  assert.equal(v.verdict, 'replayed');
  assert.deepEqual(Object.keys(v.evidence).sort(), ['exploitProof', 'feasibility', 'modeledPath', 'runtimeSupport']);
  assert.match(v.statement.doesNotProve, /integrity claim only/);

  // 1. the bundle is edited after signing
  const wp = path.join(out, 'witness.json');
  const doc = JSON.parse(fs.readFileSync(wp, 'utf8'));
  doc.evidence.exploitProof.status = 'bound';
  const forged = path.join(out, 'forged.json'); fs.writeFileSync(forged, JSON.stringify(doc));
  assert.equal(run(['witness', 'verify', forged, '--public-key', pub], { env }).status, 1);

  // 2. a source blob changed since signing
  fs.writeFileSync(path.join(root, 'app.js'), WITNESS_SRC + '\n// edited\n');
  const altered = run([...base, '--artifacts', path.join(out, 'artifacts'), '--root', root], { env });
  assert.equal(altered.status, 1);
  assert.match(altered.stdout, /source-blob-altered/);
  fs.writeFileSync(path.join(root, 'app.js'), WITNESS_SRC);

  // 3. an artifact was swapped
  const prov = path.join(out, 'artifacts', 'provenance.json');
  const pdoc = JSON.parse(fs.readFileSync(prov, 'utf8')); pdoc.hops.pop();
  fs.writeFileSync(prov, JSON.stringify(pdoc));
  const swapped = run([...base, '--artifacts', path.join(out, 'artifacts'), '--root', root], { env });
  assert.equal(swapped.status, 1);

  // 4. the wrong key
  const other = mkTestTmp('agsec-dag-xdg2-');
  const wrong = run(['witness', 'build', root, '--out', path.join(other, 'w')], { env: { XDG_CONFIG_HOME: other } });
  assert.equal(wrong.status, 0, wrong.stderr);
  const wrongKey = run(['witness', 'verify', wp, '--public-key', path.join(other, 'agentic-security', 'attest-key.pub.pem')], { env });
  assert.equal(wrongKey.status, 1);
});

test('witness build: a project with no modeled path is unavailable (exit 1), never an empty "clean" bundle', () => {
  const root = project({ 'app.js': 'function f() { return 1; }\n' });
  const xdg = mkTestTmp('agsec-dag-xdg-');
  const out = path.join(mkTestTmp('agsec-dag-out-'), 'w');
  const r = run(['witness', 'build', root, '--out', out], { env: { XDG_CONFIG_HOME: xdg } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unavailable/);
  assert.match(r.stderr, /not evidence that the software is safe/);
  assert.ok(!fs.existsSync(path.join(out, 'witness.json')));
});

test('witness: usage errors exit 2', () => {
  assert.equal(run(['witness']).status, 2);
  assert.equal(run(['witness', 'build']).status, 2);
  assert.equal(run(['witness', 'verify']).status, 2);
});

// ---- off by default --------------------------------------------------------------------------------------------------
test('a default scan output carries none of the opt-in DAG reports', () => {
  const root = project({ 'app.js': DIRECT });
  const r = run(['scan', root, '--format', 'json'], { env: { NODE_DEBUG: '' } });
  assert.ok(r.status === 0 || r.status === 1 || r.status === 2 || r.status === 3, r.stderr);
  assert.doesNotMatch(r.stdout, /graph-view-report|sink-query-report|boundary-contracts-report|path-witness/);
});
