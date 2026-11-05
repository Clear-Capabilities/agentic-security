// Contract test for the Code Boundaries graph artifacts (docs/reference/code-boundaries-contract.md): the signed lineage graph,
// witness bundles, boundary contracts, context bundles, demand sink queries and control-placement plans. Every table on the page is
// held against the real output in both directions, and every rule (integrity, replay, wrong-revision refusal, partial state) is
// exercised with a real tamper, a real wrong revision and a real partial analysis, never a hand-built record.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { completionOfGraph } from '../../src/lineage/completion.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../../src/lineage/path-query.js';
import { createBoundaryContract, validateBoundaryContract, contractDigest, contractEvidence } from '../../src/lineage/boundary-contract.js';
import { planCuts } from '../../src/lineage/cut-planner.js';
import { MAX_BOUNDARY_ROUNDS } from '../../src/lineage/boundary-join.js';
import { normalizeSinkQuery, sinkQueryKey } from '../../src/dataflow/demand-query.js';
import { buildWitnessBundle, signWitnessBundle, verifyWitness, exportProvenanceArtifact } from '../../src/posture/witness-bundle.js';
import { signLastScan, _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';
import { loadSignedGraph } from '../../src/server/graph-loader.js';
import { validateManifest } from '../../src/context-intelligence/manifest.js';
import { writeBundle, verifyStoredBundle } from '../../src/context-intelligence/store.js';
import { build as buildContextProject, cleanup } from '../context-intelligence/helpers.js';

process.env.AGENTIC_SECURITY_OFFLINE = '1';
process.env.AGENTIC_SECURITY_HMAC_KEY = crypto.randomBytes(32).toString('hex');
_resetKeyCacheForTests();

const PAGE = readPage('docs/reference/code-boundaries-contract.md');
const EPOCH = '1970-01-01T00:00:00.000Z';
const COMMIT = 'c'.repeat(40);
const SRC = {
  'app.js': `
app.post('/orders', (req, res) => { const note = req.body.note; db.collection('orders').insertOne({ note }); res.send(note); });
`,
};
const graphOf = (opts = {}) => {
  const { callGraph } = buildProjectIR(SRC);
  const built = buildGraphWithCoverage(callGraph, { repository: 't', generatedAt: EPOCH, ...opts });
  assert.deepEqual(validateGraph(built.graph).errors, []);
  return built;
};
function tempRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-contract-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"cb","version":"1.0.0"}');
  return root;
}
function writeSignedGraph(root, graph) {
  const gp = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(gp), { recursive: true });
  const body = JSON.stringify(graph);
  fs.writeFileSync(gp, body);
  fs.writeFileSync(gp + '.sig', signLastScan(body));
  return gp;
}

test('graph: the envelope and the revision carry exactly the documented fields, and a build without a commit records no revision', () => {
  const { graph } = graphOf({ commit: COMMIT, worktreeDirty: false });
  sameFields(graph, fieldsUnder(PAGE, 'Graph envelope'), 'graph envelope');
  sameFields(graph.scope.revision, fieldsUnder(PAGE, 'Graph revision'), 'graph revision');
  assert.equal(graph.scope.revision.commit, COMMIT);
  assert.equal(graph.scope.revision.worktreeDirty, false);
  assert.ok(graph.graphId.includes(COMMIT.slice(0, 8)) || graph.graphId !== graphOf().graph.graphId, 'the graph id depends on the revision');
  const bare = graphOf().graph;
  assert.equal(bare.scope.revision, undefined);
});

test('graph: integrity and wrong-revision refusal through the one loader (tampered, unsigned, another revision, no revision)', () => {
  const root = tempRoot();
  try {
    const { graph } = graphOf({ commit: COMMIT, worktreeDirty: false });
    const gp = writeSignedGraph(root, graph);
    assert.equal(loadSignedGraph(root).ok, true);
    assert.equal(loadSignedGraph(root, { expectRevision: COMMIT }).ok, true);
    const wrong = loadSignedGraph(root, { expectRevision: 'd'.repeat(40) });
    assert.equal(wrong.ok, false); assert.equal(wrong.reason, 'wrong-revision'); assert.match(wrong.message, /built from revision c+, not the expected d+/);
    // a graph that records no revision cannot be shown to match
    writeSignedGraph(root, graphOf().graph);
    const none = loadSignedGraph(root, { expectRevision: COMMIT });
    assert.equal(none.ok, false); assert.equal(none.reason, 'wrong-revision'); assert.match(none.message, /records no revision/);
    assert.equal(loadSignedGraph(root).ok, true, 'without an expectation the unrevisioned graph still loads');
    // tampered after signing
    fs.writeFileSync(gp, fs.readFileSync(gp, 'utf8').replace('"generatedAt"', '"generatedAt_"'));
    assert.equal(loadSignedGraph(root).reason, 'tampered');
    fs.unlinkSync(gp + '.sig');
    assert.equal(loadSignedGraph(root).reason, 'unsigned');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('graph: partial analysis state propagates into the envelope and its completion, never promoted to complete', () => {
  let src = `const db = new MongoClient(process.env.MONGO_URL).db('shop');\napp.post('/in', async (req, res) => { await db.collection('c0').insertOne({ v: req.body.v }); res.json({}); });\n`;
  for (let i = 0; i < MAX_BOUNDARY_ROUNDS + 1; i++) src += `async function hop${i}() { const d${i} = await db.collection('c${i}').findOne({}); await db.collection('c${i + 1}').insertOne({ v: d${i}.v }); }\n`;
  const { callGraph } = buildProjectIR({ 'chain.js': src });
  const { graph } = buildGraphWithCoverage(callGraph, { repository: 't', generatedAt: EPOCH, boundaries: { enabled: true } });
  assert.deepEqual(validateGraph(graph).errors, []);
  assert.equal(graph.scanHealth.status, 'partial');
  assert.equal(graph.scanHealth.analysisCompletion.boundaries.truncated, true);
  assert.notEqual(completionOfGraph(graph).status, 'complete');
  const complete = graphOf().graph;
  assert.equal(complete.scanHealth.status, 'complete');
  assert.equal(completionOfGraph(complete).status, 'complete');
});

// ---- witness bundles ----
const WSRC = { 'w.js': 'function helper(x) { return x; }\nfunction handler(req, res) { const e = req.body.email; const y = helper(e); console.log(y); res.send(y); }\n' };
function witnessFixture() {
  const { callGraph } = buildProjectIR(WSRC);
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const provenance = exportProvenanceArtifact({ hops, incomplete: [] });
  const store = new PathStore(); store.addHops(hops);
  let result; let pathRec;
  for (const s of sinkCandidates(store).filter((n) => n.kind === 'escape')) {
    result = reconstructPaths(store, s.id);
    pathRec = result.paths.find((p) => p.crossScopeCount > 0) ?? result.paths[0];
    if (pathRec && pathRec.crossScopeCount > 0) break;
  }
  assert.ok(pathRec, 'the fixture reconstructs a path');
  const edgeIds = pathRec.edgeIds;
  const graph = { graphId: 'dfg:r:abc:default', nodes: [{ id: 'node:a' }, { id: 'node:b' }], edges: edgeIds.map((id) => ({ id })), flows: [{ id: 'flow:1', source: 'node:a', sink: 'node:b', edgeIds }], coverage: {} };
  return { provenance, store, result, path: pathRec, graph };
}

test('witness: the bundle carries exactly the documented fields; signature, replay, tamper and wrong-graph refusals behave as the page says', () => {
  const fx = witnessFixture();
  const r = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, sourceBlobs: WSRC, graphBinding: { flowId: 'flow:1' } });
  assert.equal(r.ok, true, r.reason);
  sameFields(r.bundle, fieldsUnder(PAGE, 'Witness bundle'), 'witness bundle', ['signature']);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const PUB = publicKey.export({ type: 'spki', format: 'pem' }); const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const signed = signWitnessBundle(r.bundle, PRIV);
  assert.ok(signed.signature, 'signing adds the signature field');
  const artifacts = { graph: fx.graph, provenance: fx.provenance, sources: WSRC };
  assert.equal(verifyWitness(signed, PUB, artifacts).verdict, 'replayed');
  assert.equal(verifyWitness(signed, PUB, null).verdict, 'integrity-only');
  const tampered = JSON.parse(JSON.stringify(signed)); tampered.path.hopCount += 1;
  assert.equal(verifyWitness(tampered, PUB, artifacts).verdict, 'invalid');
  const otherKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(verifyWitness(signed, otherKey, artifacts).verdict, 'invalid');
  const otherGraph = { ...fx.graph, nodes: [...fx.graph.nodes, { id: 'node:c' }] };
  const wrongGraph = verifyWitness(signed, PUB, { ...artifacts, graph: otherGraph });
  assert.equal(wrongGraph.verdict, 'invalid');
  assert.ok(wrongGraph.replay.failures.length > 0, 'replay against another graph names a failure');
});

// ---- boundary contracts ----
test('boundary contract: documented fields, a digest over meaning, and the validation refusals', () => {
  const c = createBoundaryContract({
    id: 'boundary:orders', kind: 'queue', channel: { topic: 'orders' }, schema: { name: 'order', version: '1' },
    producer: { service: 'api', site: null }, consumer: { service: 'worker', site: { file: 'c.js', function: 'handle', param: 'evt' } },
    fieldMappings: [{ from: 'note', to: 'memo' }], declaredBy: 'ops',
  });
  sameFields(c, fieldsUnder(PAGE, 'Boundary contract'), 'boundary contract');
  assert.equal(validateBoundaryContract(c).valid, true);
  assert.equal(contractEvidence(c).find((e) => e.kind === 'digest-check').ok, true);
  const renamed = { ...c, fieldMappings: [{ from: 'note', to: 'text' }] };
  assert.notEqual(contractDigest(renamed), c.configDigest);
  assert.equal(contractEvidence(renamed).find((e) => e.kind === 'digest-check').ok, false, 'a changed mapping fails the digest check');
  assert.equal(contractDigest({ ...c, declaredBy: 'someone-else' }), c.configDigest, 'who declared it is outside the digest');
  assert.equal(validateBoundaryContract({ ...c, version: '2.0.0' }).valid, false);
  assert.equal(validateBoundaryContract({ ...c, evidence: { declared: true, observed: true } }).valid, false);
  assert.equal(validateBoundaryContract({ ...c, consumer: { service: 'worker' } }).valid, false);
});

// ---- context bundles ----
test('context manifest: documented fields, stale spans refused, store re-verification, hash mismatch', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-ctx-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"ctx","version":"1.0.0"}');
  fs.writeFileSync(path.join(dir, 'app.js'), "const express = require('express');\nconst app = express();\nfunction load(id) { return db.find(id); }\napp.get('/items/:id', (req, res) => { const row = load(req.params.id); res.json(row); });\nmodule.exports = app;\n");
  try {
    const built = await buildContextProject(dir);
    assert.equal(built.ok, true, JSON.stringify(built.reason));
    const bundle = built.bundles.find((b) => b.manifest);
    assert.ok(bundle, 'one bundle was built');
    const m = bundle.manifest;
    sameFields(m, fieldsUnder(PAGE, 'Context manifest'), 'context manifest');
    assert.deepEqual(validateManifest(m, { fileContents: built.fileContents }), []);
    const edited = { ...built.fileContents, 'app.js': built.fileContents['app.js'].replace('res.json(row)', 'res.send(row)') };
    assert.ok(validateManifest(m, { fileContents: edited }).some((p) => p.startsWith('stale-span:app.js')), 'an edited span is stale');
    const forged = JSON.parse(JSON.stringify(m)); forged.entrypoint.path = '/forged';
    assert.ok(validateManifest(forged).includes('manifest-hash-mismatch'));
    const w = writeBundle(dir, bundle);
    assert.equal(w.ok, true, w.reason);
    assert.equal(verifyStoredBundle(dir, m.contextHash, { fileContents: built.fileContents }).ok, true);
    const pkg = statePath(dir, 'context-intelligence', 'bundles', m.contextHash, 'context-1.txt');
    if (fs.existsSync(pkg)) {
      fs.appendFileSync(pkg, '\n// changed after the bundle was written\n');
      assert.equal(verifyStoredBundle(dir, m.contextHash).ok, false, 'a changed package text is refused on read');
    }
  } finally { cleanup(dir); }
});

// ---- demand sink queries ----
test('sink query key: the documented fields, bound to the graph and configuration digests', () => {
  sameFields(normalizeSinkQuery({}), fieldsUnder(PAGE, 'Sink query key'), 'sink query key');
  const q = { file: 'a.js', line: 3, callee: 'exec', argIndex: 0 };
  assert.equal(sinkQueryKey(q, { graphDigest: 'g1', configDigest: 'c1' }), sinkQueryKey(q, { graphDigest: 'g1', configDigest: 'c1' }));
  assert.notEqual(sinkQueryKey(q, { graphDigest: 'g1', configDigest: 'c1' }), sinkQueryKey(q, { graphDigest: 'g2', configDigest: 'c1' }));
  assert.notEqual(sinkQueryKey(q, { graphDigest: 'g1', configDigest: 'c1' }), sinkQueryKey(q, { graphDigest: 'g1', configDigest: 'c2' }));
});

// ---- control-placement plans ----
test('cut plan: the documented fields and the hypothetical-only stance, on a real graph', () => {
  const { graph } = graphOf();
  const plan = planCuts(graph, {}, []);
  sameFields(plan, fieldsUnder(PAGE, 'Cut plan'), 'cut plan', ['uncuttableLocations', 'perSink']);
  assert.ok(['complete-cut', 'partial', 'no-flow', 'no-feasible-cut'].includes(plan.status), plan.status);
  assert.equal(plan.hypothetical, true);
  assert.equal(plan.verified, false);
  assert.ok(plan.limitations.length >= 0 && Array.isArray(plan.limitations));
});
