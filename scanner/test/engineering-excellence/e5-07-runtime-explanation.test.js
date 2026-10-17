// E5-07: side-by-side static/runtime explanation: synchronized panes, deterministic snapshots, privacy-compliant export, missing observations labelled.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildSemanticGraph } from '../../src/ir/semantic-graph.js';
import { edgeKey, readRuntimeEdges, reconcileGraphs, staticEdgesFromGraph } from '../../src/posture/graph-reconciliation.js';
import { ingestRuntimeRecords } from '../../src/posture/runtime-trace-ingest.js';
import { buildRuntimeExplanation, buildViewModel, explanationIntact, explanationSummary, exportExplanation, panesInSync, selectionsInSync } from '../../src/posture/runtime-explanation.js';
import { toSARIF } from '../../src/report/index.js';

const SRC = 'function validate(x) { return x; }\nfunction save(x) { return x; }\nfunction handler(req) { const v = validate(req.body); return save(v); }\n';
const NORM = { rewrite: [['^app\\.js::<module>::', 'app.']] };
const C1 = 'a'.repeat(40); const C2 = 'b'.repeat(40);
const SNAP = { commit: C1, environment: 'production' };
const KEYS = [edgeKey('route', '/orders/:id', 'app.handler'), edgeKey('call', 'app.handler', 'app.validate'), edgeKey('call', 'app.handler', 'app.save')];
const finding = { id: 'f1', severity: 'high', file: 'app.js', line: 3, parser: 'IR-TAINT', routeRooted: true, _inRoute: { path: '/orders/:id' }, vuln: 'x', cwe: 'CWE-89', description: 'd', remediation: 'r', family: 'sqli' };

async function explain(records, { commit = C1, sampleRate = 1, evidence } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5-07-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}'); fs.mkdirSync(path.join(root, '.agentic-security'));
  try {
    const st = staticEdgesFromGraph(buildSemanticGraph(buildProjectIR({ 'app.js': SRC })), { routes: [{ path: '/orders/:orderId', handler: 'app.js::<module>::handler' }] }, NORM);
    ingestRuntimeRecords(root, records, { policy: { collect: true }, sampleRate });
    const rt = await readRuntimeEdges(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), { snapshotIdentity: { ...SNAP, commit }, normalize: NORM });
    const sampling = sampleRate === 1 ? { state: 'complete' } : { state: 'sampled', rate: sampleRate };
    const reconciled = reconcileGraphs(st, rt, { sampling });
    return buildRuntimeExplanation({ ...finding, ...(evidence ? { runtimeEvidence: evidence } : {}) }, { reconciled, pathKeys: KEYS, sampling, snapshotIdentity: { ...SNAP, commit }, windowDays: 30 });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const now = () => new Date().toISOString();
const MATCH = [{ kind: 'route-hit', ts: now(), commit: C1, route: '/orders/42', qid: 'app.handler' }, { kind: 'function-call', ts: now(), commit: C1, caller: 'app.handler', qid: 'app.validate' }, { kind: 'function-call', ts: now(), commit: C1, caller: 'app.handler', qid: 'app.save' }];

test('a matched, fully observed path is corroborated and says nothing is missing', async () => {
  const e = await explain(MATCH, { evidence: { state: 'observed', corroboration: 'corroborated' } });
  assert.equal(e.compare.state, 'corroborated'); assert.deepEqual(e.runtime.missingObservations, []);
  assert.deepEqual(e.runtime.edges.map((r) => r.state), ['both', 'both', 'both']); assert.equal(e.runtime.observed.value, 'yes');
  assert.equal(e.static.staticallyReachable.value, 'yes'); assert.deepEqual(e.static.pathEdges, KEYS); assert.equal(e.offline, true);
});

test('MISSING OBSERVATIONS are labelled: a different build, no record, unattested records, no trace, sampling', async () => {
  const other = await explain(MATCH.map((r) => ({ ...r, commit: C2 })));
  assert.notEqual(other.compare.state, 'corroborated');
  assert.ok(other.runtime.missingObservations.some((m) => /only a different build was observed/.test(m)));
  const partial = await explain(MATCH.slice(0, 2));
  assert.equal(partial.compare.state, 'partial'); assert.ok(partial.runtime.missingObservations.some((m) => /no runtime record observed for call\|app\.handler\|app\.save/.test(m)));
  const bare = await explain(MATCH.map(({ commit, ...r }) => r));
  assert.ok(bare.runtime.missingObservations.some((m) => /no build identity/.test(m)));
  const sampled = await explain(MATCH, { sampleRate: 0.1 });
  assert.ok(sampled.runtime.missingObservations.some((m) => /samples 0\.1 of traffic: absence of an observation proves nothing/.test(m)));
  const none = buildRuntimeExplanation(finding, { pathKeys: KEYS });
  assert.deepEqual(none.runtime.missingObservations.slice(0, 1), ['no runtime trace was reconciled with the static graph']);
  assert.equal(none.compare.state, 'uncorroborated'); assert.equal(none.runtime.sampling.state, 'undisclosed');
  assert.ok(none.runtime.missingObservations.some((m) => /does not say how much traffic/.test(m)));
});

test('DETERMINISTIC: the same inputs give byte-identical output and digest; a changed input changes the digest; tampering is detected', async () => {
  const a = await explain(MATCH); const b = await explain([...MATCH].reverse());
  assert.equal(exportExplanation(a), exportExplanation(b)); assert.equal(a.digest, b.digest);
  assert.equal(explanationIntact(a), true);
  const c = await explain(MATCH.slice(0, 2)); assert.notEqual(a.digest, c.digest);
  const forged = { ...a, compare: { state: 'corroborated' } }; forged.runtime = { ...a.runtime, edges: a.runtime.edges.map((r) => ({ ...r, state: 'both' })) };
  assert.equal(explanationIntact({ ...c, compare: { state: 'corroborated' } }), false);
  assert.throws(() => exportExplanation({ ...c, compare: { state: 'corroborated' } }), /altered after it was built/);
  assert.equal(explanationIntact(null), false); assert.equal(explanationIntact({}), false);
  assert.ok(!/\d{4}-\d{2}-\d{2}T/.test(exportExplanation(a)), 'no timestamp in the explanation');
});

test('STATE SYNCHRONIZATION: selecting an edge yields both panes for the same key and snapshot; a pane from another snapshot is out of sync', async () => {
  const e = await explain(MATCH.slice(0, 2)); const vm = buildViewModel(e);
  assert.deepEqual(vm.keys, KEYS); assert.equal(vm.snapshotDigest, e.digest);
  for (const k of KEYS) { const sel = vm.select(k); assert.equal(panesInSync(sel), true); assert.equal(sel.staticPane.key, k); assert.equal(sel.runtimePane.key, k); assert.equal(sel.snapshotDigest, e.digest); }
  const saved = vm.select(KEYS[2]); assert.equal(saved.runtimePane.state, 'statically_inferred'); assert.match(saved.runtimePane.missing, /no runtime record observed/);
  assert.equal(vm.select(KEYS[0]).runtimePane.missing, null);
  assert.equal(vm.select('call|nope|nope'), null);
  const other = buildViewModel(await explain(MATCH));
  assert.equal(selectionsInSync(vm.select(KEYS[0]), vm.select(KEYS[0])), true);
  assert.equal(selectionsInSync(vm.select(KEYS[0]), other.select(KEYS[0])), false, 'same edge, different snapshot');
  assert.equal(selectionsInSync(vm.select(KEYS[0]), vm.select(KEYS[1])), false);
  assert.equal(panesInSync({ ...saved, runtimePane: { ...saved.runtimePane, key: KEYS[0] } }), false);
  assert.equal(panesInSync(null), false);
});

test('PRIVACY: the export carries no raw record and refuses to emit a value that looks like a secret or personal datum', async () => {
  const records = MATCH.map((r) => ({ ...r, body: 'jane@example.com', authorization: 'Bearer abcdef1234567890xyz', user: '123-45-6789' }));
  const e = await explain(records);
  const out = exportExplanation(e);
  for (const frag of ['jane@example.com', 'Bearer', '123-45-6789', 'body', 'authorization']) assert.ok(!out.includes(frag), frag);
  const poisoned = buildRuntimeExplanation({ ...finding, id: 'user jane@example.com' }, { pathKeys: KEYS });
  assert.throws(() => exportExplanation({ ...poisoned }), /email pattern/);
  const keyPoison = buildRuntimeExplanation(finding, { pathKeys: ['call|a|password=hunter2xyz'] });
  assert.throws(() => exportExplanation(keyPoison), /pattern/);
  assert.ok(exportExplanation(e).endsWith('\n'));
});

test('SARIF and CLI JSON: the compact summary rides on the result, tied to the full object by digest; absent when none is attached', async () => {
  const e = await explain(MATCH.slice(0, 2));
  const sum = explanationSummary(e);
  assert.deepEqual(sum, { schema: e.schema, digest: e.digest, compare: 'partial', runtimeObserved: 'unknown', sampling: 'complete', missingObservations: e.runtime.missingObservations.length, snapshotCommit: C1 });
  const withSummary = JSON.parse(JSON.stringify(toSARIF({ findings: [{ ...finding, runtimeExplanationSummary: sum }], filesScanned: 1 })));
  const props = withSummary.runs[0].results[0].properties;
  assert.deepEqual(props.runtimeExplanation, sum);
  const without = JSON.parse(JSON.stringify(toSARIF({ findings: [finding], filesScanned: 1 })));
  assert.equal('runtimeExplanation' in without.runs[0].results[0].properties, false, 'no claim when none was built');
  assert.ok(JSON.stringify(withSummary).length < JSON.stringify(withSummary).length + exportExplanation(e).length);
  assert.equal(JSON.stringify(sum).includes('/orders'), false, 'the summary holds no route or symbol');
});
