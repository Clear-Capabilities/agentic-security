// DAG-10: replayable path witness bundles. Every tamper case below is paired with a control that passes, so
// a rejection cannot come from a malformed fixture. The fixture is real analysis output (parser, seeding,
// field-identity driver, provenance store, bounded reconstruction), not hand-built hops.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { buildProjectIR } from '../src/ir/index.js';
import { planSeeds, seedEntryStateFactory } from '../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../src/lineage/driver.js';
import { PathStore } from '../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../src/lineage/path-query.js';
import { computeGraphDigest } from '../src/lineage/export-json.js';
import {
  buildWitnessBundle, signWitnessBundle, verifyWitness, verifyWitnessSignature, replayWitness, parseWitnessBundle,
  exportProvenanceArtifact, transferModelFingerprints, WITNESS_SCHEMA,
} from '../src/posture/witness-bundle.js';
import { assessRuntimeSupport, bindExploitProofs, sanitizeCausalGroups, EVIDENCE_STATUS_KEYS } from '../src/posture/witness-runtime.js';

const SRC = `
function helper(x) { return x; }
function handler(req, res) {
  const e = req.body.email;
  const y = helper(e);
  console.log(y);
  res.send(y);
}
`;
const SOURCES = { 'app.js': SRC };

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' });
const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });
const clone = (v) => JSON.parse(JSON.stringify(v));

const GRAPH_EDGES = ['edge:aaaaaaaaaaaa', 'edge:bbbbbbbbbbbb', 'edge:cccccccccccc'];

function analyse({ incomplete = [] } = {}) {
  const { callGraph } = buildProjectIR(SOURCES);
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const provenance = exportProvenanceArtifact({ hops, incomplete });
  const store = new PathStore();
  store.addHops(hops);
  for (const u of incomplete) store.markTruncated(u.qid, u.context, u.reasons[0]);
  return { hops, provenance, store };
}

function fixture({ queryOpts = {}, graphExtra = {}, incomplete = [], pick = (r) => r.paths.find((p) => p.crossScopeCount > 0) ?? r.paths[0] } = {}) {
  const { provenance, store } = analyse({ incomplete });
  const sinks = sinkCandidates(store).filter((n) => n.kind === 'escape');
  let result; let path;
  for (const s of sinks) {
    result = reconstructPaths(store, s.id, queryOpts);
    path = pick(result);
    if (path && path.crossScopeCount > 0) break;
  }
  const graph = {
    graphId: 'dfg:r:abc:default',
    nodes: [{ id: 'node:a' }, { id: 'node:b' }],
    edges: GRAPH_EDGES.map((id) => ({ id })),
    flows: [{ id: 'flow:1', source: 'node:a', sink: 'node:b', edgeIds: GRAPH_EDGES }],
    coverage: incomplete.length ? { analysisCompletion: { status: 'partial', incomplete } } : {},
    ...graphExtra,
  };
  return { provenance, store, result, path, graph };
}

function bundleOf(fx, extra = {}) {
  const r = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, sourceBlobs: SOURCES, graphBinding: { flowId: 'flow:1' }, ...extra });
  assert.equal(r.ok, true, r.reason);
  return r.bundle;
}
const artifactsOf = (fx) => ({ graph: fx.graph, provenance: fx.provenance, sources: SOURCES });
const codes = (rep) => rep.failures.map((f) => f.code);

// ---------------------------------------------------------------------------------------------------

test('W1: a bundle replays against its exact artifact set, signed and unsigned, and says what it does not prove', () => {
  const fx = fixture();
  assert.ok(fx.path && fx.path.crossScopeCount > 0, 'fixture must cross a call boundary or the binding checks are vacuous');
  const bundle = bundleOf(fx);
  assert.equal(bundle.schema, WITNESS_SCHEMA);
  const signed = signWitnessBundle(bundle, PRIV);
  const v = verifyWitness(signed, PUB, artifactsOf(fx));
  assert.equal(v.ok, true, JSON.stringify(v.replay.failures));
  assert.equal(v.verdict, 'replayed');
  assert.match(v.statement.doesNotProve, /integrity claim only/);
  assert.match(signed.doesNotProve, /does not prove any transfer model is correct/);
  assert.equal(signed.issuance.independentlyCertified, false);
  assert.equal(replayWitness(bundle, artifactsOf(fx)).ok, true);
  assert.equal(signed.completion.overall, 'complete');
  assert.equal(verifyWitness(signed, PUB, null).verdict, 'integrity-only');
});

test('W2: altering a recorded edge fails the signature, and fails replay even when re-signed', () => {
  const fx = fixture();
  const bundle = bundleOf(fx);
  for (const mutate of [
    (b) => { b.path.edges[1].line = 9999; },
    (b) => { b.path.edges[0].inKind = b.path.edges[0].inKind === 'production' ? 'selection' : 'production'; },
    (b) => { b.path.edges[2].widenReasons = ['injected-widening']; },
    (b) => { [b.path.edges[0], b.path.edges[1]] = [b.path.edges[1], b.path.edges[0]]; },
  ]) {
    const t = clone(signWitnessBundle(bundle, PRIV));
    mutate(t);
    assert.equal(verifyWitnessSignature(t, PUB).ok, false, 'a modified bundle must not verify');
    const resigned = signWitnessBundle((() => { const x = clone(t); delete x.signature; delete x.issuance; return x; })(), PRIV);
    const v = verifyWitness(resigned, PUB, artifactsOf(fx));
    assert.equal(v.ok, false);
    assert.ok(codes(v.replay).some((c) => ['edge-altered', 'edge-derivation', 'edge-missing', 'path-chain'].includes(c)), codes(v.replay).join());
  }
  assert.equal(verifyWitness(signWitnessBundle(bundle, PRIV), PUB, artifactsOf(fx)).ok, true, 'control: the unmodified bundle replays');
});

test('W3: altering or omitting a source blob fails replay', () => {
  const fx = fixture();
  const bundle = signWitnessBundle(bundleOf(fx), PRIV);
  assert.ok(bundle.sources.length >= 1);
  const altered = verifyWitness(bundle, PUB, { ...artifactsOf(fx), sources: { 'app.js': SRC.replace('req.body.email', 'req.body.name') } });
  assert.equal(altered.ok, false);
  assert.ok(codes(altered.replay).includes('source-blob-altered'));
  const omitted = verifyWitness(bundle, PUB, { ...artifactsOf(fx), sources: {} });
  assert.ok(codes(omitted.replay).includes('source-blob-missing'));
  const dropped = clone(bundle); dropped.sources = []; dropped.references.unboundSourceFiles = [];
  assert.ok(codes(replayWitness(dropped, artifactsOf(fx))).includes('source-blob-missing'), 'a bundle that drops its source binding is rejected');
});

test('W4: altering a call-site binding, or the hop stream that carries it, fails replay', () => {
  const fx = fixture();
  const bundle = bundleOf(fx);
  const idx = bundle.path.edges.findIndex((e) => e.crossScope);
  assert.ok(idx >= 0, 'fixture has a cross-scope edge');
  for (const mutate of [
    (b) => { b.path.edges[idx].binding.calleeContext = 'forged-context'; },
    (b) => { b.path.edges[idx].binding.calleeScope = 'app.js::<module>::forged@1'; },
    (b) => { b.path.edges[idx].binding.siteNodeId = 'n999'; },
    (b) => { b.path.edges[idx].binding.direction = b.path.edges[idx].binding.direction === 'call' ? 'return' : 'call'; },
  ]) {
    const t = clone(bundle); mutate(t);
    const rep = replayWitness(t, artifactsOf(fx));
    assert.equal(rep.ok, false);
    assert.ok(codes(rep).some((c) => c === 'binding' || c === 'edge-altered'), codes(rep).join());
  }
  // the carrying hop removed from the export: the digest no longer matches AND the edge is no longer derived
  const prov = clone(fx.provenance);
  prov.hops = prov.hops.filter((h) => h.peerScope == null);
  const rep = replayWitness(bundle, { ...artifactsOf(fx), provenance: prov });
  assert.equal(rep.ok, false);
  assert.ok(codes(rep).includes('provenance-digest'));
  assert.ok(codes(rep).includes('edge-missing'));
  // a hop quietly rewritten to name another callee
  const prov2 = clone(fx.provenance);
  const k = prov2.hops.findIndex((h) => h.peerScope != null);
  prov2.hops[k].peerContext = 'other-context';
  assert.equal(replayWitness(bundle, { ...artifactsOf(fx), provenance: prov2 }).ok, false);
});

test('W5: altering the configuration digest, the configuration, the graph or the transfer-model fingerprint fails replay', () => {
  const fx = fixture();
  const bundle = bundleOf(fx);
  const a = clone(bundle); a.graphRef.analysisConfigDigest = 'sha256:' + '0'.repeat(64);
  assert.ok(codes(replayWitness(a, artifactsOf(fx))).includes('config-digest'));
  const b = clone(bundle); b.config.pathQuery.maxDepth = 3;
  assert.ok(codes(replayWitness(b, artifactsOf(fx))).includes('config-digest'));
  assert.ok(codes(replayWitness(bundle, { ...artifactsOf(fx), config: { other: true } })).includes('config-digest'));
  const g = clone(fx.graph); g.edges.push({ id: 'edge:dddddddddddd' });
  assert.ok(codes(replayWitness(bundle, { ...artifactsOf(fx), graph: g })).includes('graph-digest'));
  const t = clone(bundle); t.transferModels.halfEdgeClassification = 'sha256:' + '1'.repeat(64);
  assert.ok(codes(replayWitness(t, artifactsOf(fx))).includes('transfer-model'));
  assert.deepEqual(transferModelFingerprints(), transferModelFingerprints(), 'fingerprints are deterministic');
  assert.equal(replayWitness(bundle, artifactsOf(fx)).ok, true, 'control');
});

test('W6: a partial witness stays partial through serialization, and cannot be edited or stripped into complete', () => {
  const fx = fixture({ queryOpts: { maxDepth: 2 }, pick: (r) => r.paths[0] });
  assert.equal(fx.path.complete, false, 'fixture path is depth-limited');
  const signed = signWitnessBundle(bundleOf(fx), PRIV);
  assert.equal(signed.completion.overall, 'partial');
  assert.equal(signed.evidence.modeledPath.status, 'connected_partial');
  const round = JSON.parse(JSON.stringify(signed));
  const v = verifyWitness(round, PUB, artifactsOf(fx));
  assert.equal(v.ok, true, JSON.stringify(v.replay.failures));
  assert.equal(round.completion.overall, 'partial');
  assert.equal(v.replay.derived.overall, 'partial');
  assert.equal(v.replay.derived.terminalReason, 'depth-limit');
  // edits
  const e1 = clone(round); e1.completion.overall = 'complete';
  assert.equal(verifyWitnessSignature(e1, PUB).ok, false);
  assert.ok(codes(replayWitness(e1, artifactsOf(fx))).includes('completeness'));
  const e2 = clone(round); e2.completion.path.complete = true; e2.completion.path.terminalReason = 'origin'; e2.path.terminal.reason = 'origin'; e2.completion.overall = 'complete';
  assert.ok(codes(replayWitness(e2, artifactsOf(fx))).includes('completeness'), 'a depth-limited path cannot be relabelled as reaching an origin');
  // a field dropped in transit is invalid, never read as complete
  const e3 = clone(round); delete e3.completion.store;
  assert.equal(parseWitnessBundle(JSON.stringify(e3)).ok, false);
  assert.equal(verifyWitnessSignature(e3, PUB).ok, false);
  assert.equal(replayWitness(e3, artifactsOf(fx)).ok, false);
  const e4 = clone(round); delete e4.completion.path.complete;
  assert.equal(parseWitnessBundle(JSON.stringify(e4)).ok, false);
  assert.equal(parseWitnessBundle(JSON.stringify(round)).ok, true, 'control: the intact partial bundle parses');
});

test('W7: incomplete analysis units travel with the provenance export, so a bundle cannot claim complete over them', () => {
  const probe = fixture();
  const scope = probe.store.getNode(probe.path.nodeIds[0]).scope;
  const context = probe.store.getNode(probe.path.nodeIds[0]).context;
  const incomplete = [{ qid: scope, context, reasons: ['analysis-iteration-budget'] }];
  const fx = fixture({ incomplete });
  const bundle = bundleOf(fx);
  assert.equal(bundle.completion.analysis.status, 'partial');
  assert.equal(bundle.completion.overall, 'partial');
  assert.ok(bundle.path.edges.some((e) => e.truncated), 'truncation marks reach the recorded edges');
  assert.equal(replayWitness(bundle, artifactsOf(fx)).ok, true);
  const lie = clone(bundle); lie.completion.analysis.status = 'complete'; lie.completion.overall = 'complete';
  assert.ok(codes(replayWitness(lie, artifactsOf(fx))).includes('completeness'));
  // a provenance export that omits the marks is not the store the bundle was built from
  const stripped = { ...fx.provenance, truncations: [] }; stripped.digest = exportProvenanceArtifact({ hops: fx.provenance.hops }).digest;
  const r = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: stripped, sourceBlobs: SOURCES });
  assert.equal(r.ok, false);
  assert.match(r.reason, /disagree/);
});

test('W8: the four evidence statuses are separate, exactly four, and cannot be merged into a score', () => {
  const fx = fixture();
  const bundle = signWitnessBundle(bundleOf(fx), PRIV);
  assert.deepEqual(Object.keys(bundle.evidence).sort(), [...EVIDENCE_STATUS_KEYS].sort());
  assert.deepEqual(bundle.evidence, {
    modeledPath: { status: 'connected_complete' }, feasibility: { status: 'not_assessed' },
    runtimeSupport: { status: 'not_consulted' }, exploitProof: { status: 'none' },
  });
  assert.equal(bundle.controlEvidence, null, 'the DAG-04 slot is defined and null until it lands');
  for (const key of ['confidence', 'score', 'overall', 'risk']) {
    const t = clone(bundle); t.evidence[key] = 0.9;
    assert.equal(replayWitness(t, artifactsOf(fx)).ok, false, `evidence.${key} must be rejected`);
  }
  const t2 = clone(bundle); t2.evidence.runtimeSupport = { status: 'path_supported', confidence: 'high' };
  assert.equal(replayWitness(t2, artifactsOf(fx)).ok, false);
  const t3 = clone(bundle); t3.confidence = 0.99;
  assert.equal(verifyWitnessSignature(t3, PUB).ok, false, 'an unknown top-level key is rejected, not ignored');
  assert.equal(JSON.stringify(bundle).match(/"(confidence|score)"\s*:/g), null);
});

test('W9: a control-evidence slot is validated, bound to path edges, and drives only the feasibility status', () => {
  const fx = fixture();
  const edgeId = fx.path.edgeIds[0];
  const ok = bundleOf(fx, { controlEvidence: { status: 'infeasible', predicateRefs: [{ edgeId, ref: 'pred:guard-1' }], controlRefs: [] } });
  assert.equal(ok.evidence.feasibility.status, 'infeasible');
  assert.equal(ok.evidence.runtimeSupport.status, 'not_consulted');
  assert.equal(ok.evidence.modeledPath.status, 'connected_complete', 'feasibility never edits the modeled-path status');
  assert.equal(replayWitness(ok, artifactsOf(fx)).ok, true);
  const bad = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, controlEvidence: { status: 'feasible', predicateRefs: [{ edgeId: 'pedge:nope', ref: 'x' }], controlRefs: [] } });
  assert.equal(bad.ok, false);
});

test('W10: construction bounds are enforced on replay and an empty result is not attested', () => {
  const fx = fixture();
  const bundle = bundleOf(fx);
  assert.ok(codes(replayWitness(bundle, artifactsOf(fx), { bounds: { maxPathEdges: 2 } })).includes('bounds'));
  assert.ok(codes(replayWitness(bundle, artifactsOf(fx), { bounds: { maxHops: 1 } })).includes('bounds'));
  const none = reconstructPaths(fx.store, 'pnode:path:doesnotexist');
  const r = buildWitnessBundle({ result: none, store: fx.store, graph: fx.graph, provenance: fx.provenance });
  assert.equal(r.ok, false, 'no path means nothing to witness; absence is not attested');
});

// ---- runtime support, kept apart from the modeled path ----------------------------------------------

const T = (m) => new Date(Date.UTC(2026, 0, 1, 12, 0, m)).toISOString();
const states = (spec) => ({ evaluated: true, byEdge: Object.fromEntries(Object.entries(spec).map(([k, v]) => [k, { states: v.states, uncertainObservations: v.uncertain ?? 0 }])) });
const OBS = { states: ['RUNTIME_OBSERVED'] };
const group = (over = {}) => ({
  id: 'g1', sessionRef: 'trace-123', environment: 'prod', deploymentRef: 'deploy-7', firstObservedAt: T(0), lastObservedAt: T(2),
  edgeObservations: GRAPH_EDGES.map((edgeId, i) => ({ edgeId, firstObservedAt: T(i), lastObservedAt: T(i), matchConfidence: 'high', matchedEdgeIds: [edgeId], observationIds: [`obs-${i}`] })),
  ...over,
});
const EXPECTED = { environment: 'prod', deploymentRef: 'deploy-7' };
const assess = (edgeStates, causalGroups, expected = EXPECTED) => assessRuntimeSupport({ pathEdgeIds: GRAPH_EDGES, edgeStates, causalGroups, expected });
const allObserved = states(Object.fromEntries(GRAPH_EDGES.map((e) => [e, OBS])));

test('R1: independently observed edges from unrelated traces never yield an end-to-end claim', () => {
  const perEdgeGroups = GRAPH_EDGES.map((edgeId, i) => group({ id: `g${i}`, sessionRef: `trace-${i}`, edgeObservations: [group().edgeObservations[i]] }));
  const a = assess(allObserved, perEdgeGroups);
  assert.equal(a.status, 'edge_partial');
  assert.equal(a.wholePath.supported, false);
  assert.equal(a.observedEdgeIds.length, 3, 'every edge WAS observed; that is not an execution of the path');
  assert.match(a.wholePath.reasons.join(), /edges-not-in-group/);
  assert.equal(assess(allObserved, []).status, 'edge_partial', 'with no causal group at all the answer is still partial');
  assert.equal(assess(allObserved, [group()]).status, 'path_supported', 'control: one compatible group supports the whole path');
});

test('R2: whole-path support needs compatible environment, deployment, window, identity, order and unambiguous mappings', () => {
  const cases = {
    'environment-mismatch': group({ environment: 'staging' }),
    'deployment-mismatch': group({ deploymentRef: 'deploy-8' }),
    'no-session-or-trace-reference': group({ sessionRef: null }),
    'time-window-too-wide': group({ lastObservedAt: T(3600) }),
    'ambiguous-edge-mapping': (() => { const g = group(); g.edgeObservations[1].matchConfidence = 'ambiguous'; return g; })(),
    'ambiguous-edge-mapping ': (() => { const g = group(); g.edgeObservations[1].matchedEdgeIds = [GRAPH_EDGES[1], GRAPH_EDGES[2]]; return g; })(),
    'causal-order-violated': (() => { const g = group(); g.edgeObservations[2].firstObservedAt = T(0); g.edgeObservations[2].lastObservedAt = T(0); g.edgeObservations[1].firstObservedAt = T(2); g.edgeObservations[1].lastObservedAt = T(2); return g; })(),
  };
  for (const [reason, g] of Object.entries(cases)) {
    const a = assess(allObserved, [g]);
    assert.equal(a.status, 'edge_partial', reason);
    assert.ok(a.wholePath.reasons.includes(reason.trim()), `${reason}: ${a.wholePath.reasons.join()}`);
  }
  assert.equal(assess(allObserved, [group({ identityToken: 'idt_0123456789abcdef' })], { ...EXPECTED, identityToken: 'idt_fedcba9876543210' }).status, 'edge_partial', 'a different identity scope');
  assert.equal(assess(allObserved, [group()], { deploymentRef: 'deploy-7' }).status, 'edge_partial', 'an unstated environment cannot be assumed compatible');
  assert.equal(assess(allObserved, [group({ identityToken: 'idt_0123456789abcdef' })], { ...EXPECTED, identityToken: 'idt_0123456789abcdef' }).status, 'path_supported');
});

test('R3: static-only, partial telemetry, complete support, blocked attempt, candidate-only and no-observation stay distinguishable', () => {
  const seen = {
    staticOnly: assess(null, []),
    unevaluated: assess({ evaluated: false, byEdge: {} }, []),
    noObservation: assess(states(Object.fromEntries(GRAPH_EDGES.map((e) => [e, { states: ['RUNTIME_NOT_OBSERVED'] }]))), []),
    candidates: assess(states({ [GRAPH_EDGES[0]]: { states: ['RUNTIME_NOT_OBSERVED'], uncertain: 2 }, [GRAPH_EDGES[1]]: { states: ['RUNTIME_NOT_OBSERVED'] }, [GRAPH_EDGES[2]]: { states: ['RUNTIME_NOT_OBSERVED'] } }), []),
    partial: assess(states({ [GRAPH_EDGES[0]]: OBS, [GRAPH_EDGES[1]]: { states: ['RUNTIME_NOT_OBSERVED'] }, [GRAPH_EDGES[2]]: { states: ['RUNTIME_NOT_OBSERVED'] } }), []),
    supported: assess(allObserved, [group()]),
    blocked: assess(states({ [GRAPH_EDGES[0]]: OBS, [GRAPH_EDGES[1]]: { states: ['RUNTIME_BLOCKED'] }, [GRAPH_EDGES[2]]: { states: ['RUNTIME_NOT_OBSERVED'] } }), [group()]),
  };
  assert.deepEqual(Object.fromEntries(Object.entries(seen).map(([k, v]) => [k, v.status])), {
    staticOnly: 'not_consulted', unevaluated: 'not_consulted', noObservation: 'no_observation_in_window', candidates: 'candidate_only',
    partial: 'edge_partial', supported: 'path_supported', blocked: 'blocked_attempt',
  });
  assert.match(seen.noObservation.statements.join(' '), /not evidence that the path is unreachable or safe/);
  assert.match(seen.blocked.statements.join(' '), /only that this attempt was refused/);
  assert.deepEqual(seen.candidates.candidateEdgeIds, [GRAPH_EDGES[0]], 'low-confidence mappings are listed as candidates, never as observed');
  assert.equal(seen.candidates.observedEdgeIds.length, 0);
  assert.notEqual(seen.noObservation.status, seen.staticOnly.status, 'consulted-and-empty differs from never consulted');
});

test('R4: exploit proof references are bound to sink, value and configuration; stale or mismatched ones are rejected', () => {
  const fx = fixture();
  const base = bundleOf(fx);
  const good = { id: 'proof-1', kind: 'proof', sinkRef: base.query.sinkRef, dataElementId: base.references.field.dataElementId, graphDigest: base.graphRef.digest, analysisConfigDigest: base.graphRef.analysisConfigDigest };
  const withGood = bundleOf(fx, { exploitProofs: [good] });
  assert.equal(withGood.evidence.exploitProof.status, 'bound');
  assert.equal(withGood.exploit.bound[0].executionBacked, true);
  assert.equal(withGood.evidence.runtimeSupport.status, 'not_consulted', 'a proof does not become runtime support');
  assert.equal(replayWitness(withGood, artifactsOf(fx)).ok, true);
  for (const [name, bad, reason] of [
    ['stale graph', { ...good, id: 'p2', graphDigest: 'sha256:' + 'a'.repeat(64) }, 'stale-graph'],
    ['other sink', { ...good, id: 'p3', sinkRef: 'pnode:escape:other' }, 'sink-mismatch'],
    ['other value', { ...good, id: 'p4', dataElementId: 'data:other' }, 'value-mismatch'],
    ['other config', { ...good, id: 'p5', analysisConfigDigest: 'sha256:' + 'b'.repeat(64) }, 'configuration-mismatch'],
    ['unbound', { id: 'p6', kind: 'proof' }, 'unbound'],
  ]) {
    const b = bundleOf(fx, { exploitProofs: [bad] });
    assert.equal(b.evidence.exploitProof.status, 'rejected', name);
    assert.deepEqual(b.exploit.rejected[0].reasons, [reason], name);
    assert.equal(b.exploit.bound.length, 0, `${name}: nothing is silently re-attached`);
  }
  // editing a recorded rejection into a binding fails replay
  const forged = bundleOf(fx, { exploitProofs: [{ ...good, id: 'p2', graphDigest: 'sha256:' + 'a'.repeat(64) }] });
  forged.evidence.exploitProof.status = 'bound'; forged.exploit.status = 'bound';
  assert.equal(replayWitness(forged, artifactsOf(fx)).ok, false);
  assert.equal(bindExploitProofs([], { sinkRef: 'x' }).status, 'none');
});

test('R5: runtime evidence rides in the bundle, replays to the same status, and cannot be upgraded by editing', () => {
  const fx = fixture();
  const runtime = { edgeStates: allObserved, causalGroups: [group()], expected: EXPECTED };
  const b = bundleOf(fx, { runtime });
  assert.equal(b.evidence.runtimeSupport.status, 'path_supported');
  assert.equal(b.evidence.modeledPath.status, 'connected_complete');
  assert.equal(replayWitness(b, artifactsOf(fx)).ok, true);
  const partial = bundleOf(fx, { runtime: { edgeStates: allObserved, causalGroups: [], expected: EXPECTED } });
  assert.equal(partial.evidence.runtimeSupport.status, 'edge_partial');
  const up = clone(partial); up.evidence.runtimeSupport.status = 'path_supported'; up.runtime.assessment.status = 'path_supported';
  assert.equal(replayWitness(up, artifactsOf(fx)).ok, false, 'upgrading partial runtime support to whole-path is rejected');
  const noBinding = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, runtime });
  assert.equal(noBinding.ok, false, 'telemetry maps to graph edges, so runtime evidence needs a flow binding');
});

test('R6: payloads, identities, trace ids and secrets are redacted or pseudonymized; unknown fields are dropped', () => {
  const secret = 'AKIAABCDEFGHIJKLMNOP';
  const fx = fixture();
  const g = group({ sessionRef: 'raw-trace-id-8841', identity: 'alice@example.com', payload: { body: 'card 4111111111111111' }, authorization: 'Bearer abc' });
  g.edgeObservations[0].requestBody = 'ssn 123-45-6789';
  const b = bundleOf(fx, { runtime: { edgeStates: allObserved, causalGroups: [g], expected: { ...EXPECTED, identity: 'alice@example.com' } }, exploitProofs: [{ id: 'p1', kind: 'proof', note: `found key ${secret} in output` }] });
  const text = JSON.stringify(b);
  for (const leaked of ['alice@example.com', 'raw-trace-id-8841', '4111111111111111', '123-45-6789', 'Bearer abc', secret]) assert.ok(!text.includes(leaked), `${leaked} must not appear`);
  assert.match(b.runtime.inputs.causalGroups[0].sessionRef, /^sref_[0-9a-f]{16}$/);
  assert.match(b.runtime.inputs.causalGroups[0].identityToken, /^idt_[0-9a-f]{16}$/);
  assert.equal(b.runtime.inputs.expected.identityToken, b.runtime.inputs.causalGroups[0].identityToken, 'the same identity yields the same token, so scope still compares');
  assert.ok(b.runtime.droppedFields >= 3);
  assert.equal(b.evidence.runtimeSupport.status, 'path_supported');
  assert.equal(replayWitness(b, artifactsOf(fx)).ok, true, 'redaction keeps enough metadata for authorized replay');
  const s = sanitizeCausalGroups([group({ sessionRef: 'raw-1' })]);
  assert.deepEqual(sanitizeCausalGroups(s.groups).groups, s.groups, 'sanitizing is idempotent, which replay relies on');
});

// ---- CLI -----------------------------------------------------------------------------------------------

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'agentic-security.js');

test('C1: verify-attestation dispatches a witness bundle, reports integrity-only without artifacts and replays with them', () => {
  const fx = fixture();
  const signed = signWitnessBundle(bundleOf(fx), PRIV);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'witness-cli-'));
  try {
    const bundleFile = path.join(dir, 'witness.json'); const pubFile = path.join(dir, 'pub.pem'); const artFile = path.join(dir, 'artifacts.json');
    fs.writeFileSync(bundleFile, JSON.stringify(signed)); fs.writeFileSync(pubFile, PUB);
    fs.writeFileSync(artFile, JSON.stringify(artifactsOf(fx)));
    const run = (...a) => spawnSync(process.execPath, [CLI, 'verify-attestation', bundleFile, '--public-key', pubFile, ...a], { encoding: 'utf8' });

    const integrity = run();
    assert.equal(integrity.status, 0, integrity.stderr);
    assert.match(integrity.stdout, /integrity only/i);
    assert.match(integrity.stdout, /does NOT prove/);

    const replayed = run('--witness-artifacts', artFile);
    assert.equal(replayed.status, 0, replayed.stderr + replayed.stdout);
    assert.match(replayed.stdout, /replays against the supplied artifacts/);

    const bad = JSON.parse(fs.readFileSync(artFile, 'utf8')); bad.sources['app.js'] += '\n// edited';
    fs.writeFileSync(artFile, JSON.stringify(bad));
    const failed = run('--witness-artifacts', artFile);
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /source-blob-altered/);

    const t = clone(signed); t.completion.overall = 'complete'; t.path.hopCount = 1;
    fs.writeFileSync(bundleFile, JSON.stringify(t));
    assert.equal(run().status, 1, 'a modified bundle fails the signature');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
