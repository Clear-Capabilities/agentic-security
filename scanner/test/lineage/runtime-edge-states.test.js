// Edge states, identity tokens and the absent-from-static / identity queries (PRD 2). Hand-built graph, observations and correlation:
// the point is the RULES for when each state may appear, and above all when it may not.
import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveEdgeStates, validateExploitEvidence, runtimeFlowsAbsentFromStatic, identitiesUsingRiskyPaths, EDGE_STATES } from '../../src/lineage/runtime-edge-states.js';
import { makeIdentityTokenizer } from '../../src/lineage/identity-token.js';
import { parseK8sAuditLogObservations, parseHttpAccessLogObservations, parseOtelJsonObservations } from '../../src/lineage/observation-adapters.js';
import { validateObservationAttributes } from '../../src/lineage/runtime-observation.js';

const graph = {
  nodes: [{ id: 'node:a' }, { id: 'node:b' }, { id: 'node:c' }, { id: 'node:d' }],
  edges: ['e1', 'e2', 'e3', 'e4', 'e5', 'e6'].map((n, i) => ({ id: `edge:${n}`, from: 'node:a', to: i < 5 ? 'node:b' : 'node:c' })),
  flows: [
    { id: 'flow:ok', edgeIds: ['edge:e1'], policyVerdict: 'permitted' },
    { id: 'flow:bad', edgeIds: ['edge:e4'], policyVerdict: 'prohibited' },
    { id: 'flow:atk', edgeIds: ['edge:e5'], policyVerdict: 'permitted' },
  ],
};
const obs = (id, edge, over = {}) => ({ id, matchedEdgeIds: [`edge:${edge}`], matchConfidence: 'high', attributes: {}, ...over });
const decision = (d) => ({ 'network.securityDecision': d });
const observations = [
  obs('o1', 'e1', { attributes: decision('allowed') }),
  obs('o2', 'e2', { attributes: decision('denied') }),
  obs('o3', 'e3', { attributes: { ...decision('allowed') } }), obs('o3b', 'e3', { attributes: decision('denied') }),
  obs('o4', 'e4', { attributes: { ...decision('allowed'), 'identity.token': 'idt_aaaaaaaaaaaaaaaa' } }),
  obs('o5', 'e5', { attributes: { ...decision('allowed'), 'identity.token': 'idt_bbbbbbbbbbbbbbbb' } }),
  obs('o6', 'e6', { matchConfidence: 'low' }),
];
const correlation = { evaluated: true, consideredObservationIds: observations.map((o) => o.id), unmatchedObservationIds: [] };
const edgeEv = [{ kind: 'proof', id: 'proof-1', flowId: 'flow:atk' }];
const states = deriveEdgeStates(graph, correlation, observations, { exploitEvidence: edgeEv });

test('with no telemetry consulted every edge is STATIC_ONLY, which is not "nothing seen"', () => {
  const s = deriveEdgeStates(graph, { evaluated: false }, null);
  assert.equal(s.evaluated, false);
  assert.ok(Object.values(s.byEdge).every((e) => e.states.length === 1 && e.states[0] === 'STATIC_ONLY'));
  assert.equal(s.counts.STATIC_ONLY, graph.edges.length);
});

test('each state appears exactly when its rule holds', () => {
  const S = (e) => states.byEdge[`edge:${e}`];
  assert.deepEqual(S('e1').states, ['RUNTIME_OBSERVED']);
  assert.deepEqual(S('e2').states, ['RUNTIME_BLOCKED'], 'only denied: attempted and refused, not observed as completing');
  assert.deepEqual(S('e3').states, ['RUNTIME_OBSERVED', 'RUNTIME_BLOCKED'], 'both allowed and denied traffic');
  assert.deepEqual(S('e4').states, ['RUNTIME_OBSERVED', 'RUNTIME_POLICY_VIOLATION']);
  assert.deepEqual(S('e5').states, ['RUNTIME_OBSERVED', 'RUNTIME_EXPLOIT_CORRELATED']);
  assert.equal(S('e5').primary, 'RUNTIME_EXPLOIT_CORRELATED'); assert.equal(S('e5').exploitEvidence[0].id, 'proof-1');
  assert.deepEqual(S('e6').states, ['RUNTIME_NOT_OBSERVED'], 'a low-confidence observation does not make an edge observed');
  assert.equal(S('e6').uncertainObservations, 1); assert.match(S('e6').note, /not counted/);
  for (const e of Object.values(states.byEdge)) for (const st of e.states) assert.ok(EDGE_STATES.includes(st));
});

test('exploit correlation is never inferred: no evidence, no state, even on a violating observed edge', () => {
  const none = deriveEdgeStates(graph, correlation, observations, {});
  assert.ok(Object.values(none.byEdge).every((e) => !e.states.includes('RUNTIME_EXPLOIT_CORRELATED')));
  const onBlocked = deriveEdgeStates(graph, correlation, observations, { exploitEvidence: [{ kind: 'proof', id: 'p', edgeId: 'edge:e2' }] });
  assert.ok(!onBlocked.byEdge['edge:e2'].states.includes('RUNTIME_EXPLOIT_CORRELATED'), 'a refused path was not exploited');
  const notObserved = deriveEdgeStates(graph, correlation, observations, { exploitEvidence: [{ kind: 'proof', id: 'p', edgeId: 'edge:e6' }] });
  assert.ok(!notObserved.byEdge['edge:e6'].states.includes('RUNTIME_EXPLOIT_CORRELATED'), 'evidence about an edge no one saw is not runtime correlation');
});

test('observations outside the correlation window or environment are not counted', () => {
  const s = deriveEdgeStates(graph, { ...correlation, consideredObservationIds: ['o1'] }, observations);
  assert.deepEqual(s.byEdge['edge:e1'].states, ['RUNTIME_OBSERVED']);
  assert.deepEqual(s.byEdge['edge:e4'].states, ['RUNTIME_NOT_OBSERVED']);
});

test('exploit evidence is validated: unknown kinds, missing targets and ambiguous targets are reported, never trusted', () => {
  const v = validateExploitEvidence([{ kind: 'proof', id: 'a', edgeId: 'edge:x' }, { kind: 'rumour', id: 'b', edgeId: 'x' }, { kind: 'proof', id: 'c' }, { kind: 'proof', id: 'd', edgeId: 'x', flowId: 'y' }, 'nope']);
  assert.equal(v.evidence.length, 1); assert.equal(v.errors.length, 4);
  assert.deepEqual(validateExploitEvidence(null), { evidence: [], errors: [] });
  assert.equal(validateExploitEvidence({}).errors.length, 1);
});

test('runtime flows absent from the static graph: unmatched destinations only, labelled as candidates', () => {
  const o = [{ id: 'placed', matchedNodeIds: ['node:q'], attributes: { 'destination.service': 'OrdersQueue' } }, { id: 'u1', attributes: { 'destination.host': 'shadow.internal', 'destination.port': 443, 'service.name': 'web' }, environment: 'production', firstObservedAt: 't', lastObservedAt: 't', eventCountBand: '1' }, { id: 'u2', attributes: { 'network.securityDecision': 'allowed' } }, { id: 'm1', attributes: { 'destination.host': 'known' } }];
  const r = runtimeFlowsAbsentFromStatic(o, { unmatchedObservationIds: ['placed', 'u1', 'u2'] });
  assert.equal(r.candidates.length, 1, 'a node-placed observation is not absent from the static graph, and one with no destination identifier has nothing to list');
  assert.equal(r.candidates[0].destination, 'host=shadow.internal port=443');
  assert.match(r.note, /candidates, not proof/);
});

test('identities using risky paths: tokens on policy-violating or exploit-correlated edges only', () => {
  const r = identitiesUsingRiskyPaths(states);
  assert.deepEqual(r.identities.map((i) => i.token), ['idt_aaaaaaaaaaaaaaaa', 'idt_bbbbbbbbbbbbbbbb']);
  assert.deepEqual(r.identities[0].states, ['RUNTIME_POLICY_VIOLATION']);
  assert.match(r.note, /not evidence that no identity used them/);
  assert.deepEqual(identitiesUsingRiskyPaths(deriveEdgeStates(graph, correlation, [obs('x', 'e1', { attributes: { 'identity.token': 'idt_cccccccccccccccc' } })])).identities, []);
});

const ctx = (extra = {}) => ({ version: '1.0.0', adapter: 'x', source: 's', environment: 'production', windowStart: '2026-08-01T00:00:00.000Z', windowEnd: '2026-08-31T00:00:00.000Z', importedAt: '2026-08-31T00:00:00.000Z', retention: { expiresAt: null }, ...extra });
const K8S = '{"objectRef":{"namespace":"payments","resource":"secrets"},"responseStatus":{"code":200},"user":{"username":"alice@example.com"},"requestReceivedTimestamp":"2026-08-02T10:05:00.000Z"}';
const HTTP = '{"host":"api.internal","remote_user":"bob","timestamp":"2026-08-02T10:05:00.000Z"}';

test('identity is recorded only as a keyed token, only when a tokenizer is supplied, and the raw value is never stored', () => {
  for (const [parse, text] of [[parseK8sAuditLogObservations, K8S], [parseHttpAccessLogObservations, HTTP]]) {
    const without = parse(text, ctx()).drafts[0];
    assert.equal(without.attributes['identity.token'], undefined, 'no tokenizer: identity dropped');
    const tz = (raw) => `idt_${Buffer.from(raw).toString('hex').padEnd(16, '0').slice(0, 16)}`;
    const withTok = parse(text, ctx({ tokenizeIdentity: tz })).drafts[0];
    assert.match(withTok.attributes['identity.token'], /^idt_[0-9a-f]{16}$/);
    assert.doesNotMatch(JSON.stringify(withTok), /alice|bob/);
    assert.ok(validateObservationAttributes(withTok.attributes).valid);
    const bad = parse(text, ctx({ tokenizeIdentity: (raw) => raw })).drafts[0];
    assert.equal(bad.attributes['identity.token'], undefined, 'a tokenizer that returns the raw value is not trusted');
  }
  const otel = JSON.stringify({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'api' } }] }, scopeSpans: [{ spans: [{ startTimeUnixNano: '1785000000000000000', endTimeUnixNano: '1785000001000000000', attributes: [{ key: 'server.address', value: { stringValue: 'db.internal' } }, { key: 'enduser.id', value: { stringValue: 'carol' } }] }] }] }] });
  const d = parseOtelJsonObservations(otel, ctx({ tokenizeIdentity: makeIdentityTokenizer() })).drafts[0];
  assert.match(d.attributes['identity.token'], /^idt_[0-9a-f]{16}$/); assert.doesNotMatch(JSON.stringify(d), /carol/);
});

test('the tokenizer is deterministic per install and different identities differ', () => {
  const t = makeIdentityTokenizer();
  assert.equal(t('alice'), t('alice')); assert.notEqual(t('alice'), t('bob')); assert.equal(t(''), null); assert.equal(t(5), null);
  assert.match(t('alice'), /^idt_[0-9a-f]{16}$/);
});

test('an observation placed on a node but no edge (a refused queue publish) is still reported, as BLOCKED, not lost', () => {
  const o = [{ id: 'q1', matchedNodeIds: ['node:queue'], matchedEdgeIds: [], matchConfidence: 'medium', attributes: { 'network.securityDecision': 'denied' } },
    { id: 'q2', matchedNodeIds: ['node:store'], matchedEdgeIds: [], matchConfidence: 'high', attributes: { 'network.securityDecision': 'allowed' } },
    { id: 'q3', matchedNodeIds: ['node:weak'], matchedEdgeIds: [], matchConfidence: 'low', attributes: {} }];
  const s = deriveEdgeStates(graph, { evaluated: true, consideredObservationIds: ['q1', 'q2', 'q3'] }, o);
  assert.deepEqual(s.byNode['node:queue'].states, ['RUNTIME_BLOCKED']);
  assert.deepEqual(s.byNode['node:store'].states, ['RUNTIME_OBSERVED']);
  assert.equal(s.byNode['node:weak'], undefined, 'a low-confidence placement creates nothing');
  assert.deepEqual(deriveEdgeStates(graph, { evaluated: false }, null).byNode, {});
});
