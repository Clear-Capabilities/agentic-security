// The runtime explorer page and the vulnerable-functions-in-production query (PRD 2 section 5, section 6).
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderRuntimeExplorer, vulnerableFunctionsInProduction } from '../../src/lineage/runtime-explorer-view.js';
import { deriveEdgeStates, runtimeFlowsAbsentFromStatic } from '../../src/lineage/runtime-edge-states.js';

const graph = {
  nodes: [{ id: 'node:ui', label: 'checkout form' }, { id: 'node:api', label: 'payments <api>' }, { id: 'node:db', label: 'cards db' }],
  edges: [
    { id: 'edge:1', from: 'node:ui', to: 'node:api', provenance: 'code', coverageStatus: 'modeled', boundaryCrossings: ['internet'], evidenceRefs: ['ev:1'], protocol: { name: 'https' } },
    { id: 'edge:2', from: 'node:api', to: 'node:db', provenance: 'code', coverageStatus: 'modeled', boundaryCrossings: [], evidenceRefs: [] },
  ],
  dataElements: [{ id: 'de:pan', label: 'card number', dataClasses: ['PCI'] }],
  flows: [{ id: 'flow:pan', dataElementIds: ['de:pan'], source: 'node:ui', sink: 'node:db', edgeIds: ['edge:1', 'edge:2'], policyVerdict: 'permitted' }],
};
const observations = [
  { id: 'o1', adapter: 'http-access-log', environment: 'production', matchedNodeIds: ['node:api'], matchedEdgeIds: ['edge:1'], matchConfidence: 'high', matchMethod: 'destination_literal', eventCountBand: '11-100', firstObservedAt: '2026-08-01T00:00:00Z', lastObservedAt: '2026-08-02T00:00:00Z', attributes: { 'network.securityDecision': 'allowed', 'identity.token': 'idt_0123456789abcdef' } },
  { id: 'o2', matchedNodeIds: [], matchedEdgeIds: [], attributes: { 'destination.host': '<script>alert(1)</script>.internal' }, firstObservedAt: 't', lastObservedAt: 't' },
];
const correlation = { evaluated: true, consideredObservationIds: ['o1', 'o2'], unmatchedObservationIds: ['o2'] };
const render = (over = {}) => {
  const states = deriveEdgeStates(graph, over.correlation ?? correlation, over.observations ?? observations);
  return renderRuntimeExplorer({ graph, edgeStates: states, correlation, observations: over.observations ?? observations, absent: runtimeFlowsAbsentFromStatic(over.observations ?? observations, correlation) });
};

test('the page has all five views, the PRD path (field to API to DB) with a state per hop, and both evidences per edge', () => {
  const h = render();
  for (const id of ['static', 'runtime', 'both', 'risk', 'unexpected']) assert.match(h, new RegExp(`<section id="${id}">`));
  assert.match(h, /card number/); assert.match(h, /checkout form[^<]*&rarr; payments/); assert.match(h, /cards db/);
  assert.match(h, /<section id="risk">[\s\S]*card number[\s\S]*RUNTIME_OBSERVED/, 'a PCI flow with an observed hop is in the high-risk view');
  assert.match(h, /<details>[\s\S]*Static evidence[\s\S]*ev:1[\s\S]*Runtime evidence[\s\S]*count band 11-100[\s\S]*decision allowed[\s\S]*idt_0123456789abcdef/);
  assert.match(h, /edge:2[\s\S]*RUNTIME_NOT_OBSERVED/, 'the unobserved hop says so');
});

test('the page is inert: no script, a deny-by-default CSP, and hostile telemetry text is escaped', () => {
  const h = render();
  assert.doesNotMatch(h, /<script/i); assert.match(h, /Content-Security-Policy" content="default-src 'none'/);
  assert.doesNotMatch(h, /<script>alert/); assert.match(h, /&lt;script&gt;alert\(1\)&lt;\/script&gt;\.internal/);
  assert.doesNotMatch(h, /payments <api>/); assert.match(h, /payments &lt;api&gt;/);
  assert.match(h, /Not observed does not mean unreachable or safe/);
});

test('with no telemetry the page says nothing was consulted instead of showing a clean runtime view', () => {
  const states = deriveEdgeStates(graph, { evaluated: false }, null);
  const h = renderRuntimeExplorer({ graph, edgeStates: states, correlation: { evaluated: false }, observations: [] });
  assert.match(h, /No telemetry was consulted/); assert.match(h, /STATIC_ONLY/);
  assert.match(h, /No observed flow is sensitive[\s\S]*not about the system/);
});

test('unplaced and refused observations appear under unexpected runtime paths', () => {
  const h = render();
  assert.match(h, /<section id="unexpected">[\s\S]*not placed on any static node/);
});

test('vulnerable functions in production: only findings whose scan recorded observed evidence; absence is counted, never called safe', () => {
  const f = (id, state) => ({ id, severity: 'high', vuln: 'x', file: 'a.js', line: 1, cwe: 'CWE-89', runtimeEvidence: { state, basis: 'b', sampling: { state: 'complete' } } });
  const r = vulnerableFunctionsInProduction([f('a', 'observed'), f('b', 'not_observed_in_window'), f('c', 'unknown'), { id: 'd' }]);
  assert.equal(r.evaluated, true); assert.deepEqual(r.findings.map((x) => x.id), ['a']);
  assert.deepEqual(r.counts, { observed: 1, notObservedInWindow: 1, unknown: 1 });
  assert.match(r.note, /not about reachability/);
  const none = vulnerableFunctionsInProduction([{ id: 'd' }]);
  assert.equal(none.evaluated, false); assert.match(none.reason, /not "no vulnerable function ran"/);
  assert.equal(vulnerableFunctionsInProduction(null).evaluated, false);
});
