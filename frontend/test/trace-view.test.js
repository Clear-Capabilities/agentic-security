import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeTraceSteps, computeAlternatePaths, computeTraceViewModel } from '../src/views/trace-view.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);

test('computeTraceSteps for the masked-log flow produces the real source->rename->transform->sink sequence', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);

  const sourceStep = steps.find((s) => s.kind === 'source');
  assert.ok(sourceStep);
  assert.equal(sourceStep.node, 'Web App');

  const renameStep = steps.find((s) => s.mappingType === 'rename');
  assert.ok(renameStep, 'expected a rename step for req.body.card_number -> payment.pan');
  assert.equal(renameStep.fromPath, 'req.body.card_number');
  assert.equal(renameStep.toPath, 'payment.pan');
  assert.equal(renameStep.node, 'Payments Service');

  const transformStep = steps.find((s) => s.kind === 'transformation');
  assert.ok(transformStep, 'expected a transformation step for the maskCard() hop');
  assert.equal(transformStep.fromPath, 'payment.pan');
  assert.equal(transformStep.toPath, 'maskedPan');
  assert.equal(transformStep.node, 'Application Logs');
  assert.equal(transformStep.transformations.length, 1);
  assert.equal(transformStep.transformations[0].callee, 'maskCard');
  assert.equal(transformStep.transformations[0].kind, 'mask');
  assert.equal(transformStep.protection.handling.verdict, 'protected');

  const sinkStep = steps.find((s) => s.kind === 'sink');
  assert.ok(sinkStep);
  assert.equal(sinkStep.node, 'Application Logs');
  assert.equal(sinkStep.protectionSummary, 'protected');
});

test('computeTraceSteps never invents a transformation the edge does not actually declare', () => {
  const flow = flowByKey('flow.pci.raw_log');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const transformSteps = steps.filter((s) => s.kind === 'transformation');
  assert.equal(transformSteps.length, 0, 'the raw-log flow has no transformation on its identity-mapped edge');
  const identityStep = steps.find((s) => s.mappingType === 'identity');
  assert.ok(identityStep);
});

test('computeTraceSteps marks the external, cleartext payment-API hop as a real trust-boundary crossing', () => {
  const flow = flowByKey('flow.pci.payment_api');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const sinkStep = steps.find((s) => s.kind === 'sink');
  assert.equal(sinkStep.protectionSummary, 'unprotected');
});

test('computeAlternatePaths for card_number lists the OTHER card_number flows, not itself', () => {
  const maskedLogFlow = flowByKey('flow.pci.masked_log');
  const alternates = computeAlternatePaths(FLAGSHIP_GRAPH, maskedLogFlow);
  assert.ok(!alternates.some((a) => a.flowId === maskedLogFlow.id), 'must not list itself as an alternate');
  assert.ok(alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.raw_log']), 'the raw-log flow shares card_number and must appear as an alternate');
  assert.ok(alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.payment_api']));
});

test('computeAlternatePaths for a PII flow never lists a PCI flow (different data element)', () => {
  const analyticsFlow = flowByKey('flow.pii.analytics');
  const alternates = computeAlternatePaths(FLAGSHIP_GRAPH, analyticsFlow);
  assert.ok(!alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.masked_log']));
});

test('computeTraceViewModel returns null when nothing is selected', () => {
  assert.equal(computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: null, filters: {} }), null);
});

test('computeTraceViewModel returns null when the selection is a node or edge, not a flow', () => {
  const nodeId = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys['node.web'];
  assert.equal(computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: nodeId, filters: {} }), null);
});

test('computeTraceViewModel for a real flow selection returns flow, steps, and alternatePaths together', () => {
  const flowId = FLOW_KEYS['flow.pci.masked_log'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm);
  assert.equal(vm.flow.id, flowId);
  assert.ok(vm.steps.length > 0);
  assert.ok(vm.alternatePaths.length > 0);
});
