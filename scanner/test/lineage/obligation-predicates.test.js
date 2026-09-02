import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateGraphFlowPredicate,
  buildObligationMappingFromGraphPredicate,
} from '../../src/lineage/obligation-predicates.js';
import { validateObligationMapping } from '../../src/lineage/obligation-mapping.js';

// A minimal, hand-built graph — just enough shape for a `graph-flow`
// predicate to walk: one dataElement (PHI), one external sink node, one
// edge carrying a transit verdict, one flow tying them together. Two
// variants: PROTECTED (positive) and UNPROTECTED (negative).
function _minimalGraph({ transitVerdict, dataClass = 'PHI', sinkKind = 'external' }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    nodes: [
      { id: 'node:src1', kind: 'api' },
      { id: 'node:sink1', kind: sinkKind },
    ],
    edges: [
      {
        id: 'edge:e1',
        from: 'node:src1', to: 'node:sink1',
        protection: { transit: { verdict: transitVerdict, evidenceGrade: 'code' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: ['evidence:ev1'],
      },
    ],
    dataElements: [
      { id: 'data:d1', name: 'patient_record', dataClasses: [dataClass] },
    ],
    flows: [
      { id: 'flow:f1', dataElementIds: ['data:d1'], source: 'node:src1', sink: 'node:sink1', edgeIds: ['edge:e1'] },
    ],
  };
}

const PROTECTED_SPEC = { type: 'graph-flow', dataClass: 'PHI', sinkKind: 'external', dimension: 'transit', requiredVerdict: 'protected' };

test('evaluateGraphFlowPredicate: a protected flow matches, contributes its flow id and edge evidence', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, true);
  assert.deepEqual(r.contributingGraphIds, ['flow:f1']);
  assert.deepEqual(r.evidence, ['evidence:ev1']);
  assert.equal(r.resultsCount, 1);
  assert.equal(r.failedCount, 0);
});

test('evaluateGraphFlowPredicate: an unprotected flow does not match', () => {
  const graph = _minimalGraph({ transitVerdict: 'unprotected' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, false);
  assert.equal(r.failedCount, 1);
});

test('evaluateGraphFlowPredicate: no relevant flows (wrong dataClass) is not_applicable, not a false match', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', dataClass: 'PII' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
  assert.equal(r.matched, null);
  assert.deepEqual(r.contributingGraphIds, []);
});

test('evaluateGraphFlowPredicate: no relevant flows (wrong sink kind) is not_applicable', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', sinkKind: 'store' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
});

test('evaluateGraphFlowPredicate: a flow with no edges / missing edge is treated as not_assessed, not a crash', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  graph.flows[0].edgeIds = ['edge:does-not-exist'];
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, false);
});

test('evaluateGraphFlowPredicate: a real graph with zero flows at all is not_applicable, never throws', () => {
  const graph = { graphId: 'dfg:x:y:default', nodes: [], edges: [], dataElements: [], flows: [] };
  assert.doesNotThrow(() => evaluateGraphFlowPredicate(PROTECTED_SPEC, graph));
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
});

// =====================================================================
// buildObligationMappingFromGraphPredicate — the record-minting half
// =====================================================================

function _baseArgs(graph, evaluation) {
  return {
    framework: 'hipaa-security-rule',
    frameworkVersion: 'test-digest-123',
    requirementId: '§164.312(e)',
    requirementSource: 'https://example.test/hipaa',
    predicateLabel: 'graph:transit-protection:PHI:external:transit:protected',
    graph,
    evaluation,
  };
}

test('buildObligationMappingFromGraphPredicate: a matched predicate produces an evidence_supported, validateObligationMapping-clean record', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'evidence_supported');
  assert.equal(record.frameworkVersion, 'test-digest-123');
  assert.equal(record.factType, 'code_inferred');
  assert.deepEqual(record.applicabilityInputs, {
    entityRole: null, jurisdiction: null, dataSubject: null, businessProcess: null,
    merchantLevel: null, systemScope: null, aiSystemRole: null,
  });
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, true, JSON.stringify(errors));
});

test('buildObligationMappingFromGraphPredicate: a failed predicate produces gap_detected', () => {
  const graph = _minimalGraph({ transitVerdict: 'unprotected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'gap_detected');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: no relevant flows produces not_applicable', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', dataClass: 'PII' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'not_applicable');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: a null/absent graph produces unknown, never throws', () => {
  const record = buildObligationMappingFromGraphPredicate({
    framework: 'hipaa-security-rule', frameworkVersion: 'test-digest-123',
    requirementId: '§164.312(e)', requirementSource: null,
    predicateLabel: 'graph:transit-protection:PHI:external:transit:protected',
    graph: null, evaluation: null,
  });
  assert.equal(record.state, 'unknown');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: the id is a real obligationId, stable for identical inputs', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const a = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  const b = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.match(a.id, /^obligation:[0-9a-f]{12}$/);
  assert.equal(a.id, b.id);
});

test('buildObligationMappingFromGraphPredicate: a truthy graph with a missing/null evaluation degrades to unknown, never throws', () => {
  // A caller-contract violation (forgetting to call evaluateGraphFlowPredicate
  // first) must never throw — matches this package's "public API never
  // throws on malformed input" convention (obligation-mapping.js,
  // path-query.js, flow-grade.js all hold this).
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  assert.doesNotThrow(() => buildObligationMappingFromGraphPredicate(_baseArgs(graph, null)));
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, null));
  assert.equal(record.state, 'unknown');
  assert.equal(validateObligationMapping(record).valid, true);
});
