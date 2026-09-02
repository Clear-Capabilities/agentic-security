import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  evaluateGraphFlowPredicate,
  buildObligationMappingFromGraphPredicate,
} from '../../src/lineage/obligation-predicates.js';
import { validateObligationMapping } from '../../src/lineage/obligation-mapping.js';
import { buildFixtureGraph } from '../../../bench/data-lineage/runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, '../../../bench/data-lineage/fixtures');

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

// =====================================================================
// Final whole-branch review fix round — BLOCKING 1 & 2 regressions.
// =====================================================================

test('BLOCKING 1: a flow whose transit verdict was never assessed (not_assessed) does NOT count as a failure', () => {
  const graph = _minimalGraph({ transitVerdict: 'not_assessed' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.hasFailure, false, 'not_assessed must never be treated as a genuine failure');
  assert.equal(r.hasUnassessed, true);
  assert.equal(r.failedCount, 0);
  assert.equal(r.notAssessedCount, 1);
});

test('BLOCKING 1: an unknown transit verdict also does NOT count as a failure', () => {
  const graph = _minimalGraph({ transitVerdict: 'unknown' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.hasFailure, false);
  assert.equal(r.hasUnassessed, true);
});

test('BLOCKING 1: buildObligationMappingFromGraphPredicate on an unassessed-only evaluation produces unknown, NEVER a false gap_detected', () => {
  // This is the exact defect the final whole-branch review reproduced live
  // against the real bench/data-lineage/ corpus: an UNASSESSED verdict
  // (never checked) used to collapse into the same 'gap_detected' state as
  // a genuine, checked 'unprotected' failure.
  const graph = _minimalGraph({ transitVerdict: 'not_assessed' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'unknown');
  assert.notEqual(record.state, 'gap_detected');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('BLOCKING 1: worst-case-wins — a genuine assessed failure outranks a co-occurring unassessed flow', () => {
  const graph = _minimalGraph({ transitVerdict: 'unprotected' });
  // Add a second, unassessed flow to the same graph so both cases are present at once.
  graph.nodes.push({ id: 'node:sink2', kind: 'external' });
  graph.edges.push({
    id: 'edge:e2', from: 'node:src1', to: 'node:sink2',
    protection: { transit: { verdict: 'not_assessed', evidenceGrade: 'none' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
    evidenceRefs: [],
  });
  graph.flows.push({ id: 'flow:f2', dataElementIds: ['data:d1'], source: 'node:src1', sink: 'node:sink2', edgeIds: ['edge:e2'] });

  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(evaluation.hasFailure, true);
  assert.equal(evaluation.hasUnassessed, true);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'gap_detected', 'a real failure must win over a co-occurring unassessed flow');
});

test('BLOCKING 2: a sink node whose kind was rewritten to "unresolved" (FR-203, dynamic destination) is still matched, not silently excluded', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', sinkKind: 'unresolved' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true, '"unresolved" must match a spec.sinkKind of "external" — it is the same category, just dynamically resolved');
});

// =====================================================================
// Real-corpus regression — the exact reproduction from the final review.
// =====================================================================

test('REAL CORPUS: the AC-07 flagship fixture (PHI reaching anthropic.messages.create()) is applicable and resolves to unknown, never a false gap_detected or false not_applicable', () => {
  const fixtureId = 'js-ai-model-output-to-ai-model-provider-phi';
  const source = fs.readFileSync(path.join(FIXTURES_ROOT, fixtureId, 'source.js'), 'utf8');
  const graph = buildFixtureGraph(fixtureId, source);

  // Confirm the real pipeline still produces the exact shape this
  // regression depends on — if graph-builder.js output ever changes, this
  // assertion (not a silently-passing predicate test) is what will tell us.
  const sinkNode = graph.nodes.find((n) => n.subtype === 'ai-model-provider');
  assert.equal(sinkNode.kind, 'unresolved', 'fixture assumption drifted: sink is no longer kind:unresolved');

  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true, 'BLOCKING 2 regression: an unresolved destination must not read as not_applicable');
  assert.equal(r.hasFailure, false);
  assert.equal(r.hasUnassessed, true, 'this edge genuinely was never assessed for transit protection');

  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, r));
  assert.equal(record.state, 'unknown', 'BLOCKING 1 regression: an unassessed edge must never render as gap_detected');
});

test('REAL CORPUS: sweeping every bench/data-lineage/ fixture through the predicate never produces a false gap_detected and never throws', () => {
  const fixtureIds = fs.readdirSync(FIXTURES_ROOT).filter((f) =>
    fs.statSync(path.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0, 'the real corpus must be non-empty for this sweep to mean anything');

  let sawApplicable = 0;
  for (const fixtureId of fixtureIds) {
    const srcPath = path.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs.existsSync(srcPath)) continue;
    const source = fs.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);

    let evaluation, record;
    assert.doesNotThrow(() => { evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph); }, `threw on fixture ${fixtureId}`);
    assert.doesNotThrow(() => { record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation)); }, `threw building record for ${fixtureId}`);
    assert.equal(validateObligationMapping(record).valid, true, `invalid record for ${fixtureId}`);

    if (evaluation.applicable) {
      sawApplicable++;
      // A gap_detected verdict on real, unmodified corpus fixtures must
      // trace back to a genuine, assessed failure — never to unassessed
      // flows alone. This is the load-bearing, non-vacuous half of the
      // sweep: it fails loudly if the false-positive this review found
      // is ever reintroduced.
      if (record.state === 'gap_detected') {
        assert.equal(evaluation.hasFailure, true, `${fixtureId} reports gap_detected with no genuine assessed failure`);
      }
    }
  }
  assert.ok(sawApplicable > 0, 'the sweep must exercise at least one applicable (PHI-to-external) real fixture, or this test is vacuous');
});

// =====================================================================
// RECOMMENDED 4 — defensive hardening, malformed-graph shapes never throw.
// =====================================================================

test('RECOMMENDED 4: non-array graph fields (dataElements/nodes/edges/flows) never throw', () => {
  const malformed = { graphId: 'x', dataElements: null, nodes: 'not-an-array', edges: undefined, flows: {} };
  assert.doesNotThrow(() => evaluateGraphFlowPredicate(PROTECTED_SPEC, malformed));
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, malformed);
  assert.equal(r.applicable, false);
});

test('RECOMMENDED 4: a bare-string dataClasses value on a dataElement never throws and never substring-matches', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  graph.dataElements[0].dataClasses = 'PHI'; // malformed: string, not array
  assert.doesNotThrow(() => evaluateGraphFlowPredicate(PROTECTED_SPEC, graph));
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false, 'Array.isArray guard must reject a bare string rather than falling through to .includes() substring matching');
});

test('RECOMMENDED 4: null entries inside array fields are filtered rather than dereferenced', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  graph.nodes.push(null);
  graph.edges.push(null);
  graph.dataElements.push(null);
  graph.flows.push(null);
  assert.doesNotThrow(() => evaluateGraphFlowPredicate(PROTECTED_SPEC, graph));
});
