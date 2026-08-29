import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, TRANSFORM_KINDS,
  REVERSIBILITY_VALUES, EXTERNALITY_VALUES, COVERAGE_STATUS_VALUES,
  DESTINATION_RESOLUTION_VALUES, POLICY_STATES, EVIDENCE_TYPES,
  FLOW_SUMMARY_VALUES, GRAPH_SCOPE_SOURCES, SOURCE_CATEGORIES, SINK_CATEGORIES,
  emptyGraphEnvelope,
} from '../../src/lineage/schema.js';

test('SCHEMA_VERSION is a semver string', () => {
  assert.match(SCHEMA_VERSION, /^\d+\.\d+\.\d+$/);
});

test('enums are frozen non-empty arrays of unique strings', () => {
  for (const arr of [
    NODE_KINDS, MAPPING_TYPES, TRANSFORM_KINDS, REVERSIBILITY_VALUES,
    EXTERNALITY_VALUES, COVERAGE_STATUS_VALUES, DESTINATION_RESOLUTION_VALUES,
    POLICY_STATES, EVIDENCE_TYPES, FLOW_SUMMARY_VALUES, GRAPH_SCOPE_SOURCES,
  ]) {
    assert.ok(Object.isFrozen(arr));
    assert.ok(arr.length > 0);
    assert.equal(new Set(arr).size, arr.length, 'no duplicate values');
    for (const v of arr) assert.equal(typeof v, 'string');
  }
});

test('NODE_KINDS matches PRD section 10.3 exactly', () => {
  assert.deepEqual([...NODE_KINDS].sort(), [
    'api', 'boundary', 'external', 'log', 'process', 'queue',
    'sink', 'source', 'store', 'transform', 'unresolved',
  ].sort());
});

test('SOURCE_CATEGORIES and SINK_CATEGORIES are non-empty frozen unique arrays covering PRD sections 11/12', () => {
  for (const arr of [SOURCE_CATEGORIES, SINK_CATEGORIES]) {
    assert.ok(Object.isFrozen(arr));
    assert.equal(new Set(arr).size, arr.length);
  }
  for (const cat of ['http-body', 'http-query', 'graphql-argument', 'queue-message', 'ai-model-output', 'declared']) {
    assert.ok(SOURCE_CATEGORIES.includes(cat), `SOURCE_CATEGORIES missing "${cat}"`);
  }
  for (const cat of ['log', 'database', 'external-api', 'ai-vector-store', 'ai-training', 'declared']) {
    assert.ok(SINK_CATEGORIES.includes(cat), `SINK_CATEGORIES missing "${cat}"`);
  }
});

test('emptyGraphEnvelope has every required top-level key', () => {
  const env = emptyGraphEnvelope({ graphId: 'dfg:test:abc:def' });
  assert.equal(env.schemaVersion, SCHEMA_VERSION);
  assert.equal(env.graphId, 'dfg:test:abc:def');
  assert.equal(typeof env.generatedAt, 'string');
  for (const key of ['scope', 'scanHealth', 'taxonomy', 'coverage', 'extensions']) {
    assert.equal(typeof env[key], 'object');
    assert.notEqual(env[key], null);
  }
  for (const key of ['nodes', 'edges', 'dataElements', 'transformations', 'flows', 'controls', 'policies', 'evidence', 'limitations']) {
    assert.ok(Array.isArray(env[key]), `${key} must be an array`);
  }
});

test('emptyGraphEnvelope defaults scope.source to scan', () => {
  const env = emptyGraphEnvelope({ graphId: 'dfg:test:abc:def' });
  assert.equal(env.scope.source, 'scan');
});
