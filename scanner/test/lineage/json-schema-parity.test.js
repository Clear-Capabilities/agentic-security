import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, TRANSFORM_KINDS,
  COVERAGE_STATUS_VALUES, DESTINATION_RESOLUTION_VALUES, POLICY_STATES, EVIDENCE_TYPES,
  EXTERNALITY_VALUES, GRAPH_SCOPE_SOURCES,
} from '../../src/lineage/schema.js';
import { PROTECTION_VERDICTS, EVIDENCE_GRADES } from '../../src/lineage/protection.js';
import { LINEAGE_DATA_CLASSES, AI_PROCESSING_CONTEXTS } from '../../src/lineage/classification.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(__dirname, '../../src/lineage/dataflow-graph.schema.json');

function loadSchema() {
  return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
}

test('schema file exists and parses as JSON', () => {
  assert.ok(fs.existsSync(schemaPath));
  assert.doesNotThrow(() => loadSchema());
});

test('schema $id and version match schema.js SCHEMA_VERSION', () => {
  const schema = loadSchema();
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.ok(schema.$id.includes(SCHEMA_VERSION));
  assert.equal(schema.properties.schemaVersion.const, SCHEMA_VERSION);
});

test('node kind enum matches schema.js NODE_KINDS exactly (no drift)', () => {
  const schema = loadSchema();
  const nodeKindEnum = schema.$defs.node.properties.kind.enum;
  assert.deepEqual([...nodeKindEnum].sort(), [...NODE_KINDS].sort());
});

test('field mapping type enum matches schema.js MAPPING_TYPES', () => {
  const schema = loadSchema();
  const enumVals = schema.$defs.fieldMapping.properties.mappingType.enum;
  assert.deepEqual([...enumVals].sort(), [...MAPPING_TYPES].sort());
});

test('transform kind enum matches schema.js TRANSFORM_KINDS', () => {
  const schema = loadSchema();
  const enumVals = schema.$defs.transformation.properties.kind.enum;
  assert.deepEqual([...enumVals].sort(), [...TRANSFORM_KINDS].sort());
});

test('protection verdict and evidence grade enums match protection.js', () => {
  const schema = loadSchema();
  const verdictEnum = schema.$defs.protectionDimension.properties.verdict.enum;
  const gradeEnum = schema.$defs.protectionDimension.properties.evidenceGrade.enum;
  assert.deepEqual([...verdictEnum].sort(), [...PROTECTION_VERDICTS].sort());
  assert.deepEqual([...gradeEnum].sort(), [...EVIDENCE_GRADES].sort());
});

test('coverage status, destination resolution, policy state, evidence type enums match schema.js', () => {
  const schema = loadSchema();
  assert.deepEqual([...schema.$defs.node.properties.coverageStatus.enum].sort(), [...COVERAGE_STATUS_VALUES].sort());
  assert.deepEqual([...schema.$defs.protocol.properties.destinationResolution.enum].sort(), [...DESTINATION_RESOLUTION_VALUES].sort());
  assert.deepEqual([...schema.$defs.flow.properties.policyVerdict.enum].sort(), [...POLICY_STATES].sort());
  assert.deepEqual([...schema.$defs.evidence.properties.evidenceType.enum].sort(), [...EVIDENCE_TYPES].sort());
});

test('node externality.value enum matches schema.js EXTERNALITY_VALUES', () => {
  const schema = loadSchema();
  const enumVals = schema.$defs.node.properties.externality.properties.value.enum;
  assert.deepEqual([...enumVals].sort(), [...EXTERNALITY_VALUES].sort());
});

test('dataElement dataClasses item enum matches classification.js LINEAGE_DATA_CLASSES', () => {
  const schema = loadSchema();
  const enumVals = schema.$defs.dataElement.properties.dataClasses.items.enum;
  assert.deepEqual([...enumVals].sort(), [...LINEAGE_DATA_CLASSES].sort());
});

test('dataElement aiContexts item enum matches classification.js AI_PROCESSING_CONTEXTS', () => {
  const schema = loadSchema();
  const enumVals = schema.$defs.dataElement.properties.aiContexts.items.enum;
  assert.deepEqual([...enumVals].sort(), [...AI_PROCESSING_CONTEXTS].sort());
});

test('scope.source enum matches schema.js GRAPH_SCOPE_SOURCES', () => {
  const schema = loadSchema();
  const enumVals = schema.properties.scope.properties.source.enum;
  assert.deepEqual([...enumVals].sort(), [...GRAPH_SCOPE_SOURCES].sort());
});

test('top-level required envelope keys are all present', () => {
  const schema = loadSchema();
  const required = schema.required;
  for (const key of ['schemaVersion', 'graphId', 'generatedAt', 'nodes', 'edges', 'dataElements', 'transformations', 'flows', 'evidence', 'coverage', 'limitations']) {
    assert.ok(required.includes(key), `schema.required missing "${key}"`);
  }
});
