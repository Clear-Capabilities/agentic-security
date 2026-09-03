import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EVIDENCE_GRADES } from '../../src/lineage/protection.js';
import { scenarioId } from '../../src/lineage/ids.js';
import {
  SCENARIO_OPERATION_KINDS,
  SCENARIO_VERSION,
  validateScenario,
} from '../../src/lineage/scenario.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, '../../src/lineage/dataflow-graph.schema.json');

test('EVIDENCE_GRADES includes assumed, and the schema enum matches exactly', () => {
  assert.ok(EVIDENCE_GRADES.includes('assumed'));
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  const schemaEnum = schema.$defs.protectionDimension.properties.evidenceGrade.enum;
  assert.deepEqual([...schemaEnum].sort(), [...EVIDENCE_GRADES].sort());
});

test('scenarioId is deterministic for identical inputs and differs on any input change', () => {
  const base = { graphId: 'graph:abc', graphDigest: 'sha256:aaa' };
  const a = scenarioId(base);
  const b = scenarioId(base);
  assert.equal(a, b);
  assert.notEqual(a, scenarioId({ ...base, graphDigest: 'sha256:bbb' }));
  assert.notEqual(a, scenarioId(base, ['discriminator-1']));
  assert.match(a, /^scenario:[0-9a-f]+$/);
});

test('SCENARIO_OPERATION_KINDS is the 6 in-scope kinds, no synthetic-insertion kind', () => {
  assert.deepEqual(SCENARIO_OPERATION_KINDS, [
    'require_transit_protection',
    'apply_handling',
    'remove_entity',
    'replace_recipient_fact',
    'change_storage_fact',
    'change_governance_fact',
  ]);
});

test('validateScenario: a well-formed record is valid', () => {
  const record = {
    id: scenarioId({ graphId: 'graph:abc', graphDigest: 'sha256:aaa' }),
    version: SCENARIO_VERSION,
    baseGraphId: 'graph:abc',
    baseGraphDigest: 'sha256:aaa',
    operations: [
      { kind: 'require_transit_protection', targetEdgeId: 'edge:1', evidenceGrade: 'assumed' },
    ],
    assumptions: ['TLS is enforced at the load balancer'],
    author: 'ross@clearcapabilities.com',
    createdAt: '2026-09-02T00:00:00.000Z',
    expiration: null,
    simulatedDelta: null,
    verificationRequirements: ['Confirm the load balancer config enforces TLS 1.2+'],
  };
  const { valid, errors } = validateScenario(record);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateScenario: never throws on garbage input, reports errors instead', () => {
  for (const bad of [null, undefined, 42, [], {}, { id: 'not-scenario:x' }]) {
    assert.doesNotThrow(() => validateScenario(bad));
    const { valid, errors } = validateScenario(bad);
    assert.equal(valid, false);
    assert.ok(errors.length > 0);
  }
});

test('validateScenario: rejects an operation with an unrecognized kind', () => {
  const record = {
    id: 'scenario:x', version: SCENARIO_VERSION, baseGraphId: 'g', baseGraphDigest: 'd',
    operations: [{ kind: 'insert_gateway', targetEdgeId: 'edge:1' }],
    assumptions: [], author: 'a', createdAt: '2026-09-02T00:00:00.000Z',
    expiration: null, simulatedDelta: null, verificationRequirements: [],
  };
  const { valid, errors } = validateScenario(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.operations[0].kind'));
});

test('validateScenario: rejects a require_transit_protection operation missing targetEdgeId', () => {
  const record = {
    id: 'scenario:x', version: SCENARIO_VERSION, baseGraphId: 'g', baseGraphDigest: 'd',
    operations: [{ kind: 'require_transit_protection' }],
    assumptions: [], author: 'a', createdAt: '2026-09-02T00:00:00.000Z',
    expiration: null, simulatedDelta: null, verificationRequirements: [],
  };
  const { valid, errors } = validateScenario(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.operations[0].targetEdgeId'));
});
