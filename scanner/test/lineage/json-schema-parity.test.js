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
import { validateGraph } from '../../src/lineage/validate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(__dirname, '../../src/lineage/dataflow-graph.schema.json');
const flagshipPath = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');

function loadSchema() {
  return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
}

function loadFlagship() {
  return JSON.parse(fs.readFileSync(flagshipPath, 'utf8'));
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

// --- $defs.<entity>.required vs. validate.js's own enforcement -----------
//
// The enum-array checks above (and the envelope-required check just above
// this comment) were the parity test's ENTIRE surface until this block was
// added. Neither one ever looked at a per-entity `$defs.<entity>.required`
// array — which is exactly how `node.subtype` drifted: the schema declared
// it `required` + `type: "string"`, while `validate.js` never referenced
// `node.subtype` at all (not even an optional-type check), and nothing here
// ever compared the two. See the hotfix that added this block for the full
// story; this is the closed blind spot.
//
// `validate.js` does not enforce "required" the same way the JSON Schema
// does, and it never groups its checks by `$defs` entity name — so instead
// of a hand-maintained table (which is exactly how the ORIGINAL `subtype`
// gap went unnoticed: a hardcoded list nobody could catch drifting), this
// block DERIVES, empirically, which schema-required fields `validate.js`
// actually enforces: for each `$defs.<entity>.required` field, delete it
// from a real, otherwise-valid instance (the flagship fixture, already
// `validateGraph()`-clean per `flagship-fixture.test.js`) and check whether
// `validateGraph()` now reports an error. A field only counts as "enforced"
// if its own absence, on its own, produces a validation error — a field
// that is merely enum/shape-checked WHEN PRESENT (e.g. `edge.protocol`,
// node's own `externality`) does not count, because `validate.js` does not
// error when it is absent. This is a mechanization of the plan's own
// stated definition, not a redefinition of it (task review MF-1) — it is
// re-run on every test invocation, so it can never silently drift from
// what `validate.js` actually does the way a hardcoded literal already did
// once.
//
// KNOWN_REQUIRED_GAPS is the accepted, pre-existing set of fields the JSON
// Schema declares `required` but `validate.js` does not enforce at all.
// Three of these are RISK-BEARING, not merely opaque object bags —
// `edge.coverageStatus` and `flow.coverageStatus` are the same enum
// `node.coverageStatus` IS enum-checked for (AC-11's "a discovered sink
// stays visible with a reason" rests on this field), and `evidence.claim`
// is the evidence contract's own free-text assertion — `validate.js`
// checks neither at all. These, and the rest of the set, are escalated as
// their own numbered entry in `DESIGN_GRAPH_BUILDER.md` §11 (task review
// MF-2) rather than left implicit here; this list exists so a NEW gap of
// this exact kind can never again slip in silently — any field that shows
// up in the schema's `required` array but isn't derived as enforced must
// be listed here, on purpose, or the test below fails. These are NOT part
// of this hotfix and are deliberately left as-is — the Global Constraints
// for this task forbid tightening any OTHER validation.

const ENTITY_TARGET = {
  // Every locator reads from a FRESH structuredClone of the flagship
  // fixture (never a shared mutable reference) so one field's deletion
  // can never leak into another field's check.
  node: (g) => g.nodes[0],
  edge: (g) => g.edges.find((e) => Array.isArray(e.fieldMappings) && e.fieldMappings.length > 0),
  fieldMapping: (g) => g.edges.find((e) => Array.isArray(e.fieldMappings) && e.fieldMappings.length > 0).fieldMappings[0],
  protectionDimension: (g) => g.edges.find((e) => Array.isArray(e.fieldMappings) && e.fieldMappings.length > 0).protection.transit,
  dataElement: (g) => g.dataElements[0],
  transformation: (g) => g.transformations[0],
  flow: (g) => g.flows[0],
  evidence: (g) => g.evidence[0],
};

function deriveEnforcedRequired(entity, schemaRequiredFields) {
  const enforced = [];
  for (const field of schemaRequiredFields) {
    const graph = structuredClone(loadFlagship());
    const target = ENTITY_TARGET[entity](graph);
    delete target[field];
    const result = validateGraph(graph);
    if (!result.valid) enforced.push(field);
  }
  return enforced;
}

function deriveAllEnforcedRequired(schema) {
  const derived = {};
  for (const entity of Object.keys(ENTITY_TARGET)) {
    derived[entity] = deriveEnforcedRequired(entity, schema.$defs[entity].required);
  }
  return derived;
}

const KNOWN_REQUIRED_GAPS = {
  node: ['system', 'externality', 'lifecycleStages', 'governanceRefs', 'confidence'],
  fieldMapping: ['fromPath', 'toPath', 'dataElementIds', 'transformationIds'],
  protectionDimension: [],
  edge: ['protocol', 'boundaryCrossings', 'evidenceRefs', 'coverageStatus'],
  dataElement: ['aliases', 'sourceLocations', 'classificationEvidence', 'manualOverride'],
  transformation: [],
  flow: ['dataElementIds', 'edgeIds', 'evidenceRefs', 'coverageStatus'],
  evidence: ['claim'],
};

test('every $defs entity with a `required` array is accounted for by ENTITY_TARGET/KNOWN_REQUIRED_GAPS', () => {
  const schema = loadSchema();
  const entitiesWithRequired = Object.keys(schema.$defs).filter((name) => Array.isArray(schema.$defs[name].required));
  assert.deepEqual([...entitiesWithRequired].sort(), Object.keys(ENTITY_TARGET).sort(),
    'a $defs entity gained/lost a `required` array without this test being updated');
  assert.deepEqual([...entitiesWithRequired].sort(), Object.keys(KNOWN_REQUIRED_GAPS).sort());
});

for (const entity of ['node', 'fieldMapping', 'protectionDimension', 'edge', 'dataElement', 'transformation', 'flow', 'evidence']) {
  test(`$defs.${entity}.required: every field validate.js enforces as required is declared required in the schema`, () => {
    const schema = loadSchema();
    const schemaRequired = schema.$defs[entity].required;
    const enforced = deriveEnforcedRequired(entity, schemaRequired);
    for (const field of enforced) {
      assert.ok(schemaRequired.includes(field), `validate.js enforces "${entity}.${field}" as required, but the schema does not declare it required`);
    }
  });

  test(`$defs.${entity}.required: no undocumented drift from what validate.js enforces (closes the subtype blind spot)`, () => {
    const schema = loadSchema();
    const schemaRequired = schema.$defs[entity].required;
    const enforced = new Set(deriveEnforcedRequired(entity, schemaRequired));
    const unenforced = schemaRequired.filter((f) => !enforced.has(f));
    assert.deepEqual([...unenforced].sort(), [...KNOWN_REQUIRED_GAPS[entity]].sort(),
      `$defs.${entity}.required declares a field validate.js does not enforce and that is not in KNOWN_REQUIRED_GAPS.${entity} — ` +
      `either validate.js needs a real check for it, or it must be added to KNOWN_REQUIRED_GAPS.${entity} as a deliberate, documented gap`);
  });
}

test('derivation sanity: deriveAllEnforcedRequired runs cleanly and returns a non-empty enforced set for every entity with at least one genuinely-enforced field', () => {
  const schema = loadSchema();
  const derived = deriveAllEnforcedRequired(schema);
  assert.deepEqual(Object.keys(derived).sort(), Object.keys(ENTITY_TARGET).sort());
  for (const entity of ['node', 'edge', 'dataElement', 'transformation', 'flow', 'evidence']) {
    assert.ok(derived[entity].length > 0, `expected at least one enforced field for "${entity}"`);
  }
});

// --- Direct regression pins for this hotfix -------------------------------

test('node.subtype is NOT in $defs.node.required (subtype may be absent)', () => {
  const schema = loadSchema();
  assert.ok(!schema.$defs.node.required.includes('subtype'));
});

test('node.subtype accepts both "string" and "null" (subtype may be present-and-null)', () => {
  const schema = loadSchema();
  const subtypeType = schema.$defs.node.properties.subtype.type;
  assert.deepEqual([...subtypeType].sort(), ['null', 'string']);
});
