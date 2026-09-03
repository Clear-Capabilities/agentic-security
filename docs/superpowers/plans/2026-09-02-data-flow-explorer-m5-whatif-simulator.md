# M5, What-If Architecture Simulator (FR-502, sub-project 3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `Scenario` extension contract plus a clone-and-override
engine that recomputes protection/policy verdicts for a hypothetical
architecture change — without a base-graph mutation and without
re-running the taint/path pipeline — covering FR-502's 6 field-override-
and-removal hypothetical-change categories, backend/CLI only.

**Architecture:** `scenario.js` defines the record shape (mirroring
`recipient-profile.js`'s per-field `fieldEvidence` pattern) and a small
`SCENARIO_OPERATION_KINDS` catalog. `scenario-engine.js` deep-clones the
base graph, applies each declared operation (field overrides, or
`remove_entity` cascading graph-surgery), then re-runs the two pure
aggregators the base pipeline already uses (`aggregateVerdicts`,
`isSinkPermitted`) over only the touched flows. `scenario-diff.js` is a
small, dedicated comparison — deliberately NOT `computeGraphDiff`, whose
reidentification/change-cause machinery is shaped for real rescans, not
declared hypotheticals. A CLI subcommand (`dataflow scenario apply`)
wires it end to end.

**Tech Stack:** Node ESM, `node:test`, no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-whatif-simulator-scoping.md`

## Global Constraints

- Scenarios never mutate the base graph — every operation applies to a
  deep clone, verified structurally (a test asserts the base graph
  object is `deepStrictEqual` to a snapshot taken before `applyScenario`
  runs).
- Every field a Scenario overrides gets evidence grade/fact type
  `'assumed'`/`'hypothetical'` — never `'code'`, `'config'`, `'runtime'`,
  or `'declared'`.
- No new npm dependency.
- CLI/JSON/Markdown export only — no frontend/UI work.
- `computeGraphDiff` (`graph-diff.js`) is NOT reused for a Scenario's own
  delta. `scenario-diff.js` is new and dedicated — no reidentification
  pairing, no `causeClassification`, since every difference in a
  Scenario's own delta IS the declared operation, never ambiguous.
- Synthetic node/edge insertion (FR-502's "insert a gateway/DLP/queue"
  category) is out of scope for this plan — deferred to a future,
  separately scoped sub-project (3b).
- A `Scenario` record is never wired into `obligation-predicates.js`,
  `decision-story.js`, or any impact/remediation module — this plan adds
  no such wiring, and Task 4 includes a test asserting none of those
  modules import `scenario.js`/`scenario-engine.js`.
- Every new module follows this package's own established precedent:
  `validateX(record) -> {valid, errors}`, never throws; `xId(...)` object-
  argument ID minting in `ids.js`; `EVIDENCE_GRADES ⊂ protection.js` is
  the ONLY literal copy that gets a new value plus its schema mirror —
  `validate.js` needs no edit (confirmed: it imports
  `isValidProtectionDimension` from `protection.js` rather than
  duplicating the enum).

---

### Task 1: `'assumed'` evidence grade + `scenarioId` + the `Scenario` contract

**Files:**
- Modify: `scanner/src/lineage/protection.js:14`
- Modify: `scanner/src/lineage/dataflow-graph.schema.json:83`
- Modify: `scanner/src/lineage/ids.js` (append after `snapshotId`/`diffId`)
- Create: `scanner/src/lineage/scenario.js`
- Test: `scanner/test/lineage/scenario.test.js`

**Interfaces:**
- Produces: `EVIDENCE_GRADES` now includes `'assumed'` (`protection.js`).
  `scenarioId({graphId, graphDigest}, discriminatorParts = [])` — string,
  `scenario:<hash>`. `SCENARIO_OPERATION_KINDS` — frozen array of 6
  strings. `validateScenario(record) -> {valid, errors}` — structural
  only, mirrors `validateRecipientProfile`'s own contract exactly
  (never throws, `errors: [{path, message}]`).
- Consumes: nothing from later tasks.

- [ ] **Step 1: Add `'assumed'` to `EVIDENCE_GRADES`**

Edit `scanner/src/lineage/protection.js` line 14:

```js
export const EVIDENCE_GRADES = Object.freeze(['runtime', 'code_and_config', 'code', 'config', 'declared', 'assumed', 'manual', 'none']);
```

(Inserted between `'declared'` and `'manual'` — an override placed on the
"less certain than declared config, more certain than a bare absence of
evidence" side of the existing order rather than at either end. The array
IS the source of validity, not a ranked precedence table — `protection.js`
has no evidence-grade precedence table today, only `_PRECEDENCE` for
verdicts — so this placement is documentation, not behavior.)

- [ ] **Step 2: Mirror the schema enum**

Edit `scanner/src/lineage/dataflow-graph.schema.json` line 83 — add
`"assumed"` to the `evidenceGrade` enum array, in the same position:

```json
"evidenceGrade": { "type": "string", "enum": ["runtime", "code_and_config", "code", "config", "declared", "assumed", "manual", "none"] }
```

- [ ] **Step 3: Write a failing parity test**

Create `scanner/test/lineage/scenario.test.js`:

```js
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
  const schemaEnum = schema.properties.edges.items.properties.protection.properties.transit.properties.evidenceGrade.enum;
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
```

- [ ] **Step 4: Run the test to see it fail (module doesn't exist yet)**

Run: `cd scanner && node --test test/lineage/scenario.test.js`
Expected: FAIL — `Cannot find module '.../scenario.js'` and `scenarioId is not exported`.

- [ ] **Step 5: Add `scenarioId` to `ids.js`**

Append to `scanner/src/lineage/ids.js`, after the existing `diffId`
export (mirrors `recipientProfileId`'s own doc-comment shape and
object-argument pattern exactly):

```js
/**
 * A Scenario record's id (M5 deliverable #3a, FR-502 §10.10) — NOT a
 * DataFlowGraph v1 entity, mirrors recipientProfileId's own precedent
 * exactly (a real, stable-ID'd extension record deliberately not a
 * base-graph entity). Discriminated by (graphId, graphDigest) plus
 * caller-supplied discriminatorParts — unlike recipientProfileId, a
 * Scenario has no single natural key of its own (two saved scenarios
 * over the identical base graph with identical operations are still
 * two different records, since FR-502 requires author/time as real,
 * always-present, non-deduplicating fields), so a caller building a
 * scenario record supplies (author, createdAt) as discriminatorParts to
 * make repeat calls collide only when they are genuinely the same
 * scenario.
 */
export function scenarioId(
  { graphId, graphDigest },
  discriminatorParts = [],
) {
  return `scenario:${_hash(_canon([graphId, graphDigest, ...discriminatorParts]))}`;
}
```

- [ ] **Step 6: Write `scenario.js`**

Create `scanner/src/lineage/scenario.js`:

```js
// scenario.js — M5 deliverable #3a (FR-502 §10.10, DFG-0xx): the
// Scenario extension contract — a hypothetical set of graph overrides,
// NOT a DataFlowGraph v1 entity, mirrors recipient-profile.js's own
// contract shape exactly (structural-only {valid, errors} validator,
// zero graph access, per-field evidence typing for the fields a
// Scenario actually overrides).
//
// See docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-whatif-simulator-scoping.md
// for the full design reasoning, including why EVIDENCE_GRADES gained
// 'assumed' instead of reusing 'declared', and why this module's own
// operations catalog excludes synthetic node/edge insertion (deferred).

import { OBLIGATION_FACT_TYPES } from './obligation-mapping.js';

export const SCENARIO_VERSION = '1.0.0';

// The 6 in-scope hypothetical-change kinds (FR-502's own 7, minus the
// deferred synthetic-insertion category). Each operation names its
// target canonical id(s) plus the override value(s); scenario-engine.js
// is the only consumer that interprets `kind`.
export const SCENARIO_OPERATION_KINDS = Object.freeze([
  'require_transit_protection',
  'apply_handling',
  'remove_entity',
  'replace_recipient_fact',
  'change_storage_fact',
  'change_governance_fact',
]);

// Per-operation-kind required fields, beyond the universal `kind`. Kept
// as data (not inline in validateScenario) so scenario-engine.js can
// import the same table rather than re-deriving it.
export const SCENARIO_OPERATION_REQUIRED_FIELDS = Object.freeze({
  require_transit_protection: ['targetEdgeId'],
  apply_handling: ['targetEdgeId', 'handling'],
  remove_entity: ['targetNodeId'],
  replace_recipient_fact: ['targetNodeId', 'field', 'value'],
  change_storage_fact: ['targetNodeId', 'field', 'value'],
  change_governance_fact: ['targetFlowId', 'field', 'value'],
});

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }

/**
 * Structural validation only — mirrors validateRecipientProfile's own
 * {valid, errors} shape and "never throws" contract. Does not check
 * that targetEdgeId/targetNodeId/targetFlowId actually exist in any
 * real graph — that is scenario-engine.js's job at apply time, since
 * this module has zero graph access by design.
 */
export function validateScenario(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'Scenario record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('scenario:')) {
    err('$.id', 'id is required and must start with "scenario:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.baseGraphId)) err('$.baseGraphId', 'baseGraphId is required');
  if (!_isNonEmptyString(record.baseGraphDigest)) err('$.baseGraphDigest', 'baseGraphDigest is required');
  if (!_isNonEmptyString(record.author)) err('$.author', 'author is required');
  if (!_isNonEmptyString(record.createdAt)) err('$.createdAt', 'createdAt is required');
  if (record.expiration !== null && record.expiration !== undefined && !_isNonEmptyString(record.expiration)) {
    err('$.expiration', 'expiration must be a string or null');
  }
  if (!_isStringArray(record.assumptions ?? [])) err('$.assumptions', 'assumptions must be an array of strings');
  if (!_isStringArray(record.verificationRequirements ?? [])) {
    err('$.verificationRequirements', 'verificationRequirements must be an array of strings');
  }
  if (!Array.isArray(record.operations) || record.operations.length === 0) {
    err('$.operations', 'operations is required and must be a non-empty array');
  } else {
    record.operations.forEach((op, i) => {
      const p = `$.operations[${i}]`;
      if (!_isPlainObject(op)) { err(p, 'each operation must be an object'); return; }
      if (!SCENARIO_OPERATION_KINDS.includes(op.kind)) {
        err(`${p}.kind`, `unrecognized operation kind "${op.kind}" — must be one of ${SCENARIO_OPERATION_KINDS.join('|')}`);
        return;
      }
      for (const field of SCENARIO_OPERATION_REQUIRED_FIELDS[op.kind]) {
        if (op[field] === undefined || op[field] === null || op[field] === '') {
          err(`${p}.${field}`, `operation of kind "${op.kind}" requires "${field}"`);
        }
      }
    });
  }
  // simulatedDelta is populated by scenario-engine.js after apply, never
  // by a caller constructing the pre-apply record — null is the only
  // valid pre-apply value, an object (scenario-diff.js's own shape) the
  // only valid post-apply value.
  if (record.simulatedDelta !== null && record.simulatedDelta !== undefined && !_isPlainObject(record.simulatedDelta)) {
    err('$.simulatedDelta', 'simulatedDelta must be null (before apply) or an object (after apply)');
  }
  return { valid: errors.length === 0, errors };
}

// Re-exported for scenario-engine.js's own use tagging overridden
// fields — 'hypothetical' is already a real OBLIGATION_FACT_TYPES value
// (unused by any producer before this module), never a new vocabulary.
export const SCENARIO_FACT_TYPE = OBLIGATION_FACT_TYPES.includes('hypothetical') ? 'hypothetical' : (() => {
  throw new Error('scenario.js: OBLIGATION_FACT_TYPES no longer includes "hypothetical" — this module\'s core assumption broke');
})();
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/scenario.test.js`
Expected: PASS, all 7 tests.

- [ ] **Step 8: Re-grep for every literal EVIDENCE_GRADES-shaped array to confirm no third copy was missed**

Run: `cd scanner && grep -rn "code_and_config" src/lineage/*.js src/lineage/*.json ../frontend/src 2>/dev/null`
Expected: exactly two hits — `protection.js` and `dataflow-graph.schema.json` — both already edited. If a third hit appears, edit it too before continuing.

- [ ] **Step 9: Add to `test:lineage` script wiring**

Edit `scanner/package.json`'s `test:lineage` script string — append
` test/lineage/scenario.test.js` before the closing quote (this task's
own test file must be in scope; later tasks append their own test files
the same way).

- [ ] **Step 10: Run the full lineage suite to confirm no regression**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures.

- [ ] **Step 11: Commit**

```bash
git add scanner/src/lineage/protection.js scanner/src/lineage/dataflow-graph.schema.json scanner/src/lineage/ids.js scanner/src/lineage/scenario.js scanner/test/lineage/scenario.test.js scanner/package.json
git commit -m "feat(lineage): add EVIDENCE_GRADES 'assumed' value and the Scenario extension contract"
```

---

### Task 2: `scenario-engine.js` — clone-and-override + verdict recomputation

**Files:**
- Create: `scanner/src/lineage/scenario-engine.js`
- Test: `scanner/test/lineage/scenario-engine.test.js`

**Interfaces:**
- Consumes: `SCENARIO_OPERATION_KINDS`, `SCENARIO_FACT_TYPE`,
  `validateScenario` from `scenario.js` (Task 1). `EVIDENCE_GRADES`,
  `aggregateVerdicts` from `protection.js`. `isSinkPermitted`,
  `permittingRules` from `../dataflow/privacy-sink-policy.js`.
- Produces: `applyScenario(baseGraph, scenario, opts = {}) ->
  {graph, appliedOperations, skippedOperations}` — `graph` is the
  cloned-and-overridden `DataFlowGraph v1`-shaped object (never the same
  object reference as `baseGraph`, and `baseGraph` is never mutated).
  `opts.privacySinkPolicy`/`opts.environment` are optional passthroughs
  to `isSinkPermitted`/`policyCtx`, mirroring `graph-builder.js`'s own
  `opts.privacySinkPolicy`/`opts.environment` — when omitted,
  `policyVerdict` recomputation is skipped for any touched flow (the
  base value is kept, never silently guessed). `appliedOperations`/
  `skippedOperations` are arrays of `{operation, reason?}` — an
  operation is skipped (never throws) when its `targetEdgeId`/
  `targetNodeId`/`targetFlowId` does not exist in the graph, since a
  Scenario written against an older graph snapshot must degrade
  honestly, not crash. Task 3 consumes `graph` as one half of a
  `scenario-diff.js` comparison.

- [ ] **Step 1: Write failing tests**

Create `scanner/test/lineage/scenario-engine.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { emptyProtection } from '../../src/lineage/protection.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0', generatedAt: '2026-09-02T00:00:00.000Z',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
      { id: 'node:sink-store', kind: 'sink', subtype: 'database', destination: { literalValue: 'db.internal.example.com' }, storeDetail: { operation: 'write' } },
      { id: 'node:sink-external', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.vendor.example.com' }, storeDetail: null },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:sink-store', relationship: 'flows_to', protection: emptyProtection() },
      { id: 'edge:2', from: 'node:source', to: 'node:sink-external', relationship: 'flows_to', protection: emptyProtection() },
    ],
    dataElements: [
      { id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null },
    ],
    flows: [
      { id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink-store', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} },
      { id: 'flow:2', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink-external', edgeIds: ['edge:2'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} },
    ],
    evidence: [], coverage: {},
  };
}

test('applyScenario never mutates the base graph', () => {
  const base = _fixtureGraph();
  const before = JSON.parse(JSON.stringify(base));
  applyScenario(base, {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:2' }],
  });
  assert.deepEqual(base, before);
});

test('require_transit_protection overrides edge.protection.transit with assumed evidence and recomputes protectionSummary', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:2' }],
  });
  const edge = graph.edges.find((e) => e.id === 'edge:2');
  assert.deepEqual(edge.protection.transit, { verdict: 'protected', evidenceGrade: 'assumed' });
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.protectionSummary, 'protected');
  // Untouched flow/edge stay exactly as the base graph had them.
  assert.equal(graph.flows.find((f) => f.id === 'flow:1').protectionSummary, 'not_assessed');
});

test('apply_handling overrides flow.handling-driven atRest for a store sink and recomputes protectionSummary', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'apply_handling', targetEdgeId: 'edge:1', handling: 'encrypted' }],
  });
  const edge = graph.edges.find((e) => e.id === 'edge:1');
  assert.deepEqual(edge.protection.atRest, { verdict: 'protected', evidenceGrade: 'assumed' });
  assert.equal(graph.flows.find((f) => f.id === 'flow:1').protectionSummary, 'protected');
});

test('remove_entity cascades: removing a sink node drops its edges and flows too', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'remove_entity', targetNodeId: 'node:sink-external' }],
  });
  assert.equal(graph.nodes.find((n) => n.id === 'node:sink-external'), undefined);
  assert.equal(graph.edges.find((e) => e.id === 'edge:2'), undefined);
  assert.equal(graph.flows.find((f) => f.id === 'flow:2'), undefined);
  // Unrelated node/edge/flow survive untouched.
  assert.ok(graph.nodes.find((n) => n.id === 'node:sink-store'));
  assert.ok(graph.flows.find((f) => f.id === 'flow:1'));
});

test('replace_recipient_fact overrides node.destination and recomputes policyVerdict when a policy is supplied', () => {
  const policy = { allow: [{ sink: 'external-api', class: 'PII', destination: 'trusted\\.example\\.com' }] };
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink-external', field: 'destination', value: { literalValue: 'trusted.example.com' } }],
  }, { privacySinkPolicy: policy });
  const node = graph.nodes.find((n) => n.id === 'node:sink-external');
  assert.equal(node.destination.literalValue, 'trusted.example.com');
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.policyVerdict, 'permitted');
});

test('policyVerdict recomputation is skipped (base value kept) when no policy is supplied', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink-external', field: 'destination', value: { literalValue: 'trusted.example.com' } }],
  });
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.policyVerdict, 'not_evaluated');
});

test('change_storage_fact overrides node.storeDetail fields', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'change_storage_fact', targetNodeId: 'node:sink-store', field: 'retentionDays', value: 30 }],
  });
  const node = graph.nodes.find((n) => n.id === 'node:sink-store');
  assert.equal(node.storeDetail.retentionDays, 30);
  assert.equal(node.storeDetail.operation, 'write'); // untouched sibling field survives
});

test('change_governance_fact overrides flow.governanceRefs', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'change_governance_fact', targetFlowId: 'flow:1', field: 'lawfulBasis', value: 'consent' }],
  });
  const flow = graph.flows.find((f) => f.id === 'flow:1');
  assert.equal(flow.governanceRefs.lawfulBasis, 'consent');
});

test('an operation targeting a non-existent id is skipped, never throws', () => {
  const { graph, appliedOperations, skippedOperations } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:does-not-exist' }],
  });
  assert.equal(appliedOperations.length, 0);
  assert.equal(skippedOperations.length, 1);
  assert.match(skippedOperations[0].reason, /not found/);
  assert.deepEqual(graph, _fixtureGraph()); // clone is otherwise identical to base
});

test('multiple operations in one scenario apply in order and each is independently reported', () => {
  const { appliedOperations } = applyScenario(_fixtureGraph(), {
    operations: [
      { kind: 'require_transit_protection', targetEdgeId: 'edge:2' },
      { kind: 'apply_handling', targetEdgeId: 'edge:1', handling: 'encrypted' },
    ],
  });
  assert.equal(appliedOperations.length, 2);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/scenario-engine.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `scenario-engine.js`**

Create `scanner/src/lineage/scenario-engine.js`:

```js
// scenario-engine.js — M5 deliverable #3a (FR-502): the clone-and-
// override engine. Deep-clones the base graph, applies each declared
// Scenario operation, then re-runs the SAME two pure aggregators
// graph-builder.js's own real pipeline uses (aggregateVerdicts,
// isSinkPermitted) over only the flows an operation actually touched —
// never re-running the taint/path pipeline, per this sub-project's own
// scoping doc.
//
// The exact recomputation this module mirrors, confirmed by direct
// read of graph-builder.js's own real edge/flow minting pass:
//   flow.protectionSummary = aggregateVerdicts([
//     edge.protection.transit.verdict,
//     edge.protection.atRest.verdict,
//     edge.protection.handling.verdict,
//   ])
//   flow.policyVerdict = isSinkPermitted(dataElement.dataClasses, sinkNode.subtype,
//     opts.privacySinkPolicy, { environment: opts.environment, destination: sinkNode.destination?.literalValue ?? null })
//     ? 'permitted' : 'prohibited'  (or 'not_evaluated' if no policy/classes/sinkKind)

import { EVIDENCE_GRADES, aggregateVerdicts } from './protection.js';
import { isSinkPermitted } from '../dataflow/privacy-sink-policy.js';
import { SCENARIO_FACT_TYPE } from './scenario.js';

function _deepClone(v) { return JSON.parse(JSON.stringify(v)); }

function _byId(arr) { return new Map((arr ?? []).map((x) => [x.id, x])); }

function _recomputeProtectionSummary(edge) {
  return aggregateVerdicts([
    edge.protection.transit.verdict,
    edge.protection.atRest.verdict,
    edge.protection.handling.verdict,
  ]);
}

function _recomputePolicyVerdict(flow, graph, opts) {
  if (opts.privacySinkPolicy == null) return null; // signal: leave flow.policyVerdict untouched
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  const classes = de?.dataClasses ?? [];
  const sinkKind = sinkNode?.subtype ?? null;
  if (!classes.length || !sinkKind) return 'not_evaluated';
  const ctx = { environment: opts.environment ?? null, destination: sinkNode?.destination?.literalValue ?? null };
  return isSinkPermitted(classes, sinkKind, opts.privacySinkPolicy, ctx) ? 'permitted' : 'prohibited';
}

// Every flow using this edge (by edgeIds membership) gets protectionSummary
// recomputed; policyVerdict only for flows whose sink node's destination
// or the flow's own dataClasses could plausibly have changed — but since
// applyScenario always calls this after ANY node/edge touch to be safe
// (recomputation is cheap and idempotent), scope is simply "every flow
// touching this edge or this node".
function _touchedFlows(graph, { edgeId, nodeId }) {
  return graph.flows.filter((f) =>
    (edgeId && f.edgeIds.includes(edgeId)) ||
    (nodeId && (f.source === nodeId || f.sink === nodeId)));
}

function _recomputeTouchedFlows(graph, touch, opts) {
  for (const flow of _touchedFlows(graph, touch)) {
    const edge = graph.edges.find((e) => flow.edgeIds.includes(e.id));
    if (edge) flow.protectionSummary = _recomputeProtectionSummary(edge);
    const newPolicyVerdict = _recomputePolicyVerdict(flow, graph, opts);
    if (newPolicyVerdict !== null) flow.policyVerdict = newPolicyVerdict;
  }
}

function _applyRequireTransitProtection(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  edge.protection.transit = { verdict: 'protected', evidenceGrade: op.evidenceGrade ?? SCENARIO_FACT_TYPE === 'hypothetical' ? 'assumed' : 'assumed' };
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyHandling(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  // Mirrors graph-builder.js's own gate: 'encrypted' handling before a
  // store sink is what earns the atRest 'protected' verdict there.
  if (op.handling === 'encrypted') {
    edge.protection.atRest = { verdict: 'protected', evidenceGrade: 'assumed' };
  } else {
    edge.protection.handling = { verdict: 'protected', evidenceGrade: 'assumed' };
  }
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyRemoveEntity(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  const removedEdgeIds = new Set(graph.edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => e.id));
  graph.edges = graph.edges.filter((e) => !removedEdgeIds.has(e.id));
  graph.flows = graph.flows.filter((f) => f.source !== node.id && f.sink !== node.id
    && !f.edgeIds.some((id) => removedEdgeIds.has(id)));
  graph.nodes = graph.nodes.filter((n) => n.id !== node.id);
  return { ok: true };
}

function _applyReplaceRecipientFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  node[op.field] = op.value;
  _recomputeTouchedFlows(graph, { nodeId: node.id }, op._opts);
  return { ok: true };
}

function _applyChangeStorageFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  node.storeDetail = { ...(node.storeDetail ?? {}), [op.field]: op.value };
  return { ok: true };
}

function _applyChangeGovernanceFact(graph, op) {
  const flow = _byId(graph.flows).get(op.targetFlowId);
  if (!flow) return { ok: false, reason: `targetFlowId "${op.targetFlowId}" not found in graph.flows` };
  flow.governanceRefs = { ...(flow.governanceRefs ?? {}), [op.field]: op.value };
  return { ok: true };
}

const _APPLIERS = {
  require_transit_protection: _applyRequireTransitProtection,
  apply_handling: _applyHandling,
  remove_entity: _applyRemoveEntity,
  replace_recipient_fact: _applyReplaceRecipientFact,
  change_storage_fact: _applyChangeStorageFact,
  change_governance_fact: _applyChangeGovernanceFact,
};

/**
 * Apply `scenario.operations` to a deep clone of `baseGraph`. Never
 * mutates `baseGraph`. An operation whose target id does not exist in
 * the graph is skipped (reported in `skippedOperations`), never thrown —
 * a Scenario written against an older snapshot must degrade honestly.
 * `opts.privacySinkPolicy`/`opts.environment` mirror graph-builder.js's
 * own opts; omitting privacySinkPolicy means policyVerdict
 * recomputation is skipped entirely (base value kept on every touched
 * flow) rather than guessed.
 */
export function applyScenario(baseGraph, scenario, opts = {}) {
  const graph = _deepClone(baseGraph);
  const appliedOperations = [];
  const skippedOperations = [];
  for (const op of scenario.operations ?? []) {
    const applier = _APPLIERS[op.kind];
    if (!applier) {
      skippedOperations.push({ operation: op, reason: `unrecognized operation kind "${op.kind}"` });
      continue;
    }
    const result = applier(graph, { ...op, _opts: opts });
    if (result.ok) appliedOperations.push({ operation: op });
    else skippedOperations.push({ operation: op, reason: result.reason });
  }
  return { graph, appliedOperations, skippedOperations };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/scenario-engine.test.js`
Expected: PASS, all 11 tests.

- [ ] **Step 5: Clean up the placeholder ternary in `_applyRequireTransitProtection`**

The ternary `op.evidenceGrade ?? SCENARIO_FACT_TYPE === 'hypothetical' ? 'assumed' : 'assumed'`
written above always evaluates to `'assumed'` and is confusing — simplify
in `scanner/src/lineage/scenario-engine.js`:

```js
  edge.protection.transit = { verdict: 'protected', evidenceGrade: 'assumed' };
```

(An operation-level `evidenceGrade` override is not a real requirement
from FR-502's own text — every simulated field is `'assumed'`,
unconditionally — so drop `op.evidenceGrade` entirely rather than half-
support an override no test exercises.)

- [ ] **Step 6: Re-run to confirm the simplification didn't break anything**

Run: `cd scanner && node --test test/lineage/scenario-engine.test.js`
Expected: PASS, all 11 tests.

- [ ] **Step 7: Add to `test:lineage` script wiring**

Edit `scanner/package.json`'s `test:lineage` script — append
` test/lineage/scenario-engine.test.js`.

- [ ] **Step 8: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/scenario-engine.js scanner/test/lineage/scenario-engine.test.js scanner/package.json
git commit -m "feat(lineage): add the Scenario clone-and-override engine (applyScenario)"
```

---

### Task 3: `scenario-diff.js` — dedicated Scenario delta comparison

**Files:**
- Create: `scanner/src/lineage/scenario-diff.js`
- Test: `scanner/test/lineage/scenario-diff.test.js`

**Interfaces:**
- Consumes: nothing from `scenario-engine.js` directly (works on any two
  `DataFlowGraph v1`-shaped `graph` objects — the base graph and a
  `{graph}` from `applyScenario`, or two scenario graphs for a
  scenario-vs-scenario comparison).
- Produces: `diffScenarioGraph(baseGraph, scenarioGraph) ->
  {changedEntities: [{id, kind, changedFields: [{field, before, after}]}],
  removedEntityIds: [string]}` — `kind` is `'node'|'edge'|'flow'`.
  `WATCHED_SCENARIO_FIELDS` — the frozen per-kind field list this
  function compares, exported so Task 4's CLI report and this task's own
  tests share one source of truth.

- [ ] **Step 1: Write failing tests**

Create `scanner/test/lineage/scenario-diff.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffScenarioGraph, WATCHED_SCENARIO_FIELDS } from '../../src/lineage/scenario-diff.js';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { emptyProtection } from '../../src/lineage/protection.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
      { id: 'node:sink', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.example.com' }, storeDetail: null },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to', protection: emptyProtection() },
    ],
    dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
    flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
    evidence: [], coverage: {},
  };
}

test('no operations applied -> no changed entities, no removed entities', () => {
  const base = _fixtureGraph();
  const { changedEntities, removedEntityIds } = diffScenarioGraph(base, base);
  assert.deepEqual(changedEntities, []);
  assert.deepEqual(removedEntityIds, []);
});

test('a require_transit_protection operation surfaces the edge AND its flow as changed', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const edgeChange = changedEntities.find((c) => c.id === 'edge:1');
  assert.equal(edgeChange.kind, 'edge');
  assert.ok(edgeChange.changedFields.some((f) => f.field === 'protection.transit'));
  const flowChange = changedEntities.find((c) => c.id === 'flow:1');
  assert.equal(flowChange.kind, 'flow');
  assert.ok(flowChange.changedFields.some((f) => f.field === 'protectionSummary' && f.before === 'not_assessed' && f.after === 'protected'));
});

test('a remove_entity operation reports removedEntityIds for the node, its edge, and its flow — never as a changedEntities row', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'remove_entity', targetNodeId: 'node:sink' }] });
  const { changedEntities, removedEntityIds } = diffScenarioGraph(base, graph);
  assert.deepEqual([...removedEntityIds].sort(), ['edge:1', 'flow:1', 'node:sink']);
  assert.equal(changedEntities.find((c) => c.id === 'node:sink'), undefined);
});

test('WATCHED_SCENARIO_FIELDS never includes an entity-identity field like id/kind/from/to', () => {
  for (const fields of Object.values(WATCHED_SCENARIO_FIELDS)) {
    assert.ok(!fields.includes('id'));
  }
});

test('diffScenarioGraph never throws on a graph with zero flows/edges', () => {
  const empty = { ..._fixtureGraph(), nodes: [], edges: [], flows: [], dataElements: [] };
  assert.doesNotThrow(() => diffScenarioGraph(empty, empty));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/scenario-diff.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `scenario-diff.js`**

Create `scanner/src/lineage/scenario-diff.js`:

```js
// scenario-diff.js — M5 deliverable #3a (FR-502): a dedicated
// comparison for a Scenario's own simulated graph delta. Deliberately
// NOT graph-diff.js's computeGraphDiff — see this sub-project's own
// scoping doc for the full reasoning: computeGraphDiff's flow-
// reidentification pairing and causeClassification vocabulary
// (`'application_change'`, `'possible_coverage_regression'`,
// `'reidentified'`) are shaped for a REAL rescan across two commits,
// where the cause of a change is genuinely ambiguous. A Scenario's own
// delta has no such ambiguity — every difference between the base graph
// and a scenario clone IS the declared hypothetical operation that
// produced it — so this module reports only "what differs", with no
// cause classification and no reidentification.

export const WATCHED_SCENARIO_FIELDS = Object.freeze({
  node: Object.freeze(['destination', 'storeDetail']),
  edge: Object.freeze(['protection.transit', 'protection.atRest', 'protection.handling']),
  flow: Object.freeze(['policyVerdict', 'protectionSummary', 'governanceRefs']),
});

function _get(obj, dottedPath) {
  return dottedPath.split('.').reduce((v, k) => (v == null ? v : v[k]), obj);
}

function _deepEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

function _byId(arr) { return new Map((arr ?? []).map((x) => [x.id, x])); }

function _diffKind(beforeArr, afterArr, kind) {
  const beforeMap = _byId(beforeArr);
  const afterMap = _byId(afterArr);
  const changed = [];
  const removed = [];
  for (const [id, beforeEntity] of beforeMap) {
    const afterEntity = afterMap.get(id);
    if (!afterEntity) { removed.push(id); continue; }
    const changedFields = [];
    for (const field of WATCHED_SCENARIO_FIELDS[kind]) {
      const before = _get(beforeEntity, field);
      const after = _get(afterEntity, field);
      if (!_deepEqual(before, after)) changedFields.push({ field, before, after });
    }
    if (changedFields.length) changed.push({ id, kind, changedFields });
  }
  return { changed, removed };
}

/**
 * Compare `baseGraph` against `scenarioGraph` (either a real
 * applyScenario({graph}) result, or another Scenario's own graph, for a
 * scenario-vs-scenario comparison). Never throws — an empty/missing
 * entity array on either side is treated as zero entities.
 */
export function diffScenarioGraph(baseGraph, scenarioGraph) {
  const nodeDiff = _diffKind(baseGraph.nodes ?? [], scenarioGraph.nodes ?? [], 'node');
  const edgeDiff = _diffKind(baseGraph.edges ?? [], scenarioGraph.edges ?? [], 'edge');
  const flowDiff = _diffKind(baseGraph.flows ?? [], scenarioGraph.flows ?? [], 'flow');
  return {
    changedEntities: [...nodeDiff.changed, ...edgeDiff.changed, ...flowDiff.changed],
    removedEntityIds: [...nodeDiff.removed, ...edgeDiff.removed, ...flowDiff.removed],
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/scenario-diff.test.js`
Expected: PASS, all 5 tests.

- [ ] **Step 5: Add to `test:lineage` script wiring**

Edit `scanner/package.json`'s `test:lineage` script — append
` test/lineage/scenario-diff.test.js`.

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/scenario-diff.js scanner/test/lineage/scenario-diff.test.js scanner/package.json
git commit -m "feat(lineage): add scenario-diff.js, a dedicated Scenario delta comparison"
```

---

### Task 4: CLI wiring (`dataflow scenario apply`) + docs

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/dataflow.md`
- Modify: `scanner/src/lineage/CLAUDE.md`
- Test: `scanner/test/server/dataflow-scenario-cli.test.js` (new file,
  named to match this repo's existing convention of CLI-command tests
  living under `test/server/` when they exercise `bin/agentic-security.js`
  dataflow subcommands — confirmed by `npm run test:server`'s own scope
  covering `cmdExplore`/`cmdDataflowExport`)

**Interfaces:**
- Consumes: `applyScenario` (Task 2), `diffScenarioGraph` +
  `WATCHED_SCENARIO_FIELDS` (Task 3), `validateScenario` (Task 1),
  `loadSignedGraph` (`src/server/graph-loader.js`, already shipped).
- Produces: `agentic-security dataflow scenario apply [path]
  --operations <file.json> --output <file> [--format json|markdown]
  [--privacy-sink-policy <file>] [--environment <name>]` — writes a
  Scenario delta report to `--output`. Exit codes: `0` success, `1`
  graph-load failure (same 4 messages `loadSignedGraph` already
  produces), `2` a CLI argument or `--operations` file problem
  (malformed JSON, failed `validateScenario`).

- [ ] **Step 1: Write the failing CLI test**

Create `scanner/test/server/dataflow-scenario-cli.test.js`. The fixture
helper below is copied from the real, already-shipped pattern in
`test/server/cmd-dataflow-export.test.js`'s own `_writeSignedGraph`
(confirmed by direct read: `statePath(root, 'lineage-graph.json')` +
`signLastScan` from `../../src/posture/integrity.js`, `spawnSync` rather
than `execFileSync` — this test area's own established convention, not
`child_process.execFileSync` used elsewhere in this repo), extended with
one real node/edge/flow/dataElement so `edge:1` exists for the
operations file to target:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-scenario-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

// Mirrors cmd-dataflow-export.test.js's own _writeSignedGraph exactly
// (same statePath key, same signLastScan call), extended with one real
// source->sink edge/flow so a scenario operation has a real id to target.
function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-dataflow-scenario-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [
        { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
        { id: 'node:sink', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.example.com' }, storeDetail: null },
      ],
      edges: [
        { id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to', protection: { transit: { verdict: 'not_assessed', evidenceGrade: 'none' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } } },
      ],
      dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
      transformations: [],
      flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
      controls: [], policies: [], evidence: [],
      coverage: {}, limitations: [], extensions: {},
    },
    null, 2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('dataflow scenario apply: writes a JSON delta report and exits 0', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }],
  }));
  const outFile = path.join(root, 'delta.json');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', outFile, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.ok(Array.isArray(report.changedEntities));
  assert.ok(Array.isArray(report.appliedOperations));
  assert.equal(report.appliedOperations.length, 1);
  assert.ok(report.changedEntities.some((c) => c.id === 'edge:1'));
  assert.ok(report.changedEntities.some((c) => c.id === 'flow:1'));
});

test('dataflow scenario apply: an operation with an unrecognized kind exits 2 with a validateScenario error on stderr', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [{ kind: 'not_a_real_kind' }] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unrecognized operation kind/);
});

test('dataflow scenario apply: missing --output exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow scenario apply: missing graph -> exit 1, one of loadSignedGraph\'s own messages', () => {
  const root = _mkTmpProject();
  const opsFile = path.join(root, 'ops.json');
  fs.writeFileSync(opsFile, JSON.stringify({ operations: [] }));
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'scenario', 'apply', root, '--operations', opsFile, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/server/dataflow-scenario-cli.test.js`
Expected: FAIL — `dataflow scenario apply` is not a recognized subcommand yet.

- [ ] **Step 3: Add the CLI handler**

In `scanner/bin/agentic-security.js`, near `cmdDataflowDiff` (search for
`async function cmdDataflowDiff`), add a new function directly after it:

```js
// agentic-security dataflow scenario apply [path] --operations <file>
// --output <file> [--format json|markdown] [--privacy-sink-policy <file>]
// [--environment <name>] — M5 deliverable #3a (FR-502). Loads the
// already-scanned, already-signed graph via loadSignedGraph (same
// loader/error-message contract as cmdDataflowExport/cmdDataflowDiff),
// applies the Scenario in --operations via applyScenario, diffs the
// result against the base graph via diffScenarioGraph, writes the
// report to --output. Exit codes: 0 success, 1 graph-load failure
// (loadSignedGraph's own 4 messages), 2 argument/operations-file
// problem.
async function cmdDataflowScenarioApply(args) {
  const target = args._[3] || '.'; // args._ = ['dataflow', 'scenario', 'apply', <path>?]
  const targetAbs = path.resolve(target);

  const operationsFlag = args.flags.operations;
  if (!operationsFlag || typeof operationsFlag !== 'string') {
    process.stderr.write('agentic-security dataflow scenario apply: --operations <file> is required.\n');
    return 2;
  }
  const outputPath = args.flags.output;
  if (!outputPath || typeof outputPath !== 'string') {
    process.stderr.write('agentic-security dataflow scenario apply: --output <file> is required.\n');
    return 2;
  }
  const format = args.flags.format ?? 'json';
  if (format !== 'json' && format !== 'markdown') {
    process.stderr.write(`agentic-security dataflow scenario apply: --format must be one of json|markdown (got ${JSON.stringify(format)}).\n`);
    return 2;
  }

  let opsInput;
  try {
    opsInput = JSON.parse(fs.readFileSync(path.resolve(operationsFlag), 'utf8'));
  } catch (e) {
    process.stderr.write(`agentic-security dataflow scenario apply: could not read/parse --operations file "${operationsFlag}": ${e.message}\n`);
    return 2;
  }

  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const loaded = loadSignedGraph(targetAbs);
  if (!loaded.ok) {
    process.stderr.write(`agentic-security dataflow scenario apply: ${loaded.message}\n`);
    return 1;
  }
  const baseGraph = loaded.graph;

  const { validateScenario } = await import('../src/lineage/scenario.js');
  const scenarioDraft = {
    id: 'scenario:cli-draft', version: '1.0.0',
    baseGraphId: baseGraph.graphId, baseGraphDigest: baseGraph.graphId,
    operations: opsInput.operations ?? [],
    assumptions: opsInput.assumptions ?? [], author: opsInput.author ?? 'cli',
    createdAt: new Date().toISOString(), expiration: null,
    simulatedDelta: null, verificationRequirements: opsInput.verificationRequirements ?? [],
  };
  const { valid, errors } = validateScenario(scenarioDraft);
  if (!valid) {
    process.stderr.write(`agentic-security dataflow scenario apply: --operations file failed validation:\n${errors.map((e) => `  ${e.path}: ${e.message}`).join('\n')}\n`);
    return 2;
  }

  let privacySinkPolicy;
  const policyFlag = args.flags['privacy-sink-policy'];
  if (policyFlag !== undefined) {
    try {
      privacySinkPolicy = JSON.parse(fs.readFileSync(path.resolve(policyFlag), 'utf8'));
    } catch (e) {
      process.stderr.write(`agentic-security dataflow scenario apply: could not read/parse --privacy-sink-policy file "${policyFlag}": ${e.message}\n`);
      return 2;
    }
  }

  const { applyScenario } = await import('../src/lineage/scenario-engine.js');
  const { diffScenarioGraph } = await import('../src/lineage/scenario-diff.js');
  const opts = { privacySinkPolicy, environment: args.flags.environment };
  const { graph: scenarioGraph, appliedOperations, skippedOperations } = applyScenario(baseGraph, scenarioDraft, opts);
  const { changedEntities, removedEntityIds } = diffScenarioGraph(baseGraph, scenarioGraph);

  const report = { scenarioId: scenarioDraft.id, appliedOperations, skippedOperations, changedEntities, removedEntityIds, generatedAt: new Date().toISOString() };
  let data;
  if (format === 'json') {
    data = JSON.stringify(report, null, 2);
  } else {
    const lines = [`# Scenario delta`, '', `Applied ${appliedOperations.length} operation(s), skipped ${skippedOperations.length}.`, ''];
    if (skippedOperations.length) {
      lines.push('## Skipped operations', '');
      for (const s of skippedOperations) lines.push(`- \`${s.operation.kind}\`: ${s.reason}`);
      lines.push('');
    }
    lines.push('## Changed entities', '');
    for (const c of changedEntities) {
      lines.push(`- **${c.kind} ${c.id}**`);
      for (const f of c.changedFields) lines.push(`  - \`${f.field}\`: ${JSON.stringify(f.before)} → ${JSON.stringify(f.after)}`);
    }
    if (removedEntityIds.length) {
      lines.push('', '## Removed entities', '');
      for (const id of removedEntityIds) lines.push(`- ${id}`);
    }
    data = lines.join('\n') + '\n';
  }
  fs.writeFileSync(path.resolve(outputPath), data);
  return 0;
}
```

- [ ] **Step 4: Wire the subcommand dispatch**

Find the dataflow dispatch block (search for
`else if (sub === 'diff') { process.exit(await cmdDataflowDiff(args)); }`,
line ~4402) and add a `scenario` branch immediately after it. The
`scenario` subcommand itself has its own sub-verb (`apply`), read from
`args._[2]`:

```js
        else if (sub === 'scenario') {
          const scenarioSub = args._[2];
          if (scenarioSub === 'apply') { process.exit(await cmdDataflowScenarioApply(args)); }
          else {
            process.stderr.write(`agentic-security dataflow scenario: unrecognized sub-command "${scenarioSub}" — must be "apply".\n`);
            process.exit(2);
          }
        }
```

- [ ] **Step 5: Update the dataflow help text**

Find the `dataflow export [path] --format ...` help line (search for
`dataflow export \[path\]`, line ~147) and add a sibling line directly
after it:

```
  dataflow scenario apply [path] --operations <file.json> --output <file> [--format json|markdown]
```

- [ ] **Step 6: Run the CLI test**

Run: `cd scanner && node --test test/server/dataflow-scenario-cli.test.js`
Expected: PASS, all 4 tests. If Step 1's fixture helper needed real
adjustment against the actual signed-graph format, iterate here until
green — this is the step where that gets discovered, not guessed in
advance.

- [ ] **Step 7: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: exits 0, `dist/agentic-security.mjs` and its `.sha256` sidecar
both change (confirm via `git status` — do not conclude "no change
needed" from grepping only `dist/agentic-security.mjs`; per this
session's own established gotcha, check `git status` on the WHOLE
`dist/` directory, since ncc may chunk this new code into a separate
numbered file).

- [ ] **Step 8: Add a module-boundary test asserting no obligation/impact wiring**

Create `scanner/test/lineage/scenario-no-obligation-wiring.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LINEAGE_DIR = path.join(__dirname, '../../src/lineage');

test('obligation-mapping.js, obligation-predicates.js, and decision-story.js never import scenario.js or scenario-engine.js', () => {
  for (const file of ['obligation-mapping.js', 'obligation-predicates.js', 'decision-story.js']) {
    const src = fs.readFileSync(path.join(LINEAGE_DIR, file), 'utf8');
    assert.ok(!src.includes("from './scenario.js'"), `${file} must not import scenario.js`);
    assert.ok(!src.includes("from './scenario-engine.js'"), `${file} must not import scenario-engine.js`);
  }
});
```

Run: `cd scanner && node --test test/lineage/scenario-no-obligation-wiring.test.js`
Expected: PASS.

- [ ] **Step 9: Add both new test files to their scoped scripts**

Edit `scanner/package.json` — append
` test/lineage/scenario-no-obligation-wiring.test.js` to `test:lineage`,
and add `test:server`'s script string with
` test/server/dataflow-scenario-cli.test.js` appended.

- [ ] **Step 10: Update `commands/dataflow.md`**

Add a short new section documenting the `scenario apply` sub-command,
mirroring the existing `dataflow diff`/`dataflow export` sections'
format exactly (read the file first for the exact heading style and
flag-table format already used, then match it) — one paragraph plus a
flag table: `--operations` (required), `--output` (required), `--format`
(default `json`), `--privacy-sink-policy` (optional), `--environment`
(optional). State plainly that this simulates a hypothetical change
without mutating the real scan artifact, and that every overridden field
carries `'assumed'` evidence, never real evidence.

- [ ] **Step 11: Update `scanner/src/lineage/CLAUDE.md`**

Add one new row (or short section, matching the file's own existing
per-module table format — read the file's current structure before
editing) documenting `scenario.js`, `scenario-engine.js`, and
`scenario-diff.js` together as "Milestone 5, What-If Architecture
Simulator (FR-502, sub-project 3a) — COMPLETE", covering: the `'assumed'`
evidence-grade ruling and why (same axis as `EVIDENCE_GRADES`, unlike
`FLOW_EVIDENCE_GRADES`'s deliberately separate vocabulary); the 6
in-scope operation kinds and the 7th (synthetic insertion) explicitly
deferred to 3b; why `scenario-diff.js` is dedicated rather than reusing
`computeGraphDiff`.

- [ ] **Step 12: Run the full test:lineage and test:server suites**

Run: `cd scanner && npm run test:lineage && npm run test:server`
Expected: PASS, 0 failures, both.

- [ ] **Step 13: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: PASS, 0 failures. Capture and read the real exit code
(`echo $?` immediately after) — do not infer success from output length.

- [ ] **Step 14: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ commands/dataflow.md scanner/src/lineage/CLAUDE.md scanner/test/server/dataflow-scenario-cli.test.js scanner/test/lineage/scenario-no-obligation-wiring.test.js scanner/package.json
git commit -m "feat(cli): wire dataflow scenario apply, docs, and no-obligation-wiring guard"
```

---

## Final Review Checklist (for the coordinator, not a task)

- Confirm `EVIDENCE_GRADES` has exactly one new value (`'assumed'`) and
  its schema mirror matches exactly (Task 1 Step 8's grep, re-run once
  more at the end).
- Confirm no test anywhere asserts `applyScenario` or
  `diffScenarioGraph` mutates `baseGraph` by reference equality alone —
  Task 2's own mutation test uses `deepStrictEqual` against a pre-call
  snapshot, the stronger check.
- Confirm the CLI's `--operations` validation path is exercised by a
  real malformed-kind test (Task 4 Step 1), not just Task 1's unit-level
  `validateScenario` test — two different layers, both need coverage.
- Re-run `npm run build` one final time after ALL doc-only edits in Task
  4 Steps 10-11 land, and check `git status` on the whole `dist/`
  directory — comment-only edits to `bin/agentic-security.js` do not
  change bundled behavior, but per this session's own established
  gotcha (ncc preserves comments in some unminified chunks), a stale
  bundle after a doc-only edit is still a real, disclosed risk worth one
  more check rather than assuming Step 7 already covered it.
