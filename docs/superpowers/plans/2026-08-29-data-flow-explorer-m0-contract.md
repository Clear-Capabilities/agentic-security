# Data Flow Explorer — Milestone 0 (Contract & Fixture) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the canonical `DataFlowGraph v1` contract (schema, stable-ID spec, taxonomy, protection-verdict model), a deterministic flagship fixture that exercises it, and the backend-only Milestone-0 deliverables (threat model doc, first benchmark fixtures, a performance harness skeleton) — the foundation every later Data Flow Explorer milestone builds on.

**Architecture:** New isolated package `scanner/src/lineage/` (per PRD §18.1, mirroring how `privacy-deep-walker.js` was kept isolated from `dataflow/engine.js` — see D-0047 in `scanner/src/dataflow/CLAUDE.md`). This milestone is backend-only: schema + ID + taxonomy + protection modules, a hand-rolled structural validator (no new runtime dependency — matches this codebase's existing preference for hand-rolled implementations over adding libraries), a real JSON Schema document for external interop, and a fixture-generator script that produces a committed, deterministic flagship graph. No frontend/UI work happens in this plan — that is Milestone 0's second half, planned separately once this contract is frozen (later plans cannot name exact node/edge/projection shapes until this one lands).

**Tech Stack:** Node ≥ 24, ESM, `node:crypto` (already used for stable IDs elsewhere, see `scanner/src/posture/stable-id.js`), `node:test` + `node:assert` (existing test runner convention), no new npm dependencies.

**Spec:** `/Users/ross/code/agentic-security/AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` — primarily §9 (classification model), §10 (canonical graph contract), §18.1–18.3 (lineage-engine architecture, inputs, build phases — this plan only reaches phase 12 "validate the graph contract," not phases 2–11 which are Milestone 1/2), §20 (coverage/assurance), §22.2 (benchmark expansion design), §24 (privacy/security of the visualization), §26 Milestone 0 exit gate, Appendix D (visual reference fixture — D.1–D.3 only; D.4–D.6 golden-image/design-handoff deliverables belong to the second Milestone-0 plan).

## Global Constraints

- ESM throughout `scanner/src/` — `import`/`export`, no CommonJS.
- No new npm dependency without a documented reason; this plan adds none.
- Every new module needs a paired `vulnerable/clean`-style test file under `scanner/test/lineage/` following the existing `node --test` convention (see `scanner/CLAUDE.md`'s "Test commands" table).
- New test files must be added to a new `test:lineage` script in `scanner/package.json`, following the existing scoped-script pattern (explicit file list, not a glob — see every existing `test:*` entry).
- Nothing in this package may import from or mutate `scanner/src/dataflow/engine.js`'s taint state (PRD §18.1: "may not share mutable taint state with the general engine in P0"). Pure reads of `scanner/src/dataflow/privacy-taxonomy.js`'s exported functions are fine — that module is already a stateless, pure taxonomy reader.
- `DataFlowGraph v1`'s envelope, node, edge, dataElement, transformation, flow, and evidence contracts must match PRD §10.2–10.11 field names exactly — a future milestone's projection/API code will read these field names literally.
- The flagship fixture must carry a generic marker (`scope.source: 'fixture'`) rather than being special-cased by name anywhere in production code (PRD Appendix D.1: "Production UI code may not contain special cases keyed to fixture filenames, node names, endpoints, commits, authors, or expected verdicts").
- Every unknown/unverified fact in the fixture must be the literal string `'unknown'`, `'not_assessed'`, or `'manual_required'` — never guessed or defaulted to a passing verdict (PRD FR-504, §8.4 risk precedence).
- Follow this repo's `git commit` convention: commit after each task with a message describing the change; do not amend prior commits.

---

## File Structure

```
scanner/src/lineage/
  schema.js                          # Task 1 — enums, SCHEMA_VERSION
  ids.js                             # Task 2 — stable-ID functions
  protection.js                      # Task 3 — protection verdict model
  classification.js                  # Task 4 — data classes + AI contexts
  validate.js                        # Task 5 — structural graph validator
  dataflow-graph.schema.json         # Task 6 — authoritative JSON Schema doc
  CLAUDE.md                          # Task 12 — package-local guide
  fixtures/
    build-flagship-fixture.mjs       # Task 7 — deterministic fixture generator
    flagship-graph.json              # Task 7 — generated, committed output

scanner/test/lineage/
  schema.test.js                     # Task 1
  ids.test.js                        # Task 2
  protection.test.js                 # Task 3
  classification.test.js             # Task 4
  validate.test.js                   # Task 5
  json-schema-parity.test.js         # Task 6
  flagship-fixture.test.js           # Task 7
  flagship-fixture-semantics.test.js # Task 8

docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md   # Task 9

bench/data-lineage/
  README.md                          # Task 10
  fixtures/
    js-api-to-log-masked/{source.js,expected.json}
    js-api-to-log-raw/{source.js,expected.json}
    js-api-to-external-http-cleartext/{source.js,expected.json}
  perf/
    generate-synthetic-graph.mjs     # Task 11
    runner.mjs                       # Task 11

scanner/package.json                 # Task 12 — new test:lineage script
scanner/CLAUDE.md                    # Task 12 — new row in test-commands table
CLAUDE.md (root)                     # Task 12 — new row in repository-layout table
```

---

### Task 1: Schema enums and envelope constants

**Files:**
- Create: `scanner/src/lineage/schema.js`
- Test: `scanner/test/lineage/schema.test.js`

**Interfaces:**
- Produces: `SCHEMA_VERSION` (string `'1.0.0'`), `NODE_KINDS`, `MAPPING_TYPES`, `TRANSFORM_KINDS`, `REVERSIBILITY_VALUES`, `EXTERNALITY_VALUES`, `COVERAGE_STATUS_VALUES`, `DESTINATION_RESOLUTION_VALUES`, `POLICY_STATES`, `EVIDENCE_TYPES`, `FLOW_SUMMARY_VALUES`, `GRAPH_SCOPE_SOURCES`, `SOURCE_CATEGORIES`, `SINK_CATEGORIES` — all `Object.freeze([...])` string arrays. `emptyGraphEnvelope(overrides)` — returns a fresh `DataFlowGraph v1` envelope object with every required top-level key present and empty. `SOURCE_CATEGORIES`/`SINK_CATEGORIES` are the PRD section 11 (FR-101) / section 12 (FR-201) category taxonomy — a fixed vocabulary a node's `subtype` or an inventory row's category field draws from. This is the taxonomy itself, not the pattern-matching registries that recognize a category in real code (`source-registry.js`/`sink-registry.js`, PRD DFG-003 — Milestone 1).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/schema.test.js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/schema.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/schema.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/lineage/schema.js
//
// DataFlowGraph v1 — canonical envelope and enum contract (Data Flow
// Explorer PRD section 10). This module carries only pure constants and
// the empty-envelope constructor; no analysis logic lives here. A change
// to any array below is a schema-version-bumping change — see
// scanner/src/lineage/CLAUDE.md.
//
// Isolated from scanner/src/dataflow/ on purpose (PRD section 18.1): this
// package may read pure, stateless exports from dataflow/privacy-taxonomy.js
// but must never import scanner/src/dataflow/engine.js or touch its taint
// state.

export const SCHEMA_VERSION = '1.0.0';

export const NODE_KINDS = Object.freeze([
  'source', 'process', 'transform', 'api', 'store', 'queue',
  'log', 'sink', 'external', 'boundary', 'unresolved',
]);

export const MAPPING_TYPES = Object.freeze([
  'identity', 'rename', 'projection', 'serialization', 'deserialization',
  'transformation', 'aggregation', 'join', 'filter', 'sort', 'conditional', 'unknown',
]);

export const TRANSFORM_KINDS = Object.freeze([
  'mask', 'redact', 'tokenize', 'hash', 'encrypt', 'decrypt', 'encode',
  'decode', 'aggregate', 'truncate', 'normalize', 'custom', 'unknown',
]);

export const REVERSIBILITY_VALUES = Object.freeze(['reversible', 'irreversible', 'unknown']);

export const EXTERNALITY_VALUES = Object.freeze(['internal', 'external', 'unknown']);

export const COVERAGE_STATUS_VALUES = Object.freeze(['modeled', 'partial', 'candidate', 'unsupported', 'manual']);

export const DESTINATION_RESOLUTION_VALUES = Object.freeze([
  'literal', 'resolved_from_constant', 'resolved_from_config', 'resolved_from_schema',
  'declared_service', 'runtime_corroborated', 'dynamic', 'unknown',
]);

export const POLICY_STATES = Object.freeze([
  'prohibited', 'permitted', 'conditionally_permitted', 'manual_review_required', 'not_evaluated',
]);

export const EVIDENCE_TYPES = Object.freeze([
  'code', 'ir', 'configuration', 'iac', 'schema', 'service_declaration', 'policy', 'manual', 'runtime',
]);

export const FLOW_SUMMARY_VALUES = Object.freeze(['protected', 'unprotected', 'mixed', 'unknown', 'not_assessed']);

// Not named in the PRD's own envelope example (section 10.2) but required
// by Appendix D.1's "no special-casing by name" rule: the UI needs a
// GENERIC signal for the "Illustrative demo data" ribbon, not a check
// against a specific fixture filename or node id.
export const GRAPH_SCOPE_SOURCES = Object.freeze(['scan', 'fixture']);

// PRD section 11 (FR-101) source categories and section 12 (FR-201) sink
// categories — the fixed vocabulary a node's `subtype`/an inventory row's
// category field draws from. This is the TAXONOMY only; the pattern-
// matching registries that recognize one of these categories in real
// source code (source-registry.js / sink-registry.js, PRD DFG-003) are
// Milestone 1, not this module.
export const SOURCE_CATEGORIES = Object.freeze([
  'http-body', 'http-query', 'http-route', 'http-header', 'http-cookie', 'http-upload',
  'graphql-argument', 'grpc-field', 'cli-argument', 'env-value', 'queue-message',
  'database-read', 'storage-read', 'user-input', 'external-api-response',
  'webhook-payload', 'ai-model-output', 'ai-tool-result', 'ai-retrieved-document',
  'ai-memory', 'declared',
]);

export const SINK_CATEGORIES = Object.freeze([
  'log', 'stdout', 'http-response', 'client-storage', 'database', 'file', 'object-storage',
  'cache', 'queue', 'analytics', 'monitoring', 'email', 'sms', 'push-notification', 'collaboration',
  'external-api', 'webhook', 'ai-model-provider', 'ai-local-model', 'ai-agent', 'ai-tool',
  'ai-vector-store', 'ai-memory', 'ai-training', 'ai-evaluation', 'ai-telemetry',
  'backup', 'export', 'declared',
]);

/**
 * A fresh DataFlowGraph v1 envelope with every required top-level key
 * present. Callers overlay real content; every array starts empty and
 * every nested object starts as `{}` except `scope.source`, which
 * defaults to `'scan'` (a fixture builder must set it to `'fixture'`
 * explicitly — the safe default assumes real analyzer output).
 */
export function emptyGraphEnvelope(overrides = {}) {
  const { graphId, generatedAt, scope, ...rest } = overrides;
  return {
    schemaVersion: SCHEMA_VERSION,
    graphId: graphId || null,
    generatedAt: generatedAt || new Date().toISOString(),
    scope: { source: 'scan', ...(scope || {}) },
    scanHealth: {},
    taxonomy: {},
    nodes: [],
    edges: [],
    dataElements: [],
    transformations: [],
    flows: [],
    controls: [],
    policies: [],
    evidence: [],
    coverage: {},
    limitations: [],
    extensions: {},
    ...rest,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/schema.test.js`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/schema.js scanner/test/lineage/schema.test.js
git commit -m "feat(lineage): add DataFlowGraph v1 schema enums and envelope constructor"
```

---

### Task 2: Stable-ID module

**Files:**
- Create: `scanner/src/lineage/ids.js`
- Test: `scanner/test/lineage/ids.test.js`

**Interfaces:**
- Consumes: nothing from Task 1 directly (pure hashing), but the ID *prefixes* below (`node:`, `edge:`, `data:`, `flow:`, `transform:`, `evidence:`, `dfg:`) are the format every later task's fixture/validator relies on.
- Produces: `graphId({repository, commit, configHash})`, `nodeId(kind, discriminatorParts)`, `dataElementId(canonicalName, discriminatorParts)`, `edgeId(fromId, toId, relationship, discriminatorParts = [])`, `flowId(sourceNodeId, sinkNodeId, dataElementIds, discriminatorParts = [])`, `transformationId(anchorId, calleeName, discriminatorParts = [])`, `evidenceId(claim, location, discriminatorParts = [])` — all deterministic (same inputs → same output), all return strings.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/ids.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  graphId, nodeId, dataElementId, edgeId, flowId, transformationId, evidenceId,
} from '../../src/lineage/ids.js';

test('graphId follows the dfg:<repo>:<commit>:<configHash> shape from PRD 10.2', () => {
  assert.equal(
    graphId({ repository: 'payments-platform', commit: 'abc123', configHash: 'cfg1' }),
    'dfg:payments-platform:abc123:cfg1',
  );
});

test('graphId degrades gracefully with missing parts', () => {
  const id = graphId({});
  assert.match(id, /^dfg:unknown-repo:uncommitted:default$/);
});

test('nodeId is deterministic for identical discriminators', () => {
  const a = nodeId('source', ['payments-platform', 'web-app', 'checkout']);
  const b = nodeId('source', ['payments-platform', 'web-app', 'checkout']);
  assert.equal(a, b);
  assert.match(a, /^node:source:[0-9a-f]{12}$/);
});

test('nodeId differs for differing discriminators', () => {
  const a = nodeId('source', ['payments-platform', 'web-app']);
  const b = nodeId('source', ['payments-platform', 'gateway']);
  assert.notEqual(a, b);
});

test('dataElementId distinguishes same field name in different services (PRD 10.4)', () => {
  const a = dataElementId('email', ['service-a']);
  const b = dataElementId('email', ['service-b']);
  assert.notEqual(a, b);
  assert.match(a, /^data:[0-9a-f]{12}$/);
});

test('edgeId is deterministic and order-sensitive on from/to', () => {
  const n1 = nodeId('source', ['a']);
  const n2 = nodeId('process', ['b']);
  const e1 = edgeId(n1, n2, 'data_flow');
  const e2 = edgeId(n1, n2, 'data_flow');
  const e3 = edgeId(n2, n1, 'data_flow');
  assert.equal(e1, e2);
  assert.notEqual(e1, e3);
  assert.match(e1, /^edge:[0-9a-f]{12}$/);
});

test('flowId is order-independent over dataElementIds (a set, not a sequence)', () => {
  const src = nodeId('source', ['a']);
  const sink = nodeId('sink', ['b']);
  const de1 = dataElementId('x', []);
  const de2 = dataElementId('y', []);
  const f1 = flowId(src, sink, [de1, de2]);
  const f2 = flowId(src, sink, [de2, de1]);
  assert.equal(f1, f2, 'dataElementIds are sorted before hashing');
  assert.match(f1, /^flow:[0-9a-f]{12}$/);
});

test('flowId differs when a discriminator is added (same source/sink/fields, different path)', () => {
  const src = nodeId('source', ['a']);
  const sink = nodeId('sink', ['b']);
  const de = dataElementId('x', []);
  const f1 = flowId(src, sink, [de], ['masked-branch']);
  const f2 = flowId(src, sink, [de], ['raw-branch']);
  assert.notEqual(f1, f2);
});

test('transformationId and evidenceId are deterministic and correctly prefixed', () => {
  assert.match(transformationId('node:x', 'maskCard'), /^transform:[0-9a-f]{12}$/);
  assert.equal(transformationId('node:x', 'maskCard'), transformationId('node:x', 'maskCard'));
  assert.match(evidenceId('claim-a', 'file.js:10'), /^evidence:[0-9a-f]{12}$/);
  assert.equal(evidenceId('claim-a', 'file.js:10'), evidenceId('claim-a', 'file.js:10'));
});

test('no collisions across 5000 distinct nodeId discriminators (PRD 21 scale target)', () => {
  const seen = new Set();
  for (let i = 0; i < 5000; i++) {
    const id = nodeId('process', ['payments-platform', `svc-${i}`, `fn-${i % 37}`]);
    assert.ok(!seen.has(id), `collision at i=${i}`);
    seen.add(id);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/ids.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/lineage/ids.js
//
// Stable-ID spec for DataFlowGraph v1 (PRD 10.1: "Stable within the
// repository/commit; independent of visual layout"). Mirrors the shape
// scanner/src/posture/stable-id.js already established for findings:
// sha256 over a canonicalized, pipe-joined material string, truncated to
// a fixed hex length, prefixed by the entity kind. Same rationale — a
// content hash survives reordering and re-emission, unlike an
// incrementing counter.

import * as crypto from 'node:crypto';

const ID_HEX_LEN = 12;

function _hash(material, len = ID_HEX_LEN) {
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, len);
}

function _canon(parts) {
  return parts.map((p) => (p === undefined || p === null ? '' : String(p))).join('|');
}

/** PRD 10.2's literal example shape: `dfg:<repository>:<commit>:<configuration-hash>`. */
export function graphId({ repository, commit, configHash } = {}) {
  const repo = repository || 'unknown-repo';
  const c = commit || 'uncommitted';
  const cfg = configHash || 'default';
  return `dfg:${repo}:${c}:${cfg}`;
}

/** discriminatorParts should include enough of {system, location, destination} to be unique within the graph. */
export function nodeId(kind, discriminatorParts = []) {
  return `node:${kind}:${_hash(_canon([kind, ...discriminatorParts]))}`;
}

/** discriminatorParts should include the owning service/schema so the same field name in two services never collides (PRD 10.4). */
export function dataElementId(canonicalName, discriminatorParts = []) {
  return `data:${_hash(_canon([canonicalName, ...discriminatorParts]))}`;
}

export function edgeId(fromId, toId, relationship, discriminatorParts = []) {
  return `edge:${_hash(_canon([fromId, toId, relationship, ...discriminatorParts]))}`;
}

/**
 * dataElementIds is treated as a SET (sorted before hashing) — a flow
 * carrying {card_number, cvv} has one identity regardless of the order the
 * builder discovered them in. `discriminatorParts` is the escape hatch for
 * two flows sharing source/sink/fields that must still be distinct paths
 * (e.g. a masked branch vs. a raw branch to the same log sink).
 */
export function flowId(sourceNodeId, sinkNodeId, dataElementIds = [], discriminatorParts = []) {
  const sorted = [...dataElementIds].sort();
  return `flow:${_hash(_canon([sourceNodeId, sinkNodeId, ...sorted, ...discriminatorParts]))}`;
}

export function transformationId(anchorId, calleeName, discriminatorParts = []) {
  return `transform:${_hash(_canon([anchorId, calleeName, ...discriminatorParts]))}`;
}

export function evidenceId(claim, location, discriminatorParts = []) {
  return `evidence:${_hash(_canon([claim, location, ...discriminatorParts]))}`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/ids.test.js`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/ids.js scanner/test/lineage/ids.test.js
git commit -m "feat(lineage): add deterministic stable-ID functions for DataFlowGraph v1"
```

---

### Task 3: Protection verdict model

**Files:**
- Create: `scanner/src/lineage/protection.js`
- Test: `scanner/test/lineage/protection.test.js`

**Interfaces:**
- Produces: `PROTECTION_VERDICTS`, `EVIDENCE_GRADES`, `PROTECTION_DIMENSIONS` (`['transit', 'atRest', 'handling']`) — frozen arrays. `emptyProtection()` → `{transit: {verdict, evidenceGrade}, atRest: {...}, handling: {...}}` with every verdict `'not_assessed'`/evidenceGrade `'none'`. `aggregateVerdicts(verdicts)` — takes an array of verdict strings, returns the single highest-precedence verdict per PRD §8.4's risk-precedence ordering. `isValidProtectionDimension(dim)` — structural check for one `{verdict, evidenceGrade}` object.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/protection.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROTECTION_VERDICTS, EVIDENCE_GRADES, PROTECTION_DIMENSIONS,
  emptyProtection, aggregateVerdicts, isValidProtectionDimension,
} from '../../src/lineage/protection.js';

test('enums match PRD section 14.1', () => {
  assert.deepEqual([...PROTECTION_VERDICTS].sort(), ['not_applicable', 'not_assessed', 'protected', 'unknown', 'unprotected'].sort());
  assert.deepEqual([...EVIDENCE_GRADES].sort(), ['code', 'code_and_config', 'config', 'declared', 'manual', 'none', 'runtime'].sort());
  assert.deepEqual([...PROTECTION_DIMENSIONS], ['transit', 'atRest', 'handling']);
});

test('emptyProtection defaults every dimension to not_assessed / none', () => {
  const p = emptyProtection();
  for (const dim of PROTECTION_DIMENSIONS) {
    assert.equal(p[dim].verdict, 'not_assessed');
    assert.equal(p[dim].evidenceGrade, 'none');
  }
});

test('isValidProtectionDimension accepts a well-formed dimension and rejects a bad one', () => {
  assert.equal(isValidProtectionDimension({ verdict: 'protected', evidenceGrade: 'code' }), true);
  assert.equal(isValidProtectionDimension({ verdict: 'super-safe', evidenceGrade: 'code' }), false);
  assert.equal(isValidProtectionDimension({ verdict: 'protected', evidenceGrade: 'trust-me' }), false);
  assert.equal(isValidProtectionDimension(null), false);
});

// PRD section 8.4 risk precedence: unprotected/prohibited -> mixed ->
// unknown/manual_required -> protected/permitted -> not_assessed.
test('aggregateVerdicts: any unprotected wins over everything else', () => {
  assert.equal(aggregateVerdicts(['protected', 'unprotected', 'unknown']), 'unprotected');
});

test('aggregateVerdicts: mixed only applies when this module is told to treat a set as branches (see AC-12)', () => {
  // A caller that already knows it has multiple DISTINCT branches passes
  // 'mixed' in directly as one of the verdicts being aggregated (e.g. an
  // upstream aggregation step already computed "protected on branch A,
  // unprotected on branch B" -> 'mixed'). This function's own precedence
  // table must still rank 'mixed' correctly among the rest.
  assert.equal(aggregateVerdicts(['protected', 'mixed']), 'mixed');
  assert.equal(aggregateVerdicts(['mixed', 'unknown']), 'mixed');
});

test('aggregateVerdicts: unknown beats protected', () => {
  assert.equal(aggregateVerdicts(['protected', 'unknown']), 'unknown');
});

test('aggregateVerdicts: all protected stays protected', () => {
  assert.equal(aggregateVerdicts(['protected', 'protected']), 'protected');
});

test('aggregateVerdicts: not_assessed only when nothing stronger present', () => {
  assert.equal(aggregateVerdicts(['not_assessed', 'not_assessed']), 'not_assessed');
  assert.equal(aggregateVerdicts(['not_assessed', 'protected']), 'protected');
});

test('aggregateVerdicts on empty input is not_assessed, never a guess', () => {
  assert.equal(aggregateVerdicts([]), 'not_assessed');
});

test('aggregateVerdicts throws on an unrecognized verdict rather than silently ranking it low', () => {
  assert.throws(() => aggregateVerdicts(['protected', 'super-safe']), /unrecognized verdict/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/protection.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/lineage/protection.js
//
// Protection verdict model (Data Flow Explorer PRD section 14.1 + 8.4).
// Every protection dimension carries two INDEPENDENT fields: a verdict
// and an evidence grade — "declared protected" must never render
// identically to code-and-configuration-proven protection (PRD 14.1).
//
// This module defines the model only (enums, the empty/default shape,
// and the pure aggregation function). The analyzers that actually DECIDE
// a verdict per edge (transit/at-rest/handling — PRD FR-401 through
// FR-403) are Milestone 2 (DFG-010), not this module.

export const PROTECTION_VERDICTS = Object.freeze(['protected', 'unprotected', 'unknown', 'not_applicable', 'not_assessed']);

export const EVIDENCE_GRADES = Object.freeze(['runtime', 'code_and_config', 'code', 'config', 'declared', 'manual', 'none']);

export const PROTECTION_DIMENSIONS = Object.freeze(['transit', 'atRest', 'handling']);

export function emptyProtection() {
  const dim = () => ({ verdict: 'not_assessed', evidenceGrade: 'none' });
  return { transit: dim(), atRest: dim(), handling: dim() };
}

export function isValidProtectionDimension(d) {
  if (!d || typeof d !== 'object') return false;
  return PROTECTION_VERDICTS.includes(d.verdict) && EVIDENCE_GRADES.includes(d.evidenceGrade);
}

// PRD section 8.4: "For an aggregated path, visible risk precedence is
// unprotected/prohibited -> mixed -> unknown/manual_required ->
// protected/permitted -> not_assessed." Lower index = higher precedence
// (wins the aggregation). 'mixed' is not itself in PROTECTION_VERDICTS —
// it is a caller-supplied aggregate state from an upstream step (e.g. "one
// branch protected, one branch unprotected") that this function's own
// ranking table must still place correctly among the five base verdicts.
const _PRECEDENCE = ['unprotected', 'mixed', 'unknown', 'protected', 'not_applicable', 'not_assessed'];

/**
 * Reduce a set of verdicts (protection verdicts, or 'mixed') to the single
 * highest-precedence one. Never guesses: an empty array is 'not_assessed',
 * and an unrecognized verdict throws rather than silently sorting last —
 * a typo here must not quietly rank as "safest".
 */
export function aggregateVerdicts(verdicts) {
  if (!Array.isArray(verdicts) || verdicts.length === 0) return 'not_assessed';
  let best = null;
  let bestRank = Infinity;
  for (const v of verdicts) {
    const rank = _PRECEDENCE.indexOf(v);
    if (rank === -1) throw new Error(`aggregateVerdicts: unrecognized verdict "${v}"`);
    if (rank < bestRank) { bestRank = rank; best = v; }
  }
  return best;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/protection.test.js`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/protection.js scanner/test/lineage/protection.test.js
git commit -m "feat(lineage): add protection verdict model and risk-precedence aggregation"
```

---

### Task 4: Classification model (data classes + AI processing contexts)

**Files:**
- Create: `scanner/src/lineage/classification.js`
- Test: `scanner/test/lineage/classification.test.js`

**Interfaces:**
- Consumes: `DEFAULT_TAXONOMY`, `compileTaxonomy`, `classifyFieldAgainst`, `loadPrivacyTaxonomy`, `BUILTIN_TAXONOMY_VERSION` from `../dataflow/privacy-taxonomy.js` (read-only reuse, per PRD §3's explicit instruction to reuse this taxonomy rather than duplicate it).
- Produces: `AI_PROCESSING_CONTEXTS` (frozen array of 15 strings, PRD §9.2), `LINEAGE_DATA_CLASSES` (frozen array — the taxonomy's classes plus `'CONFIDENTIAL'`, PRD §9.1), `isAiContext(value)`, `classifyDataElementName(name, compiled)` — thin wrapper returning `{classes, aiContexts: []}` (aiContexts always empty here — a name alone can never prove AI processing; that requires flow evidence, Milestone 1).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/classification.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AI_PROCESSING_CONTEXTS, LINEAGE_DATA_CLASSES, isAiContext, classifyDataElementName,
} from '../../src/lineage/classification.js';

test('AI_PROCESSING_CONTEXTS has all 15 contexts from PRD section 9.2', () => {
  assert.equal(AI_PROCESSING_CONTEXTS.length, 15);
  for (const c of AI_PROCESSING_CONTEXTS) assert.match(c, /^ai\./);
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.system_prompt'));
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.rag_context'));
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.model_artifact'));
});

test('LINEAGE_DATA_CLASSES extends the privacy taxonomy with CONFIDENTIAL', () => {
  assert.ok(LINEAGE_DATA_CLASSES.includes('PII'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('PHI'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('PCI'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('CREDENTIALS'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('CONFIDENTIAL'));
});

test('isAiContext validates against the enum, not a loose prefix check', () => {
  assert.equal(isAiContext('ai.model_input'), true);
  assert.equal(isAiContext('ai.made_up_context'), false);
  assert.equal(isAiContext('not-ai-at-all'), false);
});

test('classifyDataElementName reuses the privacy taxonomy for classes and never guesses AI contexts from a name', () => {
  const hit = classifyDataElementName('card_number');
  assert.ok(hit.classes.includes('PCI'));
  assert.deepEqual(hit.aiContexts, [], 'AI processing can only be proven by flow evidence, not a field name');
});

test('classifyDataElementName returns empty classes for an unrecognized name', () => {
  const hit = classifyDataElementName('totally_unrelated_field');
  assert.deepEqual(hit.classes, []);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/classification.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/lineage/classification.js
//
// Data classification model (Data Flow Explorer PRD section 9). Reuses
// scanner/src/dataflow/privacy-taxonomy.js for the PII/PHI/PCI/FIN/
// CREDENTIALS/GEOLOCATION/DEVICE_ID classes and their versioned,
// operator-extensible pattern config — PRD section 3 names this module
// explicitly as reusable, not something to re-implement. This file adds
// only what privacy-taxonomy.js does not already have: the CONFIDENTIAL
// class (PRD 9.1's 8th built-in class — proprietary/business-confidential
// data has no reliable field-NAME pattern, unlike PII/PHI/PCI, so it
// ships with zero default patterns and is populated entirely through the
// same operator-config extension mechanism privacy-taxonomy.js already
// supports) and the AI processing context enum (PRD 9.2), which is
// DELIBERATELY ORTHOGONAL to data class — see the PRD's explicit warning
// against modeling AI as a mutually-exclusive label.

import { DEFAULT_TAXONOMY, classifyFieldAgainst, compileTaxonomy } from '../dataflow/privacy-taxonomy.js';

// PRD section 9.2 — all 15 supported AI processing contexts. "AI" as a
// filter means "matches ANY of these", never a single flag.
export const AI_PROCESSING_CONTEXTS = Object.freeze([
  'ai.system_prompt', 'ai.user_prompt', 'ai.model_input', 'ai.model_output',
  'ai.rag_context', 'ai.embedding', 'ai.vector_store', 'ai.memory',
  'ai.tool_argument', 'ai.tool_result', 'ai.training_data',
  'ai.fine_tuning_data', 'ai.evaluation_data', 'ai.telemetry', 'ai.model_artifact',
]);

// CONFIDENTIAL ships with no default patterns on purpose — "confidential
// business data" has no reliable field-name regex the way "ssn" or
// "diagnosis" does. An operator adds patterns via the SAME
// .agentic-security/privacy-taxonomy.json extension mechanism
// privacy-taxonomy.js already documents (a class name not already in
// DEFAULT_TAXONOMY is accepted as a brand-new organization-defined class).
const _CONFIDENTIAL_EXTRA = Object.freeze({ severity: 'medium', patterns: [] });

export const LINEAGE_DATA_CLASSES = Object.freeze([...Object.keys(DEFAULT_TAXONOMY), 'CONFIDENTIAL']);

const _COMPILED_WITH_CONFIDENTIAL = compileTaxonomy({ ...DEFAULT_TAXONOMY, CONFIDENTIAL: _CONFIDENTIAL_EXTRA });

export function isAiContext(value) {
  return AI_PROCESSING_CONTEXTS.includes(value);
}

/**
 * Classify a data element's canonical/declared name against the
 * (privacy-taxonomy-plus-CONFIDENTIAL) class list. Returns
 * `{classes: string[], aiContexts: []}` — aiContexts is ALWAYS empty from
 * this function: a name alone can never prove a field reaches an AI
 * processing context (PRD 10.5/FR-205 — that requires actual lineage
 * evidence connecting the field to a model input/prompt/embedding/etc.,
 * which is Milestone 1 scope). Callers must not skip that proof step by
 * reading a non-empty aiContexts here; it is shaped this way specifically
 * so there is nothing to accidentally read.
 */
export function classifyDataElementName(name, compiled = _COMPILED_WITH_CONFIDENTIAL) {
  return { classes: classifyFieldAgainst(name, compiled), aiContexts: [] };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/classification.test.js`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/classification.js scanner/test/lineage/classification.test.js
git commit -m "feat(lineage): add data-class + orthogonal AI-processing-context model"
```

---

### Task 5: Structural graph validator

**Files:**
- Create: `scanner/src/lineage/validate.js`
- Test: `scanner/test/lineage/validate.test.js`

**Interfaces:**
- Consumes: everything from Tasks 1–4 (`schema.js` enums + `emptyGraphEnvelope`, `ids.js` prefix formats via regex, `protection.js` `isValidProtectionDimension`/`PROTECTION_DIMENSIONS`, `classification.js` `LINEAGE_DATA_CLASSES`/`isAiContext`).
- Produces: `validateGraph(graph)` → `{valid: boolean, errors: [{path: string, message: string}]}`. Never throws — a malformed input (wrong type, missing arrays) produces errors, not an exception.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/validate.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { nodeId, dataElementId, edgeId, flowId } from '../../src/lineage/ids.js';
import { emptyProtection } from '../../src/lineage/protection.js';
import { validateGraph } from '../../src/lineage/validate.js';

test('an empty-but-well-formed envelope is valid', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('non-object input never throws and reports one error', () => {
  assert.deepEqual(validateGraph(null), { valid: false, errors: [{ path: '$', message: 'graph must be an object' }] });
  assert.deepEqual(validateGraph('nope').valid, false);
  assert.deepEqual(validateGraph(undefined).valid, false);
});

test('wrong schemaVersion is an error', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.schemaVersion = '0.9.0';
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.schemaVersion'));
});

test('a well-formed node with a bad kind is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push({
    id: nodeId('source', ['x']), kind: 'not-a-real-kind', subtype: 'x', label: 'X',
    aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path.includes('nodes[0].kind')));
});

test('a valid two-node, one-edge, one-flow graph passes', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const src = nodeId('source', ['payments-platform', 'web']);
  const sink = nodeId('log', ['payments-platform', 'logs']);
  const de = dataElementId('card_number', ['payments-platform']);
  graph.nodes.push(
    { id: src, kind: 'source', subtype: 'web-app', label: 'Web App', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['collection'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
    { id: sink, kind: 'log', subtype: 'application-logs', label: 'Application Logs', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['storage'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
  );
  graph.dataElements.push({ id: de, name: 'card_number', aliases: [], declaredType: null, dataClasses: ['PCI'], aiContexts: [], sourceLocations: [], dataSubjectCategory: null, classificationEvidence: [], manualOverride: false });
  const edge = { id: edgeId(src, sink, 'data_flow'), from: src, to: sink, relationship: 'data_flow', fieldMappings: [{ fromPath: 'card_number', toPath: 'maskedPan', dataElementIds: [de], mappingType: 'transformation', transformationIds: [] }], protocol: { name: 'in-process', destinationResolution: 'literal' }, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' };
  graph.edges.push(edge);
  graph.flows.push({ id: flowId(src, sink, [de]), dataElementIds: [de], source: src, sink: sink, edgeIds: [edge.id], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled', findingRefs: [], governanceRefs: {}, limitations: [] });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('an edge referencing a nonexistent node id is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.edges.push({ id: 'edge:deadbeef0000', from: 'node:missing:aaa', to: 'node:missing:bbb', relationship: 'data_flow', fieldMappings: [], protocol: {}, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.message.includes('unknown node id')));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/validate.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/lineage/validate.js
//
// Structural validator for DataFlowGraph v1 (PRD section 10). Hand-rolled
// rather than a generic JSON-Schema interpreter + a new `ajv`-style
// dependency, matching this codebase's existing preference for
// hand-rolled implementations over new runtime deps (see every parser in
// scanner/src/ir/). scanner/src/lineage/dataflow-graph.schema.json (Task
// 6) is the authoritative JSON Schema document for external interop /
// documentation; this file is what the engine actually calls at graph-
// build phase 12 (PRD 18.3: "Validate the graph contract and freeze it
// before rendering").
//
// Never throws. A malformed top-level input produces one error and
// returns early; a malformed nested entity is skipped for further
// structural checks on ITSELF but does not stop validation of siblings.

import { SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES } from './schema.js';
import { isValidProtectionDimension, PROTECTION_DIMENSIONS } from './protection.js';

function _err(errors, path, message) {
  errors.push({ path, message });
}

function _requireArray(graph, key, errors) {
  if (!Array.isArray(graph[key])) _err(errors, `$.${key}`, `${key} must be an array`);
}

function _requireObject(graph, key, errors) {
  if (typeof graph[key] !== 'object' || graph[key] === null || Array.isArray(graph[key])) {
    _err(errors, `$.${key}`, `${key} must be an object`);
  }
}

function _validateNode(node, idx, errors, seenIds) {
  const path = (suffix) => `$.nodes[${idx}]${suffix}`;
  if (!node || typeof node !== 'object') { _err(errors, path(''), 'node must be an object'); return; }
  if (typeof node.id !== 'string' || !node.id) _err(errors, path('.id'), 'node.id is required');
  else seenIds.add(node.id);
  if (!NODE_KINDS.includes(node.kind)) _err(errors, path('.kind'), `unrecognized node kind "${node.kind}"`);
  if (typeof node.label !== 'string' || !node.label) _err(errors, path('.label'), 'node.label is required');
  if (!Array.isArray(node.aliases)) _err(errors, path('.aliases'), 'node.aliases must be an array');
  if (!Array.isArray(node.dataElementIds)) _err(errors, path('.dataElementIds'), 'node.dataElementIds must be an array');
  if (!Array.isArray(node.evidenceRefs)) _err(errors, path('.evidenceRefs'), 'node.evidenceRefs must be an array');
  if (!COVERAGE_STATUS_VALUES.includes(node.coverageStatus)) _err(errors, path('.coverageStatus'), `unrecognized coverageStatus "${node.coverageStatus}"`);
  if (node.externality && !EXTERNALITY_VALUES.includes(node.externality.value)) {
    _err(errors, path('.externality.value'), `unrecognized externality "${node.externality.value}"`);
  }
}

function _validateDataElement(de, idx, errors, seenIds) {
  const path = (suffix) => `$.dataElements[${idx}]${suffix}`;
  if (!de || typeof de !== 'object') { _err(errors, path(''), 'dataElement must be an object'); return; }
  if (typeof de.id !== 'string' || !de.id) _err(errors, path('.id'), 'dataElement.id is required');
  else seenIds.add(de.id);
  if (typeof de.name !== 'string' || !de.name) _err(errors, path('.name'), 'dataElement.name is required');
  if (!Array.isArray(de.dataClasses)) _err(errors, path('.dataClasses'), 'dataElement.dataClasses must be an array');
  if (!Array.isArray(de.aiContexts)) _err(errors, path('.aiContexts'), 'dataElement.aiContexts must be an array');
}

function _validateEdge(edge, idx, errors, nodeIds, dataElementIds) {
  const path = (suffix) => `$.edges[${idx}]${suffix}`;
  if (!edge || typeof edge !== 'object') { _err(errors, path(''), 'edge must be an object'); return; }
  if (typeof edge.id !== 'string' || !edge.id) _err(errors, path('.id'), 'edge.id is required');
  if (!nodeIds.has(edge.from)) _err(errors, path('.from'), `unknown node id "${edge.from}"`);
  if (!nodeIds.has(edge.to)) _err(errors, path('.to'), `unknown node id "${edge.to}"`);
  if (edge.relationship !== 'data_flow') _err(errors, path('.relationship'), `unrecognized relationship "${edge.relationship}"`);
  if (!Array.isArray(edge.fieldMappings)) _err(errors, path('.fieldMappings'), 'edge.fieldMappings must be an array');
  else {
    edge.fieldMappings.forEach((fm, i) => {
      if (!MAPPING_TYPES.includes(fm?.mappingType)) _err(errors, path(`.fieldMappings[${i}].mappingType`), `unrecognized mappingType "${fm?.mappingType}"`);
      for (const deId of fm?.dataElementIds || []) {
        if (!dataElementIds.has(deId)) _err(errors, path(`.fieldMappings[${i}].dataElementIds`), `unknown dataElement id "${deId}"`);
      }
    });
  }
  if (!edge.protection || typeof edge.protection !== 'object') {
    _err(errors, path('.protection'), 'edge.protection is required');
  } else {
    for (const dim of PROTECTION_DIMENSIONS) {
      if (!isValidProtectionDimension(edge.protection[dim])) _err(errors, path(`.protection.${dim}`), `invalid protection dimension`);
    }
  }
}

function _validateFlow(flow, idx, errors, nodeIds, dataElementIds, edgeIds) {
  const path = (suffix) => `$.flows[${idx}]${suffix}`;
  if (!flow || typeof flow !== 'object') { _err(errors, path(''), 'flow must be an object'); return; }
  if (typeof flow.id !== 'string' || !flow.id) _err(errors, path('.id'), 'flow.id is required');
  if (!nodeIds.has(flow.source)) _err(errors, path('.source'), `unknown node id "${flow.source}"`);
  if (!nodeIds.has(flow.sink)) _err(errors, path('.sink'), `unknown node id "${flow.sink}"`);
  for (const deId of flow.dataElementIds || []) {
    if (!dataElementIds.has(deId)) _err(errors, path('.dataElementIds'), `unknown dataElement id "${deId}"`);
  }
  for (const eId of flow.edgeIds || []) {
    if (!edgeIds.has(eId)) _err(errors, path('.edgeIds'), `unknown edge id "${eId}"`);
  }
}

/**
 * Structurally validate a DataFlowGraph v1 envelope. Returns
 * `{valid, errors}` and never throws.
 */
export function validateGraph(graph) {
  const errors = [];
  if (!graph || typeof graph !== 'object' || Array.isArray(graph)) {
    return { valid: false, errors: [{ path: '$', message: 'graph must be an object' }] };
  }

  if (graph.schemaVersion !== SCHEMA_VERSION) {
    _err(errors, '$.schemaVersion', `expected "${SCHEMA_VERSION}", got "${graph.schemaVersion}"`);
  }
  if (typeof graph.graphId !== 'string' || !graph.graphId.startsWith('dfg:')) {
    _err(errors, '$.graphId', 'graphId must be a string starting with "dfg:"');
  }
  for (const key of ['nodes', 'edges', 'dataElements', 'transformations', 'flows', 'controls', 'policies', 'evidence', 'limitations']) {
    _requireArray(graph, key, errors);
  }
  for (const key of ['scope', 'scanHealth', 'taxonomy', 'coverage', 'extensions']) {
    _requireObject(graph, key, errors);
  }

  const nodeIds = new Set();
  const dataElementIds = new Set();
  const edgeIds = new Set();

  (Array.isArray(graph.nodes) ? graph.nodes : []).forEach((n, i) => _validateNode(n, i, errors, nodeIds));
  (Array.isArray(graph.dataElements) ? graph.dataElements : []).forEach((d, i) => _validateDataElement(d, i, errors, dataElementIds));
  (Array.isArray(graph.edges) ? graph.edges : []).forEach((e, i) => {
    _validateEdge(e, i, errors, nodeIds, dataElementIds);
    if (e && typeof e.id === 'string') edgeIds.add(e.id);
  });
  (Array.isArray(graph.flows) ? graph.flows : []).forEach((f, i) => _validateFlow(f, i, errors, nodeIds, dataElementIds, edgeIds));

  return { valid: errors.length === 0, errors };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/validate.test.js`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/validate.js scanner/test/lineage/validate.test.js
git commit -m "feat(lineage): add structural DataFlowGraph v1 validator"
```

---

### Task 6: Authoritative JSON Schema document + parity test

**Files:**
- Create: `scanner/src/lineage/dataflow-graph.schema.json`
- Test: `scanner/test/lineage/json-schema-parity.test.js`

**Interfaces:**
- Consumes: all enum exports from `schema.js` and `protection.js` (Tasks 1, 3) — the test cross-checks the JSON file's `enum` arrays against these exports so the two representations of the contract cannot silently drift apart.
- Produces: a real JSON Schema (2020-12 dialect) document at `scanner/src/lineage/dataflow-graph.schema.json`, for external interop/documentation (PRD Milestone 0 deliverable: "`DataFlowGraph v1` JSON Schema").

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/json-schema-parity.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCHEMA_VERSION, NODE_KINDS, MAPPING_TYPES, TRANSFORM_KINDS,
  COVERAGE_STATUS_VALUES, DESTINATION_RESOLUTION_VALUES, POLICY_STATES, EVIDENCE_TYPES,
} from '../../src/lineage/schema.js';
import { PROTECTION_VERDICTS, EVIDENCE_GRADES } from '../../src/lineage/protection.js';

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

test('top-level required envelope keys are all present', () => {
  const schema = loadSchema();
  const required = schema.required;
  for (const key of ['schemaVersion', 'graphId', 'generatedAt', 'nodes', 'edges', 'dataElements', 'transformations', 'flows', 'evidence', 'coverage', 'limitations']) {
    assert.ok(required.includes(key), `schema.required missing "${key}"`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/json-schema-parity.test.js`
Expected: FAIL — schema file does not exist

- [ ] **Step 3: Write the implementation**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://agentic-security.dev/schemas/dataflow-graph/1.0.0.json",
  "title": "DataFlowGraph v1",
  "description": "Canonical application data-lineage graph contract (Data Flow Explorer PRD section 10). Renderer-independent; consumed by Architecture, Privacy, and Trace projections.",
  "type": "object",
  "required": ["schemaVersion", "graphId", "generatedAt", "scope", "scanHealth", "taxonomy", "nodes", "edges", "dataElements", "transformations", "flows", "controls", "policies", "evidence", "coverage", "limitations", "extensions"],
  "properties": {
    "schemaVersion": { "const": "1.0.0" },
    "graphId": { "type": "string", "pattern": "^dfg:" },
    "generatedAt": { "type": "string", "format": "date-time" },
    "scope": { "type": "object" },
    "scanHealth": { "type": "object" },
    "taxonomy": { "type": "object" },
    "nodes": { "type": "array", "items": { "$ref": "#/$defs/node" } },
    "edges": { "type": "array", "items": { "$ref": "#/$defs/edge" } },
    "dataElements": { "type": "array", "items": { "$ref": "#/$defs/dataElement" } },
    "transformations": { "type": "array", "items": { "$ref": "#/$defs/transformation" } },
    "flows": { "type": "array", "items": { "$ref": "#/$defs/flow" } },
    "controls": { "type": "array" },
    "policies": { "type": "array" },
    "evidence": { "type": "array", "items": { "$ref": "#/$defs/evidence" } },
    "coverage": { "type": "object" },
    "limitations": { "type": "array" },
    "extensions": { "type": "object" }
  },
  "$defs": {
    "node": {
      "type": "object",
      "required": ["id", "kind", "subtype", "label", "aliases", "system", "externality", "lifecycleStages", "governanceRefs", "dataElementIds", "evidenceRefs", "confidence", "coverageStatus"],
      "properties": {
        "id": { "type": "string", "pattern": "^node:" },
        "kind": { "type": "string", "enum": ["source", "process", "transform", "api", "store", "queue", "log", "sink", "external", "boundary", "unresolved"] },
        "subtype": { "type": "string" },
        "label": { "type": "string" },
        "aliases": { "type": "array", "items": { "type": "string" } },
        "location": { "type": ["object", "null"] },
        "system": { "type": "object" },
        "destination": { "type": ["object", "null"] },
        "externality": { "type": "object" },
        "lifecycleStages": { "type": "array", "items": { "type": "string" } },
        "governanceRefs": { "type": "object" },
        "dataElementIds": { "type": "array", "items": { "type": "string" } },
        "evidenceRefs": { "type": "array", "items": { "type": "string" } },
        "confidence": { "type": "object" },
        "coverageStatus": { "type": "string", "enum": ["modeled", "partial", "candidate", "unsupported", "manual"] }
      }
    },
    "fieldMapping": {
      "type": "object",
      "required": ["fromPath", "toPath", "dataElementIds", "mappingType", "transformationIds"],
      "properties": {
        "fromPath": { "type": "string" },
        "toPath": { "type": "string" },
        "dataElementIds": { "type": "array", "items": { "type": "string" } },
        "mappingType": { "type": "string", "enum": ["identity", "rename", "projection", "serialization", "deserialization", "transformation", "aggregation", "join", "filter", "sort", "conditional", "unknown"] },
        "transformationIds": { "type": "array", "items": { "type": "string" } }
      }
    },
    "protocol": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "destinationResolution": { "type": "string", "enum": ["literal", "resolved_from_constant", "resolved_from_config", "resolved_from_schema", "declared_service", "runtime_corroborated", "dynamic", "unknown"] }
      }
    },
    "protectionDimension": {
      "type": "object",
      "required": ["verdict", "evidenceGrade"],
      "properties": {
        "verdict": { "type": "string", "enum": ["protected", "unprotected", "unknown", "not_applicable", "not_assessed"] },
        "evidenceGrade": { "type": "string", "enum": ["runtime", "code_and_config", "code", "config", "declared", "manual", "none"] }
      }
    },
    "edge": {
      "type": "object",
      "required": ["id", "from", "to", "relationship", "fieldMappings", "protocol", "boundaryCrossings", "protection", "evidenceRefs", "coverageStatus"],
      "properties": {
        "id": { "type": "string", "pattern": "^edge:" },
        "from": { "type": "string" },
        "to": { "type": "string" },
        "relationship": { "const": "data_flow" },
        "fieldMappings": { "type": "array", "items": { "$ref": "#/$defs/fieldMapping" } },
        "protocol": { "$ref": "#/$defs/protocol" },
        "boundaryCrossings": { "type": "array", "items": { "type": "string" } },
        "protection": {
          "type": "object",
          "required": ["transit", "atRest", "handling"],
          "properties": {
            "transit": { "$ref": "#/$defs/protectionDimension" },
            "atRest": { "$ref": "#/$defs/protectionDimension" },
            "handling": { "$ref": "#/$defs/protectionDimension" }
          }
        },
        "evidenceRefs": { "type": "array", "items": { "type": "string" } },
        "coverageStatus": { "type": "string", "enum": ["modeled", "partial", "candidate", "unsupported", "manual"] }
      }
    },
    "dataElement": {
      "type": "object",
      "required": ["id", "name", "aliases", "dataClasses", "aiContexts", "sourceLocations", "classificationEvidence", "manualOverride"],
      "properties": {
        "id": { "type": "string", "pattern": "^data:" },
        "name": { "type": "string" },
        "aliases": { "type": "array", "items": { "type": "string" } },
        "declaredType": { "type": ["string", "null"] },
        "dataClasses": { "type": "array", "items": { "type": "string" } },
        "aiContexts": { "type": "array", "items": { "type": "string" } },
        "sourceLocations": { "type": "array" },
        "dataSubjectCategory": { "type": ["string", "null"] },
        "classificationEvidence": { "type": "array" },
        "manualOverride": { "type": "boolean" },
        "firstSeenProvenance": { "type": ["object", "null"] }
      }
    },
    "transformation": {
      "type": "object",
      "required": ["id", "kind", "reversibility"],
      "properties": {
        "id": { "type": "string", "pattern": "^transform:" },
        "inputPath": { "type": "string" },
        "outputPath": { "type": "string" },
        "callee": { "type": "string" },
        "location": { "type": ["object", "null"] },
        "kind": { "type": "string", "enum": ["mask", "redact", "tokenize", "hash", "encrypt", "decrypt", "encode", "decode", "aggregate", "truncate", "normalize", "custom", "unknown"] },
        "reversibility": { "type": "string", "enum": ["reversible", "irreversible", "unknown"] },
        "algorithm": { "type": ["string", "null"] },
        "appliesToAllPaths": { "type": ["boolean", "null"] },
        "controlCredit": { "type": ["boolean", "null"] },
        "controlCreditReason": { "type": ["string", "null"] }
      }
    },
    "flow": {
      "type": "object",
      "required": ["id", "dataElementIds", "source", "sink", "edgeIds", "policyVerdict", "protectionSummary", "evidenceRefs", "coverageStatus"],
      "properties": {
        "id": { "type": "string", "pattern": "^flow:" },
        "dataElementIds": { "type": "array", "items": { "type": "string" } },
        "source": { "type": "string" },
        "sink": { "type": "string" },
        "edgeIds": { "type": "array", "items": { "type": "string" } },
        "transformationIds": { "type": "array", "items": { "type": "string" } },
        "alternatePathCount": { "type": "integer", "minimum": 0 },
        "policyVerdict": { "type": "string", "enum": ["prohibited", "permitted", "conditionally_permitted", "manual_review_required", "not_evaluated"] },
        "protectionSummary": { "type": "string", "enum": ["protected", "unprotected", "mixed", "unknown", "not_assessed"] },
        "evidenceRefs": { "type": "array", "items": { "type": "string" } },
        "confidence": { "type": "object" },
        "coverageStatus": { "type": "string", "enum": ["modeled", "partial", "candidate", "unsupported", "manual"] },
        "findingRefs": { "type": "array" },
        "governanceRefs": { "type": "object" },
        "limitations": { "type": "array" }
      }
    },
    "evidence": {
      "type": "object",
      "required": ["id", "claim", "evidenceType"],
      "properties": {
        "id": { "type": "string", "pattern": "^evidence:" },
        "claim": { "type": "string" },
        "evidenceType": { "type": "string", "enum": ["code", "ir", "configuration", "iac", "schema", "service_declaration", "policy", "manual", "runtime"] },
        "location": { "type": ["object", "null"] },
        "producer": { "type": ["string", "null"] },
        "confidenceTier": { "type": ["string", "null"] },
        "snippet": { "type": ["string", "null"] },
        "timestamp": { "type": ["string", "null"] },
        "commit": { "type": ["string", "null"] },
        "limitations": { "type": "array" },
        "conflict": { "type": ["boolean", "null"] }
      }
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/json-schema-parity.test.js`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/dataflow-graph.schema.json scanner/test/lineage/json-schema-parity.test.js
git commit -m "feat(lineage): add authoritative DataFlowGraph v1 JSON Schema document"
```

---

### Task 7: Flagship fixture generator and generated fixture

**Files:**
- Create: `scanner/src/lineage/fixtures/build-flagship-fixture.mjs`
- Create: `scanner/src/lineage/fixtures/flagship-graph.json` (generated output, committed)
- Test: `scanner/test/lineage/flagship-fixture.test.js`

**Interfaces:**
- Consumes: `emptyGraphEnvelope` (Task 1), `graphId`/`nodeId`/`dataElementId`/`edgeId`/`flowId`/`transformationId`/`evidenceId` (Task 2), `emptyProtection` (Task 3), `classifyDataElementName` (Task 4), `validateGraph` (Task 5).
- Produces: a committed, deterministic `flagship-graph.json` matching PRD Appendix D.2/D.3's payments-platform fixture (13 reference nodes plus one documented extension node, 3 data elements, 8 named flows). `scope.source: 'fixture'`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/lineage/flagship-fixture.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { validateGraph } from '../../src/lineage/validate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const builderPath = path.join(__dirname, '../../src/lineage/fixtures/build-flagship-fixture.mjs');

function loadFixture() {
  return JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
}

test('flagship-graph.json exists and is valid JSON', () => {
  assert.ok(fs.existsSync(fixturePath));
  assert.doesNotThrow(() => loadFixture());
});

test('flagship fixture passes validateGraph with zero errors', () => {
  const result = validateGraph(loadFixture());
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('flagship fixture is marked as a fixture, not scan output (Appendix D.1)', () => {
  const graph = loadFixture();
  assert.equal(graph.scope.source, 'fixture');
});

test('re-running the builder produces byte-identical output (determinism, AC-14)', () => {
  const before = fs.readFileSync(fixturePath, 'utf8');
  execFileSync('node', [builderPath], { cwd: path.join(__dirname, '../..') });
  const after = fs.readFileSync(fixturePath, 'utf8');
  assert.equal(before, after, 'builder output drifted — regenerate is not idempotent');
});

test('all 13 Appendix D.2 reference nodes are present by stable fixture key', () => {
  const graph = loadFixture();
  const keys = graph.extensions.fixtureNodeKeys;
  for (const key of [
    'node.web', 'node.gateway', 'node.payments', 'node.ai', 'node.postgres',
    'node.logs', 'node.payment_api', 'node.analytics', 'node.model', 'node.vector',
    'node.unresolved', 'node.retention', 'node.deletion',
  ]) {
    assert.ok(keys[key], `missing fixture node key ${key}`);
    assert.ok(graph.nodes.some((n) => n.id === keys[key]), `node id for ${key} not in graph.nodes`);
  }
});

test('all 8 Appendix D.3 reference flows are present by stable fixture key', () => {
  const graph = loadFixture();
  const keys = graph.extensions.fixtureFlowKeys;
  for (const key of [
    'flow.pci.masked_log', 'flow.pci.raw_log', 'flow.pci.database', 'flow.pci.payment_api',
    'flow.pci.ai', 'flow.phi.ai', 'flow.pii.analytics', 'flow.pii.unresolved',
  ]) {
    assert.ok(keys[key], `missing fixture flow key ${key}`);
    assert.ok(graph.flows.some((f) => f.id === keys[key]), `flow id for ${key} not in graph.flows`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/flagship-fixture.test.js`
Expected: FAIL — fixture file does not exist

- [ ] **Step 3: Write the fixture generator**

```js
// scanner/src/lineage/fixtures/build-flagship-fixture.mjs
//
// Generates the deterministic flagship DataFlowGraph v1 fixture (Data
// Flow Explorer PRD Appendix D.2/D.3 — the synthetic "payments-platform"
// application). Run with `node build-flagship-fixture.mjs` from anywhere;
// writes flagship-graph.json next to this script. Re-running must
// produce byte-identical output (AC-14) — there is no Date.now()/random
// anywhere in this file; `generatedAt` is a fixed synthetic timestamp,
// per Appendix D.1's rule that fixture content can never leak
// non-reproducible values into what looks like a real scan artifact.
//
// PRD Appendix D.1: "Production UI code may not contain special cases
// keyed to fixture filenames, node names, endpoints, commits, authors, or
// expected verdicts." This generator is the ONE place fixture-specific
// facts are allowed to live; `graph.extensions.fixtureNodeKeys` /
// `fixtureFlowKeys` give tests and (later) UI fixtures a genuinely
// generic lookup table rather than hardcoded ids, without smuggling
// fixture-awareness into scanner/src/lineage's own production modules.
//
// One deliberate extension beyond Appendix D.2's literal 13-row table:
// D.3's flow.pii.analytics path text reads "Support/Registration source
// -> Events Service -> Analytics DB/Provider", naming an "Events Service"
// hop that has no row of its own in D.2. Rather than silently reusing an
// unrelated node for that role, this generator adds one extra node
// (node.events) to make the path the PRD itself describes actually
// representable. Documented here, not hidden.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { emptyGraphEnvelope } from '../schema.js';
import { graphId, nodeId, dataElementId, edgeId, flowId, transformationId, evidenceId } from '../ids.js';
import { emptyProtection } from '../protection.js';
import { classifyDataElementName } from '../classification.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = 'payments-platform';
const COMMIT = 'fixture0000000000000000000000000000000';
const GENERATED_AT = '2026-08-29T00:00:00.000Z';

function node({ key, kind, subtype, label, aliases = [], lifecycleStages = [], externality = 'internal', dataElementIds = [] }) {
  const id = nodeId(kind, [REPO, key]);
  return {
    id, kind, subtype, label, aliases,
    location: null,
    system: { application: REPO, environment: 'production' },
    destination: null,
    externality: { value: externality, evidenceRefs: [] },
    lifecycleStages, governanceRefs: {}, dataElementIds, evidenceRefs: [],
    confidence: { score: 1, tier: 'high' },
    coverageStatus: 'modeled',
  };
}

function dataElement(name, discriminator) {
  const { classes } = classifyDataElementName(name);
  return {
    id: dataElementId(name, [REPO, discriminator]),
    name, aliases: [], declaredType: null,
    dataClasses: classes, aiContexts: [],
    sourceLocations: [], dataSubjectCategory: null,
    classificationEvidence: [], manualOverride: false,
    firstSeenProvenance: { commit: COMMIT, note: 'fixture evidence only, not default production content' },
  };
}

function edge({ from, to, mappings = [], protocolName = 'in-process', destinationResolution = 'literal', boundaryCrossings = [], protection = emptyProtection() }) {
  return {
    id: edgeId(from, to, 'data_flow', mappings.map((m) => m.toPath)),
    from, to, relationship: 'data_flow',
    fieldMappings: mappings,
    protocol: { name: protocolName, destinationResolution },
    boundaryCrossings, protection, evidenceRefs: [], coverageStatus: 'modeled',
  };
}

function flow({ dataElementIds, source, sink, edgeIds, transformationIds = [], policyVerdict, protectionSummary, discriminator = [], governanceRefs = {}, limitations = [] }) {
  return {
    id: flowId(source, sink, dataElementIds, discriminator),
    dataElementIds, source, sink, edgeIds, transformationIds,
    alternatePathCount: 0, policyVerdict, protectionSummary,
    evidenceRefs: [], confidence: { score: 1, tier: 'high' },
    coverageStatus: 'modeled', findingRefs: [], governanceRefs, limitations,
  };
}

function build() {
  const graph = emptyGraphEnvelope({
    graphId: graphId({ repository: REPO, commit: COMMIT, configHash: 'fixture-default' }),
    generatedAt: GENERATED_AT,
    scope: { source: 'fixture', repository: REPO, commit: COMMIT, environment: 'production' },
  });

  // --- Nodes (Appendix D.2 + the documented node.events extension) ---
  const web = node({ key: 'web', kind: 'source', subtype: 'web-app', label: 'Web App', aliases: ['Checkout Form', 'Registration Form'], lifecycleStages: ['collection'], externality: 'internal' });
  const gateway = node({ key: 'gateway', kind: 'api', subtype: 'api-gateway', label: 'API Gateway', lifecycleStages: ['processing'] });
  const payments = node({ key: 'payments', kind: 'process', subtype: 'service', label: 'Payments Service', lifecycleStages: ['processing'] });
  const events = node({ key: 'events', kind: 'process', subtype: 'service', label: 'Events Service', lifecycleStages: ['processing'] });
  const ai = node({ key: 'ai', kind: 'process', subtype: 'ai-assistant', label: 'AI Assistant', lifecycleStages: ['processing'] });
  const postgres = node({ key: 'postgres', kind: 'store', subtype: 'postgres-table', label: 'PostgreSQL', lifecycleStages: ['storage'] });
  const logs = node({ key: 'logs', kind: 'log', subtype: 'application-logs', label: 'Application Logs', lifecycleStages: ['storage'] });
  const paymentApi = node({ key: 'payment_api', kind: 'external', subtype: 'payment-api', label: 'Payment API', aliases: ['Payment Processor'], lifecycleStages: ['sharing'], externality: 'external' });
  const analytics = node({ key: 'analytics', kind: 'external', subtype: 'analytics-api', label: 'Analytics API', aliases: ['Analytics Provider', 'Analytics DB'], lifecycleStages: ['sharing'], externality: 'external' });
  const model = node({ key: 'model', kind: 'external', subtype: 'ai-model-provider', label: 'Model Provider', lifecycleStages: ['sharing'], externality: 'external' });
  const vector = node({ key: 'vector', kind: 'store', subtype: 'vector-store', label: 'Vector Store', lifecycleStages: ['storage'], externality: 'unknown' });
  const unresolved = node({ key: 'unresolved', kind: 'unresolved', subtype: 'unresolved-destination', label: 'Unresolved Destination', lifecycleStages: ['sharing'], externality: 'unknown' });
  const retention = node({ key: 'retention', kind: 'process', subtype: 'retention-policy', label: 'Retention Policy', lifecycleStages: ['retention'] });
  const deletion = node({ key: 'deletion', kind: 'process', subtype: 'deletion-job', label: 'Deletion Job', lifecycleStages: ['deletion'] });

  // --- Data elements ---
  const cardNumber = dataElement('card_number', 'payments');
  const patientSummary = dataElement('patient_summary', 'support');
  const email = dataElement('email', 'events');

  [web, gateway, payments, events, ai, postgres, logs, paymentApi, analytics, model, vector, unresolved, retention, deletion]
    .forEach((n) => { graph.nodes.push(n); });
  [cardNumber, patientSummary, email].forEach((d) => { graph.dataElements.push(d); });

  const cardIds = [cardNumber.id];

  // --- flow.pci.masked_log: Web -> Payments -> maskCard() -> Application Logs (handling protected) ---
  const maskTransform = { id: transformationId(payments.id, 'maskCard'), inputPath: 'payment.pan', outputPath: 'maskedPan', callee: 'maskCard', location: { file: 'services/payment.js', line: 55 }, kind: 'mask', reversibility: 'irreversible', algorithm: null, appliesToAllPaths: true, controlCredit: true, controlCreditReason: 'maskCard() proven on this branch (all feasible paths)' };
  graph.transformations.push(maskTransform);
  const e1a = edge({ from: web.id, to: payments.id, mappings: [{ fromPath: 'req.body.card_number', toPath: 'payment.pan', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }] });
  const maskedProtection = emptyProtection();
  maskedProtection.handling = { verdict: 'protected', evidenceGrade: 'code' };
  const e1b = edge({ from: payments.id, to: logs.id, mappings: [{ fromPath: 'payment.pan', toPath: 'maskedPan', dataElementIds: cardIds, mappingType: 'transformation', transformationIds: [maskTransform.id] }], protection: maskedProtection, boundaryCrossings: [] });
  graph.edges.push(e1a, e1b);
  const flowMaskedLog = flow({ dataElementIds: cardIds, source: web.id, sink: logs.id, edgeIds: [e1a.id, e1b.id], transformationIds: [maskTransform.id], policyVerdict: 'not_evaluated', protectionSummary: 'protected', discriminator: ['masked-branch'] });
  graph.flows.push(flowMaskedLog);

  // --- flow.pci.raw_log: Web -> Payments -> raw logger (RAW PCI, unprotected) ---
  const e2 = edge({ from: payments.id, to: logs.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payment.pan', dataElementIds: cardIds, mappingType: 'identity', transformationIds: [] }], protection: (() => { const p = emptyProtection(); p.handling = { verdict: 'unprotected', evidenceGrade: 'code' }; return p; })() });
  graph.edges.push(e2);
  const flowRawLog = flow({ dataElementIds: cardIds, source: web.id, sink: logs.id, edgeIds: [e1a.id, e2.id], policyVerdict: 'not_evaluated', protectionSummary: 'unprotected', discriminator: ['raw-branch'], limitations: ['RAW PCI: card_number logged without masking on this branch'] });
  graph.flows.push(flowRawLog);

  // --- flow.pci.database: Web -> Payments -> payments.pan (at rest unknown) ---
  const dbProtection = emptyProtection();
  dbProtection.atRest = { verdict: 'unknown', evidenceGrade: 'none' };
  const e3 = edge({ from: payments.id, to: postgres.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payments.pan', dataElementIds: cardIds, mappingType: 'identity', transformationIds: [] }], protection: dbProtection });
  graph.edges.push(e3);
  const flowDatabase = flow({ dataElementIds: cardIds, source: web.id, sink: postgres.id, edgeIds: [e1a.id, e3.id], policyVerdict: 'not_evaluated', protectionSummary: 'unknown', limitations: ['No correlated at-rest encryption configuration found for this store'] });
  graph.flows.push(flowDatabase);

  // --- flow.pci.payment_api: Web -> Payments -> http://payments.example/charge (transit unprotected) ---
  const httpProtection = emptyProtection();
  httpProtection.transit = { verdict: 'unprotected', evidenceGrade: 'code' };
  const e4 = edge({ from: payments.id, to: paymentApi.id, mappings: [{ fromPath: 'payment.pan', toPath: 'payload.cardNumber', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }], protocolName: 'http', destinationResolution: 'literal', boundaryCrossings: ['trust-zone:external'], protection: httpProtection });
  graph.edges.push(e4);
  const flowPaymentApi = flow({ dataElementIds: cardIds, source: web.id, sink: paymentApi.id, edgeIds: [e1a.id, e4.id], policyVerdict: 'not_evaluated', protectionSummary: 'unprotected', limitations: ['Cleartext HTTP scheme: no TLS termination evidence found'] });
  graph.flows.push(flowPaymentApi);

  // --- flow.pci.ai: Payments -> AI Assistant -> Model Provider (review) ---
  const e5a = edge({ from: payments.id, to: ai.id, mappings: [{ fromPath: 'payment.pan', toPath: 'promptContext.paymentCard', dataElementIds: cardIds, mappingType: 'rename', transformationIds: [] }] });
  const e5b = edge({ from: ai.id, to: model.id, mappings: [{ fromPath: 'promptContext.paymentCard', toPath: 'model.messages[].content', dataElementIds: cardIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  graph.edges.push(e5a, e5b);
  const flowPciAi = flow({ dataElementIds: cardIds, source: web.id, sink: model.id, edgeIds: [e1a.id, e5a.id, e5b.id], policyVerdict: 'manual_review_required', protectionSummary: 'unknown', governanceRefs: { recipient: 'manual_required', purpose: 'manual_required', lawfulBasis: 'manual_required' }, limitations: ['AI recipient/purpose/retention evidence not established from code alone'] });
  graph.flows.push(flowPciAi);

  // --- flow.phi.ai: Support Form (Web) -> AI Assistant -> Model Provider + Vector Store ---
  const phiIds = [patientSummary.id];
  const e6a = edge({ from: web.id, to: ai.id, mappings: [{ fromPath: 'req.body.patient_summary', toPath: 'promptContext.summary', dataElementIds: phiIds, mappingType: 'rename', transformationIds: [] }] });
  const e6b = edge({ from: ai.id, to: model.id, mappings: [{ fromPath: 'promptContext.summary', toPath: 'model.messages[].content', dataElementIds: phiIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  const e6c = edge({ from: ai.id, to: vector.id, mappings: [{ fromPath: 'promptContext.summary', toPath: 'vector.document', dataElementIds: phiIds, mappingType: 'transformation', transformationIds: [] }] });
  graph.edges.push(e6a, e6b, e6c);
  const flowPhiAi = flow({
    dataElementIds: phiIds, source: web.id, sink: model.id, edgeIds: [e6a.id, e6b.id, e6c.id],
    policyVerdict: 'manual_review_required', protectionSummary: 'unknown',
    governanceRefs: { lawfulBasis: 'manual_required', retention: 'unknown', transfer: 'review' },
    limitations: ['Lawful basis, retention, and transfer mechanism not established from code alone'],
  });
  graph.flows.push(flowPhiAi);

  // --- flow.pii.analytics: Web (Registration) -> Events Service -> Analytics API (90-day retention only if evidenced) ---
  const piiIds = [email.id];
  const e7a = edge({ from: web.id, to: events.id, mappings: [{ fromPath: 'req.body.email', toPath: 'event.email', dataElementIds: piiIds, mappingType: 'rename', transformationIds: [] }] });
  const e7b = edge({ from: events.id, to: analytics.id, mappings: [{ fromPath: 'event.email', toPath: 'traits.email', dataElementIds: piiIds, mappingType: 'projection', transformationIds: [] }], boundaryCrossings: ['trust-zone:external'] });
  graph.edges.push(e7a, e7b);
  const flowPiiAnalytics = flow({
    dataElementIds: piiIds, source: web.id, sink: analytics.id, edgeIds: [e7a.id, e7b.id],
    policyVerdict: 'not_evaluated', protectionSummary: 'unknown',
    governanceRefs: { retention: 'unknown', deletion: 'not_found' },
    limitations: ['No correlated retention/deletion policy evidence found for this recipient'],
  });
  graph.flows.push(flowPiiAnalytics);
  // Retention/deletion process nodes are wired for the fixture's governance
  // story even without a resolved edge protection verdict — they represent
  // declared process steps, not a data-flow edge with its own verdict.
  graph.edges.push(edge({ from: analytics.id, to: retention.id, mappings: [] }));
  graph.edges.push(edge({ from: retention.id, to: deletion.id, mappings: [] }));

  // --- flow.pii.unresolved: inbound source -> dynamic outbound call ---
  const e8 = edge({ from: web.id, to: unresolved.id, mappings: [{ fromPath: 'req.body.email', toPath: 'unknown', dataElementIds: piiIds, mappingType: 'unknown', transformationIds: [] }], destinationResolution: 'dynamic', boundaryCrossings: ['trust-zone:unknown'] });
  graph.edges.push(e8);
  const flowUnresolved = flow({
    dataElementIds: piiIds, source: web.id, sink: unresolved.id, edgeIds: [e8.id],
    policyVerdict: 'not_evaluated', protectionSummary: 'unknown',
    limitations: ['Destination computed from an unresolved runtime value (dynamic URL expression)'],
  });
  graph.flows.push(flowUnresolved);

  // --- Evidence (one representative entry per flow, matching PRD 16's four-question shape) ---
  for (const [claim, evType, note] of [
    ['card_number reaches Application Logs via maskCard() on the masked branch', 'code', 'services/payment.js:55'],
    ['card_number reaches Application Logs raw on a separate branch', 'code', 'services/payment.js:60'],
    ['card_number reaches payments.pan with no correlated at-rest configuration', 'code', 'services/payment.js:70'],
    ['card_number reaches http://payments.example/charge over cleartext HTTP', 'code', 'clients/gateway.js:72'],
  ]) {
    graph.evidence.push({ id: evidenceId(claim, note), claim, evidenceType: evType, location: { note }, producer: 'lineage-fixture-builder', confidenceTier: 'high', snippet: null, timestamp: GENERATED_AT, commit: COMMIT, limitations: [], conflict: false });
  }

  graph.coverage = { languages: [{ language: 'js', filesExpected: 6, filesAnalyzed: 6 }], parseFailures: [], destinationResolutionStatus: 'complete-for-fixture', pathBudgetTruncation: false };
  graph.limitations = ['This is a synthetic fixture graph, not a real repository scan. See scope.source.'];
  graph.scanHealth = { status: 'complete', reason: 'fixture' };
  graph.taxonomy = { version: '1.0.0', source: 'built-in + CONFIDENTIAL extension' };

  graph.extensions = {
    fixtureNodeKeys: {
      'node.web': web.id, 'node.gateway': gateway.id, 'node.payments': payments.id,
      'node.ai': ai.id, 'node.postgres': postgres.id, 'node.logs': logs.id,
      'node.payment_api': paymentApi.id, 'node.analytics': analytics.id, 'node.model': model.id,
      'node.vector': vector.id, 'node.unresolved': unresolved.id, 'node.retention': retention.id,
      'node.deletion': deletion.id, 'node.events': events.id,
    },
    fixtureFlowKeys: {
      'flow.pci.masked_log': flowMaskedLog.id, 'flow.pci.raw_log': flowRawLog.id,
      'flow.pci.database': flowDatabase.id, 'flow.pci.payment_api': flowPaymentApi.id,
      'flow.pci.ai': flowPciAi.id, 'flow.phi.ai': flowPhiAi.id,
      'flow.pii.analytics': flowPiiAnalytics.id, 'flow.pii.unresolved': flowUnresolved.id,
    },
  };

  return graph;
}

function main() {
  const graph = build();
  const outPath = path.join(__dirname, 'flagship-graph.json');
  fs.writeFileSync(outPath, JSON.stringify(graph, null, 2) + '\n');
  console.log(`wrote ${outPath}`);
}

main();
```

- [ ] **Step 4: Generate and verify**

Run:
```bash
cd scanner && node src/lineage/fixtures/build-flagship-fixture.mjs && node --test test/lineage/flagship-fixture.test.js
```
Expected: fixture file written; PASS (6 tests). If `validateGraph` reports errors, fix the generator (not the validator) until it is clean — the generator's output is what must conform to the contract, not the other way around.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/fixtures/ scanner/test/lineage/flagship-fixture.test.js
git commit -m "feat(lineage): add deterministic flagship graph fixture generator and output"
```

---

### Task 8: Flagship fixture semantic assertions

**Files:**
- Create: `scanner/test/lineage/flagship-fixture-semantics.test.js`

**Interfaces:**
- Consumes: `flagship-graph.json` (Task 7), `aggregateVerdicts` (Task 3).
- Produces: nothing new — this task is pure test coverage proving the fixture actually models the distinctions PRD Acceptance Criteria AC-01, AC-02, AC-03, AC-05, AC-07, and Appendix A require, so a later regression (someone "simplifying" the fixture) is caught immediately.

- [ ] **Step 1: Write the test**

```js
// scanner/test/lineage/flagship-fixture-semantics.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const graph = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

function flowByKey(key) {
  const id = graph.extensions.fixtureFlowKeys[key];
  return graph.flows.find((f) => f.id === id);
}
function nodeByKey(key) {
  const id = graph.extensions.fixtureNodeKeys[key];
  return graph.nodes.find((n) => n.id === id);
}

// AC-01: PCI to multiple sinks, each with its own independent verdict.
test('AC-01: card_number reaches log, database, and payment API as three distinct flows', () => {
  const log = flowByKey('flow.pci.masked_log');
  const db = flowByKey('flow.pci.database');
  const api = flowByKey('flow.pci.payment_api');
  assert.equal(log.sink, nodeByKey('node.logs').id);
  assert.equal(db.sink, nodeByKey('node.postgres').id);
  assert.equal(api.sink, nodeByKey('node.payment_api').id);
  // Different verdicts prove these are independently evaluated, not one shared claim.
  assert.notEqual(log.protectionSummary, db.protectionSummary);
});

// AC-02: masked and raw log flows are visibly distinct; masking earns credit, raw does not.
test('AC-02: masked log flow is protected with a proven transform; raw log flow is unprotected', () => {
  const masked = flowByKey('flow.pci.masked_log');
  const raw = flowByKey('flow.pci.raw_log');
  assert.equal(masked.protectionSummary, 'protected');
  assert.ok(masked.transformationIds.length > 0);
  const transform = graph.transformations.find((t) => t.id === masked.transformationIds[0]);
  assert.equal(transform.kind, 'mask');
  assert.equal(transform.controlCredit, true);
  assert.equal(raw.protectionSummary, 'unprotected');
  assert.equal(raw.transformationIds.length, 0);
});

// AC-03: cleartext external call is unprotected in transit, with the exact edge visible.
test('AC-03: payment API flow is transit-unprotected over literal HTTP', () => {
  const api = flowByKey('flow.pci.payment_api');
  const edge = graph.edges.find((e) => e.id === api.edgeIds[api.edgeIds.length - 1]);
  assert.equal(edge.protocol.name, 'http');
  assert.equal(edge.protection.transit.verdict, 'unprotected');
  assert.ok(edge.boundaryCrossings.includes('trust-zone:external'));
});

// AC-05: a dynamic destination remains a visible, distinctly-kinded node.
test('AC-05: the unresolved flow terminates in a kind:unresolved node, not a dropped edge', () => {
  const unresolved = flowByKey('flow.pii.unresolved');
  const sinkNode = graph.nodes.find((n) => n.id === unresolved.sink);
  assert.equal(sinkNode.kind, 'unresolved');
  const edge = graph.edges.find((e) => e.id === unresolved.edgeIds[0]);
  assert.equal(edge.protocol.destinationResolution, 'dynamic');
});

// AC-07: AI x regulated-data intersection shows a real path with honest governance unknowns.
test('AC-07: PHI-plus-AI flow reaches the model provider and reports governance facts as manual/unknown, never guessed', () => {
  const phiAi = flowByKey('flow.phi.ai');
  assert.equal(phiAi.sink, nodeByKey('node.model').id);
  const de = graph.dataElements.find((d) => phiAi.dataElementIds.includes(d.id));
  assert.ok(de.dataClasses.includes('PHI'));
  assert.equal(phiAi.governanceRefs.lawfulBasis, 'manual_required');
  assert.equal(phiAi.governanceRefs.retention, 'unknown');
});

// Appendix A: the application-level summary must not claim overall "PCI protected"
// merely because one of several card_number paths is masked/encrypted.
test('Appendix A: not every card_number flow is protected — a mixed picture is preserved', () => {
  const cardFlows = graph.flows.filter((f) => {
    const de = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
    return de && de.dataClasses.includes('PCI');
  });
  const summaries = new Set(cardFlows.map((f) => f.protectionSummary));
  assert.ok(summaries.has('protected'));
  assert.ok(summaries.has('unprotected') || summaries.has('unknown'), 'at least one PCI flow must be non-protected — the fixture must not launder an overall-safe claim');
});

test('every node referenced by extensions.fixtureNodeKeys/fixtureFlowKeys actually resolves', () => {
  for (const [key, id] of Object.entries(graph.extensions.fixtureNodeKeys)) {
    assert.ok(graph.nodes.some((n) => n.id === id), `dangling fixtureNodeKeys entry ${key}`);
  }
  for (const [key, id] of Object.entries(graph.extensions.fixtureFlowKeys)) {
    assert.ok(graph.flows.some((f) => f.id === id), `dangling fixtureFlowKeys entry ${key}`);
  }
});
```

- [ ] **Step 2: Run and verify**

Run: `cd scanner && node --test test/lineage/flagship-fixture-semantics.test.js`
Expected: PASS (7 tests). If any fail, the fixture generator (Task 7) is missing the distinction — fix the generator, regenerate, re-run Task 7's tests too, then re-run this file.

- [ ] **Step 3: Commit**

```bash
git add scanner/test/lineage/flagship-fixture-semantics.test.js
git commit -m "test(lineage): pin flagship fixture against PCI/PHI/AI acceptance criteria"
```

---

### Task 9: Threat model document

**Files:**
- Create: `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`

**Interfaces:**
- Consumes: PRD §24 ("Privacy and security of the visualization itself"), §28.4 (security test list), AC-15 (malicious labels), §17.4 (server security — forward-looking, since the server itself is Milestone 3, but the threat model must be written before that server exists per the Milestone 0 exit gate).
- Produces: a written document only — no code. This is a genuine Milestone 0 deliverable ("threat model") that later milestones' security tests (Task 28.4) get written against.

- [ ] **Step 1: Write the document**

```markdown
# Data Flow Explorer — Threat Model

Status: living document, first written for Milestone 0 (contract/fixture
phase, before any server or UI code exists). Threats below are organized
by the asset they target. Each entry names the PRD requirement that is
the mitigation, and — where the mitigating code does not exist yet — the
milestone responsible for landing it. This file must be revisited at
every milestone exit gate (PRD section 26) and updated, not left to rot.

## Assets

1. **The graph artifact itself** — may reveal architecture, field names,
   vendors, endpoints, database schemas, and security controls (PRD
   section 24). Confidential by default.
2. **The local read-only API / server** (Milestone 3) — a loopback HTTP
   server serving graph queries and evidence.
3. **The browser client** — renders untrusted repository text (file
   paths, symbol names, string literals, comments) as part of node
   labels, evidence snippets, and policy reasons.
4. **Exported artifacts** (self-contained HTML, PNG/SVG, JSON/CSV,
   DPIA/RoPA) — leave the local machine once exported; must not
   over-disclose by default.
5. **State on disk** (`.agentic-security/` graph cache, layout cache,
   attestations) — subject to the same retention/reset/legal-hold rules
   as every other scanner artifact (PRD section 24, first bullet).

## Threats and mitigations

### T1 — Hostile repository text executes in the browser (XSS via scanned content)

A malicious or adversarially-crafted repository can contain HTML, script
tags, control characters, or extremely long identifiers in file/symbol
names, string literals, comments, or route paths. Any of these can reach
a node label, evidence snippet, or policy-reason string in the graph.

- **Mitigation:** every label and snippet is escaped and inserted via
  safe DOM/text APIs; no scanned HTML or Markdown may execute (PRD
  section 16, AC-15). Bounded string length on any rendered label.
- **Status:** contract-level guard only today — `dataElement.name`,
  `node.label`, and evidence `claim`/`snippet` fields carry no HTML
  interpretation semantics in the schema itself (Task 1/6, this
  milestone). The actual escaping/rendering code is Milestone 3 (UI).
  Milestone 3's plan MUST include an adversarial fixture (HTML/script
  tags/control chars/very long identifiers in file and symbol names) and
  a test asserting the rendered DOM contains no live `<script>`,
  `javascript:` URL, or unescaped tag from that fixture.

### T2 — DNS rebinding / hostile Host header against the local server

A malicious webpage open in the same browser could point requests at
`127.0.0.1:<port>` if the server trusts an arbitrary `Host` header or
allows cross-origin requests.

- **Mitigation (PRD section 17.4):** bind only to `127.0.0.1`/`::1`,
  random port by default, random session token required, validate the
  `Host` header, restrictive CSP, CORS disabled by default, same-site
  cookie or request token for state-changing endpoints.
- **Status:** not yet built (Milestone 3). Recorded here so the Milestone
  3 plan is written against this threat, not discovered afterward.

### T3 — CSRF against write/rescan endpoints

Once state-changing endpoints exist (`POST /api/v1/rescan`, remediation
writes — PRD section 17.3), a page the user has open elsewhere could
trigger a same-origin-looking request.

- **Mitigation:** session-token or same-site-cookie requirement on every
  state-changing endpoint (PRD section 17.4); P0 API is otherwise
  read-only with respect to source and policy (PRD section 17.3).
- **Status:** Milestone 3 (server does not exist yet).

### T4 — Path traversal through evidence/file-line lookups

An evidence reference or exported location string could be crafted (or a
bug could construct one) to escape the scanned repository root when the
server resolves it back to a file on disk.

- **Mitigation:** confine file/line evidence lookups to the scanned root
  (PRD section 17.4); reject any resolved path outside it.
- **Status:** Milestone 3. This milestone's evidence schema
  (`evidence.location`) is a plain object with no path-resolution logic
  attached to it yet, so there is no traversal surface today — the
  requirement is recorded for when Milestone 3 adds a resolver.

### T5 — Oversized or cyclic graph input causes denial of service

A pathological repository (huge fan-out, generated code, adversarially
constructed cycles) could produce a graph whose validation, layout, or
path-reconstruction is superlinear or non-terminating.

- **Mitigation:** the graph-build phase bounds interprocedural contexts
  and alternate paths per source/sink pair with explicit truncation (PRD
  section 18.4, Milestone 1/2 scope); the server caps request size, graph
  query complexity, and path enumeration (PRD section 17.4, Milestone 3).
- **Status today:** `validateGraph` (Task 5, this milestone) is a single
  linear pass over `nodes`/`edges`/`dataElements`/`flows` with no
  recursion into cyclic structures — it cannot itself loop forever on a
  cyclic graph, because it never walks edges transitively, only checks
  that referenced ids exist. The performance harness (Task 11, this
  milestone) establishes the baseline timing for a synthetic 5,000
  node / 10,000 edge graph so a future regression is measurable, not
  just asserted safe.

### T6 — Secret values or unredacted source leak into an export or the URL

PRD section 24: keep source snippets out of URLs/browser history/
telemetry; default shared exports to short, redacted snippets.

- **Mitigation:** evidence `snippet` fields default to redacted/short;
  URL state carries only canonical IDs and non-sensitive filter
  expressions (PRD section 7.11); export defaults require explicit
  opt-in for unredacted evidence (PRD section 17.5).
- **Status:** this milestone's `evidence` contract (Task 5/6) makes
  `snippet` an optional, independently-settable field — the fixture
  builder (Task 7) never populates it, so today's only evidence consumer
  (tests) never observes an unredacted snippet. The redaction POLICY
  itself (what counts as "short," default-on vs. explicit opt-in) is
  Milestone 3/4 (export code).

### T7 — Fixture content leaks into or is mistaken for a real scan

Appendix D.1: fixture-backed screens/exports must be marked "Illustrative
demo data" and must never leak synthetic filenames, endpoints, commits,
authors, or governance metadata into a real repository scan; production
code must not special-case fixture names.

- **Mitigation:** `scope.source` is a generic, always-present envelope
  field (`'scan' | 'fixture'`) — Task 1 defaults it to `'scan'`, and only
  the fixture builder (Task 7) sets it to `'fixture'` explicitly. No
  module in `scanner/src/lineage/` checks a filename, node id, or commit
  hash to decide fixture-ness.
- **Status:** enforced today by construction (there is no name-based
  special case to regress) and pinned by
  `test/lineage/flagship-fixture.test.js`'s `scope.source` assertion
  (Task 7). Milestone 3's UI must read `scope.source`, not a name, to
  render the "Illustrative demo data" ribbon (AC-24).

### T8 — Manual overrides or scenario data launder as scanner evidence

PRD section 24 / risk table: a manual classification override or a
What-If scenario (Milestone 5) could be displayed indistinguishably from
code-derived evidence, producing false assurance.

- **Mitigation:** `dataElement.manualOverride` is a required boolean
  field in the contract (Task 1/5/6, this milestone) — a manual override
  can never be silently indistinguishable from taxonomy-derived
  classification at the schema level. Scenario/`HYPOTHETICAL` evidence
  grading is Milestone 5 scope (DFG-036) and is out of scope for this
  document until that milestone's plan is written, but the
  `protection.js` evidence-grade enum (Task 3) already reserves
  `'declared'` and `'manual'` as distinct grades from `'code'` /
  `'runtime'` — a future scenario evidence type has a place to land
  without overloading an existing grade.

## What this milestone does NOT yet threat-model

Everything that requires the server, browser client, or export pipeline
to exist: XSS rendering behavior (T1's actual DOM assertions), DNS
rebinding/CSRF/traversal defenses (T2–T4, no server exists), and export
redaction defaults (T6, no export pipeline exists). These are named
above specifically so the milestone that builds each capability starts
from a stated threat, not a blank page.
```

- [ ] **Step 2: Commit**

```bash
git add docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md
git commit -m "docs(lineage): add Data Flow Explorer threat model (Milestone 0 deliverable)"
```

---

### Task 10: Benchmark corpus design + first fixtures

**Files:**
- Create: `bench/data-lineage/README.md`
- Create: `bench/data-lineage/fixtures/js-api-to-log-masked/{source.js,expected.json}`
- Create: `bench/data-lineage/fixtures/js-api-to-log-raw/{source.js,expected.json}`
- Create: `bench/data-lineage/fixtures/js-api-to-external-http-cleartext/{source.js,expected.json}`

**Interfaces:**
- Produces: a corpus design doc (PRD §22.2's category list, target counts) and 3 concrete first-fixture entries following that design — establishing the pattern for the ~200-fixture corpus Milestone 1's DFG-018 will mass-author. `expected.json` records the human-labeled expected verdict per fixture (source/sink/dataClass/protection), independent of any engine implementation (there is no lineage engine yet — Milestone 1).

- [ ] **Step 1: Write the design doc**

```markdown
# bench/data-lineage/ — Data-Flow Explorer accuracy corpus (design)

Successor to `bench/privacy-recall/` (PRD section 3: "Baseline contains
only four fixtures and is not adequate proof of broad, cross-language
lineage accuracy"). This corpus measures the Milestone 1/2 lineage
engine's field-to-sink precision/recall, external-destination recall, and
false-`protected` rate (PRD section 22.3's release thresholds) — it does
NOT exist to gate anything yet, because the engine it measures has not
been built. This milestone (M0) only establishes the fixture SHAPE and
seeds the first 3 entries; a runner/checker script lands with Milestone 1
(DFG-018), once there is an engine to run fixtures through.

## Target corpus shape (PRD section 22.2)

At least:
- 100 vulnerable/positive field flows
- 100 clean/negative or protected flows
- every supported language (initial order: JS/TS, Python, then Java/C#/Go,
  then Kotlin/Ruby/PHP — PRD section 22.1)
- every source and sink category (PRD sections 11, 12)
- direct, aliased, cross-file, interprocedural, serialized, database,
  queue, API, and AI paths
- masked, hashed, tokenized, encrypted, weakly-encrypted, branch-partial,
  and reversed transformations
- HTTPS, cleartext, certificate-verification-disabled, dynamic-scheme,
  proxy-terminated, and unknown-transport cases
- dynamic destinations and unsupported-candidate cases
- policy-permitted and policy-prohibited flows

## Fixture shape

Each entry is a directory under `fixtures/<id>/`:
- `source.<ext>` — a small, self-contained source file exercising exactly
  one flow shape. Named descriptively: `<lang>-<source-category>-to-<sink-category>-<distinguishing-trait>`.
- `expected.json` — the human-labeled expected result, independent of any
  engine implementation:
  ```json
  {
    "language": "js",
    "dataClass": ["PCI"],
    "sourceCategory": "http-body",
    "sinkCategory": "log",
    "expectedProtection": { "handling": "protected" },
    "expectedTransformKind": "mask",
    "notes": "maskCard() applied on every feasible path before the log call"
  }
  ```

## Seeded first entries (this milestone)

- `js-api-to-log-masked/` — positive case, masked (protected handling).
- `js-api-to-log-raw/` — positive case, raw (unprotected handling, RAW PCI).
- `js-api-to-external-http-cleartext/` — positive case, unprotected transit
  over literal HTTP.

These establish the fixture-authoring pattern; Milestone 1's DFG-018 mass-authors
the remaining ~194+ entries against it, plus the runner/checker script
(`bench/data-lineage/runner.mjs`, mirroring `bench/cve-replay/runner.mjs`'s
pre/post scoring shape) once the lineage engine exists to score against.
```

- [ ] **Step 2: Write the three seed fixtures**

```js
// bench/data-lineage/fixtures/js-api-to-log-masked/source.js
function maskCard(pan) {
  return pan.slice(0, 4) + '********' + pan.slice(-4);
}

function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  const maskedPan = maskCard(cardNumber);
  logger.info('processing payment', { pan: maskedPan });
}
```

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": { "handling": "protected" },
  "expectedTransformKind": "mask",
  "notes": "maskCard() applied to every feasible path before logger.info()"
}
```

```js
// bench/data-lineage/fixtures/js-api-to-log-raw/source.js
function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  logger.info('processing payment', { pan: cardNumber });
}
```

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": { "handling": "unprotected" },
  "expectedTransformKind": null,
  "notes": "card_number reaches logger.info() with no transform on the path"
}
```

```js
// bench/data-lineage/fixtures/js-api-to-external-http-cleartext/source.js
async function chargeCard(req) {
  const cardNumber = req.body.card_number;
  await fetch('http://payments.example/charge', {
    method: 'POST',
    body: JSON.stringify({ cardNumber }),
  });
}
```

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "external-api",
  "expectedProtection": { "transit": "unprotected" },
  "expectedTransformKind": null,
  "notes": "literal http:// scheme, no TLS — transit must be unprotected regardless of scheme alone (PRD FR-401)"
}
```

- [ ] **Step 3: Commit**

```bash
git add bench/data-lineage/
git commit -m "docs(lineage): design the data-lineage accuracy corpus and seed 3 fixtures"
```

---

### Task 11: Performance harness skeleton

**Files:**
- Create: `bench/data-lineage/perf/generate-synthetic-graph.mjs`
- Create: `bench/data-lineage/perf/runner.mjs`

**Interfaces:**
- Consumes: `emptyGraphEnvelope`, `nodeId`, `edgeId`, `dataElementId`, `flowId`, `emptyProtection`, `validateGraph` (Tasks 1, 2, 3, 5).
- Produces: a synthetic-graph generator sized to the PRD §21 reference scale (5,000 nodes / 10,000 edges) and a timing runner reporting `validateGraph` and ID-generation throughput on it. This is the skeleton later milestones extend with real render/query/layout timings (PRD §21's actual UI-facing metrics are Milestone 3 scope) — it exists now so build-overhead regressions on the contract layer itself are caught immediately, before any UI exists to blame instead.

- [ ] **Step 1: Write the synthetic graph generator**

```js
// bench/data-lineage/perf/generate-synthetic-graph.mjs
//
// Synthetic DataFlowGraph v1 at the PRD section 21 reference scale
// (5,000 nodes / 10,000 edges), for performance-harness use only — not a
// fixture with any semantic meaning (contrast with
// scanner/src/lineage/fixtures/build-flagship-fixture.mjs, which encodes
// real Appendix D content). Import `generateSyntheticGraph(nodeCount,
// edgeCount)` directly rather than shelling out, so the perf runner pays
// no extra process-spawn overhead when timing graph-scale operations.

import { emptyGraphEnvelope } from '../../../scanner/src/lineage/schema.js';
import { graphId, nodeId, edgeId, dataElementId, flowId } from '../../../scanner/src/lineage/ids.js';
import { emptyProtection } from '../../../scanner/src/lineage/protection.js';

export function generateSyntheticGraph(nodeCount = 5000, edgeCount = 10000) {
  const graph = emptyGraphEnvelope({
    graphId: graphId({ repository: 'synthetic-perf', commit: 'synthetic', configHash: `${nodeCount}x${edgeCount}` }),
  });

  const kinds = ['source', 'process', 'store', 'log', 'external'];
  for (let i = 0; i < nodeCount; i++) {
    const kind = kinds[i % kinds.length];
    graph.nodes.push({
      id: nodeId(kind, ['synthetic-perf', `n${i}`]),
      kind, subtype: 'synthetic', label: `Node ${i}`, aliases: [],
      location: null, system: {}, destination: null,
      externality: { value: 'internal', evidenceRefs: [] },
      lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
      confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
    });
  }

  const de = dataElementId('synthetic_field', ['synthetic-perf']);
  graph.dataElements.push({
    id: de, name: 'synthetic_field', aliases: [], declaredType: null,
    dataClasses: [], aiContexts: [], sourceLocations: [], dataSubjectCategory: null,
    classificationEvidence: [], manualOverride: false,
  });

  for (let i = 0; i < edgeCount; i++) {
    const from = graph.nodes[i % nodeCount].id;
    const to = graph.nodes[(i * 7 + 1) % nodeCount].id;
    graph.edges.push({
      id: edgeId(from, to, 'data_flow', [String(i)]),
      from, to, relationship: 'data_flow',
      fieldMappings: [], protocol: { name: 'synthetic', destinationResolution: 'literal' },
      boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled',
    });
  }

  for (let i = 0; i < 500; i++) {
    const source = graph.nodes[i % nodeCount].id;
    const sink = graph.nodes[(nodeCount - 1 - i) % nodeCount].id;
    graph.flows.push({
      id: flowId(source, sink, [de], [String(i)]),
      dataElementIds: [de], source, sink, edgeIds: [], transformationIds: [],
      alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed',
      evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
      findingRefs: [], governanceRefs: {}, limitations: [],
    });
  }

  return graph;
}
```

- [ ] **Step 2: Write the timing runner**

```js
// bench/data-lineage/perf/runner.mjs
//
// Contract-layer performance harness (PRD section 21's "Graph build
// overhead" and validation-cost concerns, scoped to what exists at
// Milestone 0: no render/query/layout timings yet, since there is no UI
// — Milestone 3 extends this file with those). Run:
//   node bench/data-lineage/perf/runner.mjs
// Prints timing; exits 0 always at this milestone (no baseline to gate
// against yet — a --check flag with a committed baseline lands once
// Milestone 3's UI timings make the PRD 21 targets checkable for real).

import { generateSyntheticGraph } from './generate-synthetic-graph.mjs';
import { validateGraph } from '../../../scanner/src/lineage/validate.js';

function timeIt(label, fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  console.log(`${label}: ${ms.toFixed(1)}ms`);
  return { result, ms };
}

function main() {
  const { result: graph, ms: genMs } = timeIt('generate 5000-node/10000-edge synthetic graph', () => generateSyntheticGraph(5000, 10000));
  console.log(`  nodes=${graph.nodes.length} edges=${graph.edges.length} flows=${graph.flows.length}`);

  const { result: validation, ms: valMs } = timeIt('validateGraph over the synthetic graph', () => validateGraph(graph));
  console.log(`  valid=${validation.valid} errorCount=${validation.errors.length}`);

  console.log('\nSummary:');
  console.log(`  generation: ${genMs.toFixed(1)}ms`);
  console.log(`  validation: ${valMs.toFixed(1)}ms`);
  console.log('\nNo baseline gate yet — this harness establishes the measurement point for Milestone 3 to extend with real render/query/layout timings against PRD section 21 targets.');
}

main();
```

- [ ] **Step 3: Run and verify it completes without error**

Run: `cd /Users/ross/code/agentic-security && node bench/data-lineage/perf/runner.mjs`
Expected: prints generation/validation timings, `valid=true errorCount=0`, exits 0.

- [ ] **Step 4: Commit**

```bash
git add bench/data-lineage/perf/
git commit -m "feat(lineage): add contract-layer performance harness skeleton"
```

---

### Task 12: Wire test:lineage script and update documentation

**Files:**
- Modify: `scanner/package.json`
- Modify: `scanner/CLAUDE.md`
- Modify: `CLAUDE.md` (repository root)
- Create: `scanner/src/lineage/CLAUDE.md`

**Interfaces:** none — this task is wiring and documentation only.

- [ ] **Step 1: Add the `test:lineage` script**

In `scanner/package.json`'s `"scripts"` object, add (alphabetically near `test:mcp`/`test:report`, following the existing style of an explicit file list):

```json
"test:lineage": "node --test test/lineage/schema.test.js test/lineage/ids.test.js test/lineage/protection.test.js test/lineage/classification.test.js test/lineage/validate.test.js test/lineage/json-schema-parity.test.js test/lineage/flagship-fixture.test.js test/lineage/flagship-fixture-semantics.test.js",
```

- [ ] **Step 2: Run it**

Run: `cd scanner && npm run test:lineage`
Expected: PASS (all 8 files, ~40 tests total).

- [ ] **Step 3: Add a row to `scanner/CLAUDE.md`'s test-commands table**

Add, after the `test:mcp` row:

```markdown
| `npm run test:lineage` | `src/lineage/` — DataFlowGraph v1 contract, IDs, fixture | When editing `src/lineage/` |
```

- [ ] **Step 4: Create `scanner/src/lineage/CLAUDE.md`**

```markdown
# scanner/src/lineage/

Data Flow Explorer's canonical `DataFlowGraph v1` contract package
(PRD: `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`, section 18.1).
Isolated by design from `scanner/src/dataflow/`'s taint engine — see that
package's own CLAUDE.md for why (D-0047's precedent: a second, independent
engine sharing only pure, stateless utilities, never mutable taint state).

## What's here (Milestone 0 — contract and fixture only)

| Module | Responsibility |
|---|---|
| `schema.js` | Envelope shape, `SCHEMA_VERSION`, node/mapping/transform/coverage/policy/evidence enums |
| `ids.js` | Deterministic stable-ID functions (`nodeId`, `edgeId`, `dataElementId`, `flowId`, `transformationId`, `evidenceId`, `graphId`) — sha256-over-canonicalized-material, same shape as `posture/stable-id.js`'s finding IDs |
| `protection.js` | Protection verdict model: `PROTECTION_VERDICTS` × `EVIDENCE_GRADES` per dimension (`transit`/`atRest`/`handling`), plus `aggregateVerdicts()`'s risk-precedence reduction (PRD 8.4) |
| `classification.js` | Data classes (reuses `dataflow/privacy-taxonomy.js` + adds `CONFIDENTIAL`) and the 15 AI processing contexts (PRD 9.2) — AI is modeled as orthogonal to data class, never a mutually-exclusive label |
| `validate.js` | Hand-rolled structural validator (`validateGraph`) — no new npm dependency; `dataflow-graph.schema.json` is the JSON-Schema-dialect twin, kept in parity by `test/lineage/json-schema-parity.test.js` |
| `dataflow-graph.schema.json` | Authoritative JSON Schema (2020-12) document for external interop/documentation |
| `fixtures/build-flagship-fixture.mjs` | Deterministic generator for the payments-platform reference fixture (PRD Appendix D.2/D.3) — re-run and re-commit `flagship-graph.json` if you change the generator; a diff test (`flagship-fixture.test.js`) enforces idempotence |

## What is NOT here yet (later milestones)

- The actual lineage-tracking engine (source/sink registries, worklist,
  interprocedural summaries, path DAG) — Milestone 1 (DFG-004, DFG-005).
- External destination resolution, database/queue field mapping,
  transit/at-rest/handling ANALYZERS (this package only defines the
  verdict *model*, not what decides a verdict) — Milestone 2.
- The local API/server and any UI — Milestone 3.
- Decision-intelligence extensions (stories, scenarios, snapshots/diffs,
  obligations, runtime twin, recipients, impact/remediation) —
  Milestones 4/5.

## Conventions

- Every enum here is a single source of truth for its concept. If you add
  a new node kind, mapping type, transform kind, etc., you MUST update
  three places: `schema.js` (or `protection.js`/`classification.js`),
  `dataflow-graph.schema.json`'s matching `enum` array, and
  `validate.js` if the new value needs a structural check —
  `json-schema-parity.test.js` fails loudly if the first two drift apart.
- Stable IDs are content hashes, not counters — see `ids.js`'s header.
  Never construct an id string by hand; always call the exported
  function, so a discriminator-shape change only has one call site to fix.
- The flagship fixture is the ONE place fixture-specific facts (node
  names like "Payments Service", synthetic commit hashes, etc.) are
  allowed to live. No other module in this package — and per PRD Appendix
  D.1, no UI code in a later milestone — may special-case a fixture name.
  The generic hook is `graph.scope.source === 'fixture'`.
```

- [ ] **Step 5: Add a row to the root `CLAUDE.md` repository-layout table**

Insert after the `scanner/src/dataflow/provenance/` row (or after `scanner/src/dataflow/` if there is no such row — check the current table before inserting):

```markdown
| `scanner/src/lineage/` | Data Flow Explorer: canonical `DataFlowGraph v1` contract (schema, stable IDs, protection/classification model), isolated from the taint engine. Milestone 0 of `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`. | `scanner/src/lineage/CLAUDE.md` |
```

- [ ] **Step 6: Run the full lineage scope once more, then the broader dataflow scope, to confirm no cross-contamination**

Run:
```bash
cd scanner && npm run test:lineage && npm run test:dataflow
```
Expected: both PASS. `test:dataflow` passing unchanged confirms Task 4's read-only import of `privacy-taxonomy.js` introduced no regression in the existing privacy-taint tests.

- [ ] **Step 7: Commit**

```bash
git add scanner/package.json scanner/CLAUDE.md CLAUDE.md scanner/src/lineage/CLAUDE.md
git commit -m "docs(lineage): wire test:lineage script and document the new package"
```

---

### Task 13: Final gate check

**Files:** none (verification-only task).

- [ ] **Step 1: Run the full scanner test suite**

Run: `cd scanner && npm test`
Expected: exit 0. This confirms the new `scanner/src/lineage/` package and its read-only reuse of `dataflow/privacy-taxonomy.js` did not regress anything in the full existing gate (SAST, posture, dataflow, MCP, report, lifecycle, cpp-dataflow, python).

- [ ] **Step 2: Run the lifecycle/dead-module check specifically**

Run: `cd scanner && npm run test:lifecycle`
Expected: exit 0. `test/no-dead-modules.test.js` and the Stop-hook drift checker (`session-stop-drift-check.js`) both care about new files under `src/{sast,posture,dataflow}` specifically — `src/lineage/` is a new top-level package outside that watched list, so this step is a genuine check that nothing else in the lifecycle scope reacted badly to the new directory, not an assumption that it's exempt from every check.

- [ ] **Step 3: Confirm nothing under `scanner/src/lineage/` is accidentally covered by `.claude/settings.json`'s read-deny list**

Run: `cd /Users/ross/code/agentic-security && grep -n "lineage" .claude/settings.json || echo "no match — fine, nothing to adjust"`
Expected: no match (the read-deny list is for generated bundles/caches, not new source).

- [ ] **Step 4: Report status**

If all of Steps 1–3 pass, Milestone 0's contract-and-fixture half is complete: `DataFlowGraph v1`'s schema, stable-ID spec, protection-verdict model, classification model, structural validator, JSON Schema document, a deterministic flagship fixture satisfying AC-01/02/03/05/07 and Appendix A's "not overall-protected" rule, a threat-model document, the first 3 accuracy-corpus fixtures with a documented corpus design, and a contract-layer performance harness are all committed and gated. This unblocks two follow-on tracks that can now be planned precisely (their exact field/projection names were not knowable before this plan landed):

- **Milestone 0's second half** — design tokens, layout blueprint, component contracts, and the clickable high-fidelity UI prototype (PRD section 7.7 onward, Appendix D.4–D.6) — a separate plan, since it introduces net-new frontend tooling (React/TypeScript/a bundler) this plan deliberately did not touch.
- **Milestone 1** — the actual typed lineage engine (DFG-004 through DFG-011) that populates this contract with real analysis instead of a hand-authored fixture.
```
