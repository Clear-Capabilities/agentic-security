# Blast-Radius: Impact Assessment (FR-507, M5 deliverable #4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an `ImpactAssessment` extension contract plus a pure
read/aggregate computation — "what does this graph's own real evidence
say is reachable from a compromised node/edge/flow/data-element" —
reusing `frontend/src/lib/focus-controls.js`'s already-shipped BFS
traversal, with a CLI verb to run it.

**Architecture:** `impact-assessment.js` defines the record contract.
`impact-engine.js` runs `showAllPaths` from the target's resolved
node(s), aggregates affected data classes and `RecipientProfile`
records via a `contributingGraphIds` membership filter, and reports
coverage limitations. No mutation, no hypothesis — a pure read over the
real, already-scanned graph, simpler than the What-If Simulator's own
clone-and-override engine (M5 3a). A CLI verb (`dataflow impact
assess`) wires it end to end, mirroring `dataflow scenario apply`'s own
shape exactly.

**Tech Stack:** Node ESM, `node:test`, no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-blast-radius-impact-scoping.md`

## Global Constraints

- No frontend/UI work — CLI/JSON/Markdown export only.
- `scope` is always `'possible'` — never fabricate an `'observed'`
  value (no runtime-corroboration layer exists yet; Digital Twin, M5
  #7, is a future producer of a real `'observed'` value).
- `targetKind` accepts `node`/`edge`/`flow`/`dataElement` only —
  `finding:*` targets are out of scope (findings have no stable
  graph-entity id).
- No `affectedObligationIds` field — `ObligationMapping` records are
  built on demand per compliance-framework requirement, not stored on
  the graph; aggregating them is real, separate future scope, not
  attempted here (see the spec's own "Out of scope" section).
- `affectedRecipientProfileIds` degrades honestly to `[]` when
  `graph.recipientProfiles` doesn't exist on the graph at all.
- `coverageLimitations` reports the WHOLE graph's own non-`'full'`-tier
  coverage entries (`graph.coverage.languages[]`) — NOT scoped down to
  only the affected subgraph, since no node carries a `language` field
  to filter by (a real, disclosed simplification found while writing
  this plan; the spec's own "scoped down" framing overstated what's
  cheaply computable — a coverage gap in the WHOLE graph is still a
  real, honest limitation on any impact assessment computed over it,
  just not narrowed to the exact affected nodes).
- No new npm dependency.
- Every new module follows this package's own established precedent:
  `validateImpactAssessment(record) -> {valid, errors}`, never throws;
  `impactAssessmentId(...)` object-argument ID minting in `ids.js`,
  mirroring `recipientProfileId`'s/`scenarioId`'s own exact pattern
  (confirmed: `src/lineage/ids.js:180-185`).
- `showAllPaths`/`showUpstream`/`showDownstream` are imported from
  `'../../../frontend/src/lib/focus-controls.js'` — the established
  cross-import precedent (`export-privacy.js:31` imports
  `computePrivacyViewModel` the identical way). Never reimplemented.

---

### Task 1: `impact-assessment.js` contract + `impact-engine.js` computation

**Files:**
- Create: `scanner/src/lineage/impact-assessment.js`
- Create: `scanner/src/lineage/impact-engine.js`
- Modify: `scanner/src/lineage/ids.js` (append `impactAssessmentId`)
- Test: `scanner/test/lineage/impact-assessment.test.js`
- Test: `scanner/test/lineage/impact-engine.test.js`

**Interfaces:**
- Produces: `IMPACT_TARGET_KINDS = Object.freeze(['node', 'edge',
  'flow', 'dataElement'])` and `validateImpactAssessment(record) ->
  {valid, errors}` (`impact-assessment.js`). `impactAssessmentId({
  graphId, graphDigest, targetId }, discriminatorParts = [])`
  (`ids.js`). `computeImpactAssessment(graph, targetId, opts = {}) ->
  ImpactAssessment` (`impact-engine.js`) — throws only on a structurally
  invalid `targetId` (not a string, or not prefixed with a known kind);
  degrades honestly (empty arrays) for a well-formed but non-existent
  target id.
- Consumes: nothing from later tasks.

- [ ] **Step 1: Add `impactAssessmentId` to `ids.js`**

Append to `scanner/src/lineage/ids.js`, after the existing `scenarioId`
export:

```js
/**
 * An ImpactAssessment record's id (M5 deliverable #4, FR-507 §10.10) —
 * NOT a DataFlowGraph v1 entity, mirrors recipientProfileId's/
 * scenarioId's own precedent exactly. Discriminated by (graphId,
 * graphDigest, targetId) — graphDigest is required for the identical
 * reason every other extension-contract id in this file requires it
 * (graphId alone never distinguishes two same-commit graphs with
 * genuinely different content); targetId is the compromised entity the
 * assessment was computed FROM, so two assessments over the same graph
 * but different targets never collide.
 */
export function impactAssessmentId(
  { graphId, graphDigest, targetId },
  discriminatorParts = [],
) {
  return `impact:${_hash(_canon([graphId, graphDigest, targetId, ...discriminatorParts]))}`;
}
```

- [ ] **Step 2: Write failing tests for `impact-assessment.js`**

Create `scanner/test/lineage/impact-assessment.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { impactAssessmentId } from '../../src/lineage/ids.js';
import {
  IMPACT_TARGET_KINDS,
  IMPACT_SCOPE_VALUES,
  validateImpactAssessment,
} from '../../src/lineage/impact-assessment.js';

test('impactAssessmentId is deterministic and differs on any input change', () => {
  const base = { graphId: 'graph:abc', graphDigest: 'sha256:aaa', targetId: 'node:sink' };
  const a = impactAssessmentId(base);
  const b = impactAssessmentId(base);
  assert.equal(a, b);
  assert.notEqual(a, impactAssessmentId({ ...base, targetId: 'node:other' }));
  assert.match(a, /^impact:[0-9a-f]+$/);
});

test('IMPACT_TARGET_KINDS is exactly the 4 in-scope kinds, no finding kind', () => {
  assert.deepEqual(IMPACT_TARGET_KINDS, ['node', 'edge', 'flow', 'dataElement']);
});

test('validateImpactAssessment: a well-formed record is valid', () => {
  const record = {
    id: impactAssessmentId({ graphId: 'graph:abc', graphDigest: 'sha256:aaa', targetId: 'node:sink' }),
    version: '1.0.0',
    graphId: 'graph:abc', graphDigest: 'sha256:aaa',
    targetId: 'node:sink', targetKind: 'node',
    scope: 'possible',
    affectedNodeIds: ['node:sink'], affectedEdgeIds: [],
    affectedDataClasses: ['PII'],
    affectedRecipientProfileIds: [],
    coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateImpactAssessment: never throws on garbage input, reports errors instead', () => {
  for (const bad of [null, undefined, 42, [], {}, { id: 'not-impact:x' }]) {
    assert.doesNotThrow(() => validateImpactAssessment(bad));
    const { valid, errors } = validateImpactAssessment(bad);
    assert.equal(valid, false);
    assert.ok(errors.length > 0);
  }
});

test('validateImpactAssessment: rejects an unrecognized targetKind', () => {
  const record = {
    id: 'impact:x', version: '1.0.0', graphId: 'g', graphDigest: 'd',
    targetId: 'finding:123', targetKind: 'finding', scope: 'possible',
    affectedNodeIds: [], affectedEdgeIds: [], affectedDataClasses: [],
    affectedRecipientProfileIds: [], coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.targetKind'));
});

test('validateImpactAssessment: rejects a scope other than possible/observed', () => {
  const record = {
    id: 'impact:x', version: '1.0.0', graphId: 'g', graphDigest: 'd',
    targetId: 'node:x', targetKind: 'node', scope: 'definitely',
    affectedNodeIds: [], affectedEdgeIds: [], affectedDataClasses: [],
    affectedRecipientProfileIds: [], coverageLimitations: [],
    generatedAt: '2026-09-02T00:00:00.000Z',
  };
  const { valid, errors } = validateImpactAssessment(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.scope'));
});
```

- [ ] **Step 3: Run to verify failure**

Run: `cd scanner && node --test test/lineage/impact-assessment.test.js`
Expected: FAIL — module not found.

- [ ] **Step 4: Write `impact-assessment.js`**

Create `scanner/src/lineage/impact-assessment.js`:

```js
// impact-assessment.js — M5 deliverable #4 (FR-507 §10.10): the
// ImpactAssessment extension contract — the result of asking "what is
// reachable from this compromised node/edge/flow/data element, per the
// graph's own already-scanned evidence." NOT a DataFlowGraph v1 entity,
// mirrors recipient-profile.js's/scenario.js's own contract shape
// exactly (structural-only {valid, errors} validator, zero graph
// access at construction time).
//
// See docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-blast-radius-impact-scoping.md
// for the full design reasoning, including why there is no
// affectedObligationIds field (ObligationMapping records are built on
// demand per compliance framework, not stored on the graph) and why
// `scope` is always 'possible' today (no runtime-corroboration layer
// exists yet).

export const IMPACT_VERSION = '1.0.0';

export const IMPACT_TARGET_KINDS = Object.freeze(['node', 'edge', 'flow', 'dataElement']);

// 'possible' is the only value any producer emits today — 'observed'
// is reserved for a future Digital Twin (M5 #7) increment with a real
// runtime-corroboration signal. Both are valid schema values now so
// that increment needs no breaking change to this contract later.
export const IMPACT_SCOPE_VALUES = Object.freeze(['possible', 'observed']);

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }

/**
 * Structural validation only — mirrors validateRecipientProfile's/
 * validateScenario's own {valid, errors} shape and "never throws"
 * contract.
 */
export function validateImpactAssessment(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'ImpactAssessment record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('impact:')) {
    err('$.id', 'id is required and must start with "impact:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.targetId)) err('$.targetId', 'targetId is required');
  if (!IMPACT_TARGET_KINDS.includes(record.targetKind)) {
    err('$.targetKind', `targetKind must be one of ${IMPACT_TARGET_KINDS.join('|')}`);
  }
  if (!IMPACT_SCOPE_VALUES.includes(record.scope)) {
    err('$.scope', `scope must be one of ${IMPACT_SCOPE_VALUES.join('|')}`);
  }
  if (!_isStringArray(record.affectedNodeIds ?? [])) err('$.affectedNodeIds', 'affectedNodeIds must be an array of strings');
  if (!_isStringArray(record.affectedEdgeIds ?? [])) err('$.affectedEdgeIds', 'affectedEdgeIds must be an array of strings');
  if (!_isStringArray(record.affectedDataClasses ?? [])) err('$.affectedDataClasses', 'affectedDataClasses must be an array of strings');
  if (!_isStringArray(record.affectedRecipientProfileIds ?? [])) err('$.affectedRecipientProfileIds', 'affectedRecipientProfileIds must be an array of strings');
  if (!_isStringArray(record.coverageLimitations ?? [])) err('$.coverageLimitations', 'coverageLimitations must be an array of strings');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  return { valid: errors.length === 0, errors };
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/impact-assessment.test.js`
Expected: PASS, all 5 tests.

- [ ] **Step 6: Write failing tests for `impact-engine.js`**

Create `scanner/test/lineage/impact-engine.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeImpactAssessment } from '../../src/lineage/impact-engine.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input' },
      { id: 'node:mid', kind: 'process', subtype: null },
      { id: 'node:sink', kind: 'sink', subtype: 'external-api' },
      { id: 'node:orphan', kind: 'sink', subtype: 'log' },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:mid', relationship: 'flows_to' },
      { id: 'edge:2', from: 'node:mid', to: 'node:sink', relationship: 'flows_to' },
    ],
    dataElements: [
      { id: 'de:1', name: 'email', dataClasses: ['PII'] },
      { id: 'de:2', name: 'ssn', dataClasses: ['PII', 'CONFIDENTIAL'] },
    ],
    flows: [
      { id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
      { id: 'flow:2', dataElementIds: ['de:2'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
    ],
    recipientProfiles: [
      { id: 'recipient:vendor', provider: 'vendor', contributingGraphIds: ['node:sink'] },
      { id: 'recipient:unrelated', provider: 'other', contributingGraphIds: ['node:orphan'] },
    ],
    coverage: { languages: [
      { language: 'js', tier: 'partial', filesAnalyzed: 5, filesExpected: 5 },
      { language: 'python', tier: 'pattern-only', filesAnalyzed: 2, filesExpected: 2 },
    ] },
  };
}

test('computeImpactAssessment from a node target: affected set includes every downstream/upstream node and edge', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:mid');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
  assert.deepEqual([...record.affectedEdgeIds].sort(), ['edge:1', 'edge:2']);
  assert.equal(record.targetKind, 'node');
  assert.equal(record.scope, 'possible');
});

test('computeImpactAssessment: affectedDataClasses is the deduplicated union of every flow touching the affected edges', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.deepEqual([...record.affectedDataClasses].sort(), ['CONFIDENTIAL', 'PII']);
});

test('computeImpactAssessment: affectedRecipientProfileIds filters by contributingGraphIds intersection, excluding unrelated profiles', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, ['recipient:vendor']);
});

test('computeImpactAssessment: an edge target resolves to its own from/to nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'edge:2');
  assert.equal(record.targetKind, 'edge');
  assert.ok(record.affectedNodeIds.includes('node:mid'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
});

test('computeImpactAssessment: a flow target resolves to its own source/sink nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'flow:1');
  assert.equal(record.targetKind, 'flow');
  assert.ok(record.affectedNodeIds.includes('node:source'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
});

test('computeImpactAssessment: a dataElement target resolves to every node touched by any flow carrying it', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'de:2');
  assert.equal(record.targetKind, 'dataElement');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
});

test('computeImpactAssessment: a well-formed but non-existent target id degrades honestly to empty arrays, never throws', () => {
  assert.doesNotThrow(() => computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist'));
  const record = computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist');
  assert.deepEqual(record.affectedNodeIds, []);
  assert.deepEqual(record.affectedEdgeIds, []);
  assert.deepEqual(record.affectedDataClasses, []);
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: throws on a malformed targetId (no recognized prefix)', () => {
  assert.throws(() => computeImpactAssessment(_fixtureGraph(), 'not-a-real-prefix:x'));
});

test('computeImpactAssessment: coverageLimitations reports every non-full-tier language, whole-graph', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.equal(record.coverageLimitations.length, 2);
  assert.ok(record.coverageLimitations.some((s) => s.includes('js') && s.includes('partial')));
  assert.ok(record.coverageLimitations.some((s) => s.includes('python') && s.includes('pattern-only')));
});

test('computeImpactAssessment: graph.recipientProfiles absent degrades to empty array, never an error', () => {
  const graph = _fixtureGraph();
  delete graph.recipientProfiles;
  const record = computeImpactAssessment(graph, 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: id, graphId, graphDigest, generatedAt are all real, non-placeholder values', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.match(record.id, /^impact:[0-9a-f]+$/);
  assert.equal(record.graphId, 'graph:abc');
  assert.ok(record.graphDigest.length > 0);
  assert.ok(record.generatedAt.length > 0);
});
```

- [ ] **Step 7: Run to verify failure**

Run: `cd scanner && node --test test/lineage/impact-engine.test.js`
Expected: FAIL — module not found.

- [ ] **Step 8: Write `impact-engine.js`**

Create `scanner/src/lineage/impact-engine.js`:

```js
// impact-engine.js — M5 deliverable #4 (FR-507): the pure read/
// aggregate computation behind "assess impact" from a compromised
// node/edge/flow/data element. Reuses the already-shipped, already-
// tested BFS traversal in frontend/src/lib/focus-controls.js — the
// established scanner/src/ -> frontend/src/ cross-import precedent
// (export-privacy.js's own computePrivacyViewModel import). No
// mutation, no hypothesis, no re-run of the taint/path pipeline — a
// pure filter/aggregate over the graph's own already-computed fields.

import { showAllPaths } from '../../../frontend/src/lib/focus-controls.js';
import { computeGraphDigest } from './export-json.js';
import { impactAssessmentId } from './ids.js';
import { IMPACT_VERSION } from './impact-assessment.js';

const _KIND_PREFIXES = Object.freeze({ node: 'node:', edge: 'edge:', flow: 'flow:', dataElement: 'de:' });

function _resolveTargetKind(targetId) {
  if (typeof targetId !== 'string') return null;
  for (const [kind, prefix] of Object.entries(_KIND_PREFIXES)) {
    if (targetId.startsWith(prefix)) return kind;
  }
  return null;
}

// Every node id a target resolves to, as the seed set for showAllPaths.
// A node target is itself; an edge target is its own from/to; a flow
// target is its own source/sink; a dataElement target is every node any
// flow carrying that data element touches (source/sink, since a flow's
// own intermediate hops aren't separately recorded on the flow object).
function _seedNodeIds(graph, targetId, targetKind) {
  if (targetKind === 'node') return [targetId];
  if (targetKind === 'edge') {
    const edge = (graph.edges ?? []).find((e) => e.id === targetId);
    return edge ? [edge.from, edge.to] : [];
  }
  if (targetKind === 'flow') {
    const flow = (graph.flows ?? []).find((f) => f.id === targetId);
    return flow ? [flow.source, flow.sink] : [];
  }
  if (targetKind === 'dataElement') {
    const ids = new Set();
    for (const f of graph.flows ?? []) {
      if (f.dataElementIds?.includes(targetId)) { ids.add(f.source); ids.add(f.sink); }
    }
    return [...ids];
  }
  return [];
}

function _affectedDataClasses(graph, affectedEdgeIds) {
  const classes = new Set();
  for (const f of graph.flows ?? []) {
    if (!(f.edgeIds ?? []).some((id) => affectedEdgeIds.has(id))) continue;
    for (const deId of f.dataElementIds ?? []) {
      const de = (graph.dataElements ?? []).find((d) => d.id === deId);
      for (const c of de?.dataClasses ?? []) classes.add(c);
    }
  }
  return [...classes].sort();
}

function _affectedRecipientProfileIds(graph, affectedNodeIds) {
  return (graph.recipientProfiles ?? [])
    .filter((rp) => (rp.contributingGraphIds ?? []).some((id) => affectedNodeIds.has(id)))
    .map((rp) => rp.id)
    .sort();
}

// Whole-graph, not scoped to the affected subgraph — no node carries a
// language field to filter by, so a per-language coverage gap is
// reported as a real, honest limitation on any assessment computed
// over this graph, not narrowed to the exact affected nodes. See this
// sub-project's own implementation plan for the full disclosed
// reasoning.
function _coverageLimitations(graph) {
  return (graph.coverage?.languages ?? [])
    .filter((l) => l.tier && l.tier !== 'full')
    .map((l) => `${l.language}: coverage tier '${l.tier}'${typeof l.irTaintRecallPct === 'number' ? ` (${l.irTaintRecallPct}% measured recall)` : ''}`);
}

/**
 * Compute an ImpactAssessment for `targetId` over `graph`. Throws only
 * when `targetId` has no recognized canonical-id prefix (a genuine
 * caller error, not a missing-entity case). A well-formed targetId
 * that does not exist in the graph degrades honestly to empty
 * affected-* arrays, never an error — mirrors applyScenario's own
 * skip-not-throw contract for a stale/missing target.
 */
export function computeImpactAssessment(graph, targetId, opts = {}) {
  const targetKind = _resolveTargetKind(targetId);
  if (!targetKind) {
    throw new Error(`computeImpactAssessment: targetId "${targetId}" has no recognized prefix (expected one of node:/edge:/flow:/de:)`);
  }

  const seedNodeIds = _seedNodeIds(graph, targetId, targetKind);
  const affectedNodeIds = new Set();
  const affectedEdgeIds = new Set();
  for (const seedId of seedNodeIds) {
    const { nodeIds, edgeIds } = showAllPaths(graph, seedId);
    for (const id of nodeIds) affectedNodeIds.add(id);
    for (const id of edgeIds) affectedEdgeIds.add(id);
  }

  const graphDigest = computeGraphDigest(graph);
  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  return {
    id: impactAssessmentId({ graphId: graph.graphId, graphDigest, targetId }, [generatedAt]),
    version: IMPACT_VERSION,
    graphId: graph.graphId,
    graphDigest,
    targetId,
    targetKind,
    scope: 'possible',
    affectedNodeIds: [...affectedNodeIds].sort(),
    affectedEdgeIds: [...affectedEdgeIds].sort(),
    affectedDataClasses: _affectedDataClasses(graph, affectedEdgeIds),
    affectedRecipientProfileIds: _affectedRecipientProfileIds(graph, affectedNodeIds),
    coverageLimitations: _coverageLimitations(graph),
    generatedAt,
  };
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/impact-engine.test.js`
Expected: PASS, all 11 tests.

- [ ] **Step 10: Add both new test files to the `test:lineage` script wiring**

Edit `scanner/package.json`'s `test:lineage` script — append
` test/lineage/impact-assessment.test.js
test/lineage/impact-engine.test.js`.

- [ ] **Step 11: Run the full lineage suite to confirm no regression**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures.

- [ ] **Step 12: Commit**

```bash
git add scanner/src/lineage/impact-assessment.js scanner/src/lineage/impact-engine.js scanner/src/lineage/ids.js scanner/test/lineage/impact-assessment.test.js scanner/test/lineage/impact-engine.test.js scanner/package.json
git commit -m "feat(lineage): add the ImpactAssessment extension contract and computeImpactAssessment"
```

---

### Task 2: CLI wiring (`dataflow impact assess`) + docs

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/dataflow.md`
- Modify: `scanner/src/lineage/CLAUDE.md`
- Test: `scanner/test/server/dataflow-impact-cli.test.js` (new)
- Modify: `scanner/package.json`

**Interfaces:**
- Consumes: `computeImpactAssessment` (Task 1), `validateImpactAssessment`
  (Task 1), `loadSignedGraph` (`src/server/graph-loader.js`, already
  shipped).
- Produces: `agentic-security dataflow impact assess [path] --target
  <canonical-id> --output <file> [--format json|markdown]`. Exit
  codes: `0` success, `1` graph-load failure (the same 4 messages
  `loadSignedGraph` already produces), `2` a CLI argument problem
  (missing `--target`/`--output`, or a `--target` with no recognized
  canonical-id prefix).

- [ ] **Step 1: Write the failing CLI test**

Create `scanner/test/server/dataflow-impact-cli.test.js`. The fixture
helper is copied from `test/server/cmd-dataflow-export.test.js`'s own
`_writeSignedGraph` pattern (`statePath` + `signLastScan` — the
established real-fixture-signing convention this test area uses,
confirmed in the M5 What-If Simulator sub-project's own Task 4), with
one real recipient profile added so `--target` has something to
aggregate:

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-dataflow-impact-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-dataflow-impact-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [
        { id: 'node:source', kind: 'source', subtype: 'user-input' },
        { id: 'node:sink', kind: 'sink', subtype: 'external-api' },
      ],
      edges: [{ id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to' }],
      dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
      transformations: [],
      flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
      recipientProfiles: [{ id: 'recipient:vendor', provider: 'vendor', contributingGraphIds: ['node:sink'] }],
      controls: [], policies: [], evidence: [],
      coverage: { languages: [{ language: 'js', tier: 'partial', filesAnalyzed: 1, filesExpected: 1 }] },
      limitations: [], extensions: {},
    },
    null, 2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

test('dataflow impact assess: writes a JSON assessment and exits 0', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'impact.json');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', outFile, '--format', 'json'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.ok(report.affectedNodeIds.includes('node:sink'));
  assert.deepEqual(report.affectedRecipientProfileIds, ['recipient:vendor']);
  assert.equal(report.scope, 'possible');
});

test('dataflow impact assess: --format markdown writes a real Markdown report', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const outFile = path.join(root, 'impact.md');
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', outFile, '--format', 'markdown'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Impact assessment/);
  assert.match(md, /node:sink/);
});

test('dataflow impact assess: a malformed --target (no recognized prefix) exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'bogus-id', '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /recognized/);
});

test('dataflow impact assess: missing --target exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow impact assess: missing --output exits 2', () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

test('dataflow impact assess: missing graph -> exit 1, one of loadSignedGraph\'s own messages', () => {
  const root = _mkTmpProject();
  const r = spawnSync(process.execPath, [CLI, 'dataflow', 'impact', 'assess', root, '--target', 'node:source', '--output', path.join(root, 'out.json')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/server/dataflow-impact-cli.test.js`
Expected: FAIL — `dataflow impact` is not a recognized subcommand yet.

- [ ] **Step 3: Add the CLI handler**

In `scanner/bin/agentic-security.js`, find `async function
cmdDataflowScenarioApply` (the M5 What-If Simulator sub-project's own
CLI handler) and add a new function directly after it:

```js
// agentic-security dataflow impact assess [path] --target <canonical-id>
// --output <file> [--format json|markdown] — M5 deliverable #4
// (FR-507). Loads the already-scanned, already-signed graph via
// loadSignedGraph (same loader/error-message contract as every other
// dataflow subcommand), computes an ImpactAssessment via
// computeImpactAssessment, writes it to --output. Exit codes: 0
// success, 1 graph-load failure (loadSignedGraph's own 4 messages), 2
// argument problem.
async function cmdDataflowImpactAssess(args) {
  const target = args._[3] || '.'; // args._ = ['dataflow', 'impact', 'assess', <path>?]
  const targetAbs = path.resolve(target);

  const targetIdFlag = args.flags.target;
  if (!targetIdFlag || typeof targetIdFlag !== 'string') {
    process.stderr.write('agentic-security dataflow impact assess: --target <canonical-id> is required.\n');
    return 2;
  }
  const outputPath = args.flags.output;
  if (!outputPath || typeof outputPath !== 'string') {
    process.stderr.write('agentic-security dataflow impact assess: --output <file> is required.\n');
    return 2;
  }
  const format = args.flags.format ?? 'json';
  if (format !== 'json' && format !== 'markdown') {
    process.stderr.write(`agentic-security dataflow impact assess: --format must be one of json|markdown (got ${JSON.stringify(format)}).\n`);
    return 2;
  }

  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const loaded = loadSignedGraph(targetAbs);
  if (!loaded.ok) {
    process.stderr.write(`agentic-security dataflow impact assess: ${loaded.message}\n`);
    return 1;
  }

  const { computeImpactAssessment } = await import('../src/lineage/impact-engine.js');
  let record;
  try {
    record = computeImpactAssessment(loaded.graph, targetIdFlag);
  } catch (e) {
    process.stderr.write(`agentic-security dataflow impact assess: ${e && e.message ? e.message : e}\n`);
    return 2;
  }

  let data;
  if (format === 'json') {
    data = JSON.stringify(record, null, 2);
  } else {
    const lines = [
      `# Impact assessment`, '',
      `Target: \`${record.targetId}\` (${record.targetKind})`,
      `Scope: ${record.scope}`, '',
      `## Affected nodes (${record.affectedNodeIds.length})`, '',
      ...record.affectedNodeIds.map((id) => `- ${id}`), '',
      `## Affected edges (${record.affectedEdgeIds.length})`, '',
      ...record.affectedEdgeIds.map((id) => `- ${id}`), '',
      `## Affected data classes`, '',
      record.affectedDataClasses.length ? record.affectedDataClasses.map((c) => `- ${c}`).join('\n') : '_none_', '',
      `## Affected recipients`, '',
      record.affectedRecipientProfileIds.length ? record.affectedRecipientProfileIds.map((id) => `- ${id}`).join('\n') : '_none_', '',
    ];
    if (record.coverageLimitations.length) {
      lines.push('## Coverage limitations', '', ...record.coverageLimitations.map((s) => `- ${s}`), '');
    }
    data = lines.join('\n') + '\n';
  }
  try {
    await fsp.mkdir(path.dirname(path.resolve(outputPath)), { recursive: true });
    await fsp.writeFile(path.resolve(outputPath), data);
  } catch (e) {
    process.stderr.write(`agentic-security dataflow impact assess: could not write --output "${outputPath}": ${e && e.message ? e.message : e}\n`);
    return 2;
  }
  return 0;
}
```

- [ ] **Step 4: Wire the subcommand dispatch**

Find the `else if (sub === 'scenario') { ... }` block in the `dataflow`
case's own dispatch chain (search for `agentic-security dataflow
scenario: unrecognized sub-command`) and add an `impact` branch as a
sibling, immediately after it, before the final fallback
`unknown subcommand` line:

```js
        else if (sub === 'impact') {
          const impactSub = args._[2];
          if (impactSub === 'assess') { process.exit(await cmdDataflowImpactAssess(args)); }
          else {
            process.stderr.write(`agentic-security dataflow impact: unrecognized sub-command "${impactSub}" — must be "assess".\n`);
            process.exit(2);
          }
        }
```

Then update the final fallback line (the one ending "...are supported")
to also name `"impact"` as a 5th real subcommand, exactly the same kind
of edit the What-If Simulator sub-project's own Task 4 made for
`"scenario"` — find the exact current wording by running `grep -n
"unknown subcommand" bin/agentic-security.js` first, since this file
changes between sub-projects and the plan text must not silently
overwrite an unrelated addition.

- [ ] **Step 5: Update the pre-existing "unknown subcommand" test**

Find the test asserting the "unknown subcommand" message's exact wording
(search `test/cli/dataflow-watch.test.js` for `unknown subcommand`,
following the exact precedent the What-If Simulator sub-project's own
final-review fix round already established for adding `"scenario"`) and
update its expected regex to also include `"impact"` in the list.

- [ ] **Step 6: Update the dataflow help text**

Find the `dataflow scenario apply [path] ...` help line (search for
`dataflow scenario apply`) and add a sibling line directly after it:

```
  dataflow impact assess [path] --target <canonical-id> --output <file> [--format json|markdown]
```

- [ ] **Step 7: Run the CLI test**

Run: `cd scanner && node --test test/server/dataflow-impact-cli.test.js`
Expected: PASS, all 6 tests.

- [ ] **Step 8: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: exit 0. Confirm via `git status` on the WHOLE `dist/`
directory (never a targeted grep of only `dist/agentic-security.mjs` —
per this session's own established, twice-proven gotcha, ncc may chunk
a dynamically-imported subtree into a separate numbered file).

- [ ] **Step 9: Add a module-boundary test asserting no obligation/decision-story wiring**

Create `scanner/test/lineage/impact-no-obligation-wiring.test.js`,
mirroring `scenario-no-obligation-wiring.test.js`'s own exact shape:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LINEAGE_DIR = path.join(__dirname, '../../src/lineage');

test('obligation-mapping.js, obligation-predicates.js, and decision-story.js never import impact-assessment.js or impact-engine.js', () => {
  for (const file of ['obligation-mapping.js', 'obligation-predicates.js', 'decision-story.js']) {
    const src = fs.readFileSync(path.join(LINEAGE_DIR, file), 'utf8');
    assert.ok(!src.includes("from './impact-assessment.js'"), `${file} must not import impact-assessment.js`);
    assert.ok(!src.includes("from './impact-engine.js'"), `${file} must not import impact-engine.js`);
  }
});
```

Run: `cd scanner && node --test test/lineage/impact-no-obligation-wiring.test.js`
Expected: PASS.

- [ ] **Step 10: Add both new test files to their scoped scripts**

Edit `scanner/package.json` — append
` test/lineage/impact-no-obligation-wiring.test.js` to `test:lineage`,
and append ` test/server/dataflow-impact-cli.test.js` to `test:server`.

- [ ] **Step 11: Update `commands/dataflow.md`**

Add a new section documenting `impact assess`, mirroring the existing
"Data Flow Explorer scenario apply" section's exact format (heading
style, flag table, exit-code paragraph, example commands) — read that
section first and match it, don't invent a new format. State plainly
that this is a read-only computation over the real graph (never
mutates anything), that `scope` is always `'possible'` today (no
runtime-corroboration layer exists to report `'observed'`), and that
`--target` accepts `node:*`/`edge:*`/`flow:*`/`de:*` canonical ids
only.

- [ ] **Step 12: Update `scanner/src/lineage/CLAUDE.md`**

Add a new top-level section "Milestone 5, Blast-Radius: Impact
Assessment (FR-507, deliverable #4) — COMPLETE", mirroring the
existing "Milestone 5, What-If Architecture Simulator" section's own
format (a module table, then prose paragraphs for the load-bearing
design decisions) — covering: the `RecipientProfile`-only aggregation
(no `ObligationMapping` aggregation, and why); `scope` always
`'possible'`; the whole-graph (not subgraph-scoped) coverage
limitations simplification and why; the `frontend/src/lib/
focus-controls.js` cross-import reuse.

- [ ] **Step 13: Run the full test:lineage and test:server suites**

Run: `cd scanner && npm run test:lineage && npm run test:server`
Expected: PASS, 0 failures, both.

- [ ] **Step 14: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: PASS, 0 failures. Capture and read the real exit code
immediately after (`echo $?`) — do not infer success from output
length. If a Chrome-resource-contention-shaped failure appears (a
`cmd-dataflow-export.test.js` or `export-image.test.js` test failing
with a `null`/killed status, unrelated to any file this task touches),
re-run just that file in isolation to confirm it passes alone before
concluding it's pre-existing environmental flakiness rather than a
real regression — this exact pattern was confirmed twice already in
the M5 What-If Simulator sub-project's own Task 4, do not re-litigate
it from scratch, but DO verify it reproduces the same way rather than
assuming.

- [ ] **Step 15: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ commands/dataflow.md scanner/src/lineage/CLAUDE.md scanner/test/server/dataflow-impact-cli.test.js scanner/test/lineage/impact-no-obligation-wiring.test.js scanner/test/cli/dataflow-watch.test.js scanner/package.json
git commit -m "feat(cli): wire dataflow impact assess, docs, and no-obligation-wiring guard"
```

## Final Review Checklist (for the coordinator, not a task)

- Confirm `computeImpactAssessment` never throws on a well-formed but
  non-existent target id (Task 1's own test covers this — re-verify
  the SHIPPED code still does, not just the plan text).
- Confirm the CLI's `--target` validation path is exercised by a real
  malformed-prefix test (Task 2 Step 1), not just Task 1's unit-level
  test — two different layers, both need coverage, matching the M5
  What-If Simulator sub-project's own established pattern.
- Re-run `npm run build` one final time after ALL doc-only edits in
  Task 2 Steps 11-12 land, and check `git status` on the whole `dist/`
  directory — a doc-only edit to `bin/agentic-security.js`'s own help
  text (Step 6) DOES touch bundled source, unlike a `.md`/`CLAUDE.md`
  edit; confirm the rebuild step already covers it before assuming a
  second rebuild is unnecessary.
- Confirm the final "unknown subcommand" fallback message and its own
  pinned test (Task 2 Steps 4-5) stay consistent with EACH OTHER after
  any later edit — this exact class of drift (the message updated but
  not the test, or vice versa) was a real, found-and-fixed defect in
  the M5 What-If Simulator sub-project's own Task 4.
