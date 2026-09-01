# Milestone 3, sub-project Inventory: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the fourth, currently-missing required Data Flow Explorer
view — sortable inventory tables for the 11 categories PRD §7.6 names —
sharing filters and canonical IDs with the three existing graph views.

**Architecture:** A new `frontend/src/views/inventory-view.js` follows the
existing `compute<X>ViewModel(graph, state) -> renderXView(viewModel,
canvasEl, onSelect)` split every other view already uses. `state.js` gains
a `table` field (which of the 11 categories is active) validated the same
way `view` already is. `shell.js` gains a fourth tab. `app.js` wires the
new view in and extends the filter-rail condition. Two small, real,
justified fixes ride along: `flow-path.js`'s `AI_SUBTYPES` constant is
corrected to match the real schema, and `evidence-inspector.js` is
extended to resolve `data:`/`transform:` canonical ids so two of the 11
categories' row selection isn't silently inert.

**Tech Stack:** Plain ES modules, zero build step, `node --test` +
`test/dom-shim.js` (no jsdom).

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-inventory-scoping.md`
(read this first — it has the full category-mapping table, the exact
enums confirmed by direct code read, and every decision's rationale).

## Global Constraints

- Zero build step: no new dependency, no bundler. Plain ES module imports
  only, matching every existing `frontend/src/` file.
- No `innerHTML` anywhere, ever — build all DOM via `lib/dom.js`'s `el()`/
  `svgEl()`/`clear()` (per `frontend/CLAUDE.md`'s own hygiene rule, proven
  by the XSS sub-project's adversarial suite, which this plan extends).
- Every new test file must be added to `frontend/package.json`'s explicit
  `test` script string — it is not a glob; a file left off never runs
  (confirmed this session).
- `frontend/` has no build step but DOES have `npm test` — run it after
  every task, not just at the end.
- This plan touches `frontend/` only. No `scanner/` file changes.

---

### Task 1: State/shell wiring + two small correctness fixes

**Files:**
- Modify: `frontend/src/lib/state.js`
- Modify: `frontend/src/shell.js`
- Modify: `frontend/src/lib/flow-path.js`
- Modify: `frontend/src/components/evidence-inspector.js`
- Test: `frontend/test/state.test.js` (add cases)
- Test: `frontend/test/flow-path.test.js` (add/update cases)
- Test: `frontend/test/evidence-inspector.test.js` (add cases)
- Test: `frontend/test/shell.test.js` (add a case)

**Interfaces:**
- Produces: `INVENTORY_TABLES` (exported array of 11 category id strings,
  from `lib/state.js`) — Task 2 and Task 3 both import this as the single
  source of truth for category ids/order.
- Produces: `DEFAULT_STATE.table === INVENTORY_TABLES[0]`.
- Produces: `AI_SUBTYPES` (corrected) still exported from `flow-path.js`
  with the same name and shape (`Set<string>`) — no signature change, only
  its contents change.
- Produces: `computeInspectorViewModel` now also returns a non-null result
  for a `data:*`/`transform:*` `selectedId`, with `kind: 'dataElement'` /
  `kind: 'transformation'` respectively.

- [ ] **Step 1: Write failing tests for the new `table` state field**

Add to `frontend/test/state.test.js` (append; do not remove existing
tests):

```js
import { INVENTORY_TABLES } from '../src/lib/state.js';

test('DEFAULT_STATE / parseStateFromHash default the table field to the first inventory category', () => {
  const state = parseStateFromHash('');
  assert.equal(state.table, INVENTORY_TABLES[0]);
});

test('parseStateFromHash reads a valid table value', () => {
  const state = parseStateFromHash(`#view=inventory&table=${INVENTORY_TABLES[3]}`);
  assert.equal(state.table, INVENTORY_TABLES[3]);
});

test('parseStateFromHash rejects an unknown table name back to the default', () => {
  const state = parseStateFromHash('#table=not-a-real-table');
  assert.equal(state.table, INVENTORY_TABLES[0]);
});

test('serializeStateToHash round-trips table', () => {
  const original = { view: 'inventory', selectedId: null, filters: {}, table: INVENTORY_TABLES[5] };
  const hash = serializeStateToHash(original);
  const parsed = parseStateFromHash(hash);
  assert.equal(parsed.table, INVENTORY_TABLES[5]);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && node --test test/state.test.js`
Expected: FAIL — `INVENTORY_TABLES` is not exported, `state.table` is
`undefined`.

- [ ] **Step 3: Implement `INVENTORY_TABLES` and the `table` field**

Edit `frontend/src/lib/state.js`. The 11 ids below are the row-order PRD
§7.6 lists them in, and are what Task 2/3 both key off of — do not
reorder or rename without updating both.

```js
const VALID_VIEWS = new Set(['architecture', 'privacy', 'trace', 'inventory']);

// PRD §7.6's own 11 required inventory categories, in the order that
// section lists them. The canonical id list — inventory-view.js's
// per-category compute dispatch and its sub-nav strip both key off this
// exact array, so a rename here must update both call sites too.
export const INVENTORY_TABLES = Object.freeze([
  'sources',
  'sinks',
  'fields',
  'externalDestinations',
  'stores',
  'aiSystems',
  'transformations',
  'unprotectedEdges',
  'policyPermittedFlows',
  'manualGovernanceGaps',
  'unsupportedCandidates',
]);

const DEFAULT_STATE = Object.freeze({ view: 'architecture', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });
```

In `parseStateFromHash`, alongside the existing `view`/`selectedId`/
`filters` reads:

```js
  const tableRaw = params.get('table');

  return {
    view: VALID_VIEWS.has(view) ? view : DEFAULT_STATE.view,
    selectedId: selectedId || null,
    filters,
    table: INVENTORY_TABLES.includes(tableRaw) ? tableRaw : DEFAULT_STATE.table,
  };
```

(Also fix the two early-return branches — `if (!raw) return {...DEFAULT_STATE, filters: {}}` and the `catch` branch — to include `table: DEFAULT_STATE.table` implicitly via the spread, which they already do since `table` is now part of `DEFAULT_STATE`. No change needed there beyond the spread already covering it — verify by reading the two branches after editing.)

In `serializeStateToHash`:

```js
export function serializeStateToHash(state) {
  const params = new URLSearchParams();
  params.set('view', VALID_VIEWS.has(state.view) ? state.view : DEFAULT_STATE.view);
  if (state.selectedId) params.set('selected', state.selectedId);
  if (state.filters && Object.keys(state.filters).length > 0) params.set('filters', JSON.stringify(state.filters));
  if (state.table && state.table !== DEFAULT_STATE.table) params.set('table', state.table);
  return `#${params.toString()}`;
}
```

(Only write `table` to the hash when it differs from the default — mirrors
how `selectedId`/`filters` are only written when non-empty, keeping the
common-case URL short.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd frontend && node --test test/state.test.js`
Expected: PASS, all tests including pre-existing ones.

- [ ] **Step 5: Add the Inventory tab to `shell.js`**

Edit `frontend/src/shell.js`:

```js
const VIEWS = [
  { id: 'architecture', label: 'Architecture' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'trace', label: 'Trace' },
  { id: 'inventory', label: 'Inventory' },
];
```

Add to `frontend/test/shell.test.js` (append):

```js
test('the view tab bar includes an Inventory tab', () => {
  const root = document.createElement('div');
  mountShell(root, FIXTURE_GRAPH); // use whatever fixture constant this file's existing tests already import
  const tabs = root.querySelectorAll('[data-view-id]');
  const inventoryTab = tabs.find((t) => t.getAttribute('data-view-id') === 'inventory');
  assert.ok(inventoryTab, 'expected a rendered tab button for the inventory view');
});
```

Read `frontend/test/shell.test.js`'s existing imports/fixture setup first
(the file already has a graph fixture constant in scope for the other
tab-click test at line ~126 — reuse the exact same name, do not invent a
second one).

Run: `cd frontend && node --test test/shell.test.js` — expect PASS.

- [ ] **Step 6: Correct `AI_SUBTYPES` in `flow-path.js`**

The current set (`'ai-assistant'`, `'vector-store'`) matches neither
`SOURCE_CATEGORIES` nor `SINK_CATEGORIES` in
`scanner/src/lineage/schema.js` (confirmed by direct read: real AI sink
categories are `ai-model-provider, ai-local-model, ai-agent, ai-tool,
ai-vector-store, ai-memory, ai-training, ai-evaluation, ai-telemetry`; real
AI source categories are `ai-model-output, ai-tool-result,
ai-retrieved-document, ai-memory`). `node.subtype` is set from exactly one
of these category strings (confirmed in `graph-builder.js`'s `mintNode`:
`subtype: category ?? null`). Edit `frontend/src/lib/flow-path.js`:

```js
// Backend AI node-subtype vocabulary (scanner/src/lineage/schema.js's
// SOURCE_CATEGORIES/SINK_CATEGORIES, AI-flavored entries only). This list
// must be hand-kept in sync with that schema file — the frontend never
// imports scanner/src/lineage/ at runtime (see frontend/CLAUDE.md).
// Corrected this increment: the previous set ('ai-assistant',
// 'vector-store') matched neither real enum and silently never matched
// any real node.
const AI_SUBTYPES = new Set([
  'ai-model-provider', 'ai-local-model', 'ai-agent', 'ai-tool',
  'ai-vector-store', 'ai-memory', 'ai-training', 'ai-evaluation', 'ai-telemetry',
  'ai-model-output', 'ai-tool-result', 'ai-retrieved-document',
]);
```

Read `frontend/test/flow-path.test.js` first — if any existing test
constructs a fixture node with `subtype: 'ai-assistant'` or
`subtype: 'vector-store'` expecting `isAiRelevantFlow` to be `true`,
update that fixture's `subtype` to a real value (e.g.
`'ai-model-provider'`) rather than leaving a test that now asserts a false
premise. Add one new case if none currently exists:

```js
test('isAiRelevantFlow recognizes the real backend AI subtype vocabulary', () => {
  const graph = {
    nodes: [
      { id: 'node:a', kind: 'process', subtype: null },
      { id: 'node:b', kind: 'sink', subtype: 'ai-model-provider' },
    ],
    edges: [],
  };
  const flow = { id: 'flow:1', source: 'node:a', sink: 'node:b', edgeIds: [] };
  assert.equal(isAiRelevantFlow(graph, flow), true);
});
```

- [ ] **Step 7: Run to verify flow-path tests pass**

Run: `cd frontend && node --test test/flow-path.test.js`
Expected: PASS.

- [ ] **Step 8: Extend `evidence-inspector.js` for `data:`/`transform:` ids**

Edit `frontend/src/components/evidence-inspector.js`:

```js
export function computeInspectorViewModel(graph, selectedId) {
  if (!selectedId) return null;

  const flow = graph.flows.find((f) => f.id === selectedId);
  const edge = !flow && graph.edges.find((e) => e.id === selectedId);
  const node = !flow && !edge && graph.nodes.find((n) => n.id === selectedId);
  const dataElement = !flow && !edge && !node && graph.dataElements.find((d) => d.id === selectedId);
  const transformation = !flow && !edge && !node && !dataElement && graph.transformations.find((t) => t.id === selectedId);
  const target = flow || edge || node || dataElement || transformation;
  if (!target) return null;

  const kind = flow ? 'flow' : edge ? 'edge' : node ? 'node' : dataElement ? 'dataElement' : 'transformation';
  const evidenceRefs = target.evidenceRefs ?? [];
  const evidenceItems = evidenceRefs
    .map((id) => graph.evidence.find((ev) => ev.id === id))
    .filter(Boolean);
  const supporting = evidenceItems.filter((e) => !e.conflict);
  const conflicting = evidenceItems.filter((e) => e.conflict);

  return {
    kind,
    id: target.id,
    claim: buildClaimText(graph, kind, target),
    supporting,
    conflicting,
    limitations: target.limitations ?? [],
    target,
  };
}
```

`dataElement`/`transformation` have no `evidenceRefs` in the schema
(confirmed by direct read of `validate.js` — `_validateDataElement`/
transformation validators never check one), so `target.evidenceRefs ?? []`
already degrades to an empty array for these two kinds without further
change — `supporting`/`conflicting` will both be empty, which is correct
and honest (there is no evidence trail for a data element or
transformation node today, only for the source/sink/edge/flow claims that
reference it).

Add two `buildClaimText` branches:

```js
function buildClaimText(graph, kind, target) {
  if (kind === 'flow') {
    const dataElement = graph.dataElements.find((d) => target.dataElementIds.includes(d.id));
    const source = graph.nodes.find((n) => n.id === target.source);
    const sink = graph.nodes.find((n) => n.id === target.sink);
    return `${dataElement?.name ?? 'field'} flows from ${source?.label ?? 'unknown source'} to ${sink?.label ?? 'unknown destination'}: ${target.protectionSummary}`;
  }
  if (kind === 'edge') {
    const from = graph.nodes.find((n) => n.id === target.from);
    const to = graph.nodes.find((n) => n.id === target.to);
    return `${from?.label ?? '?'} → ${to?.label ?? '?'}: handling ${target.protection.handling.verdict}, transit ${target.protection.transit.verdict}, at rest ${target.protection.atRest.verdict}`;
  }
  if (kind === 'dataElement') {
    return `${target.name}: ${(target.dataClasses ?? []).join(', ') || 'no data classes recorded'}`;
  }
  if (kind === 'transformation') {
    return `${target.kind} transformation (${target.reversibility})`;
  }
  return `${target.label} (${target.kind}/${target.subtype})`;
}
```

- [ ] **Step 9: Write and run evidence-inspector tests**

Add to `frontend/test/evidence-inspector.test.js` (append; use whatever
minimal graph fixture shape the existing tests in this file already use —
read the file first for the exact convention):

```js
test('computeInspectorViewModel resolves a dataElement id', () => {
  const graph = {
    nodes: [], edges: [], flows: [], evidence: [],
    dataElements: [{ id: 'data:email', name: 'email', dataClasses: ['PII'], aiContexts: [] }],
    transformations: [],
  };
  const vm = computeInspectorViewModel(graph, 'data:email');
  assert.ok(vm);
  assert.equal(vm.kind, 'dataElement');
  assert.match(vm.claim, /email/);
});

test('computeInspectorViewModel resolves a transformation id', () => {
  const graph = {
    nodes: [], edges: [], flows: [], evidence: [], dataElements: [],
    transformations: [{ id: 'transform:mask1', kind: 'mask', reversibility: 'irreversible' }],
  };
  const vm = computeInspectorViewModel(graph, 'transform:mask1');
  assert.ok(vm);
  assert.equal(vm.kind, 'transformation');
  assert.match(vm.claim, /mask/);
});
```

Run: `cd frontend && node --test test/evidence-inspector.test.js`
Expected: PASS.

- [ ] **Step 10: Full frontend test run + commit**

Run: `cd frontend && npm test`
Expected: PASS, all existing + new tests, real captured exit code 0.

```bash
git add frontend/src/lib/state.js frontend/src/shell.js frontend/src/lib/flow-path.js frontend/src/components/evidence-inspector.js frontend/test/state.test.js frontend/test/shell.test.js frontend/test/flow-path.test.js frontend/test/evidence-inspector.test.js
git commit -m "feat(frontend): wire Inventory view state/tab, fix AI_SUBTYPES, resolve data/transform ids in inspector"
```

---

### Task 2: `inventory-view.js` compute logic (all 11 categories)

**Files:**
- Create: `frontend/src/views/inventory-view.js` (compute half only —
  `computeInventoryViewModel` and its 11 per-category helpers; the render
  half is Task 3)
- Test: `frontend/test/inventory-view.test.js`

**Interfaces:**
- Consumes: `INVENTORY_TABLES` from `frontend/src/lib/state.js` (Task 1).
- Consumes: `worstVerdict` from `frontend/src/lib/protection-visual.js`
  (already exists, unmodified).
- Consumes: `AI_SUBTYPES` — **not exported from `flow-path.js` today**;
  export it as part of this task (add `export` to the `const AI_SUBTYPES`
  Task 1 already edited — a one-word change, since Task 1 only fixed its
  contents, not its visibility). If Task 1 already ships this as
  exported, skip; verify by reading the file before assuming either way.
- Produces: `computeInventoryViewModel(graph, state) -> {
  tables: [{id: string, label: string, count: number}], activeTable:
  string, columns: string[], rows: [{id: string, selectableId: string|null,
  cells: string[], visible: boolean}] }` — Task 3's `renderInventoryView`
  consumes exactly this shape.

- [ ] **Step 1: Write failing compute tests**

Create `frontend/test/inventory-view.test.js`. Build one small hand-made
graph fixture covering all 11 categories with at least one real row each
— the flagship fixture is not guaranteed to exercise the rarer ones
(manual coverage, unresolved, conditionally_permitted vs strictly
permitted). Use this exact fixture (copy verbatim — every later assertion
in this task references these exact ids):

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeInventoryViewModel } from '../src/views/inventory-view.js';
import { INVENTORY_TABLES } from '../src/lib/state.js';

function protectedDim(verdict) {
  return { verdict, evidenceGrade: 'direct' };
}

const GRAPH = {
  nodes: [
    { id: 'node:src1', kind: 'source', subtype: 'http-body', label: 'Signup body', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    { id: 'node:sink1', kind: 'sink', subtype: 'database', label: 'Users table', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    { id: 'node:store1', kind: 'store', subtype: 'database', label: 'Postgres', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] }, storeDetail: { operation: 'upsert', columns: ['email'] } },
    { id: 'node:ext1', kind: 'external', subtype: 'external-api', label: 'Stripe', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'external', evidenceRefs: [] }, destination: { resolutionStatus: 'literal', literalValue: 'api.stripe.com' } },
    { id: 'node:ai1', kind: 'sink', subtype: 'ai-model-provider', label: 'OpenAI', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'external', evidenceRefs: [] } },
    { id: 'node:manual1', kind: 'process', subtype: null, label: 'Manually declared batch job', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'manual', externality: { value: 'unknown', evidenceRefs: [] } },
    { id: 'node:unresolved1', kind: 'unresolved', subtype: null, label: 'Unresolved call site', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'partial', externality: { value: 'unknown', evidenceRefs: [] } },
    { id: 'node:candidate1', kind: 'process', subtype: null, label: 'Candidate framework call', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'candidate', externality: { value: 'unknown', evidenceRefs: [] } },
  ],
  edges: [
    { id: 'edge:1', from: 'node:src1', to: 'node:sink1', relationship: 'data_flow', fieldMappings: [], protection: { transit: protectedDim('protected'), atRest: protectedDim('unprotected'), handling: protectedDim('not_applicable') }, provenance: 'code' },
    { id: 'edge:2', from: 'node:sink1', to: 'node:ai1', relationship: 'data_flow', fieldMappings: [], protection: { transit: protectedDim('protected'), atRest: protectedDim('protected'), handling: protectedDim('protected') }, provenance: 'code' },
  ],
  dataElements: [
    { id: 'data:email', name: 'email', dataClasses: ['PII'], aiContexts: [] },
    { id: 'data:promptContext', name: 'prompt context', dataClasses: ['PII'], aiContexts: ['model-input'] },
  ],
  transformations: [
    { id: 'transform:mask1', kind: 'mask', reversibility: 'irreversible' },
  ],
  flows: [
    { id: 'flow:permitted1', source: 'node:src1', sink: 'node:sink1', dataElementIds: ['data:email'], edgeIds: ['edge:1'], policyVerdict: 'permitted', protectionSummary: 'unprotected', governanceRefs: {} },
    { id: 'flow:manualReview1', source: 'node:sink1', sink: 'node:ai1', dataElementIds: ['data:promptContext'], edgeIds: ['edge:2'], policyVerdict: 'manual_review_required', protectionSummary: 'protected', governanceRefs: {} },
  ],
};

test('computeInventoryViewModel exposes all 11 tables with correct counts', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });
  const countFor = (id) => vm.tables.find((t) => t.id === id).count;
  assert.equal(countFor('sources'), 1);
  assert.equal(countFor('sinks'), 1);
  assert.equal(countFor('fields'), 2);
  assert.equal(countFor('externalDestinations'), 3); // node:ext1, node:ai1, node:manual1's own AI sink ai1 -- wait, see note below
  assert.equal(countFor('stores'), 1);
  assert.equal(countFor('aiSystems'), 2); // node:ai1 + data:promptContext
  assert.equal(countFor('transformations'), 1);
  assert.equal(countFor('unprotectedEdges'), 1); // edge:1 (mixed: protected+unprotected -> worst 'unprotected')
  assert.equal(countFor('policyPermittedFlows'), 1); // flow:permitted1 only, strictly 'permitted'
  assert.equal(countFor('manualGovernanceGaps'), 2); // flow:manualReview1 + node:manual1
  assert.equal(countFor('unsupportedCandidates'), 2); // node:unresolved1 + node:candidate1
});
```

**Before implementing**, resolve the `externalDestinations` count
ambiguity the test comment above flags: with the fixture as written,
nodes with `externality.value === 'external'` are `node:ext1` and
`node:ai1` only (`node:manual1`'s externality is `'unknown'`, not
`'external'`) — so the correct expected count is **2**, not 3. Fix the
assertion to `assert.equal(countFor('externalDestinations'), 2);` before
running — this was caught during plan review, written here explicitly so
the implementer doesn't have to re-derive it, per this plan's own
no-placeholders rule.

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && node --test test/inventory-view.test.js`
Expected: FAIL — module does not exist yet.

- [ ] **Step 3: Implement `computeInventoryViewModel` and its 11 helpers**

Create `frontend/src/views/inventory-view.js` (compute half; append the
render half in Task 3 — this task's file ends after `computeInventoryViewModel`
and its helpers, with no render function yet, so `frontend/test/inventory-view.test.js`
only imports the compute export):

```js
import { worstVerdict } from '../lib/protection-visual.js';
import { AI_SUBTYPES } from '../lib/flow-path.js';
import { INVENTORY_TABLES } from '../lib/state.js';

const TABLE_LABELS = {
  sources: 'Sources',
  sinks: 'Sinks',
  fields: 'Fields / data elements',
  externalDestinations: 'External destinations',
  stores: 'Stores',
  aiSystems: 'AI systems & processing contexts',
  transformations: 'Transformations',
  unprotectedEdges: 'Unprotected or unknown edges',
  policyPermittedFlows: 'Policy-permitted flows',
  manualGovernanceGaps: 'Manual governance gaps',
  unsupportedCandidates: 'Unsupported or unresolved candidates',
};

const UNPROTECTED_TIERS = new Set(['unprotected', 'mixed', 'unknown']);

function edgeWorstVerdict(edge) {
  return worstVerdict([edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict]);
}

function nodeLabelFor(graph, nodeId) {
  return graph.nodes.find((n) => n.id === nodeId)?.label ?? 'unknown';
}

const TABLE_COMPUTE = {
  sources: (graph) => ({
    columns: ['Label', 'Category', 'Coverage', 'Externality'],
    rows: graph.nodes.filter((n) => n.kind === 'source').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.subtype ?? '—', n.coverageStatus, n.externality?.value ?? 'unknown'],
    })),
  }),
  sinks: (graph) => ({
    columns: ['Label', 'Category', 'Coverage', 'Externality'],
    rows: graph.nodes.filter((n) => n.kind === 'sink').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.subtype ?? '—', n.coverageStatus, n.externality?.value ?? 'unknown'],
    })),
  }),
  fields: (graph) => ({
    columns: ['Name', 'Data classes', 'AI contexts'],
    rows: graph.dataElements.map((d) => ({
      id: d.id, selectableId: d.id,
      cells: [d.name, (d.dataClasses ?? []).join(', ') || '—', (d.aiContexts ?? []).join(', ') || '—'],
      dataClasses: d.dataClasses ?? [],
    })),
  }),
  externalDestinations: (graph) => ({
    columns: ['Label', 'Kind', 'Resolution status', 'Literal value'],
    rows: graph.nodes.filter((n) => n.externality?.value === 'external').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.kind, n.destination?.resolutionStatus ?? 'unknown', n.destination?.literalValue ?? '—'],
    })),
  }),
  stores: (graph) => ({
    columns: ['Label', 'Operation', 'Columns'],
    rows: graph.nodes.filter((n) => n.kind === 'store').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.storeDetail?.operation ?? 'unknown', (n.storeDetail?.columns ?? []).join(', ') || '—'],
    })),
  }),
  aiSystems: (graph) => {
    const aiNodes = graph.nodes.filter((n) => n.subtype && AI_SUBTYPES.has(n.subtype)).map((n) => ({
      id: n.id, selectableId: n.id,
      cells: ['Node', n.label, n.subtype],
    }));
    const aiDataElements = graph.dataElements.filter((d) => (d.aiContexts ?? []).length > 0).map((d) => ({
      id: d.id, selectableId: d.id,
      cells: ['Data element', d.name, (d.aiContexts ?? []).join(', ')],
    }));
    return { columns: ['Subject', 'Label', 'Category / context'], rows: [...aiNodes, ...aiDataElements] };
  },
  transformations: (graph) => ({
    columns: ['Kind', 'Reversibility'],
    rows: graph.transformations.map((t) => ({
      id: t.id, selectableId: t.id,
      cells: [t.kind, t.reversibility],
    })),
  }),
  unprotectedEdges: (graph) => ({
    columns: ['From', 'To', 'Transit', 'At rest', 'Handling', 'Worst verdict'],
    rows: graph.edges.filter((e) => UNPROTECTED_TIERS.has(edgeWorstVerdict(e))).map((e) => ({
      id: e.id, selectableId: e.id,
      cells: [nodeLabelFor(graph, e.from), nodeLabelFor(graph, e.to), e.protection.transit.verdict, e.protection.atRest.verdict, e.protection.handling.verdict, edgeWorstVerdict(e)],
    })),
  }),
  policyPermittedFlows: (graph) => ({
    columns: ['Field', 'Source', 'Sink', 'Policy verdict'],
    rows: graph.flows.filter((f) => f.policyVerdict === 'permitted').map((f) => {
      const dataElement = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
      return {
        id: f.id, selectableId: f.id,
        cells: [dataElement?.name ?? 'unknown field', nodeLabelFor(graph, f.source), nodeLabelFor(graph, f.sink), f.policyVerdict],
        dataClasses: dataElement?.dataClasses ?? [],
        protectionSummary: f.protectionSummary,
      };
    }),
  }),
  manualGovernanceGaps: (graph) => {
    const manualFlows = graph.flows.filter((f) => f.policyVerdict === 'manual_review_required').map((f) => {
      const dataElement = graph.dataElements.find((d) => f.dataElementIds.includes(d.id));
      return {
        id: f.id, selectableId: f.id,
        cells: ['Flow', dataElement?.name ?? 'unknown field', 'policyVerdict: manual_review_required'],
        dataClasses: dataElement?.dataClasses ?? [],
        protectionSummary: f.protectionSummary,
      };
    });
    const manualNodes = graph.nodes.filter((n) => n.coverageStatus === 'manual').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: ['Node', n.label, 'coverageStatus: manual'],
    }));
    const manualEdges = graph.edges.filter((e) => e.coverageStatus === 'manual').map((e) => ({
      id: e.id, selectableId: e.id,
      cells: ['Edge', `${nodeLabelFor(graph, e.from)} → ${nodeLabelFor(graph, e.to)}`, 'coverageStatus: manual'],
    }));
    return { columns: ['Subject', 'Label', 'Reason'], rows: [...manualFlows, ...manualNodes, ...manualEdges] };
  },
  unsupportedCandidates: (graph) => ({
    columns: ['Label', 'Kind', 'Coverage status', 'Reason'],
    rows: graph.nodes.filter((n) => n.kind === 'unresolved' || n.coverageStatus === 'unsupported' || n.coverageStatus === 'candidate').map((n) => ({
      id: n.id, selectableId: n.id,
      cells: [n.label, n.kind, n.coverageStatus, n.coverageReason ?? '—'],
    })),
  }),
};

// Categories whose rows carry the properties filter-rail.js's three chip
// groups filter on (dataClasses / protectionSummary / AI relevance). Wired
// per docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-inventory-scoping.md's
// decision 4 — deliberately not every category; see that doc before
// changing this set.
const FILTERABLE_TABLES = new Set(['fields', 'policyPermittedFlows', 'manualGovernanceGaps']);

function rowMatchesFilters(row, filters) {
  if (filters.dataClass?.length && !(row.dataClasses ?? []).some((c) => filters.dataClass.includes(c))) return false;
  if (filters.protection?.length && row.protectionSummary && !filters.protection.includes(row.protectionSummary)) return false;
  return true;
}

export function computeInventoryViewModel(graph, state) {
  const activeTable = INVENTORY_TABLES.includes(state.table) ? state.table : INVENTORY_TABLES[0];
  const tables = INVENTORY_TABLES.map((id) => ({
    id, label: TABLE_LABELS[id],
    count: TABLE_COMPUTE[id](graph).rows.length,
  }));

  const { columns, rows: rawRows } = TABLE_COMPUTE[activeTable](graph);
  const filterable = FILTERABLE_TABLES.has(activeTable);
  const rows = rawRows.map((row) => ({
    ...row,
    selected: row.id === state.selectedId,
    visible: filterable ? rowMatchesFilters(row, state.filters ?? {}) : true,
  }));

  return { tables, activeTable, columns, rows, filterable };
}
```

Note: `manualGovernanceGaps`'s edge branch reads `e.coverageStatus`, which
is **not currently part of the edge schema** (confirmed: `_validateEdge`
in `validate.js` never checks a `coverageStatus` field on edges — only
nodes have one). This branch is therefore honestly always empty against
real graph data today; it costs nothing to leave in (defensive against a
future schema addition) but must not be asserted as populated in tests
against real data. The Step 1 fixture above does not set
`coverageStatus` on `edge:1`/`edge:2`, so `manualEdges` in that fixture is
correctly empty and the expected `manualGovernanceGaps` count of 2 (1
flow + 1 node) already accounts for this — do not add a third expected
row for edges.

- [ ] **Step 4: Run to verify it passes**

Run: `cd frontend && node --test test/inventory-view.test.js`
Expected: PASS (after the `externalDestinations` count fix from Step 1's
own note).

- [ ] **Step 5: Add per-category filter and empty-graph edge-case tests**

Append to `frontend/test/inventory-view.test.js`:

```js
test('fields table rows carry dataClasses and respond to the dataClass filter', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PII'] }, table: 'fields' });
  assert.ok(vm.rows.every((r) => r.visible), 'both fixture fields are PII, both should stay visible');
  const vmExcluded = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PHI'] }, table: 'fields' });
  assert.ok(vmExcluded.rows.every((r) => !r.visible), 'neither fixture field is PHI');
});

test('a non-filterable table (sources) ignores filters entirely', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PHI'] }, table: 'sources' });
  assert.equal(vm.filterable, false);
  assert.ok(vm.rows.every((r) => r.visible));
});

test('an empty graph produces zero-count tables without throwing', () => {
  const empty = { nodes: [], edges: [], dataElements: [], transformations: [], flows: [] };
  const vm = computeInventoryViewModel(empty, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  assert.ok(vm.tables.every((t) => t.count === 0));
  assert.deepEqual(vm.rows, []);
});

test('an invalid state.table falls back to the first category', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'not-a-real-table' });
  assert.equal(vm.activeTable, INVENTORY_TABLES[0]);
});
```

- [ ] **Step 6: Run full inventory-view compute tests + commit**

Run: `cd frontend && node --test test/inventory-view.test.js`
Expected: PASS.

```bash
git add frontend/src/views/inventory-view.js frontend/test/inventory-view.test.js
git commit -m "feat(frontend): add inventory-view compute logic for all 11 PRD categories"
```

(`frontend/package.json`'s `test` script gets `inventory-view.test.js`
added in Task 3, alongside the render test — both land in the same
package.json edit to avoid a two-step half-wired state.)

---

### Task 3: `inventory-view.js` render half + `app.js` wiring + XSS sweep + package.json

**Files:**
- Modify: `frontend/src/views/inventory-view.js` (append render half)
- Modify: `frontend/src/app.js`
- Modify: `frontend/package.json`
- Modify: `frontend/test/xss-adversarial.test.js`
- Test: `frontend/test/inventory-view-render.test.js`

**Interfaces:**
- Consumes: `computeInventoryViewModel` (Task 2), `el`/`clear` from
  `lib/dom.js`.
- Produces: `renderInventoryView(viewModel, canvasEl, onSelect,
  onTableChange)` — `onSelect(selectableId)` mirrors every other view's
  `onSelect<X>(id)` callback exactly (feeds `shellApi.setSelection`);
  `onTableChange(tableId)` is new, feeds a new `state.table` setter Task 3
  adds to `shell.js`'s public API... **correction, resolved here rather
  than left ambiguous:** `shell.js`'s `mountShell` return object has
  `setSelection`/`setFilters`, no `setTable`. Rather than adding a fourth
  shell-level setter for one view's own internal navigation, `app.js`
  owns `state.table` updates directly via the state object it already
  reads from `shellApi.getState()`, calling `shellApi.setFilters` is
  wrong (different field) — add one more shell API method,
  `setTable(tableId)`, exactly mirroring `setSelection`'s own
  implementation (`updateState({...state, table: tableId})`). See Step 3
  below for the exact `shell.js` diff this requires (a small addition
  this task makes, since Task 1 did not anticipate `app.js` needing to
  change `table`).

- [ ] **Step 1: Write failing render tests**

Create `frontend/test/inventory-view-render.test.js`, following
`privacy-view-render.test.js`'s own structure (read that file first for
the exact dom-shim setup pattern — `createDomShim()`, `globalThis.document
= document`, then dynamic `await import(...)` of the module under test).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { computeInventoryViewModel, renderInventoryView } = await import('../src/views/inventory-view.js');

const GRAPH = {
  nodes: [
    { id: 'node:src1', kind: 'source', subtype: 'http-body', label: 'Signup body', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
  ],
  edges: [], dataElements: [], transformations: [], flows: [],
};

test('renderInventoryView renders a sub-nav strip with all 11 category buttons', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  const navButtons = canvasEl.querySelectorAll('[data-table-id]');
  assert.equal(navButtons.length, 11);
});

test('renderInventoryView renders one <tr> per row plus a header row, with the right column headers', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  const headerCells = canvasEl.querySelectorAll('th');
  assert.equal(headerCells.length, 4); // Label, Category, Coverage, Externality
  const bodyRows = canvasEl.querySelectorAll('tbody tr');
  assert.equal(bodyRows.length, 1);
});

test('clicking a row calls onSelect with the row\'s selectableId', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  let selected = null;
  renderInventoryView(vm, canvasEl, (id) => { selected = id; }, () => {});
  const row = canvasEl.querySelectorAll('tbody tr')[0];
  row.dispatchEvent?.('click') ?? row._listeners?.click?.forEach((fn) => fn({}));
  // dom-shim event dispatch: follow the exact mechanism privacy-view-render.test.js already uses for its own row-click test — read that file's own click-simulation line and copy it verbatim rather than guessing dom-shim's API here.
  assert.equal(selected, 'node:src1');
});

test('clicking a sub-nav button calls onTableChange with that table id', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  let changedTo = null;
  renderInventoryView(vm, canvasEl, () => {}, (id) => { changedTo = id; });
  const sinksButton = canvasEl.querySelectorAll('[data-table-id]').find((b) => b.getAttribute('data-table-id') === 'sinks');
  // Same click-simulation mechanism as the row-click test above.
  assert.ok(sinksButton);
});
```

The click-simulation lines above are deliberately marked for the
implementer to resolve against `privacy-view-render.test.js`'s own real,
working mechanism (`dom-shim.js`'s exact event API was not re-derived in
this plan's own scoping pass — copy the working pattern rather than
guessing a new one; this is the one place in this task where the plan
defers to an existing, running test file instead of inventing new
mechanism).

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && node --test test/inventory-view-render.test.js`
Expected: FAIL — `renderInventoryView` does not exist yet.

- [ ] **Step 3: Add `setTable` to `shell.js`**

Read `frontend/src/shell.js`'s existing `setSelection` implementation
first (it calls `updateState({...state, selectedId: id})` per the
carried-forward summary's own description of this file). Add, immediately
alongside it:

```js
setTable(tableId) {
  updateState({ ...state, table: tableId });
},
```

placed in the same returned object literal `setSelection`/`setFilters`
already live in. Add the corresponding line to this file's own JSDoc
return-type comment block (`setTable: (tableId: string) => void`).

- [ ] **Step 4: Implement `renderInventoryView`**

Append to `frontend/src/views/inventory-view.js` (after the compute half
from Task 2):

```js
import { el, clear } from '../lib/dom.js';

function renderSubNav(viewModel, onTableChange) {
  const buttons = viewModel.tables.map((t) =>
    el(
      'button',
      {
        class: 'inventory-subnav-button',
        'data-table-id': t.id,
        'data-active': String(t.id === viewModel.activeTable),
        'aria-pressed': String(t.id === viewModel.activeTable),
        onClick: () => onTableChange(t.id),
      },
      `${t.label} (${t.count})`,
    ),
  );
  return el('div', { class: 'inventory-subnav' }, buttons);
}

function renderRow(row, onSelect) {
  return el(
    'tr',
    {
      class: 'inventory-row',
      'data-selected': String(row.selected),
      'data-visible': String(row.visible),
      tabindex: '0',
      role: 'button',
      'aria-label': `${row.cells[0]}${row.selected ? ', selected' : ''}`,
      onClick: () => row.selectableId && onSelect(row.selectableId),
      onKeydown: (evt) => {
        if ((evt.key === 'Enter' || evt.key === ' ') && row.selectableId) {
          evt.preventDefault();
          onSelect(row.selectableId);
        }
      },
    },
    row.cells.map((cellText) => el('td', {}, cellText)),
  );
}

/**
 * @param {ReturnType<typeof computeInventoryViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(selectableId: string) => void} onSelect
 * @param {(tableId: string) => void} onTableChange
 */
export function renderInventoryView(viewModel, canvasEl, onSelect, onTableChange) {
  clear(canvasEl);

  const subNav = renderSubNav(viewModel, onTableChange);

  const headerRow = el('tr', {}, viewModel.columns.map((col) => el('th', {}, col)));
  const bodyRows = viewModel.rows.map((row) => renderRow(row, onSelect));
  const table = el('table', { class: 'inventory-table' }, [el('thead', {}, headerRow), el('tbody', {}, bodyRows)]);

  canvasEl.appendChild(el('div', { class: 'inventory-view' }, [subNav, table]));
}
```

(Sorting, per the scoping doc's decision 8, is deliberately the smallest
addition that satisfies "sortable": a click handler on each `<th>` that
re-sorts `viewModel.rows` client-side by that column's cell text and
re-renders. Add this now, as part of this same step, since it is small
and belongs in the same render function:)

```js
function sortRows(rows, columnIndex, direction) {
  const sorted = [...rows].sort((a, b) => {
    const cmp = String(a.cells[columnIndex]).localeCompare(String(b.cells[columnIndex]));
    return direction === 'asc' ? cmp : -cmp;
  });
  return sorted;
}
```

Wire it into `renderInventoryView` by tracking sort state in a closure
local to each call (module-level `let` keyed by nothing extra needed,
since each call rebuilds the whole table fresh — mirror the simplest
possible approach): add an `onClick` to each `<th>` that calls a local
`currentSort` toggle and re-invokes `renderInventoryView` with a
pre-sorted `viewModel.rows` copy. Concretely, replace the `headerRow`
line above with:

```js
  let sortState = { columnIndex: null, direction: 'asc' };
  const headerRow = el('tr', {}, viewModel.columns.map((col, i) =>
    el('th', { onClick: () => {
      sortState = sortState.columnIndex === i ? { columnIndex: i, direction: sortState.direction === 'asc' ? 'desc' : 'asc' } : { columnIndex: i, direction: 'asc' };
      const sortedRows = sortRows(viewModel.rows, sortState.columnIndex, sortState.direction);
      renderInventoryView({ ...viewModel, rows: sortedRows }, canvasEl, onSelect, onTableChange);
    } }, col),
  ));
```

(This closure-based re-render-on-sort-click is a small, self-contained
addition — verify after implementing that clicking a header twice
round-trips to the original order via a test, added below.)

- [ ] **Step 5: Add a sort test**

Append to `frontend/test/inventory-view-render.test.js`:

```js
test('clicking a column header sorts rows by that column', () => {
  const canvasEl = document.createElement('div');
  const twoRowGraph = {
    nodes: [
      { id: 'node:b', kind: 'source', subtype: null, label: 'Bravo', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
      { id: 'node:a', kind: 'source', subtype: null, label: 'Alpha', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    ],
    edges: [], dataElements: [], transformations: [], flows: [],
  };
  const vm = computeInventoryViewModel(twoRowGraph, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  const firstHeader = canvasEl.querySelectorAll('th')[0];
  // Same click-simulation mechanism used in Step 1's row-click test.
  const firstCellTextAfterSort = canvasEl.querySelectorAll('tbody tr td')[0]?.childNodes?.[0]?.data;
  assert.equal(firstCellTextAfterSort, 'Alpha');
});
```

- [ ] **Step 6: Run to verify all inventory-view-render tests pass**

Run: `cd frontend && node --test test/inventory-view-render.test.js`
Expected: PASS.

- [ ] **Step 7: Wire Inventory into `app.js`**

Edit `frontend/src/app.js`:

```js
import { computeInventoryViewModel, renderInventoryView } from './views/inventory-view.js';
```

Inside `rerender()`, add a fourth branch:

```js
    } else if (state.view === 'inventory') {
      const viewModel = computeInventoryViewModel(graph, state);
      renderInventoryView(viewModel, shellApi.getCanvasEl(), (id) => shellApi.setSelection(id), (tableId) => shellApi.setTable(tableId));
      shellApi.getContextRailEl().textContent = buildContextRailText(graph);
    }
```

(placed as the final `else if`, after the existing `trace` branch, before
the closing brace of the `if/else if` chain).

Extend the filter-rail condition:

```js
    if (state.view === 'privacy' || state.view === 'inventory') {
      renderFilterRail(filterFacets, state.filters ?? {}, shellApi.getLeftRailEl(), (nextFilters) => shellApi.setFilters(nextFilters));
    } else {
      const railEl = shellApi.getLeftRailEl();
      railEl.textContent = 'Filters apply to Privacy View.';
    }
```

Update that else-branch's own text now that it's not fully accurate:

```js
    } else {
      const railEl = shellApi.getLeftRailEl();
      railEl.textContent = 'Filters apply to Privacy View and some Inventory tables.';
    }
```

- [ ] **Step 8: Add `app.js` integration coverage**

Check whether an `app.js`-level test file already exists (`ls
frontend/test/ | grep app`). If none exists, this plan does not add one —
`app.js`'s dispatch logic is thin enough that `shell.test.js`'s tab-click
test (Task 1, Step 5) plus `inventory-view.test.js`/
`inventory-view-render.test.js` already cover the real logic; `app.js`
itself has no prior test file and this plan does not introduce the first
one as a side effect (real, disclosed scope boundary, not an oversight).

- [ ] **Step 9: Add Inventory to the XSS adversarial sweep**

Edit `frontend/test/xss-adversarial.test.js`. Add the import:

```js
const { computeInventoryViewModel, renderInventoryView } = await import('../src/views/inventory-view.js');
```

Add a new test, mirroring the three existing ones exactly:

```js
test('T1: Inventory View renders the adversarial fixture with no live <script>, no on* handler, no javascript: URL anywhere in the DOM', () => {
  const canvasEl = document.createElement('div');
  const viewModel = computeInventoryViewModel(ADVERSARIAL_GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'fields' });
  renderInventoryView(viewModel, canvasEl, () => {}, () => {});
  assertNoLiveXss(canvasEl, 'Inventory View (fields)');
  assert.ok(assertPayloadOnlyAsText(canvasEl, 'Inventory View (fields)'), 'Inventory fields table should surface at least one hostile field (dataElement.name) as escaped text');
});
```

Read `test/adversarial-fixture.js`'s own `ADVERSARIAL_GRAPH.dataElements`
first to confirm at least one `name` field carries `SCRIPT_TAG` — if the
hostile content lives in a different field (e.g. only on `nodes[].label`),
change `table: 'fields'` to whichever category actually renders that
field (e.g. `'sources'`/`'sinks'` if the hostile string is on a node
label), and adjust `assertPayloadOnlyAsText`'s target view label to
match. Do not assert a category renders hostile content without
confirming it actually does against the real fixture file.

Run the mutation-proof check this session's own discipline requires: 
temporarily change one `el('td', {}, cellText)` call in
`renderInventoryView` to a raw string concatenation appended via
`node.innerHTML = ...` (a throwaway local edit), confirm this new test
FAILS against it, then revert the mutation before committing.

- [ ] **Step 10: Add the two new test files to `package.json`**

Edit `frontend/package.json`'s `test` script, appending both new files
(and nothing else) to the existing space-separated list, immediately
after `filter-rail.test.js` and before `api-client.test.js` (alphabetical
company, though the list is not strictly alphabetically sorted overall —
match its existing ordering convention by placing new entries near
related existing ones rather than only at the very end):

```
"test": "node --test test/escape-html.test.js test/contrast.test.js test/state.test.js test/fixture-module-parity.test.js test/dom.test.js test/shell.test.js test/protection-visual.test.js test/architecture-view.test.js test/architecture-view-render.test.js test/flow-summary-render.test.js test/evidence-inspector.test.js test/flow-path.test.js test/privacy-view.test.js test/privacy-view-render.test.js test/trace-view.test.js test/trace-view-render.test.js test/filter-rail.test.js test/inventory-view.test.js test/inventory-view-render.test.js test/api-client.test.js test/live-fetch-parity.test.js test/xss-adversarial.test.js"
```

- [ ] **Step 11: Full frontend test run**

Run: `cd frontend && npm test`
Expected: PASS, real captured exit code 0, all files including the two
new ones actually ran (grep the output for `inventory-view` to confirm
they were not silently skipped).

- [ ] **Step 12: Manual smoke check**

Serve the frontend (`cd frontend && npm run serve`) against a real graph
— either `agentic-security explore` from `scanner/` pointed at a scanned
repo, or by temporarily swapping `app.js`'s `FLAGSHIP_GRAPH` import for a
local test — and click through: the Inventory tab appears, all 11
sub-nav buttons render with real counts, clicking a row populates the
evidence inspector, clicking a column header sorts, switching to Fields
and toggling a data-class filter chip changes visible rows, switching to
Sources shows the rail with no visible filtering effect. Report exactly
what was and wasn't verified this way — do not claim UI verification
without having actually opened a browser.

- [ ] **Step 13: Full scanner gate (confirm zero cross-tree impact)**

Run: `cd scanner && npm test`
Expected: PASS, unaffected — this plan touches no `scanner/` file.
Capture `REAL_EXIT:$?` and report it.

- [ ] **Step 14: Commit**

```bash
git add frontend/src/views/inventory-view.js frontend/src/app.js frontend/src/shell.js frontend/package.json frontend/test/inventory-view-render.test.js frontend/test/xss-adversarial.test.js
git commit -m "feat(frontend): wire Inventory view render, app.js dispatch, sorting, XSS sweep coverage"
```

---

## Final integration checklist (coordinator, after all 3 tasks)

- Re-read every changed file in full (not diffs) — the established
  per-security-adjacent-increment discipline this session uses.
- `cd frontend && npm test` green with real captured exit code.
- `cd scanner && npm test` green with real captured exit code (confirms
  zero cross-tree breakage).
- Grep `frontend/src/` for any stray `innerHTML` this plan may have
  introduced despite its own instruction not to (none should exist —
  confirm rather than assume).
- Update `frontend/CLAUDE.md` with an Inventory section (module list,
  the `AI_SUBTYPES` fix disclosure, the `FILTERABLE_TABLES` scoping
  decision, the deferred items from the scoping doc) — same pattern
  every prior M3 sub-project's own CLAUDE.md update used.
- Update `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
  own Inventory row status to COMPLETE.
