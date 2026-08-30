# Data Flow Explorer — Privacy View, Trace View, and Filters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Data Flow Explorer prototype's three primary views by adding Privacy View (the lifecycle data map) and Trace View (the numbered source-to-sink evidence stepper), plus the left-rail filter chips deferred from the Architecture View plan — and in doing so, make flow selection reachable from the UI for the first time (Privacy View's rows double as flow selectors), which also finally gives Architecture View's already-built, already-tested `computeFlowSummary` a real consumer.

**Architecture:** Same conventions as the merged foundation and Architecture View plans: zero build step, pure view-model / thin-render split per view, every pure function tested against the REAL merged `frontend/src/data/flagship-graph.js` fixture. **Deliberate departure from Architecture View: Privacy View and Trace View are plain HTML/CSS (`el()` from `lib/dom.js`), not SVG.** Architecture View's Critical bug (elements built in the HTML namespace inside an `<svg>` tree, so nothing painted) is a namespace-mismatch problem that plain HTML elements cannot have — there is no foreign-namespace trap when everything is `<div>`/`<table>`/`<button>`. This is also a better fit for the PRD's own requirement that Privacy View "remain usable as a table... at 200% zoom" (§7.9) and that "every graph task has an inventory/table alternative" (§7.6) — building it as a real table from the start satisfies both without a second implementation.

**Tech Stack:** Plain ES modules, `el()`/`clear()` from `frontend/src/lib/dom.js` (already merged), `node:test` plus `frontend/test/dom-shim.js` (already merged, extended with `createElementNS` support during the Architecture View fix wave — real HTML elements don't need that, but the shim already supports plain `createElement` fully), zero new dependencies.

**Spec:** The Data Flow Explorer PRD (untracked root working document, not present on disk between sessions — every value/shape here is re-verified directly against the real, merged fixture and the real, merged `frontend/src/shell.js`/`frontend/src/views/architecture-view.js`, not from memory). Implements PRD §7.9 (Privacy View blueprint), §7.10 (Trace View blueprint), §7.8's left-rail filter requirement (deferred from the Architecture View plan), and AC-16 (cross-view selection — this plan is what finally makes flow selection reachable, closing the gap the Architecture View final review flagged as I2/I3).

## Global Constraints

- **Zero build step, no new dependencies.**
- **Privacy View and Trace View render via `el()` (HTML), never `svgEl()`/SVG.** This is a deliberate, stated departure from Architecture View, not an oversight — see Architecture above.
- **Every decision function is pure, unit-tested against the REAL `FLAGSHIP_GRAPH`.**
- **The real fixture's relevant shape** (re-verified at plan-writing time against the merged `frontend/src/data/flagship-graph.js`): every node's `lifecycleStages` array has exactly one entry, and the six values present across the 14 nodes are exactly the PRD's six stage names: `collection`×1 (`node.web`), `processing`×4 (`node.gateway`, `node.payments`, `node.ai`, `node.events`), `storage`×3 (`node.postgres`, `node.logs`, `node.vector`), `sharing`×4 (`node.payment_api`, `node.analytics`, `node.model`, `node.unresolved`), `retention`×1 (`node.retention`), `deletion`×1 (`node.deletion`). The one `transformation` object has `{id, inputPath, outputPath, callee, location:{file,line}, kind, reversibility, algorithm, appliesToAllPaths, controlCredit, controlCreditReason}` — note `callee` (not `functionRef`) and a flat `location` (unlike evidence's `location:{note}` string form). Three flows carry non-empty `governanceRefs` with literal `'manual_required'`/`'unknown'`/`'review'`/`'not_found'` string values: `flow.pci.ai` (`{recipient, purpose, lawfulBasis: 'manual_required'}`), `flow.phi.ai` (`{lawfulBasis: 'manual_required', retention: 'unknown', transfer: 'review'}`), `flow.pii.analytics` (`{retention: 'unknown', deletion: 'not_found'}`) — the other five flows have `governanceRefs: {}`.
- **Flow selection becomes reachable through Privacy View's own rows** (each row IS a flow; clicking one calls `shellApi.setSelection(flow.id)`), not through a separate dedicated flow-picker widget — this is the natural, minimal way to close the Architecture View review's I2/I3 findings, and it means no new UI concept is needed beyond "rows are clickable," matching the pattern already established for nodes/edges in Architecture View.
- **The left-rail filter chips built in this plan apply to Privacy View's rows only** — NOT retrofitted into Architecture View's node/edge dimming, which is a selection-driven mechanism, not a filter-driven one, and reconciling the two is explicitly out of scope here. This is a deliberate scoping decision, not a gap; note it in the docs task.
- **"AI relevance" is computed from flow/node TOPOLOGY** (does the flow's path touch a node whose `subtype` is `ai-assistant`, `ai-model-provider`, or `vector-store`), never from `dataElement.aiContexts` — confirmed again against the real fixture: all three `dataElements` still have `aiContexts: []` (classification.js never guesses AI relevance from a name alone), so a `dataElement.aiContexts`-based filter would show zero AI-relevant fields despite two real AI-topology flows (`flow.pci.ai`, `flow.phi.ai`) existing.
- Follow this repo's `git commit` convention: commit after each task with a descriptive message.

---

## File Structure

```
frontend/src/lib/
  flow-path.js                    # new — Task 1: flowPathNodeIds(), isAiRelevantFlow()
frontend/src/views/
  architecture-view.js            # modify — Task 1: refactor computeFlowSummary to use the shared helper
  privacy-view.js                 # new — Task 2 (pure) + Task 3 (render)
  trace-view.js                   # new — Task 4 (pure) + Task 5 (render)
frontend/src/components/
  filter-rail.js                  # new — Task 6 (pure + render)
frontend/src/app.js                # modify — Task 7
frontend/src/shell.js              # modify — Task 7 (mount the filter rail into the left rail)
frontend/styles/
  privacy-view.css                # new — Task 3
  trace-view.css                  # new — Task 5
  filter-rail.css                 # new — Task 6
frontend/index.html                # modify — Task 7: link the three new CSS files
frontend/test/
  flow-path.test.js                # new — Task 1
  privacy-view.test.js             # new — Task 2
  trace-view.test.js               # new — Task 4
  filter-rail.test.js              # new — Task 6
frontend/CLAUDE.md                 # modify — Task 8
frontend/package.json              # modify — Task 8
```

---

### Task 1: Shared flow-path helper, and refactor Architecture View to use it

**Files:**
- Create: `frontend/src/lib/flow-path.js`
- Modify: `frontend/src/views/architecture-view.js` (refactor only — no behavior change)
- Test: `frontend/test/flow-path.test.js`

**Interfaces:**
- Produces: `flowPathNodeIds(graph, flow) → Set<string>` (every node ID on the flow's path: `flow.source`, `flow.sink`, and every `edge.from`/`edge.to` for edges in `flow.edgeIds`), `isAiRelevantFlow(graph, flow) → boolean`. Consumed by Task 2 (Privacy View), Task 6 (filter rail), and this task's own refactor of `computeFlowSummary`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/flow-path.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { flowPathNodeIds, isAiRelevantFlow } from '../src/lib/flow-path.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);

test('flowPathNodeIds includes the flow\\'s own source and sink', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const ids = flowPathNodeIds(FLAGSHIP_GRAPH, flow);
  assert.ok(ids.has(flow.source));
  assert.ok(ids.has(flow.sink));
});

test('flowPathNodeIds includes every edge endpoint for a multi-hop flow', () => {
  const flow = flowByKey('flow.pci.ai'); // 3 edges: web->payments->ai->model
  const ids = flowPathNodeIds(FLAGSHIP_GRAPH, flow);
  for (const edgeId of flow.edgeIds) {
    const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
    assert.ok(ids.has(edge.from), `missing edge.from ${edge.from}`);
    assert.ok(ids.has(edge.to), `missing edge.to ${edge.to}`);
  }
});

test('isAiRelevantFlow is true for flows whose path touches the AI assistant or model provider', () => {
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')), true);
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.phi.ai')), true);
});

test('isAiRelevantFlow is false for flows that never touch an AI-kind node', () => {
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.masked_log')), false);
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pii.analytics')), false);
});

test('isAiRelevantFlow does not rely on dataElement.aiContexts (which is empty for every field in this fixture)', () => {
  for (const de of FLAGSHIP_GRAPH.dataElements) {
    assert.deepEqual(de.aiContexts, [], 'sanity check: this fixture genuinely has no populated aiContexts anywhere');
  }
  // yet an AI-topology flow must still be detected:
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')), true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/flow-path.test.js`
Expected: FAIL — `Cannot find module '../src/lib/flow-path.js'`

- [ ] **Step 3: Write `frontend/src/lib/flow-path.js`**

```js
// Shared per-flow path/topology helpers, used by every view that needs to
// know "which nodes does this flow actually touch" — extracted here after
// Architecture View independently reimplemented the same node-collection
// logic inline in computeFlowSummary, to avoid a third divergent copy when
// Privacy View needed it too.

export function flowPathNodeIds(graph, flow) {
  const ids = new Set([flow.source, flow.sink]);
  for (const edgeId of flow.edgeIds) {
    const edge = graph.edges.find((e) => e.id === edgeId);
    if (edge) {
      ids.add(edge.from);
      ids.add(edge.to);
    }
  }
  return ids;
}

const AI_SUBTYPES = new Set(['ai-assistant', 'ai-model-provider', 'vector-store']);

// AI relevance is computed from flow/node TOPOLOGY (does the path touch an
// AI-kind node), never from dataElement.aiContexts — that field is never
// populated by name-only classification (see scanner/src/lineage's
// classification.js), so an aiContexts-based filter would show zero AI
// relevance despite real AI-processing flows existing in the graph.
export function isAiRelevantFlow(graph, flow) {
  const pathNodeIds = flowPathNodeIds(graph, flow);
  return graph.nodes.some((n) => pathNodeIds.has(n.id) && AI_SUBTYPES.has(n.subtype));
}
```

- [ ] **Step 4: Refactor `computeFlowSummary` in `frontend/src/views/architecture-view.js` to use the shared helper**

Read the current file first. Replace the inline `pathNodeIds` computation:

```js
  const pathNodeIds = new Set([flow.source, flow.sink]);
  for (const e of edges) {
    pathNodeIds.add(e.from);
    pathNodeIds.add(e.to);
  }
```

with an import and a call to the new shared helper:

```js
import { flowPathNodeIds } from '../lib/flow-path.js';
```

(add alongside the existing `worstVerdict, protectionVisual` import from `../lib/protection-visual.js`, and the existing `clear` import from `../lib/dom.js`)

```js
  const pathNodeIds = flowPathNodeIds(graph, flow);
```

This is a pure refactor — no behavior change. `computeFlowSummary`'s signature and return shape are unchanged.

- [ ] **Step 5: Run tests to verify nothing broke**

Run: `cd frontend && node --test test/flow-path.test.js test/architecture-view.test.js`
Expected: PASS — the new flow-path tests pass, and every existing `architecture-view.test.js` test (including the `computeFlowSummary` tests) still passes unchanged, proving the refactor preserved behavior.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib/flow-path.js frontend/test/flow-path.test.js frontend/src/views/architecture-view.js
git commit -m "refactor(frontend): extract shared flow-path helper, reuse in Architecture View"
```

---

### Task 2: Privacy View — pure view-model

**Files:**
- Create: `frontend/src/views/privacy-view.js` (pure half only; Task 3 appends the render half)
- Test: `frontend/test/privacy-view.test.js`

**Interfaces:**
- Consumes: `flowPathNodeIds` (Task 1).
- Produces: `LIFECYCLE_STAGES` (array of 6 lowercase stage strings, PRD order), `stageForNode(node) → string`, `computePrivacyRow(graph, flow) → {...}`, `computePrivacyViewModel(graph, state) → {stages, rows}`. Consumed by Task 3's render function and Task 7's `app.js`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/privacy-view.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { LIFECYCLE_STAGES, stageForNode, computePrivacyRow, computePrivacyViewModel } from '../src/views/privacy-view.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);
const nodeByKey = (key) => FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS[key]);

test('LIFECYCLE_STAGES has the six PRD-named stages in order', () => {
  assert.deepEqual(LIFECYCLE_STAGES, ['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);
});

test('stageForNode reads the real fixture\\'s lifecycleStages field directly', () => {
  assert.equal(stageForNode(nodeByKey('node.web')), 'collection');
  assert.equal(stageForNode(nodeByKey('node.retention')), 'retention');
  assert.equal(stageForNode(nodeByKey('node.deletion')), 'deletion');
});

test('every real fixture node maps to one of the six known stages', () => {
  for (const node of FLAGSHIP_GRAPH.nodes) {
    assert.ok(LIFECYCLE_STAGES.includes(stageForNode(node)), `node ${node.id} has stage "${stageForNode(node)}" not in LIFECYCLE_STAGES`);
  }
});

test('computePrivacyRow for the masked-log PCI flow places its nodes in the correct stage cells', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const row = computePrivacyRow(FLAGSHIP_GRAPH, flow);
  assert.equal(row.dataElementName, 'card_number');
  assert.deepEqual(row.dataClasses, ['PCI']);
  const collectionCell = row.stageCells.find((c) => c.stage === 'collection');
  const processingCell = row.stageCells.find((c) => c.stage === 'processing');
  const storageCell = row.stageCells.find((c) => c.stage === 'storage');
  assert.ok(collectionCell.nodeLabels.includes('Web App'));
  assert.ok(processingCell.nodeLabels.includes('Payments Service'));
  assert.ok(storageCell.nodeLabels.includes('Application Logs'));
});

test('computePrivacyRow surfaces real manual_required governance facts, never invents them', () => {
  const aiFlow = flowByKey('flow.pci.ai');
  const row = computePrivacyRow(FLAGSHIP_GRAPH, aiFlow);
  assert.deepEqual(row.governanceRefs, aiFlow.governanceRefs);
  assert.equal(row.governanceRefs.lawfulBasis, 'manual_required');

  const nonGovernedFlow = flowByKey('flow.pci.masked_log');
  const nonGovernedRow = computePrivacyRow(FLAGSHIP_GRAPH, nonGovernedFlow);
  assert.deepEqual(nonGovernedRow.governanceRefs, {}, 'a flow with no real governance facts must show an empty object, not fabricated manual_required markers');
});

test('computePrivacyRow reports AI relevance via topology, matching flow-path.js', () => {
  assert.equal(computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')).isAiRelevant, true);
  assert.equal(computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pii.analytics')).isAiRelevant, false);
});

test('computePrivacyViewModel produces one row per real flow, in the same order as graph.flows', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  assert.equal(vm.rows.length, FLAGSHIP_GRAPH.flows.length);
  assert.deepEqual(vm.stages, LIFECYCLE_STAGES);
  assert.ok(vm.rows.every((r) => !r.selected));
});

test('computePrivacyViewModel marks the selected flow\\'s row as selected and no others', () => {
  const selectedFlowId = FLOW_KEYS['flow.pci.raw_log'];
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: selectedFlowId, filters: {} });
  const selectedRows = vm.rows.filter((r) => r.selected);
  assert.equal(selectedRows.length, 1);
  assert.equal(selectedRows[0].flowId, selectedFlowId);
});

test('computePrivacyViewModel applies a dataClass filter (OR within the dimension)', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { dataClass: ['PHI'] } });
  const visibleRows = vm.rows.filter((r) => r.visible);
  assert.ok(visibleRows.length > 0, 'at least the PHI flow should remain visible');
  assert.ok(visibleRows.every((r) => r.dataClasses.includes('PHI')));
});

test('computePrivacyViewModel with no filters marks every row visible', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  assert.ok(vm.rows.every((r) => r.visible));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/privacy-view.test.js`
Expected: FAIL — `Cannot find module '../src/views/privacy-view.js'`

- [ ] **Step 3: Write `frontend/src/views/privacy-view.js`**

```js
import { flowPathNodeIds, isAiRelevantFlow } from '../lib/flow-path.js';

export const LIFECYCLE_STAGES = Object.freeze(['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);

export function stageForNode(node) {
  return LIFECYCLE_STAGES.includes(node.lifecycleStages?.[0]) ? node.lifecycleStages[0] : 'processing';
}

export function computePrivacyRow(graph, flow) {
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const pathNodeIds = flowPathNodeIds(graph, flow);
  const pathNodes = graph.nodes.filter((n) => pathNodeIds.has(n.id));

  const stageCells = LIFECYCLE_STAGES.map((stage) => ({
    stage,
    nodeLabels: pathNodes.filter((n) => stageForNode(n) === stage).map((n) => n.label),
  }));

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    stageCells,
    governanceRefs: flow.governanceRefs ?? {},
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
    isAiRelevant: isAiRelevantFlow(graph, flow),
  };
}

function rowMatchesFilters(row, filters) {
  if (filters.dataClass?.length && !filters.dataClass.some((c) => row.dataClasses.includes(c))) return false;
  if (filters.protection?.length && !filters.protection.includes(row.protectionSummary)) return false;
  if (filters.ai && !row.isAiRelevant) return false;
  return true;
}

export function computePrivacyViewModel(graph, state) {
  const rows = graph.flows.map((flow) => {
    const row = computePrivacyRow(graph, flow);
    return {
      ...row,
      selected: row.flowId === state.selectedId,
      visible: rowMatchesFilters(row, state.filters ?? {}),
    };
  });
  return { stages: LIFECYCLE_STAGES, rows };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/privacy-view.test.js`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/privacy-view.js frontend/test/privacy-view.test.js
git commit -m "feat(frontend): add Privacy View's pure view-model"
```

---

### Task 3: Privacy View — HTML rendering

**Files:**
- Modify: `frontend/src/views/privacy-view.js` (append the render half)
- Create: `frontend/styles/privacy-view.css`

**Interfaces:**
- Consumes: `computePrivacyViewModel`'s output shape (Task 2), `el`/`clear` (`lib/dom.js`), `protectionVisual` (`lib/protection-visual.js`).
- Produces: `renderPrivacyView(viewModel, canvasEl, onSelectFlow)` where `onSelectFlow(flowId: string)` is called when a row is clicked. Consumed by Task 7's `app.js`.

- [ ] **Step 1: Write `frontend/styles/privacy-view.css`**

```css
.privacy-view {
  width: 100%;
  overflow-x: auto;
}

.privacy-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-size-body);
}

.privacy-table th {
  text-align: left;
  padding: var(--space-1) var(--space-2);
  color: var(--text-secondary);
  font-size: var(--font-size-panel-title);
  text-transform: uppercase;
  border-bottom: var(--border-width) solid var(--border-default);
  background: var(--surface-panel);
  position: sticky;
  top: 0;
}

.privacy-row {
  cursor: pointer;
  border-bottom: var(--border-width) solid var(--border-default);
}

.privacy-row:hover {
  background: var(--surface-elevated);
}

.privacy-row[data-selected="true"] {
  box-shadow: inset 3px 0 0 var(--accent-selection);
  background: var(--surface-elevated);
}

.privacy-row[data-visible="false"] {
  display: none;
}

.privacy-field-cell {
  padding: var(--space-1) var(--space-2);
  color: var(--text-primary);
  font-weight: 500;
  white-space: nowrap;
}

.privacy-stage-cell {
  padding: var(--space-1) var(--space-2);
  color: var(--text-secondary);
  vertical-align: top;
}

.privacy-stage-cell-empty {
  color: var(--border-default);
}

.privacy-governance-badge {
  display: inline-block;
  border: 1px solid var(--status-unknown);
  color: var(--status-unknown);
  border-radius: var(--radius-default);
  padding: 1px 6px;
  font-size: var(--font-size-code);
  margin-top: 4px;
}

.privacy-class-badge {
  display: inline-block;
  border-radius: var(--radius-default);
  padding: 1px 6px;
  font-size: var(--font-size-code);
  margin-right: 4px;
  border: 1px solid var(--border-default);
}
```

- [ ] **Step 2: Append the render function to `frontend/src/views/privacy-view.js`**

Add these imports at the top, alongside the existing `flowPathNodeIds, isAiRelevantFlow` import:

```js
import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';
```

Append at the end of the file:

```js
const CLASS_BADGE_COLOR_VAR = { PII: '--class-pii', PHI: '--class-phi', PCI: '--class-pci' };

/**
 * @param {ReturnType<typeof computePrivacyViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(flowId: string) => void} onSelectFlow
 */
export function renderPrivacyView(viewModel, canvasEl, onSelectFlow) {
  clear(canvasEl);

  const headerRow = el('tr', {}, [
    el('th', {}, 'Field'),
    ...viewModel.stages.map((stage) => el('th', {}, stage.charAt(0).toUpperCase() + stage.slice(1))),
  ]);

  const bodyRows = viewModel.rows.map((row) => renderPrivacyRow(row, onSelectFlow));

  const table = el('table', { class: 'privacy-table' }, [el('thead', {}, headerRow), el('tbody', {}, bodyRows)]);

  canvasEl.appendChild(el('div', { class: 'privacy-view' }, table));
}

function renderPrivacyRow(row, onSelectFlow) {
  const classBadges = row.dataClasses.map((cls) =>
    el('span', { class: 'privacy-class-badge', style: `color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--text-secondary'}); border-color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--border-default'})` }, cls),
  );

  const fieldCell = el('td', { class: 'privacy-field-cell' }, [
    el('div', {}, row.dataElementName),
    el('div', {}, classBadges),
    row.isAiRelevant ? el('span', { class: 'privacy-governance-badge', style: 'border-color: var(--context-ai); color: var(--context-ai)' }, 'AI processing') : null,
  ]);

  const stageCells = row.stageCells.map((cell) => renderStageCell(cell, row));

  return el(
    'tr',
    {
      class: 'privacy-row',
      'data-selected': String(row.selected),
      'data-visible': String(row.visible),
      tabindex: '0',
      role: 'button',
      'aria-label': `${row.dataElementName} lifecycle, ${row.protectionSummary}${row.selected ? ', selected' : ''}`,
      onClick: () => onSelectFlow(row.flowId),
      onKeydown: (evt) => {
        if (evt.key === 'Enter' || evt.key === ' ') {
          evt.preventDefault();
          onSelectFlow(row.flowId);
        }
      },
    },
    [fieldCell, ...stageCells],
  );
}

function renderStageCell(cell, row) {
  if (cell.nodeLabels.length === 0) {
    return el('td', { class: 'privacy-stage-cell privacy-stage-cell-empty' }, '—');
  }
  const children = [el('div', {}, cell.nodeLabels.join(', '))];

  // Governance facts are shown once, on whichever stage cell is the most
  // relevant home for them — sharing (recipient/purpose/lawfulBasis/transfer)
  // or retention/deletion — rather than repeating them on every cell.
  const governanceKeysForStage = {
    sharing: ['recipient', 'purpose', 'lawfulBasis', 'transfer'],
    retention: ['retention'],
    deletion: ['deletion'],
  };
  const relevantKeys = governanceKeysForStage[cell.stage] ?? [];
  for (const key of relevantKeys) {
    if (key in row.governanceRefs) {
      const value = row.governanceRefs[key];
      children.push(el('div', { class: 'privacy-governance-badge' }, `${key}: ${value}`));
    }
  }

  if (cell.stage === 'sharing' && row.protectionSummary) {
    const visual = protectionVisual(row.protectionSummary === 'unknown' ? 'unknown' : row.protectionSummary);
    children.push(el('div', { class: 'privacy-governance-badge', style: `border-color: var(${visual.colorVar}); color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`));
  }

  return el('td', { class: 'privacy-stage-cell' }, children);
}
```

- [ ] **Step 3: Manual browser smoke check**

The render half is browser-only per this plan's Global Constraints — exercised by Task 7's end-to-end smoke check once `app.js` wires everything together. No standalone check for this task.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/views/privacy-view.js frontend/styles/privacy-view.css
git commit -m "feat(frontend): render Privacy View as an HTML lifecycle table"
```

---

### Task 4: Trace View — pure view-model

**Files:**
- Create: `frontend/src/views/trace-view.js` (pure half only; Task 5 appends the render half)
- Test: `frontend/test/trace-view.test.js`

**Interfaces:**
- Produces: `computeTraceSteps(graph, flow) → Array<step>`, `computeAlternatePaths(graph, flow) → Array<{flowId, destinationLabel, protectionSummary}>`, `computeTraceViewModel(graph, state) → {flow, steps, alternatePaths} | null` (null when `state.selectedId` doesn't resolve to a real flow). Consumed by Task 5's render function and Task 7's `app.js`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/trace-view.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeTraceSteps, computeAlternatePaths, computeTraceViewModel } from '../src/views/trace-view.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);

test('computeTraceSteps for the masked-log flow produces the real source->rename->transform->sink sequence', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);

  const sourceStep = steps.find((s) => s.kind === 'source');
  assert.ok(sourceStep);
  assert.equal(sourceStep.node, 'Web App');

  const renameStep = steps.find((s) => s.mappingType === 'rename');
  assert.ok(renameStep, 'expected a rename step for req.body.card_number -> payment.pan');
  assert.equal(renameStep.fromPath, 'req.body.card_number');
  assert.equal(renameStep.toPath, 'payment.pan');
  assert.equal(renameStep.node, 'Payments Service');

  const transformStep = steps.find((s) => s.kind === 'transformation');
  assert.ok(transformStep, 'expected a transformation step for the maskCard() hop');
  assert.equal(transformStep.fromPath, 'payment.pan');
  assert.equal(transformStep.toPath, 'maskedPan');
  assert.equal(transformStep.node, 'Application Logs');
  assert.equal(transformStep.transformations.length, 1);
  assert.equal(transformStep.transformations[0].callee, 'maskCard');
  assert.equal(transformStep.transformations[0].kind, 'mask');
  assert.equal(transformStep.protection.handling.verdict, 'protected');

  const sinkStep = steps.find((s) => s.kind === 'sink');
  assert.ok(sinkStep);
  assert.equal(sinkStep.node, 'Application Logs');
  assert.equal(sinkStep.protectionSummary, 'protected');
});

test('computeTraceSteps never invents a transformation the edge does not actually declare', () => {
  const flow = flowByKey('flow.pci.raw_log');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const transformSteps = steps.filter((s) => s.kind === 'transformation');
  assert.equal(transformSteps.length, 0, 'the raw-log flow has no transformation on its identity-mapped edge');
  const identityStep = steps.find((s) => s.mappingType === 'identity');
  assert.ok(identityStep);
});

test('computeTraceSteps marks the external, cleartext payment-API hop as a real trust-boundary crossing', () => {
  const flow = flowByKey('flow.pci.payment_api');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const sinkStep = steps.find((s) => s.kind === 'sink');
  assert.equal(sinkStep.protectionSummary, 'unprotected');
});

test('computeAlternatePaths for card_number lists the OTHER card_number flows, not itself', () => {
  const maskedLogFlow = flowByKey('flow.pci.masked_log');
  const alternates = computeAlternatePaths(FLAGSHIP_GRAPH, maskedLogFlow);
  assert.ok(!alternates.some((a) => a.flowId === maskedLogFlow.id), 'must not list itself as an alternate');
  assert.ok(alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.raw_log']), 'the raw-log flow shares card_number and must appear as an alternate');
  assert.ok(alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.payment_api']));
});

test('computeAlternatePaths for a PII flow never lists a PCI flow (different data element)', () => {
  const analyticsFlow = flowByKey('flow.pii.analytics');
  const alternates = computeAlternatePaths(FLAGSHIP_GRAPH, analyticsFlow);
  assert.ok(!alternates.some((a) => a.flowId === FLOW_KEYS['flow.pci.masked_log']));
});

test('computeTraceViewModel returns null when nothing is selected', () => {
  assert.equal(computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: null, filters: {} }), null);
});

test('computeTraceViewModel returns null when the selection is a node or edge, not a flow', () => {
  const nodeId = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys['node.web'];
  assert.equal(computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: nodeId, filters: {} }), null);
});

test('computeTraceViewModel for a real flow selection returns flow, steps, and alternatePaths together', () => {
  const flowId = FLOW_KEYS['flow.pci.masked_log'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm);
  assert.equal(vm.flow.id, flowId);
  assert.ok(vm.steps.length > 0);
  assert.ok(vm.alternatePaths.length > 0);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/trace-view.test.js`
Expected: FAIL — `Cannot find module '../src/views/trace-view.js'`

- [ ] **Step 3: Write `frontend/src/views/trace-view.js`**

```js
export function computeTraceSteps(graph, flow) {
  const steps = [];
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));

  steps.push({
    kind: 'source',
    fieldName: dataElement?.name ?? 'unknown field',
    node: sourceNode?.label ?? 'unknown source',
  });

  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  for (const edge of edges) {
    const toNode = graph.nodes.find((n) => n.id === edge.to);
    const mappings = edge.fieldMappings ?? [];

    if (mappings.length === 0) {
      steps.push({
        kind: 'hop',
        node: toNode?.label ?? 'unknown',
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
      continue;
    }

    for (const mapping of mappings) {
      const transformations = (mapping.transformationIds ?? [])
        .map((tid) => graph.transformations.find((t) => t.id === tid))
        .filter(Boolean);
      steps.push({
        kind: transformations.length > 0 ? 'transformation' : 'propagation',
        fromPath: mapping.fromPath,
        toPath: mapping.toPath,
        mappingType: mapping.mappingType,
        transformations,
        node: toNode?.label ?? 'unknown',
        boundaryCrossing: (edge.boundaryCrossings ?? []).length > 0,
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
    }
  }

  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  steps.push({
    kind: 'sink',
    node: sinkNode?.label ?? 'unknown destination',
    externality: sinkNode?.externality?.value ?? 'unknown',
    protectionSummary: flow.protectionSummary,
  });

  return steps;
}

export function computeAlternatePaths(graph, flow) {
  return graph.flows
    .filter((f) => f.id !== flow.id && f.dataElementIds.some((id) => flow.dataElementIds.includes(id)))
    .map((f) => ({
      flowId: f.id,
      destinationLabel: graph.nodes.find((n) => n.id === f.sink)?.label ?? 'unknown',
      protectionSummary: f.protectionSummary,
    }));
}

export function computeTraceViewModel(graph, state) {
  if (!state.selectedId) return null;
  const flow = graph.flows.find((f) => f.id === state.selectedId);
  if (!flow) return null;
  return {
    flow,
    steps: computeTraceSteps(graph, flow),
    alternatePaths: computeAlternatePaths(graph, flow),
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/trace-view.test.js`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/trace-view.js frontend/test/trace-view.test.js
git commit -m "feat(frontend): add Trace View's pure view-model"
```

---

### Task 5: Trace View — HTML rendering

**Files:**
- Modify: `frontend/src/views/trace-view.js` (append the render half)
- Create: `frontend/styles/trace-view.css`

**Interfaces:**
- Consumes: `computeTraceViewModel`'s output shape (Task 4), `el`/`clear` (`lib/dom.js`), `protectionVisual` (`lib/protection-visual.js`).
- Produces: `renderTraceView(viewModel, canvasEl, onSelectAlternate)` where `onSelectAlternate(flowId: string)` is called when an alternate-path entry is clicked. `viewModel` may be `null` (nothing selected, or selection isn't a flow) — the function must render an honest empty/prompt state, not crash. Consumed by Task 7's `app.js`.

- [ ] **Step 1: Write `frontend/styles/trace-view.css`**

```css
.trace-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  max-width: 640px;
}

.trace-step {
  display: flex;
  gap: var(--space-2);
  padding: var(--space-2);
  background: var(--surface-panel);
  border: var(--border-width) solid var(--border-default);
  border-radius: var(--radius-default);
}

.trace-step-number {
  flex: 0 0 auto;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--surface-elevated);
  color: var(--text-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: var(--font-size-code);
  font-weight: 600;
}

.trace-step-body {
  flex: 1 1 auto;
}

.trace-step-kind {
  color: var(--text-secondary);
  font-size: var(--font-size-code);
  text-transform: uppercase;
}

.trace-step-mapping {
  font-family: var(--font-mono);
  font-size: var(--font-size-code);
  color: var(--text-primary);
  margin: 4px 0;
}

.trace-step-node {
  color: var(--text-secondary);
  font-size: var(--font-size-body);
}

.trace-step-boundary {
  display: inline-block;
  border: 1px solid var(--status-unprotected);
  color: var(--status-unprotected);
  border-radius: var(--radius-default);
  padding: 1px 6px;
  font-size: var(--font-size-code);
  margin-top: 4px;
}

.trace-alternates {
  margin-top: var(--space-2);
}

.trace-alternate-item {
  padding: var(--space-1) 0;
  cursor: pointer;
  color: var(--text-secondary);
}

.trace-alternate-item:hover {
  color: var(--text-primary);
}

.trace-empty {
  color: var(--text-secondary);
  font-style: italic;
  padding: var(--space-2);
}
```

- [ ] **Step 2: Append the render function to `frontend/src/views/trace-view.js`**

Add these imports at the top:

```js
import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';
```

Append at the end of the file:

```js
/**
 * @param {ReturnType<typeof computeTraceViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(flowId: string) => void} onSelectAlternate
 */
export function renderTraceView(viewModel, canvasEl, onSelectAlternate) {
  clear(canvasEl);

  if (!viewModel) {
    canvasEl.appendChild(el('p', { class: 'trace-empty' }, 'Select a flow from Privacy View (or click a node/edge in Architecture View that resolves to a flow) to trace it.'));
    return;
  }

  const container = el('div', { class: 'trace-view' });
  viewModel.steps.forEach((step, i) => {
    container.appendChild(renderTraceStep(step, i + 1));
  });

  if (viewModel.alternatePaths.length > 0) {
    const items = viewModel.alternatePaths.map((alt) => {
      const visual = protectionVisual(alt.protectionSummary);
      return el(
        'div',
        {
          class: 'trace-alternate-item',
          tabindex: '0',
          role: 'button',
          onClick: () => onSelectAlternate(alt.flowId),
          onKeydown: (evt) => {
            if (evt.key === 'Enter' || evt.key === ' ') {
              evt.preventDefault();
              onSelectAlternate(alt.flowId);
            }
          },
        },
        `${visual.glyph} ${alt.destinationLabel} — ${visual.label}`,
      );
    });
    container.appendChild(el('div', { class: 'trace-alternates' }, [el('h4', {}, 'Alternate destinations'), ...items]));
  }

  canvasEl.appendChild(container);
}

function renderTraceStep(step, number) {
  const bodyChildren = [el('div', { class: 'trace-step-kind' }, step.kind)];

  if (step.kind === 'source') {
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, step.fieldName));
  } else if (step.kind === 'transformation' || step.kind === 'propagation') {
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${step.fromPath} → ${step.toPath} (${step.mappingType})`));
    for (const t of step.transformations) {
      bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${t.callee}() — ${t.kind}, ${t.reversibility}`));
    }
  }

  bodyChildren.push(el('div', { class: 'trace-step-node' }, step.node));

  if (step.boundaryCrossing) {
    bodyChildren.push(el('span', { class: 'trace-step-boundary' }, 'Trust boundary crossing'));
  }

  if (step.protection) {
    const visual = protectionVisual(step.protection.handling.verdict);
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${visual.glyph} Handling: ${visual.label}`));
  }

  if (step.kind === 'sink') {
    const visual = protectionVisual(step.protectionSummary);
    bodyChildren.push(el('div', { class: 'trace-step-mapping' }, `${visual.glyph} Overall: ${visual.label} · ${step.externality} destination`));
  }

  return el('div', { class: 'trace-step' }, [el('div', { class: 'trace-step-number' }, String(number)), el('div', { class: 'trace-step-body' }, bodyChildren)]);
}
```

- [ ] **Step 3: Manual browser smoke check**

Browser-only per this plan's Global Constraints — exercised by Task 7's end-to-end check.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/views/trace-view.js frontend/styles/trace-view.css
git commit -m "feat(frontend): render Trace View as a numbered HTML stepper"
```

---

### Task 6: Left-rail filter chips

**Files:**
- Create: `frontend/src/components/filter-rail.js`
- Create: `frontend/styles/filter-rail.css`
- Test: `frontend/test/filter-rail.test.js`

**Interfaces:**
- Consumes: `isAiRelevantFlow` (`lib/flow-path.js`), `el`/`clear` (`lib/dom.js`).
- Produces: `computeFilterFacets(graph) → {dataClasses: string[], protectionTiers: string[]}` (pure, tested), `renderFilterRail(facets, currentFilters, railEl, onFiltersChange)` where `onFiltersChange(nextFilters)` is called whenever a chip is toggled (thin DOM, browser-only). Consumed by Task 7's `app.js`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/filter-rail.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeFilterFacets } from '../src/components/filter-rail.js';

test('computeFilterFacets derives dataClasses from the real fixture\\'s dataElements, deduplicated and sorted', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  assert.deepEqual(facets.dataClasses, ['PCI', 'PHI', 'PII']);
});

test('computeFilterFacets\\'s protectionTiers is the fixed enum, not derived from what happens to be present', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  assert.deepEqual(facets.protectionTiers, ['protected', 'unprotected', 'mixed', 'unknown']);
});

test('computeFilterFacets never throws on a graph with zero dataElements', () => {
  const emptyGraph = { ...FLAGSHIP_GRAPH, dataElements: [] };
  assert.doesNotThrow(() => computeFilterFacets(emptyGraph));
  assert.deepEqual(computeFilterFacets(emptyGraph).dataClasses, []);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/filter-rail.test.js`
Expected: FAIL — `Cannot find module '../src/components/filter-rail.js'`

- [ ] **Step 3: Write `frontend/src/components/filter-rail.js`**

```js
import { el, clear } from '../lib/dom.js';

// A fixed enum, not derived from "whatever protectionSummary values happen
// to be present in this fixture" — a filter chip for `unprotected` must
// still exist even on a graph where nothing currently is, so a user can
// confirm that's genuinely true rather than the chip silently not existing.
const PROTECTION_TIERS = Object.freeze(['protected', 'unprotected', 'mixed', 'unknown']);

export function computeFilterFacets(graph) {
  const dataClasses = [...new Set((graph.dataElements ?? []).flatMap((d) => d.dataClasses ?? []))].sort();
  return { dataClasses, protectionTiers: PROTECTION_TIERS };
}

/**
 * @param {ReturnType<typeof computeFilterFacets>} facets
 * @param {{dataClass?: string[], protection?: string[], ai?: boolean}} currentFilters
 * @param {HTMLElement} railEl
 * @param {(next: object) => void} onFiltersChange
 */
export function renderFilterRail(facets, currentFilters, railEl, onFiltersChange) {
  clear(railEl);

  const dataClassChips = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'Data class'), ...facets.dataClasses.map((cls) => renderChip(cls, currentFilters.dataClass?.includes(cls) ?? false, () => toggleListFilter(currentFilters, 'dataClass', cls, onFiltersChange)))],
  );

  const protectionChips = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'Protection'), ...facets.protectionTiers.map((tier) => renderChip(tier, currentFilters.protection?.includes(tier) ?? false, () => toggleListFilter(currentFilters, 'protection', tier, onFiltersChange)))],
  );

  const aiChip = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'AI'), renderChip('AI processing', currentFilters.ai === true, () => onFiltersChange({ ...currentFilters, ai: !currentFilters.ai }))],
  );

  railEl.appendChild(el('div', { class: 'filter-rail' }, [dataClassChips, protectionChips, aiChip]));
}

function toggleListFilter(currentFilters, key, value, onFiltersChange) {
  const current = currentFilters[key] ?? [];
  const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  onFiltersChange({ ...currentFilters, [key]: next });
}

function renderChip(label, active, onClick) {
  return el(
    'button',
    {
      class: 'filter-chip',
      'data-active': String(active),
      'aria-pressed': String(active),
      onClick,
    },
    label,
  );
}
```

- [ ] **Step 4: Write `frontend/styles/filter-rail.css`**

```css
.filter-rail-group {
  margin-bottom: var(--space-2);
}

.filter-rail-group h4 {
  font-size: var(--font-size-body);
  text-transform: uppercase;
  color: var(--text-secondary);
  margin: 0 0 var(--space-1) 0;
}

.filter-chip {
  display: inline-block;
  margin: 2px;
  padding: 2px 8px;
  border-radius: var(--radius-default);
  border: 1px solid var(--border-default);
  background: transparent;
  color: var(--text-secondary);
  font-family: var(--font-family);
  font-size: var(--font-size-code);
  cursor: pointer;
}

.filter-chip[data-active="true"] {
  border-color: var(--accent-selection);
  color: var(--text-primary);
  background: var(--surface-elevated);
}

.filter-chip:focus-visible {
  outline: 2px solid var(--accent-selection);
  outline-offset: 2px;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd frontend && node --test test/filter-rail.test.js`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/filter-rail.js frontend/styles/filter-rail.css frontend/test/filter-rail.test.js
git commit -m "feat(frontend): add left-rail filter chips"
```

---

### Task 7: Wire it all together

**Files:**
- Modify: `frontend/src/app.js`
- Modify: `frontend/src/shell.js`
- Modify: `frontend/index.html`

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: the fully running application with all three views and filters wired.

- [ ] **Step 1: Read the current `frontend/src/shell.js` and expose the left-rail element**

`mountShell` currently sets `leftRail`'s content once at mount time (`el('div', { class: 'shell__left-rail' }, 'Filters (wired by the next plan)')`) with no getter. Add a `getLeftRailEl()` getter, following the exact pattern already used for `getCanvasEl`/`getInspectorEl`/`getContextRailEl`:

```js
    getCanvasEl: () => canvas,
    getInspectorEl: () => inspector,
    getContextRailEl: () => contextRail,
    getLeftRailEl: () => leftRail,
```

Update the JSDoc return-type comment to include `getLeftRailEl: () => HTMLElement,` alongside the existing getters. This is purely additive — do not change any other existing behavior.

- [ ] **Step 2: Add a test for the new getter**

Read the current `frontend/test/shell.test.js` first (it already has a `getContextRailEl` test from the Architecture View plan — follow that exact pattern) and add an analogous test for `getLeftRailEl()`.

Run: `cd frontend && node --test test/shell.test.js`
Expected: PASS (all existing tests plus the new one)

- [ ] **Step 3: Rewrite `frontend/src/app.js`**

Read the current file first (it currently only wires Architecture View). Replace it with:

```js
import { mountShell } from './shell.js';
import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';
import { computeArchitectureViewModel, renderArchitectureView } from './views/architecture-view.js';
import { computePrivacyViewModel, renderPrivacyView } from './views/privacy-view.js';
import { computeTraceViewModel, renderTraceView } from './views/trace-view.js';
import { computeInspectorViewModel, renderInspector } from './components/evidence-inspector.js';
import { computeFilterFacets, renderFilterRail } from './components/filter-rail.js';

export function bootstrap(rootEl, graph) {
  const shellApi = mountShell(rootEl, graph);
  const filterFacets = computeFilterFacets(graph);

  function rerender() {
    const state = shellApi.getState();

    if (state.view === 'architecture') {
      const viewModel = computeArchitectureViewModel(graph, state);
      renderArchitectureView(viewModel, shellApi.getCanvasEl(), (id) => shellApi.setSelection(id));
    } else if (state.view === 'privacy') {
      const viewModel = computePrivacyViewModel(graph, state);
      renderPrivacyView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
    } else if (state.view === 'trace') {
      const viewModel = computeTraceViewModel(graph, state);
      renderTraceView(viewModel, shellApi.getCanvasEl(), (flowId) => shellApi.setSelection(flowId));
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());

    renderFilterRail(filterFacets, state.filters ?? {}, shellApi.getLeftRailEl(), (nextFilters) => shellApi.setFilters(nextFilters));
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
```

- [ ] **Step 4: Update `frontend/index.html`**

Read the current file first. Add `<link>` tags for the three new CSS files (`styles/privacy-view.css`, `styles/trace-view.css`, `styles/filter-rail.css`) alongside the existing `architecture-view.css`/`inspector.css` links — no other changes needed, since `app.js`'s public `bootstrap()` signature is unchanged.

- [ ] **Step 5: Run the full frontend suite**

Run: `cd frontend && npm test`
Expected: PASS, all test files including the 4 new ones plus the updated `shell.test.js`

- [ ] **Step 6: Manual browser smoke check — learn from the Architecture View plan's lesson**

The Architecture View final review found that an earlier verification pass checked `textContent`/attribute presence but never actual visual rendering (bounding boxes, `checkVisibility()`), which let a Critical SVG-namespace bug through undetected. This task's views are plain HTML (`el()`), which cannot have that specific namespace bug — but still verify REAL rendering, not just DOM presence:

Start a static server (`cd frontend && npm run serve`, or equivalent) and use real browser automation if available (search for `mcp__claude-in-chrome__*` tools). If the extension bridge is unavailable (a known issue in this environment), drive real headless Chrome directly via the DevTools Protocol: Chrome exists at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, Node has a built-in `WebSocket` — spawn `chrome --headless=new --remote-debugging-port=<port> --disable-gpu --no-sandbox --user-data-dir=<a fresh /tmp dir>`, fetch `http://localhost:<port>/json/new?<url>` (PUT — the page-target endpoint, not the browser-level `/json/version` one) to get a `webSocketDebuggerUrl`, connect, and use `Runtime.evaluate`.

Verify, with real observed values (not assumptions):

1. Switch to the Privacy tab — a real HTML `<table>` renders with 6 stage-name column headers and 8 rows (one per real flow), each row's bounding box (`getBoundingClientRect()`) has non-zero height.
2. Click a Privacy View row (using a REAL coordinate-based click via `Input.dispatchMouseEvent` at the row's actual on-screen position — not a programmatic `.click()`/`dispatchEvent` call, which is exactly the blind spot that missed the Architecture View bug) — `window.location.hash` updates to `selected=flow%3A...`, and the row gets `data-selected="true"`.
3. Switch to the Trace tab with that flow still selected (AC-16) — the numbered stepper renders with the correct step count for that flow (verify against what `computeTraceSteps` would produce for the real flow you selected), and at least one step shows a real protection-verdict glyph (not just text).
4. Click an "Alternate destinations" entry in Trace View — the selection changes to that alternate flow, and switching back to Privacy View shows the NEW flow's row as selected (cross-view persistence again).
5. Toggle a data-class filter chip in the left rail — Privacy View's non-matching rows become hidden (`data-visible="false"`, confirm via `getBoundingClientRect()` that a hidden row's height is 0 or it's not in the visible layout — `display:none` produces a zero-size rect, which is the correct signal here, unlike the Architecture View bug where zero-size was WRONG for an element that should have been visible; the point is to confirm the CSS rule you expect is actually the one taking effect).
6. Zero console errors throughout.

If browser automation isn't available in your environment, say so explicitly (DONE_WITH_CONCERNS) rather than skipping verification.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app.js frontend/src/shell.js frontend/index.html frontend/test/shell.test.js
git commit -m "feat(frontend): wire Privacy View, Trace View, and filters together"
```

---

### Task 8: Documentation and gate check

**Files:**
- Modify: `frontend/CLAUDE.md`
- Modify: `frontend/package.json`

**Interfaces:** none — documentation and wiring only.

- [ ] **Step 1: Add the new test files to `frontend/package.json`'s `test` script**

Read the file first. Append `test/flow-path.test.js test/privacy-view.test.js test/trace-view.test.js test/filter-rail.test.js` to the existing list.

- [ ] **Step 2: Run the full frontend suite**

Run: `cd frontend && npm test`
Expected: PASS, all test files.

- [ ] **Step 3: Update `frontend/CLAUDE.md`**

Add rows for the 4 new modules (`src/lib/flow-path.js`, `src/views/privacy-view.js`, `src/views/trace-view.js`, `src/components/filter-rail.js`), following the existing table's style exactly. Explicitly note in `privacy-view.js`'s and `trace-view.js`'s rows that they render via `el()` (HTML), NOT `svgEl()`/SVG — a deliberate departure from `architecture-view.js`, made specifically to avoid the namespace-mismatch bug class that shipped there. Note in the Conventions section (or a new bullet) that the left-rail filters (`filter-rail.js`) currently apply to Privacy View only, not Architecture View's node/edge dimming — a deliberate scoping decision, not a gap.

- [ ] **Step 4: Run the full frontend suite once more, then commit**

Run: `cd frontend && npm test`
Expected: PASS

```bash
git add frontend/CLAUDE.md frontend/package.json
git commit -m "docs(frontend): document Privacy View, Trace View, and filters"
```

---

## Self-Review Notes (completed by the plan author before handoff)

**Spec coverage:** PRD §7.9 (Privacy View: 6 lifecycle stages, field rows, governance facts, MANUAL REQUIRED markers) → Tasks 2-3. §7.10 (Trace View: numbered steps, field mappings, transformation semantics, trust-boundary crossings, alternate paths) → Tasks 4-5. §7.8's left-rail filter requirement (deferred from the Architecture View plan) → Task 6. AC-16 (cross-view selection actually reachable, closing the Architecture View review's I2/I3) → Task 7, specifically because Privacy View's rows are the flow-selection mechanism. §7.6 (table alternative for every graph fact) → satisfied structurally, since Privacy View IS a table, not a secondary alternative to one. What this plan does **not** cover, deliberately: retrofitting filters into Architecture View's node/edge dimming (Global Constraints), golden-image pixel regression testing (DFG-034, still its own later backlog item), the Trace View's evidence-inspector-adjacent "why this control was/wasn't credited" reasoning text beyond what `evidence-inspector.js` (already merged) already provides when a trace step's underlying edge/flow is separately selected.

**Placeholder scan:** every step contains complete, runnable code. Task 3/5's Step 3 (manual browser check deferred to Task 7) is an explicit, honest scoping decision matching the Architecture View plan's precedent for render-half tasks, not a placeholder.

**Type consistency:** `flowPathNodeIds(graph, flow) → Set<string>` / `isAiRelevantFlow(graph, flow) → boolean` (Task 1) used identically in Tasks 2 and 6, and in Architecture View's refactored `computeFlowSummary`. `computePrivacyViewModel(graph, state) → {stages, rows}` (Task 2) consumed identically by Task 3's `renderPrivacyView` and Task 7's `app.js`. `computeTraceViewModel(graph, state) → {flow, steps, alternatePaths} | null` (Task 4) consumed identically by Task 5's `renderTraceView` and Task 7's `app.js`. `computeFilterFacets(graph) → {dataClasses, protectionTiers}` (Task 6) consumed identically by Task 7's `app.js`. `mountShell`'s extended return contract (Task 7's `getLeftRailEl` addition) is additive — does not change any existing consumer, matching the exact pattern already used for `getContextRailEl` in the Architecture View plan.
