# Data Flow Explorer: Trace View Branch-Aware Rendering + Test-Quality Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Trace View's false linear-sequence rendering of branching flows (I2 from the Privacy/Trace Views plan's final whole-branch review), and close two non-blocking test-quality gaps that same review's fix-wave re-review flagged as follow-up material.

**Architecture:** Both changes are additive to the existing pure/render split established across `frontend/`. Task 1 adds a new pure grouping function to `trace-view.js` that the existing render function consumes; it does not change `computeTraceSteps`'s existing consumers' assumptions (only adds a field). Task 2 adds test coverage only — no production code changes.

**Tech Stack:** Plain ES modules, no bundler/framework (`frontend/CLAUDE.md`'s zero-build-step decision). Tests: Node's built-in `node:test` + `node:assert/strict`, `frontend/test/dom-shim.js` (a dependency-free `document` shim — not jsdom) for render-level tests. Real fixture only (`frontend/src/data/flagship-graph.js`'s `FLAGSHIP_GRAPH`, addressed via `FLAGSHIP_GRAPH.extensions.fixtureFlowKeys`/`fixtureNodeKeys` semantic keys) — never synthetic data, per this repo's established discipline.

**Spec:** No formal spec document for this follow-up; it implements specific findings from the final whole-branch review of `docs/superpowers/plans/2026-08-30-data-flow-explorer-privacy-trace-views.md` (I2) and from that plan's fix-wave re-review (the two "non-blocking minor notes" about test coverage). Read `frontend/CLAUDE.md` first — it is the living module map and the authority on this directory's conventions.

## Global Constraints

- **No `innerHTML` with graph-derived content, ever.** Use `el()` (`frontend/src/lib/dom.js`) or `document.createTextNode`/`textContent`.
- **No new runtime dependency, no build tooling, no framework.** The zero-build-step decision is deliberate (see `frontend/README.md`).
- **Privacy View and Trace View use `el()` only, never `svgEl()`.** That SVG-only helper is Architecture View's alone (a deliberate departure made specifically to avoid the namespace-mismatch bug class documented in `frontend/CLAUDE.md`).
- **Every test must use the real `FLAGSHIP_GRAPH` fixture, never synthetic data.** Verify any fixture fact you assert on (an ID, a label, a verdict) by actually reading it from `frontend/src/data/flagship-graph.js` before writing the assertion — do not guess or copy a fact from this plan without confirming it still holds, since the fixture is regenerated from `scanner/src/lineage/fixtures/flagship-graph.json` and could in principle have drifted.
- **Run `cd frontend && npm test` after every task and report the exact pass/fail count from the run you just executed.** All existing tests must keep passing; this plan adds tests, it never weakens or removes an assertion from an existing one except where a task explicitly says to replace one.
- New test files must be added to `frontend/package.json`'s `test` script's explicit file list (it is not a glob) or `npm test` will silently never run them — this exact gap has bitten this project before (`filter-rail.test.js` was originally left out).

---

## Task 1: Trace View renders branching flows as real branch groups, not a false linear sequence

**Files:**
- Modify: `frontend/src/views/trace-view.js`
- Modify: `frontend/test/trace-view.test.js`
- Modify: `frontend/test/trace-view-render.test.js`
- Modify: `frontend/styles/trace-view.css`
- Modify: `frontend/CLAUDE.md` (the `trace-view.js` module-table row)

**Background:** `computeTraceSteps` iterates `flow.edgeIds` in array order and `renderTraceView` numbers every resulting step sequentially (1, 2, 3, ...). This is correct for a flow whose edges form a simple chain, but wrong for a flow that genuinely fans out — one node with more than one outgoing edge within the same flow. The real fixture has exactly this shape: flow `flow.phi.ai` (real id `flow:5eaf2ae939ad`, semantic key from `FLAGSHIP_GRAPH.extensions.fixtureFlowKeys`) is `Web App → AI Assistant`, then **AI Assistant branches to both Model Provider and Vector Store** (edges `edge:503be4d731cd` and `edge:7a1ec420d86a`, both with `from: "node:process:d09c75cee70b"` — the AI Assistant node). `flow.sink` for this flow is Model Provider, but the Vector Store branch is a real edge in `flow.edgeIds` too. Today this renders as four numbered steps in sequence (AI Assistant → Model Provider → Vector Store → sink=Model Provider again), which reads as if data visited Model Provider, then Vector Store, then arrived back at Model Provider — false, and confusing about which branch is the flow's declared sink. Confirm these facts yourself before starting (`node -e` against `frontend/src/data/flagship-graph.js`, same as this plan's author did) — do not trust this paragraph blindly.

**Interfaces:**
- Consumes: `computeTraceSteps(graph, flow)` (existing, in this same file) — its per-step objects for `kind: 'hop' | 'transformation' | 'propagation'` gain one new field, `fromNodeId` (the edge's `from` node id — the value used to detect a shared branch point). `kind: 'source'` and `kind: 'sink'` steps are unaffected.
- Produces: a new exported pure function `computeTraceStepGroups(steps)` — takes the flat array `computeTraceSteps` returns and groups it into an ordered array of `{ type: 'source', step } | { type: 'sink', step } | { type: 'sequential', step } | { type: 'branch', steps: [...] }`. `renderTraceView` is the only consumer for now.

- [ ] **Step 1: Add `fromNodeId` to `computeTraceSteps`'s hop/transformation/propagation step objects**

In `frontend/src/views/trace-view.js`, `computeTraceSteps` (currently lines 4-57): add `fromNodeId: edge.from` to the object pushed for the `mappings.length === 0` branch (currently lines 21-26) and to the object pushed inside the `for (const mapping of mappings)` loop (currently lines 34-44). Do not touch the `source` or `sink` step objects — they have no associated edge.

```js
    if (mappings.length === 0) {
      steps.push({
        kind: 'hop',
        node: toNode?.label ?? 'unknown',
        fromNodeId: edge.from,
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
        fromNodeId: edge.from,
        boundaryCrossing: (edge.boundaryCrossings ?? []).length > 0,
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
    }
```

- [ ] **Step 2: Write the failing tests for `fromNodeId` and the new grouping function**

Add to `frontend/test/trace-view.test.js` (it already imports `computeTraceSteps`, `computeAlternatePaths`, `computeTraceViewModel` from `../src/views/trace-view.js`, and already has `FLOW_KEYS`/`flowByKey` helpers at the top — add `computeTraceStepGroups` to the existing import line rather than adding a second import from the same module):

```js
test('computeTraceSteps tags every hop/transformation/propagation step with the edge\'s fromNodeId', () => {
  const flow = flowByKey('flow.phi.ai');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const middleSteps = steps.filter((s) => s.kind !== 'source' && s.kind !== 'sink');
  assert.equal(middleSteps.length, 3, 'expected 3 middle steps: Web App->AI Assistant, AI Assistant->Model Provider, AI Assistant->Vector Store');
  for (const step of middleSteps) {
    assert.ok(step.fromNodeId, 'expected every middle step to carry the edge\'s from-node id');
  }
});

test('computeTraceStepGroups groups the AI Assistant fan-out (flow.phi.ai) as one branch, not three sequential steps', () => {
  const flow = flowByKey('flow.phi.ai');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const groups = computeTraceStepGroups(steps);

  assert.equal(groups[0].type, 'source');
  assert.equal(groups[groups.length - 1].type, 'sink');

  const branchGroups = groups.filter((g) => g.type === 'branch');
  assert.equal(branchGroups.length, 1, 'expected exactly one branch group for the AI Assistant fan-out');
  assert.equal(branchGroups[0].steps.length, 2, 'expected both the Model Provider and Vector Store hops in the same branch group');
  const destinations = branchGroups[0].steps.map((s) => s.node).sort();
  assert.deepEqual(destinations, ['Model Provider', 'Vector Store']);

  const sequentialGroups = groups.filter((g) => g.type === 'sequential');
  assert.equal(sequentialGroups.length, 1, 'expected exactly one plain sequential step: Web App -> AI Assistant');
  assert.equal(sequentialGroups[0].step.node, 'AI Assistant');
});

test('computeTraceStepGroups produces zero branch groups for a non-branching flow', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const steps = computeTraceSteps(FLAGSHIP_GRAPH, flow);
  const groups = computeTraceStepGroups(steps);
  assert.equal(groups.filter((g) => g.type === 'branch').length, 0);
  assert.equal(groups.filter((g) => g.type === 'sequential').length, groups.length - 2, 'every non-source/sink group should be sequential when nothing branches');
});
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `cd frontend && node --test test/trace-view.test.js`
Expected: FAIL — `computeTraceStepGroups is not a function` (and the `fromNodeId` assertions fail too, since Step 1's field doesn't exist yet if you run tests before Step 1's edit; if you did Step 1 first, only the `computeTraceStepGroups` tests fail at this point, which is fine — just confirm the new tests genuinely exercise unwritten code before moving on).

- [ ] **Step 4: Implement `computeTraceStepGroups`**

Add to `frontend/src/views/trace-view.js`, exported, placed after `computeTraceSteps`:

```js
export function computeTraceStepGroups(steps) {
  const middleSteps = steps.filter((s) => s.kind !== 'source' && s.kind !== 'sink');
  const sourceStep = steps.find((s) => s.kind === 'source');
  const sinkStep = steps.find((s) => s.kind === 'sink');

  const groupsByFrom = new Map();
  for (const step of middleSteps) {
    if (!groupsByFrom.has(step.fromNodeId)) groupsByFrom.set(step.fromNodeId, []);
    groupsByFrom.get(step.fromNodeId).push(step);
  }

  const groups = [];
  if (sourceStep) groups.push({ type: 'source', step: sourceStep });
  for (const groupSteps of groupsByFrom.values()) {
    if (groupSteps.length > 1) {
      groups.push({ type: 'branch', steps: groupSteps });
    } else {
      groups.push({ type: 'sequential', step: groupSteps[0] });
    }
  }
  if (sinkStep) groups.push({ type: 'sink', step: sinkStep });
  return groups;
}
```

(`groupsByFrom` is a `Map`, which preserves insertion order — the order groups are pushed matches the order their first step was first seen in `middleSteps`, which is the order edges appear in `flow.edgeIds`. This is correct for the real fixture's shapes, including `flow.phi.ai`: the singleton Web App→AI Assistant group is seen first, then the AI Assistant branch group.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && node --test test/trace-view.test.js`
Expected: PASS, all tests including the 3 new ones.

- [ ] **Step 6: Update the render path to consume groups instead of the flat step array**

In `frontend/src/views/trace-view.js`, replace the step-rendering loop inside `renderTraceView` (currently):

```js
  const container = el('div', { class: 'trace-view' });
  viewModel.steps.forEach((step, i) => {
    container.appendChild(renderTraceStep(step, i + 1));
  });
```

with:

```js
  const container = el('div', { class: 'trace-view' });
  const groups = computeTraceStepGroups(viewModel.steps);
  let stepNumber = 0;
  for (const group of groups) {
    stepNumber += 1;
    if (group.type === 'branch') {
      container.appendChild(renderTraceBranchGroup(group.steps, stepNumber));
    } else {
      container.appendChild(renderTraceStep(group.step, String(stepNumber)));
    }
  }
```

Add a new function, placed near `renderTraceStep`:

```js
function renderTraceBranchGroup(steps, number) {
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  const items = steps.map((step, i) => renderTraceStep(step, `${number}${letters[i]}`));
  return el('div', { class: 'trace-branch-group' }, [
    el('div', { class: 'trace-branch-label' }, `${steps.length} branches from here`),
    ...items,
  ]);
}
```

Change `renderTraceStep`'s signature: it currently takes `(step, number)` and does `String(number)` when building the number badge (currently the last line: `el('div', { class: 'trace-step-number' }, String(number))`). Since every caller now already passes a string (`String(stepNumber)` for a plain step, `` `${number}${letters[i]}` `` for a branch member), rename the parameter to `label` and drop the `String(...)` wrapper — pass `label` directly to `el(...)`.

- [ ] **Step 7: Add minimal CSS for the new branch-group wrapper**

Read `frontend/styles/trace-view.css` first — it already defines `.trace-step`, `.trace-step-number`, `.trace-step-body`, etc. using this file's design-token variables (`var(--space-2)`, `var(--surface-panel)`, `var(--border-default)`, `var(--radius-default)`, etc. — check `frontend/styles/tokens.css` for the full token list before picking values). Add two new rules, consistent with the existing token usage: `.trace-branch-group` should visually read as "these steps are alternatives/siblings, not a continuation" — e.g. a left border or indent distinguishing it from a plain `.trace-step`, with the same `gap`/`flex-direction: column` pattern the file already uses for `.trace-view`. `.trace-branch-label` should read as a small secondary caption (follow the pattern already used by `.trace-step-kind` or `.trace-alternate-item` for secondary/muted text). Keep it minimal — this is a follow-up test-and-correctness plan, not a visual redesign.

- [ ] **Step 8: Add a render-level regression test for the branch grouping**

Add to `frontend/test/trace-view-render.test.js` (it already sets up the `dom-shim` + real fixture pattern at the top — reuse `FLOW_KEYS`, `FLAGSHIP_GRAPH`, `computeTraceViewModel`, `renderTraceView`, which are already imported/defined there):

```js
test('renderTraceView shows the AI Assistant fan-out (flow.phi.ai) as one branch group with lettered sub-steps, not implied sequence (I2 regression)', () => {
  const flowId = FLOW_KEYS['flow.phi.ai'];
  const state = { view: 'trace', selectedId: flowId, filters: {} };
  const viewModel = computeTraceViewModel(FLAGSHIP_GRAPH, state);
  assert.ok(viewModel, 'expected a trace view model for this flow');

  const canvasEl = document.createElement('div');
  renderTraceView(viewModel, canvasEl, () => {});

  const container = canvasEl.firstChild;
  const branchGroupEls = [...container.childNodes].filter((n) => n.className === 'trace-branch-group');
  assert.equal(branchGroupEls.length, 1, 'expected exactly one rendered branch-group container');

  const branchGroupEl = branchGroupEls[0];
  const stepEls = [...branchGroupEl.childNodes].filter((n) => n.className === 'trace-step');
  assert.equal(stepEls.length, 2, 'expected both branch destinations rendered as sibling steps inside the branch group');

  const stepNumberTexts = stepEls.map((s) => s.childNodes[0].textContent);
  assert.ok(stepNumberTexts.every((t) => /^\d+[a-z]$/.test(t)), `expected lettered sub-step numbers (e.g. "3a"), got: ${stepNumberTexts.join(', ')}`);
  const baseNumbers = new Set(stepNumberTexts.map((t) => t.match(/^(\d+)/)[1]));
  assert.equal(baseNumbers.size, 1, 'both branch destinations must share the same base step number');

  const destinationTexts = stepEls.map((s) => s.textContent);
  assert.ok(destinationTexts.some((t) => t.includes('Model Provider')));
  assert.ok(destinationTexts.some((t) => t.includes('Vector Store')));
});
```

(Adjust the exact DOM-walking details — `.childNodes`, `.className` — to match whatever `dom-shim.js` actually supports; the existing tests in this same file already demonstrate the working pattern for walking a rendered tree with this shim, so mirror that rather than guessing at shim capabilities.)

- [ ] **Step 9: Run the full frontend test suite**

Run: `cd frontend && npm test`
Expected: PASS, every test including all the new ones in this task.

- [ ] **Step 10: Update `frontend/CLAUDE.md`'s `trace-view.js` module-table row**

Add a sentence describing the new grouping behavior — a branching flow's steps sharing one `from` node render as one labeled branch group with lettered sub-step numbers (e.g. "3a"/"3b"), not a false linear sequence — and name the real fixture example (`flow.phi.ai`, AI Assistant fanning out to Model Provider and Vector Store). Keep the rest of the row's existing content intact; this is an addition, not a rewrite.

- [ ] **Step 11: Commit**

```bash
git add frontend/src/views/trace-view.js frontend/test/trace-view.test.js frontend/test/trace-view-render.test.js frontend/styles/trace-view.css frontend/CLAUDE.md
git commit -m "fix(frontend): Trace View groups branching flows instead of a false linear sequence (I2)"
```

---

## Task 2: Test-quality follow-ups from the fix-wave re-review

**Files:**
- Create: `frontend/test/flow-summary-render.test.js`
- Modify: `frontend/test/privacy-view-render.test.js`
- Modify: `frontend/package.json`

**Background:** The Privacy/Trace Views plan's fix-wave re-review confirmed all its fixes were correct, but flagged two non-blocking gaps for a future pass: (1) `renderFlowSummary()` (`frontend/src/views/architecture-view.js`) — the function that finally gave `computeFlowSummary` a real consumer — has zero test coverage of its own; only a live CDP check proved it renders. (2) The existing Privacy View protection-verdict regression test (`frontend/test/privacy-view-render.test.js`) only asserts each row's protection cell is non-empty and isn't the `'—'` placeholder — it would still pass if every row rendered the *wrong* verdict, as long as that wrong verdict was some non-empty text.

**Interfaces:**
- Consumes: `computeArchitectureViewModel(graph, state)` and `renderFlowSummary(flowSummary, contextRailEl)` (both exported from `frontend/src/views/architecture-view.js`, both already exist and are unchanged by this task). `protectionVisual(verdict)` (exported from `frontend/src/lib/protection-visual.js`, unchanged).
- Produces: nothing new for other code — this task is test-only.

- [ ] **Step 1: Confirm the real fixture facts this task's tests rely on**

Before writing any test, run something equivalent to:

```bash
cd frontend && node -e '
import("./src/data/flagship-graph.js").then(({FLAGSHIP_GRAPH}) => {
  const g = FLAGSHIP_GRAPH;
  const flowId = g.extensions.fixtureFlowKeys["flow.pci.payment_api"];
  const flow = g.flows.find(f => f.id === flowId);
  console.log("flow:", JSON.stringify(flow, null, 2));
});
'
```

and confirm for yourself (do not trust this plan\'s prose alone): the real `dataElementName` for `flow.pci.payment_api`, its `sourceLabel`/`destinationLabel`, its `protectedCount`, and that its `transitVerdict` really is `'unprotected'` (this is the same flow the Task-1-adjacent fix-wave used for the C1 regression test — its Payments Service → Payment API edge has `transit.verdict === 'unprotected'`, and since `worstVerdict` prioritizes `'unprotected'` above every other tier, the whole flow's `transitVerdict` must also be `'unprotected'` regardless of its other edges — confirm this is still true in the fixture you actually have, not just true in this plan).

- [ ] **Step 2: Write `frontend/test/flow-summary-render.test.js`**

```js
// Render-level regression test for I3 in the Privacy/Trace Views plan's
// final whole-branch review: computeFlowSummary() (architecture-view.js)
// was fully computed into viewModel.flowSummary whenever a flow was
// selected, but nothing rendered it -- confirmed dead code at the time via
// `grep -rn flowSummary frontend/src`. The fix-wave gave it a real
// consumer, renderFlowSummary(), wired into the shell's context rail by
// app.js -- but renderFlowSummary() itself has never had a dedicated
// render-level test (flagged as a non-blocking follow-up by the fix-wave's
// own re-review: only a live CDP check proved it actually renders). This
// file closes that gap: same dependency-free `document` shim
// (test/dom-shim.js) and real fixture pattern as every other
// *-render.test.js in this directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderFlowSummary } = await import('../src/views/architecture-view.js');

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

test('renderFlowSummary renders the real selected flow\'s data element, path, counts, and dimension verdicts', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const state = { view: 'architecture', selectedId: flowId, filters: {} };
  const viewModel = computeArchitectureViewModel(FLAGSHIP_GRAPH, state);
  assert.ok(viewModel.flowSummary, 'expected a computed flow summary for this selection');
  assert.equal(viewModel.flowSummary.transitVerdict, 'unprotected', 'fixture assumption this test relies on');

  const contextRailEl = document.createElement('div');
  renderFlowSummary(viewModel.flowSummary, contextRailEl);

  const text = contextRailEl.textContent;
  assert.ok(text.includes(viewModel.flowSummary.dataElementName), 'expected the real data element name to render');
  assert.ok(text.includes(`${viewModel.flowSummary.sourceLabel} → ${viewModel.flowSummary.destinationLabel}`), 'expected the real source->destination path to render');
  assert.ok(text.includes(`${viewModel.flowSummary.protectedCount} protected`), 'expected the real protected-edge count to render');
  assert.match(text, /Transit: Unprotected/, 'the real unprotected transitVerdict must render, not be silently dropped');
});

test('renderFlowSummary(null, ...) clears the context rail rather than leaving stale content', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const state = { view: 'architecture', selectedId: flowId, filters: {} };
  const viewModel = computeArchitectureViewModel(FLAGSHIP_GRAPH, state);

  const contextRailEl = document.createElement('div');
  renderFlowSummary(viewModel.flowSummary, contextRailEl);
  assert.ok(contextRailEl.childNodes.length > 0, 'sanity: the rail actually had content before clearing');

  renderFlowSummary(null, contextRailEl);
  assert.equal(contextRailEl.childNodes.length, 0, 'renderFlowSummary(null, ...) must clear stale content — app.js relies on this to avoid showing a stale flow summary after deselecting or switching views');
});
```

(If `createDomShim()`'s `document.createElement('div').textContent` getter doesn't concatenate all descendant text the way you expect, check how `trace-view-render.test.js` or `privacy-view-render.test.js` read rendered text and mirror that instead of assuming.)

- [ ] **Step 3: Run the new test file to verify it passes against the existing (already-correct) `renderFlowSummary`**

Run: `cd frontend && node --test test/flow-summary-render.test.js`
Expected: PASS — `renderFlowSummary` was already implemented correctly by the earlier fix wave; this step is confirming the new test is accurate, not driving new production code. If it fails, the test has a wrong assumption about the fixture or the render output — fix the test, not the (already-reviewed-correct) production code, unless you find an actual bug in `renderFlowSummary` while doing this (if so, note it clearly in your report; do not silently fix production code beyond this task's stated scope without flagging it).

- [ ] **Step 4: Tighten the existing I7 regression test in `frontend/test/privacy-view-render.test.js`**

Replace the first test in that file (currently named `'renderPrivacyView gives every row a non-empty, non-placeholder protection verdict cell (Fix 3b regression)'`) with a version that checks the cell's text matches the row's REAL `protectionSummary`, not just that it's non-empty:

```js
import { protectionVisual } from '../src/lib/protection-visual.js';

// ... (keep the existing findByClassName helper and other imports as-is)

test('renderPrivacyView shows the CORRECT protection verdict per row, not just a non-empty one (tightened Fix 3b regression)', () => {
  const canvasEl = document.createElement('div');
  const viewModel = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(viewModel, canvasEl, () => {});

  const protectionCells = findByClassName(canvasEl, 'privacy-protection-cell');
  assert.equal(protectionCells.length, viewModel.rows.length, 'expected one protection cell per row, in row order');
  assert.ok(protectionCells.length >= 8, 'sanity: the real fixture has 8 flows');

  viewModel.rows.forEach((row, i) => {
    const expected = protectionVisual(row.protectionSummary);
    const text = protectionCells[i].textContent.trim();
    assert.equal(text, `${expected.glyph} ${expected.label}`, `row ${row.flowId}'s protection cell must show its real protectionSummary (${row.protectionSummary}), not just any non-empty text`);
  });
});
```

Confirm `protectionCells[i]` really does correspond to `viewModel.rows[i]` before relying on this — read `renderPrivacyView`/`renderPrivacyRow` in `frontend/src/views/privacy-view.js` to confirm rows render in `viewModel.rows` array order (they do, as of the current code — `renderPrivacyView` does `viewModel.rows.map((row) => renderPrivacyRow(row, onSelectFlow))` — but confirm this hasn't changed before trusting it). Add the `protectionVisual` import at the top of the test file alongside the existing imports; do not duplicate an existing import line.

Keep the file's second test (`'renderPrivacyView surfaces retention/deletion governance facts...'`) exactly as-is — it is already precise and out of scope for this task.

- [ ] **Step 5: Run the tightened test to verify it passes**

Run: `cd frontend && node --test test/privacy-view-render.test.js`
Expected: PASS. If it fails, that means the real rendered text doesn't exactly match `` `${glyph} ${label}` `` — inspect the actual rendered `textContent` and adjust the assertion's expected format to match reality (do not weaken the assertion back to a non-empty check to make it pass).

- [ ] **Step 6: Wire the new test file into `npm test`**

In `frontend/package.json`'s `"test"` script (an explicit space-separated file list, not a glob), add `test/flow-summary-render.test.js` to the list. Place it near the other `architecture-view*` entries for readability, though exact position doesn't matter functionally.

- [ ] **Step 7: Run the full frontend test suite**

Run: `cd frontend && npm test`
Expected: PASS, every test including the new file and the tightened assertion.

- [ ] **Step 8: Commit**

```bash
git add frontend/test/flow-summary-render.test.js frontend/test/privacy-view-render.test.js frontend/package.json
git commit -m "test(frontend): add renderFlowSummary render-level coverage, tighten I7 protection-verdict regression test"
```

---

## Self-Review Notes (from the plan author)

- **Spec coverage:** I2 (Task 1) and both fix-wave re-review minor notes (Task 2) are covered. The third minor note from that re-review — the identity ternary that disappeared as a byproduct of the I7 fix — required no action (it was a byproduct, not a live defect) and is not a task here.
- **Explicitly out of scope, confirmed not touched by either task:** the 8 Minor findings from the original final whole-branch review (identity ternary already resolved as noted above; various doc nits; `shell.js`'s stale placeholder strings; Trace View's empty-state wording; governance badge colors; Trace View repeating the sink node) remain untouched — neither task's file list overlaps them.
- **Type/interface consistency check:** `computeTraceStepGroups`'s return shape (`{type, step}` for source/sink/sequential, `{type, steps}` for branch) is used consistently between Task 1 Step 4 (implementation) and Step 6 (render consumption) and Step 2/8's tests. `renderTraceStep`'s parameter rename from `number` to `label` is applied at both its definition and both call sites in the same step.
