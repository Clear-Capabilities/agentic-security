# Data Flow Explorer — Architecture View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first of the Data Flow Explorer's three real views — Architecture View — plus the shared components every later view reuses: a verdict-visual vocabulary (the AC-20 "never color alone" enforcement point) and the evidence inspector (PRD §16's four-question sequence). Wire it all into the `AppShell` foundation so the prototype genuinely renders the flagship fixture, not a placeholder.

**Architecture:** All new code lives under `frontend/`, continuing the zero-build-step, plain-ES-modules approach (no bundler, no TypeScript, no graph library — this view's layout is a small, deterministic, hand-rolled trust-zone-column algorithm, not ELK/Cytoscape, since 14 nodes doesn't warrant either and that evaluation is explicitly Milestone 3's per the foundation plan's own README). Every view module splits into a **pure view-model function** (takes the graph + shell state, returns plain data — fully unit-tested, no DOM) and a **thin render function** (takes the view-model, mounts real DOM/SVG — browser-only, following the `dom.js`/`shell.js` precedent of verification via a dependency-free DOM shim plus a manual browser smoke check, not jsdom). This split is what makes the actual decision logic (which nodes highlight, which verdict wins an aggregation, what the evidence inspector says) testable without a browser, while keeping the DOM-touching code honestly thin.

**Tech Stack:** Plain ES modules, hand-rolled SVG (via the existing `el()` DOM builder, which works for SVG elements too as long as `document.createElementNS` is used for the SVG namespace — see Task 3), `node:test` plus the existing `frontend/test/dom-shim.js` for DOM-touching tests, zero new dependencies.

**Spec:** The Data Flow Explorer PRD (untracked root working document, not present on disk between sessions — this plan embeds every value it needs, re-verified against the real, merged `frontend/src/data/flagship-graph.js` on `main`, not from memory of the PRD's abstract prose). Implements PRD §7.8 (Architecture View screen blueprint), §8 (visual grammar / AC-20), §16 (evidence inspector), and the AC-16 (cross-view selection) wiring the prior plan's `mountShell()` state API exists to serve.

## Global Constraints

- **Zero build step, no new dependencies** — continues the prior plan's architecture decision. No graph/SVG library.
- **Every module that makes a decision (zone assignment, verdict aggregation, selection highlighting, evidence-claim text) is a pure function, unit-tested against the REAL `FLAGSHIP_GRAPH` data** (imported from `frontend/src/data/flagship-graph.js`), not synthetic stand-in data — this is the only way a test can catch drift if the backend fixture regenerates with a different shape.
- **The real fixture's exact current shape** (verified directly against `frontend/src/data/flagship-graph.js` on `main` at plan-writing time): 14 nodes (kinds present: `source`×1, `api`×1, `process`×5, `store`×2, `log`×1, `external`×3, `unresolved`×1), 15 edges, 8 flows, 3 dataElements (`card_number`/PCI, `diagnosis`/PHI, `email`/PII — note `dataClasses` values are UPPERCASE strings), 1 transformation, 4 evidence items. Flow objects use flat `source`/`sink` fields (not `sourceNodeId`/`sinkNodeId`) and flat `policyVerdict`/`protectionSummary` fields. Edge `protection` has three dimensions (`transit`/`atRest`/`handling`), each `{verdict, evidenceGrade}`. `graph.extensions.fixtureNodeKeys`/`fixtureFlowKeys` map the PRD Appendix D stable keys (`node.web`, `flow.pci.masked_log`, etc.) to real canonical IDs — use these in tests instead of hardcoding raw hash-suffixed IDs, since regenerating the fixture changes the hashes but not the keys.
- **Two real nodes in the current fixture have zero edges touching them**: `node.retention` and `node.deletion` (governance processes with no modeled data-carrying edge — confirmed by reading the fixture directly). This is a genuine, useful "disconnected node" case (AC-11) — do not treat it as a bug to route around; the Architecture View must still render them (in their zone column, unhighlighted, with no incident edges).
- **No `dataElement.aiContexts` value is populated anywhere in the current fixture** (`classification.js`'s AI-context detection deliberately never guesses AI relevance from a field name alone — see the merged Milestone-0 contract's own documentation). Do not build any "AI" concept in this plan against `dataElement.aiContexts` — it will show zero results. This plan does not need an AI filter at all (that's explicitly deferred to the follow-up filter-rail plan, which will need to derive AI-relevance from flow/node topology instead, e.g. whether a flow's path touches `node.ai`/`node.model`).
- **Verdict aggregation precedence** (PRs §8.4, exact quoted order): "unprotected/prohibited → mixed → unknown/manual_required → protected/permitted → not_assessed" — read as *display priority when summarizing multiple underlying verdicts into one*, not a raw severity ranking: if ANY constituent is unprotected, show unprotected; else if any is mixed, show mixed; else unknown; else protected; `not_assessed` is lowest priority (shown only when there is no other signal at all). `not_applicable` is not in the PRD's list — treat it at the same lowest priority as `not_assessed` (both mean "no real information to prioritize").
- **AC-20 (verdicts distinguishable without color)**: every verdict must render with a distinct text label AND a distinct glyph/icon AND a distinct line style — color is never the only differentiator. This is enforced by making `protectionVisual()` (Task 1) the single source of truth every later view/component calls — never let a view hardcode a color or glyph for a verdict independently.
- **Selection/highlighting is shared logic, not per-view**: computing "which nodes/edges are part of the current selection" is the same algorithm whether the selection is a node, edge, or flow ID — implement it once (Task 2's `resolveSelection`), not duplicated per view.
- **This plan does not include**: the left-rail filter chips (§7.8's "Left rail" content — deferred to the follow-up plan alongside Privacy/Trace views, since filter infrastructure is genuinely shared across all three and is cleaner to build once all three views' filtering needs are known), golden-image pixel regression testing (DFG-034, its own later backlog item, consistent with the prior plan's scoping), and semantic zoom/large-graph performance work (Milestone 3, gated on real performance numbers this 14-node fixture can't produce).
- Follow this repo's `git commit` convention: commit after each task with a descriptive message.

---

## File Structure

```
frontend/src/lib/
  protection-visual.js          # new — Task 1: verdict → {label, glyph, lineStyle, colorVar}

frontend/src/views/
  architecture-view.js          # new — Task 2 (pure view-model) + Task 3 (SVG render)

frontend/src/components/
  evidence-inspector.js         # new — Task 4: pure view-model + thin render

frontend/src/
  app.js                        # new — Task 5: wires shell + architecture view + inspector together

frontend/styles/
  architecture-view.css         # new — Task 3
  inspector.css                 # new — Task 4

frontend/index.html             # modify — Task 5: point the bootstrap script at app.js
frontend/src/shell.js           # modify — Task 5: add getContextRailEl() (small, additive)

frontend/test/
  protection-visual.test.js         # new — Task 1
  architecture-view.test.js         # new — Task 2 (pure logic only)
  evidence-inspector.test.js        # new — Task 4 (pure logic only)
  shell.test.js                     # modify — Task 5: one new test for getContextRailEl()

frontend/CLAUDE.md              # modify — Task 6
frontend/package.json           # modify — Task 6: add new test files to the `test` script
```

---

### Task 1: Protection-verdict visual vocabulary

**Files:**
- Create: `frontend/src/lib/protection-visual.js`
- Test: `frontend/test/protection-visual.test.js`

**Interfaces:**
- Produces: `protectionVisual(verdict) → {verdict, label, glyph, lineStyle, colorVar}` where `lineStyle` is one of `'solid'|'dashed'|'dotted'` and `colorVar` is a CSS custom-property name string (e.g. `'--status-protected'`) matching `frontend/styles/tokens.css`'s existing tokens. Also produces `VERDICT_PRECEDENCE` (the ordered array used for aggregation) and `worstVerdict(verdicts: string[]) → string`. Consumed by Task 2 (edge/flow aggregation), Task 3 (SVG styling), Task 4 (inspector badges).

- [ ] **Step 1: Write the failing test**

Create `frontend/test/protection-visual.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { protectionVisual, worstVerdict, VERDICT_PRECEDENCE } from '../src/lib/protection-visual.js';

test('protectionVisual returns a distinct label, glyph, and line style for every known verdict', () => {
  const verdicts = ['protected', 'unprotected', 'mixed', 'unknown', 'not_applicable', 'not_assessed'];
  const seen = new Set();
  for (const v of verdicts) {
    const visual = protectionVisual(v);
    assert.equal(visual.verdict, v);
    assert.ok(visual.label && visual.label.length > 0, `${v} needs a label`);
    assert.ok(visual.glyph && visual.glyph.length > 0, `${v} needs a glyph`);
    assert.ok(['solid', 'dashed', 'dotted'].includes(visual.lineStyle), `${v} needs a valid lineStyle`);
    assert.ok(visual.colorVar.startsWith('--'), `${v} needs a CSS custom-property colorVar`);
    const dedupeKey = `${visual.label}|${visual.glyph}|${visual.lineStyle}`;
    assert.ok(!seen.has(dedupeKey), `${v}'s label+glyph+lineStyle combination "${dedupeKey}" collides with an earlier verdict — AC-20 requires every verdict distinguishable without relying on color`);
    seen.add(dedupeKey);
  }
});

test('protectionVisual falls back to the not_assessed visual for an unrecognized verdict rather than throwing', () => {
  const visual = protectionVisual('some-future-verdict-not-yet-known');
  assert.equal(visual.verdict, 'not_assessed');
});

test('worstVerdict picks unprotected over everything else', () => {
  assert.equal(worstVerdict(['protected', 'unknown', 'unprotected']), 'unprotected');
});

test('worstVerdict picks mixed when present and no unprotected', () => {
  assert.equal(worstVerdict(['protected', 'mixed', 'not_assessed']), 'mixed');
});

test('worstVerdict picks unknown over protected and not_assessed', () => {
  assert.equal(worstVerdict(['protected', 'unknown', 'not_assessed']), 'unknown');
});

test('worstVerdict prefers protected over not_assessed (a real signal beats no signal)', () => {
  assert.equal(worstVerdict(['not_assessed', 'protected']), 'protected');
});

test('worstVerdict returns not_assessed only when nothing else is present', () => {
  assert.equal(worstVerdict(['not_assessed', 'not_applicable']), 'not_assessed');
});

test('worstVerdict on an empty array returns not_assessed rather than throwing', () => {
  assert.equal(worstVerdict([]), 'not_assessed');
});

test('VERDICT_PRECEDENCE is exported and matches the PRD 8.4 order (unprotected, mixed, unknown, protected, then the no-signal states)', () => {
  assert.deepEqual(VERDICT_PRECEDENCE.slice(0, 4), ['unprotected', 'mixed', 'unknown', 'protected']);
  assert.ok(VERDICT_PRECEDENCE.includes('not_assessed'));
  assert.ok(VERDICT_PRECEDENCE.includes('not_applicable'));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/protection-visual.test.js`
Expected: FAIL — `Cannot find module '../src/lib/protection-visual.js'`

- [ ] **Step 3: Write `frontend/src/lib/protection-visual.js`**

```js
// The single source of truth for how a protection verdict renders — every
// view/component must call protectionVisual() rather than hardcoding a
// color or glyph, so AC-20 (verdicts distinguishable without color) holds
// everywhere by construction, not by convention.
//
// These verdict strings are NOT imported from scanner/src/lineage/protection.js
// — the browser bundle never imports anything under scanner/src/lineage/ at
// runtime (see frontend/CLAUDE.md). Keep this list in sync by hand if the
// backend's PROTECTION_VERDICTS/FLOW_SUMMARY_VALUES enums ever change.

// PRD §8.4, exact quoted precedence: "unprotected/prohibited → mixed →
// unknown/manual_required → protected/permitted → not_assessed". Read as
// display priority when aggregating multiple verdicts into one, not a raw
// severity order: not_assessed is LOWEST priority because it means "no
// information," and any real signal (even a protected one) should be shown
// instead of "not assessed." not_applicable isn't named in the PRD list;
// treated at the same lowest priority as not_assessed (both mean "nothing
// to prioritize").
export const VERDICT_PRECEDENCE = Object.freeze([
  'unprotected',
  'mixed',
  'unknown',
  'protected',
  'not_applicable',
  'not_assessed',
]);

const VISUALS = Object.freeze({
  protected: { verdict: 'protected', label: 'Protected', glyph: '✓', lineStyle: 'solid', colorVar: '--status-protected' },
  unprotected: { verdict: 'unprotected', label: 'Unprotected', glyph: '✗', lineStyle: 'solid', colorVar: '--status-unprotected' },
  mixed: { verdict: 'mixed', label: 'Mixed', glyph: '±', lineStyle: 'solid', colorVar: '--status-unprotected' },
  unknown: { verdict: 'unknown', label: 'Unknown', glyph: '?', lineStyle: 'dashed', colorVar: '--status-unknown' },
  not_applicable: { verdict: 'not_applicable', label: 'Not applicable', glyph: '·', lineStyle: 'dotted', colorVar: '--text-secondary' },
  not_assessed: { verdict: 'not_assessed', label: 'Not assessed', glyph: '–', lineStyle: 'dotted', colorVar: '--status-unknown' },
});

export function protectionVisual(verdict) {
  return VISUALS[verdict] ?? VISUALS.not_assessed;
}

export function worstVerdict(verdicts) {
  for (const tier of VERDICT_PRECEDENCE) {
    if (verdicts.includes(tier)) return tier;
  }
  return 'not_assessed';
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/protection-visual.test.js`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/protection-visual.js frontend/test/protection-visual.test.js
git commit -m "feat(frontend): add the protection-verdict visual vocabulary (AC-20)"
```

---

### Task 2: Architecture View — pure view-model

**Files:**
- Create: `frontend/src/views/architecture-view.js` (this task writes the pure half only; Task 3 appends the render half to the same file)
- Test: `frontend/test/architecture-view.test.js`

**Interfaces:**
- Consumes: `protectionVisual`, `worstVerdict` (Task 1).
- Produces: `ZONE_ORDER` (array of 5 zone-name strings), `zoneForNode(node) → string`, `resolveSelection(graph, selectedId) → {active, nodeIds: Set, edgeIds: Set, flow}`, `computeFlowSummary(graph, flow) → {...}`, `computeArchitectureViewModel(graph, state) → {zones, nodes, edges, flowSummary}`. All pure. `computeArchitectureViewModel` is consumed by Task 3's `renderArchitectureView` and by Task 5's `app.js`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/architecture-view.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import {
  ZONE_ORDER, zoneForNode, resolveSelection, computeFlowSummary, computeArchitectureViewModel,
} from '../src/views/architecture-view.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

test('ZONE_ORDER has the five PRD-named trust zones in order', () => {
  assert.deepEqual(ZONE_ORDER, ['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone']);
});

test('zoneForNode maps every kind present in the real fixture to one of the five zones', () => {
  for (const node of FLAGSHIP_GRAPH.nodes) {
    assert.ok(ZONE_ORDER.includes(zoneForNode(node)), `node ${node.id} (kind ${node.kind}) mapped to an unknown zone`);
  }
});

test('zoneForNode places the web source in Public Internet and the API gateway in Application Layer', () => {
  const web = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.web']);
  const gateway = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.gateway']);
  assert.equal(zoneForNode(web), 'Public Internet');
  assert.equal(zoneForNode(gateway), 'Application Layer');
});

test('zoneForNode places external and unresolved nodes in External Zone', () => {
  const paymentApi = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.payment_api']);
  const unresolved = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.unresolved']);
  assert.equal(zoneForNode(paymentApi), 'External Zone');
  assert.equal(zoneForNode(unresolved), 'External Zone');
});

test('computeArchitectureViewModel zones partition all 14 real nodes with no duplicates and no omissions', () => {
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  const allZoneNodeIds = vm.zones.flatMap((z) => z.nodeIds);
  assert.equal(allZoneNodeIds.length, FLAGSHIP_GRAPH.nodes.length);
  assert.equal(new Set(allZoneNodeIds).size, FLAGSHIP_GRAPH.nodes.length);
});

test('computeArchitectureViewModel with no selection: nothing is selected or dimmed', () => {
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  assert.ok(vm.nodes.every((n) => !n.selected && !n.dimmed));
  assert.ok(vm.edges.every((e) => !e.selected && !e.dimmed));
  assert.equal(vm.flowSummary, null);
});

test('resolveSelection on a flow ID includes its source and sink nodes and every one of its edges', () => {
  const maskedLogFlowId = FLOW_KEYS['flow.pci.masked_log'];
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === maskedLogFlowId);
  const selection = resolveSelection(FLAGSHIP_GRAPH, maskedLogFlowId);
  assert.ok(selection.active);
  assert.equal(selection.edgeIds.size, flow.edgeIds.length);
  for (const edgeId of flow.edgeIds) assert.ok(selection.edgeIds.has(edgeId));
  assert.ok(selection.nodeIds.has(flow.source));
  assert.ok(selection.nodeIds.has(flow.sink));
});

test('computeArchitectureViewModel dims every node/edge NOT part of a selected flow', () => {
  const rawLogFlowId = FLOW_KEYS['flow.pci.raw_log'];
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === rawLogFlowId);
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: rawLogFlowId, filters: {} });
  const selectedNodeCount = vm.nodes.filter((n) => n.selected).length;
  const dimmedNodeCount = vm.nodes.filter((n) => n.dimmed).length;
  assert.ok(selectedNodeCount > 0 && selectedNodeCount < FLAGSHIP_GRAPH.nodes.length, 'a flow selection should highlight some but not all nodes');
  assert.equal(selectedNodeCount + dimmedNodeCount, FLAGSHIP_GRAPH.nodes.length);
  assert.notEqual(vm.flowSummary, null);
  assert.equal(vm.flowSummary.flowId, rawLogFlowId);
});

test('resolveSelection on a node ID selects just that node plus its incident edges', () => {
  const webId = NODE_KEYS['node.web'];
  const selection = resolveSelection(FLAGSHIP_GRAPH, webId);
  assert.deepEqual([...selection.nodeIds], [webId]);
  const expectedEdgeCount = FLAGSHIP_GRAPH.edges.filter((e) => e.from === webId || e.to === webId).length;
  assert.equal(selection.edgeIds.size, expectedEdgeCount);
  assert.ok(expectedEdgeCount > 0, 'sanity check: the web node should have at least one incident edge in this fixture');
});

test('resolveSelection on the disconnected retention node selects it with zero edges, not an error', () => {
  const retentionId = NODE_KEYS['node.retention'];
  const selection = resolveSelection(FLAGSHIP_GRAPH, retentionId);
  assert.deepEqual([...selection.nodeIds], [retentionId]);
  assert.equal(selection.edgeIds.size, 0, 'node.retention has no modeled edges in the real fixture — this is a genuine disconnected-node case (AC-11), not a bug');
});

test('resolveSelection on an unknown ID returns an inactive selection rather than throwing', () => {
  const selection = resolveSelection(FLAGSHIP_GRAPH, 'node:this-id-does-not-exist');
  assert.equal(selection.active, false);
});

test('resolveSelection on null returns an inactive selection', () => {
  const selection = resolveSelection(FLAGSHIP_GRAPH, null);
  assert.equal(selection.active, false);
});

test('computeFlowSummary for the raw-log PCI flow reports it as unprotected with an internal-only recipient', () => {
  const rawLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.raw_log']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, rawLogFlow);
  assert.equal(summary.dataElementName, 'card_number');
  assert.deepEqual(summary.dataClasses, ['PCI']);
  assert.equal(summary.protectionSummary, 'unprotected');
  assert.deepEqual(summary.externalRecipients, [], 'the raw-log flow stays internal — Application Logs is not external');
});

test('computeFlowSummary for the payment-API PCI flow reports an external recipient', () => {
  const paymentApiFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.payment_api']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, paymentApiFlow);
  assert.ok(summary.externalRecipients.length > 0, 'the payment-API flow should surface Payment API as an external recipient');
});

test('computeFlowSummary aggregates per-dimension verdicts using worstVerdict across the flow\\'s own edges', () => {
  const maskedLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.masked_log']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, maskedLogFlow);
  assert.equal(summary.handlingVerdict, 'protected', 'the masked-log flow\\'s handling dimension should reflect the proven maskCard() protection');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: FAIL — `Cannot find module '../src/views/architecture-view.js'`

- [ ] **Step 3: Write `frontend/src/views/architecture-view.js`**

```js
import { worstVerdict } from '../lib/protection-visual.js';

export const ZONE_ORDER = Object.freeze(['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone']);

export function zoneForNode(node) {
  switch (node.kind) {
    case 'source':
      return 'Public Internet';
    case 'api':
      return 'Application Layer';
    case 'process':
    case 'transform':
      return 'Service Layer';
    case 'store':
    case 'log':
    case 'queue':
    case 'sink':
      return 'Data Layer';
    case 'external':
    case 'unresolved':
      return 'External Zone';
    default:
      // boundary, or any future kind not yet mapped: a safe internal default
      // rather than silently dropping the node from every zone.
      return 'Service Layer';
  }
}

export function resolveSelection(graph, selectedId) {
  const empty = { active: false, nodeIds: new Set(), edgeIds: new Set(), flow: null };
  if (!selectedId) return empty;

  const flow = graph.flows.find((f) => f.id === selectedId);
  if (flow) {
    const edgeIds = new Set(flow.edgeIds);
    const nodeIds = new Set();
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) {
        nodeIds.add(edge.from);
        nodeIds.add(edge.to);
      }
    }
    nodeIds.add(flow.source);
    nodeIds.add(flow.sink);
    return { active: true, nodeIds, edgeIds, flow };
  }

  const node = graph.nodes.find((n) => n.id === selectedId);
  if (node) {
    const edgeIds = new Set(graph.edges.filter((e) => e.from === selectedId || e.to === selectedId).map((e) => e.id));
    return { active: true, nodeIds: new Set([selectedId]), edgeIds, flow: null };
  }

  const edge = graph.edges.find((e) => e.id === selectedId);
  if (edge) {
    return { active: true, nodeIds: new Set([edge.from, edge.to]), edgeIds: new Set([selectedId]), flow: null };
  }

  return empty;
}

function edgeVerdict(edge) {
  return worstVerdict([edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict]);
}

export function computeFlowSummary(graph, flow) {
  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);

  const pathNodeIds = new Set([flow.source, flow.sink]);
  for (const e of edges) {
    pathNodeIds.add(e.from);
    pathNodeIds.add(e.to);
  }
  const externalRecipients = graph.nodes
    .filter((n) => pathNodeIds.has(n.id) && n.externality?.value === 'external')
    .map((n) => n.label);

  let protectedCount = 0;
  let unprotectedCount = 0;
  let unknownCount = 0;
  for (const e of edges) {
    const v = edgeVerdict(e);
    if (v === 'protected') protectedCount += 1;
    else if (v === 'unprotected' || v === 'mixed') unprotectedCount += 1;
    else unknownCount += 1;
  }

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    sourceLabel: sourceNode?.label ?? 'unknown source',
    destinationLabel: sinkNode?.label ?? 'unknown destination',
    totalDestinations: 1,
    protectedCount,
    unprotectedCount,
    unknownCount,
    externalRecipients,
    transitVerdict: worstVerdict(edges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(edges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(edges.map((e) => e.protection.handling.verdict)),
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
  };
}

export function computeArchitectureViewModel(graph, state) {
  const selection = resolveSelection(graph, state.selectedId);

  const zones = ZONE_ORDER.map((name) => ({
    name,
    nodeIds: graph.nodes.filter((n) => zoneForNode(n) === name).map((n) => n.id),
  }));

  const nodes = graph.nodes.map((n) => ({
    id: n.id,
    label: n.label,
    kind: n.kind,
    subtype: n.subtype,
    zone: zoneForNode(n),
    selected: selection.nodeIds.has(n.id),
    dimmed: selection.active && !selection.nodeIds.has(n.id),
  }));

  const edges = graph.edges.map((e) => ({
    id: e.id,
    from: e.from,
    to: e.to,
    verdict: edgeVerdict(e),
    selected: selection.edgeIds.has(e.id),
    dimmed: selection.active && !selection.edgeIds.has(e.id),
  }));

  const flowSummary = selection.flow ? computeFlowSummary(graph, selection.flow) : null;

  return { zones, nodes, edges, flowSummary };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/architecture-view.test.js`
Expected: PASS (13 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/architecture-view.js frontend/test/architecture-view.test.js
git commit -m "feat(frontend): add Architecture View's pure view-model"
```

---

### Task 3: Architecture View — SVG rendering

**Files:**
- Modify: `frontend/src/views/architecture-view.js` (append the render half)
- Create: `frontend/styles/architecture-view.css`

**Interfaces:**
- Consumes: `computeArchitectureViewModel`'s output shape (Task 2), `protectionVisual` (Task 1), `el`/`clear` (`frontend/src/lib/dom.js`, already merged).
- Produces: `renderArchitectureView(viewModel, canvasEl, onSelect)` where `onSelect(id: string)` is called with a node/edge id when the user clicks it. Consumed by Task 5's `app.js`.

- [ ] **Step 1: Write `frontend/styles/architecture-view.css`**

```css
.arch-view {
  width: 100%;
  height: 100%;
  min-height: 480px;
}

.arch-zone-label {
  fill: var(--text-secondary);
  font-family: var(--font-family);
  font-size: var(--font-size-panel-title);
  font-weight: 600;
}

.arch-zone-bg {
  fill: var(--surface-panel);
  stroke: var(--border-default);
  stroke-width: var(--border-width);
}

.arch-node {
  cursor: pointer;
}

.arch-node-box {
  fill: var(--surface-elevated);
  stroke: var(--border-default);
  stroke-width: 1.5px;
  rx: var(--radius-default);
}

.arch-node[data-selected="true"] .arch-node-box {
  stroke: var(--accent-selection);
  stroke-width: 2.5px;
}

.arch-node[data-dimmed="true"] {
  opacity: 0.35;
}

.arch-node-label {
  fill: var(--text-primary);
  font-family: var(--font-family);
  font-size: var(--font-size-node-title);
}

.arch-node-glyph {
  fill: var(--text-secondary);
  font-family: var(--font-mono);
  font-size: 11px;
}

.arch-edge {
  fill: none;
  stroke-width: 2px;
  cursor: pointer;
}

.arch-edge[data-dimmed="true"] {
  opacity: 0.25;
}

.arch-edge[data-selected="true"] {
  stroke-width: 3px;
}

.arch-edge-linestyle-dashed {
  stroke-dasharray: 6 4;
}

.arch-edge-linestyle-dotted {
  stroke-dasharray: 2 3;
}

.arch-edge-glyph {
  font-family: var(--font-mono);
  font-size: 11px;
}
```

- [ ] **Step 2: Append the render function to `frontend/src/views/architecture-view.js`**

Add this import at the top (alongside the existing `worstVerdict` import):

```js
import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';
```

Append at the end of the file:

```js
const SVG_NS = 'http://www.w3.org/2000/svg';
const ZONE_WIDTH = 220;
const ZONE_PADDING = 12;
const NODE_HEIGHT = 44;
const NODE_GAP = 16;
const NODE_WIDTH = ZONE_WIDTH - ZONE_PADDING * 2;

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null) continue;
    node.setAttribute(key, String(value));
  }
  return node;
}

/**
 * @param {ReturnType<typeof computeArchitectureViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(id: string) => void} onSelect
 */
export function renderArchitectureView(viewModel, canvasEl, onSelect) {
  clear(canvasEl);

  const zoneCount = viewModel.zones.length;
  const maxNodesInAZone = Math.max(1, ...viewModel.zones.map((z) => z.nodeIds.length));
  const height = Math.max(480, maxNodesInAZone * (NODE_HEIGHT + NODE_GAP) + 80);
  const width = zoneCount * ZONE_WIDTH;

  const svg = svgEl('svg', { class: 'arch-view', viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Architecture view: trust zones, nodes, and data-flow edges' });

  const nodePositions = new Map();
  viewModel.zones.forEach((zone, zoneIndex) => {
    const zoneX = zoneIndex * ZONE_WIDTH;
    svg.appendChild(svgEl('rect', { class: 'arch-zone-bg', x: zoneX, y: 0, width: ZONE_WIDTH, height, rx: 4 }));
    const zoneLabel = svgEl('text', { class: 'arch-zone-label', x: zoneX + ZONE_PADDING, y: 24 });
    zoneLabel.textContent = zone.name;
    svg.appendChild(zoneLabel);

    zone.nodeIds.forEach((nodeId, i) => {
      const node = viewModel.nodes.find((n) => n.id === nodeId);
      const y = 48 + i * (NODE_HEIGHT + NODE_GAP);
      const x = zoneX + ZONE_PADDING;
      nodePositions.set(nodeId, { x: x + NODE_WIDTH / 2, y: y + NODE_HEIGHT / 2 });
      svg.appendChild(renderNode(node, x, y, onSelect));
    });
  });

  // Edges drawn after nodes so they can reference final positions; dimmed
  // edges are drawn first so a highlighted edge always renders on top.
  const sortedEdges = [...viewModel.edges].sort((a, b) => Number(a.selected) - Number(b.selected));
  for (const edge of sortedEdges) {
    const from = nodePositions.get(edge.from);
    const to = nodePositions.get(edge.to);
    if (!from || !to) continue; // an edge whose endpoint isn't rendered (shouldn't happen with this fixture) is safely skipped, not a crash
    svg.appendChild(renderEdge(edge, from, to, onSelect));
  }

  canvasEl.appendChild(svg);
}

function renderNode(node, x, y, onSelect) {
  const group = el('g', {
    class: 'arch-node',
    'data-selected': String(node.selected),
    'data-dimmed': String(node.dimmed),
    tabindex: '0',
    role: 'button',
    'aria-label': `${node.label}, ${node.kind}${node.selected ? ', selected' : ''}`,
    onClick: () => onSelect(node.id),
    onKeydown: (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        onSelect(node.id);
      }
    },
  });
  group.appendChild(svgEl('rect', { class: 'arch-node-box', x, y, width: NODE_WIDTH, height: NODE_HEIGHT }));
  const glyph = svgEl('text', { class: 'arch-node-glyph', x: x + 8, y: y + 16 });
  glyph.textContent = node.kind.slice(0, 3).toUpperCase();
  group.appendChild(glyph);
  const label = svgEl('text', { class: 'arch-node-label', x: x + 8, y: y + 34 });
  label.textContent = node.label;
  group.appendChild(label);
  return group;
}

function renderEdge(edge, from, to, onSelect) {
  const visual = protectionVisual(edge.verdict);
  const midX = (from.x + to.x) / 2;
  const midY = (from.y + to.y) / 2;
  const path = svgEl('path', {
    d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`,
    style: `stroke: var(${visual.colorVar})`,
  });
  const group = el('g', {
    class: 'arch-edge',
    'data-selected': String(edge.selected),
    'data-dimmed': String(edge.dimmed),
    tabindex: '0',
    role: 'button',
    'aria-label': `Edge, protection ${visual.label}${edge.selected ? ', selected' : ''}`,
    onClick: () => onSelect(edge.id),
    onKeydown: (evt) => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        onSelect(edge.id);
      }
    },
  });
  path.classList.add(`arch-edge-linestyle-${visual.lineStyle === 'solid' ? 'solid' : visual.lineStyle}`);
  group.appendChild(path);
  const glyph = svgEl('text', { class: 'arch-edge-glyph', x: midX, y: midY - 4, fill: `var(${visual.colorVar})` });
  glyph.textContent = visual.glyph;
  group.appendChild(glyph);
  return group;
}
```

- [ ] **Step 3: Manual browser smoke check**

The render half is browser-only per this plan's Global Constraints — it's exercised by Task 5's end-to-end smoke check once `app.js` wires everything together. No standalone check for this task; proceed to commit.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/views/architecture-view.js frontend/styles/architecture-view.css
git commit -m "feat(frontend): render Architecture View as SVG"
```

---

### Task 4: Evidence inspector

**Files:**
- Create: `frontend/src/components/evidence-inspector.js`
- Create: `frontend/styles/inspector.css`
- Test: `frontend/test/evidence-inspector.test.js`

**Interfaces:**
- Consumes: `protectionVisual` (Task 1), `el`/`clear` (`dom.js`).
- Produces: `computeInspectorViewModel(graph, selectedId) → {kind, id, claim, supporting, conflicting, limitations, target} | null` (pure, tested), `renderInspector(viewModel, inspectorEl)` (thin DOM, browser-only). Consumed by Task 5's `app.js`.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/evidence-inspector.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeInspectorViewModel } from '../src/components/evidence-inspector.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;

test('computeInspectorViewModel returns null when nothing is selected', () => {
  assert.equal(computeInspectorViewModel(FLAGSHIP_GRAPH, null), null);
});

test('computeInspectorViewModel returns null for an unresolvable id rather than throwing', () => {
  assert.equal(computeInspectorViewModel(FLAGSHIP_GRAPH, 'flow:does-not-exist'), null);
});

test('computeInspectorViewModel on the masked-log flow resolves real supporting evidence, not a placeholder', () => {
  const flowId = FLOW_KEYS['flow.pci.masked_log'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.equal(vm.kind, 'flow');
  assert.equal(vm.id, flowId);
  assert.ok(vm.claim.includes('card_number'), 'the claim should name the actual field');
  assert.ok(vm.supporting.length > 0, 'the masked-log flow has a real evidenceRefs entry — it must resolve to a real evidence object');
  for (const item of vm.supporting) {
    assert.ok(FLAGSHIP_GRAPH.evidence.some((e) => e.id === item.id), 'every supporting item must be a real evidence object from the graph, not fabricated');
  }
});

test('computeInspectorViewModel exposes the flow\\'s real limitations array (what the scanner does not know)', () => {
  const flowId = FLOW_KEYS['flow.pci.database'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.deepEqual(vm.limitations, FLAGSHIP_GRAPH.flows.find((f) => f.id === flowId).limitations);
  assert.ok(vm.limitations.length > 0, 'the database flow has a real, honest limitation (no correlated at-rest config) — it must not be dropped');
});

test('computeInspectorViewModel on an edge describes all three protection dimensions', () => {
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.masked_log']);
  const edgeId = flow.edgeIds[flow.edgeIds.length - 1];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, edgeId);
  assert.equal(vm.kind, 'edge');
  const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
  assert.ok(vm.claim.includes(edge.protection.handling.verdict));
});

test('computeInspectorViewModel on a node describes its kind/subtype', () => {
  const webId = NODE_KEYS['node.web'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, webId);
  assert.equal(vm.kind, 'node');
  assert.ok(vm.claim.includes('Web App'));
});

test('computeInspectorViewModel never returns a conflicting-evidence item unless the evidence object actually says conflict:true', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.equal(vm.conflicting.length, 0, 'no evidence in the current fixture is marked conflicting — this must not be invented');
  for (const item of vm.conflicting) assert.equal(item.conflict, true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/evidence-inspector.test.js`
Expected: FAIL — `Cannot find module '../src/components/evidence-inspector.js'`

- [ ] **Step 3: Write `frontend/src/components/evidence-inspector.js`**

```js
import { el, clear } from '../lib/dom.js';
import { protectionVisual } from '../lib/protection-visual.js';

export function computeInspectorViewModel(graph, selectedId) {
  if (!selectedId) return null;

  const flow = graph.flows.find((f) => f.id === selectedId);
  const edge = !flow && graph.edges.find((e) => e.id === selectedId);
  const node = !flow && !edge && graph.nodes.find((n) => n.id === selectedId);
  const target = flow || edge || node;
  if (!target) return null;

  const kind = flow ? 'flow' : edge ? 'edge' : 'node';
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
  return `${target.label} (${target.kind}/${target.subtype})`;
}

/** @param {ReturnType<typeof computeInspectorViewModel>} viewModel */
export function renderInspector(viewModel, inspectorEl) {
  clear(inspectorEl);
  if (!viewModel) {
    inspectorEl.appendChild(el('p', { class: 'inspector-empty' }, 'Select a node, edge, or flow to see its evidence.'));
    return;
  }

  const container = el('div', { class: 'inspector' });
  container.appendChild(el('h3', { class: 'inspector-title' }, 'Evidence inspector'));

  container.appendChild(el('p', { class: 'inspector-claim' }, viewModel.claim));

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'Supporting evidence'));
  if (viewModel.supporting.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'No supporting evidence recorded.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-evidence-list' },
        viewModel.supporting.map((ev) => renderEvidenceItem(ev)),
      ),
    );
  }

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'Conflicting evidence'));
  if (viewModel.conflicting.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'None recorded.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-evidence-list' },
        viewModel.conflicting.map((ev) => renderEvidenceItem(ev)),
      ),
    );
  }

  container.appendChild(el('h4', { class: 'inspector-section-title' }, 'What the scanner does not know'));
  if (viewModel.limitations.length === 0) {
    container.appendChild(el('p', { class: 'inspector-empty' }, 'No limitations recorded for this claim.'));
  } else {
    container.appendChild(
      el(
        'ul',
        { class: 'inspector-limitations-list' },
        viewModel.limitations.map((text) => el('li', {}, text)),
      ),
    );
  }

  if (viewModel.kind === 'edge' || viewModel.kind === 'flow') {
    container.appendChild(renderVerdictBadges(viewModel));
  }

  inspectorEl.appendChild(container);
}

function renderEvidenceItem(evidence) {
  return el('li', { class: 'inspector-evidence-item' }, [
    el('span', { class: 'inspector-evidence-claim' }, evidence.claim),
    el('span', { class: 'inspector-evidence-location' }, evidence.location?.note ?? 'location unknown'),
  ]);
}

function renderVerdictBadges(viewModel) {
  const target = viewModel.target;
  const dims = viewModel.kind === 'edge'
    ? [
        ['Transit', target.protection.transit.verdict],
        ['At rest', target.protection.atRest.verdict],
        ['Handling', target.protection.handling.verdict],
      ]
    : [['Protection summary', target.protectionSummary]];
  return el(
    'div',
    { class: 'inspector-verdicts' },
    dims.map(([label, verdict]) => {
      const visual = protectionVisual(verdict);
      return el('div', { class: 'inspector-verdict-row' }, [
        el('span', { class: 'inspector-verdict-dim-label' }, `${label}: `),
        el('span', { class: 'inspector-verdict-badge', style: `border-color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`),
      ]);
    }),
  );
}
```

- [ ] **Step 4: Write `frontend/styles/inspector.css`**

```css
.inspector {
  color: var(--text-primary);
  font-size: var(--font-size-body);
}

.inspector-title {
  font-size: var(--font-size-panel-title);
  margin: 0 0 var(--space-1) 0;
}

.inspector-claim {
  color: var(--text-primary);
  font-weight: 500;
  margin-bottom: var(--space-2);
}

.inspector-section-title {
  font-size: var(--font-size-body);
  text-transform: uppercase;
  color: var(--text-secondary);
  margin: var(--space-2) 0 var(--space-1) 0;
}

.inspector-empty {
  color: var(--text-secondary);
  font-style: italic;
}

.inspector-evidence-list,
.inspector-limitations-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.inspector-evidence-item {
  display: flex;
  flex-direction: column;
  padding: var(--space-1) 0;
  border-bottom: var(--border-width) solid var(--border-default);
}

.inspector-evidence-location {
  color: var(--text-secondary);
  font-family: var(--font-mono);
  font-size: var(--font-size-code);
}

.inspector-limitations-list li {
  padding: 4px 0;
  color: var(--status-unknown);
}

.inspector-verdicts {
  margin-top: var(--space-2);
}

.inspector-verdict-row {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  padding: 4px 0;
}

.inspector-verdict-badge {
  border: 1.5px solid;
  border-radius: var(--radius-default);
  padding: 2px 8px;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd frontend && node --test test/evidence-inspector.test.js`
Expected: PASS (7 tests)

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/evidence-inspector.js frontend/styles/inspector.css frontend/test/evidence-inspector.test.js
git commit -m "feat(frontend): add the evidence inspector"
```

---

### Task 5: Wire it all together

**Files:**
- Create: `frontend/src/app.js`
- Modify: `frontend/index.html`
- Modify: `frontend/src/shell.js` (add `getContextRailEl()`)
- Modify: `frontend/test/shell.test.js` (one new test)

**Interfaces:**
- Consumes: `mountShell` (`shell.js`), `FLAGSHIP_GRAPH` (`data/flagship-graph.js`), `computeArchitectureViewModel`/`renderArchitectureView` (Tasks 2-3), `computeInspectorViewModel`/`renderInspector` (Task 4), `protectionVisual` (Task 1).
- Produces: the running application. `mountShell`'s new `getContextRailEl()` getter is consumed here and available to later view plans.

- [ ] **Step 1: Add `getContextRailEl()` to `frontend/src/shell.js`**

In the returned object (find the existing `getCanvasEl: () => canvas,` line), add a sibling line:

```js
    getCanvasEl: () => canvas,
    getInspectorEl: () => inspector,
    getContextRailEl: () => contextRail,
```

Update the JSDoc return-type comment above `mountShell` to include `getContextRailEl: () => HTMLElement,` alongside the existing getters.

- [ ] **Step 2: Add a test for the new getter to `frontend/test/shell.test.js`**

Read the existing file first to match its DOM-shim setup pattern exactly (it already imports `frontend/test/dom-shim.js` and mounts a shell instance per test — follow that same pattern rather than inventing a new one). Add:

```js
test('mountShell exposes getContextRailEl returning the context rail element', () => {
  const { document, root } = createTestDom(); // use this file's existing DOM-shim setup helper — match its actual name/shape
  const shellApi = mountShell(root, FLAGSHIP_GRAPH);
  const contextRailEl = shellApi.getContextRailEl();
  assert.ok(contextRailEl);
  assert.equal(contextRailEl.className, 'shell__context-rail');
});
```

(Adjust the exact helper/import names to match what `frontend/test/shell.test.js` already uses — read the file first; do not guess at its setup function's name.)

- [ ] **Step 3: Run the shell test to verify it passes**

Run: `cd frontend && node --test test/shell.test.js`
Expected: PASS (all existing tests plus the 1 new one)

- [ ] **Step 4: Write `frontend/src/app.js`**

```js
import { mountShell } from './shell.js';
import { FLAGSHIP_GRAPH } from './data/flagship-graph.js';
import { computeArchitectureViewModel, renderArchitectureView } from './views/architecture-view.js';
import { computeInspectorViewModel, renderInspector } from './components/evidence-inspector.js';

export function bootstrap(rootEl, graph) {
  const shellApi = mountShell(rootEl, graph);

  function rerender() {
    const state = shellApi.getState();

    if (state.view === 'architecture') {
      const viewModel = computeArchitectureViewModel(graph, state);
      renderArchitectureView(viewModel, shellApi.getCanvasEl(), (id) => shellApi.setSelection(id));
    } else {
      // Privacy and Trace views are a follow-up plan — show an honest
      // placeholder rather than silently rendering nothing or reusing
      // Architecture View's content under a different tab.
      shellApi.getCanvasEl().textContent = `${state.view} view is not implemented yet.`;
    }

    const inspectorViewModel = computeInspectorViewModel(graph, state.selectedId);
    renderInspector(inspectorViewModel, shellApi.getInspectorEl());
  }

  shellApi.onStateChange(rerender);
  rerender();

  return shellApi;
}
```

- [ ] **Step 5: Update `frontend/index.html`**

Replace the existing inline `<script type="module">` block (the one that imports `mountShell` and `FLAGSHIP_GRAPH` directly and calls `mountShell(root, FLAGSHIP_GRAPH)`) with:

```html
  <link rel="stylesheet" href="styles/architecture-view.css" />
  <link rel="stylesheet" href="styles/inspector.css" />
</head>
<body>
  <div id="app-root"></div>
  <script type="module">
    import { bootstrap } from './src/app.js';
    bootstrap(document.getElementById('app-root'), (await import('./src/data/flagship-graph.js')).FLAGSHIP_GRAPH);
  </script>
</body>
</html>
```

(Read the current file first and make the minimal edit — add the two new `<link>` tags near the existing ones, and replace only the inline script body, keeping everything else in the file, including the `<title>` and existing `tokens.css`/`shell.css` links, exactly as-is.)

- [ ] **Step 6: Manual browser smoke check**

Start a static server (`cd frontend && npm run serve`, or equivalent) and use real browser automation (if available — search for `mcp__claude-in-chrome__*` tools if not already loaded) to open the page and verify, with real observed evidence (quote actual text/attributes you saw, don't just reason about what the code should do):

1. Architecture View renders on load: 5 zone columns with labels, 14 node boxes distributed across them, edges drawn between nodes with distinct line styles (some solid, some dashed).
2. Click a node (e.g. the Web App box) — it gets a visible selection outline, the inspector panel on the right updates to show a claim mentioning "Web App", and `window.location.hash` updates to include `selected=node%3A...`.
3. Click an edge whose verdict is `unprotected` — the inspector shows "Unprotected" with the ✗ glyph (not just a color).
4. Switch to the Privacy tab and back to Architecture via the view tabs — the same node/edge remains selected (proving `getState()`/hash persistence survives a view switch, AC-16's actual point).
5. Zero console errors.

If browser automation isn't available in your environment, say so explicitly in your report (DONE_WITH_CONCERNS) rather than skipping verification.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app.js frontend/index.html frontend/src/shell.js frontend/test/shell.test.js
git commit -m "feat(frontend): wire the shell, Architecture View, and evidence inspector together"
```

---

### Task 6: Documentation and gate check

**Files:**
- Modify: `frontend/CLAUDE.md`
- Modify: `frontend/package.json`

**Interfaces:** none — documentation and wiring only.

- [ ] **Step 1: Add the new test files to `frontend/package.json`'s `test` script**

Append `test/protection-visual.test.js test/architecture-view.test.js test/evidence-inspector.test.js` to the existing space-separated list in the `"test"` script (read the file first to see its current exact content and insert correctly — don't guess at the current list).

- [ ] **Step 2: Run the full frontend suite**

Run: `cd frontend && npm test`
Expected: PASS, all test files including the 3 new ones plus the updated `shell.test.js`

- [ ] **Step 3: Update `frontend/CLAUDE.md`**

Add rows to the existing module table for the new files (`src/lib/protection-visual.js`, `src/views/architecture-view.js`, `src/components/evidence-inspector.js`, `src/app.js`), following the existing table's style exactly. Include in `protection-visual.js`'s row a note that its verdict strings are hand-kept-in-sync with the backend's enums (matching the existing pattern already used for other modules that can't import `scanner/src/lineage/` at runtime). Include in `architecture-view.js`'s row a note about the pure-view-model/thin-render split and where the trust-zone-column mapping logic lives.

- [ ] **Step 4: Run the full frontend suite once more, then commit**

Run: `cd frontend && npm test`
Expected: PASS

```bash
git add frontend/CLAUDE.md frontend/package.json
git commit -m "docs(frontend): document Architecture View and the evidence inspector"
```

---

## Self-Review Notes (completed by the plan author before handoff)

**Spec coverage:** PRD §7.8 (Architecture View blueprint: trust-zone columns, nodes, edges, flow-summary-adjacent inspector) → Tasks 2-3, 5. §8/AC-20 (verdicts distinguishable without color) → Task 1, enforced structurally by every later task consuming `protectionVisual()` rather than hardcoding styling. §16 (evidence inspector four-question sequence) → Task 4. AC-16 (cross-view selection persistence) → Task 5's manual smoke check step 4, built on the prior plan's `mountShell` state API. AC-11 (disconnected nodes remain visible) → explicitly tested in Task 2 against the real `node.retention`/`node.deletion` disconnected-node case. What this plan does **not** cover, deliberately: left-rail filters (deferred to the Privacy/Trace follow-up plan, per Global Constraints), Privacy View, Trace View, golden-image regression testing (DFG-034).

**Placeholder scan:** every step contains complete, runnable code. Task 5 Step 6 (manual browser check) is an explicit, honest scoping decision matching the prior plan's precedent for `shell.js`/`dom.js` — not a deferred TODO.

**Type consistency:** `protectionVisual(verdict) → {verdict, label, glyph, lineStyle, colorVar}` (Task 1) used identically in Tasks 3 and 4. `worstVerdict(verdicts) → string` (Task 1) used identically in Task 2. `computeArchitectureViewModel(graph, state) → {zones, nodes, edges, flowSummary}` (Task 2) consumed identically by Task 3's `renderArchitectureView` and Task 5's `app.js`. `computeInspectorViewModel(graph, selectedId) → {...} | null` (Task 4) consumed identically by Task 5. `mountShell`'s extended return contract (Task 5's `getContextRailEl` addition) is additive — does not change any existing consumer.
