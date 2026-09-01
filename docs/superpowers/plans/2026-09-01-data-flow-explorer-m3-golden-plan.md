# Milestone 3, sub-project Golden: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Formal golden-DOM regression tests proving AC-16/17/18/19's
reference-composition claims against the REAL flagship fixture and REAL
view code, plus an honest AC-22 split: real tests for the 3 states that
have real UI (Error/Selected/Hovered), and visible, named `test.todo`
entries for the 8 that don't — never a silent gap.

**Architecture:** All new test files, no production-code changes unless a
real bug is found while writing them (disclosed if so). Every test reuses
the SAME dom-shim pattern (`test/dom-shim.js`) and the SAME
`FLAGSHIP_GRAPH.extensions.fixtureFlowKeys`/`fixtureNodeKeys` named-lookup
maps every other test file in this codebase already uses — never a raw
hash id.

**Tech Stack:** `node --test`, `test/dom-shim.js`. No new dependency.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md`
(read this first — the full real-vs-aspirational gap analysis, and why
AC-22 is split the way it is).

## Global Constraints

- `frontend/` only, no `scanner/` changes.
- No new production feature work (saved views, zoom, export mode) — see
  the spec's decision 2. If a test reveals a real bug in EXISTING code,
  fix it minimally and disclose it; do not build new UI to satisfy an
  AC-22 row that has none today.
- Every new test file added to `frontend/package.json`'s explicit `test`
  script list.
- Reference nodes/flows by their `FLAGSHIP_GRAPH.extensions.
  fixtureNodeKeys`/`fixtureFlowKeys` names (e.g. `'flow.pci.payment_api'`),
  never by raw `node:.../flow:...` hash ids — matches every existing test
  file's own convention.
- **Ground every numeric/textual claim in this plan against the REAL
  computed output before trusting it** — this plan's own author ran the
  real compute functions this session and confirmed the values below,
  but re-verify at implementation time; the codebase moves.

---

### Task 1: `golden-architecture.test.js` + `golden-privacy.test.js`

**Files:**
- Test: `frontend/test/golden-architecture.test.js` (new)
- Test: `frontend/test/golden-privacy.test.js` (new)
- Modify: `frontend/package.json`

**Interfaces:**
- Consumes: `FLAGSHIP_GRAPH` from `src/data/flagship-graph.js`,
  `computeArchitectureViewModel`/`renderArchitectureView` from
  `src/views/architecture-view.js`, `computePrivacyViewModel`/
  `renderPrivacyView` from `src/views/privacy-view.js`.

- [ ] **Step 1: Confirm the real node/flow keys this task needs**

Read `frontend/src/data/flagship-graph.js`'s `extensions.fixtureNodeKeys`/
`fixtureFlowKeys` objects in full (they're near the end of the file).
Confirmed this session (re-verify — do not blind-trust): `fixtureFlowKeys`
includes `'flow.pci.payment_api'` (the cleartext/unprotected payment
flow — `protectionSummary: 'unprotected'`), `'flow.pci.masked_log'` /
`'flow.pci.raw_log'` (the two logging branches AC-17 names), and
`'flow.pci.ai'`/`'flow.phi.ai'`/`'flow.pii.analytics'`/
`'flow.pii.unresolved'`. The 9 §7.8-named reference NODE labels
(`Web App`, `API Gateway`, `Payments Service`, `AI Assistant`,
`PostgreSQL`, `Application Logs`, `Payment API`, `Analytics API`,
`Unresolved Destination`) are each a real `node.label` in
`FLAGSHIP_GRAPH.nodes` — confirm by reading, not by grep alone (a label
could theoretically collide with substring matches).

- [ ] **Step 2: Write `golden-architecture.test.js`**

Follow `test/architecture-view-render.test.js`'s existing dom-shim setup
pattern (`createDomShim()`, `globalThis.document = document`, dynamic
`await import(...)`). Confirmed this session: `architecture-view.js`'s
dimming mechanism is a real `'data-dimmed'` attribute (string `"true"`/
`"false"`) set on both node and edge elements — read the file's own
`computeArchitectureViewModel` to confirm the exact property names
(`node.dimmed`/`edge.dimmed`) before writing assertions, and confirm the
exact 5 trust-zone labels' rendering location (a `<div>`/heading per
zone column — read `computeArchitectureViewModel`'s `zones` output shape
and `renderArchitectureView`'s zone-column rendering first).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderArchitectureView } = await import('../src/views/architecture-view.js');

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

const REFERENCE_NODE_LABELS = [
  'Web App', 'API Gateway', 'Payments Service', 'AI Assistant', 'PostgreSQL',
  'Application Logs', 'Payment API', 'Analytics API', 'Unresolved Destination',
];

const REFERENCE_ZONES = ['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone'];

function allElements(root) {
  const out = [];
  const walk = (node) => { for (const c of node.childNodes) { if (c.nodeType === 'element') { out.push(c); walk(c); } } };
  walk(root);
  return out;
}
function allText(root) {
  return allElements(root).flatMap((el) => el.childNodes.filter((c) => c.nodeType === 'text').map((c) => c.data)).join(' ');
}

test('AC-17: Architecture View renders all 9 named reference nodes from the flagship fixture', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const label of REFERENCE_NODE_LABELS) {
    assert.ok(text.includes(label), `expected reference node "${label}" to render`);
  }
});

test('AC-17: Architecture View renders all 5 named trust zones', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const zone of REFERENCE_ZONES) {
    assert.ok(text.includes(zone), `expected trust zone "${zone}" to render`);
  }
});

test('AC-17: selecting the cleartext payment flow dims unrelated content without removing it from the DOM', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: FLOW_KEYS['flow.pci.payment_api'], filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const nodeElements = allElements(canvasEl).filter((el) => el.attrs.has('data-dimmed'));
  assert.ok(nodeElements.length > 0, 'sanity: expected at least one dimmable element');
  assert.ok(nodeElements.some((el) => el.attrs.get('data-dimmed') === 'true'), 'expected at least one unrelated node dimmed, not removed');
  assert.ok(nodeElements.some((el) => el.attrs.get('data-dimmed') === 'false'), 'expected the selected flow\'s own nodes to stay un-dimmed');
  // Still present in the DOM — dimming, never deletion:
  const text = allText(canvasEl);
  for (const label of REFERENCE_NODE_LABELS) assert.ok(text.includes(label), `"${label}" must still be in the DOM while dimmed`);
});

test('AC-17: the raw and masked logging branches both render with distinct verdicts', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  // Confirm both flow.pci.masked_log's and flow.pci.raw_log's own edges
  // render with DIFFERENT protection verdicts somewhere in the tree —
  // read architecture-view.js's own edge-verdict rendering (likely a
  // data-verdict attribute or visible glyph/label) before finalizing
  // this assertion's exact mechanism; do not guess the attribute name.
});
```

(The last test's body is intentionally left for the implementer to
complete after reading the real edge-verdict rendering mechanism — this
plan's own investigation confirmed the masked/raw log edges exist and
have different `protection.handling.verdict` values in the fixture, but
did not trace the exact DOM attribute/text `architecture-view.js` uses to
surface that verdict on an edge. Read the file, find the real mechanism,
then write a real, non-empty assertion — do not leave the test body
empty or a bare `assert.ok(true)`.)

- [ ] **Step 3: Run and verify**

Run: `cd frontend && node --test test/golden-architecture.test.js`
Expected: PASS. If a REAL gap is found (a named node/zone missing, or
dimming genuinely broken), this is a real, disclosed finding — report it,
fix it minimally if the fix is small and obviously correct, otherwise
leave the test red and flag it prominently in the task's own report
rather than weakening the assertion.

- [ ] **Step 4: Write `golden-privacy.test.js`**

Read `frontend/src/views/privacy-view.js` in full first (already read
this session — re-verify current content). Real governance values
confirmed present in the fixture this session (re-verify):
`flow.pci.ai`'s flow has `governanceRefs: {recipient: 'manual_required',
purpose: 'manual_required', lawfulBasis: 'manual_required'}`;
`flow.phi.ai` has `{lawfulBasis: 'manual_required', retention: 'unknown',
transfer: 'review'}`; `flow.pii.analytics` has `{retention: 'unknown',
deletion: 'not_found'}`. `renderStageCell`'s real rendering format is
`` `${key}: ${value}` `` (e.g. the literal text `"lawfulBasis:
manual_required"`) — confirm this is still the exact real format before
asserting on it verbatim.

```js
test('AC-18: the three named data-class fields (card_number/PCI, diagnosis/PHI, email/PII) each render a row preserving field identity across lifecycle stages', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const fieldName of ['card_number', 'diagnosis', 'email']) {
    assert.ok(text.includes(fieldName), `expected field "${fieldName}" to render a row`);
  }
});

test('AC-18: missing governance data renders the real MANUAL REQUIRED / UNKNOWN / REVIEW / NOT FOUND signal (exact real format, not the PRD prose casing)', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  assert.ok(text.includes('manual_required'), 'expected a manual_required governance badge somewhere');
  assert.ok(text.includes('unknown'), 'expected an unknown-retention badge somewhere');
  assert.ok(text.includes('review'), 'expected a transfer-review badge somewhere');
  assert.ok(text.includes('not_found'), 'expected a deletion-not-found badge somewhere');
});

test('AC-18: all 6 lifecycle stages render as columns', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const stage of ['Collection', 'Processing', 'Storage', 'Sharing', 'Retention', 'Deletion']) {
    assert.ok(text.includes(stage), `expected lifecycle stage "${stage}" column`);
  }
});
```

- [ ] **Step 5: Run, add both files to `package.json`, full test run**

Run: `cd frontend && node --test test/golden-privacy.test.js` then add
both new files to `frontend/package.json`'s `test` script (near
`privacy-view-render.test.js`/`architecture-view-render.test.js`), then
`cd frontend && npm test` — PASS, real exit code.

- [ ] **Step 6: Commit**

```bash
git add frontend/test/golden-architecture.test.js frontend/test/golden-privacy.test.js frontend/package.json
git commit -m "test(frontend): golden-DOM regression tests for AC-17/AC-18 reference compositions"
```

---

### Task 2: `golden-trace.test.js` + `golden-shell-state.test.js`

**Files:**
- Test: `frontend/test/golden-trace.test.js` (new)
- Test: `frontend/test/golden-shell-state.test.js` (new)
- Modify: `frontend/package.json`

- [ ] **Step 1: Confirm the real trace-step output**

Read `frontend/src/views/trace-view.js` in full. **Confirmed this
session, re-verify**: `computeTraceViewModel(FLAGSHIP_GRAPH, {selectedId:
FLOW_KEYS['flow.pci.payment_api'], ...})` currently produces **4 steps**,
not the 5 §7.10's own table names (`source` → `propagation` [Web App →
Payments Service, `req.body.card_number` → `payment.pan`] →
`propagation` [Payments Service → Payment API, `payment.pan` →
`payload.cardNumber`] → `sink` [Payment API, external,
`protectionSummary: 'unprotected'`]), and `alternatePaths.length` is 4.
**This is a real, disclosed discrepancy from the PRD's own illustrative
table** (the PRD names 5 steps including a separate `SERIALIZATION` step
this fixture's real compute output does not currently produce as its own
step) — write this task's assertions against the REAL current output,
confirmed by re-running the compute function yourself before writing any
assertion, never against §7.10's own table numbers. If the real step
count or shape has changed since this plan was written, that's expected
drift — ground truth is the real function output, always.

- [ ] **Step 2: Write `golden-trace.test.js`**

```js
test('AC-19: the cleartext payment flow renders its real ordered steps with both field-rename mappings', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm, 'sanity: the flow must be selectable and produce a view model');
  renderTraceView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  assert.ok(text.includes('card_number'), 'expected the source field name to render');
  assert.ok(text.includes('req.body.card_number'), 'expected the first field-mapping\'s fromPath to render');
  assert.ok(text.includes('payment.pan'), 'expected the rename mapping target to render');
  assert.ok(text.includes('payload.cardNumber'), 'expected the second rename mapping target to render');
});

test('AC-19: the external HTTP trust-boundary edge is visibly flagged unprotected', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  renderTraceView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  assert.ok(text.includes('unprotected'), 'expected the real unprotected verdict to render for this flow\'s external hop');
});

test('AC-19: alternate destinations render with their own individual verdicts', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm.alternatePaths.length > 0, 'sanity: this flow must have real alternates in the fixture');
  renderTraceView(vm, canvasEl, () => {});
  // Confirm each alternate's own protectionSummary text appears — read
  // trace-view.js's renderTraceView / the "Alternate destinations" list
  // rendering to confirm the exact DOM shape before finalizing this
  // assertion (this plan's own investigation confirmed 4 real alternates
  // exist in the fixture but did not trace their exact render markup).
});
```

(Same discipline as Task 1's last test — the alternate-destinations
assertion body is left for the implementer to complete against the real
rendering code, not guessed.)

- [ ] **Step 3: Write `golden-shell-state.test.js`**

Read `frontend/src/shell.js`'s full public API (`mountShell`'s returned
object: `getState`, `setSelection`, `setFilters`, `setTable`, `setActiveView`
— confirm `setActiveView` is the real method name for switching views;
this plan's own earlier investigation did not confirm this exact name,
only that `buildViewTabs`'s `onClick` calls `updateState({...state,
view: nextView})` internally — check whether that's exposed as a public
`setActiveView` method or only reachable via a real tab click in
`shell.test.js`'s own existing tests, and use whichever is real).

```js
test('AC-16: selection and filters persist across a real view switch, and the header/coverage banner stay unchanged', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, FLAGSHIP_GRAPH);

  const flowId = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys['flow.pci.payment_api'];
  shell.setSelection(flowId);
  shell.setFilters({ dataClass: ['PCI'] });

  const headerTextBefore = root.querySelector('.shell__header-meta')?.textContent;

  // Switch views via a real tab click (or setActiveView, whichever is
  // confirmed real per this step's own header note) from architecture to privacy.
  const tabs = root.querySelectorAll('[data-view-id]');
  const privacyTab = tabs.find((t) => t.getAttribute('data-view-id') === 'privacy');
  privacyTab.dispatch('click');

  const state = shell.getState();
  assert.equal(state.selectedId, flowId, 'selection must persist across the view switch');
  assert.deepEqual(state.filters, { dataClass: ['PCI'] }, 'filters must persist across the view switch');
  const headerTextAfter = root.querySelector('.shell__header-meta')?.textContent;
  assert.equal(headerTextBefore, headerTextAfter, 'header/coverage content must not change when only the view changes');

  shell.destroy();
});
```

- [ ] **Step 4: Run, add both files to `package.json`, full test run**

Run each file individually first, then add both to `package.json`, then
`cd frontend && npm test` — PASS, real exit code.

- [ ] **Step 5: Commit**

```bash
git add frontend/test/golden-trace.test.js frontend/test/golden-shell-state.test.js frontend/package.json
git commit -m "test(frontend): golden-DOM regression test for AC-19 trace composition, AC-16 cross-view state persistence"
```

---

### Task 3: AC-22 state-matrix split (3 real + 8 disclosed gaps) + docs

**Files:**
- Test: `frontend/test/golden-state-matrix.test.js` (new)
- Test: `frontend/test/golden-state-matrix-gaps.test.js` (new)
- Modify: `frontend/package.json`
- Modify: `frontend/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`

- [ ] **Step 1: Write `golden-state-matrix.test.js` (the 3 real states)**

Read `frontend/src/main.js`'s `showError`/`catch` block, and confirm the
real hover CSS selectors (`styles/privacy-view.css`'s `.privacy-row:hover`,
`styles/inventory-view.css`'s `.inventory-row:hover`,
`styles/trace-view.css`'s `.trace-alternate-item:hover` — confirmed
present this session, re-verify still current) before writing this file.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

test('AC-22 Error state: a failed graph fetch shows the real error UI and never a clean/protected summary', async () => {
  const { showErrorForTest } = await import('../src/main.js'); // export this helper if main.js does not already expose one for testing — check first; if main.js has no exported test seam, read its real showError function inline via its own module scope instead of re-exporting, whichever is less invasive
  // ... real assertion against the rendered error DOM: title/message present, no "Scan complete"/"Protected" text anywhere.
});

test('AC-22 Selected state: a selected element carries a real, visible selection marker across two different views', () => {
  // Reuse golden-architecture/golden-privacy's own selection tests' real
  // data-dimmed / data-selected findings — this test asserts the SAME
  // real mechanism is present on at least Architecture View and Privacy
  // View's own selected rows, not a new one.
});

test('AC-22 Hovered state: a real :hover CSS rule exists for the interactive row class in each view stylesheet with a hover-capable row', () => {
  const readCss = (relPath) => readFileSync(fileURLToPath(new URL(`../${relPath}`, import.meta.url)), 'utf8');
  assert.ok(readCss('styles/privacy-view.css').includes('.privacy-row:hover'));
  assert.ok(readCss('styles/inventory-view.css').includes('.inventory-row:hover'));
  assert.ok(readCss('styles/trace-view.css').includes('.trace-alternate-item:hover'));
});
```

`main.js`'s `showError` is currently a MODULE-INTERNAL function, not
exported (confirmed by this session's earlier read — re-verify). Reading
whether it needs a test-only export, or whether this AC-22 row is better
proven by a smaller, real assertion (e.g. that `main.js`'s real fetch-
catch path calls `el()`-based rendering, never leaves stale "Scan
complete" text on screen) is a real, disclosed decision the implementer
makes and documents — do not force an export that weakens `main.js`'s
own encapsulation without disclosing why.

- [ ] **Step 2: Write `golden-state-matrix-gaps.test.js` (8 disclosed gaps)**

```js
import { test } from 'node:test';

// AC-22 / PRD §8.4's 11-state visual matrix. 3 states (Error, Selected,
// Hovered) have real, tested UI — see golden-state-matrix.test.js. The 8
// below have NO dedicated visual treatment anywhere in src/ or styles/
// today, confirmed by direct grep this sub-project's own scoping pass
// (docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md).
// Each entry names exactly what would need to exist before it's
// testable — visible in `npm test` output forever, not a doc that can
// go stale silently.

test.todo('AC-22 Loading/scanning: needs a skeleton-topology + named-phase UI — no loading state exists in src/ today');
test.todo('AC-22 Partial: needs a persistent amber banner + hatched/badged affected regions — coverage.status is read but has no dedicated partial-scan visual treatment');
test.todo('AC-22 Truncated: needs a path/graph-budget notice on contributing nodes — no truncation UI exists');
test.todo('AC-22 Unsupported (persistent banner, distinct from Inventory\'s own unsupportedCandidates table row): needs a graph-level "candidate remains in inventory with unsupported reason" banner — only the Inventory table row exists today, not a standalone banner');
test.todo('AC-22 Unresolved destination (the specific dashed-edge/question-mark glyph treatment named in §8.4, distinct from the node itself rendering): the node renders today (confirmed), but the SPECIFIC dashed-edge/question-mark visual treatment is unconfirmed — verify at a future increment whether architecture-view.js already does this or needs it added');
test.todo('AC-22 Zero filtered results: needs an active-filter-explanation + reset-action empty state — filtering hides rows today (data-visible=false) but shows no explanatory empty state when ALL rows are hidden');
test.todo('AC-22 Error, phase 2 (retry/export-diagnostics action): main.js\'s real error UI shows a message but has no retry or export-diagnostics action — only the base "failed" state is real');
test.todo('AC-22 Stale artifact: needs a commit-mismatch + rescan-action banner with visibly timestamped old evidence — no staleness UI exists');
```

- [ ] **Step 3: Run, add both files to `package.json`, full test run**

Run: `cd frontend && node --test test/golden-state-matrix.test.js
test/golden-state-matrix-gaps.test.js` — confirm the `test.todo` entries
show as TODO in the output (not silently absent, not counted as
failures). Add both files to `package.json`. Run full `npm test` — PASS,
real exit code, confirm the TODO count in the summary output matches (8).

- [ ] **Step 4: Update `frontend/CLAUDE.md`**

Add a "Milestone 3, sub-project Golden — COMPLETE" section, same style
as every prior sub-project's own entry in this file: what's proven
(AC-16/17/18/19 golden-DOM regressions, real trace step count discovered
to differ from the PRD's own illustrative table), and the honest AC-22
split (3 real, 8 disclosed `test.todo` gaps, quoting the exact 8 gap
descriptions from Step 2 or a summary of them).

- [ ] **Step 5: Update the M3 scoping table**

Mark Golden's row COMPLETE in
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`,
with the real AC-22 split disclosed in the row text (not "AC-22 passes"
— it does not, honestly, for 8 of 11 states; say what actually happened).

- [ ] **Step 6: Commit**

```bash
git add frontend/test/golden-state-matrix.test.js frontend/test/golden-state-matrix-gaps.test.js frontend/package.json frontend/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md
git commit -m "test(frontend): AC-22 state-matrix split — 3 real states tested, 8 disclosed gaps as visible test.todo entries"
```

---

## Final integration checklist (coordinator, after all 3 tasks)

- Re-read every changed file in full.
- `cd frontend && npm test` green, real captured exit code — confirm the
  TODO count shows in the summary (Node's test runner reports `todo` in
  its own summary line).
- `cd scanner && npm test` green, real captured exit code.
- Confirm no test in this sub-project asserts on something that isn't
  real (re-read Tasks 1/2's "left for the implementer" bodies — they
  must not have been left empty or trivially-true in the final diff).
