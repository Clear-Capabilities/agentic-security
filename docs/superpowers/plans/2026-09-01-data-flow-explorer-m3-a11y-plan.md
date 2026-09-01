# Milestone 3, sub-project A11y: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove AC-20 (contrast/redundancy) and AC-21 (viewport reflow)
with real, automated tests plus a real CDP-measured pass, and fix the one
real, disclosed bug found during scoping: the right inspector currently
disappears (`display:none`) rather than becoming an overlay below 1280px,
which risks making a selected flow/node's evidence permanently
unreachable at the smallest AC-21-required viewport.

**Architecture:** Two automated-test tasks (contrast math against the
real `tokens.css` file content; a keyboard-focus-parity sweep over real
rendered DOM) that touch no production code. One CSS/JS task that fixes
the inspector overlay and gives Inventory View its first real stylesheet
(a genuine prerequisite — it currently has none). One real-browser
measurement task, performed directly (not dom-shim-simulated, since
viewport/layout claims cannot be proven by a DOM shim with no CSSOM),
whose findings are written into `frontend/CLAUDE.md`, mirroring Perf's
own measured-result precedent.

**Tech Stack:** Plain ES modules/CSS, zero build step, `node --test` +
`test/dom-shim.js` for automated tests; real Chrome via
`mcp__claude-in-chrome__*` tools against a real `agentic-security explore`
server for the measurement pass.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-a11y-scoping.md`
(read this first — full AC text, every decision's rationale, and the
confirmed findings: the inspector CSS bug, Inventory's missing
stylesheet, and Architecture View's already-adequate keyboard support).

## Global Constraints

- Zero build step: plain files only, no bundler, no new dependency.
- `frontend/` only. No `scanner/` changes.
- Every new test file added to `frontend/package.json`'s explicit `test`
  script list (not a glob).
- Mobile/narrow breakpoints are out of scope (scoping doc decision 7).
- `contrast.js`'s own algorithm is not modified, only called against real
  data by a new test.

---

### Task 1: Automated contrast + structural-redundancy + keyboard-focus tests

**Files:**
- Test: `frontend/test/tokens-contrast.test.js` (new)
- Test: `frontend/test/protection-visual.test.js` (extend)
- Test: `frontend/test/keyboard-focus-parity.test.js` (new)
- Modify: `frontend/package.json`

**Interfaces:**
- Consumes: `contrastRatio`/`meetsAA` from `lib/contrast.js` (unmodified).
- Consumes: `VISUALS`... **correction, resolved here**: `protection-
  visual.js` does not currently export its internal `VISUALS` object —
  only `protectionVisual(verdict)` and `worstVerdict(verdicts)` are
  exported. Rather than exporting an internal implementation constant
  (which would let a future caller depend on its exact shape), the
  structural test calls `protectionVisual()` for every known verdict
  string and asserts the returned object's own shape — it does not need
  `VISUALS` itself. The known verdict list is `PROTECTION_VERDICTS`-
  equivalent: `['protected', 'unprotected', 'mixed', 'unknown',
  'not_applicable', 'not_assessed']` — copy this exact array (it's
  `protection-visual.js`'s own `VERDICT_PRECEDENCE` array reordered/
  same-membership; **read `protection-visual.js` first and use its real
  `VERDICT_PRECEDENCE` export directly** rather than retyping the list by
  hand, so this test can never drift from the real enum).

- [ ] **Step 1: Write and verify `tokens-contrast.test.js`**

Read `frontend/styles/tokens.css` in full first, to confirm the exact
token names and hex values currently there (do not assume the ones quoted
in the scoping doc are still current by the time you implement — re-read).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { contrastRatio, meetsAA } from '../src/lib/contrast.js';

const TOKENS_PATH = fileURLToPath(new URL('../styles/tokens.css', import.meta.url));
const CSS = readFileSync(TOKENS_PATH, 'utf8');

// Extracts every `--name: #HEXVALUE;` declaration inside ONE named CSS
// block (`:root { ... }` or `:root[data-theme="light"] { ... }`), keyed
// by the bare token name (no leading `--`). Regex-based, not a real CSS
// parser — sufficient because tokens.css is a hand-authored, single-file,
// flat custom-property list with no nesting beyond the two theme blocks
// this test explicitly targets.
function extractTokens(css, blockStartPattern) {
  const startMatch = blockStartPattern.exec(css);
  assert.ok(startMatch, `expected to find a block matching ${blockStartPattern}`);
  const blockStart = startMatch.index + startMatch[0].length;
  const blockEnd = css.indexOf('}', blockStart);
  const block = css.slice(blockStart, blockEnd);
  const tokens = {};
  const re = /--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6});/g;
  let m;
  while ((m = re.exec(block))) {
    tokens[m[1]] = m[2];
  }
  return tokens;
}

const darkTokens = extractTokens(CSS, /:root\s*\{/);
const lightTokens = extractTokens(CSS, /:root\[data-theme="light"\]\s*\{/);

test('sanity: both theme blocks were actually found and non-trivially parsed', () => {
  assert.ok(Object.keys(darkTokens).length > 5, 'dark token block should have several colors');
  assert.ok(Object.keys(lightTokens).length > 5, 'light token block should have several colors');
  assert.ok('status-protected' in darkTokens, 'dark block should define --status-protected');
  assert.ok('status-protected' in lightTokens, 'light block should define --status-protected');
});

const STATUS_TOKENS = ['status-protected', 'status-unprotected', 'status-unknown'];
const BACKGROUND_TOKENS = ['surface-canvas', 'surface-panel'];

for (const theme of [{ name: 'dark', tokens: darkTokens }, { name: 'light', tokens: lightTokens }]) {
  for (const statusToken of STATUS_TOKENS) {
    for (const bgToken of BACKGROUND_TOKENS) {
      test(`${theme.name} theme: --${statusToken} meets AA against --${bgToken}`, () => {
        const statusColor = theme.tokens[statusToken];
        const bgColor = theme.tokens[bgToken];
        assert.ok(statusColor, `--${statusToken} must exist in the ${theme.name} block`);
        assert.ok(bgColor, `--${bgToken} must exist in the ${theme.name} block`);
        assert.ok(
          meetsAA(statusColor, bgColor),
          `--${statusToken} (${statusColor}) against --${bgToken} (${bgColor}) in ${theme.name} theme: ${contrastRatio(statusColor, bgColor).toFixed(2)}:1, needs >= 4.5:1`,
        );
      });
    }
  }
}

// Regression pin on the two ratios tokens.css's own comments already
// hand-verified — confirms the existing comments are still true, not just
// that new code agrees with itself.
test('dark theme: --status-banner-text against --status-unknown is ~10.27:1 (per tokens.css\'s own comment)', () => {
  const ratio = contrastRatio(darkTokens['status-banner-text'], darkTokens['status-unknown']);
  assert.ok(Math.abs(ratio - 10.27) < 0.1, `expected ~10.27:1, got ${ratio.toFixed(2)}:1`);
});

test('light theme: --status-banner-text against --status-unknown is ~4.69:1 (per tokens.css\'s own comment)', () => {
  const ratio = contrastRatio(lightTokens['status-banner-text'], lightTokens['status-unknown']);
  assert.ok(Math.abs(ratio - 4.69) < 0.1, `expected ~4.69:1, got ${ratio.toFixed(2)}:1`);
});
```

If any `meetsAA` assertion FAILS against the real current tokens (i.e. a
real, pre-existing contrast violation is discovered, not introduced by
this plan), do not silently adjust the test to pass — this is a real
finding. Report it in the task's own DONE_WITH_CONCERNS status and
ledger entry rather than weakening the assertion or picking a different
background token to compare against. Do not "fix" `tokens.css` colors as
part of this task without flagging the change explicitly — a real color
value change is a visible product change, more than this task's own
scope, and needs its own disclosed decision.

Run: `cd frontend && node --test test/tokens-contrast.test.js`
Expected: PASS (per the scoping doc's own manual pre-verification, these
ratios should already hold — this test formalizes, not fixes).

- [ ] **Step 2: Extend `protection-visual.test.js`**

Read `frontend/src/lib/protection-visual.js` first to confirm the exact
current export names (`protectionVisual`, `worstVerdict`,
`VERDICT_PRECEDENCE`) before writing this — do not assume `VISUALS`
itself is exported (it is not, per this task's own Interfaces note above).

```js
import { protectionVisual, VERDICT_PRECEDENCE } from '../src/lib/protection-visual.js';

test('AC-20: every real verdict has a non-empty glyph, label, and lineStyle — text/icon/border redundancy holds structurally, not by convention', () => {
  for (const verdict of VERDICT_PRECEDENCE) {
    const visual = protectionVisual(verdict);
    assert.ok(visual.glyph && visual.glyph.length > 0, `${verdict}: glyph must be non-empty`);
    assert.ok(visual.label && visual.label.length > 0, `${verdict}: label must be non-empty`);
    assert.ok(visual.lineStyle && visual.lineStyle.length > 0, `${verdict}: lineStyle must be non-empty`);
    assert.ok(visual.colorVar && visual.colorVar.length > 0, `${verdict}: colorVar must be non-empty`);
  }
});

test('AC-20: no two verdicts share the same glyph (icon alone must be able to distinguish them)', () => {
  const glyphs = VERDICT_PRECEDENCE.map((v) => protectionVisual(v).glyph);
  assert.equal(new Set(glyphs).size, glyphs.length, `expected ${glyphs.length} distinct glyphs, got: ${glyphs.join(' ')}`);
});
```

Run: `cd frontend && node --test test/protection-visual.test.js`
Expected: PASS. If the second test (distinct glyphs) fails against real
current values, this is a real finding — report it, do not silently
delete the assertion. (Read `protection-visual.js`'s `VISUALS` object
during Step 2's own investigation to sanity-check this by eye first — the
scoping doc did not check glyph-uniqueness, so this is new ground; if a
real collision exists, add ONE new distinct glyph to the colliding
entry, disclosed, rather than leaving two verdicts visually identical
without color.)

- [ ] **Step 3: Write and verify `keyboard-focus-parity.test.js`**

This sweeps ALL FOUR views' real rendered DOM (small, view-appropriate
hand-built fixtures — reuse the SAME minimal fixture pattern
`inventory-view-render.test.js`/`privacy-view-render.test.js` already
use, do not invent a fifth fixture shape) and asserts: every element
carrying an `onClick`-derived listener is either a native `<button>` tag
or has a `tabindex` attribute set.

`dom-shim.js`'s `FakeElement` does not expose "does this element have a
registered click listener" directly as a queryable property — read
`test/dom-shim.js` first to find the real mechanism `el()`'s `onClick`
wiring produces on the shim (likely an internal listener map) and use
that, OR (simpler, and sufficient for this test's actual claim) assert
structurally instead: every `<tr class="...-row">`, SVG node/edge
element, and non-`<button>` interactive-looking element (identified by
`role="button"` or a project-specific class naming convention already in
use — `architecture-view.js`'s node/edge elements, `privacy-view.js`'s
`.privacy-row`, `inventory-view.js`'s `.inventory-row`) has a `tabindex`
attribute. This sidesteps needing to introspect the shim's internal
listener storage and directly tests the real AC-20/21-relevant property
(can a keyboard-only user reach it), which is what actually matters.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { computeArchitectureViewModel, renderArchitectureView } = await import('../src/views/architecture-view.js');
const { computePrivacyViewModel, renderPrivacyView } = await import('../src/views/privacy-view.js');
const { computeTraceViewModel, renderTraceView } = await import('../src/views/trace-view.js');
const { computeInventoryViewModel, renderInventoryView } = await import('../src/views/inventory-view.js');
const { ADVERSARIAL_GRAPH } = await import('./adversarial-fixture.js');

function allElements(root) {
  const out = [];
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') { out.push(child); walk(child); }
    }
  };
  walk(root);
  return out;
}

// An element counts as "interactive" for this sweep if it has role="button"
// (every view's own convention for a non-native clickable element) — a
// native <button> is excluded from the check below since it's natively
// focusable without an explicit tabindex.
function assertKeyboardReachable(canvasEl, viewName) {
  const interactive = allElements(canvasEl).filter((el) => el.tagName !== 'BUTTON' && el.attrs.get('role') === 'button');
  assert.ok(interactive.length > 0, `${viewName}: sanity — expected at least one non-<button> interactive element in this fixture`);
  for (const el of interactive) {
    assert.ok(el.attrs.has('tabindex'), `${viewName}: a role="button" element (<${el.tagName}>) has no tabindex — unreachable by keyboard`);
  }
}

test('AC-20/21 keyboard reachability: Architecture View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(ADVERSARIAL_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Architecture View');
});

test('AC-20/21 keyboard reachability: Privacy View', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(ADVERSARIAL_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Privacy View');
});

test('AC-20/21 keyboard reachability: Trace View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeTraceViewModel(ADVERSARIAL_GRAPH, { view: 'trace', selectedId: 'flow:evil1', filters: {} });
  renderTraceView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Trace View');
});

test('AC-20/21 keyboard reachability: Inventory View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(ADVERSARIAL_GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  assertKeyboardReachable(canvasEl, 'Inventory View');
});
```

Before trusting this test file, confirm `ADVERSARIAL_GRAPH` actually
produces at least one row/node in EACH of the four views' default state
used above (`table: 'sources'` for Inventory, `selectedId: 'flow:evil1'`
for Trace) — `xss-adversarial.test.js`'s own existing tests already prove
Architecture/Privacy/Trace do; confirm Inventory's `sources` table does
too (it should, per this session's own earlier finding that
`ADVERSARIAL_GRAPH`'s `node:source:evil1` is `kind: 'source'`). If any
view's sanity assertion (`interactive.length > 0`) fails because the
fixture doesn't populate that view, use a small inline fixture for that
one view instead of forcing `ADVERSARIAL_GRAPH` to fit — disclosed, not
silently worked around.

Run: `cd frontend && node --test test/keyboard-focus-parity.test.js`
Expected: PASS (per scoping doc's own confirmed finding: all four views
already have real `tabindex` support).

- [ ] **Step 4: Add all three new test files to `package.json`, run full suite**

Add `test/tokens-contrast.test.js`, `test/keyboard-focus-parity.test.js`
(protection-visual.test.js is already registered — no new entry needed
for it) to `frontend/package.json`'s `test` script, placed near
`test/contrast.test.js`/`test/protection-visual.test.js` respectively.

Run: `cd frontend && npm test`
Expected: PASS, real captured exit code 0, all new files confirmed to
have actually run (grep output).

- [ ] **Step 5: Commit**

```bash
git add frontend/test/tokens-contrast.test.js frontend/test/protection-visual.test.js frontend/test/keyboard-focus-parity.test.js frontend/package.json
git commit -m "test(frontend): formalize AC-20 contrast/redundancy and keyboard-focus-parity as automated tests"
```

(If Step 1 or Step 2 found a REAL violation that could not be resolved
within this task's own small scope, commit the passing tests and file it
as a disclosed, open finding in the task's own report and the SDD
ledger — do not block the whole task on a separately-scoped color/glyph
fix unless it's a one-line change, in which case make it and disclose it.)

---

### Task 2: Inspector overlay fix + Inventory View stylesheet

**Files:**
- Modify: `frontend/styles/shell.css`
- Modify: `frontend/src/shell.js`
- Create: `frontend/styles/inventory-view.css`
- Modify: `frontend/index.html`
- Test: `frontend/test/shell.test.js` (add cases)

**Interfaces:**
- Produces: `mountShell()`'s returned API gains no new PUBLIC method (the
  overlay toggle is internal UI state, not part of the cross-view
  `{view, selectedId, filters, table}` state `lib/state.js` persists to
  the URL — a transient viewport affordance, not shareable/bookmarkable
  state). The toggle button and its `aria-expanded`/`data-overlay-open`
  wiring live entirely inside `shell.js`'s closure.

- [ ] **Step 1: Fix the inspector overlay CSS**

Read `frontend/styles/shell.css` in full first (confirm the exact current
`@media (max-width: 1280px)` block content matches what's quoted below —
re-verify, don't assume it hasn't changed).

Replace:

```css
@media (max-width: 1280px) {
  .shell {
    grid-template-columns: var(--left-rail-collapsed-width) 1fr 0;
  }
  .shell__inspector {
    display: none;
  }
}
```

with:

```css
.shell__inspector-toggle {
  display: none;
  background: transparent;
  border: var(--border-width) solid var(--border-default);
  color: var(--text-primary);
  border-radius: var(--radius-default);
  padding: 4px var(--space-1);
  cursor: pointer;
  font-family: var(--font-family);
  font-size: var(--font-size-body);
}
.shell__inspector-toggle:focus-visible {
  outline: 2px solid var(--accent-selection);
  outline-offset: 2px;
}

@media (max-width: 1280px) {
  .shell {
    grid-template-columns: var(--left-rail-collapsed-width) 1fr 0;
  }
  .shell__inspector-toggle {
    display: inline-flex;
    align-items: center;
  }
  .shell__inspector {
    position: fixed;
    top: calc(var(--header-height) + var(--view-tabs-height));
    right: 0;
    bottom: var(--context-rail-height);
    width: min(360px, 90vw);
    z-index: 20;
    box-shadow: -4px 0 16px rgba(0, 0, 0, 0.4);
    transform: translateX(100%);
    transition: transform var(--motion-duration) ease-out;
  }
  .shell__inspector[data-overlay-open="true"] {
    transform: translateX(0);
  }
}
```

(`transform`/`transition` both respect the existing `--motion-duration`
token, which is already zeroed under `prefers-reduced-motion: reduce` per
`tokens.css`'s own existing media block — no separate reduced-motion
handling needed here, it's inherited for free.)

- [ ] **Step 2: Add the toggle button and overlay state to `shell.js`**

Read `frontend/src/shell.js` in full first. Add a closure-local
`inspectorOverlayOpen` boolean (default `false`), a toggle button built
alongside the view tabs, and wire `.shell__inspector`'s
`data-overlay-open` attribute to it.

In `mountShell(rootEl, graph)`, alongside the existing `let state = ...`:

```js
  let inspectorOverlayOpen = false;
```

Give the inspector element a stable id so the toggle can reference it via
`aria-controls` (find the existing line that creates `inspector` — likely
`const inspector = el('div', { class: 'shell__inspector' }, ...)` per the
carried-forward summary of this file — read it to confirm the exact
current line before editing):

```js
  const inspector = el('div', { class: 'shell__inspector', id: 'shell-inspector' }, 'Evidence inspector (wired by the next plan)');
```

(Keep the existing placeholder text/content exactly as-is — this task
only adds the `id` attribute, nothing else about this line changes.)

Add the toggle button, built once, appended into the SAME row as the view
tabs (`tabs` element) so it's visually grouped with view navigation:

```js
  const inspectorToggle = el(
    'button',
    {
      class: 'shell__inspector-toggle',
      'aria-expanded': 'false',
      'aria-controls': 'shell-inspector',
      onClick: () => {
        inspectorOverlayOpen = !inspectorOverlayOpen;
        inspector.setAttribute('data-overlay-open', String(inspectorOverlayOpen));
        inspectorToggle.setAttribute('aria-expanded', String(inspectorOverlayOpen));
      },
    },
    'Inspector',
  );
```

Read how `tabs`/`leftRail`/`canvas`/`inspector`/`contextRail` are
assembled into `shell` (the final `el('div', {class:'shell'}, [...])`
call) and append `inspectorToggle` as a sibling appended into the
`shell__view-tabs` row's own children — the simplest real approach is to
append it directly to the `tabs` element after it's built:

```js
  tabs.appendChild(inspectorToggle);
```

(placed once, right after `const tabs = buildViewTabs(...)` — read the
exact current line to confirm `tabs` is the right variable name before
editing).

- [ ] **Step 3: Add a `shell.test.js` case**

```js
test('the inspector overlay toggle exists, is aria-controlled, and toggles data-overlay-open on the inspector element', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  const toggle = root.querySelectorAll('[aria-controls="shell-inspector"]')[0];
  assert.ok(toggle, 'expected an inspector toggle button controlling #shell-inspector');
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');

  toggle.dispatch('click');
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  const inspectorEl = shell.getInspectorEl();
  assert.equal(inspectorEl.getAttribute('data-overlay-open'), 'true');

  toggle.dispatch('click');
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  assert.equal(inspectorEl.getAttribute('data-overlay-open'), 'false');

  shell.destroy();
});
```

(Use `.dispatch('click')` — the real dom-shim click-simulation mechanism
confirmed in Task 3 of the M3-Inventory plan, not a guessed
`dispatchEvent` call. Reuse whatever `makeGraph()`-equivalent fixture
helper `shell.test.js` already defines — read the file first.)

Run: `cd frontend && node --test test/shell.test.js`
Expected: PASS.

- [ ] **Step 4: Create `frontend/styles/inventory-view.css`**

Mirror `privacy-view.css`'s exact conventions (read it first — the class
names below must match `inventory-view.js`'s real `renderInventoryView`
output exactly; re-verify the class names by reading that file's current
`renderSubNav`/`renderRow`/`renderInventoryView` before finalizing):

```css
.inventory-view {
  width: 100%;
  overflow-x: auto;
}

.inventory-subnav {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
  padding: var(--space-1) 0 var(--space-2) 0;
}

.inventory-subnav-button {
  background: transparent;
  border: var(--border-width) solid var(--border-default);
  color: var(--text-secondary);
  border-radius: var(--radius-default);
  padding: 4px var(--space-1);
  cursor: pointer;
  font-family: var(--font-family);
  font-size: var(--font-size-code);
  white-space: nowrap;
}
.inventory-subnav-button[data-active="true"] {
  color: var(--text-primary);
  background: var(--surface-elevated);
  box-shadow: inset 0 0 0 var(--border-width) var(--accent-selection);
}
.inventory-subnav-button:focus-visible {
  outline: 2px solid var(--accent-selection);
  outline-offset: 2px;
}

.inventory-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-size-body);
}

.inventory-table th {
  text-align: left;
  padding: var(--space-1) var(--space-2);
  color: var(--text-secondary);
  font-size: var(--font-size-panel-title);
  text-transform: uppercase;
  border-bottom: var(--border-width) solid var(--border-default);
  background: var(--surface-panel);
  position: sticky;
  top: 0;
  cursor: pointer;
}

.inventory-row {
  cursor: pointer;
  border-bottom: var(--border-width) solid var(--border-default);
}
.inventory-row td {
  padding: var(--space-1) var(--space-2);
  color: var(--text-primary);
}
.inventory-row:hover {
  background: var(--surface-elevated);
}
.inventory-row[data-selected="true"] {
  box-shadow: inset 3px 0 0 var(--accent-selection);
  background: var(--surface-elevated);
}
.inventory-row[data-visible="false"] {
  display: none;
}
.inventory-row:focus-visible {
  outline: 2px solid var(--accent-selection);
  outline-offset: -2px;
}
```

- [ ] **Step 5: Wire the new stylesheet into `index.html`**

Read `frontend/index.html`'s current `<link>` list first, add:

```html
  <link rel="stylesheet" href="styles/inventory-view.css" />
```

placed after the `filter-rail.css` line (matching the existing list's
rough view-then-component ordering).

- [ ] **Step 6: Full frontend test run + commit**

Run: `cd frontend && npm test`
Expected: PASS, real captured exit code 0 (CSS/HTML changes don't affect
`node --test`, but confirms nothing else broke).

```bash
git add frontend/styles/shell.css frontend/src/shell.js frontend/styles/inventory-view.css frontend/index.html frontend/test/shell.test.js
git commit -m "fix(frontend): inspector becomes a real overlay below 1280px instead of disappearing; add Inventory View's first stylesheet"
```

---

### Task 3: Real CDP-driven viewport measurement pass

**Files:**
- Modify: `frontend/CLAUDE.md` (the only file this task writes — a
  findings write-up, mirroring Perf's own measured-result precedent)

This task has NO pre-written code — it is a real measurement, performed
directly against a real browser, not simulated. The coordinator (or a
subagent with `mcp__claude-in-chrome__*` tool access) performs it
directly rather than dispatching a blind implementer, since judgment is
needed at each step (what "task-usable" and "no control unreachable"
concretely mean when actually looking at the rendered page).

- [ ] **Step 1: Serve a real graph**

From `scanner/`, run `agentic-security explore` against a real scanned
repository (the flagship fixture, or a real scan of `frontend/` itself —
whichever the operator already has set up; Task 3 of the M3-Inventory
plan already established this exact workflow, reuse it) and note the
printed `http://127.0.0.1:<port>/#token=...` URL.

- [ ] **Step 2: Resize and check each of the four required viewports**

For EACH of `1280×720`, `1440×900`, `1680×945`, `2560×1440`, and for EACH
of the four views (Architecture, Privacy, Trace, Inventory):

1. Resize the browser tab to the exact viewport dimensions
   (`mcp__claude-in-chrome__resize_window` or equivalent — confirm the
   real tool name via `ToolSearch` before use).
2. Navigate to that view, select a node/flow/row to populate the
   inspector.
3. Check and record: is the canvas usable (not visually broken/
   overlapping)? Is the left rail present (full or collapsed, per width)?
   Is the inspector reachable (in-grid above 1280px; via the new overlay
   toggle at/below 1280px — click the toggle and confirm the inspector
   becomes visible with real content, not empty)? Are primary labels
   (node labels, table cell text, view-tab labels) visually legible — spot
   check computed font-size via `mcp__claude-in-chrome__javascript_tool`
   (`getComputedStyle(el).fontSize`) on a representative label at each
   viewport, confirm ≥12px? Any console errors?

- [ ] **Step 3: Write up the real findings**

Add a new section to `frontend/CLAUDE.md`, in the same style as the
existing "Milestone 3, sub-project Perf — MEASURED, real result" section
— i.e. REAL findings, not a claim of success. If every viewport/view
combination passes cleanly, say so plainly with the specific evidence
(computed font sizes observed, confirmation the inspector toggle worked
at 1280px). If ANYTHING does not pass (a specific view/viewport
combination where a control was unreachable, a label fell below 12px, or
the canvas broke), report that as a real, disclosed, open finding —
exactly Perf's own precedent (it reported a genuine failure, not a
success, and this project treated that as valuable information, not a
problem to hide). Do not soften a real finding to make this task look
more complete than it is.

- [ ] **Step 4: Commit**

```bash
git add frontend/CLAUDE.md
git commit -m "docs(frontend): record M3-A11y's real CDP viewport measurement (AC-21)"
```

---

## Final integration checklist (coordinator, after all 3 tasks)

- Re-read every changed file in full.
- `cd frontend && npm test` green, real captured exit code.
- `cd scanner && npm test` green, real captured exit code (confirms zero
  cross-tree impact — this plan touches `frontend/` only).
- Update `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
  own A11y row to COMPLETE, including whatever Task 3 actually found
  (not a generic "done").
