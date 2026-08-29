# Data Flow Explorer — Prototype Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation the Data Flow Explorer's clickable prototype needs — design tokens, safe-rendering helpers, a build-time-generated (and parity-tested) copy of the real flagship fixture, shared cross-view selection state, and the static `AppShell` — so a follow-up plan can build the three actual views (Architecture/Privacy/Trace) against a locked-in, real foundation instead of guessing at shapes.

**Architecture:** A new top-level `frontend/` directory, sibling to `scanner/`. **Zero build step by design**: plain ES modules loaded via `<script type="module">` in a static `index.html` — no bundler, no TypeScript compiler, no React, no Cytoscape/ELK. This is a deliberate scope decision, not an oversight: this repo has zero frontend tooling today (confirmed — `scanner/package.json` has no bundler/React/TS-compiler dependency anywhere), the PRD's own §17.2 "recommended" stack is explicitly conditional ("must pass the performance gates before being finalized"), and this milestone's fixture is 14 nodes/15 edges — nowhere near the 5,000-node scale (PRD §21) that would justify a heavier renderer. That evaluation belongs to Milestone 3, when real performance gates are actually being run. Validation of the graph happens at BUILD TIME in Node, reusing the real `scanner/src/lineage/validate.js` — the browser bundle imports **zero** files from `scanner/src/lineage/` at runtime (PRD §18.3: "No renderer may infer new security or privacy facts... All verdicts must be produced and validated before presentation"); it only receives a generated, pre-validated static data module.

**Tech Stack:** Plain ES modules (browser-native, no transpilation), `node:test` for the build-time/pure-logic tests, zero new npm dependencies (a hand-written HTML-escaper and a hand-written WCAG contrast calculator, since neither an existing in-repo escaper is quote-complete nor is there any existing contrast-checking code — see the research this plan is grounded in, cited inline below).

**Spec:** The Data Flow Explorer PRD (root working document, untracked by repo convention — not on disk between sessions; this plan embeds every exact value it needs). Implements PRD §7.7 (application shell), §8.1 (design tokens), §8.2 (typography/density), §16 last line + AC-15 (safe rendering hygiene), §18.3 (validate-before-present), and lays groundwork for AC-16 (shared selection state across views). Backlog items: part of DFG-027 (design tokens + `AppShell`), part of DFG-026 (flagship fixture — here, consuming it correctly in the frontend), part of DFG-028 (cross-view selection/URL-safe query state).

## Global Constraints

- **Zero build step.** Plain ES modules only, loaded via `<script type="module">`. No bundler, no TypeScript, no React, no Cytoscape.js, no ELK — deferred to Milestone 3's performance-gated renderer decision.
- **No new npm dependencies.** Confirmed via research: no existing escaping helper in this repo is quote-complete (`scanner/src/posture/fleet.js`'s `renderFleetHtml`'s `esc` escapes `&<>"` but not `'`; `scanner/src/badge.js`'s `_xmlEscape` escapes only `&<>`) — write one new one. No contrast-checking code exists anywhere — write one new one. Both are small, dependency-free, and directly testable in plain Node.
- **The prototype must consume the REAL fixture shape exactly**, verified directly against `scanner/src/lineage/fixtures/flagship-graph.json` on `main` (not the PRD's abstract §10 prose, which differs in places): `flow` objects use `source`/`sink` fields (not `sourceNodeId`/`sinkNodeId`), and flat `policyVerdict`/`protectionSummary` fields; `dataElement.dataClasses` values are UPPERCASE strings (`"PCI"`, not `"pci"`); `evidence` uses `evidenceType` (not `type`) and a loose `location: {note: "file:line"}` (a string note, not `{file,line}` — except `transformation.location`, which IS the structured `{file,line}` form); `limitations` is a flat array of strings; `graph.scope` is `{source, repository, commit, environment}`; `graph.extensions.fixtureNodeKeys` and `graph.extensions.fixtureFlowKeys` are ready-made lookup maps from the PRD Appendix D stable keys (`node.web`, `flow.pci.masked_log`, etc.) to the real canonical IDs — use these directly for any saved-view/default-selection logic rather than re-deriving them.
- **Validation is build-time, not runtime.** A Node-side generator script imports the real `scanner/src/lineage/validate.js` and `validateGraph()` to prove the embedded fixture copy is valid before it ever reaches the browser. The browser-side code never imports anything under `scanner/src/lineage/`.
- **All graph-derived text goes through `escapeHtml()` or `textContent`-only DOM insertion — never `innerHTML` with graph-derived content.** The formal adversarial-fixture XSS gate (AC-15) is explicitly scoped to Milestone 3 by `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s existing T1 entry ("The actual escaping/rendering code is Milestone 3 (UI)"), but ordinary escaping hygiene is not optional now that rendering code exists — this plan closes that "before any UI exists" framing gap in the threat-model doc (Task 6).
- **Design tokens are copied verbatim from the PRD's reference values** (embedded in Task 2 below) — do not invent, round, or "improve" a color/spacing value.
- **WCAG 2.2 AA contrast (4.5:1 for normal text) is verified programmatically, not just visually** — this is an explicit Milestone 0 deliverable (design-to-engineering handoff requires "contrast results"), not something to defer.
- Follow this repo's `git commit` convention: commit after each task with a descriptive message.

---

## File Structure

```
frontend/
  package.json                       # new — minimal, just a `test` script, zero dependencies
  README.md                          # new — zero-build-step explanation, how to open the prototype
  CLAUDE.md                          # new — package-local conventions
  index.html                         # new — entry point (built in Task 5)
  styles/
    tokens.css                       # new — PRD §8.1 design tokens (dark + light), Task 2
    shell.css                        # new — AppShell layout, Task 5
  src/
    lib/
      escape-html.js                 # new — Task 1
      contrast.js                    # new — Task 2
      dom.js                         # new — Task 3
      state.js                       # new — Task 3
    data/
      flagship-graph.js              # new — generated, Task 4 (git-ignored input is the source JSON; this file IS committed since it's small and reviewable)
    shell.js                         # new — Task 5

  scripts/
    generate-fixture-module.mjs      # new — Task 4, Node-side build script

  test/
    escape-html.test.js              # new — Task 1
    contrast.test.js                 # new — Task 2
    state.test.js                    # new — Task 3
    fixture-module-parity.test.js    # new — Task 4

CLAUDE.md                            # modify — Task 6, root repository-layout row
docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md  # modify — Task 6, close the "before any UI exists" framing gap
```

---

### Task 1: Safe HTML-escaping helper

**Files:**
- Create: `frontend/src/lib/escape-html.js`
- Test: `frontend/test/escape-html.test.js`

**Interfaces:**
- Produces: `escapeHtml(value) → string` — escapes `&`, `<`, `>`, `"`, `'`; treats `null`/`undefined` as `''`. Consumed by every later view/shell module that inserts graph-derived text.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/escape-html.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml } from '../src/lib/escape-html.js';

test('escapes all five HTML-significant characters', () => {
  assert.equal(
    escapeHtml(`<script>alert('&"x"')</script>`),
    '&lt;script&gt;alert(&#39;&amp;&quot;x&quot;&#39;)&lt;/script&gt;',
  );
});

test('handles null and undefined as empty string', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('passes through ordinary text unchanged', () => {
  assert.equal(escapeHtml('card_number'), 'card_number');
  assert.equal(escapeHtml('Payments Service'), 'Payments Service');
});

test('coerces non-string values (numbers, booleans) via String()', () => {
  assert.equal(escapeHtml(42), '42');
  assert.equal(escapeHtml(true), 'true');
});

test('a long adversarial payload with mixed HTML/JS never leaves a live tag boundary', () => {
  const payload = `"><img src=x onerror=alert(1)>&<svg/onload=alert(2)>`;
  const escaped = escapeHtml(payload);
  assert.ok(!escaped.includes('<img'));
  assert.ok(!escaped.includes('<svg'));
  assert.ok(!/(?<!&(amp|lt|gt|quot|#39);)[<>]/.test(escaped.replace(/&(amp|lt|gt|quot|#39);/g, '')), 'no raw angle bracket should survive outside an entity');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/escape-html.test.js`
Expected: FAIL — `Cannot find module '../src/lib/escape-html.js'`

- [ ] **Step 3: Write `frontend/src/lib/escape-html.js`**

```js
// Safe HTML-text escaping. Neither existing in-repo escaper is quote-complete
// (scanner/src/posture/fleet.js's `esc` skips `'`; scanner/src/badge.js's
// `_xmlEscape` skips `"` and `'`) — this one escapes all five HTML-significant
// characters so it is safe in both text content and quoted attribute values.

const ENTITIES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
});

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ENTITIES[c]);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/escape-html.test.js`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/escape-html.js frontend/test/escape-html.test.js
git commit -m "feat(frontend): add safe HTML-escaping helper"
```

---

### Task 2: Design tokens (dark + light) and a WCAG contrast checker

**Files:**
- Create: `frontend/styles/tokens.css`
- Create: `frontend/src/lib/contrast.js`
- Test: `frontend/test/contrast.test.js`

**Interfaces:**
- Produces: `contrastRatio(hexA, hexB) → number`, `meetsAA(hexA, hexB, {largeText}) → boolean`. Consumed by this task's own test to verify the token values, and available for any later accessibility work.
- Produces: CSS custom properties on `:root` (dark, the reference theme) and under `:root[data-theme="light"]` (light theme) — consumed by every later view/shell CSS file.

- [ ] **Step 1: Write the failing test**

Create `frontend/test/contrast.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contrastRatio, meetsAA } from '../src/lib/contrast.js';

test('contrastRatio of a color against itself is 1', () => {
  assert.ok(Math.abs(contrastRatio('#061625', '#061625') - 1) < 0.001);
});

test('contrastRatio of black against white is 21 (the theoretical maximum)', () => {
  assert.ok(Math.abs(contrastRatio('#000000', '#FFFFFF') - 21) < 0.01);
});

test('contrastRatio is symmetric', () => {
  assert.ok(Math.abs(contrastRatio('#F3F7FA', '#061625') - contrastRatio('#061625', '#F3F7FA')) < 0.001);
});

test('throws on a malformed hex color rather than silently producing NaN', () => {
  assert.throws(() => contrastRatio('not-a-color', '#000000'), /invalid hex color/);
});

test('meetsAA applies the 4.5:1 normal-text threshold by default', () => {
  assert.equal(meetsAA('#000000', '#FFFFFF'), true);
  assert.equal(meetsAA('#777777', '#808080'), false);
});

test('meetsAA applies the 3:1 large-text threshold when requested', () => {
  // a pair with a ratio between 3 and 4.5 — chosen to genuinely straddle the two thresholds
  const a = '#767676';
  const b = '#FFFFFF'; // WCAG's own reference: #767676 on white is exactly 4.5:1 (AA normal-text boundary)
  assert.equal(meetsAA(a, b), true);
  const c = '#949494'; // lighter gray — below 4.5:1 on white, but should still clear 3:1
  assert.equal(meetsAA(c, b), false);
  assert.equal(meetsAA(c, b, { largeText: true }), true);
});

test('design-token pairs actually used for body text meet AA (4.5:1)', () => {
  const TEXT_PRIMARY = '#F3F7FA';
  const TEXT_SECONDARY = '#9FB3C5';
  const SURFACE_CANVAS = '#061625';
  const SURFACE_PANEL = '#0B1E2F';
  const results = {
    'text-primary on surface-canvas': contrastRatio(TEXT_PRIMARY, SURFACE_CANVAS),
    'text-primary on surface-panel': contrastRatio(TEXT_PRIMARY, SURFACE_PANEL),
    'text-secondary on surface-canvas': contrastRatio(TEXT_SECONDARY, SURFACE_CANVAS),
    'text-secondary on surface-panel': contrastRatio(TEXT_SECONDARY, SURFACE_PANEL),
  };
  for (const [pair, ratio] of Object.entries(results)) {
    assert.ok(ratio >= 4.5, `${pair} is ${ratio.toFixed(2)}:1, below the 4.5:1 AA threshold`);
  }
});

test('status/class badge colors meet the 3:1 non-text (UI component) threshold against surface-panel', () => {
  // Status/class tokens are always paired with an icon+text label (AC-20), so they
  // are evaluated against WCAG's non-text-contrast minimum (3:1), not the stricter
  // body-text minimum — the text label itself uses text-primary/secondary, already
  // covered above.
  const SURFACE_PANEL = '#0B1E2F';
  const badgeTokens = {
    'status-protected': '#59D17D',
    'status-unprotected': '#FF625C',
    'status-unknown': '#F5B83D',
    'context-ai': '#B47AFF',
    'class-pii': '#28D1C5',
    'class-phi': '#A97BFF',
    'class-pci': '#4CA7FF',
  };
  for (const [name, hex] of Object.entries(badgeTokens)) {
    const ratio = contrastRatio(hex, SURFACE_PANEL);
    assert.ok(ratio >= 3, `${name} (${hex}) on surface-panel is ${ratio.toFixed(2)}:1, below the 3:1 non-text threshold`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/contrast.test.js`
Expected: FAIL — `Cannot find module '../src/lib/contrast.js'`

- [ ] **Step 3: Write `frontend/src/lib/contrast.js`**

```js
// WCAG 2.x relative-luminance contrast ratio, from first principles
// (https://www.w3.org/TR/WCAG21/#dfn-relative-luminance /
// https://www.w3.org/TR/WCAG21/#dfn-contrast-ratio). No existing contrast
// checker exists anywhere in this repo — this is a small, dependency-free,
// directly-testable implementation rather than a new npm dependency.

function srgbChannelToLinear(c8) {
  const c = c8 / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function hexToRgb(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(String(hex));
  if (!m) throw new Error(`hexToRgb: invalid hex color "${hex}" (expected #RRGGBB)`);
  const int = parseInt(m[1], 16);
  return [(int >> 16) & 255, (int >> 8) & 255, int & 255];
}

function relativeLuminance([r, g, b]) {
  const [rl, gl, bl] = [r, g, b].map(srgbChannelToLinear);
  return 0.2126 * rl + 0.7152 * gl + 0.0722 * bl;
}

export function contrastRatio(hexA, hexB) {
  const lumA = relativeLuminance(hexToRgb(hexA));
  const lumB = relativeLuminance(hexToRgb(hexB));
  const lighter = Math.max(lumA, lumB);
  const darker = Math.min(lumA, lumB);
  return (lighter + 0.05) / (darker + 0.05);
}

export function meetsAA(hexA, hexB, { largeText = false } = {}) {
  return contrastRatio(hexA, hexB) >= (largeText ? 3 : 4.5);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test test/contrast.test.js`
Expected: PASS (7 tests). **If any of the last two tests fail against the PRD's real token values**, do not weaken the assertion or invent a new color — that is a genuine finding. Report it in your task report as a concern and proceed to Step 5 with the token file as specified (the values are copied verbatim from the PRD by design); flag it for the controller to decide whether to escalate a token-value correction as a separate, deliberate change.

- [ ] **Step 5: Write `frontend/styles/tokens.css`**

```css
/*
 * Data Flow Explorer design tokens (PRD §8.1). Dark is the reference theme.
 * Values are copied verbatim from the PRD — do not adjust without a
 * deliberate, separately-reviewed change.
 */

:root {
  /* Surfaces */
  --surface-canvas: #061625;
  --surface-panel: #0B1E2F;
  --surface-elevated: #102A40;
  --border-default: #28445A;

  /* Text */
  --text-primary: #F3F7FA;
  --text-secondary: #9FB3C5;

  /* Selection / focus */
  --accent-selection: #3DA9FF;

  /* Protection verdict status */
  --status-protected: #59D17D;
  --status-unprotected: #FF625C;
  --status-unknown: #F5B83D;

  /* AI processing context */
  --context-ai: #B47AFF;

  /* Data class overlays */
  --class-pii: #28D1C5;
  --class-phi: #A97BFF;
  --class-pci: #4CA7FF;

  /* Spacing (8px grid, PRD §7.7) */
  --space-1: 8px;
  --space-2: 16px;
  --space-3: 24px;
  --space-4: 32px;

  /* Radius / border (PRD §8.2) */
  --radius-default: 8px;
  --border-width: 1px;

  /* Typography (PRD §8.2) — bundled system stack; never a remote/CDN font */
  --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --font-size-view-title: 23px;
  --font-size-panel-title: 15px;
  --font-size-node-title: 14px;
  --font-size-body: 13px;
  --font-size-code: 12.5px;

  /* Motion (PRD §8.2 — focus/topology change only, no ambient animation) */
  --motion-duration: 200ms;
  --motion-duration-reduced: 0ms;

  /* Shell region sizing (PRD §7.7) */
  --header-height: 56px;
  --view-tabs-height: 44px;
  --left-rail-width: 248px;
  --left-rail-collapsed-width: 56px;
  --right-inspector-width: 360px;
  --context-rail-height: 72px;
}

/* Light theme — same semantic tokens, WCAG-AA-equivalent contrast (PRD §8.1/§23) */
:root[data-theme="light"] {
  --surface-canvas: #FFFFFF;
  --surface-panel: #F4F7FA;
  --surface-elevated: #E7EEF3;
  --border-default: #C7D3DC;

  --text-primary: #0B1E2F;
  --text-secondary: #3E5568;

  --accent-selection: #1B6FC2;

  --status-protected: #1E8A4C;
  --status-unprotected: #C7362D;
  --status-unknown: #9A6B00;

  --context-ai: #6E38B8;

  --class-pii: #0E7C73;
  --class-phi: #6E44B8;
  --class-pci: #1C63A8;
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --motion-duration: var(--motion-duration-reduced);
  }
}

body {
  background: var(--surface-canvas);
  color: var(--text-primary);
  font-family: var(--font-family);
  font-size: var(--font-size-body);
  margin: 0;
}
```

- [ ] **Step 6: Commit**

```bash
git add frontend/styles/tokens.css frontend/src/lib/contrast.js frontend/test/contrast.test.js
git commit -m "feat(frontend): add design tokens (dark+light) and a WCAG contrast checker"
```

---

### Task 3: Safe DOM builder and shared cross-view URL-hash state

**Files:**
- Create: `frontend/src/lib/dom.js`
- Create: `frontend/src/lib/state.js`
- Test: `frontend/test/state.test.js`

**Interfaces:**
- Produces: `el(tag, attrs, children) → HTMLElement` — a safe DOM builder; attributes are set via `setAttribute`/`className`/event-listener binding, text children via `document.createTextNode`, never `innerHTML`. **This function is browser-only (requires `document`) and is intentionally not unit-tested in this task** — it is a thin (~20-line), purely mechanical wrapper with no branching logic worth a new `jsdom` dependency to unit-test; it is exercised by the manual browser smoke-check in Task 5's own verification step and every later view task.
- Produces: `parseStateFromHash(hash) → {view, selectedId, filters}`, `serializeStateToHash(state) → string` — pure functions, fully unit-tested, no DOM required. Consumed by `shell.js` (Task 5) and later view tasks for cross-view selection persistence (AC-16).

- [ ] **Step 1: Write the failing test**

Create `frontend/test/state.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseStateFromHash, serializeStateToHash } from '../src/lib/state.js';

test('parseStateFromHash returns defaults for an empty hash', () => {
  const state = parseStateFromHash('');
  assert.deepEqual(state, { view: 'architecture', selectedId: null, filters: {} });
});

test('parseStateFromHash returns defaults for a bare "#"', () => {
  assert.deepEqual(parseStateFromHash('#'), { view: 'architecture', selectedId: null, filters: {} });
});

test('parseStateFromHash reads view and selectedId', () => {
  const state = parseStateFromHash('#view=trace&selected=flow%3Apci.payment_api');
  assert.equal(state.view, 'trace');
  assert.equal(state.selectedId, 'flow:pci.payment_api');
});

test('parseStateFromHash reads a filters object from a JSON-encoded param', () => {
  const state = parseStateFromHash('#view=architecture&filters=%7B%22class%22%3A%5B%22PCI%22%5D%7D');
  assert.deepEqual(state.filters, { class: ['PCI'] });
});

test('parseStateFromHash falls back to defaults on malformed filters JSON rather than throwing', () => {
  const state = parseStateFromHash('#view=architecture&filters=not-json');
  assert.deepEqual(state.filters, {});
});

test('parseStateFromHash rejects an unknown view name back to the default', () => {
  const state = parseStateFromHash('#view=not-a-real-view');
  assert.equal(state.view, 'architecture');
});

test('serializeStateToHash round-trips through parseStateFromHash', () => {
  const original = { view: 'privacy', selectedId: 'node:process:abc123', filters: { class: ['PHI'], ai: true } };
  const hash = serializeStateToHash(original);
  const parsed = parseStateFromHash(hash);
  assert.deepEqual(parsed, original);
});

test('serializeStateToHash never places raw graph-derived text unescaped in a way that breaks URL parsing', () => {
  const withWeirdId = { view: 'trace', selectedId: 'flow:has "quotes" & stuff', filters: {} };
  const hash = serializeStateToHash(withWeirdId);
  const parsed = parseStateFromHash(hash);
  assert.equal(parsed.selectedId, withWeirdId.selectedId);
});

test('parseStateFromHash never throws on adversarial input', () => {
  const adversarialInputs = ['#view=&selected=&filters=', '#%zz', '#view=architecture&filters=[1,2,3', '#a=b=c&&&'];
  for (const input of adversarialInputs) {
    assert.doesNotThrow(() => parseStateFromHash(input), `input "${input}" should not throw`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/state.test.js`
Expected: FAIL — `Cannot find module '../src/lib/state.js'`

- [ ] **Step 3: Write `frontend/src/lib/dom.js`**

```js
// Safe DOM element builder. Attributes are set via setAttribute/className/
// addEventListener; text children go through createTextNode. Never uses
// innerHTML — graph-derived text can never become live markup through this
// function (PRD §16 last line, AC-15 hygiene, even though the formal
// adversarial-fixture gate is Milestone 3's).

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = String(value);
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, String(value));
  }
  for (const child of [].concat(children)) {
    if (child === undefined || child === null || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}
```

- [ ] **Step 4: Write `frontend/src/lib/state.js`**

```js
// Shared cross-view selection/filter state, persisted in the URL hash so
// switching views preserves the selected canonical ID and filters (AC-16),
// and so state is shareable/bookmarkable without a server. Per PRD §7.11:
// "URL state contains canonical IDs and non-sensitive filter expressions,
// never source snippets, field values, or secret-bearing endpoints" — this
// module only ever carries canonical IDs and filter keys/values the caller
// supplies, never arbitrary text.

const VALID_VIEWS = new Set(['architecture', 'privacy', 'trace']);
const DEFAULT_STATE = Object.freeze({ view: 'architecture', selectedId: null, filters: {} });

export function parseStateFromHash(hash) {
  const raw = String(hash ?? '').replace(/^#/, '');
  if (!raw) return { ...DEFAULT_STATE, filters: {} };

  let params;
  try {
    params = new URLSearchParams(raw);
  } catch {
    return { ...DEFAULT_STATE, filters: {} };
  }

  const view = params.get('view');
  const selectedId = params.get('selected');
  const filtersRaw = params.get('filters');

  let filters = {};
  if (filtersRaw) {
    try {
      const parsed = JSON.parse(filtersRaw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) filters = parsed;
    } catch {
      filters = {};
    }
  }

  return {
    view: VALID_VIEWS.has(view) ? view : DEFAULT_STATE.view,
    selectedId: selectedId || null,
    filters,
  };
}

export function serializeStateToHash(state) {
  const params = new URLSearchParams();
  params.set('view', VALID_VIEWS.has(state.view) ? state.view : DEFAULT_STATE.view);
  if (state.selectedId) params.set('selected', state.selectedId);
  if (state.filters && Object.keys(state.filters).length > 0) params.set('filters', JSON.stringify(state.filters));
  return `#${params.toString()}`;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd frontend && node --test test/state.test.js`
Expected: PASS (9 tests)

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib/dom.js frontend/src/lib/state.js frontend/test/state.test.js
git commit -m "feat(frontend): add safe DOM builder and cross-view URL-hash state"
```

---

### Task 4: Build-time fixture module generator, with real-validator parity proof

**Files:**
- Create: `frontend/scripts/generate-fixture-module.mjs`
- Create: `frontend/src/data/flagship-graph.js` (generated output, committed)
- Test: `frontend/test/fixture-module-parity.test.js`

**Interfaces:**
- Produces: `frontend/src/data/flagship-graph.js` exporting `export const FLAGSHIP_GRAPH = {...}` — the browser-side copy of the real fixture. Consumed by `shell.js` (Task 5) and every later view module.
- Consumes: `scanner/src/lineage/fixtures/flagship-graph.json` (the real backend fixture, already on `main`) and `scanner/src/lineage/validate.js`'s `validateGraph` (Node-side only, at generation/test time — never shipped to the browser).

- [ ] **Step 1: Write the failing test**

Create `frontend/test/fixture-module-parity.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const BACKEND_FIXTURE_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const FRONTEND_MODULE_PATH = path.join(HERE, '..', 'src', 'data', 'flagship-graph.js');

test('frontend/src/data/flagship-graph.js exists and is importable', async () => {
  assert.ok(fs.existsSync(FRONTEND_MODULE_PATH), 'run `node scripts/generate-fixture-module.mjs` first');
  const mod = await import(FRONTEND_MODULE_PATH);
  assert.ok(mod.FLAGSHIP_GRAPH, 'expected a named export FLAGSHIP_GRAPH');
});

test('the embedded copy is byte-identical in content to the real backend fixture', async () => {
  const backend = JSON.parse(fs.readFileSync(BACKEND_FIXTURE_PATH, 'utf8'));
  const mod = await import(FRONTEND_MODULE_PATH);
  assert.deepEqual(mod.FLAGSHIP_GRAPH, backend);
});

test('the embedded copy passes the REAL validateGraph() with zero errors', async () => {
  const { validateGraph } = await import(path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'validate.js'));
  const mod = await import(FRONTEND_MODULE_PATH);
  const result = validateGraph(mod.FLAGSHIP_GRAPH);
  assert.equal(result.valid, true, JSON.stringify(result.errors, null, 2));
  assert.deepEqual(result.errors, []);
});

test('extensions.fixtureNodeKeys and fixtureFlowKeys resolve to real ids in the embedded copy', async () => {
  const mod = await import(FRONTEND_MODULE_PATH);
  const graph = mod.FLAGSHIP_GRAPH;
  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  const flowIds = new Set(graph.flows.map((f) => f.id));
  for (const [key, id] of Object.entries(graph.extensions.fixtureNodeKeys ?? {})) {
    assert.ok(nodeIds.has(id), `fixtureNodeKeys.${key} -> ${id} does not resolve to a real node`);
  }
  for (const [key, id] of Object.entries(graph.extensions.fixtureFlowKeys ?? {})) {
    assert.ok(flowIds.has(id), `fixtureFlowKeys.${key} -> ${id} does not resolve to a real flow`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test test/fixture-module-parity.test.js`
Expected: FAIL — `frontend/src/data/flagship-graph.js` does not exist

- [ ] **Step 3: Write `frontend/scripts/generate-fixture-module.mjs`**

```js
#!/usr/bin/env node
// Reads the real backend flagship fixture, validates it with the REAL
// validateGraph() (Node-side only — this script never ships to the
// browser), and writes a browser-importable ES module copy. Re-run this
// whenever scanner/src/lineage/fixtures/flagship-graph.json changes;
// test/fixture-module-parity.test.js enforces that the committed output
// stays in sync and stays valid.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const BACKEND_FIXTURE_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const OUTPUT_PATH = path.join(HERE, '..', 'src', 'data', 'flagship-graph.js');
const VALIDATE_JS_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'validate.js');

async function main() {
  const graph = JSON.parse(fs.readFileSync(BACKEND_FIXTURE_PATH, 'utf8'));

  const { validateGraph } = await import(VALIDATE_JS_PATH);
  const result = validateGraph(graph);
  if (!result.valid) {
    process.stderr.write(`generate-fixture-module.mjs: backend fixture failed validateGraph():\n${JSON.stringify(result.errors, null, 2)}\n`);
    process.exit(1);
  }

  const header = `// GENERATED FILE — do not edit by hand.\n// Source: scanner/src/lineage/fixtures/flagship-graph.json\n// Regenerate: node frontend/scripts/generate-fixture-module.mjs\n// This copy has been validated by the real validateGraph() at generation\n// time (see frontend/test/fixture-module-parity.test.js for the ongoing\n// proof) — the browser bundle itself never imports scanner/src/lineage/.\n\n`;
  const body = `export const FLAGSHIP_GRAPH = ${JSON.stringify(graph, null, 2)};\n`;

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, header + body);
  process.stdout.write(`wrote ${OUTPUT_PATH} (${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.flows.length} flows)\n`);
}

main();
```

- [ ] **Step 4: Run the generator and then the test**

Run: `cd frontend && node scripts/generate-fixture-module.mjs`
Expected: `wrote .../frontend/src/data/flagship-graph.js (14 nodes, 15 edges, 8 flows)`

Run: `cd frontend && node --test test/fixture-module-parity.test.js`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add frontend/scripts/generate-fixture-module.mjs frontend/src/data/flagship-graph.js frontend/test/fixture-module-parity.test.js
git commit -m "feat(frontend): generate and parity-test the browser-side flagship fixture module"
```

---

### Task 5: AppShell skeleton

**Files:**
- Create: `frontend/index.html`
- Create: `frontend/styles/shell.css`
- Create: `frontend/src/shell.js`

**Interfaces:**
- Consumes: `el`/`clear` (Task 3's `dom.js`), `parseStateFromHash`/`serializeStateToHash` (Task 3's `state.js`), `escapeHtml` (Task 1), `FLAGSHIP_GRAPH` (Task 4's generated module).
- Produces: `mountShell(rootEl, graph) → {setActiveView(viewName), getCanvasEl(), getInspectorEl()}` — consumed by the next plan's view modules to mount their rendering into the shell's canvas/inspector regions.

- [ ] **Step 1: Write `frontend/index.html`**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Data Flow Explorer — Illustrative demo data</title>
  <link rel="stylesheet" href="styles/tokens.css" />
  <link rel="stylesheet" href="styles/shell.css" />
</head>
<body>
  <div id="app-root"></div>
  <script type="module">
    import { mountShell } from './src/shell.js';
    import { FLAGSHIP_GRAPH } from './src/data/flagship-graph.js';

    const root = document.getElementById('app-root');
    mountShell(root, FLAGSHIP_GRAPH);
  </script>
</body>
</html>
```

- [ ] **Step 2: Write `frontend/styles/shell.css`**

```css
/* AppShell layout — PRD §7.7 five persistent regions on an 8px spacing grid. */

.shell {
  display: grid;
  grid-template-rows: var(--header-height) var(--view-tabs-height) 1fr var(--context-rail-height);
  grid-template-columns: var(--left-rail-width) 1fr var(--right-inspector-width);
  grid-template-areas:
    "header header header"
    "tabs   tabs   tabs"
    "rail   canvas inspector"
    "rail   context context";
  height: 100vh;
  width: 100vw;
  background: var(--surface-canvas);
}

.shell__header {
  grid-area: header;
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0 var(--space-2);
  background: var(--surface-panel);
  border-bottom: var(--border-width) solid var(--border-default);
}

.shell__header-title {
  font-size: var(--font-size-view-title);
  font-weight: 600;
  color: var(--text-primary);
}

.shell__header-meta {
  color: var(--text-secondary);
  font-size: var(--font-size-body);
}

.shell__coverage-banner {
  grid-area: header;
  align-self: end;
  justify-self: stretch;
  margin: 0 var(--space-2) 0 var(--space-2);
  display: none;
}
.shell__coverage-banner[data-visible="true"] {
  display: block;
  background: var(--status-unknown);
  color: #061625;
  padding: 4px var(--space-2);
  border-radius: var(--radius-default);
  font-size: var(--font-size-body);
}

.shell__view-tabs {
  grid-area: tabs;
  display: flex;
  align-items: center;
  gap: var(--space-1);
  padding: 0 var(--space-2);
  background: var(--surface-panel);
  border-bottom: var(--border-width) solid var(--border-default);
}

.shell__view-tab {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-family: var(--font-family);
  font-size: var(--font-size-panel-title);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-default);
  cursor: pointer;
}
.shell__view-tab[aria-selected="true"] {
  color: var(--text-primary);
  background: var(--surface-elevated);
  box-shadow: inset 0 0 0 var(--border-width) var(--accent-selection);
}
.shell__view-tab:focus-visible {
  outline: 2px solid var(--accent-selection);
  outline-offset: 2px;
}

.shell__left-rail {
  grid-area: rail;
  background: var(--surface-panel);
  border-right: var(--border-width) solid var(--border-default);
  padding: var(--space-2);
  overflow-y: auto;
}

.shell__canvas {
  grid-area: canvas;
  overflow: auto;
  padding: var(--space-2);
}

.shell__inspector {
  grid-area: inspector;
  background: var(--surface-panel);
  border-left: var(--border-width) solid var(--border-default);
  padding: var(--space-2);
  overflow-y: auto;
}

.shell__context-rail {
  grid-area: context;
  background: var(--surface-panel);
  border-top: var(--border-width) solid var(--border-default);
  padding: 0 var(--space-2);
  display: flex;
  align-items: center;
  color: var(--text-secondary);
  font-size: var(--font-size-body);
}

@media (max-width: 1280px) {
  .shell {
    grid-template-columns: var(--left-rail-collapsed-width) 1fr 0;
  }
  .shell__inspector {
    display: none;
  }
}
```

- [ ] **Step 3: Write `frontend/src/shell.js`**

```js
import { el, clear } from './lib/dom.js';
import { escapeHtml } from './lib/escape-html.js';
import { parseStateFromHash, serializeStateToHash } from './lib/state.js';

const VIEWS = [
  { id: 'architecture', label: 'Architecture' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'trace', label: 'Trace' },
];

/**
 * @param {HTMLElement} rootEl
 * @param {object} graph - a DataFlowGraph v1 envelope (already validated at build time)
 * @returns {{ setActiveView: (viewName: string) => void, getCanvasEl: () => HTMLElement, getInspectorEl: () => HTMLElement }}
 */
export function mountShell(rootEl, graph) {
  let state = parseStateFromHash(window.location.hash);

  const shell = el('div', { class: 'shell' });
  const header = buildHeader(graph);
  const coverageBanner = buildCoverageBanner(graph);
  const tabs = buildViewTabs(state.view, (nextView) => {
    state = { ...state, view: nextView };
    window.location.hash = serializeStateToHash(state);
    applyActiveTab(tabs, state.view);
  });
  const leftRail = el('div', { class: 'shell__left-rail' }, 'Filters (wired by the next plan)');
  const canvas = el('div', { class: 'shell__canvas' });
  const inspector = el('div', { class: 'shell__inspector' }, 'Evidence inspector (wired by the next plan)');
  const contextRail = el('div', { class: 'shell__context-rail' }, buildContextRailText(graph));

  shell.appendChild(header);
  shell.appendChild(coverageBanner);
  shell.appendChild(tabs);
  shell.appendChild(leftRail);
  shell.appendChild(canvas);
  shell.appendChild(inspector);
  shell.appendChild(contextRail);

  clear(rootEl);
  rootEl.appendChild(shell);

  window.addEventListener('hashchange', () => {
    state = parseStateFromHash(window.location.hash);
    applyActiveTab(tabs, state.view);
  });

  return {
    setActiveView(viewName) {
      state = { ...state, view: viewName };
      window.location.hash = serializeStateToHash(state);
      applyActiveTab(tabs, state.view);
    },
    getCanvasEl: () => canvas,
    getInspectorEl: () => inspector,
  };
}

function buildHeader(graph) {
  const repo = graph.scope?.repository ?? 'unknown repository';
  const env = graph.scope?.environment ?? 'unknown environment';
  const scanStatus = graph.scanHealth?.status ?? 'unknown';
  const isFixture = graph.scope?.source === 'fixture';
  return el('div', { class: 'shell__header' }, [
    el('div', { class: 'shell__header-title' }, 'Data Flow Explorer'),
    el('div', { class: 'shell__header-meta' }, `${escapeHtml(repo)} · ${escapeHtml(env)} · Scan ${escapeHtml(scanStatus)}`),
    isFixture ? el('div', { class: 'shell__header-meta', 'data-illustrative': 'true' }, 'Illustrative demo data') : null,
  ]);
}

function buildCoverageBanner(graph) {
  const status = graph.coverage?.status ?? graph.scanHealth?.status;
  const banner = el('div', { class: 'shell__coverage-banner' }, `Coverage: ${escapeHtml(status ?? 'unknown')} — not a complete assessment`);
  if (status && status !== 'complete') banner.setAttribute('data-visible', 'true');
  return banner;
}

function buildViewTabs(activeView, onSelect) {
  const tabs = el(
    'div',
    { class: 'shell__view-tabs', role: 'tablist' },
    VIEWS.map((v) =>
      el(
        'button',
        {
          class: 'shell__view-tab',
          role: 'tab',
          'aria-selected': String(v.id === activeView),
          'data-view-id': v.id,
          onClick: () => onSelect(v.id),
        },
        v.label,
      ),
    ),
  );
  return tabs;
}

function applyActiveTab(tabsEl, activeView) {
  for (const btn of tabsEl.querySelectorAll('[data-view-id]')) {
    btn.setAttribute('aria-selected', String(btn.getAttribute('data-view-id') === activeView));
  }
}

function buildContextRailText(graph) {
  return `${graph.nodes.length} nodes · ${graph.edges.length} edges · ${graph.flows.length} flows`;
}
```

- [ ] **Step 4: Manual browser smoke check**

This task's core logic (`state.js`, `escape-html.js`) is already unit-tested; `dom.js` and `shell.js` are browser-only per this plan's Global Constraints. Verify manually:

Run: `cd frontend && python3 -m http.server 8420` (or any static file server — no build step means any static server works)
Open: `http://localhost:8420/` in a browser
Expected: the five shell regions render, the header shows "payments-platform · production · Scan complete" (or whatever the real fixture's scope/scanHealth say) plus "Illustrative demo data", the three view tabs (Architecture/Privacy/Trace) are clickable and update the URL hash (`#view=privacy&...`), and the context rail shows "14 nodes · 15 edges · 8 flows". Take a screenshot or describe what rendered in your task report — this is the acceptance evidence for this step since there is no automated DOM test in this plan.

- [ ] **Step 5: Commit**

```bash
git add frontend/index.html frontend/styles/shell.css frontend/src/shell.js
git commit -m "feat(frontend): add the AppShell skeleton"
```

---

### Task 6: Documentation and threat-model update

**Files:**
- Create: `frontend/README.md`
- Create: `frontend/CLAUDE.md`
- Create: `frontend/package.json`
- Modify: `CLAUDE.md` (repository root)
- Modify: `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`

**Interfaces:** none — documentation and wiring only.

- [ ] **Step 1: Write `frontend/package.json`**

```json
{
  "name": "@clear-capabilities/agentic-security-frontend-prototype",
  "private": true,
  "version": "0.0.0",
  "description": "Data Flow Explorer clickable prototype — zero build step, plain ES modules.",
  "type": "module",
  "scripts": {
    "test": "node --test test/escape-html.test.js test/contrast.test.js test/state.test.js test/fixture-module-parity.test.js",
    "generate-fixture": "node scripts/generate-fixture-module.mjs",
    "serve": "python3 -m http.server 8420"
  }
}
```

- [ ] **Step 2: Run it to confirm the aggregate script works**

Run: `cd frontend && npm test`
Expected: PASS (all 4 test files, matching what each task already verified individually)

- [ ] **Step 3: Write `frontend/README.md`**

```markdown
# Data Flow Explorer — prototype

A clickable prototype for the Data Flow Explorer, rendering the flagship
reference fixture (see `scanner/src/lineage/fixtures/`). **Zero build
step** — plain ES modules, no bundler, no TypeScript, no framework. Open
`index.html` via any static file server (not `file://`, since ES module
imports require an HTTP origin in most browsers):

```bash
npm run serve
# then open http://localhost:8420/
```

## Why no build step, no React, no Cytoscape/ELK

The PRD's own §17.2 "recommended" frontend stack is explicitly conditional
on passing later performance gates (§21: 5,000 nodes / 10,000 edges). This
prototype's fixture is 14 nodes / 15 edges. Introducing a bundler, a
compile step, and a graph-rendering library to hit a 14-node target would
be solving a problem this milestone doesn't have. That evaluation belongs
to Milestone 3, against the real performance budgets, with real graphs.

## Why the fixture is a generated file, not a live fetch

`src/data/flagship-graph.js` is generated by `scripts/generate-fixture-module.mjs`
from the real `scanner/src/lineage/fixtures/flagship-graph.json`, validated
at generation time by the real `validateGraph()` — see
`test/fixture-module-parity.test.js` for the ongoing proof that the two
stay in sync and stay valid. The browser bundle itself never imports
anything under `scanner/src/lineage/` (PRD §18.3: verdicts must be produced
and validated before presentation, not inferred by the renderer). Re-run
`npm run generate-fixture` after any change to the backend fixture.

## What's here vs. what's next

This is the *foundation*: design tokens, safe-rendering helpers
(`escape-html.js`, `dom.js`), shared cross-view URL-hash state
(`state.js`), and the static `AppShell` (`shell.js`). The three actual
views (Architecture/Privacy/Trace) and the evidence inspector are a
follow-up plan, built against this foundation's locked-in module shapes.
```

- [ ] **Step 4: Write `frontend/CLAUDE.md`**

```markdown
# frontend/

Data Flow Explorer's clickable prototype. See `README.md` for the
zero-build-step rationale and how to run it.

| Module | Responsibility |
|---|---|
| `src/lib/escape-html.js` | The one safe way to insert graph-derived text as HTML-ish content. Quote-complete (escapes `&<>"'`) — neither existing in-repo escaper (`scanner/src/posture/fleet.js`, `scanner/src/badge.js`) is. |
| `src/lib/contrast.js` | WCAG relative-luminance contrast ratio, from first principles — no existing contrast tooling anywhere in this repo. |
| `src/lib/dom.js` | Safe DOM element builder (`el()`) — never `innerHTML`. Browser-only, not unit-tested (too thin to justify a `jsdom` dependency); exercised via manual browser smoke-checks. |
| `src/lib/state.js` | Cross-view selection/filter state, persisted in the URL hash (AC-16). Pure functions, fully unit-tested. |
| `src/data/flagship-graph.js` | **Generated** — do not hand-edit. Run `npm run generate-fixture` after any change to `scanner/src/lineage/fixtures/flagship-graph.json`. `test/fixture-module-parity.test.js` enforces this file stays byte-identical to the backend fixture and passes the real `validateGraph()`. |
| `src/shell.js` | The `AppShell` — header, view tabs, left rail, canvas, inspector, context rail (PRD §7.7). |

## Conventions

- **No `innerHTML` with graph-derived content, ever.** Use `el()` (`lib/dom.js`) or `document.createTextNode`/`textContent`. The formal adversarial-fixture XSS test suite is Milestone 3's (per `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s T1 entry), but this hygiene rule is not optional now that rendering code exists.
- **No new runtime dependency without updating this file's own "why no build step" reasoning first** — the zero-build-step decision is deliberate, not an oversight; see `README.md`.
- **The prototype consumes the real fixture shape, not the PRD's abstract prose.** Field names like `flow.source`/`flow.sink`, `evidence.evidenceType`, and `dataElement.dataClasses` being UPPERCASE were confirmed against the actual committed JSON — if the backend fixture's shape changes, re-run `npm run generate-fixture`, re-run `npm test`, and update any view code that assumed the old shape.
```

- [ ] **Step 5: Add the repository-layout row to root `CLAUDE.md`**

Insert after the `scanner/src/lineage/` row:

```markdown
| `frontend/` | Data Flow Explorer clickable prototype. Zero build step (plain ES modules); consumes the `DataFlowGraph v1` fixture via a build-time-generated, parity-tested copy. Milestone 0 (second half) of the Data Flow Explorer PRD. | `frontend/CLAUDE.md` |
```

- [ ] **Step 6: Update `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`**

Find the T1 (hostile repository text / XSS) entry's status note, which currently frames itself as "before any server or UI code exists." Update it to reflect that a prototype now exists — read the actual current wording first (it was written in the earlier plan and may not match this text exactly), and edit it to state plainly: a static, zero-build-step prototype now exists (`frontend/`); it applies ordinary escaping hygiene via `frontend/src/lib/escape-html.js` and `frontend/src/lib/dom.js` (never `innerHTML` with graph-derived content) as a baseline precaution, but the FORMAL adversarial-fixture XSS test suite and CSP/server-hardening work remain scoped to Milestone 3 as originally stated — this update is narrowing an inaccurate "doesn't exist yet" framing, not expanding scope.

- [ ] **Step 7: Run the full frontend suite once more, then commit**

Run: `cd frontend && npm test`
Expected: PASS

```bash
git add frontend/README.md frontend/CLAUDE.md frontend/package.json CLAUDE.md docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md
git commit -m "docs(frontend): document the prototype foundation and update the threat model"
```

---

## Self-Review Notes (completed by the plan author before handoff)

**Spec coverage:** PRD §7.7 (AppShell five regions) → Task 5. §8.1 (design tokens, dark+light) → Task 2. §8.2 (typography/spacing/motion tokens) → Task 2. §16 last line / AC-15 hygiene → Task 1 + Task 3's `dom.js` + Task 6's threat-model update. §18.3 (validate before present, no runtime lineage import) → Task 4. AC-16 groundwork (shared selection state) → Task 3's `state.js` + Task 5's wiring. WCAG AA contrast as an explicit deliverable → Task 2. What this plan does **not** cover (deliberately, follow-up plan): the three actual views, the evidence inspector's real content, focus/keyboard interaction beyond the tab bar, semantic zoom, golden-image regression testing (DFG-034, its own later backlog item) — each needs this plan's exact module shapes locked in first.

**Placeholder scan:** every step contains complete, runnable code. Task 5's Step 4 (manual browser check) is not a placeholder — it's an explicit, honest scoping decision (documented in Task 3's Interfaces section) that `dom.js`/`shell.js` are browser-only and not unit-tested in this plan, with a concrete, checkable expected outcome given for the manual step.

**Type consistency:** `escapeHtml(value) → string` (Task 1) used identically in Task 5. `contrastRatio`/`meetsAA` (Task 2) self-contained, not consumed elsewhere in this plan. `el(tag, attrs, children)`, `clear(node)` (Task 3) used identically in Task 5. `parseStateFromHash(hash) → {view, selectedId, filters}` / `serializeStateToHash(state) → string` (Task 3) used identically in Task 5. `FLAGSHIP_GRAPH` (Task 4) consumed identically in Task 5 and in Task 5's own manual verification. `mountShell(rootEl, graph) → {setActiveView, getCanvasEl, getInspectorEl}` (Task 5) is the interface the follow-up (views) plan will consume — documented precisely so that plan can be written against it without guessing.
