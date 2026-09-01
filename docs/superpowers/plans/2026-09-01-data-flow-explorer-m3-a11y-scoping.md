# Milestone 3, sub-project A11y: contrast + viewport reflow (AC-20/AC-21)

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
own A11y row: *"Formal contrast-ratio tests (extends the existing
`contrast.js`), keyboard-focus parity, and layout assertions across the
four named viewports (1280×720/1440×900/1680×945/2560×1440) per §7.7's own
collapse/overlay rules."* Depends on Wire + Inventory (both COMPLETE) —
"needs all four views to prove the shell-level property fully."

## AC text (read verbatim this session)

- **AC-20**: *"Given high-contrast mode, grayscale output, or a user with
  color-vision deficiency, then protected, unprotected, mixed, unknown,
  manual-required, and not-assessed states remain distinguishable through
  text, icon, border/line treatment, and accessible labels."*
- **AC-21**: *"Given supported viewports of 1280×720, 1440×900, 1680×945,
  and 2560×1440, then the center visualization remains task-usable, panels
  collapse or overlay according to Section 7.7, primary labels remain at
  least 12 px, and no control or verdict becomes unreachable."*
- **§7.7** (read verbatim this session): left rail 248px, collapsible to
  56px; right inspector 360px reference, resizable 320–440px, collapsible;
  main canvas fluid, minimum 720px usable width before panels overlay.
  *"At widths below 1280 px, the inspector becomes an overlay and the
  filter rail may collapse; the graph must never shrink into unreadable
  labels. Mobile receives the inventory/table experience and a
  selected-flow summary, not a compressed full graph."*

## What already exists (confirmed by direct read this session)

- **`src/lib/contrast.js`** — real, dependency-free, first-principles WCAG
  relative-luminance + contrast-ratio implementation (`contrastRatio`,
  `meetsAA`), already unit-tested in `test/contrast.test.js` against
  synthetic hex pairs. **Never yet run against the REAL color tokens the
  app actually ships** — `styles/tokens.css`'s own comments show this was
  done manually, by hand-running `contrastRatio()` in a REPL once and
  pasting the resulting number into a CSS comment (e.g. `--status-
  banner-text`'s dark/light comments). A comment is not a test — nothing
  fails if a future token edit breaks the ratio it documents.
- **`styles/tokens.css`** — both dark (`:root`) and light
  (`:root[data-theme="light"]`) palettes already exist, with the SAME
  semantic token names in both blocks (confirmed: `--status-protected`/
  `--status-unprotected`/`--status-unknown`/`--status-banner-text`/etc.
  redefined per-theme, exactly the pattern needed for a real automated
  contrast check to iterate both themes without special-casing).
- **`src/lib/protection-visual.js`** — every verdict's `VISUALS` entry
  already carries `{verdict, label, glyph, lineStyle, colorVar}` — i.e.
  the AC-20 "text, icon, border/line treatment" redundancy already exists
  structurally for every verdict, on every view that uses it. **Never
  formally tested as a structural invariant** (no test asserts every
  `VISUALS` entry has a non-empty `glyph` AND `label` AND `lineStyle` —
  only that specific verdicts round-trip through `protectionVisual()`
  correctly, confirmed by reading `test/protection-visual.test.js`).
- **`styles/shell.css`** — the five-region grid (header/tabs/rail/canvas/
  inspector/context) with real token-driven sizing, and exactly ONE
  responsive rule:
  ```css
  @media (max-width: 1280px) {
    .shell { grid-template-columns: var(--left-rail-collapsed-width) 1fr 0; }
    .shell__inspector { display: none; }
  }
  ```
  **This does not match §7.7's own text.** §7.7 says the inspector
  "becomes an overlay" below 1280px — `display: none` makes it
  disappear entirely, not become an overlay. Since 1280×720 is itself one
  of AC-21's four REQUIRED SUPPORTED viewports (not a below-threshold
  degraded case), and the media query is `max-width: 1280px` (inclusive),
  **at exactly the smallest required viewport, the inspector is
  completely hidden with no overlay affordance to bring it back** — a
  real, concrete candidate for AC-21's "no control or verdict becomes
  unreachable" failing, not a hypothetical. This is a genuine, disclosed
  bug this sub-project fixes, not a pre-existing intentional design this
  sub-project merely tests.
- **`styles/inventory-view.css` does not exist.** Confirmed:
  `frontend/index.html`'s `<link>` list has no Inventory entry, and
  `styles/` has no such file. `inventory-view.js`'s `renderInventoryView`
  emits real class names (`inventory-view`, `inventory-subnav`,
  `inventory-subnav-button` with `data-active`/`aria-pressed`,
  `inventory-table`, `inventory-row` with `data-selected`/`data-visible`)
  that every other view's own CSS file already has a same-shaped
  counterpart for (`privacy-view.css` is the closest analog — same
  `<table>`-based structure, same `data-selected`/`data-visible` row
  attributes) — but nothing styles them today. Inventory renders with
  raw, unstyled browser table/button defaults. **This is a genuine
  prerequisite for this sub-project, not separate, deferred work**: AC-21
  requires proving all four views stay "task-usable" across four
  viewports, and an unstyled table (no sticky header, no overflow-x
  handling on a wide table, no visible row-selection affordance, no
  distinguishable sub-nav active state) cannot honestly be called
  "task-usable" — this sub-project cannot produce a real AC-21 result for
  Inventory without giving it real CSS first.
- **`test/dom-shim.js`** has no viewport/media-query concept at all (it's
  a plain DOM tree shim, no CSSOM, no `matchMedia`, no layout/box-model).
  **AC-21's viewport-reflow claims cannot be verified through
  `dom-shim.js`-based unit tests** — this is a fundamentally different
  verification mode than every prior M3 sub-project's own test suite
  (Wire/Server/XSS/Inventory were all provable via dom-shim assertions or
  curl). AC-21 needs a REAL rendering engine at REAL viewport sizes — this
  sub-project's own test plan must include real Chrome/CDP-driven
  measurement (the `agentic-security explore` server + a real served page,
  same infrastructure Task 3 of M3-Inventory's own coordinator/implementer
  already used for its manual smoke check), not just more dom-shim
  assertions. `dom-shim.js`-based tests remain the right tool for the
  STRUCTURAL half of this sub-project (e.g. "an overlay toggle control
  exists in the DOM," "every VISUALS entry has a non-empty glyph/label")
  but not the visual/layout half.
- **Keyboard-focus parity** (the scoping table's own third named item,
  alongside contrast and viewport reflow) — confirmed by reading
  `privacy-view.js`/`inventory-view.js`: every clickable row already has
  `tabindex="0"`, `role="button"`, a real `Enter`/`Space` keydown handler,
  and an `aria-label`. Confirmed by reading `filter-rail.js`: chips are
  real `<button>` elements (natively focusable/keyboard-operable, no
  custom keydown handler needed). Confirmed by reading
  `inventory-view.js`'s new sub-nav buttons: also real `<button>`
  elements. Confirmed by reading `architecture-view.js` (its nodes/edges
  are `<circle>`/`<rect>`/`<line>`-shaped SVG elements, not `<button>`s,
  so this needed a separate check): both node- and edge-rendering
  functions already set `tabindex: '0'`, `onClick`, and a real
  `onKeydown` handling `Enter`/`Space`, same pattern as every HTML view.
  **No current gap found in what's already shipped, across all four
  views** — this sub-project's own job here is a formal, automated
  regression test proving this (e.g. "every interactive element across
  all four views' real DOM output has either a native focusable tag or
  an explicit `tabindex`"), not new interaction code.

## Decisions this scoping makes

1. **This sub-project has two verification modes, not one**: (a)
   automated `node --test` assertions (contrast-ratio math against the
   real `tokens.css` file content, structural invariants on
   `protection-visual.js`, keyboard-focus-parity sweeps over real
   `compute*ViewModel`/`render*View` output via `dom-shim.js`) and (b) a
   real, CDP-driven browser measurement pass at the four named viewports
   against a really-served page, analogous to Perf's own real-Chrome
   measurement and Wire/Inventory's own manual CDP smoke checks. (b)
   cannot be replaced by more unit tests — this is a structural property
   of what AC-21 actually claims (real layout at real sizes), not a
   choice to cut corners.
2. **`test/tokens-contrast.test.js` reads `styles/tokens.css` as a real
   text file** (`fs.readFileSync`, same "read the real committed
   artifact" precedent `fixture-module-parity.test.js` already
   established for the backend fixture) and regex-extracts each `--name:
   #HEXVALUE;` custom-property declaration from both the `:root` block
   and the `:root[data-theme="light"]` block, rather than hand-copying the
   hex literals into a second JS source (which would drift the moment
   someone edits `tokens.css` without also updating a parallel JS
   constant — exactly the failure mode the existing hand-pasted comments
   already have). Assert `meetsAA()` for every verdict-status token
   against BOTH `--surface-canvas` and `--surface-panel` (the two
   backgrounds a status color/label plausibly renders on), in both
   themes, plus the two already-hand-verified pairs
   (`--status-banner-text` against `--status-unknown`, both themes) as a
   regression pin on the exact ratios the existing comments already
   claim.
3. **A structural test on `protection-visual.js`'s `VISUALS` object**
   asserts every entry has a non-empty `glyph`, `label`, and `lineStyle` —
   the code-level proof that AC-20's "text, icon, border/line treatment"
   redundancy holds for every verdict by construction, not by convention.
4. **The inspector's ≤1280px CSS is fixed from `display: none` to a real
   overlay** — `.shell__inspector` becomes `position: fixed` (or
   `absolute`, whichever `shell.css`'s existing grid allows without a
   larger rework — implementer's judgment, disclosed either way) with a
   visible toggle affordance (a button in the header or context rail;
   exact placement is this sub-project's own design decision, made and
   disclosed at implementation time, not prescribed here) so a selected
   flow/node's evidence is never permanently unreachable at the 1280px
   viewport. This is the one real, disclosed UI/CSS behavior CHANGE this
   sub-project makes — everything else is test/verification work over
   already-shipped behavior.
5. **`styles/inventory-view.css` is created**, mirroring
   `privacy-view.css`'s own conventions exactly (same token variables,
   same `data-selected`/`data-visible` attribute-selector pattern) plus
   new rules for the sub-nav strip (`.inventory-subnav`,
   `.inventory-subnav-button[data-active="true"]` — a visibly distinct
   active-tab treatment, reusing `--accent-selection` the same way
   `shell.css`'s own view-tab active state already does — read
   `shell.css`'s tab-active rule before writing this one, reuse the same
   visual language rather than inventing a new one). Wired into
   `index.html`'s `<link>` list.
6. **Architecture View's keyboard-focus parity was checked, not assumed,
   during this scoping pass — confirmed already present**, no gap: both
   node and edge SVG elements already carry `tabindex`/`onKeydown`. This
   sub-project's own scope here is the formal regression test (item 3
   below), not new interaction code for Architecture View.
7. **Mobile/narrow-viewport support (§7.7's own "mobile receives the
   inventory/table experience" sentence) is explicitly OUT of scope** —
   AC-21 only names four DESKTOP viewports (1280×720 through 2560×1440);
   mobile breakpoints are real, future, unscoped work, not silently
   assumed covered by this sub-project just because §7.7 mentions mobile
   in passing.

## Scope for this increment

1. `frontend/test/tokens-contrast.test.js` (new) — per decision 2.
2. `frontend/test/protection-visual.test.js` (extend) — per decision 3.
3. A keyboard-focus-parity sweep test (new file or extend an existing
   render-level test — implementer's judgment on placement, disclosed) —
   walks each of the four views' real rendered DOM (via the SAME small
   fixtures/pattern `xss-adversarial.test.js` already established) and
   asserts every element with an `onClick` handler is either a native
   `<button>` or carries `tabindex`.
4. `frontend/styles/shell.css` — the inspector overlay fix (decision 4).
5. `frontend/src/shell.js` — whatever minimal JS the overlay toggle needs
   (a visible open/close affordance; exact implementation is this
   sub-project's own call, disclosed).
6. `frontend/styles/inventory-view.css` (new) + `frontend/index.html`
   (wire the new stylesheet in) — per decision 5.
7. A real CDP-driven measurement pass (coordinator- or subagent-performed
   via `agentic-security explore` + a real browser) at all four named
   viewports, across all four views, checking: canvas never drops below
   720px usable width before the inspector overlay engages; primary label
   computed font-size stays ≥12px; the inspector is reachable (via the new
   overlay toggle) at 1280×720 specifically; no control is unreachable at
   any of the four sizes. Findings (pass/fail per viewport/view) are
   written into `frontend/CLAUDE.md`'s own A11y section, same as Perf's
   own measured-result precedent — a real result, not a claim.

## Do NOT touch

- Mobile/narrow breakpoints (decision 7).
- `contrast.js`'s own algorithm (already correct, already tested against
  synthetic values — this sub-project only adds a NEW test file that
  calls it against real tokens, never edits the algorithm itself).
- Any view's compute logic — this sub-project is CSS/layout/keyboard/
  contrast only, no `compute*ViewModel` changes anywhere.
- `scanner/` — frontend-only, as every M3 frontend sub-project has been.

## Test plan

1. `tokens-contrast.test.js` — real ratios against real `tokens.css`
   content, both themes, real captured pass/fail.
2. `protection-visual.test.js` extension — structural invariant, all
   verdicts.
3. Keyboard-focus-parity sweep — all four views' real render output.
4. CDP measurement pass — four viewports × four views, real browser,
   findings written up honestly (including anything that does NOT pass,
   same discipline Perf's own result used).
5. Full `frontend/npm test`, green, real captured exit code.
6. `scanner`'s own full gate, confirmed unaffected.

## Explicitly deferred

- Mobile/narrow-viewport layout (decision 7).
- Golden/state-matrix reference-composition tests (Sub-project Golden,
  depends on this sub-project's own completion).
- Any further Architecture View interaction redesign beyond closing a
  real, confirmed keyboard-focus gap if one is found (decision 6) — a
  richer keyboard nav model (arrow-key node traversal, etc.) is real,
  future, unscoped UX work.
