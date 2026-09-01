# Milestone 3, sub-project XSS: T1 adversarial-fixture test suite

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
own XSS row and `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s T1 entry,
which pre-specifies this increment's exact required shape: *"an
adversarial fixture (HTML/script tags/control chars/very long
identifiers in file and symbol names) and a test asserting the rendered
DOM contains no live `<script>`, `javascript:` URL, or unescaped tag from
that fixture."*

## What already exists (confirmed by direct read, this session, HEAD `ef2e0016`)

- **CSP hardening is already done**, both halves: `scanner/src/server/
  security.js`'s `CSP_HEADER_VALUE` (`default-src 'none'`, the `/api/v1/*`
  JSON routes) and `scanner/src/server/static-assets.js`'s
  `STATIC_CSP_HEADER_VALUE` (`default-src 'self'; script-src 'self'; ...`,
  the static/HTML routes) — both shipped in prior increments (Server S1,
  Wire). **This increment's own remaining scope is the adversarial-
  fixture test suite itself, not new CSP work** — the scoping table's own
  "CSP hardening" clause is already satisfied; re-verify this is true at
  implementation time rather than assuming, but do not duplicate work if
  it is.
- `frontend/src/lib/dom.js`'s `el()` — text children go through
  `document.createTextNode`, confirmed (per `frontend/CLAUDE.md`'s own
  documented convention) to provide full escaping on its own, since
  `createTextNode` never interprets its argument as markup. This is the
  hygiene mechanism T1's own "Mitigation" clause already names as in
  place — this increment's job is to PROVE it holds under real
  adversarial input feeding through the REAL rendering pipeline, not to
  build new escaping logic.
- `frontend/src/lib/escape-html.js` — the SEPARATE mechanism for the rare
  case of building a raw HTML/attribute STRING outside `el()`. Confirm
  whether any current view code actually uses this path (if none does,
  the adversarial fixture doesn't need to specifically target it, but
  disclose that finding rather than silently assuming).
- The three existing views' own render-level test files
  (`architecture-view-render.test.js`, `privacy-view-render.test.js`,
  `trace-view-render.test.js`) already establish the exact pattern to
  reuse: build a real `DataFlowGraph v1`-shaped fixture, run it through
  the real `compute*ViewModel()` + `render*View()` pair, walk the
  resulting DOM via `test/dom-shim.js`'s dependency-free shim (NOT
  `jsdom`), and assert on the real structure. This increment's own test
  should follow the SAME pattern, not invent a new rendering-test
  mechanism.
- `frontend/CLAUDE.md`'s own convention section already states the rule
  this increment enforces with a real proof: *"No `innerHTML` with
  graph-derived content, ever... The formal adversarial-fixture XSS test
  suite is Milestone 3's."*

## Scope for this increment

1. **A new adversarial fixture** — a hand-built `DataFlowGraph v1`-shaped
   object (mirroring `build-flagship-fixture.mjs`'s own object-literal
   style, or the simpler inline-object style `*-render.test.js` files
   already use — implementer's judgment on which is more appropriate
   given this is test-only, throwaway data, not a committed shared
   fixture) with HOSTILE VALUES in every user-influenceable string field
   a view actually renders: node `label`/`aliases`, dataElement `name`,
   evidence `claim`/`reason` strings, flow-summary text, file/symbol-name-
   shaped strings wherever a view displays one. Cover, at minimum, per
   the threat model doc's own named categories:
   - A raw `<script>alert(1)</script>` tag.
   - A `javascript:alert(1)` URL-shaped string. **Confirmed this session:
     no current view code renders any value as an `href`/`src`/`.src`
     attribute** (a full grep of `src/views/*.js`, `src/components/*.js`,
     `src/app.js` for `href`/`.src =`/`setAttribute.*src`/
     `setAttribute.*href` returns nothing) — this category is honestly
     INERT for this codebase today. Include one case anyway (as a
     regression trip-wire for whenever a future view DOES add a link/
     image), but disclose in the test's own comment that it is currently
     testing an absence, not an active defense.
   - HTML entities/tags that aren't `<script>` specifically (`<img
     onerror=...>`, `<svg onload=...>`) — since `architecture-view.js`
     renders into a REAL `<svg>` tree via `svgEl()`, an SVG-specific
     payload (`<svg onload=alert(1)>`, a hostile `<text>` content) is a
     genuinely relevant category this file's own architecture makes
     worth testing specifically, not just generic HTML.
   - Control characters (null bytes, other non-printable control chars)
     in an identifier-shaped string.
   - An extremely long identifier. **Confirmed this session: no view
     currently enforces any bounded render length** — a grep for
     `slice(0`/`substring(0`/`truncat`/`maxLength`/`MAX_LEN` across
     `src/views/*.js`/`src/lib/*.js` returns exactly one hit
     (`architecture-view.js`'s `node.kind.slice(0, 3)`, a fixed 3-char
     glyph abbreviation of an internal ENUM value, not user-controlled
     data — unrelated to this concern). The threat model doc's own
     mitigation clause ("bounded string length on any rendered label")
     is therefore a REAL, currently-unmet gap, not yet-unverified — this
     increment must either close it with a minimal, shared truncation
     mechanism (a single helper, reused wherever a label renders — see
     "Do NOT touch" below for the "don't reimplement per-view" rule) or
     explicitly document it as an accepted, deferred risk with a stated
     reason (e.g. "an unbounded label is a display/DoS-adjacent nuisance,
     not itself an XSS vector, given `el()`'s own escaping already makes
     it inert as markup — truncation is a UX concern for a later
     increment"). Pick one, disclosed, not silently skipped.
2. **The DOM assertion**: render the adversarial fixture through EACH of
   the three real views (Architecture/Privacy/Trace), walk the resulting
   DOM tree via `test/dom-shim.js`, and assert — across the WHOLE
   serialized tree, not just spot-checked nodes — that no element is
   literally a `<script>` tag, no attribute value starts with
   `javascript:`, no `on*` event-handler attribute exists anywhere
   (`onerror`, `onload`, `onclick`, etc. — a real, generic sweep, not a
   hand-picked list of the payloads used above only), and every hostile
   string from the fixture appears ONLY as escaped text content (never
   as parsed markup) wherever it does appear at all.
3. **A length-bound decision** (from item 1's own open question) —
   implement or explicitly defer, not silently ignore.

## Do NOT touch

Any existing view's own rendering LOGIC beyond what item 3 above might
require (a length bound, if implemented, should be the smallest possible
addition — e.g. one shared truncation helper in `lib/dom.js` or similar,
reused wherever a label renders, never a per-view reimplementation).
`scanner/src/server/security.js`/`static-assets.js`'s own CSP values
(already correct, confirmed above — do not "helpfully" tighten them
further without a real, disclosed reason). `frontend/src/data/
flagship-graph.js` (the real, committed fixture — this increment's own
adversarial fixture is separate, test-only, never mixed with it).

## Test plan

This IS the test — item 2 above, run against all three views. Additionally:
1. A regression check: temporarily reintroduce a hypothetical `innerHTML`
   call with the adversarial payload in one view (a throwaway local
   edit, reverted before commit) and confirm the new test suite actually
   FAILS against it — proving the test is a genuine mutant-catcher, not
   vacuously passing because the fixture never reaches the code path it
   claims to test. Revert the mutation before committing, same discipline
   the H1/I1 increments already established for their own gate-regression
   proofs this session.
2. Full `frontend/`'s own `npm test`, green, real captured exit code.
3. `scanner`'s own full gate (`npm test`), confirming nothing in
   `scanner/` needed to change for this increment — if it DID need a
   change (e.g., the CSP re-verification in item 1 above finds a real
   gap), that's real, disclosed scope, not silently absorbed.

## Explicitly deferred

Inventory, A11y, Golden (separate, later sub-projects). Server-side
defenses beyond the already-shipped CSP (the threat model doc's own T1
entry names "server-side defenses" as part of Milestone 3's scope, but
the real server-side defense IS the CSP header, already shipped in
Server S1/Wire — if a genuinely separate server-side XSS defense is
identified as still missing during this increment's own work, disclose
it explicitly rather than assuming this document's own scope already
covers it).
