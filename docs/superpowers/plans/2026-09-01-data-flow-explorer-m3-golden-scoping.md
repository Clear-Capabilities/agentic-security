# Milestone 3, sub-project Golden: reference-composition + state-matrix tests

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
own Golden row: *"Per-view golden-DOM/screenshot assertions against the
flagship fixture's own named reference compositions (§7.8's `PCI
Exposure` saved view, §7.9's lifecycle-stage layout, §7.10's 5-step
trace), plus the §8.4 11-state matrix forced-state assertions (AC-22 — no
non-clean state may ever resemble a clean scan)."* Depends on Wire,
Inventory, A11y — all COMPLETE.

## AC text and PRD sections read verbatim this session

- **AC-16** (shared shell): switching Architecture/Privacy/Trace keeps
  header, filters, canonical selection, coverage state, verdicts, and
  evidence counts consistent — only the center projection and view rail
  change.
- **AC-17** (Architecture reference composition): the `PCI Exposure`
  saved view at 1680×945 shows named trust zones/nodes/paths without
  overlapping labels.
- **AC-18** (Privacy lifecycle reference composition): six aligned
  stages; PCI/PHI-with-AI/PII rows preserve field identity; missing
  governance data shows `MANUAL REQUIRED`/`UNKNOWN`/`REVIEW`/`NOT FOUND`.
- **AC-19** (Trace/evidence reference composition): five ordered steps,
  both field-rename mappings, the red `HTTP · UNENCRYPTED` boundary edge,
  alternate destinations with verdicts, evidence with reasoning/
  confidence/provenance "only when supplied by scanner evidence."
- **AC-22** (non-clean states): per §8.4's 11-row visual state matrix,
  each state's "required visual behavior" must appear, and no non-clean
  state may ever render an unqualified clean/protected summary.
- **§7.8/7.9/7.10** (full blueprints, read verbatim): far richer than
  AC-17-19's own text — name specific saved views (`PCI Exposure`, `AI +
  Regulated Data`), zoom/focus/layout controls, hover/pin/`Escape`
  interactions, a `Lifecycle | Data map` toggle, 200% zoom usability, and
  DPIA/RoPA export fitness.

## What already exists (confirmed by direct read this session)

- **The flagship fixture's real content matches §7.8/7.9/7.10's named
  elements almost exactly** — confirmed by parsing
  `scanner/src/lineage/fixtures/flagship-graph.json` directly (14 nodes,
  8 flows, 3 dataElements). Every one of §7.8's 9 named reference nodes
  is present, **verbatim**: `Web App`, `API Gateway`, `Payments Service`,
  `AI Assistant`, `PostgreSQL`, `Application Logs`, `Payment API`,
  `Analytics API`, `Unresolved Destination`. `dataElements` are
  `card_number`/PCI, `diagnosis`/PHI (§7.9's table names this field
  `patient_summary` — a real, disclosed naming difference, not a
  blocker), `email`/PII. `Retention Policy` and `Deletion Job` nodes
  exist, matching §7.9's lifecycle table. Real evidence entries exist
  with real claim/location text semantically matching §7.10's example
  reasoning (`"card_number reaches Application Logs via maskCard() on
  the masked branch"`, location `services/payment.js:55`). **This
  confirms AC-17/18/19's reference-composition claims are substantially
  testable against REAL rendered content, not aspirational** — the
  fixture was clearly built in Milestone 0 to match this PRD text.
- **`architecture-view.js`/`privacy-view.js`/`trace-view.js` already
  render this content correctly** — confirmed by this session's own
  prior work (I1/H1/etc.) and by reading `frontend/CLAUDE.md`'s existing
  rows: `renderTraceView` already shows the unprotected-transit verdict
  for the Payments Service → Payment API hop; `computeTraceSteps`
  already produces the real source→rename→transform→sink sequence for
  the masked-log flow; `renderPrivacyView`'s stage cells and governance
  badges already exist per-row. **No compute-logic gap found for AC-17/
  18/19's substantive claims** — this sub-project's own job is a formal
  golden-DOM regression test proving this holds, not new view logic.
- **AC-16 is largely already covered, implicitly, by existing tests** —
  `state.js`'s own test suite proves `{view, selectedId, filters, table}`
  round-trips through the URL hash; `shell.js`'s tests prove tab
  switching updates state and notifies subscribers. **No single existing
  test proves the END-TO-END claim** (select a field in Architecture,
  switch to Privacy, confirm the SAME field/filters/selection carry over
  and the header/coverage banner content is unchanged) — this is real,
  narrow, missing coverage this sub-project adds.
- **§7.8/7.9/7.10's richer claims are NOT implemented, confirmed by
  direct grep**: no saved-view concept exists anywhere in `frontend/src/`
  (no `PCI Exposure`/`AI + Regulated Data` string, no saved-view
  data structure). No zoom/pan/focus controls exist (Perf's own prior
  measurement already established pan/zoom "does not exist as a feature
  at all yet"). No `Lifecycle | Data map` toggle (Privacy View always
  renders lifecycle mode, unconditionally — confirmed by reading
  `privacy-view.js`, no mode branch exists). No `Escape`-returns-to-
  prior-focus interaction (grep for `'Escape'` in `src/views/*.js`
  returns nothing). No DPIA/RoPA export, no 200%-zoom-specific layout
  handling, no presentation/diagram-export mode (§8.5, not read in
  detail this pass — confirmed absent by the same grep sweep that found
  no export code anywhere in `src/`).
- **AC-22's 11-state matrix — confirmed by direct grep, most states have
  NO dedicated UI today**: `main.js`'s `showError`/`catch` block is the
  ONLY named-state implementation with real code (the "Error" row).
  `:hover`/`[data-selected]` CSS exists broadly (the "Hovered"/"Selected"
  rows are real, confirmed working end-to-end during A11y's own CDP
  measurement this session). **The other eight rows — Loading/scanning,
  Partial, Truncated, Unsupported (as its own persistent banner, not
  just Inventory's own `unsupportedCandidates` table row — those are
  different things), Unresolved destination (the fixture's own node
  renders, but no dashed-edge/question-mark-glyph treatment is confirmed
  — check at implementation time), Zero filtered results, Stale artifact
  — have no confirmed dedicated visual treatment anywhere in `src/` or
  `styles/`.** This is the single largest, most consequential finding of
  this scoping pass: **AC-22 as literally written cannot be honestly
  tested end-to-end today** — 6-7 of 11 required states would need new
  UI built first, which is real feature work, not test-writing, and
  squarely out of a "Medium-Large" test-authoring sub-project's own
  reasonable scope.

## Decisions this scoping makes explicitly

1. **Golden's real scope is golden-DOM regression tests for AC-16/17/18/
   19 against content that ALREADY exists and ALREADY renders** —
   proving the flagship fixture's real, named reference elements appear
   correctly in each view's real DOM output, via the SAME dom-shim
   pattern every render-level test in this codebase already uses. This
   is genuinely "Medium" sized, not "Large" — the hard content-matching
   work was already done at Milestone 0/1/2; this sub-project formalizes
   it as a regression gate.
2. **§7.8/7.9/7.10's richer, unimplemented claims (saved views, zoom/
   focus/layout controls, `Lifecycle | Data map` toggle, `Escape`
   interaction, 200% zoom, DPIA/RoPA export, §8.5 presentation/export
   mode) are explicitly OUT of scope** — they are real, disclosed,
   unscoped FEATURE work belonging to M3-UX (already named, already
   deferred, in the parent M3 scoping doc), not this sub-project's job to
   silently invent or to falsely claim covered by a passing test that
   tests something narrower than the AC's own full text. Golden's own
   tests are scoped to what AC-16/17/18/19's OWN BODY TEXT (quoted above)
   actually claims, which is narrower than §7.8/7.9/7.10's full blueprint
   prose.
3. **AC-22 is honestly split into two categories, not silently narrowed
   to a passing subset without disclosure**:
   - **Testable today** (3 of 11 states: Error, Selected, Hovered) — real
     golden-DOM tests, per state.
   - **Not implemented, confirmed absent, and NOT this sub-project's job
     to build**: the other 8 states (Loading/scanning, Partial,
     Truncated, Unsupported-banner, Unresolved-destination's own dashed-
     edge/question-mark treatment specifically — the node itself does
     render, only the SPECIFIC visual treatment named in §8.4 is
     unconfirmed, Zero filtered results, Stale artifact). This sub-
     project documents this gap explicitly, in both the ledger and
     `frontend/CLAUDE.md`, with the exact same "what this does NOT mean"
     honesty discipline Milestone 2's own Sub-project I and this
     session's own M3-Inventory/A11y write-ups already established —
     never silently claim AC-22 "passes" when 8 of 11 named states have
     no code to test.
4. **AC-16's end-to-end cross-view persistence claim gets ONE new,
   real, narrow test** — select a field/filter in one view, switch
   views via `shellApi.setActiveView`, confirm `getState()` and the
   header/coverage-banner DOM content are unchanged — closing the real,
   narrow gap found in "What already exists" above, without duplicating
   `state.js`'s/`shell.js`'s own already-thorough unit coverage.
5. **No screenshot-based visual regression testing** — the scoping
   table's own phrase "golden-DOM/screenshot assertions" offers both;
   this sub-project uses DOM-structure assertions only (matching every
   other render-level test in this codebase), not pixel-diffing
   screenshots, which would need a new dependency/tooling decision this
   sub-project does not make unilaterally. If a future increment wants
   pixel-level visual regression, that's separately scoped work.

## Scope for this increment

1. `frontend/test/golden-architecture.test.js` (new) — asserts, against
   the REAL `FLAGSHIP_GRAPH` fixture rendered through the REAL
   `computeArchitectureViewModel`/`renderArchitectureView`: all 9 named
   reference nodes are present with their real labels; the 5 named trust
   zones (`Public Internet`, `Application Layer`, `Service Layer`, `Data
   Layer`, `External Zone`) are present as columns; the `card_number`
   flow's selection highlights the reachable topology (dims, does not
   remove, unrelated content — confirmed via a `data-dimmed`/opacity-
   style attribute, whichever `architecture-view.js` real currently
   uses — read it first); the raw/masked logging branches both render
   with their real, distinct verdicts; no two rendered node labels
   visually overlap (a real DOM/bounding-box check is not possible in
   dom-shim — this specific "without overlapping labels" AC-17 clause is
   NOT testable via dom-shim and is disclosed as deferred to a real-
   browser check, not silently skipped — see Explicitly Deferred).
2. `frontend/test/golden-privacy.test.js` (new) — asserts the 3 named
   fields (`card_number`/PCI, `diagnosis`/PHI, `email`/PII — using the
   REAL fixture's real name, not §7.9's example name) each render a row
   preserving field identity across all 6 lifecycle stage columns, and
   that governance badges (`MANUAL REQUIRED`/`UNKNOWN`/etc., whichever
   subset the real fixture's real `governanceRefs` actually produces —
   confirm by reading the fixture, don't assume all four badge strings
   exist in it) render exactly where `privacy-view.js`'s own
   `governanceKeysForStage` logic places them.
3. `frontend/test/golden-trace.test.js` (new) — asserts the flagship
   cleartext-payment flow's real trace renders 5 ordered steps (whatever
   the REAL `computeTraceSteps` output for that real flow actually is —
   confirm the exact step kinds/count by reading the real computed
   output first, since §7.10's own step table may not be byte-identical
   to what the current fixture/compute logic actually produces after
   several sessions of real fixes since Milestone 0), the field-rename
   mapping labels, the red `HTTP`/unprotected trust-boundary edge
   treatment, and the alternate-destinations list with individual
   verdicts.
4. `frontend/test/golden-shell-state.test.js` (new) — the one new AC-16
   end-to-end test (decision 4).
5. `frontend/test/golden-state-matrix.test.js` (new) — the 3 testable
   AC-22 rows (decision 3): Error (mock a failing `fetchGraph`, confirm
   `main.js`'s real `showError` path renders, confirm it never also
   renders a clean/protected summary alongside the error), Selected
   (confirm `data-selected="true"`/focus-ring-equivalent styling hook is
   present on a selected element across at least two views), Hovered
   (confirm a `:hover`-scoped CSS rule exists for the relevant class in
   the real stylesheet — a `styles/*.css` text-content check, mirroring
   `tokens-contrast.test.js`'s "read the real file" precedent, since
   `:hover` cannot be triggered/observed via dom-shim). The other 8
   states get ONE new file,
   `frontend/test/golden-state-matrix-gaps.test.js`, containing NOT
   assertions but a single, clearly-commented `test.todo(...)` (or
   equivalent skip-with-reason) entry per missing state, naming exactly
   what UI would need to exist before it's testable — so the gap is
   visible in `npm test`'s own output forever, not just in a doc that
   can go stale.
6. Update `frontend/CLAUDE.md` and this M3 scoping doc's own Golden row
   with the honest AC-22 split (decision 3) — same disclosure discipline
   as every prior sub-project.

## Do NOT touch

- Any view's compute/render logic — Golden is test-only, proving
  existing behavior, not changing it. If a real bug is found while
  writing these tests (matching the XSS/Inventory sub-projects' own
  precedent of finding real bugs via new test authorship), fix it
  minimally and disclose it — don't silently work around it in the test.
- `scanner/` — frontend-only.
- Any of §7.8/7.9/7.10's unimplemented richer features (decision 2) —
  building saved views, zoom controls, or export mode is NOT this
  sub-project's job, even though the PRD text technically names them.
- The 8 AC-22 states with no real UI (decision 3) — do not invent
  placeholder UI just to make a test pass; that would be worse than an
  honest `test.todo`.

## Test plan

1. The 4 new golden-DOM test files (architecture/privacy/trace/shell-
   state), each proving real, already-shipped content renders correctly
   — a regression gate, not new-feature verification.
2. `golden-state-matrix.test.js` (3 real states) +
   `golden-state-matrix-gaps.test.js` (8 disclosed gaps, `test.todo`).
3. If any test finds a REAL rendering bug (e.g. a node label genuinely
   missing, a badge genuinely never rendering), fix it minimally,
   disclose it in the ledger and `frontend/CLAUDE.md`, same as every
   prior sub-project's own mutation-proof/bug-discipline this session.
4. Full `frontend/npm test`, green, real captured exit code — including
   confirming the `test.todo` entries show up in the real test output as
   TODO (not silently absent, not accidentally counted as failures).
5. `scanner`'s own full gate, confirmed unaffected.

## Explicitly deferred

- AC-17's "without overlapping labels" clause — genuinely needs a real
  browser/bounding-box check (dom-shim has no layout engine), not a
  dom-shim assertion. A real CDP-driven check (same infrastructure
  A11y's own Task 3 already established) could close this specifically,
  but is real, additional scope beyond a "golden-DOM test" sub-project —
  disclosed as a candidate follow-up, not silently claimed covered by
  the DOM-structure tests this sub-project actually writes.
- §7.8/7.9/7.10's saved views, zoom/focus/layout controls, `Lifecycle |
  Data map` toggle, `Escape` interaction, 200% zoom usability, DPIA/RoPA
  export, §8.5 presentation/export mode — real, unscoped M3-UX-or-later
  feature work (decision 2).
- The 8 AC-22 states with no dedicated UI (decision 3) — each would need
  real feature work (a loading skeleton, a partial-scan banner, a
  truncation notice, a zero-results empty state, a stale-artifact
  banner, and confirmation of the unresolved-destination's specific
  dashed-edge/question-mark treatment) before it could be honestly
  tested; naming what's missing is this sub-project's job, building it
  is not.
- Pixel-level screenshot/visual-regression tooling (decision 5).
