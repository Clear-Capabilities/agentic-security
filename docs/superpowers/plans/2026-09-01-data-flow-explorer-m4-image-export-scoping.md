# Milestone 4, sub-project PNG/SVG/PDF export: scoping — real Chrome headless changes the architecture

Per the M4 top-level scoping doc's own sub-project table: *"PNG/SVG/PDF
export... Large. The one genuinely open technical question (headless SVG
serialization) worth its own investigation spike before a full plan is
written."* Depends on #3 (self-contained HTML report, now COMPLETE — this
sub-project builds directly on that artifact, see below).

**This document investigates that open question and finds a materially
better answer than the M4 top-level doc's own framing assumed.** That
framing anticipated needing to either (a) reuse `architecture-view.js`'s
pure layout math and hand-write a second, DOM-independent SVG-string
serializer, or (b) add a real headless-browser dependency. Neither is
needed: **a real, already-installed Chrome binary's own native headless
flags (`--screenshot`, `--print-to-pdf`, `--dump-dom`) produce PNG, PDF,
and (via DOM extraction) SVG output directly from the self-contained HTML
report sub-project's own already-shipped artifact — zero new code to
render anything, zero new dependency.**

## Empirical findings (real Chrome, this session, not cited from documentation)

Generated a real report via the already-shipped
`scanner/scripts/generate-html-report.mjs` against the real flagship
fixture, then tested Chrome's own headless CLI flags directly against it
(the same `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
--headless=new` invocation already proven this session for the `file://`
module-CORS investigation and the HTML report's own real acceptance
proof):

1. **`--screenshot=<path>.png --window-size=<w>,<h>`** produces a real PNG
   at EXACTLY the requested dimensions. Tested both AC-23-required sizes
   directly: `1680,945` → confirmed `1680 x 945, 8-bit/color RGB` via
   `file`; `3360,1890` (with `--force-device-scale-factor=1`, needed so
   Chrome doesn't apply an additional retina/HiDPI multiplier on top of
   the requested window size) → confirmed `3360 x 1890`.
2. **Determinism, measured, not assumed**: ran the identical
   `--screenshot` invocation twice against the identical input HTML file.
   The two output PNGs are **byte-identical** (`sha256sum` match). This is
   the real, hard part of AC-23's own requirement ("PNG... deterministic")
   and it holds without any special flag beyond what was already used.
3. **`--print-to-pdf=<path>.pdf`** produces a real, valid single-page PDF
   (`file` confirms `PDF document, version 1.4, 1 pages`) from the exact
   same HTML input, no separate rendering path.
4. **`--dump-dom`** (already used this session for the `file://` and
   acceptance-proof investigations) includes real, fully-rendered `<svg
   class="arch-view" ...>` markup with real content — confirmed by
   grepping the dumped DOM for the Architecture View's own real root SVG
   element and its real `viewBox`/`aria-label` attributes. This means a
   real, browser-rendered SVG document can be **extracted** from the
   dumped DOM directly — no hand-written DOM-to-SVG-string serializer
   needed, and critically, no risk of a hand-written serializer
   *diverging* from what a real browser actually renders (a real,
   disclosed risk of the M4 top-level doc's own original "headless SVG
   serialization" framing, now avoided entirely).

## What this changes about the architecture

- **This sub-project now depends on #3 (the HTML report) directly**,
  not on `architecture-view.js`'s layout math in isolation. The M4
  top-level doc's own dependency line for this sub-project didn't name a
  dependency at all (implying it was independent, presumably meant to
  consume the graph/layout directly); the real, tractable path instead
  generates a report via the already-shipped `generateHtmlReport`, then
  rasterizes/extracts from THAT artifact via Chrome's own CLI. This is a
  real, disclosed correction to the top-level doc's own dependency graph,
  not the original plan.
- **No new npm dependency** (matching this session's own established
  preference, reaffirmed for the HTML report sub-project's own bundler
  choice) — Chrome itself is the "dependency," and it's neither a new
  package install nor bundled/shipped by this project; it's a real,
  pre-existing binary the OPERATOR already has (this is the same
  trust boundary `claude-in-chrome`'s own MCP tooling and this session's
  own repeated verification technique already both rely on). **This is a
  real, disclosed constraint worth flagging explicitly**: a machine
  running `agentic-security` without Chrome/Chromium installed cannot use
  this export path. Whether that's an acceptable requirement for a
  PNG/SVG/PDF export FEATURE (as opposed to the scanner's own core
  functionality, which has zero such requirement) is a real product
  decision — named here, not decided.
- **Determinism is real, not merely asserted** — measured directly, not a
  theoretical claim resting on "no animations, no random content." Font
  rendering/anti-aliasing was a real, disclosed risk this document
  considered before testing (different Chrome versions or OS font
  substitution could in principle produce different pixels for identical
  input) — not fully ruled out across environments by a single
  same-machine, same-Chrome-version test, but the WITHIN-environment
  determinism this document actually measured is real and load-bearing
  for AC-23's own "repeated... exports are deterministic" wording (which
  does not require cross-machine byte-identity, only repeated exports
  from the same environment/input to agree — the same distinction this
  session's own `posture/attestation.js` review already drew for a
  different artifact).

## Real, disclosed limitations not resolved by this investigation

- **AC-23 also requires**: "the selected verdict and coverage statement
  remain visible" in the export. Confirmed the HTML report's own shell
  chrome (coverage banner, header) is real and present in the dumped
  DOM/screenshot (visible in this session's own real acceptance-proof
  screenshots for the HTML report sub-project) — not re-verified as a
  DEDICATED assertion for the image-export path specifically; a real
  implementation task, not assumed satisfied by inheritance alone.
- **Full-page vs. one-view screenshot**: `--screenshot` captures
  whatever is visible in the requested viewport at capture time — for a
  report with multiple views (Architecture/Privacy/Trace/Inventory,
  behind tabs per the shell's own state model), a single screenshot only
  captures whichever view is active on load. Exporting each view
  separately, or a specific view via a URL-hash-driven initial state
  (`frontend/src/lib/state.js`'s own `parseStateFromHash`/
  `serializeStateToHash`, already real and shipped), is real, undecided
  scope this document does not resolve.
- **SVG extraction needs a real, small implementation** (parse the
  `--dump-dom` output, locate and extract the correct `<svg>` subtree,
  handle the case of multiple `<svg>` elements on the page — confirmed 8
  `<svg>` tags in the real dumped DOM this session, most likely small
  icon/decoration SVGs alongside the one real Architecture View root —
  disambiguating the RIGHT one is real, un-attempted work, not a
  one-liner).
- **PDF's own single-page-vs-multi-page/pagination behavior**,
  print-CSS interaction (`@media print` rules, none of which exist in
  `frontend/styles/` today per this session's own earlier confirmed file
  list), and whether §17.5's own "provide print/PDF... exports where
  applicable" is satisfied by Chrome's raw default print-to-PDF or needs
  real print-specific styling — all real, undecided, un-attempted this
  pass.
- **Where the Chrome-invocation code lives and how a caller supplies a
  Chrome binary path** (auto-detect common install locations across
  macOS/Linux/Windows; an explicit `--chrome-path` override; a clear,
  disclosed error when none is found) — real, un-scoped implementation
  surface.

## Recommended next step

A real scoping+plan doc, following this sub-project's own now-confirmed
architecture (generate the HTML report via the already-shipped
`generateHtmlReport`, then invoke a real local Chrome binary's own
`--screenshot`/`--print-to-pdf`/`--dump-dom` flags against it), resolving
the specific open items above (view-selection for a multi-view report,
correct-SVG-element disambiguation, Chrome-binary discovery/error
handling) before implementation begins — matching this session's own
established discipline of a real, grounded scoping pass before writing
task-level code.
