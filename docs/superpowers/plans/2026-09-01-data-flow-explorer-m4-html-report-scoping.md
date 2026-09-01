# Milestone 4, sub-project Self-contained HTML report: scoping (technical question resolved; architecture decision pending)

Per the M4 top-level scoping doc's own sub-project table: *"Self-contained
HTML report... Medium. Bundles `frontend/`'s existing ES-module prototype +
one embedded graph JSON into a single static file, no server, no build step
(frontend already has zero build step — a real, confirmed advantage)."*
Depends on #2 (JSON export, now COMPLETE).

**This document does not produce an implementation plan.** It investigates
the one real open technical question this sub-project has, per this
session's own established discipline of resolving genuinely uncertain
technical questions with a real investigation before scoping/planning
around an assumption (the same discipline applied to SemanticZoom's
data-availability question and the MCP-tools/JSON-export sub-projects' own
digest/attestation investigations).

## The real open question: does `frontend/`'s zero-build-step ES-module structure actually work when opened via `file://`, offline, with no server?

`frontend/`'s own confirmed real structure (read this session): `index.html`
loads `<script type="module" src="./src/main.js">`; `main.js` and its 21
sibling JS files under `frontend/src/` use real `import`/`export`
statements across 21 separate files, each fetched as its own ES module.
This works correctly today ONLY because the app is served over `http://`
by `agentic-security explore` (Milestone 3) or a plain dev server
(`frontend/package.json`'s own `serve` script, `python3 -m http.server`) —
both real HTTP origins.

**A self-contained HTML export is opened via `file://` (double-clicked, no
server) — a fundamentally different browsing context.** Chromium-family
browsers (Chrome, Edge) refuse to resolve a `type="module"` script's own
`import`/dynamic-`import()` statements against a `file://` origin —
**empirically confirmed this session against a real, installed Chrome
binary** (below), not merely cited as well-known behavior. A naive
"concatenate `index.html` + 21 JS files + embed the graph JSON" export
would load blank/broken in Chrome the moment a user double-clicks it —
the single most likely real-world way a self-contained export actually
gets opened.

## Empirical confirmation (real Chrome, this session)

`claude-in-chrome`'s own `navigate` tool refuses `file://` URLs outright
(`"Can't interact with browser-internal or unparseable URLs"` — a real
tool-level safety restriction, not routed around). Instead, invoked the
real, locally-installed Chrome binary directly via its own headless CLI
mode (`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
--headless=new --dump-dom`) against a minimal two-file reproduction in the
scratchpad (`index.html` dynamically importing a sibling `mod.js` that
exports one function) — genuinely the same module-loading engine ordinary
Chrome uses, headless mode does not special-case module CORS. Result,
captured verbatim in the dumped DOM:

```
FAILURE:Failed to fetch dynamically imported module: file:///.../mod.js
```

This confirms the constraint directly, not by citation: a same-directory,
purely-relative ES module import genuinely fails to fetch when the parent
page is loaded via `file://`. Firefox's own (historically more permissive)
behavior was not tested — not relevant, since this deliverable cannot
assume the recipient uses a specific browser.

## What this means for the real architecture (assuming the constraint holds, which is the safe assumption)

The "no build step" property that makes `frontend/`'s own DEVELOPMENT
workflow simple (edit a file, refresh a browser tab against a server) does
**not** transfer to the EXPORT artifact's own requirements — those are
different consumers with different constraints (a developer's browser
tab, always over `http://`, vs. an end user's double-clicked file, always
over `file://`). Producing a genuinely self-contained, offline,
zero-server HTML file needs the 21 JS files' real `import`/`export` graph
resolved and inlined into ONE script with no remaining cross-file
`import` statements, plus the 9 CSS files inlined into one `<style>`
block, plus the graph JSON embedded as a data literal — a real
**bundling** step, not a "no build step" copy-paste.

Three real options, none yet chosen:

1. **Hand-rolled minimal bundler** (a new script, most plausibly living in
   `scanner/scripts/` or `frontend/scripts/`, since this is an EXPORT-time
   concern, not a change to `frontend/`'s own dev workflow or its own
   "zero build step" convention) — read each of the 21 files, resolve the
   real `import`/`export` graph (already a known, small, hand-auditable
   set — confirmed 21 files, not hundreds), rewrite each module's
   top-level bindings into a uniquely-namespaced IIFE, and concatenate in
   dependency order. No new npm dependency. Real, nontrivial work
   (writing a correct-enough module resolver/rewriter for real code, not
   a toy), but bounded — this is not "write a general bundler," it's
   "correctly inline 21 already-known files once."
2. **A real, minimal bundler dependency** (e.g. esbuild, the smallest and
   most common choice for exactly this "produce one IIFE/UMD file from an
   ES-module tree" job) — added as a **build-time-only** devDependency of
   whichever package owns the export script, never shipped to end users,
   never a runtime dependency of `scanner/`'s own published package. This
   codebase's own convention (`server/CLAUDE.md`: *"No new npm dependency,
   ever, without re-opening this decision first"*) treats a new dependency
   as a real decision, not a default — this option is named, not silently
   assumed, and should be the subject of an explicit choice before any
   implementation plan commits to it.
3. **Runtime dynamic-`import()` via `Blob`/data: URLs** — a small
   bootstrap script fetches each module's source TEXT (not as an ES
   module import, but as a value — e.g. embedded as a big string literal
   at export time, or via `fetch()` of a same-directory `file://`
   resource, which has its OWN separate, also-murky cross-browser
   support story) and constructs `Blob`-backed module URLs at runtime.
   More complex than option 1 for equivalent benefit, and trades one
   under-verified browser behavior (module CORS) for a different
   under-verified one (file:// `fetch()`/Blob-URL module support) —
   **not recommended** without a much stronger reason to prefer it over
   option 1.

**Recommendation (this document's own conclusion, not yet a decision):**
option 1 (hand-rolled minimal bundler, no new dependency) is the safer
default given this codebase's own consistently-stated "no new npm
dependency without re-opening this decision" convention and the small,
bounded, already-known module graph (21 files) — but this is a real
architectural choice with real tradeoffs (a hand-rolled resolver is more
code THIS TEAM owns and must keep correct as `frontend/src/` grows;
esbuild is a single, extremely well-tested, extremely fast, ~9MB
devDependency solving exactly this problem). Flagging for explicit
resolution rather than unilaterally committing scanner/ or frontend/ to a
new dependency.

## What's NOT in question (already confirmed real, from prior sub-projects)

- The graph payload itself: `exportGraphJSON` (COMPLETE, this session) is
  exactly the right shape to embed — already redacted by default, already
  carries a digest/scope/coverage/limitations envelope §17.5 requires.
- CSS inlining is unambiguous and low-risk — 9 files, no cross-file
  `@import` dependency graph to resolve (confirmed by a quick read of
  `frontend/styles/`'s own file list), just concatenation into one
  `<style>` block.
- `bootstrap(rootEl, graph)` (`frontend/src/app.js`) is ALREADY the exact
  entry point a self-contained export needs — it takes a plain graph
  object directly, with zero assumption about where it came from
  (confirmed this session by reading `main.js`'s own header comment,
  which documents this same property for the `explore`-server case).
  A self-contained export's own tiny bootstrap script is: embed the
  (already-redacted) graph JSON as a literal, call `bootstrap(el, graph)`
  with it — no fetch, no token, no server-specific logic at all. This
  part is genuinely simple once the bundling question is resolved.

## Explicitly deferred / out of scope for this investigation

- PNG/SVG/PDF embedding inside the HTML report (§17.5's own "provide
  print/PDF, PNG/SVG diagram... exports where applicable") — sub-project
  #4's own separate, already-flagged open technical question
  (deterministic SVG serialization with no live browser). This report's
  own v1 can embed the interactive graph explorer without a static image;
  image embedding is additive, later.
- DPIA/RoPA embedding — depends on sub-project #6 (Regulatory Overlay),
  not started.
- Any CLI/slash-command wiring — sub-project #5.

## Recommended next step

The `file://` module-CORS question is now empirically confirmed, not
open. What remains is a real, disclosed architectural decision — which of
the 3 bundling options above — that this document deliberately does not
make unilaterally, since option 2 (a bundler devDependency) is exactly
the kind of choice this codebase's own conventions ("no new npm
dependency, ever, without re-opening this decision first") treat as
consequential. This document's own recommendation stands (option 1,
hand-rolled minimal bundler, no new dependency) as the safer default;
a scoping+plan doc for this sub-project can be written once that choice
is confirmed (either by proceeding with the documented recommendation, or
by an explicit decision to spend the dependency).
