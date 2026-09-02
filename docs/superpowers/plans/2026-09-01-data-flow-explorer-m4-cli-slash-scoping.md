# Milestone 4, sub-project #5 (CLI and Claude slash commands): scoping

Per the M4 top-level scoping doc's own sub-project table: *"CLI and Claude
slash commands... Small | #1–#4 (thin wiring layer) | Once export/report/MCP
surfaces exist, this is mostly argument parsing + dispatch, following
`commands/`'s existing 10-dispatcher pattern and
`scanner/bin/agentic-security.js`'s existing `explore` subcommand
precedent."* #1–#4 are all now COMPLETE and merged. This document
investigates the real current code (not the doc's pre-#1–#4 assumptions)
and finds the gap is real but larger than "thin wiring" implied — several
concrete design decisions are needed before a plan can be written, and one
naming mismatch against the PRD's own text needs an explicit ruling.

## What already exists (confirmed by direct source read this session)

- **`scanner/bin/agentic-security.js`** has no subcommand framework — a
  hand-rolled `parseArgs` (`args._`/`args.flags`) and a giant
  `switch (args._[0])` dispatch in `main()`. `cmdExplore`
  (lines ~3019–3076) is the one existing precedent for "load the signed
  lineage graph, fail loud and early if it's missing/unsigned/tampered/
  malformed, then act on it" — it calls `loadSignedGraph` from
  `scanner/src/server/graph-loader.js` and never proceeds past a failure.
  **`explore` is currently undocumented in the top-level `USAGE`/`--help`
  block** (every other subcommand has a one-line entry there; `explore`
  has none) — a real, pre-existing discoverability gap, not something #1–#4
  introduced.
- **`loadSignedGraph(scanRoot)`** (`scanner/src/server/graph-loader.js`,
  reusing `posture/integrity.js`'s `verifyLastScan`) is the single shared
  loader for the signed `lineage-graph.json` artifact — already used by
  `explore` and (indirectly, via `dataflow-tools.js`) the M4 #1 MCP tools.
  Returns one of `{ok:false, reason:'missing'|'unsigned'|'tampered'|
  'malformed', message}` or `{ok:true, graph}`. Any new CLI command MUST
  call this exactly the way `cmdExplore` does, print `loaded.message`, and
  exit non-zero on failure — this is the established, tested contract
  (`scanner/test/server/graph-loader.test.js`).
- **The six export/report functions #1–#4 shipped** have two different
  failure conventions, confirmed by direct signature read:
  - `exportPng`/`exportPdf`/`exportSvg` (`scanner/scripts/export-image.mjs`)
    — `async`, return `{ok:true, data:Buffer}` or `{ok:false, reason}`,
    never throw for an ordinary failure (missing Chrome, broken render).
    `exportSvg` **only works when the Architecture View is active**
    (confirmed: its own `_extractArchSvg` looks for the one real
    `<svg class="arch-view">` element, which the Privacy/Trace/Inventory
    views never render) — requesting `--format svg --view privacy` must be
    rejected with a clear CLI-level error, not passed through to Chrome's
    own confusing dump-failure reason.
  - `exportGraphJSON`/`computeGraphDigest`
    (`scanner/src/lineage/export-json.js`), `exportFlowsCSV`
    (`scanner/src/lineage/export-csv.js`), `generateHtmlReport`
    (`scanner/scripts/generate-html-report.mjs`) — all **sync**, return a
    plain value (object/string), and CAN throw (e.g. `generateHtmlReport`
    throws if `frontend/styles/`'s real files drift from its hardcoded
    `CSS_LOAD_ORDER`). A CLI wrapper needs a `try/catch` around these,
    unlike the image exporters.
  - `exportGraphJSON`/`generateHtmlReport` both take `opts.redact`
    (default `true`) and `opts.filter` (`{nodeIds, edgeIds}`).
    `exportFlowsCSV(graph)` takes **no opts at all** — no redaction
    parameter exists on the CSV path. This is pre-existing behavior
    accepted when #2 shipped, not something this sub-project introduces or
    is scoped to fix; a new CLI/slash surface exposing CSV inherits that
    behavior as-is and must not claim a `--no-redact` flag has any effect
    on `--format csv`.
- **`commands/*.md` dispatcher pattern** (confirmed via `scan.md`,
  `posture.md`): YAML frontmatter (`description`, `argument-hint`) + a
  mode table + an `## Implementation` bash script that shells out to
  `node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs <args>` —
  every slash command is a thin wrapper around the compiled CLI bundle,
  never a reimplementation. **No existing `commands/*.md` file mentions
  `explore`, `dataflow`, or `lineage`** — there is currently zero slash
  surface for any Data Flow Explorer capability. `.claude-plugin/
  plugin.json`/`marketplace.json` need no edits — commands are
  auto-discovered from `commands/*.md` filenames.
- **Test precedent**: `scanner/test/server/cmd-explore.test.js`
  (`test:server` scope) spawns the real compiled CLI and asserts real
  process behavior (exit codes, stderr messages, no-token-on-failure, a
  real server actually refusing connections when it never started). A new
  command's test file follows this shape, not the direct-function-call
  shape `export-image.test.js`/`export-json.test.js`/etc. already use.

## Real gaps against the M4 top-level doc's "thin wiring" framing

1. **Naming mismatch with the PRD, not previously flagged.** The PRD's own
   §7.1 "Entry points" names the command `visualize`
   (`agentic-security-scanner visualize .`, `/agentic-security:visualize
   --class PCI --view privacy`) — written before M3/M4 shipped the actual
   verb `explore` for the live server. **Ruling (this document): keep
   `explore` as-is** (already shipped, tested, and means "start a live
   server" — renaming it now breaks existing tests/docs for zero benefit)
   **and add a separate, new verb for export**, not attempt to retrofit
   `visualize` semantics onto either. See "Command shape" below.
2. **`--class PCI`-style semantic filtering does not exist anywhere.**
   `frontend/src/lib/state.js`'s hash-state model has no `class` concept;
   nothing in the codebase computes "the filter for data class PCI" as a
   reusable function — only the raw `{nodeIds, edgeIds}` filter shape
   `exportGraphJSON`/`generateHtmlReport` already accept. **Ruling: defer
   a semantic `--class`/query-language filter to a future sub-project.**
   v1 exposes the existing raw filter shape via `--filter <path-to-json>`
   (a file containing `{nodeIds:[...], edgeIds:[...]}`) — this is "wiring
   an existing capability," which matches #5's actual charter; a semantic
   resolver is new analysis logic, which does not.
3. **AC-23 pins two exact PNG sizes** (`1680×945` and `3360×1890`, an
   exact 2×) that #4 already supports via free-form `--width`/`--height`
   but never named as a convenience. **Ruling: add `--size
   standard|2x` mapping to those two exact pairs** (default `standard`),
   with `--width`/`--height` remaining available as an escape hatch for
   custom dimensions (mutually exclusive with `--size`; CLI-level error if
   both given).
4. **Six different output shapes, two different failure conventions**,
   need one consistent CLI contract — this is real design work, not
   argument-parsing boilerplate: deciding exit codes, `--output` path
   handling (create parent dirs? refuse to overwrite? content-type by
   extension vs. by `--format`?), and how sync-throwing functions
   (JSON/CSV/HTML) get the same clean `{ok:false, reason}`-shaped CLI
   error reporting the async image exporters already have natively.
5. **`explore`'s own missing `USAGE` entry** is a small, real, adjacent
   gap this sub-project should close as a drive-by fix while already
   editing the same help block for the new command — not scope creep,
   since leaving it means the new command's own entry sits next to a
   still-undocumented sibling.

## Command shape (this document's own proposed design, not yet implemented)

```
agentic-security dataflow export \
  --format png|pdf|svg|json|csv|html \
  --output <path> \
  [--view architecture|privacy|trace|inventory] \
  [--size standard|2x] [--width <n>] [--height <n>] \
  [--no-redact] \
  [--filter <path-to-json>]
```

- New `dataflow` verb (not `export` — the bare `export` subcommand already
  exists and does something unrelated: copying `.agentic-security/`
  artifacts for legal-preservation/migration; colliding with it would be a
  real, confusing regression, not a naming nicety).
- `--format svg` combined with `--view <anything but architecture>` is
  rejected before any Chrome invocation, with a message naming the real
  constraint (only the Architecture View has a real `<svg>` element).
- `--no-redact` is honored for `json`/`html`, and explicitly documented as
  a no-op with a printed warning for `csv` (which has no redaction path at
  all today) rather than silently doing nothing.
- Exit codes: `0` success: file written. `1` graph load failure (missing/
  unsigned/tampered/malformed — `loadSignedGraph`'s own four reasons,
  message passed through verbatim, matching `explore`'s own contract).
  `2` export failure (Chrome unavailable, unsupported format/view
  combination, or a caught throw from the sync exporters) — one exit code
  covering all export-stage failures, distinct from the graph-load stage,
  mirroring `explore`'s own two distinct failure classes (graph vs.
  server).
- A new `commands/dataflow.md` slash dispatcher, following `scan.md`'s
  frontmatter + mode-table + bash-`case` pattern, wrapping this CLI
  subcommand — `/dataflow --format png --output report.png` (exact mode
  table and flag documentation to be written in the implementation plan,
  not here).

## Real, disclosed items NOT resolved by this document

- Exact `--output` path-handling semantics (parent-dir creation,
  overwrite behavior) — implementation-plan-level detail, not a scoping
  question with more than one reasonable answer.
- Whether `--filter` should also gain a friendlier alias/shorthand beyond
  "point at a JSON file" — deferred with the semantic `--class` filter
  question above; v1 ships the raw mechanism only.
- Whether a `--chrome-path` override should be exposed at the new CLI
  layer (it already exists as `AGENTIC_SECURITY_CHROME_PATH` env var,
  consumed transparently by `chrome-probe.mjs`) — likely unnecessary
  duplication; recommend leaving it as an env-var-only override and not
  adding a redundant flag, but not fully closed here.

## Recommended next step

A real implementation plan, sized as a single sub-project (worktree,
SDD execution), covering: (1) the new `cmdDataflowExport` CLI function in
`scanner/bin/agentic-security.js` plus its `USAGE` entry (and `explore`'s
missing entry as a drive-by fix); (2) the new `commands/dataflow.md` slash
dispatcher; (3) a `test/server/cmd-dataflow-export.test.js` following
`cmd-explore.test.js`'s real-spawned-process pattern, covering all six
formats, all four graph-load failure reasons, the SVG+non-architecture-view
rejection, and the `--size`/`--width`+`--height` mutual-exclusion check.
