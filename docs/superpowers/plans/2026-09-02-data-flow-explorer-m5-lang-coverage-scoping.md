# M5, language coverage-tier disclosure: scoping

Per the M5 top-level scoping doc's own deliverable #1 row and its
ruling: PRD §26's "every additional language that passes the common
gate" cannot mean "add languages beyond the ones that already pass" —
`docs/METRICS.md` (engine v0.137.1, measured 2026-08-19,
`bench/layer-recall`'s IR-TAINT column, the closest existing proxy for
PRD §22.3's own "field-to-sink recall" definition) shows **zero of the
9 lineage-wired languages clear the PRD's own ≥85% bar**:

| language (`languageForFile` string) | IR-TAINT recall (docs/METRICS.md, measured 2026-08-19) |
|---|---:|
| python | 66% |
| go | 59% |
| js | 58% |
| csharp | 57% |
| ruby | 55% |
| java | 52% |
| php | 52% |
| kotlin | 48% |
| cpp | 18% |

This sub-project builds the ruling's chosen alternative: **the
genuinely unbuilt, Explorer-specific per-language coverage-tier
disclosure UI** PRD §22.1 itself explicitly allows ("The UI may display
partial inventories for later languages, but must label the coverage
tier. P0 ships the languages that pass the gate, not a predetermined
marketing list") — never a re-run of the separate, already-executing
taint-recall improvement initiative (`scanner/src/ir/CLAUDE.md`'s own
"Taint-recall PRD" history), which stays out of scope here and is cited,
not duplicated.

## What already exists (confirmed by direct read this session)

- `graph.coverage` is validated only as a plain object
  (`validate.js`'s `_requireObject`, `dataflow-graph.schema.json`'s
  `"coverage": {"type": "object"}`) — **zero structural schema/validator
  changes are needed to add a new field to it.**
- `coverage.js`'s `buildCoverageLedger(built, opts)` already computes a
  real, per-scan `languages: [{language, filesExpected, filesAnalyzed}]`
  array from `opts.perFile` (the same `_sharedIR.perFile` map
  `engine.js`'s real `runFullScan` call site already threads through —
  confirmed live at `src/engine.js:9264`'s `buildLineageGraph(callGraph,
  {..., perFile, ...})` call). This is real, populated, per-repo data
  today, not something this sub-project has to build from scratch.
- `coverage.js`'s own `LANGUAGE_EXT_PATTERNS`/`languageForFile(file)`
  (private to that module) is the exact vocabulary source: `js`,
  `python`, `java`, `csharp`, `kotlin`, `go`, `php`, `ruby`, `cpp` — 9
  values, matching the 9 languages with real lineage/taint wiring
  exactly. **Rust/solidity/swift/dart (the 4 tree-sitter-pattern-only
  languages, zero lineage wiring per the M5 top-level doc's own
  investigation) are NOT in this list at all** — a `.rs`/`.sol`/
  `.swift`/`.dart` file falls through to `languageForFile`'s own
  `'unknown'` fallback today, indistinguishable from a genuinely
  unrecognized extension. A disclosure that wants to honestly label
  these 4 as "pattern-only, zero lineage" (rather than silently folding
  them into an undifferentiated "unknown" bucket) needs 4 new regex
  rows added to `LANGUAGE_EXT_PATTERNS`, mapping to 4 new language
  strings — cheap, mechanical, no behavior change for any file already
  matching an existing pattern.
- `opts.parseFailures` is NOT wired at the real call site
  (`src/engine.js:9264` never passes it, confirmed by direct read) —
  `languages[].filesExpected` will always equal `filesAnalyzed` in a
  real scan today (no failures ever counted). A real, disclosed,
  pre-existing gap, not something this sub-project is chartered to fix
  — noted so nobody mistakes `filesExpected === filesAnalyzed` for
  "always 100% success" rather than "failures aren't counted yet."
- No per-language coverage-tier UI/rendering exists anywhere in
  `frontend/src/` or in any `dataflow export --format` today (confirmed
  by the M5 top-level doc's own grep). Matches every M4 decision-
  intelligence capability's own precedent (Executive Risk Story Mode,
  Time Machine, Recipient Intelligence, DPIA/RoPA) of shipping a real,
  useful CLI/JSON/Markdown capability with zero frontend work for a
  first cut — this sub-project follows the same precedent.
- `bin/agentic-security.js`'s `DATAFLOW_EXPORT_FORMATS`/`cmdDataflowExport`
  dispatch already has 6 real precedents for "one new named export
  format, one new render function, wired the same way" (`json`, `csv`,
  `html`, `dpia`, `ropa`, `briefing`, `recipients` — 7 by the time
  `recipients` landed). A `coverage` format follows the identical,
  now well-established shape.

## Design

**One new, small, static module**:
`scanner/src/lineage/language-coverage-tiers.js`, exporting a frozen
`LANGUAGE_COVERAGE_TIERS` table keyed on the exact 9
`languageForFile`-normalized strings above, each entry `{language,
tier, irTaintRecallPct, measuredAt, source}` — every recall number and
date copied VERBATIM from `docs/METRICS.md`'s own committed table
(never re-measured or re-derived by this sub-project; a stale
disclosure is still an honest one as long as `measuredAt`/`source` are
present and truthful about what they cite), plus 4 more entries for
rust/solidity/swift/dart at `tier: 'pattern-only'`,
`irTaintRecallPct: null` (no lineage engine runs against them at all,
so there is no recall number to report — never fabricate one).
`coverageTierForLanguage(language) -> entry | null` is the one lookup
function — returns `null` (never a guess) for `'unknown'` or any string
not in the table.

**A new `LANGUAGE_COVERAGE_TIER_VALUES` enum** in `schema.js`:
`['full', 'partial', 'pattern-only', 'unknown']` — deliberately its own
small vocabulary, NOT a reuse of `COVERAGE_STATUS_VALUES`
(`modeled`/`partial`/`candidate`/`unsupported`/`manual`), which answers
a different question (is this one NODE's classification confident) —
collapsing the two would be the exact same category-error this
codebase has already corrected once (`FLOW_EVIDENCE_GRADES` deliberately
not reusing `EVIDENCE_GRADES`, `obligation-mapping.js`'s own
`OBLIGATION_FACT_TYPES` deliberately not reusing either). `'full'` is
real and reachable (a language whose curated recall clears 85% in a
future `docs/METRICS.md` update needs no code change to report it — the
tier is derived from the number, not hardcoded per language), even
though zero entries currently resolve to it.

**`coverage.js`'s `buildCoverageLedger`** gains one additive line per
language-bucket entry: `tier: coverageTierForLanguage(language)?.tier ??
'unknown'`, plus (only when a real curated entry exists)
`irTaintRecallPct`/`measuredAt`/`source` copied onto that language's own
ledger row. `languageForFile`'s `LANGUAGE_EXT_PATTERNS` gains the 4 new
rust/solidity/swift/dart rows.

**A new `dataflow export --format coverage` CLI mode**
(`bin/agentic-security.js`), mirroring `recipients`'s own established
shape exactly: `_renderDataflowCoverageMarkdown(graph, opts)` — one
Markdown table row per `graph.coverage.languages[]` entry (language,
files analyzed/expected in THIS repo, tier, curated recall % + as-of
date when known), plus an explicit disclosure paragraph distinguishing
"real, per-repo file counts" from "a curated, product-level recall
estimate last measured on `docs/METRICS.md`'s own date" — the two are
different kinds of fact and must never be presented as one number. Local
`_dfCoverageMdInline`/`_dfCoverageMdCell`/`_dfCoverageMdCode` escaping
helpers, byte-identical bodies to the established
`_dfRecipientsMd*`/`_dfDiffMd*` trios, per this codebase's own
per-module-owns-its-own-escaping-helpers convention.

## Global constraints for the implementation plan

- Never fabricate a recall number for a language with no curated entry
  — `coverageTierForLanguage` returns `null`, the ledger falls back to
  `tier: 'unknown'` with no `irTaintRecallPct` field at all (never
  `0`/`null` presented as if it were a measured zero).
- Every curated number must be copied verbatim from `docs/METRICS.md`'s
  own currently-committed table — do not re-derive, round differently,
  or "helpfully" adjust any of the 9 real figures.
- No schema.json/validate.js change needed for `graph.coverage` itself
  (confirmed untyped-object); DO add `LANGUAGE_COVERAGE_TIER_VALUES` to
  `schema.js` as a real, exported enum (even though nothing structurally
  validates `coverage.languages[].tier` against it — `coverage` stays
  outside `validateGraph()`'s structural checks, matching its own
  pre-existing precedent) so the vocabulary has one real source of
  truth `language-coverage-tiers.js` and its own tests both import from.
- No frontend/UI work. CLI/export only, matching every prior M4
  decision-intelligence capability's own first-cut precedent.
- `--no-redact`/`--view` should be documented no-ops for `coverage`,
  matching `recipients`'s own precedent exactly (no destination
  literal, no evidence-shaped secret anywhere in this format's own
  data — confirm this directly before writing the no-op justification,
  don't assume it from the `recipients` precedent alone).
- `--filter` has no natural node/edge-id-scoped meaning for a
  language-level table — document it as a no-op for `coverage`, an
  honest consequence (same precedent `--size`/`--width`/`--height`
  already established as silent, disclosed no-ops for non-image
  formats in the M4 CLI/slash sub-project).

## Out of scope

- Re-measuring or improving any language's real recall number — that's
  the separately-tracked taint-recall initiative, cited not duplicated.
- A 10th+ language's lineage/taint wiring (each is its own future,
  separately-scoped Large effort, per the M5 top-level doc).
- True field-to-sink recall as PRD §22.3 defines it (this sub-project
  uses `bench/layer-recall`'s IR-TAINT column as an already-disclosed
  proxy, not a new, more precise measurement).
- Frontend/UI rendering.
