# M4 Deliverable #10: Graph-Derived DPIA/RoPA Export — Implementation Plan

**Status: COMPLETE (2026-09-02), merged to main.** Written as an
as-built record (Subagent-Driven Development ran normally — three
implementer/reviewer task cycles plus a final whole-branch review and
fix round — but this doc itself was reconstructed after the fact rather
than kept alongside the ledger from the start; the SDD ledger at
`.superpowers/sdd/2026-09-02-data-flow-explorer-m4-dpia-ropa-plan/progress.md`
(gitignored, not in this commit) has the full turn-by-turn record).

**Goal:** Export a graph-derived DPIA (GDPR Art. 35) and RoPA (GDPR
Art. 30) from the Data Flow Explorer's `DataFlowGraph v1`, migrating off
the Layer-2 taint engine's `piiFields`-based generators.

**Architecture:** A new `flow.governanceRefs` field, minted by a
`resolveGovernanceRefs` hook in `coverage.js`; two new Markdown emit
functions in `scanner/src/lineage/export-privacy.js` built on top of the
already-shipped `frontend/src/views/privacy-view.js#computePrivacyViewModel`
for row computation; CLI wiring into the existing `dataflow export`
command as two new `--format` values.

**Tech Stack:** Plain ESM, no new dependencies. Reuses
`dataflow/privacy-governance.js`'s operator-config loading, `export-json.js`'s
`_filterGraph`, and (newly) `frontend/src/views/privacy-view.js` from
`scanner/`.

**Spec:** `2026-09-02-data-flow-explorer-m4-dpia-ropa-scoping.md`
(DFG-020, PRD §7.4).

## Global Constraints

- Never fabricate a governance fact — every value is either
  operator-supplied (`.agentic-security/privacy-governance.json`) or the
  literal `MANUAL_REQUIRED` sentinel.
- `opts.filter` is the same `{nodeIds, edgeIds}` shape every other
  `dataflow export` format uses; scope the GRAPH before row computation,
  never thread it into `computePrivacyViewModel`'s own `state.filters`
  (a different, per-facet shape).
- Determinism: `opts.generatedAt` must come from the graph's own
  `generatedAt`, never wall-clock time, matching `json`/`html`.
- Every value interpolated into the emitted Markdown must be escaped —
  operator-supplied prose is untrusted input to a Markdown document.

---

## Task 1: `flow.governanceRefs` (mint-time)

**Files:**
- Modify: `scanner/src/lineage/coverage.js` (`buildGraphWithCoverage`'s
  default `resolveGovernanceRefs` hook)
- Modify: `scanner/src/lineage/graph-builder.js` (flow-mint site, ~line
  875-885: `governanceRefs: opts.resolveGovernanceRefs?.(de.dataClasses
  ?? []) ?? {}`)
- Test: `scanner/test/lineage/governance-refs.test.js`

**Interfaces:**
- Produces: `flow.governanceRefs: Record<field, {value, source}>` where
  `source` is `'operator_provided'` or `'manual_required'`, for every
  field in `dataflow/privacy-governance.js#GOVERNANCE_FIELDS`.

**As built:** `resolveGovernanceRefs` calls
`dataflow/privacy-governance.js#governanceRecordFor` once per data class
on the flow's own `dataElement.dataClasses`, worst-case-wins merging
across classes (a field already resolved to `operator_provided` is never
overwritten by a later class's `manual_required`) — mirroring
`protection.js#aggregateVerdicts`'s existing tie-break precedent.

**Review found (fixed):** a flow with `dataClasses: []` (a real,
legitimate case — an unclassified field) produced `governanceRefs: {}`
instead of a full all-`MANUAL_REQUIRED` record, in tension with this
project's "missing evidence → unknown, never not-applicable" convention.
Fixed via a `'(unclassified)'` sentinel class fallback.

**Review found (fixed), separately, while writing the regression test
for the above:** the new test's own comment text (`from "nothing
to\n...disclose here"`) tripped `coverage.test.js`'s `C1/10`
reuse-boundary regex, which scans a file's ENTIRE TEXT (including
comments) for `from`/`import` immediately followed by a quoted string.
Rephrased.

## Task 2: `export-privacy.js` (DPIA/RoPA generation)

**Files:**
- Create: `scanner/src/lineage/export-privacy.js`
- Test: `scanner/test/lineage/export-privacy.test.js`

**Interfaces:**
- Consumes: `flow.governanceRefs` (Task 1);
  `frontend/src/views/privacy-view.js#computePrivacyViewModel(graph,
  state, queryPredicate)`; `export-json.js#_filterGraph` (newly exported,
  was module-private).
- Produces: `emitGraphDpiaArtifact(graph, opts)` /
  `emitGraphRopaArtifact(graph, opts)`, both returning a Markdown
  string. `opts: {filter?, generatedAt?}`.

**As built:** `_scopedViewModel(graph, filter)` filters the graph via
`_filterGraph` BEFORE calling `computePrivacyViewModel` — the plan's own
first draft would have threaded `opts.filter` into
`computePrivacyViewModel`'s `state.filters` directly, a bug caught before
implementation (that parameter expects per-facet selected-value arrays,
e.g. `{dataClass: [...]}`, and would have silently no-op'd on
`{nodeIds, edgeIds}`).

`emitGraphDpiaArtifact` groups `computePrivacyViewModel`'s rows by data
class (`_groupRowsByClass`) into narrative sections; `emitGraphRopaArtifact`
emits one table row per (flow × data class) — a real precision
improvement over the taint-engine generator's per-dataClass-only rows,
made possible by the graph's own per-flow destination resolution.

**Review found (fixed):** `_groupRowsByClass`'s bare `for (const cls of
row.dataClasses)` silently dropped any flow with `dataClasses: []` from
the WHOLE document — not merely ungrouped, genuinely invisible, for a
document whose entire purpose is a complete inventory. RoPA's own
sibling loop already had a `'(unclassified)'` fallback; mirrored here.

## Task 3: CLI wiring

**Files:**
- Modify: `scanner/bin/agentic-security.js` (`DATAFLOW_EXPORT_FORMATS`,
  `cmdDataflowExport`)
- Modify: `commands/dataflow.md`
- Test: `scanner/test/cli/dataflow-export-privacy.test.js`

**As built:** `dpia`/`ropa` join `json`/`csv`/`html` in the
non-view-scoped set (warn + no-op for `--view`); `--no-redact` is a
documented no-op (neither format calls `exportGraphJSON`'s redaction
path); `--filter` genuinely scopes the graph (unlike `csv`, which is a
no-op there too — a real, disclosed asymmetry).

**Review found (fixed):** `commands/dataflow.md` was never updated with
the two new formats across its argument-hint, format table, and all
three no-op option lists. Separately: `opts` omitted `generatedAt`
entirely, so the DPIA's "Generated on `<date>`" line reflected
export-time wall clock rather than the graph's own fixed `generatedAt` —
the only format among json/html/dpia/ropa that didn't already embed the
graph's own value. The coordinator's first regression-test attempt for
this was itself flawed (a same-day double-export test can't distinguish
"reads graph time" from "reads wall-clock time," since both show today's
date) — rebuilt using `AGENTIC_SECURITY_DETERMINISTIC=1`
(`src/posture/deterministic.js`), which freezes `graph.generatedAt` to
the literal `1970-01-01T00:00:00.000Z`, structurally distinct from
"today." Mutation-verified against the pre-fix code.

## Final whole-branch review + fix round

Verdict: NOT MERGE-READY on first pass — 1 BLOCKING, 3 RECOMMENDED,
3 NITPICK, all closed in one fix round (details and full verification
output in the SDD ledger; summarized here for the permanent record):

1. **BLOCKING — Markdown injection.** No escaping on any value
   interpolated into either document. An operator-supplied governance
   value containing a literal `|` shifted every later RoPA table column;
   an embedded newline broke a row out of the table or injected
   arbitrary Markdown into either document, and the two documents could
   end up contradicting each other about the same flow. Fixed:
   `_mdInline`/`_mdCell`/`_mdCode` helpers in `export-privacy.js`
   (newline collapse, `|`-escaping, backtick-safe code-span wrapping),
   applied to every interpolated value in both emit functions.

2. **RECOMMENDED — cross-class governance misattribution.** A flow
   spanning more than one data class carries ONE `governanceRefs` record
   already merged (worst-case-wins, Task 1) across ALL its classes —
   both documents re-presented that single record under each class's own
   heading/row with no indication it wasn't class-specific, silently
   losing a real per-class operator override. This spans the Task
   1/Task 2 seam; no task-level review (each scoped to its own file, each
   using single-class fixtures) could have seen it — the clearest
   demonstration this session had yet of why a final whole-branch review
   is load-bearing beyond per-task review. Fixed via disclosure (not a
   mint-time schema change, which would touch #6's shipped contract and
   the out-of-scope Privacy View frontend): a multi-class flow's bullet
   notes its other classes; any class section containing one gets an
   explicit "merged across ALL of its classes" note; RoPA marks the
   affected row's Data-class cell with `*` plus a table-footer legend.

3. **RECOMMENDED — config staleness.** Governance facts reflect
   `.agentic-security/privacy-governance.json` as of the scan that
   produced the graph, not export time — undisclosed. Fixed via a
   preamble note in both documents plus a `commands/dataflow.md` update
   (documentation only, matching the disclosure precedent already used
   for the analogous stale-graph gap in `compliance --walkthrough`,
   sub-project 6c).

4. **RECOMMENDED — npm packaging.** `frontend/src/views/privacy-view.js`
   resolves outside the published `scanner/` package (a repo-root
   sibling, not a subdirectory) — confirmed via a real `npm pack` +
   install into a fresh consumer project, then a direct dynamic
   `import()` of the installed `export-privacy.js`
   (`ERR_MODULE_NOT_FOUND` for `@clear-capabilities/frontend/...`).
   Investigated in full before deciding scope: the actual shipped,
   documented `agentic-security`/`as` commands (→
   `dist/agentic-security.mjs`) are NOT affected, since `ncc` statically
   traces the dynamic import and its own transitive `frontend/src`
   dependencies, inlining all of it into `dist/*.index.js` chunks at
   build time (confirmed by grepping the built chunks for
   `privacy-view`). Only the raw, unbundled `bin/agentic-security.js`
   run directly out of an installed package hits the real error. A full
   fix (vendoring `frontend/src/` into `scanner/` at build time, plus a
   parity test) was judged out of proportion to a non-blocking, narrow
   gap; `cmdDataflowExport`'s catch block instead gives that one case an
   actionable message pointing at the published command.

5. **NITPICK ×3, all fixed:** RoPA now has its own `Generated ... on
   <date>` line (previously DPIA-only); the RoPA footer reports row
   count and flow count separately (`N field(s) across R row(s) (F
   flow(s))` — previously conflated the two); `unknown`/`unknown`
   fallbacks reworded to `unknown source`/`unknown destination`,
   matching DPIA's descriptive style.

**Own-caused regression found and fixed during the fix round:** the new
`.agentic-security/privacy-governance.json` preamble line wrapped that
path in Markdown backticks inside a JS string literal — a backtick
immediately before `.agentic-security` reads identically to real path
construction to `test/no-stray-state.test.js`'s guard regex. The same
class of hazard this session had already hit twice against a *different*
guard (`coverage.test.js`'s `C1/10` import regex, Task 1 above). Fixed
by dropping the Markdown backticks around that one path.

**Final verification (all exit 0):** `npm run test:lineage` 807/807;
`npm run test:server` 90/90; `npm run test:smoke` 30/30; `npm run
test:lifecycle` 248/248; `npm run test:posture` 2353/2353; `npm run
build` + bundle sha256 confirmed current;
`test/cli/dataflow-export-privacy.test.js` 6/6 (real end-to-end scan →
export). New regression tests for the fix round mutation-verified
against the pre-fix file (byte-identical restore confirmed via `git diff
--stat`).
