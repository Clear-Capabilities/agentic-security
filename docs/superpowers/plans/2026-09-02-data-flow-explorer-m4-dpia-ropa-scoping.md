# M4 deliverable #10 (graph-derived DPIA/RoPA export, DFG-020) — scoping

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §7.4 (Privacy View)
and its own line "generate filtered DPIA and RoPA exports from the
selected graph scope"; PRD line 1836 ("graph-derived DPIA/RoPA/data
inventory behind a migration flag"); DFG-020 ("Graph-derived DPIA, RoPA,
and inventory migration", deps: DFG-014 Privacy View, DFG-019
self-contained export). Parent doc:
`2026-09-01-data-flow-explorer-m4-scoping.md`'s own row #10.

## Correcting the parent doc's own framing

Row #10 calls this "a thin templating layer on top" of sub-project #6
(Regulatory Obligation Overlay). Direct investigation shows this is
**wrong on two counts**, both found by reading real code, not assumed:

1. **The PRD's own literal DFG-020 dependency row does not list DFG-038
   (#6) at all** — its real prerequisites are DFG-014 (Privacy View) and
   DFG-019 (self-contained interactive export). Both are **already
   shipped**: `frontend/src/views/privacy-view.js` (Milestone 3) and
   `scanner/scripts/generate-html-report.mjs` (Milestone 4). #6 was
   never on DPIA/RoPA's own critical path — the parent doc's earlier
   note about DFG-038 listing DFG-020 as ITS OWN prerequisite (the
   inverse direction) was the real, load-bearing dependency, and #6 has
   already shipped correctly ahead of this.
2. **This is not new-from-scratch work, but it is also not templating.**
   Two graph-derived DPIA/RoPA generators already exist —
   `dataflow/privacy-taint.js#emitDpiaArtifact` and
   `dataflow/privacy-governance.js#emitRopaArtifact` — but they derive
   from the OLD Layer-2 taint engine's `piiFields` (name-in-argument
   classification, no path/alias/field-mapping precision — see the PRD's
   own "Shallow privacy analysis" row, line 86), not from the new
   `DataFlowGraph v1`. DFG-020's own name ("...migration") confirms this
   is a **replacement/supersession** of an already-shipped, already-wired
   artifact pair, not a green-field build.

## The real, concrete gap (found by reading `graph-builder.js` and
`privacy-view.js` side by side)

`frontend/src/views/privacy-view.js#computePrivacyRow` **already reads
`flow.governanceRefs`** directly off the graph (line 35:
`governanceRefs: flow.governanceRefs ?? {}`) — Privacy View's own
rendering path (`renderStageCell`'s governance-badge loop, per the
frontend CLAUDE.md's own row for this file) is fully built and wired to
display purpose/lawfulBasis/subject/retention/residency/recipient/
transfer/minimization/consent/access/deletion per flow, **the moment
real data exists there.**

Nothing populates it. `graph-builder.js` hardcodes `governanceRefs: {}`
at BOTH mint sites — the node mint (line 486) and the flow mint (line
875, confirmed: `de` — the flow's own `dataElement`, carrying
`dataClasses` — is in scope at that exact call site). This is the SAME
gap the M4 row-#6 note already found for a DIFFERENT reason
(`flow.governanceRefs` empty was part of what made the parent doc's
original #6 framing wrong too) — this sub-project is what actually
closes it.

Separately, `dataflow/privacy-governance.js` already ships the ENTIRE
governance-field infrastructure #10 needs, fully built, tested, and
correctly-conservative:
- `GOVERNANCE_FIELDS` (the PRD's own 11-field list, FR-407)
- `MANUAL_REQUIRED` sentinel — never inferred, never blank
- `loadPrivacyGovernanceConfig(scanRoot)` — reads
  `.agentic-security/privacy-governance.json` (`{byClass, default}`),
  never throws
- `governanceRecordFor(dataClass, config)` — per-class field lookup,
  `{value, source: 'operator_provided'|'manual_required'}` per field

This is **directly reusable, unmodified** — the only new work is calling
it per-flow (keyed on `dataElement.dataClasses`) at graph-mint time,
mirroring `graph-builder.js`'s own established opts-hook pattern
(`resolveSiteDecision`/`resolveDestination`/`resolveTransitProtection`,
each composed into a default in `coverage.js#buildGraphWithCoverage`).

## Design

**New hook**: `opts.resolveGovernanceRefs(dataClasses: string[]) ->
Record<field, {value, source}>`, applied at the flow-mint site
(`graph-builder.js:875`) alongside the existing `governanceRefs: {}`
literal — same additive-hook shape as every sibling hook in this file,
byte-identical graph when omitted (matching every prior hook's own
"proven byte-identical when omitted" precedent).

**Default wiring**: `coverage.js#buildGraphWithCoverage` gains a default
`resolveGovernanceRefs` closing over `governanceRecordFor`/
`loadPrivacyGovernanceConfig(opts.scanRoot)` — composing with a
caller-supplied override, matching `resolveTransitProtection`'s own
precedent (`opts.resolveGovernanceRefs ?? <default>`).

**Migration flag — ruled**: unconditional once lineage is on, i.e.
**`AGENTIC_SECURITY_LINEAGE_DEEP=1` IS the migration flag** the PRD's
caution refers to, matching the established, unbroken precedent of
EVERY sibling opts-hook in `graph-builder.js`
(`resolveSiteDecision`/`resolveDestination`/`resolveTransitProtection`
are each composed into `coverage.js#buildGraphWithCoverage`'s default
unconditionally — none carries its own separate flag beyond the graph's
own existence requiring `AGENTIC_SECURITY_LINEAGE_DEEP=1` in the first
place). A dedicated second flag would be the FIRST exception to that
precedent, and `governanceRefs` carries strictly less correctness risk
than its siblings: it only ever ATTACHES already-operator-supplied
config or the same `MANUAL_REQUIRED` sentinel Privacy View already
renders for an empty `{}` today — never fabricates anything about code
the way `resolveDestination`/`resolveTransitProtection` do. Real,
disclosed consequence (not a defect): `computeGraphDigest` canonicalizes
the whole graph, so this DOES change the digest the moment ANY
`.agentic-security/privacy-governance.json` exists on disk — the exact
same kind of disclosed, intended digest change `resolveTransitProtection`'s
own `index.js` row already precedents ("`graph` is no longer
byte-identical when `opts.fileContents` is supplied ... a real,
disclosed, intended behavior change").

**DPIA/RoPA export functions**: two new pure functions, reusing
`computePrivacyViewModel`'s ALREADY-CORRECT row shape (source/sink
node/subtype, dataClasses, protection verdicts, governanceRefs, AI
relevance) rather than re-deriving it a second time:
- `emitGraphDpiaArtifact(graph, viewModel, opts)` — narrative Markdown,
  mirroring `privacy-taint.js#emitDpiaArtifact`'s own structure/wording
  (GDPR Art. 35 framing) but populated from real graph rows.
- `emitGraphRopaArtifact(graph, viewModel, opts)` — tabular Markdown,
  mirroring `privacy-governance.js#emitRopaArtifact`'s own register
  format, one row per (dataClass × recipient/destination) rather than
  per dataClass alone (the graph's own per-flow sink/destination
  precision is a real, disclosed improvement over the taint-engine
  version's coarser per-class grouping).

Both consume `computePrivacyViewModel(graph, state, queryPredicate)`'s
own `{stages, rows}` output directly — this is the "filtered... from the
selected graph scope" requirement's own mechanism (Privacy View's
existing `state.filters`/query predicate), satisfied for free rather
than reinvented.

**Wiring — resolved concretely, not left open** (confirmed by reading
the real code, not assumed):

- **CLI**: `bin/agentic-security.js` already ships a real, well-tested
  `dataflow export [path] --format png|pdf|svg|json|csv|html --output
  <file> [--view ...] [--filter <file>]` command (`cmdDataflowExport`,
  `DATAFLOW_EXPORT_FORMATS`/`DATAFLOW_EXPORT_VIEWS` sets), already
  loading the graph via `loadSignedGraph` and already supporting
  `--filter` (a `{nodeIds, edgeIds}` JSON file, the exact "scoped export"
  mechanism this deliverable needs). **No new subcommand is needed** —
  add `'dpia'`/`'ropa'` to `DATAFLOW_EXPORT_FORMATS` and one new
  `else if` branch in `cmdDataflowExport`'s existing format dispatch,
  mirroring the `json`/`csv` branches exactly (no `--view`, since neither
  format is view-scoped, same as those two). One disclosed, deliberately
  out-of-scope gap found along the way: `cmdDataflowExport` uses
  `loadSignedGraph` directly, not sub-project 6c's `loadFreshLineageGraph`
  — every existing export format (png/pdf/svg/json/csv/html) already
  carries this same staleness exposure, a real but lower-stakes gap
  (a possibly-stale VISUALIZATION, not a signed compliance CLAIM the way
  `attest --obligations` is) — not this sub-project's to fix, named here
  so it isn't silently rediscovered later.
- **Reuse of `computePrivacyViewModel`**: confirmed LIVE, importable
  directly from Node with zero DOM dependency —
  `frontend/src/views/privacy-view.js` only touches `document`/`window`
  inside `renderPrivacyView`'s own function body (via `lib/dom.js`'s
  `el()`), never at module top level, so `import { computePrivacyViewModel
  } from '../../frontend/src/views/privacy-view.js'` succeeds in plain
  Node with no shim (verified: `node -e "import(...)"` from `scanner/`
  resolves cleanly). This is a NEW cross-package reuse pattern, worth its
  own disclosure: `generate-html-report.mjs` already reaches into
  `frontend/` today, but only to bundle its source as TEXT for browser
  embedding (`bundle-frontend.mjs`) — this is the first time `scanner/`
  would `import` a `frontend/` module LIVE, for its own Node-side
  computation. A real, deliberate architectural decision for the plan doc
  to state explicitly, not a silent precedent shift.
- **Frontend interactive export button**: NOT found — grepped
  `frontend/src/` for any existing "export"/"download" UI action; none
  exists yet (the only export surface today is the CLI's `dataflow
  export`, consumed externally). Adding one is real, separate,
  deliverable-#10-adjacent UI scope — **deferred**, named in "Out of
  scope" below, since the PRD's own "filtered... from the selected graph
  scope" requirement is fully satisfiable via the CLI's existing
  `--filter` mechanism without it.

## Out of scope for this sub-project (real, disclosed, deferred)

- **Data inventory migration** — DFG-020's own name also covers "data
  inventory," which Milestone 3's Inventory View (`inventory-view.js`)
  already covers as an interactive table; a MARKDOWN/CSV export of that
  view (`--format inventory`?) is real, separate, deliverable-#10-adjacent
  scope, not attempted here — this sub-project closes only the DPIA/RoPA
  half of DFG-020's name.
- **Populating `node.governanceRefs`** (as opposed to `flow.governanceRefs`)
  — Privacy View's own rendering only reads the flow-level field
  (confirmed by reading `computePrivacyRow` in full); a node-level
  populate is real, separate, undecided scope if a future consumer needs
  it.
- **A real operator-config UI for `.agentic-security/privacy-governance.json`**
  — stays a hand-edited JSON file, per its own existing, shipped contract;
  no UI editor is implied by this sub-project.
- **A frontend interactive export button** — the CLI's `--filter`
  mechanism already satisfies the PRD's "filtered... from the selected
  graph scope" requirement; a UI action is real, separate, deferred scope.
- **`cmdDataflowExport`'s pre-existing `loadSignedGraph`-not-
  `loadFreshLineageGraph` staleness exposure** — shared by every existing
  export format, not introduced by this sub-project, lower-stakes than
  the signed-compliance-artifact case 6c closed; named, not fixed, here.
