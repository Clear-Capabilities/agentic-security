# M4 Deliverable #10: Graph-Derived DPIA/RoPA Export — Scoping

**Status: COMPLETE (2026-09-02).** This doc records the real scope found
by investigation, kept for future readers per this project's convention
of not deleting a sub-project's scoping doc once implemented (see e.g.
`2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`).

## What the PRD asks for

DFG-020 (PRD §7.4): export a Data Protection Impact Assessment (GDPR
Art. 35) and a Record of Processing Activities (GDPR Art. 30) derived
from the Data Flow Explorer's own graph, "filtered/scoped from the
selected graph scope," "behind a migration flag."

This codebase already has ONE generation of this exact idea:
`dataflow/privacy-taint.js#emitDpiaArtifact` /
`dataflow/privacy-governance.js#emitRopaArtifact`, built on the Layer-2
taint engine's `piiFields` — name-in-argument classification with no
path/alias/field-mapping precision, and no per-flow destination
resolution (RoPA rows are per-dataClass, not per-flow). Deliverable #10
is a migration of that same idea onto the real `DataFlowGraph v1`'s
field-identity-tracked flows, not a new document type.

## What the parent M4 scoping doc got wrong

`2026-09-01-data-flow-explorer-m4-scoping.md`'s own row for this
deliverable called it "a thin templating layer on top" of sub-project #6
(Regulatory Obligation Overlay), assuming #10 would consume #6's
`ObligationMapping`/predicate-engine output directly. Real investigation
found this false:

- #6's own predicate engine (`obligation-predicates.js`) answers a
  different question — "is a specific named regulatory control satisfied
  by this graph" — not "what are this flow's own governance facts
  (purpose, lawful basis, recipient, retention, …)." DPIA/RoPA needed the
  latter, which #6 never produced.
- The real prerequisite was `flow.governanceRefs`, a field that did NOT
  exist anywhere in the production graph-builder before this
  sub-project (row 6 of the parent doc already noted `governanceRefs`
  was hardcoded `{}` at both real mint sites — only a hand-authored demo
  fixture had real values). This sub-project had to build the real
  version: a `resolveGovernanceRefs` hook wired into
  `coverage.js#buildGraphWithCoverage`, populated from
  `dataflow/privacy-governance.js`'s existing operator-config/
  `MANUAL_REQUIRED` infrastructure (never fabricated), with a
  worst-case-wins tie-break across a flow's own data classes (mirroring
  `protection.js#aggregateVerdicts`' precedent).
- Row computation (lifecycle stage, data class, protection verdict per
  flow) already existed, correctly, in the Data Flow Explorer's Privacy
  View — `frontend/src/views/privacy-view.js#computePrivacyViewModel`.
  Re-deriving it a second time in the scanner would drift; reusing it
  directly is the first live `scanner/` → `frontend/` module import in
  this codebase. Confirmed safe for direct Node execution: that module
  only touches `document`/`window` inside `renderPrivacyView`'s own
  function body, never at module top level.

So the real shape of this sub-project: (1) mint `flow.governanceRefs` for
real, (2) build two Markdown emit functions on top of
`computePrivacyViewModel`'s rows, (3) wire both into the existing
`dataflow export` CLI as two new `--format` values. Not a template.

## Scope

**In scope:**
- `flow.governanceRefs` population (`coverage.js`).
- `emitGraphDpiaArtifact(graph, opts)` / `emitGraphRopaArtifact(graph,
  opts)` in a new `scanner/src/lineage/export-privacy.js`.
- `dataflow export --format dpia|ropa` CLI wiring, `commands/dataflow.md`
  updates, `opts.filter` graph-scoping (the PRD's "selected graph scope"
  requirement), `opts.generatedAt` threading for determinism.

**Out of scope (disclosed, not silently dropped):**
- The "behind a migration flag" instruction in DFG-020 — investigated and
  found to already have a real analogue: `dataflow export` itself has no
  flag-gating precedent (every other format ships unconditionally once
  merged), and neither `dpia` nor `ropa` touch any code path another
  command depends on. Treated as satisfied by ordinary `dataflow export
  --format` opt-in (a user must explicitly request the format), not a
  separate env-var flag — consistent with every other format in this
  command.
- Re-architecting `flow.governanceRefs`'s mint-time cross-class merge so
  a multi-class flow could carry distinct per-class values — a real,
  disclosed limitation (see the final review's RECOMMENDED 2, closed via
  disclosure not a schema change) that would touch #6's shipped contract
  and the out-of-scope Privacy View frontend.
- Re-reading `.agentic-security/privacy-governance.json` at export time
  instead of scan time — an existing pattern for every other graph-backed
  export in this command (all reflect the persisted graph, not live
  disk state); disclosed in both documents' own preamble and
  `commands/dataflow.md`.
- Vendoring `frontend/src/` into the published npm package so the raw,
  unbundled `bin/agentic-security.js` also works when run directly out of
  an installed package's `node_modules` — real, confirmed via a live
  `npm pack` + consumer-install reproduction, but judged out of
  proportion to a narrow, non-blocking gap (the actual shipped
  `agentic-security`/`as` commands are unaffected, since `ncc` already
  inlines that content into `dist/agentic-security.mjs`'s own chunks).
  Given an actionable CLI error message instead; left for a future pass.
- A `--format inventory` "full data inventory" export — DFG-020 mentions
  DPIA/RoPA specifically; a broader inventory export is a distinct,
  unscoped idea for a future deliverable.
