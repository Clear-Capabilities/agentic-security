# M4 Deliverable #8 (FR-503, DFG-022 + DFG-037): Data-Flow Time Machine — Scoping

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §14 lines 481-491
("Data-Flow Time Machine and drift detection" — **another real PRD ID
collision**: `FR-503` also names an unrelated §20 "Candidate inventory"
requirement at line 1489; every reference here means the §14 capability).
`GraphSnapshot`/`GraphDiff` contracts: §10.10, lines 966-969 lines
966-969. Acceptance criterion: AC-27 (lines 1739-1741). Backlog rows:
DFG-022 ("Comparable snapshot, semantic graph-diff, and provenance
foundation") and DFG-037 ("Data-Flow Time Machine UI, provenance
timeline, comparability analysis, and drift policies," depends on
DFG-002, DFG-022, DFG-028). Parent doc: `2026-09-01-data-flow-explorer-m4-scoping.md`'s
own row 8.

## Real investigation (grounds the scope split below)

- **No snapshot/diff mechanism exists anywhere under `scanner/src/lineage/`
  today** — confirmed by search; only the CURRENT graph is ever persisted
  (`.agentic-security/lineage-graph.json`, overwritten every scan).
- **A real, directly-mirrorable architectural precedent exists**:
  `scanner/src/posture/sbom-diff.js` — persists a snapshot per git commit
  under `.agentic-security/sbom-history/<sha>.json`, loads the most recent
  prior snapshot by mtime, diffs by a content-derived key into
  added/removed/changed/substituted buckets. Not reusable CODE (it
  operates on flat SBOM components, not graph entities), but a proven,
  already-shipped shape for exactly this feature class in this codebase.
- **Canonical IDs are confirmed genuinely content-hash-based, not
  run-dependent** (`ids.js`'s `nodeId`/`edgeId`/`dataElementId`/`flowId` —
  sha256 over sorted, canonicalized discriminator parts, no timestamp/
  random/run-counter component) — this is the property that makes
  "diff two graphs by comparing their canonical ID sets" sound at all.
- **Comparability has one real, already-populated field to key on
  (`schemaVersion`) and one real, DISCLOSED gap**: `graphId`'s own
  `configHash` component is never actually supplied by any real caller
  today (`ids.js`'s own header comment already discloses this — every
  real graph's `graphId` ends in the literal `:default`), so `graphId`
  alone cannot distinguish two genuinely different-content graphs at the
  same commit. No separate analyzer-version/taxonomy-version field exists
  on a graph today.
- **Change-cause classification ("distinguish application change from
  analyzer/configuration/coverage change," AC-27's own binding
  requirement) has NO existing precedent anywhere in this codebase** —
  confirmed against `posture/scorecard.js`, `bench/layer-recall/`, and
  `sbom-diff.js` itself (whose own snapshot shape carries no
  scanner-version field either). This is genuinely new detection work,
  the hardest, most novel part of this deliverable.
- **A real, closely-mirrorable drift-policy precedent exists**:
  `dataflow/privacy-sink-policy.js` (already reused unmodified for the
  graph's own `flow.policyVerdict`, per sub-project G) and
  `obligation-predicates.js` (the Regulatory Obligation Overlay's own
  graph-fact predicate evaluator) are both small, fail-closed declarative
  matchers over a single graph's state. A drift policy needs to match a
  TRANSITION between two graphs ("new PHI → external") — a genuinely
  different shape (before/after diff, not single-graph predicate) — but
  the match-object vocabulary and fail-closed philosophy transplant
  directly.

**Overall assessment (from the investigation, not assumed): FR-503 is
larger than a single "Large" sub-project** — DFG-037 explicitly depends
on DFG-022 being built first, and DFG-022 itself has zero code today.
Realistically two dependent Large sub-projects stacked, matching the
PRD's own dependency ordering, not one.

## Scope split

**Sub-project 8a — `GraphSnapshot` contract + persistence + comparability
(small/mechanical, mirrors sub-project 6a's own shape):**
- `GraphSnapshot` §10.10 extension contract (pure validator, mirrors
  `obligation-mapping.js`/`decision-story.js`'s own established shape).
- `persistGraphSnapshot`/`loadSnapshots`/`loadSnapshot`/`mostRecentPriorSnapshot`,
  mirroring `sbom-diff.js`'s own persist-by-commit / most-recent-by-mtime
  architecture, adapted to graph entities and stored at
  `.agentic-security/lineage-snapshots/<key>.json`.
- `snapshotsComparable(a, b)` — `schemaVersion` match at minimum, with
  the `configHash`/analyzer-version gap explicitly disclosed (not
  silently ignored) as a real comparability limitation until a future
  increment adds a real config/analyzer-version signal.
- Wired into the scan flow: a snapshot is persisted ALONGSIDE the
  existing single "current" `lineage-graph.json`, never replacing it.

**Sub-project 8b — `GraphDiff` computation + change-cause classification
+ drift policies + CLI wiring (the "real work," mirrors sub-project 6b +
DPIA/RoPA's own CLI-wiring combined):**
- `GraphDiff` §10.10 extension contract.
- `computeGraphDiff(snapshotA, snapshotB)` — added/removed/changed
  canonical-ID sets across nodes/edges/dataElements/flows (a real,
  sound set comparison, per the confirmed-stable-ID property above).
- Change-cause classification: an honest, disclosed default — no real
  analyzer/config-version signal exists today to POSITIVELY detect a
  tooling-caused change, so every diff entry defaults to
  `application_change` UNLESS a real, checkable signal says otherwise
  (a `schemaVersion` mismatch → `schema_change`; a real,
  measurably-reduced `coverage` between the two snapshots →
  `coverage_change`, satisfying AC-27's own "a missing current flow
  cannot be called remediated when the current scan is incomplete or
  less capable" requirement specifically). Never a guess dressed as
  detection.
- Drift-policy DSL: a new before/after matcher over `GraphDiff`'s own
  added/changed entities, mirroring `privacy-sink-policy.js`'s fail-closed
  axis-matching style — closes AC-27's own worked example (`new PHI →
  external` policy).
- CLI wiring: a new `dataflow diff [--against <key>] [--drift-policy
  <file>] --output <file>` subcommand (a two-snapshot operation does not
  fit `dataflow export`'s existing one-graph-in shape).

**Out of scope for both (disclosed, not silently dropped), matching the
DPIA/RoPA and FR-501 sub-projects' own precedent:**
- The interactive Time Machine UI (timeline slider, before/after visual
  diff, provenance/change-cause inspector) — a genuinely separate,
  large frontend undertaking, deferred with the same reasoning FR-501's
  own scoping doc already gave for its Briefing view.
- First-introduced/last-seen commit/author/PR provenance beyond "which
  persisted snapshot first/last carried this canonical ID" — the
  existing Finding Provenance system (`posture/provenance/`) resolves
  git blame for SAST *findings*, a structurally different object; real
  git-blame-depth provenance for graph entities is a disclosed future
  enhancement, not attempted here. What ships instead is honest and
  real: which of the app's OWN persisted snapshots first/last shows a
  given canonical ID, with that snapshot's own commit/timestamp — not a
  full git-history walk.
- Real analyzer/config-version detection beyond `schemaVersion` — the
  `configHash` gap (`ids.js`'s own disclosed limitation) is not closed
  here; closing it is a real, separately-scoped future increment.
