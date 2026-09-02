# M4 Deliverable #8, Sub-project 8b: GraphDiff + Change-Cause Classification + Drift Policies + CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `GraphDiff` computation over two `GraphSnapshot`s (sub-project
8a, merged), honest change-cause classification, a before/after
drift-policy matcher, and CLI wiring — closing AC-27's own binding
worked example (a newly-introduced PHI→AI disclosure, correctly
attributed, correctly policy-flagged).

**Architecture:** A new pure contract/computation module (`graph-diff.js`)
consuming two `GraphSnapshot` records (8a's own `loadSnapshot`/
`mostRecentPriorSnapshot`); a new declarative drift-policy matcher
(`drift-policy.js`) mirroring `dataflow/privacy-sink-policy.js`'s own
fail-closed style but matching a DIFF's added/changed entities rather
than a single graph's state; a new `dataflow diff` CLI subcommand.

**Tech Stack:** Plain ESM, no new dependencies.

**Spec:** `2026-09-02-data-flow-explorer-m4-fr503-time-machine-scoping.md`
(FR-503, DFG-022, PRD §14 lines 481-491, §10.10 lines 966-969, AC-27
lines 1739-1741 — read the scoping doc first). Builds directly on
sub-project 8a (`scanner/src/lineage/graph-snapshot.js`, already merged) —
read that file's own header comment and exports before starting.

## Global Constraints

- `GraphDiff` records are explicitly NOT `DataFlowGraph v1` entities
  (§10.10), never added to `dataflow-graph.schema.json`, never routed
  through `validate.js`.
- **Never fabricate a change cause.** AC-27 requires "analyzer/config/
  coverage changes are separated from application changes." No real
  analyzer-version signal exists on a graph today (8a's own disclosed
  `configHash` gap) — the ONLY honest way to satisfy this requirement is
  to (a) REFUSE to diff two snapshots `snapshotsComparable` reports
  incomparable (never attempt a diff across a real `schemaVersion`
  mismatch and quietly call it an application change), and (b) for a
  REMOVED flow specifically, check the real, measurable `coverage`
  fields on both snapshots — if the AFTER snapshot's own coverage is
  genuinely lower, tag the removal `possible_coverage_regression`, never
  a clean `removed`, satisfying AC-27's own "a missing current flow
  cannot be called remediated when the current scan is incomplete or
  less capable" requirement literally. Every OTHER change defaults to
  `application_change` — an honest default, not a guess dressed as
  detection, since no real signal points elsewhere.
- **Canonical IDs are stable content hashes of specific DISCRIMINATOR
  fields, not full records** — confirmed by reading `ids.js` directly
  during 8a's own scoping: `nodeId`/`edgeId`/`dataElementId` hash only
  their own kind/relationship/canonicalName + explicit discriminator
  parts (never `protectionSummary`/`policyVerdict`/`coverageStatus`);
  `flowId(sourceNodeId, sinkNodeId, dataElementIds, discriminatorParts)`
  (confirmed at `graph-builder.js:714`, discriminated by `[p.shape,
  g.grade, sortedT.join(',')]`) ALSO never includes
  `protectionSummary`/`policyVerdict`/`handling`. This is why a genuine
  "changed" state (same identity, different verdict) is only meaningful
  for FLOWS, not nodes/edges/dataElements — a node/edge/dataElement
  "change" is definitionally a new id (an add+remove pair), since
  exactly the fields that would constitute a change ARE its identity
  discriminator. Do not invent a node/edge-level "changed" bucket; it
  would be structurally empty by construction and misleading to ship.
- First-introduced/last-seen provenance is scoped to the TWO snapshots
  being diffed, not a full historical walk across every persisted
  snapshot (a real, disclosed, smaller MVP than full git-blame-depth
  provenance — see the scoping doc's own "Out of scope" section).
- Real-graph tests required for every new function — build real
  `GraphSnapshot`s via 8a's own `persistGraphSnapshot` over real parsed
  graphs, never hand-built fake snapshot objects where a real one is
  achievable.
- New test files must be added to their real, correct `scanner/package.json`
  scope — check where sub-project 8a's own precedent files (`test/lineage/
  graph-snapshot.test.js` → `test:lineage`; `test/cli/lineage-snapshot-
  persist.test.js` → `test:posture`) actually landed, and follow the same
  pattern for the equivalent new files here, rather than guessing.

---

### Task 1: `graph-diff.js` — contract + `computeGraphDiff` + change-cause classification

**Files:**
- Create: `scanner/src/lineage/graph-diff.js`
- Modify: `scanner/src/lineage/ids.js` (add `diffId`)
- Test: `scanner/test/lineage/graph-diff.test.js`

**Interfaces:**
- Consumes: two `GraphSnapshot` records (8a's own `graph-snapshot.js`
  exports — `snapshotsComparable`, and each record's own `.graph`/
  `.coverage`/`.commit`/`.capturedAt`/`.schemaVersion` fields).
- Produces: `computeGraphDiff(snapshotBefore, snapshotAfter)` → a
  `GraphDiff` record, OR throws with a clear message if the two
  snapshots are not comparable (per `snapshotsComparable`) — never
  silently diffs across an incomparable pair. Task 3's CLI wiring and
  drift-policy matcher both consume this record's own `added`/`removed`/
  `changed` arrays directly.

**Design** (grounded in the Global Constraints above — no complete code
given here; this is a design spec, write real code against it, citing
the real files named):

- Read `scanner/src/lineage/graph-snapshot.js` in full first — its own
  `validateGraphSnapshot`/`snapshotsComparable`/record shape is what you
  build on.
- `computeGraphDiff(snapshotBefore, snapshotAfter)`:
  1. Call `snapshotsComparable(snapshotBefore, snapshotAfter)`. If
     `comparable` is false, `throw new Error(...)` naming the real
     reasons — never proceed.
  2. For each of `nodes`, `edges`, `dataElements`, `flows`: build an
     `id -> entity` `Map` from each snapshot's own `.graph[<entityArray>]`.
     `added` = ids in `after` not in `before`; `removed` = ids in
     `before` not in `after`.
  3. `changed` (flows ONLY, per the Global Constraint above): for every
     flow id present in BOTH snapshots, compare a fixed, exported
     `WATCHED_FLOW_FIELDS` list (`['protectionSummary', 'policyVerdict',
     'handling', 'coverageStatus']` — read the real flow schema fields
     first, in `dataflow-graph.schema.json`'s own flow `$def`, to
     confirm these are the real field names and there isn't a more
     complete list AC-27's own bullet points imply — e.g. "protection
     upgrades/downgrades" clearly needs `protectionSummary`,
     "retention/deletion or lawful-basis changes" needs a
     `governanceRefs`-derived comparison too; if `flow.governanceRefs`
     is a real, comparable field, add it to the watched list with its
     own real diffing logic — a value-by-value comparison of the
     `GOVERNANCE_FIELDS` keys, from `dataflow/privacy-governance.js`).
     Emit one `changed` entry per flow whose watched fields differ,
     naming exactly which field(s) changed and their before/after
     values — never a bare "something changed."
  4. Change-cause classification, applied per `removed` flow entry
     ONLY (per the Global Constraint): compare `snapshotBefore.coverage`
     against `snapshotAfter.coverage`'s own real completeness fields
     (read `coverage.js`'s own `buildCoverageLedger` output shape first
     — `sources.matched`, `sinks.callStatementSites`, `languages[]`'s
     own `filesAnalyzed` counts) — if the AFTER snapshot's coverage is
     measurably LOWER on any of these, tag that removed flow's own
     `causeClassification` as `'possible_coverage_regression'`;
     otherwise `'application_change'`. Every `added`/`changed` entry
     also gets a `causeClassification` field, always `'application_change'`
     (no other real signal exists for those — do not invent one).
  5. First-introduced/last-seen (scoped to these two snapshots only):
     each `added` entity gets `firstSeen: {commit: snapshotAfter.commit,
     capturedAt: snapshotAfter.capturedAt}`; each `removed` entity gets
     `lastSeen: {commit: snapshotBefore.commit, capturedAt:
     snapshotBefore.capturedAt}`.
  6. Assemble the `GraphDiff` record: `{id, version, beforeSnapshotId:
     snapshotBefore.id, afterSnapshotId: snapshotAfter.id, comparability:
     {comparable: true, reasons: []}, added: {nodes, edges, dataElements,
     flows}, removed: {nodes, edges, dataElements, flows}, changed:
     {flows}, generatedAt}`. Validate before returning (mirror
     `decision-story.js`/`graph-snapshot.js`'s own internal-validate-and-
     throw pattern).
- `validateGraphDiff(record)` — mirrors `validateGraphSnapshot`'s own
  `{valid, errors}` contract exactly.
- Add `diffId({beforeSnapshotId, afterSnapshotId}, discriminatorParts)`
  to `ids.js`, mirroring `snapshotId`'s exact object-argument shape.

**Tests to write:**
- A real "field newly reaches a sink" case: build two real graphs via
  `buildGraphWithCoverage` from two source snippets (one with an extra
  data flow the other lacks), persist both as real `GraphSnapshot`s
  (8a's own `persistGraphSnapshot`, in two real git commits via
  `execFileSync('git', ...)`, mirroring 8a's own test fixture pattern),
  diff them, assert the new flow appears in `added.flows` with
  `causeClassification: 'application_change'` and a real `firstSeen`.
- The AC-27 worked example directly: a PHI field newly reaching an
  AI-model-provider sink in the AFTER snapshot but not the BEFORE one —
  reuse `PHI_TO_AI_SOURCE` from `decision-story.test.js`/`export-briefing.test.js`
  and a companion snippet with that flow removed, confirm the diff
  surfaces it in `added.flows` with the real dataElement/sink info
  recoverable from the entity itself.
- A real `protectionSummary` change on a STABLE flow id: same source,
  two snapshots, but a governance/policy config change between them
  that flips `flow.policyVerdict` without changing the flow's own
  identity — confirm it appears in `changed.flows`, not
  `added.flows`+`removed.flows`.
- A real coverage-regression case: two snapshots where the AFTER one's
  `coverage.sources.matched` is genuinely lower (e.g., build the before
  graph from a 2-function source, the after graph from a 1-function
  subset that happens to also drop a flow) — confirm the removed flow
  is tagged `possible_coverage_regression`, not a clean `application_change`.
- `computeGraphDiff` REFUSES (throws, names the reason) on two snapshots
  with different `schemaVersion` — never silently diffs them.
- `validateGraphDiff` rejects a malformed record, accepts a well-formed
  one.
- A REAL CORPUS sweep: for every pair of adjacent `bench/data-lineage/`
  fixtures (or the same fixture persisted twice), `computeGraphDiff`
  never throws unexpectedly and every produced record validates.

- [ ] Write the failing tests (per the list above).
- [ ] Run to verify failure.
- [ ] Implement `graph-diff.js` + the `ids.js` addition per the design above.
- [ ] Run to verify pass.
- [ ] Wire the new test file into its correct scope, run the full scope, commit.

---

### Task 2: `drift-policy.js` — before/after drift-policy DSL

**Files:**
- Create: `scanner/src/lineage/drift-policy.js`
- Test: `scanner/test/lineage/drift-policy.test.js`

**Interfaces:**
- Consumes: a `GraphDiff` record (Task 1's own output);
  `GOVERNANCE_FIELDS` from `../dataflow/privacy-governance.js` if a
  policy needs to match on a governance-field transition.
- Produces: `evaluateDriftPolicies(diff, policies, graphAfter)` →
  `{violations: [...]}`. `policies` is the same operator-config shape
  `dataflow/privacy-sink-policy.js`'s own `loadPrivacySinkPolicy`
  establishes (a JSON file under `.agentic-security/`), adapted to
  drift's own rule vocabulary. Task 3's CLI wiring is the only real
  caller.

**Design** (read `dataflow/privacy-sink-policy.js` in full first — this
task mirrors its fail-closed axis-matching STYLE, not its literal
single-graph-state shape):

- A drift-policy rule matches a TRANSITION, not a state:
  `{trigger: 'new_flow' | 'changed_flow', dataClass?, sinkCategory?,
  fromPolicyVerdict?, toPolicyVerdict?, reason?}` — PRD's own worked
  examples (`new PHI → external`, `PII → AI`, `PCI → log`, `new
  unresolved recipient`, `protected → unknown/unprotected`) all reduce
  to this shape: `new_flow` rules match `dataClass`/`sinkCategory` on an
  `added.flows` entry (read the flow's own `dataElementIds`→
  `graphAfter.dataElements[].dataClasses` and its sink node's own
  `subtype`/`kind` to resolve `sinkCategory`); `changed_flow` rules
  match `fromPolicyVerdict`/`toPolicyVerdict` (or an equivalent
  from/to pair for `protectionSummary`, generalizing "protected →
  unknown/unprotected") on a `changed.flows` entry.
- Fail-closed, mirroring `privacy-sink-policy.js`'s own
  `_matchesEnvironment`/`_matchesDestination` precedent exactly: an
  unset rule field is unconstrained (matches anything); a SET field
  that the diff entry has no comparable value for does not match.
- A violation record names the real triggering flow (its id, data
  element name, sink), the rule that fired, and a human-readable
  `reason` string — never a bare boolean.
- `loadDriftPolicies(policyFilePath)` — reads a JSON file (never throws;
  a missing file is "no policies configured," matching
  `loadPrivacySinkPolicy`'s own precedent), validates each rule's shape
  loosely (never crashes on a malformed entry — skip and warn, matching
  `loadPrivacySinkPolicy`'s own malformed-JSON degradation).

**Tests to write:**
- A real `new PHI → external` policy (mirroring AC-27's own worked
  example) fires a violation against a real `GraphDiff` produced by
  Task 1's own `computeGraphDiff` on the PHI-to-AI-provider fixture.
- A `protected → unknown/unprotected` policy fires on a real
  `changed.flows` entry with that exact transition, and does NOT fire
  on the reverse (an upgrade, `unprotected → protected`).
- An unset rule field matches anything; a set field with no comparable
  diff-entry value does not match (fail-closed, mirrored from
  `privacy-sink-policy.test.js`'s own equivalent cases if that file
  exists — check first).
- `loadDriftPolicies` degrades honestly on a missing file and a
  malformed one, matching `loadPrivacySinkPolicy`'s own tested behavior.

- [ ] Write the failing tests.
- [ ] Run to verify failure.
- [ ] Implement `drift-policy.js` per the design above.
- [ ] Run to verify pass.
- [ ] Wire into its correct test scope, run the full scope, commit.

---

### Task 3: CLI wiring (`dataflow diff`)

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/dataflow.md`
- Test: `scanner/test/cli/dataflow-diff.test.js`

**Design:**
- A NEW subcommand, `dataflow diff [--against <commit>] [--drift-policy
  <path>] --output <file> [--format json|markdown]` — this is a
  two-snapshot operation, structurally unlike `dataflow export`'s
  existing one-graph-in shape, so it does not belong inside
  `cmdDataflowExport`. Read `cmdDataflowExport`'s own overall structure
  in `bin/agentic-security.js` first (argument parsing, exit-code
  contract, error-message style) and mirror its conventions in a new
  `cmdDataflowDiff` function. The real dispatch site (confirmed by
  reading it directly, current as of this plan — re-read before editing,
  it may have drifted): `main()`'s own `switch (cmd)` has a
  `case 'dataflow': { const sub = args._[1]; if (sub === 'export') {
  process.exit(await cmdDataflowExport(args)); } process.stderr.write(...
  only "export" is supported...); process.exit(2); }` block. Add
  `else if (sub === 'diff') { process.exit(await cmdDataflowDiff(args));
  }` before the fallback error, and update that error message's own
  "only \"export\" is supported" text to name both subcommands now that
  there are two — leaving it stale would print a false claim on every
  future unknown-subcommand error.
- Without `--against`, default to `graph-snapshot.js`'s own
  `mostRecentPriorSnapshot(scanRoot, currentCommit)` — the "compare
  against the last scan" default UX `sbom-diff.js` already established
  for its own diff feature.
- `--format markdown` renders a real, human-readable change report
  (added/removed/changed sections, drift-policy violations prominently
  flagged) — mirror `export-briefing.js`'s own Markdown-escaping
  discipline (`_mdInline`/`_mdCell`/`_mdCode`) for any graph-derived or
  operator-config-derived value interpolated into the report; `--format
  json` emits the raw `GraphDiff` record (plus drift-policy violations)
  as JSON.
- A clean, documented exit-code contract, matching `dataflow export`'s
  own precedent: 0 success, 2 for a usage/argument error (no snapshot to
  compare against, an incomparable pair, a malformed `--drift-policy`
  file), 1 if `--drift-policy` violations were found and the caller
  asked for a gating exit code (a new `--fail-on-drift` flag, off by
  default — mirroring `dataflow export`'s own conservative,
  opt-in-to-stricter-behavior precedent).
- Update `commands/dataflow.md`: a new `diff` section (this is a
  genuinely new subcommand, not a new `--format` value of the existing
  `export` — document it as its own thing, with its own options table
  and examples, not shoehorned into the existing format table).

**Tests to write** (mirror `test/cli/lineage-snapshot-persist.test.js`'s
own real-git-fixture, real-subprocess pattern):
- Two real scans at two real commits on a real git fixture, then
  `dataflow diff` against the prior commit produces a real, non-empty
  report naming the real added flow.
- No prior snapshot to compare against → a clear exit-2 error, not a
  crash.
- `--drift-policy` with a real "new PHI → external" rule and a real
  triggering diff → the violation appears in the output;
  `--fail-on-drift` makes that a non-zero exit, its absence does not.
- `--format json` output round-trips through `JSON.parse` and matches
  `computeGraphDiff`'s own real shape.

- [ ] Write the failing CLI tests.
- [ ] Run to verify failure.
- [ ] Wire the CLI + update `commands/dataflow.md`.
- [ ] Run to verify pass.
- [ ] `npm run build`, confirm bundle sha256 regenerates, commit.

## Self-review notes (per the writing-plans skill)

- **Spec coverage:** AC-27's own worked example (new PHI→AI, with
  recipient/protection/governance state, commit/date when available,
  contributing evidence, drift-policy result, analyzer/config/coverage
  separation, no contributor score) is covered end-to-end across the 3
  tasks: Task 1 produces the added-flow entry + honest cause
  classification; Task 2's drift-policy DSL produces the
  `PHI → AI`-shaped violation; Task 3 wires it into a real CLI report.
  No contributor/blame scoring is ever computed anywhere in this plan —
  `firstSeen`/`lastSeen` name only the snapshot's own commit/timestamp,
  never an author or a ranking.
- **Placeholder scan:** Task 1 has the most novel logic (change-cause
  classification) and gets a full design spec with exact field/function
  citations, not vague prose. Tasks 2/3 cite exact real files to mirror.
  No TBDs.
- **Type consistency:** `computeGraphDiff`'s own `added`/`removed`/
  `changed` shape (Task 1) is exactly what Task 2's `evaluateDriftPolicies`
  and Task 3's CLI/Markdown renderer both consume — confirmed consistent
  across all three tasks' own interface sections above.
- **Out-of-scope reminder:** no interactive Time Machine UI (timeline
  slider, visual diff) — CLI/JSON/Markdown only, matching the scoping
  doc's own deferral. Full historical (all-snapshots) first-introduced
  provenance and real analyzer/config-version detection beyond
  `schemaVersion` are NOT in this plan either — both real, disclosed,
  separately-scoped future work per the scoping doc.
