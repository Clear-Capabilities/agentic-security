# M5, What-If Architecture Simulator (FR-502), sub-project 3a: scoping

Per the M5 top-level scoping doc's own deliverable #3 row and the What-If
Simulator investigation fork's own findings: the hardest question for this
deliverable — can a hypothetical verdict be recomputed without re-running
the full taint/path pipeline — is answered yes for the two protection
dimensions that matter (`protection.js`'s `aggregateVerdicts`,
`privacy-sink-policy.js`'s `isSinkPermitted` are pure functions), which
points at a "clone the real graph, override already-materialized fields,
re-run only the cheap pure aggregators" design, mirroring an
already-shipped precedent in `graph-builder.js` itself.

This document re-grounds every claim directly against the current code
(after M5 deliverables #1/#2 shipped) before committing to a plan, and
corrects two real assumptions the M5 top-level doc's own summary of the
investigation fork got wrong or left unresolved.

## What already exists (confirmed by direct read this session)

- **`protection.js`'s `aggregateVerdicts(verdicts)` is a pure function** —
  no graph access, throws on an unrecognized verdict, `'not_assessed'`
  on empty input (confirmed by direct read, `protection.js:43-53`).
  `EVIDENCE_GRADES = ['runtime', 'code_and_config', 'code', 'config',
  'declared', 'manual', 'none']` (line 14) — **confirmed: no `'assumed'`
  value exists**, despite FR-502's own text requiring "assumed evidence"
  on every simulated control. A real, small gap needing a ruling before
  any implementation (see Design, below).
- **`privacy-sink-policy.js`'s `isSinkPermitted(classes, sinkKind,
  policy, ctx = {})` is a pure function** (confirmed signature) — no
  graph access, callable directly with a modified `ctx`/`policy` for a
  hypothetical "what if this destination/environment changed" scenario.
- **`handling-analyzer.js`'s `classifyHandling(path, callGraph)` is NOT
  similarly reusable** — it consumes a real reconstructed `path` object
  from `path-query.js`, which needs a real `PathStore` built from a real
  taint-analysis run. There is no cheap way to synthesize a fake `path`
  with an injected hypothetical transform hop.
- **The established "mutate an already-minted entity in a later pass"
  precedent, confirmed by direct code citation** (not just named in
  passing): `graph-builder.js`'s Sub-project D2 aggregation pass
  (`transformsById.get(tid).appliesToAllPaths = ...`) and Sub-project C1's
  at-rest gate (`edgesById.get(edgeIdStr)...edge.protection.atRest =
  {verdict: 'protected', evidenceGrade: 'code'}`) both mutate an
  already-built map entry in a pass that runs AFTER the entity was first
  minted — the exact shape a Scenario's own clone-and-override engine
  needs, applied to a cloned graph instead of the graph under
  construction.
- **`OBLIGATION_FACT_TYPES` (`obligation-mapping.js`) already includes
  `'hypothetical'`, unused by any current producer** (already confirmed
  cross-cutting this session — `RecipientProfile` was the first real
  cross-import of this vocabulary; a Scenario producing `'hypothetical'`
  facts on overridden `RecipientProfile` fields would be the second, and
  the first real PRODUCER of that specific value).
- **`RecipientProfile` (FR-506, shipped M4) is the closest extension-
  contract precedent to mirror** — the first record needing PER-FIELD
  evidence typing (`fieldEvidence`) rather than one record-level
  `factType`, because it mixes code-derived and operator-declared facts
  on one record. `Scenario` has the identical shape problem: some
  overridden fields are `'hypothetical'`, but the record's own metadata
  (author/time/expiration) is ordinary `declared` operator input.
- **`computeGraphDiff(snapshotBefore, snapshotAfter, opts = {})`
  (`graph-diff.js`, shipped M4 8b) is CONFIRMED THE WRONG TOOL for
  Scenario's own "simulated graph delta"** — a real correction to what
  the M5 top-level doc's own summary of the investigation fork left as
  "reuse as mechanism, not for its causeClassification." Reading the
  real function: it requires two full `GraphSnapshot`-shaped records
  (checked via `snapshotsComparable`, which throws on an incomparable
  pair), computes `added`/`removed` as an ID-SET diff across all four
  entity arrays, and — the load-bearing complication — runs real
  flow-REIDENTIFICATION pairing logic (`_flowCorrelationKey`-based
  1:1 pairing of removed/added flow ids sharing a correlation key,
  built specifically for "did the engine just re-key this flow, or did
  it really change") and change-cause classification
  (`'application_change'` / `'possible_coverage_regression'`) — both
  concepts that describe REAL rescans across REAL commits, and neither
  applies to a deliberate, declared hypothetical override. Forcing a
  Scenario's clone-vs-base comparison through this function risks the
  reidentification logic silently mispairing a genuinely-removed entity
  with an unrelated one, or reporting a hypothetical's own deliberate
  change as `'possible_coverage_regression'`. **Ruling: do not call
  `computeGraphDiff` at all.** Scenario needs its own small, dedicated
  comparison (see Design).
- **`buildGraphSnapshot(graph, scanRoot, opts = {})` (`graph-snapshot.js`)
  is a genuinely reusable, PURE function** (confirmed: "Zero disk I/O,
  validates and returns the snapshot, never writes it") — degrades
  gracefully with no real git repo (falls back to a content hash of the
  graph). Not needed by 3a's own design (since `computeGraphDiff` is
  ruled out), but named here since a future increment reusing
  `computeGraphDiff` properly (e.g. for FR-503-shaped "compare this
  scenario against a real historical snapshot") would need it.
- **A real, corrected scope finding on FR-502's own 7 hypothetical-change
  categories** — re-reading the PRD text directly against real graph
  fields: 4 of the 7 map cleanly onto pure field overrides (require
  TLS/cert on an edge → `edge.protection.transit`; field masking/
  encryption before a sink → `flow.handling` + cascading `atRest`/
  `protectionSummary` recompute; replace a provider or move region →
  `RecipientProfile` fields; change storage/retention/lawful-basis →
  `node.storeDetail`/`RecipientProfile` fields). **One category — "remove/
  block a destination, recipient, logger, model provider, or AI
  processing context" — is NOT a pure field override**: removing a node
  means the clone must also drop or invalidate every edge/flow that
  referenced it, real (if small) graph-surgery logic, not a one-line
  field write. The investigation fork's own table already flagged this
  correctly ("removing a NODE... means the clone must also drop every
  edge/flow that referenced it — real, non-trivial graph-surgery code");
  this document confirms it and folds it into 3a's own scope rather than
  treating it as a 6th field-override case. **One category — "insert a
  gateway/trust boundary/DLP control/queue/other declared architectural
  control"** — remains genuinely unprecedented (no code anywhere mints a
  node not derived from a real registry decision or call site) and stays
  deferred to a separate future 3b sub-project. **One category —
  "compare two alternative scenarios against the same baseline"** — is
  cheap once the base-vs-scenario comparison function exists (the same
  function, called scenario-vs-scenario instead of base-vs-scenario), so
  it is folded into 3a's own scope as a small CLI convenience, not
  deferred.

## Design

**The `Scenario` extension contract** (`scenario.js`, mirroring
`recipient-profile.js`'s own file shape — a pure schema/validator module,
zero imports, `RECIPIENT_FACT_FIELDS`-style enums where needed):
`{id, version, baseGraphId, baseGraphDigest, operations, assumptions,
author, createdAt, expiration, simulatedDelta, verificationRequirements}`
— per PRD §10.10's own `Scenario` row ("ID/version, base snapshot/digest,
hypothetical operations, assumptions, author/time/expiration, simulated
graph delta, changed verdicts/obligations, residual unknowns,
verification requirements"). `id` mirrors `recipientProfileId`'s own
object-argument pattern (`ids.js`'s `scenarioId({baseGraphId,
baseGraphDigest, ...}, discriminatorParts)`) — TIME is part of the
discriminator (two saved scenarios with identical operations at
different times are different records, never deduped, since the PRD's
own text requires `author`/`time` as real, always-present record fields).

**`SCENARIO_OPERATION_KINDS`** (a new, small, real enum — the 6
in-scope hypothetical-change kinds from FR-502's own text, EXCLUDING the
deferred synthetic-insertion case): `['require_transit_protection',
'apply_handling', 'remove_entity', 'replace_recipient_fact',
'change_storage_fact', 'change_governance_fact']` — each operation in a
Scenario's own `operations[]` array names its kind, its target canonical
id(s), and the override value(s), a small typed-union shape (full field
list specified in the implementation plan, not invented here).

**The clone-and-override engine** (`scenario-engine.js`): deep-clones the
real base graph, applies each declared operation in order:
- Field-override operations (`require_transit_protection`,
  `apply_handling`, `replace_recipient_fact`, `change_storage_fact`,
  `change_governance_fact`) directly overwrite the named field(s) on the
  cloned node/edge/flow/`RecipientProfile` record, tagging every
  overridden fact with evidence-grade/fact-type `'hypothetical'` (the
  ruling below) rather than whatever the base graph's real evidence
  said.
- `remove_entity` operations remove the named node from the clone AND
  cascade-remove every edge/flow that referenced it (`edge.from ===
  id || edge.to === id`, `flow.source === id || flow.sink === id`, plus
  any `RecipientProfile` whose `contributingGraphIds` becomes empty as a
  result) — small, real graph-surgery, confined to this one operation
  kind.
- After every operation applies, the SAME cheap pure aggregators the
  base graph-builder pipeline already uses are re-run over the affected
  entities only: `aggregateVerdicts` (for `flow.protectionSummary`, the
  same three-dimension reduction Sub-project I already established),
  `isSinkPermitted` (for `flow.policyVerdict`, reusing whatever
  `opts.privacySinkPolicy`/`ctx` the base graph was built with — a
  Scenario never invents a policy that didn't exist at build time,
  it only asks "does the ALREADY-CONFIGURED policy permit this now-
  different destination/environment").
- The clone NEVER mutates the base graph object (verified structurally
  — deep clone before any write, matching FR-502's own "scenarios never
  mutate the base graph" simulation rule).

**The comparison** (`_diffScenarioGraph(baseGraph, scenarioGraph)`, a new,
small, DEDICATED function — NOT `computeGraphDiff`, per the ruling
above): for every entity id present in `baseGraph`, compare its WATCHED
fields (`edge.protection.*`, `flow.handling`, `flow.policyVerdict`,
`flow.protectionSummary`, every `RecipientProfile` fact field,
`node.storeDetail.*`) against the scenario clone's own value; report
`{id, kind, changedFields: [{field, before, after}]}` for anything that
differs, plus a separate `removedEntityIds[]` list for anything
`remove_entity` cascaded away. No reidentification pairing, no
change-cause classification — every change here IS the declared
operation, never ambiguous, so none of `computeGraphDiff`'s own
real-rescan-shaped machinery is needed or appropriate.

**Real, disclosed ruling needed: `EVIDENCE_GRADES` has no `'assumed'`
value — ruling made, confirmed against a directly on-point precedent.**
Two real options: (a) add `'assumed'` to `protection.js`'s
`EVIDENCE_GRADES`; or (b) map FR-502's "assumed evidence" onto the
already-existing `'declared'` grade. **Recommendation, and the one this
plan implements: (a).** `'declared'` already has a real, different
meaning in this codebase (operator-supplied config, e.g.
`recipient-profiles.json`), and reusing it for "the simulator assumed
this" would blur two genuinely different provenance claims onto one
word. Checked against a directly on-point precedent before ruling:
`DESIGN_PATH_PROVENANCE.md` §16.2 (Q12) already asked "reuse
`protection.js`'s `EVIDENCE_GRADES`?" for `flow-grade.js`'s own new
concept and answered **no**, minting `FLOW_EVIDENCE_GRADES` instead —
but that refusal was because a flow's explicitness and a verdict's
evidence-provenance are different AXES entirely (confirmed:
`flow-grade.js`'s own file-header comment, `C6/0` asserts the two enums
share no value). `'assumed'` is not a new axis — it answers the exact
question `EVIDENCE_GRADES` already answers ("where did this protection
verdict's evidence come from"), just with one more real source ("the
simulator assumed it"). Extending the existing enum is the right call
here specifically because the precedent's own reasoning does not apply.
**The real edit surface, checked directly (corrects an earlier
overcount in this document's draft): only TWO places hold a literal
copy of the enum's value list** — `protection.js:14` (the source array)
and `dataflow-graph.schema.json:83` (the JSON-Schema `enum:` copy for
`edge.protection.<dim>.evidenceGrade`). `validate.js` imports and calls
`isValidProtectionDimension` from `protection.js` rather than
duplicating the list, so it needs no edit — it accepts `'assumed'`
automatically once the source array is updated. `export-briefing.js:593`
similarly only calls `EVIDENCE_GRADES.includes(...)`, no duplicate
array. Grep for the literal string `'code_and_config'` across
`src/lineage/*.js` and `*.json` confirms exactly these two files hold a
copy — the implementation plan's own task should re-run this same grep
after editing, as its own verification step, rather than trust this
count going stale.

## Global constraints for the implementation plan

- Scenarios never mutate the base graph, findings, evidence, source
  code, policy files, or observed runtime layer (FR-502's own simulation
  rule, verified structurally via deep-clone-before-write, not just
  asserted).
- A simulated/overridden field's evidence-grade or fact-type is always
  `'hypothetical'`/`'assumed'` (per the ruling above), never `'code'`,
  `'config'`, `'runtime'`, or `'declared'` — an overridden field must
  never look more certain than it is.
- No new npm dependency.
- No frontend/UI work — CLI/JSON/Markdown export only, matching
  `dataflow diff`'s own established shape (the closest sibling capability:
  a before/after comparison over a graph, already shipped, already
  CLI-wired) and every other M4/M5 decision-intelligence capability's own
  backend-first precedent.
- `computeGraphDiff` is NOT reused for Scenario's own delta — see the
  Design section's ruling. `_diffScenarioGraph` is new, small, and
  dedicated.
- Synthetic node/edge insertion ("insert a gateway/DLP/queue") is
  explicitly OUT of this sub-project's scope — deferred to a separate
  future 3b sub-project, its own dedicated investigation, given zero
  precedent exists anywhere in this codebase for minting a node not
  derived from a real registry decision or call site.
- A Scenario record is never usable as evidence in an obligation, impact,
  or remediation verification result (PRD §10.10's own cross-cutting
  rule) — this sub-project does not wire Scenario into
  `obligation-predicates.js`/any future impact-assessment module; that
  remains real, deferred, separately-scoped future work if ever
  attempted, and this sub-project's own tests should confirm no such
  wiring exists.

## Out of scope

- Synthetic node/edge insertion (deferred 3b).
- Frontend/UI side-by-side comparison rendering.
- Wiring Scenario into `decision-story.js`, `obligation-predicates.js`,
  or any future impact-assessment/remediation module.
- Re-running the taint/path pipeline under a hypothetical — the
  clone-and-override design deliberately never does this (see Design).
- A richer query/traversal-shaped operation language — the 6 in-scope
  operation kinds are field-override-or-remove only, not a general graph
  transformation DSL.
