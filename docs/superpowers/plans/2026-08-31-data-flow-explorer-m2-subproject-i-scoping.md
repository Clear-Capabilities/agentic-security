# Milestone 2, Sub-project I scoping: exit-gate closure

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row I: *"Runs AC-03 through AC-09 and AC-12, plus Sub-project H's
gate, against the real JS/TS corpus; verification and cleanup, not new
engine capability — the milestone's actual 'done' checkpoint."*

**This document CORRECTS that framing**, the same way this session's
prior sub-project scoping passes corrected theirs: direct verification
found ONE of the eight ACs (AC-12) is genuinely NOT satisfied by any
shipped code today, and it fails against an EXPLICIT PRD requirement
(line 909), not merely against the AC's own prose — closing it is real,
small, additive engine capability, not verification. A second AC (AC-08)
holds structurally but has no dedicated proof anywhere in the tree.

## Per-AC verification, each grounded in a direct read of real code/tests (session HEAD `fde5f2ce`)

- **AC-03 (cleartext external call) — CLOSED.** `resolveTransitProtectionForSite`
  (`transit-protection.js`) returns `{verdict: 'unprotected', evidenceGrade:
  'code'}` for a literal `http://` destination. Proven by
  `test/lineage/transit-protection.test.js`'s `B2/1` and by
  `bench/protection-verdict/runner.mjs`'s `adversarial-transit-http-scheme`
  (Sub-project H1).
- **AC-04 (HTTPS + verification disabled) — CLOSED.** The same function's
  nearby-finding override, proven by `B2/2` and by
  `adversarial-transit-tls-verify-disabled`.
- **AC-05 (dynamic destination — "Unresolved outbound destination" node)
  — CLOSED.** `resolveSiteDecision` (`coverage.js`) produces `kind:
  'unresolved'` for a real `fetch(url)` call site (confirmed: `test/
  lineage/coverage.test.js`'s `C1/3d`). Proven end-to-end on real code —
  not just the unit-level resolver — by `test/lineage/graph-builder.test.js`
  (line ~259, filtering `graph.nodes` for `kind === 'unresolved'`) and by
  `test/lineage/flagship-fixture-semantics.test.js` (line ~58, the
  committed reference graph's own sink node).
- **AC-06 (database encryption unknown — "at-rest protection is
  `unknown`, not protected") — CLOSED, no code change needed.** Confirmed
  directly: nothing anywhere in `src/lineage/` ever emits `verdict:
  'unknown'` for `atRest` (grep: zero hits) — the honest default when
  nothing evaluates a dimension is always `'not_assessed'`
  (`emptyProtection()`). This LOOKS like a gap against AC-06's own
  literal string, but the PRD itself resolves it: line 1495 states *"If
  protection evidence is missing, conflicting, path-incomplete, or
  outside the analyzer's supported semantics, the verdict must be
  `unknown` OR `not_assessed`"* (either, explicitly) and line 592's own
  UI-legend table groups them under one visual treatment ("Unknown or
  not assessed"). An unencrypted PHI write to a store, with no C2/C3
  storage-config evidence available, is exactly the "missing evidence"
  case line 1495 describes — `not_assessed` is PRD-sanctioned, not an
  approximation of the real answer. **No dedicated AC-06-named test
  exists** — a small, worthwhile addition (see I2 below), but not a
  code-correctness gap.
- **AC-07 (AI + regulated data intersection) — CLOSED.** Milestone 1's
  own exit-gate table already proves the core scenario
  (`bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/`,
  `patient_record` PHI reaching `anthropic.messages.create()`). Re-verified
  this session: AC-07's own text requires the model-provider path to
  "appear with... network protection" as a shown FIELD, not necessarily a
  `protected` verdict — `edge.protection.transit` is unconditionally
  present on every edge (`emptyProtection()`'s own contract), so this
  clause is satisfied by construction. The fixture's own real code
  (`anthropic.messages.create({model, messages: [...]})`) has no literal
  URL argument at all — an SDK call keyed on a receiver object, not a
  URL string — so `resolveTransitProtectionForSite` honestly returns
  `undefined` (stays `not_assessed`) for this specific fixture; disclosed
  as a real, non-blocking limitation (same PRD line 1495 sanction as
  AC-06), not a fabricated claim.
- **AC-08 (AI presence without sensitive flow) — HOLDS BY CONSTRUCTION,
  NO DEDICATED PROOF.** No mechanism anywhere mints a `flow`/data-class
  claim except from a REAL matched source identity reaching a sink via
  the taint/path engine — there is no code path that could fabricate a
  PII/PHI/PCI claim for an unreached AI sink. An AI-provider sink node
  with nothing connecting to it stays visible with a `coverageReason`,
  the identical mechanism AC-11's own disconnected-sink fixture
  (`js-api-to-log-disconnected/`) already proves for a non-AI sink.
  **Confirmed by direct search: no fixture, test, or corpus entry names
  AC-08 anywhere in the tree.** A real, small, closeable gap — the
  PROPERTY already holds, but nothing proves it for the AI-specific case
  (see I2 below).
- **AC-09 (policy-permitted flow) — CLOSED.** Sub-project G1, this
  session, `test/lineage/policy-verdict.test.js`'s 12 cases including the
  AC-09 worked example verbatim.
- **AC-12 (alternate path control gap) — NOT CLOSED. Real code gap,
  confirmed by direct read.** `flow.protectionSummary` is set to the
  LITERAL STRING `'not_assessed'`, unconditionally, at every flow's mint
  site (`graph-builder.js`, confirmed: `grep -n "protectionSummary"
  src/lineage/*.js` returns exactly two hits outside `validate.js` — the
  hardcoded literal and nothing else). **This directly violates PRD line
  909**: *"The end-to-end summary may be `protected`, `unprotected`,
  `mixed`, `unknown`, or `not_assessed`. It must be derived from the
  individual edge verdicts, never stored as an unsupported independent
  claim."* Today it IS stored as an unsupported independent claim — the
  exact failure mode that sentence forbids. `protection.js`'s
  `aggregateVerdicts(verdicts)` (confirmed: exported, tested, implements
  PRD §8.4's risk-precedence reduction — `unprotected` > `mixed` >
  `unknown` > `protected` > `not_applicable` > `not_assessed`, matching
  line 674's own precedence table exactly) is **never called anywhere in
  the graph-builder pipeline** — confirmed by grepping every real call
  site outside `protection.js`/its own tests: every other reference is a
  comment citing it as a "future precedent," never an actual invocation.
  Sub-project D2's own already-shipped `appliesToAllPaths` computation
  proves the ADJACENT property (a transform never earns cross-path
  control credit falsely) but does not itself touch
  `protectionSummary` — a different field, computed by a different
  mechanism, confirmed by reading D2's own code: it mutates
  `transformsById`, never `flowsById`.

## The resolved scope for Sub-project I

**I1 (small, real code — this is the one genuine engine-capability gap):
compute `flow.protectionSummary` for real, via `aggregateVerdicts()`.**
Each flow has exactly one edge (`flow.edgeIds: [edgeIdStr]`, confirmed —
a `flow` is minted per DISTINCT PATH via `groupsByFlowKey`'s own key,
never per coarse source/sink/dataElement group; the coarser
`(src.id, snk.id, de.id)` grouping D2 uses for `appliesToAllPaths` is a
SEPARATE, later aggregation over sibling flows, not this field's
concern). `flow.protectionSummary` should read
`aggregateVerdicts([edge.protection.transit.verdict,
edge.protection.atRest.verdict, edge.protection.handling.verdict])` —
the three dimensions of THAT flow's own edge, matching line 909's
"derived from the individual edge verdicts" literally (an edge carries
exactly these three dimension verdicts; there is no other "edge verdict"
this could mean). Since `edge.protection.handling` is never written by
any code (Sub-project H's own scoping finding, unchanged), it stays
`emptyProtection()`'s default `not_assessed` for every real edge today —
so in practice this reduces to aggregating `transit`/`atRest` only,
honestly, with `handling`'s own `not_assessed` never distorting the
result (per `aggregateVerdicts`'s own precedence, `not_assessed` never
wins over a real verdict from another dimension). **This closes AC-12's
real testable property**: write a fixture proving TWO sibling flows to
the same store — one with `atRest: protected` (a real encrypt-then-store
path) and one without — and confirm the unprotected sibling's own
`protectionSummary` is honestly `not_assessed` (never `protected`,
matching AC-06's own PRD-sanctioned equivalence), while the protected
sibling's own summary genuinely reads `protected`. This is the direct,
minimal, PRD-line-909-driven fix — it does NOT attempt to invent a
cross-branch "mixed" aggregate field (no such field exists in the schema
beyond per-flow `protectionSummary`; a coarse-group-level aggregate, if
ever needed, is undecided, out-of-scope future work, not silently
assumed here).
**Do NOT touch**: `edge.protection.handling` (still Sub-project H's own
deferred territory — this increment only READS it, never writes it),
`appliesToAllPaths` (D2's own, unrelated field), any language beyond
JS/TS.

**I2 (small, test-only — closes the two disclosed-but-unproven gaps):**
a dedicated AC-06 fixture (a PHI field written to an unencrypted store
sink, confirming `edge.protection.atRest` and the new
`flow.protectionSummary` both honestly read `not_assessed`, never
`protected`) and a dedicated AC-08 fixture (an AI-provider sink node with
no connecting flow, mirroring `js-api-to-log-disconnected/`'s own
pattern, confirming the node stays visible with a `coverageReason` and
no PII/PHI/PCI claim is ever fabricated for it). Both are proof-only —
no production code changes.

**I3 (verification + documentation — the actual "exit-gate closure"
the parent doc's own framing described, now genuinely just verification
once I1/I2 land):** run the full `test:lineage` suite and
`bench:protection-verdict:check` (Sub-project H's own gate) fresh, and
write the Milestone 2 exit-gate status table into
`scanner/src/lineage/CLAUDE.md`, mirroring the Milestone 1 exit-gate
table's own precedent exactly (one row per AC-03 through AC-09 plus
AC-12, each with its real proof location) — the same honest-disclosure
shape that table already established, including a "what this does NOT
mean" paragraph naming what remains open (C2/C3's at-rest evidence
sources, F2/F3's schema-derived/declared-service edges, H's own
`handling` dimension, Sub-project A's remaining destination-resolution
increments) so the exit-gate declaration is never mistaken for "Milestone
2 in full" the way the Milestone 1 table's own precedent was careful to
disclaim.

## What this does NOT do

Invent a cross-branch/coarse-group-level protection aggregate beyond
per-flow `protectionSummary` (undecided, not attempted). Close C2/C3
(storage/IaC and database-column at-rest detection — still genuinely
unbuilt, their own future scoping passes). Close F2/F3 (schema-derived
edge bridging, declared-service-graph ingestion — same). Close H's own
`handling` dimension (the scoping doc's (a)/(b) fork, still unresolved).
Attempt AC-01, AC-02, AC-10, AC-11, or AC-13 onward — none of those are
named in the Milestone 2 exit gate's own wording (PRD line 1809: "AC-03
through AC-09 and AC-12"); AC-01/AC-02/AC-11 are already Milestone 1
exit-gate items with their own proofs, and AC-10/AC-13+ are UI-facing,
Milestone 3+ territory. Any language beyond JS/TS.

## Recommended next step

Write I1's implementation plan (the `flow.protectionSummary` fix, the
genuinely load-bearing piece), then I2's test-only addition, then I3's
verification/documentation pass — likely all three as one increment,
given I1/I2 are both small and I3 depends on both landing first.
