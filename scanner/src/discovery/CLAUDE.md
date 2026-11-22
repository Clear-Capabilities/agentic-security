# scanner/src/discovery/

LLM-driven candidate discovery, gated by the deterministic engine.

User entry point: `agentic-security hunt --root <dir>` (`cmdHunt` in `bin/agentic-security.js`),
documented in `commands/scan.md`. Advisory only — it never gates a build and its
output does not enter `last-scan.json`.

`partition.js` splits the call graph into disjoint focus areas · `lenses.js`
holds the seven hunting lenses and the prompt builder · `hunter.js` runs one
bounded (area × lens) pass · `confirm.js` routes each candidate back through
the taint engine · `disprove.js` runs the three-angle majority-vote refutation
panel · `judge.js` shapes findings and dedupes against the prior scan ·
`llm-invoke.js` is the single injected LLM endpoint caller shared by
`hunter.js` and `disprove.js` (no other module may talk to an LLM directly) ·
`index.js` composes them.

## Detector-spec synthesis (`detector-spec-synthesis.js`, 0.195.22)

The `detector-spec-synthesis` capability (Labs): a detector-spec PROPOSAL drafted by a model from sample vulnerable files, for a human to review and never incorporated automatically. `scripts/synthesize-detector.mjs` is a thin front over `synthesizeDetectorSpec`. Order: the assurance feature gate (`detector-spec-synthesis`, off by default), then `evaluateEgress` BEFORE any sample is read (a denied call reads nothing), bounded reads (`SYNTHESIS_LIMITS`), a CSPRNG nonce, `guardedModelCall` (redaction, request cap, deadline, audit, output cap), `parseLastJsonObject` from the validator, then `validateDetectorSpec`, closed-world: identifiers only, never patterns, unknown fields refused, the nonce echoed; raw model text is never returned. `proposalOutputPath` confines the written proposal to the working directory and never under `scanner/src`. Pins: `test/discovery-spec-synthesis.test.js` (in `test:discovery`) and the synthesis cases of `test/egress-policy.test.js`.

## Rules

- **A hunter proposes; it never decides.** `confirm.js` sets a confirmation
  tier and never filters — an `unconfirmed` candidate still proceeds, because
  the taint engine models only a subset of the program and the absence of
  corroboration must never be laundered into a false-positive verdict.
  `disprove.js` is the only stage that removes a candidate: nothing reaches a
  report without surviving refutation there.
- **Every LLM call is an injected `llmInvoke`.** No module may import an SDK or
  hard-code an endpoint. Absence of an LLM degrades to an empty, well-formed
  result — it never throws and never blocks a scan.
- **Silence never refutes.** A probe that says nothing lowers a candidate to
  `unconfirmed`; only an argued majority refutes. A voter that errors is
  excluded from the denominator, not counted as agreement.
- **Severity comes from evidence, not from the model.** The confirmation tier
  sets it: taint-confirmed → high, sink-adjacent → medium, unconfirmed → low.
  This layer never emits `critical`.
- **Ids are content digests.** No clock, no randomness, anywhere in an id, a
  digest, or a sort key.
- **Bounded by default.** The pipeline is multiplicative — areas × lenses
  hunter calls, then three refutation votes per surviving candidate. Six
  files produced 168 LLM calls before C3. `makeBudget` in `index.js` wraps
  `llmInvoke` so every call is counted against a ceiling, and `maxCandidates`
  caps what reaches the panel. Never remove a bound without replacing it:
  an unbounded run's cost is a function of repository size.
- **An exhausted budget means INCOMPLETE, not clean.** Exhaustion arrives
  through the same degradation path as a dead endpoint and lands in
  `coverage.reasons`. A capped candidate is neither a finding nor cleared —
  it was not examined, and the report says so.
- **Coverage is reported.** Degraded runs and their reasons appear in every
  report. A half-failed pass must never read as a clean one.

## File selection and the budget seam

`selectHuntFiles(scanRoot)` in `index.js` is the one definition of what `hunt` reads (languages, ignored directories, the
2000-file cap); `cmdHunt` and the independent bench's `deep+discovery` configuration (`bench/independent/discovery.mjs`) both
call it, so a measurement cannot select differently from the CLI. `makeBudget` now bounds a model callback resolved from
configuration too: with no injected `llmInvoke`, `runDiscovery` passes `wrapInvoke` to `hunter.js` and `disprove.js`, which
apply it to what they resolve. Before, only an injected callback was counted, so `hunt` driven by configuration had no call or
wall-clock ceiling.

## When taint evidence overrules the panel (confirmation tiers)

`makeTaintProbe` sets `taint-confirmed` only when a taint finding in the same file, within two lines of the cited line, is the
same class of weakness the candidate claims (`confirm.js` `taintCorroborates`: injection, access control or cryptography,
grouped by CWE; a lens CWE and the taint finding's CWE must fall in the same class). A nearby flow of another class, or any
flow next to a claim no flow can establish (business logic CWE-840, feature abuse CWE-799, chained CWE-1173, wildcard
CWE-710), is `sink-adjacent`. Mechanical precedence (`disprove.js`: a refuting majority does not remove a `taint-confirmed`
candidate, it marks the refutation `overridden`) therefore applies only to a candidate the taint finding actually corroborates.
Why: a panel voted 3-0 against a wildcard "Potential Vulnerability in Anthropic API" candidate and it survived as confirmed with
high severity because a SQL-injection flow sat on the same line. The two-line window is kept because a hunter cites the start
of a statement whose sink may be a line or two below. Pinned in `test/discovery-corroboration.test.js`.

## Unvetted survivors

Silence never refutes (above), so a candidate whose panel cast no vote (a spent budget, a dead model) still reaches `fresh`. It
is marked: `judge.js` sets `unvetted: true` and `confidenceTier: 'very-low'` on any finding whose panel ran and was
`undecided`, after the stable id is computed (so the id does not change), and `hunt` prints `UNVETTED` beside it. A candidate
that never went to a panel (context intelligence's deterministic findings) has no missing verdict and is not marked. Severity
stays evidence-derived. The coverage block already says when the panel returned no votes at all.

## Nix partitioning

`partition.js` `partitionNixFiles` groups `.nix` files by their import structure (a configuration and the modules it imports are
one area), merged areas are capped, and hunter prompts for Haskell and Nix are redacted (split literals joined first) before they
leave the process. `hunt` includes `.hs`, `.lhs` and `.nix`. With no endpoint every run is degraded and says so.

## Invariant proposals (X-402)

`lenses.js` `invariantProposalFor(candidate)` maps a candidate from a state-oriented lens (`authz`, `business-logic`, and
`feature-abuse` when it is about tenants) to a PROPOSED invariant skeleton (`posture/invariants/lifecycle.js`): authored by the
model, with the candidate as source evidence and a high uncertainty. `runDiscovery` reports them as `invariantProposals` only when
`opts.invariantProposals = { config }` is passed AND the `invariant-scenarios` feature is enabled in that config; nothing else in the
report changes. A proposal is a hypothesis: it can be run as a scenario and its violations are reported as candidates, but only a
human reviewer's signed approval in the invariant ledger makes it a requirement, so a hunter never establishes its own ground truth.

## Advisory/gating separation (X-207)

Hunt output stays advisory in code, not just by convention. `memory.js` writes only through
`posture/verification/advisory-state.js` (`writeAdvisoryState`: one allowlisted file, atomic rename, never through a link), and
`report/index.js` excludes every hunt hypothesis from findings and exit codes. A hypothesis crosses into a finding only through
`promoteHypothesis` (`posture/verification/hypothesis-promotion.js`), reached from `runDiscovery` only with
`opts.promote = { policy, verify }`: a verifier receipt the promotion code verifies, an explicit policy, and an audit record. The
panel's votes, a confidence score and the confirmation tier are never inputs to that decision.

## Localization and classification of candidates (round 11)

`lenses.js` `buildHunterPromptWithMap` shows each file with its original line numbers (`  12| code`) and shares the character budget across the area's files by water-filling (`allotBudget`), so one large file can no longer spend the whole prompt; a file is cut at a line boundary and the prompt says which lines were shown. It returns `shown[file]` (range, truncation, the redacted line text, `lineMapped`: false when redaction changed the line count, in which case the file is shown unnumbered). `hunter.js` checks every citation against that map: a line outside the shown range (`line-not-shown`) or a file the prompt did not show (`file-not-shown`) is discarded; a `code` anchor must match the cited line's shown text (whitespace collapsed), may move the citation to the one matching line within two (recorded as `citedLine`), and is discarded when it matches none (`anchor-mismatch`) or several but not the cited one (`anchor-ambiguous`). A candidate without an anchor is kept and marked `anchored: false`. Counts are in the hunter result's `citation` block and the transcript. `classification.js` decides the CWE: the model may propose one; it is kept only when the lens can raise it (`LENS_CWES`; wildcard and chained may raise any listed one) and, for a weakness that is an operation on a value, the cited line or the two after it hold that operation (`OPERATION_EVIDENCE`): `cweBasis: 'operation-checked'`. Authorization and logic weaknesses have no syntactic operation and are kept as `model-proposed`. Anything else keeps the lens CWE (`cweBasis: 'lens'`, with `proposedCwe` and `cweRejected` when a proposal was refused). One CWE is recorded, never a list. Corroboration (`confirm.js`) is unchanged and now sees the specific CWE. Not measured end to end: no discovery run was made in this round (the local-model budget problem in the lessons document is unchanged). Tests: `test/discovery-citation.test.js`.

## Contract-aware mode and the evidence-grounded panel (contract-driven verification, 0.222.0)

`runDiscovery(ctx, { contractMode: { contract, approval, supplier? } })` is additive and off by default. With it, `context-supplier.js`
reads the context-intelligence store of `scanRoot` (a verified, hash-bound bundle per entry point) and: the hunter prompt gains a
VERIFIED CONTEXT block (the contract's invariant statements and the area's context packages, fenced as data, within a third of the
budget) and asks for `invariantId`, `attacker` and `prerequisites` as hypotheses; every candidate gets `candidate.qualification`
(`contracts/qualification.js`); the panel's challengers see the exact span and the recorded controls, and vote a cited blocker
(`refutation-vote/2`, `disprove.js` header). A blocker disqualifies only when its citations resolve against the bundle AND a
deterministic mechanism supports the control kind it names (the context layer's protection verdict on a reaching entry point, or the
taint layer's clean-site record); a model-only majority leaves the candidate `contested`, with the objections kept; a vote without
evidence (including every legacy Boolean vote under a supplier) never removes. The report gains `contract`, `candidatesAll` (every
candidate with its `history[]` of stage decisions) and `attrition`. Memory remembers a refutation only when it was grounded. Without
`contractMode` nothing above runs and the legacy panel behaves exactly as before.

Two defects fixed on the way: `coverage.citationsDiscarded` was always 0 (the per-run entries never carried the hunter's count), and
`--no-memory` cleared `scanRoot`, which also names the project whose egress policy and redaction apply; `opts.memory === false` now
turns memory off on its own.
