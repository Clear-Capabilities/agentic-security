# agentic-security — capability roadmap

**Status:** active
**Owner:** Ross Young / Clear Capabilities Inc.
**Created:** 2026-07-27
**Baseline:** v0.129.0

---

## Strategic thesis

The competitive field for agentic security review is converging on one shape:
a pipeline of model calls that finds, triages, and patches. That shape has a
structural weakness its authors state plainly in their own documentation —
non-deterministic output, findings that are candidates rather than conclusions,
and **no published precision or recall**. A harness whose core is a model call
cannot prove it did not regress.

This project's core is not a model call. It is a deterministic multi-layer
engine — 110+ SAST modules, a nine-language IR, an IFDS/k-CFA taint engine —
behind three gates that already run on every change:

- a **200-entry regression corpus**, baseline-gated, each entry proven to fail
  without its fix;
- a **per-file precision gate** over this repository's own findings;
- **held-out calibration** with byte-identical deterministic output.

That is the moat. This roadmap does not chase orchestration parity. It doubles
down on *provable, measurable, reproducible* security — claims a model-call
pipeline structurally cannot make — while closing the two places where the
field is genuinely ahead: **runtime proof of exploitability** and
**threat-model-scoped analysis**.

### The one-sentence goal

Be the only harness that can state its false-positive rate, prove a finding by
execution, and guarantee the same answer twice.

---

## Tier 0 — Differentiating

These are the items no competing harness can currently match. They compound:
each one makes the next more valuable.

### R1. Execution sandbox

**Problem.** The scanner has path confinement and a destructive-command guard,
but **no execution isolation whatsoever**. Nothing may safely run target code
today. This is a hard prerequisite for R2 — do not build R2 without it.

**Deliverable.** A confined execution facility for running untrusted target
code and candidate exploits: filesystem isolation, no network egress by
default, CPU/memory/wall-clock limits, and a hard refusal to execute outside
the sandbox unless explicitly overridden.

**Constraints.** Degrade gracefully and explicitly when kernel primitives are
unavailable (macOS dev machines, restricted CI). Never silently fall back to
unsandboxed execution — an unavailable sandbox must *disable* execution
features, not bypass them.

**Done when.** Escape attempts (filesystem write outside root, outbound
connection, fork bomb, wall-clock overrun) are each proven blocked by an
executing test, and the both-direction gate holds: the guard refuses the bad
case and permits the good one.

**Status: landed and verified on both platforms.** `scanner/src/sandbox/` ships a single
entry point (`runConfined`/`sandboxAvailable`) dispatching to one of three
backends. On the macOS development host, the userspace backend is **verified
by execution**: writes outside the sandbox root are blocked (no file
created), outbound network is blocked, and benign in-root work still
succeeds — proven in both directions. A wall-clock overrun stops the process
this module spawned but **does not kill the process tree** on this platform: a
backgrounded grandchild demonstrably outlives the `'timeout'` result (survivors
stay confined, but they keep running). A confinement denial is reported
distinctly from an ordinary non-zero exit (`status:'blocked'` + `denied`, vs
`'nonzero'`) — but the denial signal is read from the confined process's
stderr, so `denied:false` means "no denial observed", never "no denial
occurred". The parent environment is not forwarded to confined code; a minimal
env is constructed instead. Fork-storm
containment on this platform is **weak**: the process cap is a per-uid,
system-wide limit, not per-tree, so it only bounds a storm to
"ambient + margin" rather than to a small absolute number — documented, not
overstated, in `scanner/src/sandbox/CLAUDE.md`. Address-space capping is
**not enforceable** on the macOS family and is reported in `unsupported`
rather than emitted as a silent no-op.

The kernel-namespace backend (Linux family) is **implemented and verified by
execution in CI**. Two things changed. First, it no longer confines network egress only: it now
builds write confinement inside its mount namespace — every mount point
present at setup is rebound **read-only**, only the sandbox root is rebound
read-write, the whole capability set is dropped before the caller's command
runs (so the payload cannot rebind the tree writable again), and each run
*proves* the confinement by attempting an out-of-root canary write from inside
and refusing to execute anything if it succeeds. `pivot_root` was considered
and rejected: it would have to materialise a system tree inside the caller's
sandbox root, would change `$ROOT` semantics between backends, and would turn
an out-of-root write into an `ENOENT` that cannot be reported as a
confinement denial. Second, CI can now try to exercise it: the `sandbox-linux`
job relaxes the **host** restriction on unprivileged user-namespace creation
(no test or confinement flag is relaxed) and runs the escape suite unchanged,
with `scripts/sandbox-linux-verify.mjs` printing the selected backend and
`RAN`/`SKIPPED` per test and failing the job if the namespace suite skipped.

**That CI log now exists.** On the `sandbox-linux` job the functional probe
selected the `namespace` backend and the escape suite executed and passed —
Ubuntu 24.04, kernel `6.17.0-1020-azure`, 41 assertions, 0 failures, with the
userspace suite correctly reporting `SKIP` (not pass) on that host. All eight
escape cases hold in both directions there: in-root write succeeds, out-of-root
write is blocked and creates no file, a denied write is never reported as a
clean run, the payload cannot rebind the tree writable again, an ordinary
non-zero exit stays `nonzero`, the parent environment is not forwarded,
outbound network is blocked, and a wall-clock overrun stops the direct child.
The wall-clock caveat is unchanged from macOS — *direct child*, not process
tree. Fail-closed holds throughout: with no confinement primitive detected — or
with the write confinement unprovable on the host — execution is refused, never
run unconfined. The `sandbox-linux` job fails if the suite ever skips rather
than runs, so this stays verified per push instead of being a one-time
observation. **R1 is done; R2 is unblocked on both backends.**

### R2. Execution-verified exploitability

**Problem.** Findings are asserted, never proven. `verify_fix` executes tests
only on the SCA-upgrade path — never for SAST. The PoC generator emits
regression tests that nothing runs.

**Deliverable.** A verification tier that promotes a finding from
`taint-proven` to `execution-proven` by running its PoC inside R1's sandbox and
observing the predicted effect. Findings carry the tier explicitly; unproven
findings are never reported as proven.

**The differentiator.** An execution-proven finding **auto-enrolls as a corpus
entry** (`pre:TP post:TN`, verified missed-before / found-after). No competing
harness has a permanent regression corpus to enroll into. Every proven exploit
then permanently defends against its own regression — a compounding asset.

**Done when.** A finding is demonstrated to move between tiers on real evidence,
a proven finding lands in the corpus, and the corpus gate fails if it regresses.

**Status: landed.** The tier vocabulary (`execution-proven`
/ `proof-failed` / `taint-proven` / `unproven`), the promotion path
(`proveFinding` runs a finding's PoC inside R1's sandbox and demotes anything
that did not actually run), and report surfacing (`proofTier` +
`proofEvidence` pass through `normalizeFindings` only when attached) are
implemented and covered by `scanner/test/execution-proof.test.js`. Verified on
this development host on the `userspace` backend: a PoC that produces the
predicted marker promotes to `execution-proven`; one that runs without
producing it lands at `proof-failed`; a finding with no PoC or an unsupported
PoC language stays at its static tier. The kernel-namespace backend now
implements write confinement too and its escape suite has **RUN and passed on a
Linux host in CI** (see R1), so `execution-proven` evidence recorded on either
backend now stands on an executed escape contract.
**The differentiator has now landed.** `posture/corpus-enroll.js` turns an
execution-proven finding into a corpus entry, and `posture/corpus-match.js`
holds the scoring that enrolment and the gate now *share* —
`bench/cve-replay/runner.mjs` imports it, so the two cannot drift apart and
enrolment cannot verify a candidate with a matcher the gate does not use.
Nothing is written that has not been scored: the entry is built in a temp
directory, `pre/` and `post/` are scanned, and it moves into the corpus only on
`pre:TP post:TN`. There is no force flag, and the scoring function is
unexported so no caller can score by one route and write by another.

Demonstrated end to end, not just in unit tests: a real command-injection
finding in a scanned project was proved by executing its PoC in the sandbox
(`userspace` backend, marker observed), its fix supplied the `post/` tree, and
`scripts/enroll-proven-finding.mjs` enrolled it as
`capability/proven-command-injection-c15fc43c4198ae40`. The full gate then
scored the committed entry `pre:TP post:TN` and the baseline moved 199 → 200.
The gate was proven in the other direction too: with the entry's `pre/`
neutered, `npm run bench:cve-replay:check` reports it REGRESSED and exits
non-zero. Enrolment lands in `capability/`, never `regression/` — an automated
writer must not decide what blocks everyone's build, and the existing
five-snapshot graduation policy still governs promotion.

**Known limit, stated rather than papered over:** the loop is not yet
automatic end to end. The scan pipeline does not attach a `poc` to findings or
promote proof tiers on its own, so `last-scan.json` never contains an
`execution-proven` finding by itself — PoCs come from the PoC generator, and
the enrolment script proves them at enrol time. Automatic PoC attachment during
a scan is the remaining piece.

### R3. Published precision/recall scorecard

**Problem.** The measurement machinery exists (proof corpus, self-scan gate,
held-out calibration) but produces no durable, published artifact.

**Deliverable.** A versioned per-release scorecard — precision, recall, F1,
broken down by language and by CWE — emitted from a single command, with the
methodology and corpus stated alongside it, and every number traceable to the
run that produced it.

**Done when.** The scorecard regenerates reproducibly, is committed per release,
and any figure in it can be re-derived from a named command.


**Status: landed.** `npm run scorecard` emits `docs/SCORECARD.md` + `docs/scorecard.json`. Every rate carries its numerator and denominator; F1 and any precision rate are deliberately omitted for want of a labelled real-world population, and the document says so in its body.

### R4. Determinism as a contract

**Problem.** Determinism is an implementation property today, not a guarantee
anyone can verify.

**Deliverable.** Verified reproducibility as a first-class feature: identical
output across runs and machines, plus a signed attestation binding a finding set
to the engine version and ruleset that produced it. This is what makes output
admissible for the compliance frameworks already mapped (NIST AI 600-1, OWASP
ASVS, OWASP LLM Top 10, EU AI Act) — a combination nothing else in the field has.

**Done when.** Two runs on different machines produce byte-identical output and
a verifiable attestation, proven by an executing test.


**Status: landed, both legs verified.** `posture/attestation.js` gives an order-independent signed digest; shuffled order and differing timestamps yield the same digest, a changed severity or removed finding do not.

The cross-machine criterion now has machinery behind it rather than a disclaimer. `scripts/attest-fixture.mjs` scans a committed, dependency-free fixture (`bench/determinism/fixture/`) and prints the run attestation digest; the `determinism-attest` CI job runs it on ubuntu-latest **and** macos-latest, and `determinism-compare` fails unless every digest matches. The comparison is between live runs of the same commit rather than against a checked-in reference digest — a committed digest would need refreshing on every commit that legitimately changes a finding, which turns a gate into a chore.

The comparator refuses every way it could go green without having compared anything: fewer than two attestations (a silently failed upload), two runs from the same platform (repeatability, not cross-machine), a zero-finding digest (every machine agrees on an empty set), mismatched canonicalisations, and unparseable input. All of those, plus the disagreement case, are asserted by executing tests in `test/determinism-cross-machine.test.js`, and the fixture's non-emptiness guard was fired deliberately to confirm it exits non-zero.

**The cross-machine criterion is now MET, and a CI log settles it.** On the ci run for `62f78e80`, `determinism-attest` ran on both runners and `determinism-compare` reported two platforms — `darwin-arm64` and `linux-x64`, both node v24.18.0 — producing the identical digest `d7150a9ac88a6897fec2f1f058b86ef43e94210f508ec018261a157eb1ade77a` over 11 findings. Two machines, two operating systems, two architectures, same commit, same answer.

The attestation's own `doesNotProve` text is deliberately unchanged, because it is still correct: a single attestation is one run on one machine no matter how green CI is. It now points at where the engine-level evidence lives instead of claiming the property is untested.

### R5. Measured fix loop

**Problem.** Remediation quality is unmeasured. `verify_fix` does not run the
test suite.

**Deliverable.** Instrument find → synthesize → verify → apply, and report the
real distribution of time-to-validated-fix. Require `verify_fix` to actually
execute the covering tests and the PoC before reporting success.

**Done when.** The metric is emitted from real runs, and `verify_fix` fails
when the tests or the PoC fail.

**Status: landed.** `verifyFix` runs the project test suite when detectable; undetectable is skipped, a failing suite fails verification, a timeout is a failure.

Both halves of the done-when now hold. **The PoC leg:** `verifyFix` accepts the finding's proof-of-concept and re-runs it against the *candidate patch* inside R1's sandbox, failing verification when the PoC still demonstrates the vulnerability. The direction is asymmetric on purpose — `execution-proven` after the patch is a hard FAIL, while a PoC that could not run is recorded `inconclusive` and left out of the verdict entirely, because treating "could not prove it" as "fixed" is the false confidence this leg exists to prevent. A re-scan alone only proves the *detector* stopped firing, which a cosmetic edit achieves. Both directions are asserted against the real sandbox in `test/fix-verify-tests.test.js` and ran (not skipped) on the development host.

**The distribution:** `posture/fix-metrics.js` records one append-only record per verification attempt with every stage timed, and reports the observed time-to-validated-fix — surfaced on `scan.fixMetrics` and as a one-line stderr summary. Three bucketing rules keep the headline honest and each is asserted: failed attempts never enter the validated distribution (they short-circuit, so blending them makes a worse pipeline look faster); "tests skipped" is bucketed apart from "tests passed"; and per-stage timings come from validated runs only. Percentiles are nearest-rank, so every figure reported is a duration some run actually took, and are flagged unreliable below n=10 rather than hidden or quoted as settled.

---

## Tier 1 — Genuine gaps

Places where the field is ahead. Highest precision-per-effort available.



### R6. Threat-model-first scoping

Build a persistent, living threat model *before* scanning; use it to scope
analysis and re-rank exploitability. This kills false positives by *relevance*
rather than by pattern — a different axis from every precision mechanism
currently in the engine. Highest-leverage precision win on this list.


**Status: landed.** `posture/relevance.js` re-ranks exploitability by entry-point reachability. Recall-preserving: nothing deleted, severity never touched, `unreachable` only on positive evidence. Corpus held at 199/199.

### R7. Adversarial verification with enforced separation

A pipeline stage that attempts to **disprove** each finding, run by an agent
that is structurally never the one that found it, with a multi-perspective panel
for contested findings. `security-triager` scores; it does not refute. This is
the same pattern that caught a real dead-fix defect during v0.129.0 development
— an independent reviewer *executing* the claim rather than restating it.


**Status: landed.** `posture/verification-separation.js` refuses a verifier that is the producer, and records per-lens verdicts with a consensus. A refuted finding is neither deleted nor severity-touched.

### R8. Sandboxed resumability and checkpointing

Checkpoint long scans so they resume rather than restart, degrade gracefully
when model quota is exhausted, and fan work across workers. Currently caps
usable repository size.


**Status: landed.** `posture/scan-checkpoint.js`, opt-in via `AGENTIC_SECURITY_RESUME=1`, append-and-fsync with conservative run-key invalidation. Verified by hard-killing a scan mid-run and comparing the resumed result against an uninterrupted one across ten output channels.

### R9. Attack-surface-forward analysis

Start at attacker-reachable entry points and reason forward, complementing the
existing sink-driven taint. Composes directly with R6.


**Status: landed** alongside R6 in `posture/relevance.js`. Limits recorded honestly: reachability is file-granular, and an unresolved import graph yields `unknown` rather than a guess.

---

## Tier 2 — Worth having

- **R10. Secret redaction before any model call.** **Landed** — `llm-validator/redact.js`
  redacts at the single prompt-building choke point; values replaced, structure kept,
  ordinary code passes through byte-unchanged.
- **R11. Local/offline model path.** Fits the existing offline-degradation design.
- **R12. Hard cost ceiling.** A cost *advisor* exists; a cap does not.
- **R13. Multi-model routing with measured trust.** Route to a cheaper model only
  once its measured miss rate clears a statistical bound (Wilson upper bound),
  per decision class. Close in spirit to the existing calibration work.
- **R14. Vulnerability archaeology.** Mine git history for vulnerability patterns;
  currently only diffs are scored for material change.
- **R15. Binary / firmware / RTL reach.** Large scope expansion. **Deliberately
  deferred** — it is where the field is strongest and it is a large investment
  away from this project's differentiation.
- **R16. Specialist audit classes.** Constant-time/side-channel, zeroization,
  property-based testing, spec-to-code compliance. Narrow, high credibility.

---

## Sequencing

```
R1 (sandbox) ──▶ R2 (execution-verified) ──▶ R3 (scorecard)
                        │
                        └──▶ R5 (measured fix loop)

R6 (threat model) ──▶ R9 (attack-surface-forward)     [parallel track]
R7 (adversarial verification)                          [parallel track]
```

**R1 → R2 → R3 is the critical path.** It converts the corpus from a regression
net into a proof engine and produces the one claim no competitor can answer.
R6 and R7 run in parallel as the best precision-per-effort wins. Everything in
Tier 2 waits.

## Non-goals

- Orchestration parity for its own sake. Pipeline shape is not the moat.
- Any capability that cannot be gated. A feature that cannot be proven in both
  directions does not ship — see the verification discipline in `CLAUDE.md`.
- Binary and firmware analysis (R15) in this cycle.

## Invariants every item inherits

- No new runtime dependencies without explicit justification; offline degradation
  must stay graceful.
- Every claim traceable to a command run in the same session.
- Every gate proven in both directions before it counts.
- New capability lands with corpus and/or precision-gate coverage, or it does
  not land.
