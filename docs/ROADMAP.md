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

- a **199-entry regression corpus**, baseline-gated, each entry proven to fail
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

### R3. Published precision/recall scorecard

**Problem.** The measurement machinery exists (proof corpus, self-scan gate,
held-out calibration) but produces no durable, published artifact.

**Deliverable.** A versioned per-release scorecard — precision, recall, F1,
broken down by language and by CWE — emitted from a single command, with the
methodology and corpus stated alongside it, and every number traceable to the
run that produced it.

**Done when.** The scorecard regenerates reproducibly, is committed per release,
and any figure in it can be re-derived from a named command.

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

### R5. Measured fix loop

**Problem.** Remediation quality is unmeasured. `verify_fix` does not run the
test suite.

**Deliverable.** Instrument find → synthesize → verify → apply, and report the
real distribution of time-to-validated-fix. Require `verify_fix` to actually
execute the covering tests and the PoC before reporting success.

**Done when.** The metric is emitted from real runs, and `verify_fix` fails
when the tests or the PoC fail.

---

## Tier 1 — Genuine gaps

Places where the field is ahead. Highest precision-per-effort available.

### R6. Threat-model-first scoping

Build a persistent, living threat model *before* scanning; use it to scope
analysis and re-rank exploitability. This kills false positives by *relevance*
rather than by pattern — a different axis from every precision mechanism
currently in the engine. Highest-leverage precision win on this list.

### R7. Adversarial verification with enforced separation

A pipeline stage that attempts to **disprove** each finding, run by an agent
that is structurally never the one that found it, with a multi-perspective panel
for contested findings. `security-triager` scores; it does not refute. This is
the same pattern that caught a real dead-fix defect during v0.129.0 development
— an independent reviewer *executing* the claim rather than restating it.

### R8. Sandboxed resumability and checkpointing

Checkpoint long scans so they resume rather than restart, degrade gracefully
when model quota is exhausted, and fan work across workers. Currently caps
usable repository size.

### R9. Attack-surface-forward analysis

Start at attacker-reachable entry points and reason forward, complementing the
existing sink-driven taint. Composes directly with R6.

---

## Tier 2 — Worth having

- **R10. Secret redaction before any model call.** Cheap; removes an obvious
  enterprise objection given the existing no-runtime-cloud-calls posture.
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
