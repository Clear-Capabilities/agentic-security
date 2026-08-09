# Competitive Position PRD — becoming the harness that can prove it works

**Status:** proposed · **Owner:** unassigned · **Created:** 2026-08-09
**Engine version at authoring:** 0.134.0

> **Naming rule.** Ten competing agentic security harnesses published by major
> technology companies, banks, and security vendors were surveyed to write this
> document. **None is named anywhere in it**, per the project rule that shipped
> artifacts never reference external tools. They are described by capability and
> architecture only. The survey notes live outside the repository.

---

## 1. What the field actually looks like

Ten harnesses were surveyed: reference implementations from two frontier-model
and static-analysis vendors, a bank, a card network, an edge-network provider, a
hyperscaler, a serverless platform, a security consultancy's skill collection,
and two independent research projects.

### 1.1 They have converged on one architecture

Nine of the ten implement the same pipeline, with different vocabulary:

```
recon / threat-model → partition attack surface → N parallel hunter agents
  → adversarial disprove → judge dedupe → exploitability report → patch → re-verify
```

That shape is now **table stakes, not differentiation**. As of this version, we
implement it too (`scanner/src/discovery/`), with one structural difference
covered in §2.

### 1.2 Two things are absent across the ENTIRE field

This is the strategic opening, and it is unusually wide.

**Nobody publishes accuracy numbers.** Of the ten, four state explicitly that
they have no benchmarks or published precision/recall. One ships a "minimal
synthetic corpus". The rest are silent. Several make qualitative claims
("learnings from partnering with security teams") in place of measurement.

**Nobody has deterministic program analysis underneath the agent.** All ten are
LLM-over-pattern-matching: regex candidate matchers, an off-the-shelf pattern
engine, or a tree-sitter index. The closest competitor ships interprocedural,
field-aware taint for three languages as an *optional* pre-seeding stage.

### 1.3 Capabilities the field has that we do not

| Capability | How widely held | Our status |
|---|---|---|
| Native memory-safety track (sanitizer + fuzzing + crash triage) | 3 of 10, and it is the ENTIRE product for 2 of them | **absent** |
| Multi-model backends with consensus voting | 3 of 10 | absent |
| Explicit cost governance (per-run budget ceiling) | 2 of 10 | absent |
| Cross-run project memory / additive multi-run waves | 2 of 10 | absent |
| Variant analysis from a confirmed finding | 1 of 10 | absent |
| Binary / compiled-artifact analysis | 1 of 10 | absent, off-ICP |
| Detection & response over logs | 1 of 10 | absent, adjacent product |

---

## 2. Where we already lead

Stated precisely, because the strategy depends on not rebuilding these.

- **Deterministic substrate.** IFDS/tabulation taint with points-to, SMT path
  feasibility, sanitizer proofs, k=2 summary caching, nine languages through a
  real IR. No surveyed harness has a comparable layer.
- **The hybrid loop.** Our discovery layer is the only one where the LLM
  *proposes* and a deterministic engine *confirms*: every candidate is routed
  back through the taint engine (`discovery/confirm.js`) before it can be
  reported, and the confirmation tier — not the model — sets severity. Everyone
  else's "verification" is another LLM.
- **Execution proof tiers.** `execution-proven` / `proof-failed` / `taint-proven`
  / `unproven`, with a marker-file protocol and a confined sandbox. Two backends
  carry an escape contract verified by executing tests.
- **Coverage honesty.** `posture/coverage-report.js` and the discovery coverage
  block report what was NOT analysed. No surveyed harness reports its blind
  spots.
- **Measured fix loop.** `posture/fix-metrics.js` reports observed
  time-to-validated-fix, separating failed attempts and no-test-suite runs.
- **A gated regression corpus.** 210 entries, baseline-enforced, with a
  provenance check that actively resists fitting the corpus to the detectors.

---

## 3. The strategic thesis

> The field is prompt architecture with thin deterministic substrates and **no
> evidence any of it works**. We are the inverse. Do not chase their surface
> area. Spend everything on being the only harness that can *prove* its claims,
> and close only those capability gaps that are genuinely load-bearing.

Three consequences:

1. **Evidence beats features.** A published, reproducible accuracy number is
   worth more than any five capabilities on the §1.3 list, because no competitor
   can answer it without years of work.
2. **Our corpus currently cannot support the claim.** Measured while writing
   this: **199 of 201** capability entries carry
   `source: synthetic-shape-of-disclosed-cve`; exactly **one** is
   `execution-proven`. `scripts/corpus-provenance-check.mjs` says it outright —
   *"Only an externally-sourced, third-party-labelled population can [make this
   an independent test set]."* Fixing that is D1.
3. **Only one capability gap is load-bearing.** The native memory-safety track
   is the entire product for two surveyed harnesses and the dominant mode of a
   third. Everything else on the §1.3 list is either off-ICP or cheap.

---

## 4. Prioritised feature list

### Differentiators — nobody else can copy these quickly

| ID | Feature | Why it cannot be copied |
|---|---|---|
| **D1** | Independent evaluation population | Requires a third-party-labelled corpus and the discipline to report it honestly. Everyone else has zero numbers; we would have the only defensible ones. |
| **D2** | Third-party-verifiable finding attestation | Requires the deterministic evidence chain we already have. A finding becomes portable, signed evidence rather than a report. |
| **D3** | Measured hybrid-loop uplift | Requires having both layers. We can publish "LLM alone vs. LLM + deterministic confirmation" on the same corpus — a number literally no one else can compute. |
| **D4** | Coverage ledger as a product surface | Requires being willing to publish your blind spots. Cultural, not technical, which is exactly why it will not be copied. |
| **D5** | Mean-Time-To-Adapt, measured | One surveyed harness names MTTA as the real bottleneck and then does not measure it. We already have the instrumentation. |

### Capability gaps — close these to remove objections

| ID | Feature | Priority |
|---|---|---|
| **C1** | Native memory-safety track (sanitizer + fuzz + crash triage) | P1 — largest gap; gates the enterprise segment |
| **C2** | Multi-model backends + consensus voting | P1 — removes a procurement objection |
| **C3** | Cost governance for the discovery layer | **P0 — safety-critical, see §5** |
| **C4** | Cross-run project memory and wave scanning | P1 |
| **C5** | Variant analysis from a confirmed finding | P1 — high yield, we have the IR for it |
| **C6** | Parallel discovery execution | P1 — depends on C3 |

### Explicitly not building

- **Binary / compiled-artifact analysis.** Impressive in one surveyed harness,
  far off a vibecoder ICP, and a multi-quarter effort.
- **Detection & response over logs.** An adjacent product, not a harness feature.
- **A second pattern-matching engine.** We would be adding the weakest layer of
  every competitor to the strongest substrate in the field.

---

## 5. Build plan

Five phases. Each ends with something shippable and measurable.

### Phase 0 — Make the discovery layer safe to run (2–3 days) · **P0**

The discovery layer shipped in this version with three deferred items that are
now blocking. **It must not be pointed at a large repository until C3 lands.**

**C3.1 — Hard budget ceiling.** `discovery/index.js` currently runs
(areas × lenses) hunter calls plus three refutation votes per surviving
candidate, sequentially, with no token or currency cap. A 2000-file repo at the
8-area default is 56 hunter calls before refutation.
- Add `opts.maxTokens` / `opts.maxCostUsd`, checked between stages, defaulting
  from `hooks/model-cost-advisor.js`.
- Exhaustion is a **coverage reason**, never a silent stop — reuse the
  `coverage.reasons` channel that already exists.

**C3.2 — Candidate cap.** Nothing bounds candidates today. Cap per run, report
the cap in coverage (the precedent is `prove-findings.js`'s `capped` field,
which is reported rather than applied silently).

**C6 — Parallelism. DEFERRED to Phase 3, deliberately.**

The precondition originally written here — ten clean full-suite runs under load
— was imported from `docs/RELEASE_PIPELINE_PRD.md` §R3d, where it governs *test*
concurrency. It does not transfer: hunter runs are independent async calls
through an injected callback, and the discovery tests never touch a real
endpoint. Applying it here would have been cargo-culted rigour.

The real objection is different and better. C3 enforces the ceiling at the
`llmInvoke` seam, checked immediately before each dispatch. With N calls in
flight, a run can overshoot by up to N−1 calls, because a call already dispatched
cannot be recalled — the same limitation `posture/prove-findings.js` documents
for its aggregate budget. That overshoot is bounded and acceptable, but it means
parallelism weakens the guarantee this phase exists to establish.

Phase 0's job is to make the layer **safe**, and stacking concurrency onto a
budget introduced in the same change is how a subtle interaction gets shipped
with confidence nobody has earned. Parallelism buys wall clock, not safety, so it
belongs with the other performance work in Phase 3 — where the budget will have
been exercised for a while and the overshoot bound can be stated from
observation rather than from reading the code.

**Exit:** a discovery run on a large repository completes under a declared
budget, and the report states what the budget stopped it reaching.

**Status: ✅ C3.1 and C3.2 implemented.** Verified on a six-file fixture: 168 LLM
calls unbounded → hard-stopped at any ceiling, and 168 → 72 with a candidate cap
of 10. Exhaustion and capping both surface as coverage reasons and on the CLI.

---

### Phase 1 — D1: the independent evaluation population (2–3 weeks) · **P0**

The single highest-leverage item in this document.

**D1.1 — Real fix-commit corpus.** Vulnerability-fixing commits mined from
public advisories, with CVE/CWE labels applied by a third party.
- New track under `bench/independent/`, **never merged into the regression
  corpus** — a regression net and an accuracy measurement are different
  instruments and must keep separate denominators.
- Fetch source at evaluation time rather than vendoring it; record commit SHAs so
  a run is reproducible.
- Runner reports precision, recall and F1 **per language and per CWE family**,
  each with its `{n, d}`, reusing `posture/accuracy-scorecard.js`'s
  `formatRate()` so a percentage can never appear without its denominator.

**D1.2 — Blind-labelled held-out repositories.** Real OSS repositories scanned at
a pinned commit, findings labelled by someone who did not write the detectors.
- Smaller, slower, higher signal. This is what makes precision defensible.
- Labels live outside the detector authors' reach; the corpus-provenance rules
  that already exist extend to cover it.

**D1.3 — Publish it.** Extend `docs/SCORECARD.md` with an independent-population
section. The existing scorecard's epistemic discipline — refusing to emit an F1
without a labelled population — becomes the *reason* this number is credible
when it finally appears.

**Exit:** `docs/SCORECARD.md` reports precision/recall/F1 over a
third-party-labelled population, and a third party can reproduce it with one
command.

---

### Phase 2 — D2 + D3: evidence nobody else can produce (2–3 weeks) · **P0/P1**

**D2 — Third-party-verifiable attestation.** `posture/attestation.js` today signs
with a per-install symmetric HMAC and says so: *tamper-evidence for the operator,
not third-party non-repudiation.*
- Add asymmetric signing (Ed25519 or Sigstore) over a **per-finding evidence
  bundle**: taint path, PoC, sandbox backend and tier, marker observed, patch,
  post-fix re-proof.
- Ship `agentic-security verify-attestation <bundle>` that a buyer or auditor
  runs **without our key**.
- This is the bridge to the compliance track: EU AI Act / ASVS attestation with
  cryptographic backing rather than assertion.

**D3 — Hybrid-loop uplift measurement.** Requires D1's population.
- Run the discovery layer with confirmation **disabled** and **enabled** over the
  same population; publish the delta.
- This is the number that proves the architecture, and no surveyed harness can
  compute it because none has both layers.

**Exit:** a signed evidence bundle verifiable by a stranger, and a published
uplift figure attributable to deterministic confirmation.

---

### Phase 3 — C5 + C4 + C2: capability parity (3–4 weeks) · **P1**

**C5 — Variant analysis.** Given a *confirmed* finding, sweep for structurally
similar instances. We can do this precisely via IR and callgraph rather than by
grep, which is how the one surveyed harness that has it works.
- Auto-synthesise a candidate rule from a confirmed true positive and replay it;
  feeds the existing rule-synthesis path in `/labs`.
- Reuse `posture/root-cause-sweep.js`, which already does per-pattern sweeping
  with exact accounting.

**C4 — Cross-run project memory.** A durable workspace that merges findings
across runs, diffs coverage, and drives the next wave.
- Extends `discovery/judge.js`'s dedupe from "previous scan" to "everything ever
  seen", and turns the coverage ledger into a *plan* for what to hunt next.

**C2 — Multi-model + consensus.** An adapter layer plus N-run temperature voting.
- `discovery/llm-invoke.js` is already the single seam every LLM call passes
  through — this is a contained change by construction.

**Exit:** a confirmed finding triggers a repo-wide variant sweep; a second
discovery run targets what the first did not reach; discovery runs against at
least two providers with consensus filtering.

---

### Phase 4 — C1: the native memory-safety track (6–10 weeks) · **P1, conditional**

The largest capability gap. It is the *entire* product for two surveyed harnesses
and the dominant mode of a third, so it gates the enterprise segment — and it is
almost orthogonal to a vibecoder ICP.

**Build only if the enterprise segment is being pursued.** `docs/POSITIONING.md`
says vibecoder-first; this phase is the main thing that changes if that call
changes.

- C1.1 — sanitizer-instrumented build target and harness.
- C1.2 — crash → deduplicated, triaged finding, reusing the proof-tier
  vocabulary (a crash is an execution proof).
- C1.3 — coverage-guided fuzzing loop with a wall-clock budget.
- C1.4 — root-cause attribution to source, feeding the existing pipeline.

**Exit:** a C/C++ target produces execution-proven memory-safety findings that
flow through the same annotation, attestation and corpus machinery as everything
else.

---

## 6. Sequencing and dependencies

```
Phase 0 (C3, C6) ──> Phase 1 (D1) ──> Phase 2 (D2, D3)
                          │                    │
                          └────────> Phase 3 (C5, C4, C2)
                                               │
                                     Phase 4 (C1, conditional)
```

- **Phase 0 first, always.** The discovery layer is unbudgeted; that is a live
  hazard, not a roadmap item.
- **D3 depends on D1.** There is no uplift number without a population to measure
  it over.
- **Phase 3 is parallelisable** across three people; nothing in it blocks
  anything else.
- **Phase 4 is a business decision**, not a technical sequencing one.

## 7. How we will know it worked

| Metric | Now | Target |
|---|---|---|
| Published precision/recall over a third-party-labelled population | none | reported, reproducible in one command |
| Corpus entries with independent provenance | 1 of 201 | ≥ 150 independent, tracked separately |
| Uplift attributable to deterministic confirmation | unmeasured | published with `{n, d}` |
| Findings verifiable by a third party without our key | 0 | all execution-proven findings |
| Discovery run on a 2000-file repo | unbounded cost | completes under a declared budget |
| Competitors publishing comparable accuracy numbers | 0 of 10 | still 0 |

## 8. Risks

| Risk | Mitigation |
|---|---|
| The independent population shows worse numbers than the synthetic corpus | **That is the point.** A number we can defend beats a number we cannot. Publish it, and publish the gap between the two populations — that gap is itself a finding no competitor can report. |
| D1 becomes a data-engineering project that never ships | Timebox D1.1; D1.2 can start at 20 repositories. A small honest population beats a large aspirational one. |
| Phase 4 consumes the roadmap | Gated on an explicit ICP decision, and listed last for that reason. |
| Discovery costs money at scale before C3 lands | Phase 0 is P0 and blocks everything else. |
| We build features the field has and still cannot prove anything | The prioritisation exists to prevent exactly this: D-items outrank C-items throughout. |

## 9. Open questions

1. **Which third-party label source for D1.1?** Decided direction: real
   fix-commit datasets plus blind-labelled held-out repositories. The specific
   dataset, its licence, and whether metadata can be vendored are unresolved.
2. **Sigstore or raw Ed25519 for D2?** Sigstore gives transparency-log
   verifiability at the cost of a network dependency, which cuts against the
   no-runtime-cloud-calls rule. Likely: Ed25519 by default, Sigstore opt-in.
3. **Does C1 belong in this product at all**, or in a separate one? Phase 4
   exists to force that question rather than answer it by drift.
4. **Should the uplift measurement (D3) be run per release** as a gate, or
   published per version as a figure? A gate risks tuning to it.
