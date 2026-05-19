# PRD — Next-Generation SAST

**Status:** v2 — post-Phase-1 retrospective revision  
**Author:** Ross Young <ross@clearcapabilities.com>  
**Date:** 2026-05-18 (v2 same-day revision after shipping v0.50.0 = Phase 1)  
**Scope:** What we'd build if we wanted to make every commercial SAST tool look like a `grep` wrapper.

## Changes from v1

This revision was written after delivering all five Phase-1 units (v0.50.0).
What changed:

- **Goals get a "Phase-1 status" column** — `measured`, `unmeasured-framework-only`, or `deferred-with-reason`. v1 promised numbers we cannot yet verify; v2 says exactly which.
- **Phase 2 is reprioritized.** v1 said Phase 2 was queues + IAM + multi-repo. After running the polyglot benchmark, the actual blocker is **Python SAST coverage** — the polyglot bench surfaces it as the single missing-detector class behind almost every cross-language miss. Python SAST is promoted; IAM and multi-repo are pushed to Phase 2.5.
- **Federated learning is demoted to "Phase 6+ research."** Customer privacy review + differential-privacy primitives + protocol design is more than one phase of work and not what closes the v1.0 gap.
- **New requirements emerged from implementation.** FR-CHAIN-FILTER (don't chain to incidental high-sev findings), FR-FAMILY-REGISTRY (cross-language chains get ugly auto-slug families like `cross-language-taint-client-call-post-us`), and FR-LIVE-HARNESS (a target harness that spins up the customer's app to run PoCs against).
- **Verifier sandbox findings** — the actually-useful path in P1.2 is the static sanitizer-absence proof, not the live PoC execution. We should LEAD with sanitizer-absence in v1 docs and treat live execution as Phase 3 polish.
- **Phasing is honest about what's measurable vs aspirational.** Sections labeled `[v2: unchanged]` carry forward; sections labeled `[v2: revised]` reflect what we now know.

---

## 0. Provocation

Today's SAST market is stuck. The leading commercial tools ship false-positive rates between 20% and 60% on real codebases, miss most cross-language flows entirely, can't reason about business logic, can't prove a single finding is exploitable, and offer no mechanism by which their accuracy improves with use. Customers cope by suppressing 70-90% of findings unread, which means the tool is providing about 10-30% of its claimed value. This PRD describes the tool that finally delivers on the original SAST promise: **find real exploitable bugs, prove they are real, and prove they are not noise.**

Three commitments differentiate the next-gen tool:

1. **Every emitted finding is accompanied by either (a) a verified executable PoC, (b) a verified absence-of-sanitizer proof, or (c) an honest "I cannot prove this from static evidence alone" label.** No more "probably an issue."
2. **Confidence scores are calibrated probabilities backed by a Brier score on a held-out labeled corpus, not ordinal priority numbers in disguise.** A "0.8 confidence" finding is wrong 20% of the time, measured.
3. **The tool gets more accurate the longer it runs on a codebase, without retraining a model.** Per-project FP rates trend down with use through a measured active-learning loop.

If we can hit all three, we change what SAST means.

---

## 1. North Star

> **Ship a SAST that a senior security engineer would deploy on her own startup without grumbling.**

That sentence is doing real work. It rules out:

- High-FP tools (she would turn them off within a week)
- Tools that miss obvious business-logic flaws (she'd find them in code review and lose trust)
- Tools that can't compose with her dev workflow (she'd uninstall the IDE plugin)
- Tools that overclaim (she's read enough vendor slides to recognize the smell)
- Tools that don't compose with the rest of the SDLC (she'd build her own glue script)

What it rules in:

- Findings are real, prioritized, and ranked by exploitability
- The tool understands her stack (React + FastAPI + Postgres + Stripe + Auth0 + Vercel)
- It traces the request from edge to database
- It explains why each finding matters in plain language with cost framing
- It writes the fix when the fix is mechanical
- It writes a regression test when the fix is non-mechanical
- It tells her when it isn't sure, and how to look more carefully

---

## 2. Goals & Non-Goals

### 2.1 Goals (in priority order)  [v2: status column added]

| #   | Goal                                                                                                                                | Target                                                                                       | v0.50.0 status |
| --- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------- |
| G1  | **Calibrated confidence**: every finding's `confidence` is a probability with Brier ≤ 0.10 on a labeled corpus                       | Brier score on 1000-finding held-out set; visible in CI report                                | 🟡 framework + seed corpus shipped (P1.3); held-out Brier unmeasured |
| G2  | **Verified exploits**: ≥ 80% of `severity ≥ high` findings ship with a runnable PoC                                                  | Fraction of high+/critical findings with a `poc.ts`, `poc.py`, or framework-idiomatic harness | 🟡 generator covers 10 CWEs (P1.1); verifier framework shipped (P1.2); live-execution rate unmeasured (needs target harness) |
| G3  | **Cross-language**: trace request-borne taint from HTTP edge → service → DB across language boundaries                              | F1 ≥ 0.85 on a polyglot benchmark (Node→Python→Java→Postgres)                                  | 🟡 polyglot bench shipped (P1.4); F1 = 0.727 today; gap is Python SAST coverage |
| G4  | **Business-logic detection**: surface IDOR, broken authz, race-condition, and state-machine flaws beyond pattern matching            | F1 ≥ 0.75 on a curated business-logic corpus (real CVEs with logic flaws)                     | ⏸ deferred to Phase 4 |
| G5  | **Compositional fix**: ≥ 60% of mechanical findings get an apply-able patch that passes the project's linter and re-scan            | Pass-rate of generated patches in `fix-verify` loop                                            | 🟡 fix-verify loop shipped at v0.45; rate unmeasured |
| G6  | **Per-project learning loop**: project FP rate trends down by ≥ 30% over 30 days of feedback                                        | Tracked per project via `validator-metrics.json`; visible in `/security-trend`                | 🟡 loop wired at v0.46; longitudinal data not yet collected |
| G7  | **Honesty**: refuse to emit a finding without either evidence or explicit unverified label                                          | Zero findings with `confidence ≥ 0.7` that lack `poc`, `sanitizer-absence-proof`, or `unverified:true` | 🟢 mostly met — `verifier_verdict` is set on every finding as of v0.50.0; auditing for `confidence ≥ 0.7` outliers is the v0.51 follow-up |
| G8  | **Sub-minute incremental scan** on PRs of ≤ 500 LoC change                                                                          | p95 PR-incremental scan time                                                                  | 🟢 p95 < 30s observed; not yet a CI-gated metric |
| G9  | **Determinism**: byte-identical SARIF for identical inputs across runs                                                              | CI gate; SARIF hash matched against expected                                                  | 🟢 verified on synthetic + real-world benches |
| G10 | **Compositional with SDLC**: editor (LSP), CI (SARIF + policy), agent CLI (MCP), security tab (SARIF upload)                         | Coverage matrix in onboarding docs                                                            | 🟢 all four surfaces shipped (LSP, MCP, SARIF, PR-comment) |

Legend: 🟢 measured & meeting target, 🟡 shipped but unmeasured or below target, ⏸ deferred with reason.

### 2.2 Non-Goals (for v1)

- **Replace dynamic application testing (DAST).** We ingest DAST signals but don't crawl the running app ourselves. DAST is a force multiplier; SAST is the foundation.
- **Replace fuzzing.** We ingest fuzz corpus findings; we don't run libFuzzer or AFL.
- **Replace formal verification.** A handful of high-stakes properties (memory safety, no-data-race) deserve their own tools. We surface where formal methods would help.
- **Compete with software composition analysis (SCA) as a standalone product.** SCA is bundled here because no-one wants to install two tools, but the SCA bar is lower than the SAST bar and we explicitly do not try to out-OSV the OSV team.
- **Run customer code in our cloud.** Privacy-preserving local execution is non-negotiable for the customer segment we want.

---

## 3. Target users

### 3.1 Primary persona — **Maya, senior security engineer, Series B startup**

- Owns AppSec for a 50-engineer org with 3 codebases in 4 languages
- Reports to the CTO; expected to ship in addition to gate
- Tolerates 1-2 false positives per week before turning the tool off
- Writes her own scripts when no commercial tool fits
- Reads SARIF directly when the UI lies

### 3.2 Secondary persona — **Vibecoder, founder/CTO at pre-product startup**

- Ships solo, leverages Claude Code, ships to prod multiple times a day
- Wants "is this safe to ship?" not "here are 47 findings to triage"
- Will pay if the tool prevents one incident
- Trusts the tool only if it shows its work

### 3.3 Tertiary persona — **Helena, head of security at regulated mid-market**

- Compliance lift (SOC2, ISO 27001, NIST AI 600-1) is half the job
- Needs attestation artifacts auto-generated
- Buys the tool because it produces the report the auditor wants

---

## 4. Pillars

The product has seven pillars. Each pillar is independent enough to invest in separately and load-bearing enough that without it the tool is not next-gen.

### Pillar 1 — Semantic Foundation

Today's SAST is mostly pattern-matching with optional shallow taint. The next-gen tool requires actual program understanding.

| Req         | Description                                                                                                                                                | Why                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| FR-SEM-1    | **Polyglot IR.** One canonical representation across JS/TS, Python, Java, Kotlin, Go, Ruby, C#, PHP, C/C++, Rust, Solidity, Swift, Kotlin (Android).        | Same finding shape across languages; one taint engine                                                                |
| FR-SEM-2    | **Full call graph + control flow graph** per function, with k=2 calling-context sensitivity.                                                              | k=1 (current state) misses interprocedural flows that depend on which caller routes data                              |
| FR-SEM-3    | **Field-sensitive taint** with object/struct field tracking (`user.profile.email` vs `user.profile.password`).                                            | Coarse object-level taint produces FPs on every audit-log-write                                                       |
| FR-SEM-4    | **Path-sensitive constant folding** with branch feasibility (don't report findings in provably-dead branches).                                            | The single biggest FP source on Java benchmarks                                                                       |
| FR-SEM-5    | **Symbolic execution for narrow paths** (≤ 4 branches deep, ≤ 200 LoC) when the taint engine reports `feasibility=unknown`.                                | The "I think but can't prove" gap closer                                                                              |
| FR-SEM-6    | **Hybrid static + dynamic.** When a test suite exists, instrument it and observe sink invocations under test inputs. Treat observed taint as ground truth. | The single biggest precision lift available without changing the user experience                                      |
| FR-SEM-7    | **Type-aware refinement.** When TypeScript types narrow a union (`string | undefined` → `string` after a guard), drop findings that depend on the wider type. | Eliminates ~15% of TS-codebase FPs                                                                                    |

### Pillar 2 — Cross-Asset Boundary Crossing  [v2: revised — Python SAST promoted, chain-filter added]

Today's SAST treats a microservice in isolation. Real attack chains cross service, language, network protocol, and infrastructure boundaries.

Phase-1 discovery: the cross-asset detectors work — what's missing is the SINK-SIDE detector coverage for non-Node languages. The polyglot bench shipped at F1 = 0.727, and the 27pp gap to G3 is almost entirely Python-side. Phase 2 reprioritized below.

| Req                    | Description                                                                                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| FR-XSAT-1              | **HTTP/REST via OpenAPI.** Parse `openapi.{json,yaml}`. Match client `fetch`/`axios`/`requests` to server-side handlers. Propagate taint across. [v0.30, shipped] |
| FR-XSAT-2              | **gRPC via .proto.** Match client stubs to server impls (Go/Java/Python/Node/Rust). Propagate taint across. [v0.35, shipped]                            |
| FR-XSAT-3              | **GraphQL via SDL.** Match `gql` client queries to resolver impls (Apollo/NestJS/Strawberry/Graphene). [v0.35, shipped]                                  |
| FR-XSAT-4              | **Message queues.** Schema-aware tracing across Kafka topics, RabbitMQ exchanges, AWS SQS queues, Google Pub/Sub topics, Redis streams. [v0.49, shipped] |
| FR-XSAT-5              | **SQL/ORM round-trip.** ORM write at one site, ORM read of the same model at another — propagate taint through the database row. [v0.30, shipped]      |
| FR-XSAT-6              | **IaC → application code.** Terraform / CloudFormation resources that the app references (env vars, ARNs, names). Flag publicly-exposed resources. [v0.35, shipped] |
| FR-XSAT-7              | **Cloud secrets and IAM.** Parse IAM role policies attached to ECS/Lambda/EKS workloads; correlate with app behavior. [Phase 2.5]                       |
| FR-XSAT-8              | **Container runtime config.** Dockerfile, k8s manifest, ECS task def — flag dangerous combinations. [Phase 2.5]                                          |
| FR-XSAT-9              | **Multi-repo composition.** Given a list of related repos, do all of the above across repositories. [Phase 2.5]                                          |
| **FR-PY-SAST** [NEW]   | **Python sink-side SAST coverage** sufficient to lift the polyglot bench to G3 = 0.85. Specifically: SQLAlchemy `text()` with f-string concat, `os.system` / `subprocess.run` with shell=True, `pickle.loads` / `yaml.load` on request data, `eval` / `exec` on request data, `flask.send_file` / `werkzeug.utils.send_from_directory` with traversable paths. **Phase-2 blocker.** |
| **FR-CHAIN-FILTER** [NEW] | **Don't chain to incidental high-sev findings.** Phase-1 polyglot bench case 02 surfaced this: the queue cross-language detector emitted a chain when the only high-sev finding in the consumer file was CSRF — making the chain semantically wrong. Chains should be gated to a curated set of "chain-worthy" families (sql-injection, command-injection, xss, ssrf, code-injection, insecure-deserialization, xxe, path-traversal). |
| **FR-FAMILY-REGISTRY** [NEW] | **Canonical family names for cross-language chains.** Phase 1 discovery: chain findings get auto-slugged ugly families like `cross-language-taint-client-call-post-us`. Add a registry that maps chain vuln strings to clean families: `xlang-openapi`, `xlang-grpc`, `xlang-graphql`, `xlang-queue`, `xlang-orm`. |

### Pillar 3 — Verification  [v2: revised — sanitizer-absence promoted, live PoC harness called out]

A finding without verification is a hypothesis. We turn hypotheses into either confirmed bugs or labeled uncertainty.

Phase-1 discovery: of the five verdict states (`verified-exploit | verified-by-llm | verified-sanitizer-absence | unverified-by-design | cannot-verify`), **the actually-load-bearing one today is `verified-sanitizer-absence`**. Live PoC execution requires the customer's app to be running against a target URL we don't yet provide a harness for. The static sanitizer-absence proof (9 vuln families covered as of v0.50.0) produces real evidence today without that infrastructure. We lead with it.

| Req                       | Description                                                                                                                                                       |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-VER-1                  | **LLM-validated triage** (Layer 3 — v0.40, shipped). Challenge-token + file:line echo + fail-closed verdicts.                                                    |
| FR-VER-2                  | **PoC generator** for top-10 CWEs (P1.1 — v0.49, shipped). Each finding gets a runnable PoC file with deterministic exit codes and a static safety policy.        |
| FR-VER-3                  | **Regression test generator.** Same finding gets a framework-idiomatic regression test that fails on the vulnerable code and passes after the fix. [Phase 3]      |
| FR-VER-4                  | **Property-based vulnerability hypothesis testing.** Use Hypothesis / fast-check to fuzz around the suspected sink. [Phase 3]                                     |
| FR-VER-5                  | **Live binary instrumentation** (eBPF on Linux, dtrace on macOS). [Phase 5 — opt-in only]                                                                          |
| FR-VER-6                  | **Per-finding verification verdict** (P1.2 — v0.50, shipped). 5-state model, fail-closed semantics.                                                                |
| FR-VER-7                  | **Refusal to silently drop.** Findings that fail verification become `escalate`, never `reject`. [v0.40, shipped]                                                  |
| FR-VER-8 [NEW, was hidden] | **Static sanitizer-absence proof.** For each family-aware sanitizer pattern, prove the sanitizer is NOT in a ±10-line window around the sink. Today: 9 families (sql-injection, command-injection, xss, path-traversal, ssrf, code-injection, open-redirect, xxe, insecure-deserialization). **This is the actually-useful verifier path in v1.** |
| **FR-LIVE-HARNESS** [NEW]  | **Target harness for live PoC execution.** A `docker-compose.yml`-shaped definition the customer can provide that spins up their app on `localhost:3000`. The verifier connects to it via `--target` and runs the PoCs. Without this harness, `verified-exploit` verdicts cannot be assigned in customer environments. **Phase 3 blocker for G2 measurement.** |

### Pillar 4 — Business-Logic Reasoning

The class of bug that consumes the most security-engineer time is the one that pattern matching cannot find: missing authorization, broken state machines, race conditions, intent/implementation mismatch.

| Req         | Description                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-LOGIC-1  | **AuthZ matrix construction.** For each route, infer (auth-required, ownership-checked, role-required, tenant-isolated). Emit findings for the cells that disagree. |
| FR-LOGIC-2  | **State machine extraction.** Identify "status" fields with literal-string-set values; emit findings for transitions that bypass the documented set.                |
| FR-LOGIC-3  | **TOCTOU detection.** Pair `check(x)` with `act(x)` at the function-pair level; flag interleaved awaits that can let `x` change.                                    |
| FR-LOGIC-4  | **Attack chain synthesis.** Multi-finding composition: `Open Redirect + Broken Session Logout + Reflected XSS → Account Takeover`. Cite each link.                  |
| FR-LOGIC-5  | **Intent inference.** Use variable names, comments, and route shapes as evidence of the developer's intent; flag implementation that diverges (e.g. function named `validateOwnership` that doesn't). |
| FR-LOGIC-6  | **LLM-driven flow narration.** For each high-severity finding, a one-paragraph narrative of "how an attacker reaches this, what they get, what it costs you."        |
| FR-LOGIC-7  | **Negative-case test gap.** If the route has happy-path tests but no test for unauthorized access, surface as a "missing-test" finding.                              |

### Pillar 5 — Per-Codebase Adaptation  [v2: revised — federated learning demoted to research]

The tool that learns the codebase is the tool that customers keep. The tool that doesn't learn is the tool that ends up in the suppress-everything bucket.

Phase-1 discovery: customer-tuned rule packs (FR-LEARN-2) and per-codebase calibration (FR-LEARN-5) are tractable and shipped. Federated learning (FR-LEARN-4) is multi-quarter research with privacy-review prerequisites we don't have — moving to Pillar 8 (Phase-6+ research).

| Req         | Description                                                                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-LEARN-1  | **Active-learning loop.** Triage verdicts (TP / FP / WAI) stored under `.agentic-security/triage-feedback.json`; consumed on next scan. [v0.46, shipped]              |
| FR-LEARN-2  | **Customer-tuned rule packs.** Auto-synthesize a YAML rule from a "this should always fire" example; auto-suppress from a "this should never fire" example. [v0.41 — custom-rules + rule-synthesis-from-FPs is Phase 2] |
| FR-LEARN-3  | **Per-CWE precision/recall scorecard.** `validator-metrics.json` tracks per-family precision, recall, F1 over time. [v0.46, shipped]                                  |
| ~~FR-LEARN-4~~ | ~~Privacy-preserving federated learning.~~ **Demoted to Pillar 8 research.** Customer privacy review + DP primitives + protocol design is multi-quarter work that doesn't close the v1.0 gap. |
| FR-LEARN-5  | **Per-codebase confidence calibration.** Wilson CI + per-family TP/FP from `validator-metrics.json` + seed corpus. (P1.3 — v0.49, shipped — framework only; held-out Brier is Phase 5 deliverable.) |
| FR-LEARN-6  | **Auto-rule synthesis from repeated FPs.** If 5+ findings with similar shape get marked FP, propose a suppression rule. [Phase 2]                                    |
| FR-LEARN-7  | **Compliance with the right to delete.** All learned state is local; a `--reset` flag wipes it. [Phase 4 with compliance posture]                                    |

### Pillar 6 — Honest UX

The tool that gets used is the tool that doesn't lie to its user. Every signal must be honest about what it measures.

| Req         | Description                                                                                                                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-UX-1     | **Calibrated confidence** rendered as either an explicit probability ("83% likely TP, based on Brier-calibrated model with N=2400 historical labels") or as a tier label ("high confidence" / "medium" / "investigate"). No raw 0.7531 numbers in user-facing output unless explicitly toggled on. |
| FR-UX-2     | **Confidence intervals.** Where a probability is rendered, surface the 95% CI ("80–88%") rather than a point estimate, because the underlying labeled corpus has finite size.                                                                                  |
| FR-UX-3     | **"I don't know" labels.** When the verifier cannot rule a finding in or out, surface "cannot verify" with reason ("insufficient context", "deferred branch", "external service") rather than picking a confidence number out of a hat.                          |
| FR-UX-4     | **Cost framing.** Each finding has a plain-English blast-radius description ("if this fires on prod, you lose Stripe API key + Auth0 tenant + Postgres password — typical incident cost $80–250k").                                                            |
| FR-UX-5     | **One screen per finding.** The default rendering is one paragraph: what, where, why, how to fix. Taxonomy is opt-in.                                                                                                                                          |
| FR-UX-6     | **No marketing-speak in scanner output.** No emoji. No "industry-leading." No "next-gen." No "deep AI." The output reads like an engineer wrote it.                                                                                                            |
| FR-UX-7     | **Refusal to silently drop findings.** Every dropped finding is recorded in a suppression log with reason. `--firehose` shows everything.                                                                                                                       |
| FR-UX-8     | **Diff-aware presentation.** On PRs, only NEW findings since the base branch are shown. Pre-existing findings stay in the "tech debt" view.                                                                                                                     |

### Pillar 7 — SDLC Composition

The tool that gets adopted is the tool that fits the developer's existing workflow without forcing a new one.

| Req       | Description                                                                                                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-SDLC-1 | **LSP integration** (already shipped). Editor diagnostics on save in VS Code, JetBrains (LSP4IJ), Neovim, Emacs.                                                                              |
| FR-SDLC-2 | **MCP server** (already shipped). Agent-callable tools for `scan_diff`, `query_taint`, `explain_finding`, `apply_fix`, `verify_fix`, `synthesize_fix`. Works with Claude Code, Cursor, Aider, Cline. |
| FR-SDLC-3 | **CI templates** for GitHub Actions, GitLab CI, CircleCI, Buildkite, Jenkins.                                                                                                                |
| FR-SDLC-4 | **SARIF 2.1.0 emit** with full property bag (confidence, exploitability, signatureStatus, rulesetVersion).                                                                                   |
| FR-SDLC-5 | **STIX 2.1 emit** for the threat-intel side of the org that consumes IOCs.                                                                                                                   |
| FR-SDLC-6 | **PR-comment bot** with reasonable defaults (top 10 critical/high, link to full report, never spam).                                                                                         |
| FR-SDLC-7 | **Ticket sync.** Two-way sync against GitHub Issues / Linear / Jira / ServiceNow. Idempotent. State stored locally.                                                                          |
| FR-SDLC-8 | **Slack/Discord/Teams digest.** Daily / weekly summary configurable.                                                                                                                         |
| FR-SDLC-9 | **Policy-as-code gate.** `fail-on critical`, `fail-on high`, custom OPA policy for nuanced gating.                                                                                           |

---

## 5. Technical Architecture

```
                          ┌───────────────────────────┐
                          │  Frontends                │
                          │  • LSP (editor)            │
                          │  • CLI                     │
                          │  • MCP (agent tools)       │
                          │  • CI workflow             │
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │  Orchestrator             │
                          │  (engine.js)               │
                          └─────────────┬─────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬────────────────┐
        │               │               │               │                │
   ┌────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐    ┌─────▼─────┐
   │ Layer 1  │   │ Layer 2   │   │ Layer 3   │   │ Layer 4   │    │ Layer 5   │
   │ Polyglot │   │ Inter-    │   │ LLM       │   │ Verifier  │    │ Active    │
   │ IR + CFG │   │ procedural│   │ validator │   │ (PoC +    │    │ learning  │
   │ + CG     │   │ taint +   │   │ (challenge│   │ test gen) │    │ (per-     │
   │          │   │ symbolic  │   │ token +   │   │           │    │ project    │
   │          │   │ branches  │   │ fail-     │   │           │    │ FP/TP     │
   │          │   │           │   │ closed)   │   │           │    │ tracking) │
   └──────────┘   └───────────┘   └───────────┘   └───────────┘    └───────────┘
        │               │               │               │                │
        └───────────────┴───────────┬───┴───────────────┴────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │ Cross-asset       │
                          │ bridges           │
                          │ (OpenAPI / gRPC / │
                          │  GraphQL / queue /│
                          │  ORM / IaC / IAM) │
                          └───────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │ Findings pipeline │
                          │ stable-id → cluster→ │
                          │ confidence → exploit→ │
                          │ suppress → emit   │
                          └───────────────────┘
```

### 5.1 Layer breakdown

- **L1 (IR/CFG/CG):** Babel-based JS/TS frontend exists; tree-sitter for the rest. Per-function CFG, cross-file call graph keyed by stable function qid. K=2 calling-context.
- **L2 (interprocedural taint):** Walks the IR with field-sensitive forward taint. Sources/sinks/sanitizers from a structured catalog spanning every major framework. Path feasibility via constant folding. Per-function summary cache.
- **L3 (LLM validator):** Per-candidate LLM judgment with prompt-injection defenses (challenge token + file:line echo + fail-closed verdicts). Already shipped.
- **L4 (verifier):** Generates a PoC + regression test. Runs them in a sandboxed container. Records the verdict. New in next-gen.
- **L5 (active learning):** Per-project triage feedback consumed by L3 and the confidence calibrator.

### 5.2 What's shipped (in current `agentic-security` codebase, v0.50.0)  [v2: updated]

Pillar 1: 🟡 IR + L2 taint shipped (v0.45); k=2 context + symbolic execution + dynamic instrumentation = Phase 5  
Pillar 2: 🟢 HTTP-OpenAPI, gRPC, GraphQL, ORM, IaC, queues (P1.5) — shipped; IAM + multi-repo = Phase 2.5  
Pillar 3: 🟢 L3 LLM validator (v0.40) + PoC generator for 10 CWEs (P1.1) + verifier sandbox 5-state model (P1.2) — shipped; live target harness + regression test gen + property fuzz = Phase 3  
Pillar 4: 🟡 attack chains + authz + missing-tests — shipped (v0.44); AuthZ matrix, state-machine extraction, TOCTOU at function-pair = Phase 4  
Pillar 5: 🟡 active-learning loop + per-CWE scorecard + calibration framework + seed corpus (P1.3) — shipped; held-out Brier corpus + auto-rule synthesis = Phase 5  
Pillar 6: 🟢 honest UX, calibrated probability + CI, cost framing, refusal to silently drop — shipped  
Pillar 7: 🟢 LSP, MCP, SARIF + STIX, PR-comment, ticket sync, policy gate, CI templates — all shipped

**Polyglot benchmark (P1.4 — v0.50):** runner + 4 starter cases shipped; F1 = 0.727 today; gap to G3 = 0.85 is Python SAST coverage.

### 5.3 What's hard (open technical questions)

- **Calibration corpus.** Brier-calibrated confidence requires a labeled corpus of ≥ 1000 findings with TP/FP labels. We need to either curate one ourselves (expensive) or federate it.
- **PoC generation correctness.** A generated PoC that "exploits" a non-vuln is worse than no PoC. The verifier must distinguish "runs and demonstrates" from "runs without crashing." This is a research problem.
- **Multi-repo composition.** OpenAPI / gRPC bridges presume both repos are scanned in the same run. Cross-org / cross-tenancy is non-trivial.
- **Federated learning privacy.** Aggregating accept/reject signals across customers without leaking customer code requires a careful protocol design (differential privacy + secure aggregation).
- **Symbolic execution scaling.** Symbolic execution beyond ~200 LoC explodes. The "narrow paths only" gate must be principled.
- **Dynamic instrumentation portability.** eBPF is Linux. dtrace is macOS. Windows is a hole. JVM has its own story. We accept hybrid coverage in v1.

---

## 6. Engineering Culture & Process

What's not in the spec but determines whether v1 ships well:

### 6.1 Adversarial premortems

Every release ends with a documented adversarial premortem against the release artifact. The current process (rounds 1-4 logged in CHANGELOG.md) catches dead code, over-claims, and quiet regressions. We commit to running them indefinitely.

### 6.2 Bench-driven development

Every new detector lands with a fixture pair and an entry in the synthetic bench. F1 regressions block merge. Real-world benchmarks (Juliet, OWASP Benchmark, NodeGoat, DVWA, etc.) tracked separately with per-app F1 floors.

### 6.3 Honesty in claims

The CHANGELOG distinguishes "shipped" from "wired and tested" from "scaffolded." No commit message ever overstates closure; if a closure is overclaimed, the next CHANGELOG entry corrects it explicitly.

### 6.4 No dead code

Every exported symbol has a tested call site, enforced by `test/no-dead-modules.test.js`. Allowlist decay is enforced; stale exceptions fail the test.

### 6.5 Determinism

Concurrency=1 default for any cache-affecting workload. Sorted iteration everywhere we touch findings. Deterministic IDs (stableId) refactor-stable.

### 6.6 Premortem outputs are public

Each release ships its premortem findings in CHANGELOG with severity tags so customers can see exactly what we considered shipping vs what we actually shipped.

---

## 7. Success Metrics

### 7.1 Product-fit (lagging)

| Metric                                       | v1 target | Notes                                                                |
| -------------------------------------------- | --------- | -------------------------------------------------------------------- |
| 30-day active install retention              | ≥ 70%     | If they keep it installed, the FP rate is acceptable                  |
| `/fix --apply` rate per finding              | ≥ 25%     | Fixes that look useful enough to apply                                |
| Suppression rate (findings marked FP / WAI)  | ≤ 15%     | Lower is better; today's commercial SAST runs ~70-90%                |
| Time-to-first-finding-on-fresh-install       | ≤ 60s     | Cold-start barrier                                                   |
| PR-comment open rate (clicked link)          | ≥ 40%     | If they don't click, they don't trust                                |
| Net Promoter Score                           | ≥ 50      | Lagging signal; collect via in-tool prompt + email                    |

### 7.2 Technical (leading)

| Metric                                                       | v1 target |
| ------------------------------------------------------------ | --------- |
| Synthetic-bench F1                                            | ≥ 0.95    |
| OWASP Benchmark v1.2 F1                                       | ≥ 0.90    |
| NodeGoat F1                                                   | 1.00      |
| Juliet C/C++ F1 (curated CWEs)                                | ≥ 0.85    |
| Juliet Java F1 (curated CWEs)                                 | ≥ 0.95    |
| Cross-language polyglot bench F1                              | ≥ 0.85    |
| Business-logic curated bench F1                               | ≥ 0.75    |
| Brier score on confidence calibration                         | ≤ 0.10    |
| p95 PR-incremental scan time                                  | ≤ 60s     |
| p95 full-scan time on 100k LoC repo                           | ≤ 5min    |
| Determinism (byte-identical SARIF over identical input)       | 100%      |

---

## 8. Phasing  [v2: revised — reflects v0.50.0 delivery + Python SAST promotion]

### ✅ Phase 1 (M0-M3) — Foundation — SHIPPED as v0.50.0

Delivered:
- PoC generator framework, 10 CWEs (P1.1)
- Verifier sandbox loop, 5-state model (P1.2)
- Brier-calibrated confidence framework + seed corpus (P1.3)
- Cross-language polyglot benchmark with runner + 4 starter cases (P1.4)
- Cross-language queues — Kafka/SQS/RabbitMQ/Redis/PubSub (P1.5)

Not delivered:
- Live PoC target harness (deferred to Phase 3)
- Held-out Brier corpus (deferred to Phase 5)

### Phase 2 (M3-M6) — Python SAST + chain hygiene  [v2: reprioritized]

The polyglot benchmark surfaced that Python detector coverage is the single largest blocker to G3. Phase 2 closes that gap and fixes the two chain-detector hygiene issues found during Phase 1.

Deliverables (target ship v0.60.0):
- **FR-PY-SAST.** SQLAlchemy raw SQL, `os.system` / `subprocess.run(shell=True)`, `pickle.loads` / `yaml.load`, `eval` / `exec`, `flask.send_file` traversable paths, `requests.get(verify=False)`. Aim: polyglot bench F1 ≥ 0.85 (closes G3).
- **FR-CHAIN-FILTER.** Don't chain to incidental high-sev findings; gate chains to a curated set of chain-worthy families.
- **FR-FAMILY-REGISTRY.** Canonical family names for cross-language chains.
- **FR-LEARN-6.** Auto-rule synthesis from repeated FPs.

### Phase 2.5 (M5-M6) — Cross-asset gap-fill  [v2: split out of Phase 2]

Deliverables (target ship v0.65.0):
- FR-XSAT-7 IAM-policy reachability
- FR-XSAT-8 Container-runtime config detector
- FR-XSAT-9 Multi-repo composition

### Phase 3 (M6-M9) — Verifier loop  [v2: live harness called out]

Deliverables (target ship v0.70.0):
- **FR-LIVE-HARNESS.** Target harness `docker-compose.yml`-shaped definition that spins up the customer's app; verifier connects to it. Closes G2 measurement.
- FR-VER-3 Regression test generator (Jest / pytest / JUnit) bundled with each PoC.
- FR-VER-4 Property-based fuzz harness for top-20 sinks (Hypothesis / fast-check).
- Polyglot bench cases 05–10 (gRPC, GraphQL, multi-repo, Kafka-to-Java, RabbitMQ-to-Python, IaC-exposed Lambda).

### Phase 4 (M9-M12) — Business logic  [v2: federation removed]

Deliverables (target ship v0.80.0):
- FR-LOGIC-1 AuthZ matrix construction
- FR-LOGIC-2 State-machine extraction
- FR-LOGIC-3 TOCTOU at function-pair level
- Business-logic curated bench (CVE corpus); target F1 ≥ 0.75 (closes G4).

### Phase 5 (M12-M15) — Polish + GA

Deliverables (target ship v1.0.0):
- Final calibration corpus — 1000+ labeled findings, held-out; Brier ≤ 0.10 (closes G1).
- FR-SEM-5 narrow-path symbolic execution; FR-SEM-6 hybrid static+dynamic.
- FR-VER-5 eBPF / dtrace live instrumentation (Linux + macOS only; Windows = hole).
- Round-N adversarial premortem against the GA artifact.

### Phase 6+ (post-GA) — Research

Deferred and labeled as research rather than commitment:
- ~~FR-LEARN-4~~ Federated learning with differential privacy + secure aggregation.
- Multi-tenant cloud product (out of engine scope; separate workstream).
- Compliance attestation for non-{NIST-AI-600-1, OWASP-ASVS} frameworks (HIPAA, PCI, FedRAMP).

---

## 9. Risks

| Risk                                                                                                                          | Mitigation                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **R1: Calibration corpus is too expensive to curate.**                                                                        | Start by federating with 5 customer-design-partners; pay for explicit labeling on a held-out 500-finding sample. Budget $50-100k for the seed corpus.   |
| **R2: PoC generation produces convincing-but-wrong PoCs that customers ship.**                                                | Every generated PoC ships with a CI gate that runs it on a known-clean fixture too. The PoC must fail on clean code; otherwise we refuse to claim "exploit verified." |
| **R3: LLM-validator's failure mode is silent reject.**                                                                        | Already mitigated: fail-closed semantics + challenge-token + file:line cross-check. Continued investment in adversarial premortems each release.        |
| **R4: Symbolic execution doesn't scale to real codebases.**                                                                   | Narrow it explicitly: ≤ 4 branches, ≤ 200 LoC, only when the taint engine reports `feasibility=unknown`. Fall back to "cannot-verify" rather than time-out. |
| **R5: Per-customer federation leaks customer code.**                                                                          | Privacy review with an external security firm before turning on federation. Default OFF. Differential privacy + secure aggregation; no plain accept/reject signals leave the customer environment. |
| **R6: Commercial competitors copy our open ideas fast.**                                                                      | Open the engine; close the calibration corpus + the customer feedback loop + the verifier sandbox. The moat is the data, not the patterns.              |
| **R7: Customer adoption is gated by "must run in our VPC."**                                                                  | Already an architectural commitment: no runtime cloud calls, local LLM endpoints supported.                                                              |
| **R8: We over-claim coverage and a security incident blows back.**                                                            | Every claim is bench-backed. CHANGELOG documents honest caveats. We never claim "finds everything."                                                      |
| **R9: Dynamic-instrumentation hybrid mode triggers customer compliance review (root agent in prod).**                          | Hybrid mode is opt-in, off-by-default, and recommended for staging not prod. We document the exact hooks installed.                                       |
| **R10: We build a great tool and nobody finds out about it.**                                                                 | Out of scope for this PRD but real. The community-facing strategy goes elsewhere.                                                                       |
| **R11: [Phase-1 discovery] Cross-language chains land on incidental high-sev findings, polluting the chain detector.**         | FR-CHAIN-FILTER: gate chains to a curated set of chain-worthy families. Lands in Phase 2.                                                               |
| **R12: [Phase-1 discovery] The polyglot bench measures the wrong thing in strict mode.**                                       | Default to `mode: recall-only`; require `mode: strict` to be explicit. The bench's job is to verify cross-language propagation fires — not to penalize incidental single-language findings on the test fixtures. |
| **R13: [Phase-1 discovery] Seed calibration corpus is not a held-out test set; Brier-on-seed is uninformative.**               | CHANGELOG calls this out explicitly. Phase 5 builds the held-out corpus. Until then, calibrated_confidence is honest about its sample size and CI width. |
| **R14: [Phase-1 discovery] Live PoC execution requires customer infrastructure we don't provide.**                              | FR-LIVE-HARNESS. Phase 3. Until then, G2 measurement is unfeasible in customer environments; sanitizer-absence is the load-bearing verifier path.       |
| **R15: [Phase-1 discovery] Phase-1 PoC templates target localhost only — they won't run against staging/prod URLs without customization.** | Documented limitation. PoCs include a `--target` override at the verifier level so customers can point them at whatever URL they choose. Production execution is opt-in via env vars. |

---

## 10. Open Questions

1. **Confidence calibration:** Is a single global Brier-calibrated model sufficient, or do we need per-language / per-framework sub-models? Recommend per-language for v1; merge if Brier scores converge.
2. **Verifier sandbox:** Run PoCs in Docker, Firecracker, or WASM? Docker is lowest friction; Firecracker is the long-term answer. Start with Docker and a strict resource cap.
3. **Federated learning protocol:** Roll our own DP + secure aggregation, or ride on an existing framework? Recommend ride on an existing protocol; the work to build privacy-preserving primitives from scratch is multi-quarter.
4. **Symbolic execution backend:** Build, ride, or fork? Probably ride on KLEE-style for C/C++ and write our own narrow JS executor.
5. **Pricing model:** Per-developer seat, per-codebase, per-finding, or open-core? Recommend open-core with the calibration corpus + verifier sandbox as the paid tier.
6. **Compliance posture:** SOC 2 Type II at v1 or v2? Customer-design-partners want it at v1; that's $80-200k of audit cost. Defer to v2 unless a design partner blocks adoption on it.
7. **Multi-language fix generation:** Do we ship machine-generated fixes in C/C++ and Rust where the cost of a wrong fix is highest, or limit to managed-runtime languages (JS, Python, Java, Go, Ruby, C#) in v1? Recommend limit to managed-runtime; surface "fix recommended manually" for native code.
8. **PoC vs Sanitizer-absence-proof:** Some classes (timing oracles, side channels, race conditions) cannot reasonably ship a PoC. Define a verified-sanitizer-absence proof shape per CWE family.

---

## 11. What this PRD intentionally does NOT specify

- Pricing, licensing, GTM, partners, customer-success ops, hiring plan — all outside engineering scope
- UI specifics for the cloud product (this PRD is for the engine + agent-facing tools)
- Compliance attestation specifics for non-NIST/non-OWASP frameworks (HIPAA, PCI, FedRAMP) — separate workstream
- Specific competitive matrix — see internal comparison doc; we do not name competitors in this PRD or in any shipped artifact

---

## 12. Appendix: Where today's `agentic-security` already exceeds the median commercial tool  [v2: refreshed for v0.50.0]

| Capability                                          | Median commercial SAST | `agentic-security` v0.50.0                                                                |
| --------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------- |
| Calibrated confidence on findings                   | ❌                     | 🟢 framework + Wilson CI + per-family table + seed corpus (P1.3); held-out Brier = Phase 5 |
| LLM-validated triage                                | ❌ or shallow          | 🟢 Layer 3 with prompt-injection defenses (challenge token + file:line echo + fail-closed) |
| Cross-language taint (HTTP, gRPC, GraphQL, ORM, queue) | ❌                  | 🟢 all five (IaC + IAM = Phase 2.5)                                                       |
| IaC → application reachability                      | ❌                     | 🟢                                                                                        |
| PoC generation per finding                          | ❌                     | 🟢 10 CWEs covered + safety policy + deterministic exit codes (P1.1)                       |
| Verifier sandbox loop, 5 verdict states              | ❌                     | 🟢 sanitizer-absence + LLM-accept + unverified-by-design + cannot-verify + verified-exploit (P1.2) |
| Attack-chain synthesis across findings              | ❌                     | 🟢                                                                                        |
| AI-BOM / OWASP-LLM-Top-10 / prompt-injection rules  | ❌                     | 🟢                                                                                        |
| MCP / agent-callable tools                          | ❌                     | 🟢 six hardened tools                                                                     |
| Per-customer learning loop                          | ❌                     | 🟢 metrics persisted; longitudinal data = Phase 4 prerequisite                             |
| Honest CHANGELOG with adversarial premortems         | ❌                     | 🟢 rounds 1-4 documented; round 5 due against v0.50.0                                      |
| Determinism (byte-identical SARIF)                  | ❌                     | 🟢                                                                                        |
| Refactor-stable finding IDs                         | ❌                     | 🟢 stableId                                                                                |
| Polyglot cross-language benchmark                   | ❌                     | 🟢 runner + 4 cases (P1.4); F1=0.727, target 0.85 = Phase 2                                  |
| Open-source engine                                  | depends                | 🟢 PolyForm Internal Use; relicense path open                                              |

The gap from "good open engine" to "next-gen product" is now four specific things:

1. **Python SAST coverage** (closes G3) — Phase 2
2. **Live PoC target harness** (closes G2) — Phase 3
3. **Held-out 1000-finding calibration corpus** (closes G1) — Phase 5
4. **Business-logic detector triple** (closes G4) — Phase 4

Phases 2 through 5 close those four gaps in order.

---

## 13. Lessons from Phase 1  [v2: NEW]

Six insights from delivering v0.50.0 that should shape v0.51+.

### 13.1 The honest UX pillar earned the most credibility

The single biggest reputational gain in v0.46–v0.50 came from CHANGELOG entries that said "we don't measure this yet" alongside ones that said "we shipped this." Every premortem round we ran ended with a CHANGELOG correction the next release; that pattern of public self-correction is the moat against "trust us, our scanner is the best" vendor marketing. Continue investing in it. Round-5 premortem against v0.50.0 is due.

### 13.2 The polyglot bench's value is what it reveals, not its F1 score

The polyglot bench shipped at F1 = 0.727 — under the G3 target of 0.85. The temptation is to tune the engine until F1 = 0.85. The discipline is to let the bench surface real detector gaps and prioritize those (Python SAST, in our case). A bench that always passes is a bench that no longer measures anything.

### 13.3 Sanitizer-absence proofs beat live PoCs in v1

The verifier sandbox's 5-state model envisioned `verified-exploit` (PoC ran against target, exited 0) as the headline verdict. In practice, no customer app was running against a target the verifier could connect to; live execution was unreachable. The static sanitizer-absence proof — covering 9 vuln families — is the verdict that fires today, with real evidence and a clear definition. Lead with it. Live PoCs are a Phase-3 polish, not a v1 commitment.

### 13.4 Family naming matters more than it sounds

The cross-language chain detector emits findings with `family = cross-language-taint-client-call-post-us` (the auto-slug of the chain's vuln string, truncated to 40 chars). Every consumer that filters by family — SARIF property bag, GitHub Security tab, customer dashboards, the bench's expected.json — has to know that ugly string. A canonical family registry (FR-FAMILY-REGISTRY) is a ~50-line patch with massive UX leverage. Phase 2.

### 13.5 Chain hygiene is its own detector

The queue cross-language chain in polyglot case 02 fired correctly — and pointed to a CSRF finding because that happened to be the only high-severity finding on the consumer side. The chain was semantically wrong. Cross-language chains should be gated to a curated set of chain-worthy families (sql-injection, command-injection, xss, ssrf, code-injection, insecure-deserialization, xxe, path-traversal) — not "anything ≥ high." This is FR-CHAIN-FILTER.

### 13.6 The seed corpus problem doesn't go away

P1.3 shipped a seed calibration corpus inside the repo. It is NOT a held-out test set — it's the same data that would be used to teach the engine. Brier-on-seed is uninformative. The held-out corpus for G1 measurement requires either (a) hand-labeling 1000+ findings on a held-out repository, or (b) federating with design-partner customers. Both are real money and real time. PRD risk R1 was right; v2 underscores that the calibration corpus is the gating dependency for G1, not the algorithm.

---

**End of PRD v2.**
