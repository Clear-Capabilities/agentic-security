# Agent Harness Assessment — Specification

**Version:** 1.0
**Status:** Active
**Derived from:** PRD — AI Agent Harness Assessment Framework (v1.0, 2026-05-21)
**Owners:** Engineering, Security, Compliance (joint sign-off on material changes)

This document is the durable specification for scoring an agentic AI harness. It is the
contract between teams that build harnesses, teams that govern them, and the tools that
score them. It is intentionally short — long enough to be unambiguous, short enough that
nobody has an excuse for not reading it.

The thesis: control lives in the harness, not the model. A harness is the runtime that
wraps a model — its tools, guardrails, validators, and audit log. We score the harness
because that is what you can change.

---

## Scope

A harness is "in scope" for the Assessment when it satisfies all of:

- Wraps an AI model that takes any action with effect outside the immediate session
  (writing files, calling APIs, sending messages, spending money, modifying state).
- Operates in production, regulated, customer-facing, or shared-infrastructure contexts.
- Has at least one tool the model can invoke without per-call human approval.

Read-only chat assistants with no tool access are out of scope.

---

## The six domains

Every assessable harness is scored on exactly these domains, in this order. The order is
load-bearing — each later domain assumes the earlier ones are in place.

| # | Domain | The question it answers |
|---|--------|-------------------------|
| 1 | Tool Access | What can the agent run, and how is each call mediated? |
| 2 | Guardrails | What is the agent forbidden from running, and how is that enforced? |
| 3 | Feedback Loops | What catches the agent's mistakes before they compound? |
| 4 | Audit Evidence | How do we prove, after the fact, what the agent did? |
| 5 | Failure Mode | When the model is wrong, how gracefully does the system fail? |
| 6 | Compliance | How is the evidence above mapped to obligations on demand? |

The six are described in §5 of the PRD; this spec inlines the P0/P1 control list per
domain for review without reference.

---

## The four-level rubric

Each domain is scored on exactly one of these four levels:

| Level | Label | Definition |
|-------|-------|------------|
| 0 | **Absent** | The control does not exist, or exists only in policy text with no implementation. |
| 1 | **Partial** | Some P0 controls exist; others are missing, or the control operates inconsistently. |
| 2 | **Operating** | All P0 controls for this domain exist, are implemented in the harness, and were exercised at least once in the assessment window. |
| 3 | **Operating with continuous evidence** | Level 2 plus: the harness emits tamper-evident evidence that the control operated for every relevant event in the assessment window, recoverable without manual collection. |

A control "exists in the harness" only when its enforcement is in code or configuration,
not in a runbook or a policy document.

---

## Overall score

`overall_score = MIN(domain_scores)`

A harness is only as strong as its weakest domain. Reporting an overall score that hides
a weak surface (e.g. mean of six) is forbidden.

**Passing threshold.** A harness *passes* the Assessment when:

- Every domain is at least `Operating` (level 2).
- Audit Evidence and Compliance are at `Operating with continuous evidence` (level 3).

The asymmetry is intentional: evidence-of-control and compliance must be continuous
because they are the inputs that gate every other process (incident response, customer
diligence, regulator response).

---

## Per-domain control inventory

Each domain below lists its **P0 controls** (required for `Operating`) and
**P1 controls** (required for `Operating with continuous evidence`, alongside continuous
evidence emission). Evidence requirements follow each block.

### 1. Tool Access

**P0**

- T-1: Tools are declared in an allowlist with a machine-readable schema (name, parameters, permissions required, blast radius).
- T-2: Every tool call is mediated by the harness; the model never invokes a privileged action directly.
- T-3: Tools are categorized by sensitivity (read-only / write-local / write-shared / external-effect / financial / identity-modifying) and scoped per session, user, and environment.
- T-4: Denied tool calls are logged with the attempted call, the reason for denial, and the model's surrounding reasoning when available.

**P1**

- T-5: Just-in-time elevation: high-sensitivity tools require an out-of-band approval (human or policy engine) before execution.
- T-6: Tool descriptions are versioned; changes trigger re-assessment of dependent agents.

**Evidence**

- Signed tool manifest per agent build.
- Per-session log of `(tool_call_id, tool_name, args_hash, permitted, outcome)`.

### 2. Guardrails

**P0**

- G-1: A denylist of forbidden operations is enforced outside the model (regex/AST filters on shell, parameter validation on APIs, network egress policy).
- G-2: Rate limits, cost limits, and time limits are enforced and trigger graceful stops rather than silent throttles.
- G-3: Inputs from untrusted sources (web pages, uploads, third-party tool outputs) are tagged and cannot directly trigger sensitive tool calls without a confirmation step.
- G-4: Sandboxing exists for any code execution: ephemeral filesystem, scoped network, no credential inheritance.

**P1**

- G-5: Semantic guardrails (secondary classifier or rule engine) screen tool calls for policy violations the syntactic filter would miss.
- G-6: Limits are differentiated by user role and risk tier, not a single global value.

**Evidence**

- Denylist hash and version pinned to each deployment.
- Counts of blocked calls per category, with samples.
- Sandboxing configuration captured at session start.

### 3. Feedback Loops

**P0**

- F-1: Output validation: every tool result and final response passes through a validator (schema, range, sanity check, or critic model) before being acted on.
- F-2: Anomaly detection on agent behavior: unusual tool sequences, scope changes, repeated failures, and runaway loops trigger alerts and circuit breakers.
- F-3: Human-in-the-loop checkpoints are defined for actions above a sensitivity threshold, with a hard stop until acknowledgment.
- F-4: Self-consistency: the agent's stated intent is compared against its actual tool calls; divergence is flagged.

**P1**

- F-5: A separate verifier model reviews high-stakes plans before execution.
- F-6: User-facing "explain what you're about to do" affordances for actions with external effect.

**Evidence**

- Validator pass/fail rates per tool.
- Time-to-detect and time-to-contain metrics for anomalous runs.
- Checkpoint approval logs with reviewer identity.

### 4. Audit Evidence

**P0**

- A-1: Structured, append-only logs covering every model call, tool call, guardrail decision, and validator outcome — joined by a trace ID.
- A-2: Logs are written to integrity-protected storage (signed, hashed, or write-once).
- A-3: Sessions can be fully reconstructed and replayed from logs, including the exact prompt, tools available, model version, and harness configuration at the time.
- A-4: Retention meets the longest applicable obligation (regulatory, contractual, internal).

**P1**

- A-5: Chain-of-custody metadata for evidence used in external audits.
- A-6: Public, queryable status of which controls were operating during a given time window.

**Evidence**

- Log integrity verification reports (daily).
- Sample replay outputs reproducing prior sessions byte-for-byte.

### 5. Failure Mode

**P0**

- M-1: Defined blast radius for each tool category; failures cannot exceed it.
- M-2: Circuit breakers: repeated failures, anomaly triggers, or guardrail breaches automatically stop the agent and require human reset.
- M-3: Rollback or compensation paths exist for any reversible action; irreversible actions require explicit confirmation.
- M-4: Incident response playbooks reference the harness's logs and replay capability, and have been exercised within the last 12 months.

**P1**

- M-5: Chaos drills: scheduled exercises where a known-bad tool call is injected to verify detection and containment.
- M-6: Customer-facing communication templates for agent-caused incidents.

**Evidence**

- Most recent drill report.
- MTTR for the last three contained incidents (real or simulated).
- Inventory of irreversible actions with their corresponding confirmation mechanism.

### 6. Compliance

**P0**

- C-1: Each Assessment domain maps to specific controls in the frameworks the organization is subject to (SOC 2 CC-series, ISO 27001 Annex A, ISO 42001, NIST AI RMF, OWASP ASVS, OWASP LLM Top 10, EU AI Act Articles 9–15).
- C-2: Reports for any time window can be generated without manual log collection.
- C-3: Control failures (guardrail bypass, unlogged tool call, missed checkpoint) automatically generate compliance exceptions rather than waiting for an audit.

**P1**

- C-4: Continuous control monitoring with a dashboard view of pass/fail per control over time.
- C-5: Auto-generated evidence packages bundled per customer or per audit engagement.

**Evidence**

- Control-to-domain mapping document (versioned, owned by Compliance).
- Sample generated report covering a 30-day window.
- Exception register with disposition.

---

## Assessment cadence

A harness is re-scored on the earliest of:

- A **material change**: new tool added, model version changed, guardrails modified, new sensitivity tier introduced, integration with a new external system.
- An **incident** in which the harness was a contributor or the contained-by surface.
- A **quarterly tick**: at least every 90 days, regardless of changes.

The most recent score is the only one that counts for gating decisions. Scores older than
90 days are treated as `Absent` for the affected domain until a fresh assessment lands.

---

## Operational requirements

These constraints come from §6 of the PRD and are non-negotiable for the scoring tool
itself:

- **Latency overhead.** Assessment instrumentation must add no more than 5% latency at p95.
  Log writes are asynchronous. Guardrails are synchronous and budgeted.
- **Fail-closed.** Loss of the logging path halts the agent rather than allowing operation
  without evidence.
- **Portability.** The Assessment runs against harnesses built on any framework, any
  hosting model, any tool ecosystem. Vendor-specific evidence formats are wrapped via the
  schema in `HARNESS_ASSESSMENT_EVIDENCE.md`.
- **Privacy.** Access to raw logs is itself an audited action. PII redaction is
  configurable per environment.

---

## Versioning and amendments

This spec is versioned. Each section may evolve; material changes require sign-off from
Engineering, Security, and Compliance, and bump the major version. Compatible additions
(new optional controls, new evidence shapes) bump the minor version. The version this
document was scored against is recorded in every generated Assessment report.

The companion documents are:

- [HARNESS_ASSESSMENT_EVIDENCE.md](./HARNESS_ASSESSMENT_EVIDENCE.md) — the wire format
  for evidence a conforming harness must emit.
- `commands/harness-score.md` — the slash command that runs the scoring tool and emits a
  domain-level report against this spec.
- `commands/compliance-report.md` — emits framework-specific attestations using the
  control mappings referenced in domain 6.

---

## Open questions tracked from the PRD

- Multi-agent systems where one agent's tools are another agent's outputs.
- Whether a public registry of Assessment scores should exist.
- Re-assessment cadence when the underlying model is silently updated by a provider.
- Scoring harnesses for agents operating on a user's behalf with the user's own credentials.

These are flagged for the next spec revision; the scoring tool degrades gracefully
(`unscored`) when a domain question is answerable only after one of these resolves.
