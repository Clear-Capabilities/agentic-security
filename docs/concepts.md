# Concepts

Two ideas that cut across every command in this package: how a finding
earns its severity, and which parts of a scan ever talk to a model.

---

## Evidence before severity

A finding's `severity` is set early and never moved by anything downstream
of it — every stage after that only adds *evidence about how much to trust
it*, never edits the verdict itself. Reading a finding means reading that
evidence in order, not just the headline severity:

**Observation → Evidence → Reachability → Proof/Falsification →
Confidence → Severity/Risk.**

- **Observation** — a detector fires: `id`, `vuln`, `cwe`, `file`, `line`.
  This is the raw claim, before anything has tried to corroborate,
  reach, prove, or disprove it.
- **Evidence** — `chain[]`, the real path evidence: one hop per
  `{file, line, label, provenance}` from where tainted data entered to
  where it reached the sink. There is no top-level `source`/`sink`/`path`
  on a finding — those are Data Flow Explorer *graph* concepts, a
  different subsystem (see the [Data Flow
  Explorer](guides/data-flow-explorer.md) guide).
- **Reachability** — whether the flow this finding describes is actually
  reachable from an entry point. A finding demoted here carries
  `unreachable: true`; nothing is silently dropped, and severity does not
  move.
- **Proof/Falsification** — two separate, deliberately adversarial passes:
  `proof` (`dataflow/proof-gate.js`) asks whether the flow can be
  discharged as clean or infeasible; `falsification`
  (`posture/falsification.js`) actively tries to *disprove* the finding by
  hunting for a context-matched control on the path. Both are
  recall-preserving — a `"blocked"` falsification verdict demotes
  confidence, never removes the finding and never touches `severity`.
- **Confidence** — `confidence`/`confidenceTier`, plus `corroboration`
  (how many independent analyses agree). This is the field
  proof/falsification actually move; a `low` confidence next to a
  `"blocked"` falsification verdict means the demotion happened
  *because* of that adversarial pass, not because the detector was unsure
  from the start.
- **Severity/Risk** — `severity` itself, set once and never touched by any
  of the above, alongside the two numbers that *do* move with the
  evidence: `exploitability`/`exploitabilityTier` (how bad it is if real)
  and `riskDollars` (a modeled expected-loss estimate, honestly labeled
  `scenario_default` when it's industry base-rates rather than your own
  organization's numbers).

Every field name above is real and defined in one place, field by field,
with a captured example finding: [Reading a finding's
evidence](walkthroughs/finding-evidence.md). The scan-level counterpart —
whether the analysis that *produced* these fields actually finished — is
[Scan health](walkthroughs/scan-health.md). The stage-by-stage module
pipeline that computes all of this is [Architecture: the finding
lifecycle](architecture/finding-lifecycle.md).

---

## Deterministic vs. model-assisted

Not every capability in this package needs a model, and the ones that can
use one are never silently on. Four tiers, from least to most dependent on
an external model:

**Needs no model, ever.** SAST, SCA, secrets detection, and IaC scanning —
the core deterministic engine — run on AST/taint analysis, regex and
entropy heuristics, and dependency-graph lookups. None of it calls an LLM.
This is the scan you get with zero model configuration of any kind.

**Optionally uses one, default-on once configured.** The Layer-3 LLM
validator is gated on `AGENTIC_SECURITY_LLM_ENDPOINT` being set — not on a
separate opt-in flag. Verified directly in
`scanner/src/llm-validator/index.js`: *"an endpoint is configured
(`AGENTIC_SECURITY_LLM_ENDPOINT` set), unless the operator explicitly opts
out with `AGENTIC_SECURITY_LLM_VALIDATE=0`. ... With no endpoint configured
[it] stays a no-op — no surprise network calls."* The same endpoint also
enables `agentic-security hunt` (`scanner/src/discovery/`), the LLM-driven
candidate-discovery pass that proposes findings the deterministic engine
then confirms or refutes — advisory only, and every candidate still has to
survive the deterministic taint engine and a majority-vote refutation panel
before it's reported.

**Requires an approved provider.** Configuring an endpoint doesn't mean
every call goes out — `egress/policy.js`'s `evaluateEgress()` decides
`'allow'` or `'deny'` for every outbound model call *before* a prompt is
even built, checked against an operator-authored
`.agentic-security/egress-policy.yml` (allowed providers, DPA/BAA status,
regulated-data profile) or a blunt `AGENTIC_SECURITY_EGRESS_MODE`/
`AGENTIC_SECURITY_EGRESS_DENY` override. A denied call is written to a
tamper-evident audit log and the finding is tagged
`llmValidationStatus: 'policy-blocked'` — never a silent drop. Full
mechanics, with real captured output: [Model egress
policy](walkthroughs/model-egress.md).

**Works fully disconnected.** `--no-network` (or `AGENTIC_SECURITY_OFFLINE`)
skips every network dependency the scanner would otherwise reach for — OSV,
registry, and EPSS lookups for SCA — per the [Configuration
reference](reference/configuration.md). Combined with never setting
`AGENTIC_SECURITY_LLM_ENDPOINT` (which already keeps every LLM-driven
feature a no-op on its own), a scan run this way never dials out at all:
the deterministic core needed no network to begin with, and both of the
other two egress paths are closed by construction rather than by a
best-effort check.
