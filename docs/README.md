# agentic-security documentation

Full ASPM + LLMSecOps for Claude Code and the terminal — SAST, SCA, secrets,
IaC, prompt-injection, MCP/agent-tool audit, auth/authZ, attack chains, SBOM /
AI-BOM, and compliance evidence.

New to the tool? Start with the **[15-minute quickstart](guides/quickstart.md)**.
Otherwise, find your lane below.

---

## New here

- **[Quickstart](guides/quickstart.md)** — install, scan the demo app, read the
  verdict, fix a finding, export a report. ~15 minutes, no security background
  needed.
- **[Demo app](../examples/demo-app/)** — the deliberately-vulnerable project
  every guide scans.

## Find your lane

Not sure which task-page you want yet? Start from your role instead — 2-3
links each, into the docs on this page:

**Developer** — write code, get findings fixed
- [Fixing vulnerabilities](guides/fixing-vulnerabilities.md) — the triage → fix → verify loop
- [Reading a finding's evidence](walkthroughs/finding-evidence.md) — every real field, explained one at a time
- [Examples gallery](examples/README.md) — thirteen real findings, one screen each

**AppSec** — set the gate, read the evidence
- [Scan health](walkthroughs/scan-health.md) — what `scanHealth` measures, and why one failing analyzer can't hide another's findings
- [Assurance modes](walkthroughs/assurance-modes.md) — `advisory` / `standard` / `strict`, real captured output
- [Architecture: the finding lifecycle](architecture/finding-lifecycle.md) — the real module pipeline, detector to report

**Privacy** — trace where sensitive data actually goes
- [Data Flow Explorer](guides/data-flow-explorer.md) — the field-level graph, browsable locally in your own terminal
- [Watch one field's journey](walkthroughs/privacy-data-flow.md) — the same fixture, hop by hop
- [Model egress policy](walkthroughs/model-egress.md) — what leaves your machine, and what's redacted first

**Compliance** — evidence for a framework, honestly scoped
- [Compliance](guides/compliance.md) — the honesty model, and why the satisfied rate is never reported over all of a framework's controls
- [Coverage maps](compliance/) — per-control coverage for 4 of the 9 bundled frameworks
- [Risk in dollars](guides/risk-dollars.md) — the scenario-disclosure mechanism behind every `riskDollars` estimate

**Platform Engineering** — wire it into CI/CD, manage what it writes to disk
- [CI setup](guides/ci-setup.md) — gate every pull request; severity gate vs. assurance gate
- [Configuration & env vars](reference/configuration.md) — every toggle and `.agentic-security/` file
- [State & retention](governance/state-and-retention.md) — TTLs, encryption, `export`, `legal-hold`

## Doing a task

One page per job, each with copy-paste commands and expected output:

- **[Scanning](guides/scanning.md)** — modes, output formats, exit codes, reading findings, suppression
- **[Fixing vulnerabilities](guides/fixing-vulnerabilities.md)** — the triage → fix → verify loop
- **[SBOM & AI-BOM](guides/sbom-and-ai-bom.md)** — inventory dependencies and AI components
- **[Compliance](guides/compliance.md)** — automated technical-control evidence and gap worklists
- **[CI setup](guides/ci-setup.md)** — gate every pull request; block risky deploys
- **[Responding to a leaked secret](guides/leaked-secrets.md)** — the rotation playbook
- **[Data Flow Explorer](guides/data-flow-explorer.md)** — trace a sensitive field across your whole architecture
- **[Finding provenance](guides/finding-provenance.md)** — which commit introduced a finding, and how confident that attribution is
- **[Risk in dollars](guides/risk-dollars.md)** — the scenario-disclosure mechanism behind `riskDollars`

## Walkthroughs

Real captured output, field by field or run by run:

- **[Assurance modes](walkthroughs/assurance-modes.md)** — `advisory` / `standard` / `strict`, with a real `ci --assurance strict` run
- **[Scan health](walkthroughs/scan-health.md)** — the real `scanHealth` JSON shape and its fault-isolation guarantee
- **[Reading a finding's evidence](walkthroughs/finding-evidence.md)** — one real finding, field by field: chain, confidence, proof, falsification, riskDollars, provenance
- **[Verified remediation](walkthroughs/verified-remediation.md)** — the three real verify-loop vocabularies and the `FULL`/`MITIGATION`/`WORKAROUND` completeness tier
- **[Watch one field's journey](walkthroughs/privacy-data-flow.md)** — a narrative companion to the Data Flow Explorer, one field hop by hop
- **[Model egress policy](walkthroughs/model-egress.md)** — the real `evaluateEgress`/redaction behavior, before any outbound model call

## Governance

- **[State & retention](governance/state-and-retention.md)** — every artifact the scanner writes, its retention TTL, encryption, `export`, `legal-hold`

## Evaluating it for your company

- **[Architecture](ARCHITECTURE.md)** — how the engine's layers fit together
- **[Architecture: the finding lifecycle](architecture/finding-lifecycle.md)** — the real module pipeline, detector to report
- **[Concepts](concepts.md)** — evidence before severity; deterministic vs. model-assisted
- **[Metrics](METRICS.md)** — per-layer, per-language recall, measured with repro commands
- **[Scorecard](SCORECARD.md)** — the published accuracy scorecard
- **[Compliance coverage](compliance/)** — what each framework's controls map to
- **[Agent threat model](AGENT_THREAT_MODEL.md)** — how the tool hardens itself against the code it scans
- **[Positioning](POSITIONING.md)** — who this is for
- **[Harness compatibility](HARNESS_COMPATIBILITY.md)** — Claude Code, Codex, Cursor, Gemini CLI

## Examples

- **[Examples gallery](examples/README.md)** — thirteen real findings and real feature runs, one screen each: SQLi, authz, secrets, SCA, IaC, PII flows, cross-file taint, incomplete scan, verified fix, rejected fix, compliance evidence, model egress denial

## Troubleshooting

- **[Why did my scan fail?](troubleshooting/scan-health.md)** — real causes: analyzer timeout, stale feed, unsupported language, egress denied, and how to fix each

## Reference

- **[CLI](reference/cli.md)** — every command, flag, and exit code
- **[Configuration & env vars](reference/configuration.md)** — every toggle and `.agentic-security/` file
- **[Output schema](reference/output-schema.md)** — the real shape of `scan --format json` output: findings, scanHealth, coverage
- **[Glossary](reference/glossary.md)** — the vocabulary used across the docs, findings, and CLI output, defined once
- **[Cost optimization](MODEL_COST_OPTIMIZATION.md)** — the cache-aware model-cost advisor

## Contributing

- **[Root `CLAUDE.md`](../CLAUDE.md)** — repository map and conventions
- **[Roadmap](ROADMAP.md)** — what's planned and the non-goals
- Subsystem guides live next to their code: `scanner/CLAUDE.md`,
  `scanner/src/sast/CLAUDE.md`, `scanner/src/posture/CLAUDE.md`,
  `scanner/src/dataflow/CLAUDE.md`, `scanner/src/mcp/CLAUDE.md`.
