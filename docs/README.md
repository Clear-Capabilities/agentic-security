# agentic-security documentation

Full ASPM + LLMSecOps for Claude Code and the terminal — SAST, SCA, secrets,
IaC, prompt-injection, MCP/agent-tool audit, auth/authZ, attack chains, SBOM /
AI-BOM, and compliance attestation.

New to the tool? Start with the **[15-minute quickstart](guides/quickstart.md)**.
Otherwise, find your lane below.

---

## New here

- **[Quickstart](guides/quickstart.md)** — install, scan the demo app, read the
  verdict, fix a finding, export a report. ~15 minutes, no security background
  needed.
- **[Demo app](../examples/demo-app/)** — the deliberately-vulnerable project
  every guide scans.

## Doing a task

One page per job, each with copy-paste commands and expected output:

- **[Scanning](guides/scanning.md)** — modes, output formats, exit codes, reading findings, suppression
- **[Fixing vulnerabilities](guides/fixing-vulnerabilities.md)** — the triage → fix → verify loop
- **[SBOM & AI-BOM](guides/sbom-and-ai-bom.md)** — inventory dependencies and AI components
- **[Compliance](guides/compliance.md)** — auditor-ready attestations and gap worklists
- **[CI setup](guides/ci-setup.md)** — gate every pull request; block risky deploys
- **[Responding to a leaked secret](guides/leaked-secrets.md)** — the rotation playbook

## Evaluating it for your company

- **[Architecture](ARCHITECTURE.md)** — how the engine's layers fit together
- **[Metrics](METRICS.md)** — per-layer, per-language recall, measured with repro commands
- **[Scorecard](SCORECARD.md)** — the published accuracy scorecard
- **[Compliance coverage](compliance/)** — what each framework's controls map to
- **[Agent threat model](AGENT_THREAT_MODEL.md)** — how the tool hardens itself against the code it scans
- **[Positioning](POSITIONING.md)** — who this is for
- **[Harness compatibility](HARNESS_COMPATIBILITY.md)** — Claude Code, Codex, Cursor, Gemini CLI

## Reference

- **[CLI](reference/cli.md)** — every command, flag, and exit code
- **[Configuration & env vars](reference/configuration.md)** — every toggle and `.agentic-security/` file
- **[Cost optimization](MODEL_COST_OPTIMIZATION.md)** — the cache-aware model-cost advisor

## Contributing

- **[Root `CLAUDE.md`](../CLAUDE.md)** — repository map and conventions
- **[Roadmap](ROADMAP.md)** — what's planned and the non-goals
- Subsystem guides live next to their code: `scanner/CLAUDE.md`,
  `scanner/src/sast/CLAUDE.md`, `scanner/src/posture/CLAUDE.md`,
  `scanner/src/dataflow/CLAUDE.md`, `scanner/src/mcp/CLAUDE.md`.
