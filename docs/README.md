# Agentic Security documentation

**Autonomous Security Assurance for the AI Software Era.** Agentic Security combines deterministic analysis with security agents to discover vulnerabilities, challenge them with independent evidence, prove exploitability where possible, understand what is exposed, fix it safely, verify the result, and learn from every finding. It never treats an unavailable analyzer, a skipped step or a partial scan as proof that code is safe.

New here? Start with the **[5-minute demo](quickstart/5-minute-demo.md)**, then **[how it works](how-it-works/assurance-lifecycle.md)**.

## Start here

- **[5-minute demo](quickstart/5-minute-demo.md)**: one command, a real run, both gates
- **[15-minute quickstart](quickstart/15-minute-quickstart.md)** and the full **[quickstart guide](guides/quickstart.md)**: install, scan, fix, verify, export
- **[Demo app](../examples/demo-app/)**: the deliberately vulnerable project every guide scans
- **[One finding's journey](workflows/one-findings-journey.md)**: a real vulnerability through all ten stages

## How it works

- **[The assurance lifecycle](how-it-works/assurance-lifecycle.md)**: `Discover → Corroborate → Prove → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻`, each stage with its real maturity
- **[The evidence model](how-it-works/evidence-model.md)**: severity, confidence, reachability, proof and fix verification are separate facts
- **[Deterministic and agentic](how-it-works/deterministic-and-agentic.md)**: where models help and where they never decide
- **[The finding lifecycle](how-it-works/finding-lifecycle.md)**: the operational workflow, nested inside the lifecycle
- **[Maturity model](how-it-works/maturity-model.md)** and the **[capability registry](capabilities.yaml)**: GA, Preview, Labs and Roadmap, from one source

The ten stages: [Discover](discover/README.md) · [Corroborate](corroborate/README.md) · [Prove](prove/README.md) · [Learn](learn/README.md) · [Scale](scale/README.md) · [Observe](observe/README.md) · [Trace](trace/README.md) · [Fix](fix/README.md) · [Verify](verify/README.md) · [Detect](detect/README.md)

## The security graph

- **[Code Boundaries](security-graph/code-boundaries.md)**: the security graph underneath Agentic Security
- **[Data flow](security-graph/data-flow.md)**, **[blast radius](security-graph/blast-radius.md)** and **[provenance](security-graph/provenance.md)**

## Trust

- **[Trust and limitations](trust/trust-and-limitations.md)**: what a clean result does and does not mean
- **[Scan health](trust/scan-health.md)** · **[Assurance modes](trust/assurance-modes.md)** · **[Verified remediation](trust/verified-remediation.md)**
- **[Agent threat model](trust/agent-threat-model.md)** · **[Model egress](trust/model-egress.md)** · **[Benchmarking methodology](trust/benchmarking-methodology.md)**

## Find your role

Each role page opens with its primary question and a **Core workflow** link, so you reach the workflow in two clicks from here.

| Role | Primary question | Page |
|---|---|---|
| Developer | What do I run before merge or deploy? | [Developer](roles/developer.md) |
| AppSec | How do I trust, tune and govern the analysis? | [AppSec](roles/appsec.md) |
| CISO and security leadership | Can I trust the number, and what can the platform not prove? | [CISO](roles/ciso.md) |
| Platform engineering | How do I wire it into CI/CD and control what it writes? | [Platform engineering](roles/platform-engineering.md) |
| AI engineering | How do I secure AI-written code, agents and MCP tools? | [AI engineering](roles/ai-engineering.md) |
| Privacy | Where does sensitive data go, and what protects it? | [Privacy](roles/privacy.md) |
| Compliance | What evidence do I have, and what could the tool not check? | [Compliance](roles/compliance.md) |
| Detection engineering | What evidence can I use today, and what is not built? | [Detection engineering](roles/detection-engineering.md) |

## Workflows

- **[One finding's journey](workflows/one-findings-journey.md)** · **[Vulnerability response](workflows/vulnerability-response.md)** · **[CI gating](workflows/ci-gating.md)** · **[Compliance evidence](workflows/compliance-evidence.md)**

## More areas

- **[Integrations](integrations/README.md)** · **[Reference](reference/README.md)** (with the **[capability reference](reference/capability-reference.md)** moved from the README) · **[Labs](labs/README.md)** · **[Roadmap](roadmap/README.md)** · **[Website package](website/)**
- **[Style and terminology](STYLE-AND-TERMINOLOGY.md)** · **[Documentation migration map](DOCS-MIGRATION.md)** · **[Implementation status](implementation-status/autonomous-assurance-docs-repositioning.md)** · **[GA promotion record](implementation-status/ga-promotion.md)**

---

## Deeper reading by lane

The role pages above are the front door. These lists go further into the guides, 2-3 links per lane:

**Developer**: write code, get findings fixed
- [Fixing vulnerabilities](guides/fixing-vulnerabilities.md): the triage → fix → verify loop
- [Reading a finding's evidence](walkthroughs/finding-evidence.md): every real field, explained one at a time
- [Examples gallery](examples/README.md): thirteen real findings, one screen each
- [Local AI with Ollama](guides/ollama.md): the fix/validate/hunt stages, running on your own machine
- [Deterministic Context Intelligence](guides/context-intelligence.md): per-entry-point, hash-bound context bundles and focused, citation-checked reviews (`context` command; opt-in)
  - [Architecture](architecture/context-intelligence.md) and [integration audit](architecture/DCI_INTEGRATION_AUDIT.md)
- [Haskell](guides/haskell.md): default scan, Cabal/Stack inputs, sources and sinks, web routes, dependencies, verified fixes, limits
- [Nix and NixOS](guides/nix-nixos.md): flakes and configurations: static, declared, effective, evaluated and runtime scope; hardening, store secrets, closures
- [Installing on NixOS](guides/nixos-install.md): running the scanner itself on a NixOS host; what has not been verified

**AppSec**: set the gate, read the evidence
- [Scan health](walkthroughs/scan-health.md): what `scanHealth` measures, and why one failing analyzer can't hide another's findings
- [Assurance modes](walkthroughs/assurance-modes.md): `advisory` / `standard` / `strict`, real captured output
- [Architecture: the finding lifecycle](architecture/finding-lifecycle.md): the real module pipeline, detector to report
- [Runtime-Corroborated Security Twin](guides/runtime-twin.md): corroborate a static finding against real telemetry, honestly `complete`/`partial`/`unavailable`
- [Source-to-artifact provenance](guides/artifact-provenance.md): trace a finding to the exact container image digest that ships it, and catch a fix that never reached production

**Privacy**: trace where sensitive data actually goes
- [Data Flow Explorer](guides/data-flow-explorer.md): the field-level graph, browsable locally in your own terminal
- [Watch one field's journey](walkthroughs/privacy-data-flow.md): the same fixture, hop by hop
- [Model egress policy](walkthroughs/model-egress.md): what leaves your machine, and what's redacted first

**Compliance**: evidence for a framework, honestly scoped
- [Compliance](guides/compliance.md): the honesty model, and why the satisfied rate is never reported over all of a framework's controls
- [Coverage maps](compliance/): per-control coverage for 4 of the 9 bundled frameworks
- [Risk in dollars](guides/risk-dollars.md): the scenario-disclosure mechanism behind every `riskDollars` estimate

**Platform Engineering**: wire it into CI/CD, manage what it writes to disk
- [CI setup](guides/ci-setup.md): gate every pull request; severity gate vs. assurance gate
- [Configuration & env vars](reference/configuration.md): every toggle and `.agentic-security/` file
- [State & retention](governance/state-and-retention.md): TTLs, encryption, `export`, `legal-hold`

## Doing a task

One page per job, each with copy-paste commands and expected output:

- **[Scanning](guides/scanning.md)**: modes, output formats, exit codes, reading findings, suppression
- **[Fixing vulnerabilities](guides/fixing-vulnerabilities.md)**: the triage → fix → verify loop
- **[SBOM & AI-BOM](guides/sbom-and-ai-bom.md)**: inventory dependencies and AI components
- **[Compliance](guides/compliance.md)**: automated technical-control evidence and gap worklists
- **[CI setup](guides/ci-setup.md)**: gate every pull request; block risky deploys
- **[Responding to a leaked secret](guides/leaked-secrets.md)**: the rotation playbook
- **[Data Flow Explorer](guides/data-flow-explorer.md)**: trace a sensitive field across your whole architecture
- **[Finding provenance](guides/finding-provenance.md)**: which commit introduced a finding, and how confident that attribution is
- **[Risk in dollars](guides/risk-dollars.md)**: the scenario-disclosure mechanism behind `riskDollars`
- **[Local AI with Ollama](guides/ollama.md)**: run validation/fix/hunt against a model on your own machine, loopback-only, no cloud fallback
- **[Haskell](guides/haskell.md)**: scan, dependencies and the SBOM, verified fixes, partial scans, and the limits
- **[Nix and NixOS](guides/nix-nixos.md)**: scan a flake or a configuration: effective options, hardening, build trust, store secrets, closures, optional evaluation
- **[Installing on NixOS](guides/nixos-install.md)**: run the scanner on a NixOS host, offline use, and what has not been verified
- **[Background implementation loop](guides/loop-engineering.md)**: the bounded runbook used to build and verify the Haskell/Nix work (a development tool, not part of the scanner)
- **[Exploit proof](guides/exploit-proof-fabric.md)**: prove a finding is exploitable by running a reproducer in a confined sandbox, replay it independently, and verify a fix by replaying the same exploit against the patch
- **[Rule compiler](guides/rule-compiler.md)**: turn a proven finding into a deterministic rule with structure, a corpus, a promotion gate, a lifecycle, a shared false-positive corpus and `rules regress`
- **[Detection and response](guides/detection-and-response.md)**: turn a proven vulnerability into a validated detection, hunt historical logs honestly, and scope the observable exposure window
- **[Eval Lab and the model router](guides/eval-lab.md)**: compare a baseline and models on detection, exploit proof, remediation, cost, latency and repeatability, and route each task to the right model
- **[Release assurance](guides/release-assurance.md)**: a signed release package, a deterministic `not_deployable` / `needs_review` / `deployable` verdict, `release-view`, offline verification
- **[Engineering excellence evidence](engineering-excellence/README.md)**: measured results, the end-to-end demo, and what is not proven
- **[Fleet](guides/fleet.md)**: scan a declared set of repositories in one invocation and query cross-repository dependency reach
- **[Runtime-Corroborated Security Twin](guides/runtime-twin.md)**: ingest OpenTelemetry/Envoy/Kubernetes-audit/HTTP-access-log telemetry and reconcile it against the scanned Data Flow Explorer graph
- **[Source-to-artifact provenance](guides/artifact-provenance.md)**: scan a built container image archive, verify its signature/attestation, and trace whether a source fix actually reached what's deployed

## Walkthroughs

Real captured output, field by field or run by run:

- **[Assurance modes](walkthroughs/assurance-modes.md)**: `advisory` / `standard` / `strict`, with a real `ci --assurance strict` run
- **[Scan health](walkthroughs/scan-health.md)**: the real `scanHealth` JSON shape and how one failing analyzer is isolated
- **[Reading a finding's evidence](walkthroughs/finding-evidence.md)**: one real finding, field by field: chain, confidence, proof, falsification, riskDollars, provenance
- **[Verified remediation](walkthroughs/verified-remediation.md)**: the three real verify-loop vocabularies and the `FULL`/`MITIGATION`/`WORKAROUND` completeness tier
- **[Watch one field's journey](walkthroughs/privacy-data-flow.md)**: a narrative companion to the Data Flow Explorer, one field hop by hop
- **[Model egress policy](walkthroughs/model-egress.md)**: the real `evaluateEgress`/redaction behavior, before any outbound model call

## Governance

- **[State & retention](governance/state-and-retention.md)**: every artifact the scanner writes, its retention TTL, encryption, `export`, `legal-hold`

## Evaluating it for your company

- **[Architecture](ARCHITECTURE.md)**: how the engine's layers fit together
- **[Architecture: the finding lifecycle](architecture/finding-lifecycle.md)**: the real module pipeline, detector to report
- **[Concepts](concepts.md)**: evidence before severity; deterministic vs. model-assisted
- **[Metrics](METRICS.md)**: per-layer, per-language recall, measured with repro commands; the Haskell and Nix section carries denominators and the corpus revision
- **[Scorecard](SCORECARD.md)**: the published accuracy scorecard
- **[Haskell and Nix support](language-support.md)**: the measured per-capability support table, generated from the frozen holdout, with its limits
- **Tool versions**, [`language-toolchain.json`](language-toolchain.json) records the Node, GHC, Nix and parser versions the support is built and tested against
- **[Compliance coverage](compliance/)**: what each framework's controls map to
- **[Agent threat model](AGENT_THREAT_MODEL.md)**: how the tool hardens itself against the code it scans
- **[Positioning](POSITIONING.md)**: who this is for
- **[Harness compatibility](HARNESS_COMPATIBILITY.md)**: Claude Code, Codex, Cursor, Gemini CLI

## Examples

- **[Examples gallery](examples/README.md)**: real findings and real feature runs, including the Haskell and Nix/NixOS examples, one screen each: SQLi, authz, secrets, SCA, IaC, PII flows, cross-file taint, incomplete scan, verified fix, rejected fix, compliance evidence, model egress denial

## Troubleshooting

- **[Why did my scan fail?](troubleshooting/scan-health.md)**: real causes: analyzer timeout, stale feed, unsupported language, egress denied, and how to fix each

## Reference

- **[CLI](reference/cli.md)**: every command, flag, and exit code
- **[Configuration & env vars](reference/configuration.md)**: every toggle and `.agentic-security/` file
- **[Output schema](reference/output-schema.md)**: the real shape of `scan --format json` output: findings, scanHealth, coverage
- **[Glossary](reference/glossary.md)**: the vocabulary used across the docs, findings, and CLI output, defined once
- **Contracts**: the frozen shapes a Preview or GA capability keeps: **[sibling sweep](reference/root-cause-sweep.md)**, **[federation](reference/federation.md)**, **[fleet](reference/fleet-contract.md)**, **[Eval Lab report](reference/eval-lab-report.md)**, **[rule compiler](reference/rule-compiler-contract.md)**, **[release assurance](reference/release-assurance-contract.md)**, **[detection and response](reference/dnr-contract.md)**, **[strategic metrics](reference/strategic-metrics.md)**, **[exploit proof](reference/exploit-proof-contract.md)**, **[artifact provenance](reference/artifact-provenance-contract.md)**
- **[Cost optimization](MODEL_COST_OPTIMIZATION.md)**: the cache-aware model-cost advisor

## Contributing

- **[Root `CLAUDE.md`](../CLAUDE.md)**: repository map and conventions
- **[Roadmap](ROADMAP.md)**: what's planned and the non-goals
- Subsystem guides live next to their code: `scanner/CLAUDE.md`,
  `scanner/src/sast/CLAUDE.md`, `scanner/src/posture/CLAUDE.md`,
  `scanner/src/dataflow/CLAUDE.md`, `scanner/src/mcp/CLAUDE.md`.
