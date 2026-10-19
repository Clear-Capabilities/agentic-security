# Documentation migration map

<!-- seo: title="Documentation migration map" description="Every existing documentation path, where its content lives after the autonomous-assurance repositioning, and how each move was validated." -->

The repositioning added a new information architecture (quickstart, how it works, ten lifecycle stages, security graph, trust, roles, workflows) **without moving or deleting any existing page**. Many existing pages have inbound links from the README, other docs, source comments, tests and the capability ledger, so the safe migration is: add a canonical page in the new structure, keep the old page as the detailed reference, and link both ways.

That means every row in the table below has **no broken inbound link**, and the Compatibility column is "path unchanged" for existing files. Only `README.md` and `docs/README.md` were restructured, and the README sections that moved are listed separately with their new anchors.

## How this was built

1. Inventoried every tracked markdown file under `docs/` (excluding generated scanner state and dated internal plans under `docs/superpowers/`).
2. Found inbound links: README, `docs/README.md`, `commands/`, `skills/`, `agents/`, test files that pin README text (`scanner/test/unscored-claims.test.js`) and the capability ledger (`docs/capability-ledger.json`, which crawls the README Documentation section and `docs/README.md`).
3. Chose "add and link" over "move" wherever an inbound reference exists.
4. Validated with the link gate (`node scripts/check-doc-drift.mjs --gate`), the positioning checker (`node scripts/check-positioning-docs.mjs`, which also checks heading anchors in the pages it owns), and the capability-ledger check (`node scripts/capability-ledger/check.mjs`).

## README sections

| Current Path | New Path | Action | Compatibility | Validation |
|---|---|---|---|---|
| `README.md#what-agentic-security-does` | `docs/reference/capability-reference.md#what-agentic-security-does` | Moved verbatim; README now leads with the lifecycle and a generated capability table | README links to the new location | Positioning checker (links and anchors) |
| `README.md#findings-vs-assurance` | docs/trust/scan-health.md and docs/reference/capability-reference.md#findings-vs-assurance | Moved; summarised on the Trust page | README links to Trust | Positioning checker |
| `README.md#see-it-in-action` | `docs/reference/capability-reference.md#see-it-in-action` | Moved verbatim | Not linked externally | Positioning checker |
| `README.md#what-makes-it-different` | `docs/reference/capability-reference.md#what-makes-it-different` | Moved verbatim; the short list now sits under "Why it is different" | README commands link to the new anchor | Positioning checker |
| `README.md#fixes-are-verified-not-trusted` | `docs/trust/verified-remediation.md` | Moved; canonical Trust page plus verbatim copy in the capability reference | README links to Trust | Positioning checker |
| `README.md#stop-overpaying-for-tokens` | docs/reference/capability-reference.md#stop-overpaying-for-tokens and docs/MODEL_COST_OPTIMIZATION.md | Moved verbatim | Full detail was already in MODEL_COST_OPTIMIZATION.md | Positioning checker |
| `README.md#code-boundaries` | README.md#code-boundaries-the-security-graph-underneath and docs/security-graph/code-boundaries.md | Repositioned and moved higher; example retained | Anchor renamed; internal links updated | Positioning checker (anchors) |
| `README.md#run-ai-assisted-security-analysis-locally-with-ollama` | docs/reference/capability-reference.md#run-ai-assisted-security-analysis-locally-with-ollama and docs/guides/ollama.md | Moved verbatim | Full guide unchanged | Positioning checker |
| `README.md#security-benchmarking` | `docs/trust/benchmarking-methodology.md` | Moved and expanded | README links to it | Positioning checker |
| `README.md#compliance-frameworks` | docs/reference/capability-reference.md#compliance-frameworks and docs/workflows/compliance-evidence.md | Moved verbatim (framework table, Privacy Framework section); summarised in the workflow | README links to both | Positioning checker |
| `README.md#what-this-is-not` | README.md#what-agentic-security-is-not and docs/trust/trust-and-limitations.md | Promoted higher in short form; expanded in Trust | Anchor renamed | Positioning checker |
| `README.md#documentation` | README.md#documentation (compacted) and docs/README.md | Compacted; role lanes now lead; every previous target remains linked from docs/README.md | Capability ledger still resolves every source | capability-ledger check |
| `README.md#commands` | README.md#commands | Regrouped by lifecycle goal; every command bullet and its Modes line kept | Ledger reads the same bullets | capability-ledger check |
| `README.md#language-coverage` | README.md#language-coverage | Retained; generated Haskell and Nix blocks untouched; the list of detected vulnerability classes moved to the capability reference | Generated markers kept | docs:check-language |

## New pages (no prior path)

| Current Path | New Path | Action | Compatibility | Validation |
|---|---|---|---|---|
| (none) | `docs/capabilities.yaml` | Created: the capability registry | New | Positioning checker |
| (none) | `docs/STYLE-AND-TERMINOLOGY.md` | Created | New | Positioning checker |
| (none) | `docs/how-it-works/` (5 pages), `docs/quickstart/` (2), `docs/security-graph/` (4), `docs/trust/` (7), `docs/workflows/` (4), `docs/roles/` (8) | Created per the target structure | New | Positioning checker, link gate |
| (none) | `docs/discover/` to `docs/detect/` (10 stage pages) | Created | New | Positioning checker |
| (none) | `docs/integrations/`, `docs/reference/README.md`, `docs/labs/`, `docs/roadmap/` | Created as hubs | New | Link gate |
| (none) | `docs/website/` (5 pages) | Created: no website source exists in this repository | New | Positioning checker |
| (none) | `docs/assets/positioning/` (6 SVGs) | Created | New | Positioning checker (alt text, maturity text, no percentages) |
| (none) | `docs/reference/capability-reference.md` | Created from README sections | New | Positioning checker (anchors) |
| (none) | `docs/implementation-status/autonomous-assurance-docs-repositioning.md` | Created | New | Positioning checker |

## Existing documents

| Current Path | New Path | Action | Compatibility | Validation |
|---|---|---|---|---|
| `docs/AGENT_THREAT_MODEL.md` | `docs/trust/agent-threat-model.md` | Canonical Trust page added; engineering reference retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/ARCHITECTURE.md` | `docs/ARCHITECTURE.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md` | `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/HARNESS_ASSESSMENT_EVIDENCE.md` | `docs/HARNESS_ASSESSMENT_EVIDENCE.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/HARNESS_ASSESSMENT_SPEC.md` | `docs/HARNESS_ASSESSMENT_SPEC.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/HARNESS_COMPATIBILITY.md` | `docs/integrations/README.md` | Linked from the integrations area; page retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md` | `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/METRICS.md` | `docs/trust/benchmarking-methodology.md` | Methodology page added; measured numbers stay in METRICS.md | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/MODEL_COST_OPTIMIZATION.md` | `docs/MODEL_COST_OPTIMIZATION.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/OSCAL.md` | `docs/OSCAL.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/POSITIONING.md` | `docs/POSITIONING.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/README.md` | `docs/README.md` | Rewritten in place | Path unchanged; every previous link and section kept under "Deeper reading by lane" | Link gate; capability ledger |
| `docs/ROADMAP.md` | `docs/roadmap/README.md` | Roadmap area added for unshipped capabilities; engineering roadmap retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/SCORECARD.md` | `docs/SCORECARD.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/architecture/DCI_INTEGRATION_AUDIT.md` | `docs/architecture/DCI_INTEGRATION_AUDIT.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/architecture/context-intelligence.md` | `docs/architecture/context-intelligence.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/architecture/finding-lifecycle.md` | `docs/how-it-works/finding-lifecycle.md` | Operational workflow page added; module pipeline retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/audit/README.md` | `docs/audit/README.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/compliance/nist-800-171-r3-coverage.md` | `docs/roles/compliance.md` | Linked from the Compliance lane; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/compliance/nist-ai-600-1-coverage.md` | `docs/roles/compliance.md` | Linked from the Compliance lane; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/compliance/nist-privacy-1-1-coverage.md` | `docs/roles/compliance.md` | Linked from the Compliance lane; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/compliance/owasp-asvs-coverage.md` | `docs/roles/compliance.md` | Linked from the Compliance lane; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/compliance/owasp-llm-top10-coverage.md` | `docs/roles/compliance.md` | Linked from the Compliance lane; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/concepts.md` | `docs/how-it-works/evidence-model.md` | Evidence model page added; concepts page retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/examples/README.md` | `docs/examples/README.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/governance/state-and-retention.md` | `docs/governance/state-and-retention.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/artifact-provenance.md` | `docs/security-graph/provenance.md` | Provenance overview added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/assurance-documentation-index.md` | `docs/guides/assurance-documentation-index.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/assurance-examples.md` | `docs/guides/assurance-examples.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/assurance-review.md` | `docs/guides/assurance-review.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/assurance-rollout-and-rollback.md` | `docs/guides/assurance-rollout-and-rollback.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/assurance-scope-and-contracts.md` | `docs/guides/assurance-scope-and-contracts.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/background-controller-operations.md` | `docs/guides/background-controller-operations.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/bakeoff-recipe.md` | `docs/guides/bakeoff-recipe.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/business-logic-invariants.md` | `docs/guides/business-logic-invariants.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/ci-setup.md` | `docs/workflows/ci-gating.md` | Workflow page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/compliance.md` | `docs/workflows/compliance-evidence.md` | Workflow page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/context-intelligence.md` | `docs/guides/context-intelligence.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/data-flow-explorer.md` | `docs/security-graph/code-boundaries.md` | Repositioned as the security graph; full guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/deployment-aware-support.md` | `docs/guides/deployment-aware-support.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/engine-mechanism-evidence.md` | `docs/guides/engine-mechanism-evidence.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/evaluation-policy-card.md` | `docs/guides/evaluation-policy-card.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/evaluation-reporting.md` | `docs/guides/evaluation-reporting.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/detection-and-response.md` | `docs/detect/README.md` | Stage page added; guide retained in place (added upstream while this work was in review) | Path unchanged | Link gate; positioning checker |
| `docs/guides/eval-lab.md` | `docs/labs/README.md` | Listed in the Labs area; guide retained in place | Path unchanged | Link gate |
| `docs/guides/release-assurance.md` | `docs/labs/README.md` | Listed in the Labs area; guide retained in place | Path unchanged | Link gate |
| `docs/engineering-excellence/` | `docs/trust/benchmarking-methodology.md` | Linked from Trust (independent accuracy); directory retained in place | Path unchanged | Link gate |
| `docs/guides/exploit-proof-fabric.md` | `docs/prove/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/finding-provenance.md` | `docs/security-graph/provenance.md` | Provenance overview added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/fixing-vulnerabilities.md` | `docs/fix/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/fleet.md` | `docs/scale/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/haskell.md` | `docs/guides/haskell.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/leaked-secrets.md` | `docs/workflows/vulnerability-response.md` | Workflow page added; playbook retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/loop-engineering.md` | `docs/guides/loop-engineering.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/measurement-status.md` | `docs/guides/measurement-status.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/miniature-reproduction.md` | `docs/guides/miniature-reproduction.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/nix-nixos.md` | `docs/guides/nix-nixos.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/nixos-install.md` | `docs/guides/nixos-install.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/offline-reproduction.md` | `docs/guides/offline-reproduction.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/ollama.md` | `docs/roles/ai-engineering.md` | Linked from the AI engineering lane; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/portfolio-recovery.md` | `docs/guides/portfolio-recovery.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/quickstart.md` | `docs/quickstart/15-minute-quickstart.md` | Quickstart map added; the full guide is retained in place (many inbound links) | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/risk-dollars.md` | `docs/guides/risk-dollars.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/routing-policy-card.md` | `docs/guides/routing-policy-card.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/routing-replay.md` | `docs/guides/routing-replay.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/rule-compiler.md` | `docs/learn/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/runtime-twin.md` | `docs/observe/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/sbom-and-ai-bom.md` | `docs/guides/sbom-and-ai-bom.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/guides/scanning.md` | `docs/discover/README.md` | Stage page added; guide retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/guides/verification-oracle-conformance.md` | `docs/guides/verification-oracle-conformance.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/guides/verification-schema-migration.md` | `docs/guides/verification-schema-migration.md` | Retained in place; assurance-programme material, tracked by the capability ledger | Path unchanged; no redirect needed | Link gate |
| `docs/implementation-status/exploit-proof-fabric.md` | `docs/implementation-status/exploit-proof-fabric.md` | Retained in place; historical status record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation-status/fleet.md` | `docs/implementation-status/fleet.md` | Retained in place; historical status record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation-status/rule-compiler.md` | `docs/implementation-status/rule-compiler.md` | Retained in place; historical status record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation-status/runtime-corroborated-twin.md` | `docs/implementation-status/runtime-corroborated-twin.md` | Retained in place; historical status record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation-status/source-to-artifact-provenance.md` | `docs/implementation-status/source-to-artifact-provenance.md` | Retained in place; historical status record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation/assurance-hardening-decisions.md` | `docs/implementation/assurance-hardening-decisions.md` | Retained in place; historical assurance-hardening record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation/assurance-hardening-final-report.md` | `docs/implementation/assurance-hardening-final-report.md` | Retained in place; historical assurance-hardening record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation/assurance-hardening-handoff.md` | `docs/implementation/assurance-hardening-handoff.md` | Retained in place; historical assurance-hardening record | Path unchanged; no redirect needed | Link gate |
| `docs/implementation/assurance-hardening-status.md` | `docs/implementation/assurance-hardening-status.md` | Retained in place; historical assurance-hardening record | Path unchanged; no redirect needed | Link gate |
| `docs/language-support.md` | `docs/language-support.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/lineage/PRIVACY_COMPARISON.md` | `docs/lineage/PRIVACY_COMPARISON.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/reference/assurance-capability-matrix.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/reference/cli.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/reference/configuration.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/reference/glossary.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/reference/mcp-tool-contract.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/reference/output-schema.md` | `docs/reference/README.md` | Indexed by the new Reference hub; retained in place | Path unchanged; no redirect needed | Link gate |
| `docs/standards/README.md` | `docs/standards/README.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/troubleshooting/scan-health.md` | `docs/troubleshooting/scan-health.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/walkthroughs/assurance-modes.md` | `docs/trust/assurance-modes.md` | Canonical Trust page added; walkthrough retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/walkthroughs/finding-evidence.md` | `docs/walkthroughs/finding-evidence.md` | Retained in place; indexed by docs/README.md | Path unchanged; no redirect needed | Link gate |
| `docs/walkthroughs/model-egress.md` | `docs/trust/model-egress.md` | Canonical Trust page added; walkthrough retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/walkthroughs/privacy-data-flow.md` | `docs/security-graph/data-flow.md` | Data-flow concept page added; hop-by-hop walkthrough retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/walkthroughs/scan-health.md` | `docs/trust/scan-health.md` | Canonical Trust page added; field-by-field walkthrough retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |
| `docs/walkthroughs/verified-remediation.md` | `docs/trust/verified-remediation.md` | Canonical Trust page added; three-vocabulary walkthrough retained in place | Path unchanged; no redirect needed | Link gate; positioning checker |

## Not inventoried here

`docs/superpowers/` (dated internal implementation plans, excluded from the capability ledger for the same reason), generated state under `docs/**/.agentic-security/`, images, GIFs, JSON data and spreadsheets. They are unchanged.

## Moving a page later

If a retained page is moved in a future change, add a one-line stub at the old path that links to the new one, update inbound links in the same commit, and add the row here. The link gate fails on any dangling link.
