# The assurance lifecycle

<!-- seo: title="How Agentic Security works: the autonomous security assurance lifecycle" description="Ten stages, from discovering a weakness to detecting its recurrence, each with its real maturity and the evidence it creates." -->

![The ten-stage assurance lifecycle, with each stage's maturity written out](../assets/positioning/assurance-lifecycle.svg)

Agentic Security is organised around one canonical lifecycle. Each stage answers one question, creates a named kind of evidence, and has a maturity taken from [`docs/capabilities.yaml`](../capabilities.yaml).

`Discover → Corroborate → Prove → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻`

**The operational finding workflow is a subset of this lifecycle.** When you work one finding, you run `Find → Prove → Hunt → Scope → Fix → Verify → Detect`. Those seven steps are the part of the ten stages a single person touches in a single sitting. The lifecycle is the larger system around them, including the stages that act on many findings or on the system itself (Learn, Scale, Observe, Trace).

The simplified public view in the README (Discover, Prove, Understand, Fix, Verify, Learn) is a summary of these ten stages, not a second ordering.

The maturity labels are defined in the [maturity model](maturity-model.md): **GA** (production-supported), **Preview** (implemented, still being hardened), **Labs** (experimental) and **Roadmap** (not shipped). A Roadmap stage is described in the future tense on purpose.

## The feedback loop

`Detect / Verify / Learn → stronger future Discover and Corroborate`

What a verified fix, a detected recurrence or a promoted rule teaches the system becomes input to the next round of discovery and corroboration. Today the loop closes by hand and through the Labs rule compiler and detection loop; it does not close automatically.

---

## 1. Discover

**What might be wrong?**

Discovery produces *candidates*, not conclusions. Two kinds feed it:

- **Deterministic discovery** (GA): SAST across the supported languages, dependency analysis, secrets, infrastructure-as-code, prompt-injection and agent-tool audits. Reproducible, no model involved.
- **Agentic discovery** (Preview): `hunt` partitions the call graph into focus areas and sends each through independent lenses to propose weaknesses no rule encodes. It needs a configured model endpoint, is advisory, and never gates a build. Every candidate it proposes goes back through the deterministic engine; the model never sets severity.

Discovery may be aggressive. Confirmation is where skepticism lives.

*Evidence created:* a candidate finding (`id`, `file`, `line`, `cwe`, `family`, `parser`).

<!-- generated:capabilities:discover:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Deterministic security analysis](../guides/scanning.md) | Discover | **GA** | A candidate weakness at a file and line, found by mechanical rules (SAST, secrets, IaC, auth, prompt-injection, MCP audit), with no model in the loop. |
| [Dependency risk with function-level reachability](../guides/scanning.md) | Discover, Corroborate | **GA** | Which vulnerable dependencies exist, which are actively exploited, and whether the vulnerable function is actually reachable. |
| [Agentic discovery (hunt)](../discover/README.md) | Discover | **Preview** | Model-proposed candidate weaknesses that no rule encodes, each routed back through the deterministic engine before it is reported. Advisory; needs a configured model endpoint. |
| [Deterministic context intelligence](../guides/context-intelligence.md) | Discover, Corroborate | **Preview** | Per-entry-point, hash-bound context bundles and citation-checked focused reviews. Opt-in. |
| [Haskell and Nix/NixOS analysis](../language-support.md) | Discover, Corroborate | **Preview** | Static findings for Haskell and Nix/NixOS, with support measured per capability on a synthetic corpus and some legs honestly blocked. |
| [AI-written-code guardrails](../roles/ai-engineering.md) | Discover | **GA** | Insecure edits (injectable SQL, hardcoded keys, eval on user input) intercepted before they reach disk, and destructive shell commands blocked. |
| [MCP server and agent-tool audit](../reference/mcp-tool-contract.md) | Discover | **GA** | A hardened MCP surface for agents (including two write tools) and an audit of the agent tools a project exposes. |
| [Local model support](../guides/ollama.md) | Discover | **Preview** | Validation, fix proposal and hunt against a model on loopback, refusing non-loopback endpoints and never falling back to a cloud provider. |
<!-- generated:capabilities:discover:end -->

## 2. Corroborate

**What independent evidence supports or refutes the finding?**

Corroboration asks other analyses to agree or disagree:

- **Taint flow** (GA): a hop-by-hop path from where untrusted data entered to the sink, recorded as `chain[]` when the path spans more than one statement.
- **Reachability** (GA): whether the flow is reachable from an entry point. This is the one stage that may lower severity, and only on positive evidence.
- **Guards and falsification** (GA): a deliberate attempt to disprove the finding by finding the context-matched control that would block it. It lowers confidence; it never removes a finding or changes severity.
- **Scan health** (GA): whether the analyses that produced all of this actually finished.

*Evidence created:* `corroboration`, `proof.verdict` (a static feasibility verdict, not an exploit), `reachable`, `falsification`, `confidence` and `confidenceTier`.

<!-- generated:capabilities:corroborate:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Dependency risk with function-level reachability](../guides/scanning.md) | Discover, Corroborate | **GA** | Which vulnerable dependencies exist, which are actively exploited, and whether the vulnerable function is actually reachable. |
| [Deterministic context intelligence](../guides/context-intelligence.md) | Discover, Corroborate | **Preview** | Per-entry-point, hash-bound context bundles and citation-checked focused reviews. Opt-in. |
| [Haskell and Nix/NixOS analysis](../language-support.md) | Discover, Corroborate | **Preview** | Static findings for Haskell and Nix/NixOS, with support measured per capability on a synthetic corpus and some legs honestly blocked. |
| [Taint flow and reachability corroboration](../corroborate/README.md) | Corroborate | **GA** | A hop-by-hop path from where untrusted data entered to the sink, and whether the flow is reachable from an entry point. |
| [Falsification of findings](../concepts.md) | Corroborate | **GA** | Whether a context-matched control on the path (a sanitizer or dominating guard) blocks the finding. Lowers confidence only; never removes a finding and never changes severity. |
| [Model-assisted validation](./deterministic-and-agentic.md) | Corroborate | **Preview** | A second-opinion verdict on a finding, recorded separately from the deterministic evidence. A no-op unless a model endpoint is configured. |
| [Scan health](../trust/scan-health.md) | Corroborate | **GA** | Whether every analyzer finished, which files and feeds were incomplete or stale, and therefore whether a clean result may be called clean. |
<!-- generated:capabilities:corroborate:end -->

## 3. Prove

**Can exploitability be mechanically demonstrated?**

`triage exploit <id> --prove` runs a bounded, serialized reproducer in a confined sandbox and lets a deterministic oracle, never a model, decide whether it worked. `EXPLOIT_CONFIRMED` requires the configured number of successful reproductions and an independent replay. It needs a reproducer: you can supply one, and for a few classes (CWE-78, CWE-22, CWE-918) `proof generate` builds one. The container path and the Linux confinement backend are exercised by hosted CI jobs against a real Docker engine, with the measurements committed (see the [exploit proof contract](../reference/exploit-proof-contract.md)).

When there is no reproducer, nothing runs and the tool says so. An unproven finding stays corroborated; it is not downgraded and not upgraded.

*Evidence created:* a proof record with a state from `CANDIDATE` to `EXPLOIT_CONFIRMED`, stored under `.agentic-security/proofs/`.

<!-- generated:capabilities:prove:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Execution-backed exploit proof](../guides/exploit-proof-fabric.md) | Prove | **GA** | Whether a bounded, serialized reproducer (supplied, or generated by `proof generate`), run in a confined sandbox and judged by a deterministic oracle, reproduces the effect. Hosted CI exercises it on Linux under local confinement and in a real container, and the measurements are committed. |
<!-- generated:capabilities:prove:end -->

## 4. Learn

**Can a confirmed novel weakness become reusable deterministic knowledge?**

The finding-to-rule compiler is **Preview**, with its rule format and records frozen at version 1 ([contract](../reference/rule-compiler-contract.md)); detector spec synthesis is **Labs**. The finding-to-rule compiler (`rules synthesize|evaluate|promote|status|rollback|cost|regress`) can promote one proven finding into a reviewed deterministic rule that passes its own corpus, a mutation set and a shared false-positive corpus. `rules synthesize --auto` can propose the rule, but promotion is decided by evidence, never by a model, and a rule is regular expressions over text with structure, not a data-flow rule. The *Security Learning Rate* metric that would measure this across the system is **Roadmap**.

*Evidence created:* a promoted rule with its own regression corpus.

<!-- generated:capabilities:learn:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Finding-to-rule compiler](../guides/rule-compiler.md) | Learn | **Preview** | Whether one proven finding can be promoted to a reviewed, deterministic detection rule (regular expressions over text, with structure) that passes its own corpus, a mutation set and a shared false-positive corpus. `rules synthesize --auto` can propose the rule; promotion is still decided by evidence. |
| [Detector spec synthesis](../../commands/labs.md) | Learn | **Labs** | A detector-spec proposal drafted from sample vulnerable files, written for a human to review and never incorporated automatically. |
| [Security learning rate metric](../roadmap/README.md) | Learn | **Roadmap** | The long-term measure of how many novel confirmed weakness patterns became reusable rules, tests or controls. Not an existing KPI. |
<!-- generated:capabilities:learn:end -->

## 5. Scale

**Where else does this weakness exist?**

- Within a repository (GA): a confirmed finding triggers a repo-wide sweep for sibling instances, reported as found, candidate and mitigated counts.
- Across repositories (Preview): `fleet` runs leased, supervised scan jobs for a declared set of repositories from a local SQLite store and answers which of them depend on, or reference in code, a given one. Dependency matching is by declared package name; there is no remote-worker store.

Cross-repository claims here are limited to those two behaviors.

*Evidence created:* sibling instances, a fleet rollup, a dependents list.

<!-- generated:capabilities:scale:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Repository-wide sibling sweep](../reference/root-cause-sweep.md) | Scale | **GA** | Other instances of the same weakness in the repository, with found, candidate and mitigated counts reported separately. |
| [Fleet scanning and dependency blast radius](../guides/fleet.md) | Scale | **Preview** | Idempotent, leased scan jobs for a declared set of repositories in a local SQLite store, an honest per-repository rollup, and which repositories depend on, or reference in code, a given one. Dependency matching is by declared package name; no remote workers or distributed queue. |
| [Cross-repository graph federation](../reference/federation.md) | Scale, Trace | **GA** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
<!-- generated:capabilities:scale:end -->

## 6. Observe

**What has actually occurred at runtime?**

Today, runtime support is *offline import*: `runtime ingest` takes exported telemetry (OpenTelemetry, Envoy, Kubernetes audit logs, HTTP access logs, native JSONL), matches it against nodes in the scanned graph, derives edge states, and reports `complete`, `partial` or `unavailable`. Missing telemetry is never read as no risk (Preview).

Live, continuous collection of production behavior is **Roadmap** and is not shipped.

*Evidence created:* observations matched to graph nodes, with an honest assurance status.

<!-- generated:capabilities:observe:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Runtime corroboration of the scanned graph](../reference/runtime-corroboration-contract.md) | Observe | **GA** | Whether imported runtime telemetry (OpenTelemetry, Envoy, Kubernetes audit, HTTP access logs) matches nodes in the scanned graph, edge states (observed, blocked, policy violation, not observed, static only), identity tokens stored only as keyed hashes, and a static page of the five Explorer views. A complete, partial or unavailable status; telemetry is imported, not collected live. |
| [Continuous production runtime observation](../roadmap/README.md) | Observe | **Roadmap** | Live collection of production behavior and exercised vulnerable functions. Not shipped; today's runtime support is offline telemetry import. |
<!-- generated:capabilities:observe:end -->

## 7. Trace

**How does risk connect through code, data, architecture, provenance, and artifacts?**

Trace is grounded in the [security graph](../security-graph/code-boundaries.md) (Code Boundaries): sources, sinks, field-level flows and protection state, with blast radius and federation across repositories. [Provenance](../security-graph/provenance.md) adds which commit introduced a finding and whether a built container image still contains it. The graph and provenance are Preview; blast radius and federation are GA.

*Evidence created:* a signed graph artifact, an impact assessment, a provenance record.

<!-- generated:capabilities:trace:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Cross-repository graph federation](../reference/federation.md) | Scale, Trace | **GA** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
| [Code Boundaries security graph](../security-graph/code-boundaries.md) | Trace | **Preview** | Field-level sources, sinks, protection state, sensitive-data classes and findings as one signed graph, browsable locally. Opt-in at scan time. |
| [Blast-radius assessment](../security-graph/blast-radius.md) | Trace | **GA** | What a compromised graph node can reach, including affected data classes and recipients, read from the already-scanned graph. |
| [Finding provenance from Git history](../guides/finding-provenance.md) | Trace | **Preview** | Which commit introduced a finding, resolved from Git history, with the resolution quality stated. |
| [Graph precision, completeness and scale](../security-graph/graph-precision.md) | Trace | **Preview** | Whether a graph analysis finished, and how far its answer reaches. Adds completion status, recursion handling, call-site correlation, demand queries, path conditions, incremental invalidation, boundary contracts, control-placement planning and replayable witness bundles, each with its limits stated. The typed graph view, boundary contracts, demand sink queries, control-placement planning and witness bundles are reachable from the CLI (`dataflow view|contracts|sink-query|plan-cuts`, `witness build|verify`), each opt-in and each reporting a completion status. |
| [Source-to-artifact provenance](../guides/artifact-provenance.md) | Trace | **GA** | Whether a finding is present in a built container image and whether a fix in source reached it. Images come from OCI or Docker archives, a local Docker or Podman engine, or one named registry reference; the engine, registry and signing paths are exercised by a hosted job against a real container engine, a real registry and a real signing tool. |
| [Compliance control evidence](../guides/compliance.md) | Trace | **Preview** | Automated technical-control evidence mapped to bundled frameworks, with unassessed and manual controls kept out of the satisfied count. Not a certification. |
<!-- generated:capabilities:trace:end -->

## 8. Fix

**What is the safest remediation?**

Fixes are previewed, backed up and revertible. A deterministic zero-model swap is used where the change is context-independent; otherwise an agent composes the patch. Either way the patch is not written until it passes verification.

*Evidence created:* a candidate patch and, where the scan built one, a regression test.

<!-- generated:capabilities:fix:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Fix synthesis](../guides/fixing-vulnerabilities.md) | Fix | **GA** | A candidate patch, deterministic or agent-composed, with a preview, a backup and a revert path. A patch is never written without passing verification. |
<!-- generated:capabilities:fix:end -->

## 9. Verify

**Did the fix work, and which verification legs actually ran?**

Verification re-scans, lints and runs tests, and reports every leg as pass, fail or skip. A completeness tier (`FULL`, `MITIGATION`, `WORKAROUND`) says how much of the fix landed. A skipped leg is named, and a degraded verification is never reported as full. With `--require-proof` (Preview) the original exploit must reproduce before the patch and be blocked after it.

*Evidence created:* a verification record with legs, a tier and any degraded legs.

<!-- generated:capabilities:verify:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Verified remediation](../trust/verified-remediation.md) | Verify | **GA** | Whether a patch passed its rescan, lint and test legs, which legs were skipped, and a completeness tier of FULL, MITIGATION or WORKAROUND. |
| [Proof-gated fix](../guides/exploit-proof-fabric.md) | Verify | **GA** | With `fix --apply --require-proof`, that the original exploit reproduced before the patch and is blocked after it. |
| [Assurance gate modes](../trust/assurance-modes.md) | Verify | **GA** | Whether CI fails on an incomplete analysis (strict) or only reports it (advisory, standard). |
| [CI gating](../guides/ci-setup.md) | Verify | **GA** | A baseline-aware pull request scan that writes SARIF, JUnit and JSON and applies a severity gate and an assurance gate. |
| [Release assurance](../guides/release-assurance.md) | Verify | **Preview** | A signed release package, an independent offline verifier and a deterministic not_deployable, needs_review or deployable verdict that names every blocker and never says safe. Not part of the default scan; `release-package build` assembles the package from the last scan, and the independent verifier checks it offline. |
<!-- generated:capabilities:verify:end -->

## 10. Detect

**Was exploitation observed and can recurrence be detected?**

Half of this stage exists, as **Preview**, with its records frozen at version 1 ([contract](../reference/dnr-contract.md)). `dnr` generates a validated detection from a proven vulnerability, hunts local historical logs for it (`OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE`, `TELEMETRY_UNAVAILABLE`) and scopes the observable exposure window. It is local and text-only, built only from what the proof established, and it refuses to dress a static guess up as a defense.

The other half is **Roadmap**: connecting detections to a live SIEM or EDR and reading results back, and observing exploitation in production telemetry. None of that is shipped. See [Detect](../detect/README.md) and the [detection engineering lane](../roles/detection-engineering.md) for the exact line.

*Evidence created:* a validated detection, a hunt verdict and an exposure window, each with its stated limits.

<!-- generated:capabilities:detect:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Detection and response (dnr)](../guides/detection-and-response.md) | Detect | **Preview** | A validated detection generated from a proven vulnerability (Sigma, a generic HTTP rule, a detect-only WAF suggestion, structured log queries, YARA, and Splunk, Sentinel and CloudWatch text), a bounded hunt of local historical logs (observed, not observed, inconclusive, telemetry unavailable) and the observable exposure window. All local and text-only; no SIEM connection. |
| [Connected production detection](../detect/README.md) | Detect | **Roadmap** | Detections deployed to and read back from a connected SIEM or EDR, and exploitation observed in live production telemetry. Not shipped; today's detections are generated and hunted locally. |
<!-- generated:capabilities:detect:end -->

---

## All capabilities

<!-- generated:capabilities:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Deterministic security analysis](../guides/scanning.md) | Discover | **GA** | A candidate weakness at a file and line, found by mechanical rules (SAST, secrets, IaC, auth, prompt-injection, MCP audit), with no model in the loop. |
| [Dependency risk with function-level reachability](../guides/scanning.md) | Discover, Corroborate | **GA** | Which vulnerable dependencies exist, which are actively exploited, and whether the vulnerable function is actually reachable. |
| [Agentic discovery (hunt)](../discover/README.md) | Discover | **Preview** | Model-proposed candidate weaknesses that no rule encodes, each routed back through the deterministic engine before it is reported. Advisory; needs a configured model endpoint. |
| [Deterministic context intelligence](../guides/context-intelligence.md) | Discover, Corroborate | **Preview** | Per-entry-point, hash-bound context bundles and citation-checked focused reviews. Opt-in. |
| [Haskell and Nix/NixOS analysis](../language-support.md) | Discover, Corroborate | **Preview** | Static findings for Haskell and Nix/NixOS, with support measured per capability on a synthetic corpus and some legs honestly blocked. |
| [Taint flow and reachability corroboration](../corroborate/README.md) | Corroborate | **GA** | A hop-by-hop path from where untrusted data entered to the sink, and whether the flow is reachable from an entry point. |
| [Falsification of findings](../concepts.md) | Corroborate | **GA** | Whether a context-matched control on the path (a sanitizer or dominating guard) blocks the finding. Lowers confidence only; never removes a finding and never changes severity. |
| [Model-assisted validation](./deterministic-and-agentic.md) | Corroborate | **Preview** | A second-opinion verdict on a finding, recorded separately from the deterministic evidence. A no-op unless a model endpoint is configured. |
| [Execution-backed exploit proof](../guides/exploit-proof-fabric.md) | Prove | **GA** | Whether a bounded, serialized reproducer (supplied, or generated by `proof generate`), run in a confined sandbox and judged by a deterministic oracle, reproduces the effect. Hosted CI exercises it on Linux under local confinement and in a real container, and the measurements are committed. |
| [Finding-to-rule compiler](../guides/rule-compiler.md) | Learn | **Preview** | Whether one proven finding can be promoted to a reviewed, deterministic detection rule (regular expressions over text, with structure) that passes its own corpus, a mutation set and a shared false-positive corpus. `rules synthesize --auto` can propose the rule; promotion is still decided by evidence. |
| [Detector spec synthesis](../../commands/labs.md) | Learn | **Labs** | A detector-spec proposal drafted from sample vulnerable files, written for a human to review and never incorporated automatically. |
| [Security learning rate metric](../roadmap/README.md) | Learn | **Roadmap** | The long-term measure of how many novel confirmed weakness patterns became reusable rules, tests or controls. Not an existing KPI. |
| [Repository-wide sibling sweep](../reference/root-cause-sweep.md) | Scale | **GA** | Other instances of the same weakness in the repository, with found, candidate and mitigated counts reported separately. |
| [Fleet scanning and dependency blast radius](../guides/fleet.md) | Scale | **Preview** | Idempotent, leased scan jobs for a declared set of repositories in a local SQLite store, an honest per-repository rollup, and which repositories depend on, or reference in code, a given one. Dependency matching is by declared package name; no remote workers or distributed queue. |
| [Cross-repository graph federation](../reference/federation.md) | Scale, Trace | **GA** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
| [Runtime corroboration of the scanned graph](../reference/runtime-corroboration-contract.md) | Observe | **GA** | Whether imported runtime telemetry (OpenTelemetry, Envoy, Kubernetes audit, HTTP access logs) matches nodes in the scanned graph, edge states (observed, blocked, policy violation, not observed, static only), identity tokens stored only as keyed hashes, and a static page of the five Explorer views. A complete, partial or unavailable status; telemetry is imported, not collected live. |
| [Continuous production runtime observation](../roadmap/README.md) | Observe | **Roadmap** | Live collection of production behavior and exercised vulnerable functions. Not shipped; today's runtime support is offline telemetry import. |
| [Code Boundaries security graph](../security-graph/code-boundaries.md) | Trace | **Preview** | Field-level sources, sinks, protection state, sensitive-data classes and findings as one signed graph, browsable locally. Opt-in at scan time. |
| [Blast-radius assessment](../security-graph/blast-radius.md) | Trace | **GA** | What a compromised graph node can reach, including affected data classes and recipients, read from the already-scanned graph. |
| [Finding provenance from Git history](../guides/finding-provenance.md) | Trace | **Preview** | Which commit introduced a finding, resolved from Git history, with the resolution quality stated. |
| [Graph precision, completeness and scale](../security-graph/graph-precision.md) | Trace | **Preview** | Whether a graph analysis finished, and how far its answer reaches. Adds completion status, recursion handling, call-site correlation, demand queries, path conditions, incremental invalidation, boundary contracts, control-placement planning and replayable witness bundles, each with its limits stated. The typed graph view, boundary contracts, demand sink queries, control-placement planning and witness bundles are reachable from the CLI (`dataflow view|contracts|sink-query|plan-cuts`, `witness build|verify`), each opt-in and each reporting a completion status. |
| [Source-to-artifact provenance](../guides/artifact-provenance.md) | Trace | **GA** | Whether a finding is present in a built container image and whether a fix in source reached it. Images come from OCI or Docker archives, a local Docker or Podman engine, or one named registry reference; the engine, registry and signing paths are exercised by a hosted job against a real container engine, a real registry and a real signing tool. |
| [Fix synthesis](../guides/fixing-vulnerabilities.md) | Fix | **GA** | A candidate patch, deterministic or agent-composed, with a preview, a backup and a revert path. A patch is never written without passing verification. |
| [Verified remediation](../trust/verified-remediation.md) | Verify | **GA** | Whether a patch passed its rescan, lint and test legs, which legs were skipped, and a completeness tier of FULL, MITIGATION or WORKAROUND. |
| [Proof-gated fix](../guides/exploit-proof-fabric.md) | Verify | **GA** | With `fix --apply --require-proof`, that the original exploit reproduced before the patch and is blocked after it. |
| [Detection and response (dnr)](../guides/detection-and-response.md) | Detect | **Preview** | A validated detection generated from a proven vulnerability (Sigma, a generic HTTP rule, a detect-only WAF suggestion, structured log queries, YARA, and Splunk, Sentinel and CloudWatch text), a bounded hunt of local historical logs (observed, not observed, inconclusive, telemetry unavailable) and the observable exposure window. All local and text-only; no SIEM connection. |
| [Connected production detection](../detect/README.md) | Detect | **Roadmap** | Detections deployed to and read back from a connected SIEM or EDR, and exploitation observed in live production telemetry. Not shipped; today's detections are generated and hunted locally. |
| [Scan health](../trust/scan-health.md) | Corroborate | **GA** | Whether every analyzer finished, which files and feeds were incomplete or stale, and therefore whether a clean result may be called clean. |
| [Assurance gate modes](../trust/assurance-modes.md) | Verify | **GA** | Whether CI fails on an incomplete analysis (strict) or only reports it (advisory, standard). |
| [Model egress policy](../trust/model-egress.md) | Cross-cutting | **GA** | An allow or deny decision on every outbound model call before a prompt is built, with local-only mode and redaction. |
| [AI-written-code guardrails](../roles/ai-engineering.md) | Discover | **GA** | Insecure edits (injectable SQL, hardcoded keys, eval on user input) intercepted before they reach disk, and destructive shell commands blocked. |
| [MCP server and agent-tool audit](../reference/mcp-tool-contract.md) | Discover | **GA** | A hardened MCP surface for agents (including two write tools) and an audit of the agent tools a project exposes. |
| [Local model support](../guides/ollama.md) | Discover | **Preview** | Validation, fix proposal and hunt against a model on loopback, refusing non-loopback endpoints and never falling back to a cloud provider. |
| [CI gating](../guides/ci-setup.md) | Verify | **GA** | A baseline-aware pull request scan that writes SARIF, JUnit and JSON and applies a severity gate and an assurance gate. |
| [Compliance control evidence](../guides/compliance.md) | Trace | **Preview** | Automated technical-control evidence mapped to bundled frameworks, with unassessed and manual controls kept out of the satisfied count. Not a certification. |
| [Runner-level capability enforcement](../trust/agent-threat-model.md) | Cross-cutting | **Labs** | Filesystem, command and network limits enforced by the task runner. Off by default and operator-only; Linux is partially verified. |
| [Strategic metrics](../reference/strategic-metrics.md) | Cross-cutting | **Preview** | Assurance Coverage, Evidence Conversion and Verified Remediation Rate for the last scan and the recorded fix attempts, each with its numerator, denominator and basis. The Security Learning Rate is reported as not measured. |
| [Eval Lab and model router](../guides/eval-lab.md) | Cross-cutting | **Preview** | A measured comparison of a deterministic baseline and any number of models on detection, exploit proof, remediation, cost, latency and repeatability, and routing of each task to a model. Only a local Ollama server has a built-in adapter, tested against a stand-in. |
| [Release assurance](../guides/release-assurance.md) | Verify | **Preview** | A signed release package, an independent offline verifier and a deterministic not_deployable, needs_review or deployable verdict that names every blocker and never says safe. Not part of the default scan; `release-package build` assembles the package from the last scan, and the independent verifier checks it offline. |
<!-- generated:capabilities:end -->

Capabilities that apply to every stage rather than one, such as the model egress policy, runner-level capability enforcement and the Eval Lab, are marked cross-cutting and appear only in this table.
