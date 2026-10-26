# Capability maturity model

<!-- seo: title="Capability maturity model: GA, Preview, Labs and Roadmap" description="Every major Agentic Security capability carries exactly one maturity label, assigned from the code and tests, and checked for consistency across the documentation." -->

Every major capability uses exactly one of four labels. The labels live in one place, [`docs/capabilities.yaml`](../capabilities.yaml), and every page that states a maturity is checked against it.

| Label | Meaning | What you can rely on |
|---|---|---|
| **GA** | Production-supported | Implemented, tested, and supported for production use. A GA capability meets the [GA bar](#the-ga-bar) below, and the registry names the evidence for each criterion. |
| **Preview** | Implemented and usable, still being hardened | It works as documented. Its limits are written next to it, and its behavior may still tighten. |
| **Labs** | Experimental; the interface may change materially | It is real code, but do not build a process on its exact output shape. |
| **Roadmap** | Strategic direction; not shipped | Nothing. It is described in the future or conditional tense, and the registry lists no implementation evidence for it. |

## How a label is assigned

1. Inspect the code and tests for the capability.
2. Read its own status page and "what this does not do" section.
3. Assign the **lowest** label the evidence supports. When two labels are plausible, pick the more conservative one.
4. Record the evidence paths in the registry. Promotion is a change to the registry with evidence, never a rewrite of a page.

The labels describe the *capability*, not the quality of any one result. A GA capability can return a `partial` scan; that is the system working as designed.

## The GA bar

GA is earned, not assigned. A capability is GA only when every criterion below holds. Criteria marked mechanical are checked from fields in the registry, and the checker fails when a named page, test, gate, job or section does not exist.

| # | Criterion | How it is checked |
|---|---|---|
| G1 | **Frozen contract.** The flags, exit codes, output fields and state files the capability exposes are listed on a reference page and covered by a compatibility test. | Mechanical: `contract` names the page, `contractTest` names a test that a scanner test script runs, and the `contract-conformance` release check runs every named test. |
| G2 | **Both-direction tests.** Every claim on the capability's page has a test that proves it fires and a test that proves it stays quiet. | Reviewed, and recorded per capability in the [promotion record](../implementation-status/ga-promotion.md). |
| G3 | **Measured, with the denominator.** A bench or gate measures the capability, is evaluated by the release gate, and fails closed on a regression. | Mechanical: `gate` must be a check that `scripts/release-check.mjs` evaluates. |
| G4 | **Platform coverage stated and tested.** The capability runs in hosted CI on Linux, and on macOS where the maintainer machine is the only other evidence. | Mechanical: `platforms` lists `os:job` pairs, at least one `linux`, each job present in `.github/workflows/`. |
| G5 | **Limits are current.** The page has a "does not do" section, dated and re-read. | Mechanical: `limits` is `page#anchor`; the section must exist and carry a `limits-verified` date no more than 90 days before the checkout's HEAD commit. |
| G6 | **Stable across releases.** No contract-breaking change for two releases, and `since` records the version of promotion. | Mechanical for `since`; the compatibility test enforces the rest from then on. |
| G7 | **Degradation is honest.** Every way the capability can fail to run produces a named degraded state, never a clean result. | Reviewed, and recorded in the promotion record. |

A **Preview** capability needs a frozen `contract` page, or a dated `contractNote` that says which fields may still change. **Labs** and **Roadmap** are unchanged. The bar applies to every GA capability, the twelve that existed first included; one that fails it is fixed or demoted with the reason written on its page.

## What is checked

`node scripts/check-positioning-docs.mjs` (also run by `check-doc-drift.mjs --gate`, which the release gate runs) fails on:

- an unknown maturity or lifecycle stage;
- a GA, Preview or Labs capability with no implementation evidence, or evidence that does not exist;
- a GA capability that does not meet the mechanical criteria of the GA bar, or a Preview capability with neither a contract page nor a dated contract note;
- a Roadmap capability that lists implementation evidence;
- a page that states a maturity different from the registry (for example `[GA]` beside a Labs capability);
- a Roadmap capability described in the present tense as shipped, or a Labs capability described as production-ready;
- a committed capability table that no longer matches the registry.

Natural-language checks are imperfect, so a line can carry `<!-- positioning-ignore: reason -->`; the reason is required and visible in review.

## Every capability and its label

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
| [Execution-backed exploit proof](../guides/exploit-proof-fabric.md) | Prove | **GA** | Whether a bounded, serialized reproducer (supplied, or generated by `proof generate`), run in a confined sandbox and judged by a deterministic oracle, reproduces the effect. Hosted CI exercises it on Linux under local confinement and in a real container, and the measurements are committed. Haskell is a proof language too (GHC's interpreter, packages that ship with GHC only; command injection and path-traversal writes are proven, server-side request forgery is refused), but it has been exercised only under local confinement on macOS, not in the hosted container leg. |
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
| [Graph precision, completeness and scale](../security-graph/graph-precision.md) | Trace | **Preview** | Whether a graph analysis finished, and how far its answer reaches. Adds completion status, recursion handling, call-site correlation, demand queries, path conditions, incremental invalidation, boundary contracts, control-placement planning and replayable witness bundles, each with its limits stated. The typed graph view, boundary contracts, demand sink queries, control-placement planning and witness bundles are reachable from the CLI (`dataflow view|contracts|sink-query|plan-cuts`, `witness build|verify`), each opt-in and each reporting a completion status. Targets not yet met: incremental analysis is 2.5x and 2.4x on the two synthetic projects against a 3x target, 75 of 982 sink sites still take the full path in demand queries, the multi-service fixture finds 3 of 8 labeled positives, the optional z3 backend is not used by a default scan, and the precision figures come from a development sample; on an independent sample of the whole default scan the measured precision was 11.7% for JavaScript and TypeScript and 6.8% for Nix (one LLM labeler, wide intervals; bench/dag/independent). |
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

## Strategic metrics and their maturity

Three of the four are reported as product numbers by `agentic-security metrics` and in the [scorecard](../SCORECARD.md), each with its numerator, denominator and basis; they are one **Preview** capability, [Strategic metrics](../reference/strategic-metrics.md). The fourth is not reported, and says so.

| Metric | Definition | Inputs | Maturity as a reported metric |
|---|---|---|---|
| Assurance Coverage | Percent of requested scope that completed the required analysis | `scanHealth` files and analyzers, expected vs. completed | Preview |
| Evidence Conversion | Percent of candidates that reach stronger evidence states | Per-finding proof states, `corroboration`, taint confirmation | Preview |
| Verified Remediation Rate | Percent of remediation attempts reaching the strongest applicable verification tier | Per-fix verification tier and legs; the fix loop's own acceptance rate | Preview |
| Security Learning Rate | Percent of novel confirmed weakness patterns converted into reusable deterministic rules, tests or controls | The rule compiler's promotion machinery | Roadmap |

The Security Learning Rate is a long-term metric and is not an existing KPI. Nothing measures it yet: the rule compiler grades its rules against a corpus built from the same finding, so the compiler cannot also be the instrument that says how often it learns.

## Related

- [Assurance lifecycle](assurance-lifecycle.md)
- [Evidence model](evidence-model.md)
- [Roadmap](../roadmap/README.md)
