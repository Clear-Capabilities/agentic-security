# Trust and limitations

<!-- seo: title="Trust and limitations: what Agentic Security does not prove" description="The trust principles behind Agentic Security, what a clean result does and does not mean, and the limits that stay easy to find." -->

> **Evidence, not magic.** Agentic Security never treats an unavailable analyzer, skipped validation step, partial scan, or failed verification leg as proof that code is safe.

This page is the front door to everything the product will not claim. It replaces the README's short "What this is not" list and expands it. The detail pages are linked from each section.

## The trust principles

1. **Evidence before severity.** A model opinion is not enough for a security claim. See the [evidence model](../how-it-works/evidence-model.md).
2. **Deterministic evidence over unqualified model judgment.** See [deterministic and agentic](../how-it-works/deterministic-and-agentic.md).
3. **Incomplete analysis never becomes green.** See [scan health](scan-health.md).
4. **Remediation verification names skipped and degraded legs.** See [verified remediation](verified-remediation.md).
5. **Experimental capabilities are labeled.** See the [maturity model](../how-it-works/maturity-model.md).
6. **Limitations stay easy to find.** You are on the page.

## What Agentic Security is not

- **Not proof of absence.** A clean scan (`scanHealth.status: complete`, zero actionable findings) means nothing exploitable was found by what did run. It does not mean nothing is wrong. Every evidence field on a finding says how much to trust it; none promises there is no other one.
- **Not an auditor-issued certification.** Compliance output is automated technical-control evidence mapped to a framework's controls. It is never "compliant", "certified" or "audit-passed". A NIST SP 800-171 report is not a CMMC assessment, an SPRS score or a certification. See [Compliance: the honesty model](../guides/compliance.md#the-honesty-model--why-this-wont-inflate-your-score).
- **Not a replacement for human security review or penetration testing.** Static and agentic analysis catch patterns and some logic flaws. People catch intent. The logic-reviewer agent and `triage --validate` close part of that gap, not all of it.
- **Not an excuse to call degraded verification fully verified.** A fix report always carries a named tier and the legs that ran. See [verified remediation](verified-remediation.md).
- **Not a SaaS dashboard.** It is a CLI and a Claude Code plugin (it also works with Codex, Cursor and Gemini CLI; see [harness setup](../HARNESS_COMPATIBILITY.md)).
- **Not free for resale.** PolyForm Internal Use license; see [LICENSE](../../LICENSE).

## What a clean result means

<!-- limits-verified: 2026-10-19 -->

| You see | It means | It does not mean |
|---|---|---|
| Zero actionable findings, `scanHealth.status: complete` | Nothing actionable was found by the analyses that ran, and they all finished | Nothing is wrong |
| Zero actionable findings, `partial` | The analysis did not finish cleanly; the tool says "cannot confirm" | The code is fine |
| A finding with `unreachable: true` | Positive evidence says the flow cannot be entered; severity was demoted | The code is correct |
| `falsification.verdict: survived` | No context-matched control was found on the path | The finding is exploitable |
| `not-reproduced` in a proof record | The supplied reproducer did not produce the effect | The finding is a false positive |
| `cannot-verify` from `verify` | No proof of concept or sanitizer rule applied | The finding is false |
| A `FULL` fix tier | The sink changed, callers are routed through the fix, and tests flipped, as far as the legs ran | No other weakness exists |

## Known limits worth knowing first

<!-- limits-verified: 2026-10-19 -->

- **Independent accuracy is low, and measured.** On code the engine was not built from (278 of 283 entries scored), localized precision was 6/19 and recall 6/278, F1 0.040 (95% interval 0.013 to 0.075). Every miss is classified, and the number is the headline of the evidence, not a footnote. See [Engineering excellence evidence](../engineering-excellence/README.md) and [benchmarking methodology](benchmarking-methodology.md).
- **The regression corpus is a regression net, not a recall measurement.** Most of its entries are self-authored synthetic fixtures.
- **Taint recall is partial and measured per language.** The published figures and their date are in [METRICS](../METRICS.md); the graph carries the same coverage tiers per language.
- **Haskell and Nix support is measured on a synthetic corpus.** A score of 100% there describes robustness over those shapes, not arbitrary real-world code, and some legs (a Nix evaluation, a NixOS host) are blocked on hosts without the tool. See [language support](../language-support.md).
- **Exploit proof needs a reproducer.** You can supply one, and `proof generate` builds one only for CWE-78, CWE-22 and CWE-918. It is measured on macOS and, in hosted CI, on Linux under local confinement and in a real Docker container (the numbers are in the exploit proof contract). Without a container runtime it runs in a lower-assurance local sandbox and says so.
- **Runtime support is offline import.** It matches destinations, not functions or identities.
- **Image scanning reads archives, a local Docker or Podman engine, or one named registry reference.** The engine and registry paths were tested against stand-ins and a mock registry, not a real daemon or registry. See [Source-to-artifact provenance](../guides/artifact-provenance.md).
- **Fleet matching is by declared package name only,** with no remote-worker store, and its scaling was measured once on a toy workload.
- **Detection and response is local and text-only.** Detections are generated and hunted against local files; the renderers were not run against a live SIEM, and a hunt that finds nothing never means the flaw was not exploited.
- **A scan that skipped a file for size or density is `partial`.** Strict assurance fails it, which surprises repositories with minified bundles or very large data files.
- **Dollar estimates are scenario defaults** until you configure your own inputs; they are labeled `scenario_default`. See [Risk in dollars](../guides/risk-dollars.md).
- **EPSS and KEV feeds can be stale**, and a stale feed makes a scan `partial`.

Per-capability limits are written on each capability's own page; the registry in [`docs/capabilities.yaml`](../capabilities.yaml) names the page.

## The rest of the Trust area

| Page | Question |
|---|---|
| [Scan health](scan-health.md) | Did the analysis itself finish? |
| [Assurance modes](assurance-modes.md) | When does CI fail because the analysis was incomplete? |
| [Verified remediation](verified-remediation.md) | What did "verified" actually verify? |
| [Agent threat model](agent-threat-model.md) | Can the repo I am scanning attack the tool? |
| [Model egress](model-egress.md) | What leaves my machine? |
| [Benchmarking methodology](benchmarking-methodology.md) | How are quality claims measured, and how is leakage prevented? |
