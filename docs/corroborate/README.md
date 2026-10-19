# Corroborate

<!-- seo: title="Corroborate: What independent evidence supports or refutes the finding?" description="Stage 2 of the Agentic Security assurance lifecycle: What independent evidence supports or refutes the finding?" -->

**Stage 2 of 10.** What independent evidence supports or refutes the finding?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Corroboration asks other analyses to agree or disagree before anyone trusts a candidate.

- **Taint flow.** A hop-by-hop path from the source to the sink, recorded as `chain[]` when it spans statements. When source and sink sit in the same statement, `chain[]` is empty and the path is the statement itself (the demo app's SQL injection is exactly this).
- **Reachability.** Whether an entry point can reach the flow. The one stage allowed to lower severity, and only on positive evidence: a provably unreachable finding is demoted and marked `unreachable: true`, never dropped.
- **Guards and falsification.** A deliberate attempt to disprove the finding by finding the context-matched control (a sanitizer, a dominating guard) on the path. It lowers confidence only.
- **Static proof verdict.** `proof.verdict: feasible` means no clean or infeasible proof could be discharged. It is not an exploit.
- **Scan health.** Whether the analyses that produced all of this actually finished. See [scan health](../trust/scan-health.md).

Confidence is reported with its corroboration: `corroboration.count` and `corroboration.by` name the analyses that agree.

**Evidence this stage creates:** Corroboration, reachability, a falsification verdict, a static feasibility verdict and a confidence tier, each in its own field.

## Capabilities at this stage

<!-- generated:capabilities:corroborate:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Dependency risk with function-level reachability](../guides/scanning.md) | Discover, Corroborate | **GA** | Which vulnerable dependencies exist, which are actively exploited, and whether the vulnerable function is actually reachable. |
| [Deterministic context intelligence](../guides/context-intelligence.md) | Discover, Corroborate | **Preview** | Per-entry-point, hash-bound context bundles and citation-checked focused reviews. Opt-in. |
| [Haskell and Nix/NixOS analysis](../language-support.md) | Discover, Corroborate | **Preview** | Static findings for Haskell and Nix/NixOS, with support measured per capability on a synthetic corpus and some legs honestly blocked. |
| [Taint flow and reachability corroboration](./README.md) | Corroborate | **GA** | A hop-by-hop path from where untrusted data entered to the sink, and whether the flow is reachable from an entry point. |
| [Falsification of findings](../concepts.md) | Corroborate | **GA** | Whether a context-matched control on the path (a sanitizer or dominating guard) blocks the finding. Lowers confidence only; never removes a finding and never changes severity. |
| [Model-assisted validation](../how-it-works/deterministic-and-agentic.md) | Corroborate | **Preview** | A second-opinion verdict on a finding, recorded separately from the deterministic evidence. A no-op unless a model endpoint is configured. |
| [Scan health](../trust/scan-health.md) | Corroborate | **GA** | Whether every analyzer finished, which files and feeds were incomplete or stale, and therefore whether a clean result may be called clean. |
<!-- generated:capabilities:corroborate:end -->

## Read more

- [Evidence model](../how-it-works/evidence-model.md)
- [Reading a finding's evidence](../walkthroughs/finding-evidence.md)
- [Concepts](../concepts.md)
- [Scan health](../trust/scan-health.md)
- [Assurance modes](../trust/assurance-modes.md)

---

Previous: [Discover](../discover/README.md) · Next: [Prove](../prove/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
