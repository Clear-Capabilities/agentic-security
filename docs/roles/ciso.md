# CISO and security leadership

<!-- seo: title="CISO guide: assurance questions to ask of your security program" description="Eight questions security leaders can ask of Agentic Security output: scan completion, reachability, falsification, proof, data exposure, verified fixes, maturity and limits." -->

**Primary question:** Can I trust the number, and what can the platform not prove?

**Core workflow:** [Compliance evidence](../workflows/compliance-evidence.md)

## The eight questions, and where each answer lives

Raw finding counts are the wrong headline. These are the questions that matter, with the field or page that answers each and the maturity of that answer.

| # | Question | Where the answer comes from | Maturity |
|---|---|---|---|
| 1 | Did the required analysis actually complete? | `scanHealth.status` and `conditions[]` on every scan; the assurance gate in CI | GA |
| 2 | How many findings are reachable? | `reachable`, `unreachable`, `entrypointReachable` per finding | GA |
| 3 | How many survived falsification? | `falsification.verdict` per finding (`survived` means no blocking control was found) | GA |
| 4 | How many have stronger proof? | The proof state per finding: `STATICALLY_CORROBORATED`, `REPRODUCED`, `EXPLOIT_CONFIRMED` | Preview |
| 5 | What sensitive data is in the blast radius? | `dataflow impact assess` over the Code Boundaries graph: affected data classes and recipients | Preview |
| 6 | Which fixes are fully verified? | The verification record: `verifiedFull`, `degradedLegs[]` and the completeness tier | GA |
| 7 | What is GA and what is experimental? | [`capabilities.yaml`](../capabilities.yaml), rendered in the [README](../../README.md#what-exists-today) | GA |
| 8 | What can the platform not prove? | [Trust and limitations](../trust/trust-and-limitations.md) | GA |

Two further questions are the long-term ones: *which weakness classes are recurring*, and *how much of the estate completed a trustworthy scan*. They depend on aggregate metrics that are **Roadmap**. The per-scan inputs exist; the rolled-up metric does not. See the [strategic metrics](../how-it-works/maturity-model.md#strategic-metrics-and-their-maturity).

## What to ask your team for

- The `scanHealth` status of the scan behind any "we have zero criticals" claim.
- The verification tier and skipped legs behind any "we fixed it" claim.
- The maturity of any capability a control depends on.

## Compliance, honestly

Compliance output is automated technical-control evidence, mapped to controls, with *not assessed* and *manual* controls excluded from the satisfied count. It is not a certification, an SPRS score or a CMMC assessment. See [compliance evidence](../workflows/compliance-evidence.md) and the [honesty model](../guides/compliance.md#the-honesty-model--why-this-wont-inflate-your-score).

## Dollar figures

Risk-in-dollars estimates are scenario defaults until you supply your organization's inputs, and they are labeled `scenario_default`. See [Risk in dollars](../guides/risk-dollars.md).

## Read more

- [Assurance lifecycle](../how-it-works/assurance-lifecycle.md)
- [Scorecard](../SCORECARD.md) and [metrics](../METRICS.md)
- [Model egress](../trust/model-egress.md) and [state and retention](../governance/state-and-retention.md)
