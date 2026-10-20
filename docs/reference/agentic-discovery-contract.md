# Agentic discovery (hunt): contract

<!-- seo: title="Agentic discovery contract: the hunt report, its coverage block and what a candidate is" description="The fields the hunt command reports, the coverage block that stops a half-failed hunt reading as clean, and the rules that keep model proposals advisory." -->

**Maturity:** Preview (contract frozen)

`agentic-security hunt` asks a model for candidate weaknesses that no rule encodes, then sends every candidate back through the deterministic engine before reporting it. A candidate is a proposal. It is advisory, it never gates a build and it never writes `last-scan.json`. It needs a configured model endpoint. Stage context: [Discover](../discover/README.md). A model on your own machine: [local models](../guides/ollama.md).

## How a candidate becomes a result

The code is split into focus areas by call graph, and each area is hunted once per lens. Every candidate then passes three gates in order:

1. **Confirmation.** The taint engine looks for a flow at or within two lines of the candidate. The tier is `taint-confirmed`, `sink-adjacent` or `unconfirmed`, and the severity comes from the tier, so an unconfirmed candidate is `low`.
2. **Refutation.** A panel of model calls tries to refute the candidate on three angles: reachability, preconditions and sanitization. A majority of refuting votes removes it.
3. **Judgement.** A candidate already in the last scan is a duplicate, and one a person marked as a false positive is suppressed.

## Command

```bash
agentic-security hunt [path] [--root <dir>] [--lens a,b] [--max-areas N] [--max-llm-calls N] [--max-wall-ms N] [--max-candidates N] [--max-cost-usd N] [--no-memory] [--forget-refuted] [--no-variants]
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | The hunt ran, including a hunt in which every run degraded. Discovery is advisory and never gates |
| `2` | The project has more than 2000 source files. Narrow it with `--root` |

## The report

A compatibility test (`scanner/test/contracts/agentic-discovery.contract.test.js`) plays recorded model replies through the real pipeline and holds the report to the tables below in both directions.

**Report**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/discovery@1` |
| `focusAreas` | The areas planned, each with `id`, `label`, `files` and `size` |
| `runs` | One entry per area and lens, each with `focusAreaId`, `lens`, `degraded`, `reason` and `candidateCount` |
| `fresh` | Candidates that survived all three gates, in finding shape, with a `discovery` object |
| `verificationRecords` | One advisory verification record per fresh candidate. A taint-corroborated one is `inconclusive`, an uncorroborated one `not-run` |
| `duplicates` | Candidates the last scan already reported |
| `suppressed` | Candidates a person marked as a false positive |
| `refutedCandidates` | Candidates the panel refuted. These are raw candidates, not findings |
| `coverage` | The coverage block below |

**Coverage**

| Field | Meaning |
|---|---|
| `areasPlanned` | Focus areas the project was split into, at most the area ceiling |
| `areasHunted` | Areas where at least one lens run completed without degrading |
| `areasFullyHunted` | Areas where every lens run completed without degrading |
| `lensesPerArea` | Lenses that resolved for this run |
| `degradedRuns` | Runs that did not complete |
| `confirmedByTier` | Candidates per confirmation tier |
| `panelsRun` | Candidates that went through the refutation panel |
| `undecidedPanels` | Panels that returned no votes at all. These are not refuted |
| `rememberedRefutals` | Candidates skipped because an earlier run refuted them |
| `priorRuns` | Earlier runs in the memory, or `null` with `--no-memory` |
| `nextWave` | What to hunt next, from the memory, or `null` |
| `llmCalls` | Model calls made |
| `maxLlmCalls` | The call budget |
| `callsPerFinding` | Calls divided by fresh candidates, or `null` when there are none |
| `budgetExhausted` | `true` means the run is incomplete |
| `candidatesCapped` | Candidates not examined because of the candidate cap |
| `reasons` | Every coverage gap, in words |

**The `discovery` object on a fresh candidate**

| Field | Meaning |
|---|---|
| `lens` | The lens that proposed it |
| `focusAreaId` | The area it came from |
| `confirmation` | The tier, the evidence, who probed and why it was not corroborated |
| `refutation` | The votes, the counts, and whether the panel was undecided |

## Rules that hold

- **Coverage is part of the output.** A hunt in which a model call failed, the budget ran out, candidates were capped or discarded, or the confirmation or refutation stage corroborated nothing says so in `coverage.reasons`. A hunt that found nothing because every run degraded is not a clean result, and the command says that in so many words.
- **A silent panel never refutes.** A panel that returned no votes leaves the candidate standing and counts it in `undecidedPanels`.
- **Severity comes from evidence.** An unconfirmed candidate is `low`.
- **A budget is a ceiling.** The call budget, the wall-clock limit and the candidate cap each stop the run and are reported, never applied quietly.
- **A candidate with no file and line is discarded and counted.** It has nowhere to point.
- **Nothing is called without an endpoint.** With none configured every run degrades and the report says so.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **It does not find vulnerabilities.** It proposes candidates. The deterministic engine corroborates some of them. The rest are model opinions that survived a model panel.
- **It has no published precision for the model's proposals.** The pipeline's decision logic is tested with recorded replies. The hosted local-model job exercises the live path with a small model, and in that job the small model proposed no candidate the gates accepted, so no precision number exists to quote. A larger model will behave differently.
- **A confirmed candidate is a corroborated place to look.** For execution evidence use [exploit proof](../guides/exploit-proof-fabric.md).
- **It covers the languages the syntax-tree layer parses**, plus Nix configuration. Other files are not hunted.
- **A refuted candidate is remembered.** The memory skips it next time. If the model, the rules or the code changed, clear it with `--forget-refuted`.
- **The cap is 2000 source files.** Larger projects are not hunted at all, and the command exits 2.
