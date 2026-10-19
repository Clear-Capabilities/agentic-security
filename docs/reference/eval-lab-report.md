# Eval Lab report: contract

<!-- seo: title="Eval Lab report contract: the fields, the statistic shape and what is withheld" description="The frozen shape of the Eval Lab JSON report, the rule for statistics and costs, and the limits of what a report claims." -->

**Maturity:** Preview

`agentic-security eval report <run-id> --format json` writes a report with `schema: agentic-security/eval-lab-report` and `version: 1`. This page freezes that shape. A compatibility test (`scanner/test/contracts/eval-lab-report.contract.test.js`) builds a report and holds it to the tables below in both directions, so a field cannot be added or removed without changing this page and the `version` in the same commit. The commands and the way a run is made are in the [Eval Lab guide](../guides/eval-lab.md).

**Report**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/eval-lab-report` |
| `version` | `1` |
| `runId` | The run the report summarizes |
| `runDigest` | Digest of the run record. A run that no longer matches it is reported as failed and never used for routing |
| `providerVariance` | One entry per model and task whose repeats disagree, with the `spread` |
| `header` | Where the numbers came from (below) |
| `leakageAudit` | The result of the check that no label reached an arm (below) |
| `complete` | `true` only when nothing was excluded, stopped or cancelled |
| `incompleteReasons` | Why `complete` is `false`; empty when it is `true` |
| `arms` | One entry per arm (below) |
| `notes` | Plain-language caveats attached to this report |

**Header**

| Field | Meaning |
|---|---|
| `scannerCommit` | The scanner commit that ran |
| `scannerVersion` | The scanner version |
| `datasetId` | The dataset id |
| `datasetVersion` | The dataset version |
| `datasetHash` | Hash of the dataset manifest |
| `split` | `dev`, `validation` or `sealed` |
| `models` | The models that were run |
| `config` | Repeats, tasks, concurrency, timeout and budget |
| `machine` | The machine profile |
| `startedAt` | When the run began |
| `finishedAt` | When it ended |

**Arm**

| Field | Meaning |
|---|---|
| `id` | The arm id |
| `kind` | `deterministic` or `model` |
| `model` | The model description, empty for a deterministic arm |
| `runs` | How many times the arm ran (a deterministic arm runs once) |
| `tasks` | Per-task statistics (below), only for the tasks the arm ran |
| `economics` | Cost, latency, tokens, timeouts and failures (below) |
| `intelligencePerDollar` | Outcomes per 100 USD (below) |
| `dollarsPer` | Cost per outcome: `truePositive`, `confirmedExploit`, `verifiedFix` |
| `primary` | The one headline statistic per task |

**Detect task**

| Field | Meaning |
|---|---|
| `precision` | Share of reported findings that were real |
| `recall` | Share of real vulnerabilities that were reported |
| `f1` | Harmonic mean of the two |
| `macroF1` | F1 averaged across CWE classes |
| `localizationAccuracy` | Of the findings that hit the right file, the share that also hit the expected span |
| `completion` | Share of attempts that produced a usable answer |

**Falsify task**

| Field | Meaning |
|---|---|
| `balancedAccuracy` | Mean of the true-refutation and true-confirmation rates |
| `falseRefutationRate` | Real vulnerabilities the arm refuted |
| `falseConfirmationRate` | Non-vulnerabilities the arm confirmed |

**Statistic.** Every number above is an object with these fields.

| Field | Meaning |
|---|---|
| `n` | Runs behind the figure |
| `unmeasured` | How many runs had no value for this figure. When every run had none, `n` is `0` and `mean`, `stdev`, `min`, `max` and `ci95` are `null` |
| `mean` | Mean over runs |
| `stdev` | Standard deviation over runs |
| `min` | Smallest run |
| `max` | Largest run |
| `ci95` | 95% interval, or `null` when there are too few independent groups to compute one |
| `representative` | `false` for fewer than three runs |
| `note` | Present only on an empty statistic: `no measured value` |

**Economics**

| Field | Meaning |
|---|---|
| `usd` | Measured spend |
| `latencyMedianMs` | Median attempt latency |
| `latencyP95Ms` | 95th percentile latency |
| `inputTokens` | Input tokens |
| `outputTokens` | Output tokens |
| `timeouts` | Attempts that timed out |
| `failures` | Attempts that failed |
| `unknownCostAttempts` | Attempts whose cost was not reported |

**Intelligence per dollar**

| Field | Meaning |
|---|---|
| `confirmedVulnerabilitiesPer100Usd` | Confirmed vulnerabilities per 100 USD |
| `verifiedFixesPer100Usd` | Verified fixes per 100 USD |
| `truePositivesPer100Usd` | True positives per 100 USD |
| `recallAtBudget` | Recall reached within the budget |

## Guarantees

- **A cost that was not reported is `null` with its reason, never `0`.** `unknownCostAttempts` counts them.
- **No arm sees a label.** The leakage audit runs before any arm does; an entry that fails it is quarantined, named, and the run is marked incomplete.
- **A figure never hides its denominator.** `n` and `representative` travel with every statistic, and an interval is withheld rather than invented.
- **The deterministic baseline is a normal arm.** It runs once and is reported with `representative: false`.

## What this does not do

<!-- limits-verified: 2026-10-19 -->

- **It does not decide a winner.** A report ranks nothing on its own. Routing is a separate, explicit step that refuses a run below the minimum repeat count.
- **It does not use the SARD integration.** The lab's custody rule forbids answer keys, so that requirement is not built and the guide says so.
- **The datasets are small and written for the lab.** The figures describe those cases, not field performance.
- **Model arms depend on a provider.** A provider's behavior can change between runs; `providerVariance` shows the spread, it does not remove it.
