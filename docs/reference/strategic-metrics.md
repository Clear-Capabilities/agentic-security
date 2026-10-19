# Strategic metrics: contract

<!-- seo: title="Strategic metrics contract: Assurance Coverage, Evidence Conversion and Verified Remediation Rate" description="How each strategic metric is counted, the fields of the metrics report, and why every figure carries its numerator, its denominator and its basis." -->

**Maturity:** Preview

Three numbers a scan already carries the inputs for, reported with the count behind each. `agentic-security metrics` prints them for the last scan and the recorded fix attempts, and [the scorecard](../SCORECARD.md) publishes them for a reference project. A compatibility test (`scanner/test/contracts/strategic-metrics.contract.test.js`) holds the report to the tables below in both directions, so a field cannot be added or removed without changing this page and the report's `version` in the same commit.

```bash
agentic-security metrics [path] [--format text|json]
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Reported |
| `1` | The last scan failed its integrity check, so no metric is reported from it |
| `2` | No scan to report on, or an unknown `--format` |

## The report

`agentic-security/strategic-metrics`, version 1.

**Report**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/strategic-metrics` |
| `version` | `1` |
| `assuranceCoverage` | Of the analysis requested, how much finished |
| `evidenceConversion` | Of the findings, how many reached stronger evidence |
| `verifiedRemediationRate` | Of the fix attempts, how many reached the strongest verification tier |
| `securityLearningRate` | Always `not-measured`, with the reason |

**Assurance Coverage**

| Field | Meaning |
|---|---|
| `status` | `measured`, `partial` (one component could not be counted) or `unmeasured` |
| `reason` | Present when a component could not be counted: which one, and that the scan did not report it |
| `files` | `numerator`, `denominator`, `percent`, and what was `skipped`, `unanalysed` and `timedOut`; or `null` |
| `analyzers` | `numerator`, `denominator`, `percent`, and what `failed`, `timedOut` and was `skippedByPolicy`; or `null` |
| `percent` | The lower of the two components' percents, or `null` |
| `scanStatus` | The scan health status, such as `complete` or `partial`, or `null` |

**Evidence Conversion**

| Field | Meaning |
|---|---|
| `numerator` | Findings that reached `corroborated` or stronger |
| `denominator` | All findings |
| `percent` | The ratio as a percent with one decimal, or `null` with no findings |
| `byState` | How many findings reached each state: `single-signal`, `corroborated`, `taint-confirmed`, `execution-proven` |
| `basis` | What was counted, in words |

**Verified Remediation Rate**

| Field | Meaning |
|---|---|
| `numerator` | Attempts that passed the re-scan, the project tests and the independent attack replay |
| `denominator` | All recorded attempts |
| `percent` | The ratio as a percent with one decimal, or `null` with no attempts |
| `disappearedOnly` | Attempts that satisfied only the re-scan, which is also what deleting the code produces |
| `basis` | What was counted, in words |

## How each figure is counted

- **Assurance Coverage** reads the scan's own health record. A file counts as completed when it was scanned and did not time out; an analyzer counts as completed when it ran to the end. The headline is the lower of the two percents, so a complete analyzer set cannot hide files that were never read. A count the scan did not report makes that component `null` and the status `partial` or `unmeasured`. It is never zero.
- **Evidence Conversion** puts each finding at the strongest state it has evidence for: `execution-proven` (a recorded execution proof), `taint-confirmed` (the taint engine found the path), `corroborated` (two or more different analyzers reported it), otherwise `single-signal`. The numerator is every finding above `single-signal`. The report names the state each finding reached, so a high rate cannot hide that no finding was executed.
- **Verified Remediation Rate** counts an attempt as fully verified only when the finding disappeared on re-scan, the project's tests ran and passed, and the independent attack replay confirmed the hole shut.

## Guarantees

- **No figure appears without its numerator and denominator.** An empty denominator gives `percent: null`, never 0% or 100%.
- **A quantity the scan did not report is unmeasured, not zero.**
- **The Security Learning Rate is not reported as a number.** Nothing measures it independently of the rule compiler's own corpus.
- **Nothing is read from a scan that failed its integrity check.**

## What these metrics do not do

<!-- limits-verified: 2026-10-19 -->

- **They describe one scan.** A single scan's coverage says nothing about the next one. The scorecard's figures describe a small reference project and are not field averages.
- **Evidence Conversion is not accuracy.** A finding at `single-signal` can be real, and a corroborated one can be wrong. It measures how much independent evidence exists, not whether the finding is true.
- **The remediation rate is a lower bound.** Some vulnerability classes have no attack replay, so no attempt for them can reach the strongest tier. `disappearedOnly` shows how much of the rest rests on the re-scan alone.
- **Fix attempts are what was recorded on this machine.** An attempt made elsewhere is not counted.
