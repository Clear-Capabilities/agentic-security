# Evaluation policy card

What the evaluation instrument measures, on what, with which protections against fooling itself, and where it is known to fail.
It describes the tooling in `scanner/src/posture/evaluation/` and the populations in this repository. For the figures and their
status (historical, new, aspirational) read [measurement status](measurement-status.md); this card does not repeat them as claims.

**Status: machinery, not evidence.** No sealed, independently adjudicated population exists here, so no real-code gate has been
met and every one reads `insufficient-population` or `unmeasured`.

## Dataset provenance

| Population | Where it comes from | Who labelled it | What it can support |
|---|---|---|---|
| Independent record | Upstream packages at the parent of an advisory's fix commit (`pre/`) and at the fix commit (`post/`), implementation files only | The advisory database assigns the CWE; no one here chose file, bug or label. No second human review is recorded. | A weak, narrow measurement of one older engine in one configuration. See [measurement status](measurement-status.md). |
| Curated regression corpus | Fixtures written in this project, each admitted only when it scores correctly | The people who write the detectors | Regression protection. Not accuracy. |
| Synthetic evaluation suite | Three authored files in [evaluation-synthetic](../../scanner/test/fixtures/evaluation-synthetic) | The tool's developers | Exercising the freeze, staging, scoring and gate path. |
| Deployment ablation | Seven authored cases, each deployed two ways (14 instances) | The tool's developers | A mechanism check. One case exists because an earlier rule lost a defect on it, so the set is not blind to the rule. |
| Invariant benchmark | Fifteen authored applications (8 defective, 7 valid) | The tool's developers | A mechanism check. Frozen and pinned. |

Every synthetic population is flagged `synthetic: true` in its protocol and report, and the real-code gates refuse to count it
toward any minimum. Matching on the independent record is by CWE only, on purpose: scoring on the engine's own vocabulary would
grade it against words it chose.

## Leakage controls

| Control | What it does | Where it is tested |
|---|---|---|
| Frozen protocol | Thresholds, matching rule, denominators and split membership are hashed. Changing any of them after a result is bound to the protocol is refused (`POST_RESULT_CHANGE`); the only way forward is a new, versioned protocol. | [protocol tests](../../scanner/test/evaluation/protocol.test.js) |
| Grouped splits | Forks, paired commits, shared advisories and near-identical templates stay on one side of a split, by union-find over those links. | [grouping tests](../../scanner/test/evaluation/grouping.test.js) |
| Label custody | Only a custodian role writes or reads the label store. A worker or the engine never sees a label. | [custody tests](../../scanner/test/evaluation/custody.test.js) |
| Workspace audit | Advisory prose, evidence references, benchmark names, fixed-source hints and answer-key file names are kept out of anything the engine or a prompt sees; a leaking tree is quarantined and recorded, never scanned. | custody tests |
| Answer-key isolation | Code that reads benchmark answer-key shapes lives apart and is off by default. | [scanner/src/sast/CLAUDE.md](../../scanner/src/sast/CLAUDE.md) |
| Sealed re-use | A sealed target consumed by an evaluation is not reusable for a different detector digest (`fresh-sealed-population-required`). | [release gate tests](../../scanner/test/evaluation/release-gate.test.js) |

These are pattern checks over known terms, not proof against a paraphrase. Process-level read denial of the label directory is the
sandbox boundary's job, and it reports `blocked` where the host cannot prove the control.

## Supported strata

A stratum here is a language, a vulnerability family or a population (regression, development, sealed, operational). The report
publishes raw counts first. A language below the protocol's positive floor, or a family below 30 positives, is `unmeasured`: counts
are shown, a descriptive figure is kept apart, and no interval is given.

**No stratum is supported today.** The minimums for a pass are 100 real, adjudicated, non-synthetic sealed positives and 100
negatives per core language and 30 positives per family. This repository has none. The nine core languages are JavaScript and
TypeScript, Python, Java, Kotlin, Go, Ruby, PHP, C# and Rust; Haskell and Nix are measured separately in the
[language support registry](../language-support.md). Rust has no entries in the independent record.

## Denominators

- A rate is always written as a count over a denominator, and a percentage never appears without them.
- A known positive whose scan timed out, failed, was unavailable or was quarantined is a **miss** in end-to-end scoring. A
  conditional-on-completion figure may be shown beside it and never instead of it.
- A target no adjudicated label accounts for is `unlabeled-target`; findings no label accounts for go to a review queue and
  `unscored`, with counts and reasons. They are not silently counted as false positives.
- False positives are counted only on adjudicated negatives. Repeated alerts for one flaw count as one false positive for scoring,
  and the raw alert burden is reported beside it so deduplication never hides what a reviewer reads.
- A report carries exactly one population. Nothing merges two, and a target may not appear in more than one.

## Uncertainties

Two methods are registered in the protocol before any result is observed. The grouped bootstrap (95% percentile interval, 2000
resamples over target groups, seed derived from the protocol hash so no one picks a seed after seeing a result) covers precision,
recall and F1. The Wilson interval covers completion rate. With fewer than 10 independent groups the interval is `unmeasured`
with the reason, never a degenerate range. The deployment ablation uses a simpler paired case bootstrap and says so; with seven
cases its intervals are wide and exploratory. The historical independent record has no interval.

## Economics

Cost is accounted by kind, never summed across kinds: model, tool and cache in dollars, human review in minutes. An entry with no
amount is unmeasured, not zero, which makes every ratio a lower bound. Cost per confirmed defect and per validated fix divides
**all** machine spend, failed and duplicate attempts included, by **distinct** confirmed root causes. No cost per confirmed defect
has been measured on real code in this repository.

## Known failure modes

| Failure mode | Effect | Mitigation or status |
|---|---|---|
| Low recall on real code | The independent record found 7.2% of the labelled weaknesses. 737 of 920 misses produced no finding at all. | Open. See [measurement status](measurement-status.md) and [engine mechanism evidence](engine-mechanism-evidence.md) for what changed on a synthetic development suite. |
| Hidden by downstream filters | 162 misses had a finding that a pragma, sanitizer, rule or guard window then suppressed. | Reported by stage in the why-missed instrument. |
| Pattern-only configuration | The one real-code record used it, so it says nothing about the deep taint configuration. | Re-measurement needs a population and about half an hour of scanning, and has not been done. |
| Synthetic suites are not blind | Authors wrote cases knowing the engine; one deployment case was added because a rule failed on it. | Every figure is labelled synthetic and excluded from gates. |
| Labels unreviewed | The independent labels come from advisories with no second human review recorded. | A real gate needs two distinct non-proposer reviewers and non-model evidence. |
| A label can claim review that did not happen | The tooling validates that a label says it was independently adjudicated, not that it was. | Custody and reviewer identity are the operator's responsibility. |
| Model-assisted layer unavailable | Without an endpoint the layer is recorded `unavailable` and counted as a miss. | Stated in every run. |
| Detector change after sealed use | The sealed targets are then consumed. | Blocked until a fresh sealed population exists. |

## Reproducing this card

The bounded, offline commands are in [offline reproduction](offline-reproduction.md). Related: [evaluation reporting](evaluation-reporting.md),
[bake-off recipe](bakeoff-recipe.md) and the [routing policy card](routing-policy-card.md).
