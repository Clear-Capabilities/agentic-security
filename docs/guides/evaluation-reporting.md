# Evaluation reporting, miss diagnosis and release gates

How to turn an evaluation run into figures a reader can check, how to find out why a development miss was missed, and how the
release gates decide. Everything here is offline tooling in `scanner/src/posture/evaluation/`; none of it runs during a scan.

**No real adjudicated population and no real sealed set exist in this repository.** Every real-code gate therefore reads
`insufficient-population` or `unmeasured`. The generated and synthetic populations used by the tests exercise the arithmetic and
describe no real code. Do not quote any figure from them as engine accuracy.

## Honest accuracy report (`report.js`, `interval.js`)

```
node scripts/evaluation.mjs report --protocol <protocol.json> --score <score.json> --population sealed --run <run.json>
```

A report states, in this order: the definitions; raw TP, FP, FN, TN; precision, recall and F1 by language and by family; micro
(pooled counts) and macro (mean of per-language F1) aggregates; completion with its own interval; and what was NOT scored and why
(unlabeled targets, candidate labels, findings no adjudicated label accounts for, negatives whose scan failed).

- **Intervals.** Two documented 95% methods, registered in the protocol before any result is observed. `grouped-bootstrap-95` resamples
  target GROUPS (the union-find groups that keep forks, paired commits and near-identical templates together), percentile method, 2000
  resamples, with a seed derived from the protocol hash so nobody picks a seed after seeing a result. `wilson-95` covers the completion rate.
  With fewer than 10 independent groups the interval is `unmeasured` with the reason, never a degenerate range.
- **Small strata.** A language below the protocol's positive floor, or a family below 30 positives, is `unmeasured`: raw counts are
  published, a descriptive figure is kept apart, and no interval is given.
- **Deduplication.** Alerts that chain within the matching line window in one file and family are one root cause for SCORING (one false
  positive, not five). The operational alert burden is reported separately (`operationalAlertBurden`): raw alerts a reviewer reads,
  root causes, and the duplicates collapsed. Deduplication never hides burden.
- **Populations.** A report carries exactly one of `regression`, `development`, `sealed`, `operational`; there is no function that merges
  two, and `checkPopulationsDisjoint` refuses a target in more than one.

## Cost accounting (`economics.js`)

```
node scripts/evaluation.mjs economics <ledger.json>
```

A ledger is a list of spend entries (`model`, `tool`, `cache` in USD; `human-review` in MINUTES) with an optional outcome and root cause.
Kinds are reported side by side and never summed; minutes are never turned into dollars. An entry with no amount is unmeasured, not zero,
and makes the ratios a lower bound. Cost per confirmed defect and per validated fix divides ALL machine spend (failed, refuted and
duplicate attempts included) by DISTINCT independently confirmed root causes, so a defect found three times is one defect.

## Why was it missed (`why-missed.js`)

For a labelled DEVELOPMENT miss the instrument names the earliest stage that lost it: `scan-execution`, `parser-ir`, `source-modelling`,
`propagation`, `sink-modelling`, `filters`, `suppression`, `deduplication` or `attribution`, or `unknown` with the reason. It uses the
engine's own diagnostics: the suppression ledger (now including guard-recognized drops, each with the finding id, CWE, family, line
and the guard line that dominated), dedupe stage evidence, the sources and sinks the engine recognised, and how the IR fared on the file.
A candidate observed downstream proves the earlier stages worked, so those are checked first. Diagnostics are collected only for the
development split; a sealed target is refused. `compareMisses` gives the before and after stage counts, names each recovered defect and the
stage that lost it, and reports any new false positive instead of netting it away.

`AGENTIC_SECURITY_STAGE_EVIDENCE=1` turns the stage evidence on in the engine. It only records; the findings of a scan are identical with it on or off.

## Release gates (`gates.js`, `release-gate.js`)

```
node scripts/evaluation.mjs release-gate --protocol <p> --score <s> --run <r> --labels-dir <d> --labels-hash <h> --ledger <l> --key <pem> --out <signed.json>
node scripts/evaluation.mjs verify-gate <signed.json> --public-key <pub.pem>
node scripts/evaluation.mjs detector-digest
```

The custodian signs an AGGREGATE verdict (gate states and population counts, no per-case outcome), so detector work can iterate on
aggregate gate states and never on which sealed case failed. The signature is Ed25519 with a local custodian key: tamper evidence, not
independent certification, and the report says so.

- **Population.** `pass` needs the registered minimums (100 real adjudicated sealed positives and negatives per core language, 30 positives
  per family). Synthetic, development-split, candidate and short populations read `insufficient-population`. A smaller convenient sample never passes.
- **Quality.** The preregistered thresholds plus the per-language F1 lower bound from the grouped bootstrap. Thresholds are read from the
  frozen protocol; a caller cannot supply or relax one.
- **Integrity gates.** Zero answer-key leaks (any quarantined workspace fails), and an intact denominator (every sealed target has its outcomes,
  the scored positives equal the adjudicated sealed positives). A score from another protocol is rejected outright.
- **Baseline.** The last passing evaluation in the ledger is the baseline; an engine that clears the thresholds but scores below it fails.
  The ledger is hash-chained and its head is signed by the custodian, so an edited baseline, or a chain rebuilt after editing one, does not verify.
- **After a detector edit.** Every sealed evaluation is recorded with a digest of the detector source (`detector-digest`; the evaluation
  tooling is excluded) and the sealed targets it consumed. A different detector digest on the same sealed targets is blocked with
  `fresh-sealed-population-required`: those targets have been seen. The old result stays in the ledger as an evaluation-only artifact.

Further reading: `docs/guides/bakeoff-recipe.md`, `docs/guides/miniature-reproduction.md`, `docs/guides/engine-mechanism-evidence.md`.
