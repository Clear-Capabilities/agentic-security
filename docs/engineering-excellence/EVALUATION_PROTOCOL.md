# Independent evaluation protocol

This is the protocol for measuring the engine on code this project did not write. It is executable: every rule below is enforced by code and by a test under `scanner/test/engineering-excellence/`. It is separate from the curated regression net (`bench/cve-replay`), which is a regression net and cannot support an accuracy claim.

## Population

`bench/independent/manifest.json`: advisory-labelled upstream code, one entry per published advisory with a single fix commit. The nine provenance facts per entry, and which of them each entry carries, are in [DATASET_PROVENANCE.md](DATASET_PROVENANCE.md). Nothing is filled in by guesswork: a missing fact is counted as missing.

## Splits (frozen before any result was observed)

`bench/independent/splits.json` assigns every entry to `dev` (60%), `validation` (20%) or `sealed` (20%). Entries are grouped first (same upstream project, same advisory or CVE id, same commit; transitively) and a whole group goes to one split by a salted hash, so no related variant straddles the line. The assignment is written down and hashed; later runs read it and never recompute it, so a growing manifest cannot move an entry, and an entry that would join two splits is quarantined instead.

The older per-entry-id slice (`isHeldOut` in `runner.mjs`) is demoted to development use: it put 91 of 424 repositories on both sides. It stays only so past development numbers can be reproduced.

There is no time split, because the manifest carries no advisory publication date (only the time each entry was mined). That limit is recorded in `splits.json`.

## Access rules

- Development and validation entries may be scored freely, and are the only ones a run can select (`stratifiedSample` refuses `sealed`).
- The sealed split is read only through `selectEntries(..., { final: true, reason })`, which writes a ledger line. Scoring it is a one-way act; nothing tuned after seeing it is a held-out result.
- Model-bound prompts are built only from the scanned source. A test fails if any module on the scanning path names a benchmark root, a label file or an answer key, and the custody guard refuses a prompt carrying an advisory id, an advisory sentence or a benchmark name.

## Scoring

`bench/independent/scorer.mjs` is a pure function from per-entry rows to a report. Three definitions are kept apart and only the first may be quoted:

| Definition | Meaning |
|---|---|
| `localized` (the claim) | a matching finding landed on code the fix changed, within a three-line window |
| `file` (diagnostic) | the labelled CWE appeared in the advisory's files |
| `wide` (diagnostic) | the labelled CWE appeared anywhere in the package |

Each reports true and false positives and negatives, precision, recall and F1 with numerator and denominator, per language, per CWE and per split, with micro, macro and size-weighted F1. Fixed-version pressure (findings of any family on the fixed side) and fix survival are reported beside them.

Denominators reconcile exactly: entries in scope = scored + unscored + unaccounted. An unscored entry (not fetched, scan failure, timeout, parse failure, advisory file absent, unusable label) is in no denominator and is never a miss or a negative; it is counted by cause. A report whose denominators do not reconcile is not quotable.

A group with fewer than 30 scored entries is `insufficient_population`: counts are shown, no rate is headlined. Intervals are Wilson for a single proportion and a grouped bootstrap (whole repositories are the resampling unit) for F1, precision and recall; below ten independent groups the interval is `unmeasured`.

## Running it

```text
node scripts/engineering-excellence/independent-baseline.mjs --plan --per-language 40 --chunk 20
node scripts/engineering-excellence/independent-baseline.mjs --run <runId>
node bench/independent/forensics.mjs --run <runId>
node bench/independent/realcode.mjs approve --run <runId> --reason "<why>"
npm run bench:realcode:check          # release tier
npm run bench:realcode:check:quick    # diagnostic tier
```

The engine measured is the committed HEAD, checked out into a throwaway worktree, so editing the working tree while it runs cannot change what is measured. The measurement identity (commit, bundle digest and its sidecar, lockfile, configuration, corpus digest, toolchain) is written with the result, and a run that is not on a clean tree or has a bundle that does not match its sidecar says so and why.

## Regression policy

Approving a baseline writes floors once: for each language with enough scored entries, the lower bound of the 95% interval on the baseline's localized recall and precision. A floor is never edited; a successor is recorded beside it with a reason. `check` returns one of `passed`, `failed`, `blocked`, `insufficient_population` or `unmeasured`, and only `passed` is green. A missing run is `unmeasured`, a run that does not reconcile or is mostly unscored is `blocked`, and a language with too few entries is not compared and not green. The `quick` tier is diagnostic and fails the build only on a blocked run.

## What this does not establish

The labels are advisory-database labels, not adjudicated by people who read the code; the matching rule credits one CWE per entry; the scope is the package containing the fix, so recall is a lower bound; selection is biased towards well-maintained projects that write good advisories. No claim of the 80% per-language F1 target is made or implied by anything here.
