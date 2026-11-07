# Haskell core-family benchmark

Scores the six core families on their own: SQL injection, command and argument injection, path traversal, SSRF, sensitive data exposure, and security-sensitive cryptography. A family reports its own recall and its own false-positive count, so strength in one cannot hide an unsupported one.

`node bench/haskell-core-families/runner.mjs [--split dev|holdout] [--json] [--min-recall 0.8]`

## What counts

- **detected**: a vulnerable case has an actionable finding (disposition `confirmed` or `needs-review`) of the family's CWE set in its file.
- **confirmed**: a detected case whose disposition is `confirmed`. A detector alone cannot confirm, so this is normally 0 until execution proof or a reviewer verdict exists. It is reported separately and never substituted for `detected`.
- **miss**: every vulnerable case that is not detected, including one with no result.
- **false positive**: a safe case that has an actionable finding of the family.

## What is and is not in this directory

The 36 cases here are **author-seed**: written by the engineer who works on the scanner, to prove the harness runs end to end. They are not the independent cases the requirement asks for (25 vulnerable and 25 safe per family, 300 in all, labeled by reviewers who have not seen the scanner's verdict, with a holdout split by code origin). The runner counts only cases whose `origin` is not `author-seed` toward that requirement, so every family reports `insufficient-cases` and none is claimable. **No recall or precision figure from this directory is a result.** Tuning the engine against these cases would also be tuning against its own author's idea of the answer.

To add independent cases: put the source under `cases/<family>/`, add an entry to `manifest.json` with `label`, `group` (a vulnerable case and its fixed counterpart share a group and a split), `split` and an `origin` naming where it came from (a published fix, sanitized real code, a second author). Freeze the manifest and the definitions above before tuning.

## What the seed run showed (harness check only)

On the 36 seed cases the engine reported a finding for every vulnerable case except one weak-hash case (a hash chosen by a type annotation, `Digest MD5`), and reported two findings on safe cases: a path built with `takeFileName` and a request whose host is fixed while a value goes into the query string. These are leads for the detection work, to be re-checked on independent cases before any of them is treated as a defect.
