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

To add independent cases:

1. Put the source under `cases/<family>/`, with no hint of its verdict in the file.
2. At least two reviewers label each case without seeing the scanner's verdict, one file each in `reviews/<name>.json` with `"blind": true` (the format is in the header of `adjudicate.mjs`). Each label names `family`, `group` (a vulnerable case and its fixed counterpart share a group and so a split), `split`, `origin` (a published fix, sanitized real code, a second author; never `author-seed`) and `label` (`vulnerable`, `safe` or `unsure`).
3. `node bench/haskell-core-families/adjudicate.mjs` reports agreement, Cohen's kappa and every unresolved case (a disagreement, an `unsure`, a single reviewer). `--write` adds only the unanimous cases to `manifest.json`; an unresolved case is never added, so it can never act as a benign control.
4. `node bench/haskell-core-families/adjudicate.mjs --freeze` records digests of the manifest and of `runner.mjs`. Freeze before tuning. The runner refuses `--split holdout` without a freeze or after either file changed, and appends every holdout run to `holdout-uses.jsonl`, so repeated use of the holdout shows.

Recall and the safe-clean rate are reported with a 95% Wilson interval.

## What the seed run showed (harness check only)

On the 36 seed cases the engine reported a finding for every vulnerable case except one weak-hash case (`digest = hash` with a `Digest MD5` signature and no visible use of the digest, which the engine deliberately reports only as an info note, so that label is itself doubtful), and reported two findings on safe cases: a request whose host is fixed while a value goes into the query string (the engine reported it at `info`, but so are the vulnerable cases whose source is a command-line argument, so severity is not used to decide what counts), and a path built with `takeFileName`. The first is now refuted by the engine whenever the whole destination is a literal and the client reaches only the query, headers, body, method or authentication (a rule about the HTTP API, pinned both ways in `scanner/test/haskell/haskell-unseen-v5-shapes.test.js`, not about this case). The `takeFileName` flow is labeled sanitized and carries the engine's provably-safe verdict, so the runner does not count it as a reported vulnerability. These are leads for the detection work, to be re-checked on independent cases before any of them is treated as a defect.
