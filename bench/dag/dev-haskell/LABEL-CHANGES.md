# Label changes

`build-labels.mjs` says a label is never edited after seeing scanner output except to correct a clear mistake, and that such a correction is logged
here. This file did not exist, so that promise had nothing behind it. This is the log, started now.

## What can be established

- The development labels (`labels.json`, `labels-remainder.json`) and the fresh labels (`fresh-labels.json`) entered the repository in one commit,
  `3799a8e8` (2026-10-26). Git shows no change to any of them, or to `build-labels.mjs` / `build-fresh-labels.mjs`, since.
- **No correction is recorded below because none was recorded at the time.** That is not evidence that none was made: an edit before that commit was not
  logged anywhere. Read the labels as "labelled by one reader, with unlogged corrections possible before 2026-10-26".

## What is enforced from now on

`bench/haskell-precision/baseline.json` records a digest of each label set (`labelsDigests`), and `npm run bench:haskell-precision:check` fails when a
label verdict differs from the one recorded. A label edit therefore cannot go unnoticed; to make one deliberately, record it here (site, old verdict,
new verdict, the evidence, and that the scanner output was or was not seen) and then re-record the baseline with `npm run bench:haskell-precision:update`.

## Log

| date | set | site | old | new | evidence | scanner output seen first? |
| --- | --- | --- | --- | --- | --- | --- |
| (none recorded) | | | | | | |
