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
| (none recorded before 2026-11-02) | | | | | | |
| 2026-11-02 | development-remainder | `xmonad-contrib:XMonad/Prompt/DirExec.hs:101`, `Man.hs:76`, `OrgMode.hs:274` (path-traversal), `DirExec.hs:86` (partial function), `hackage-server:.../BlobStorage.hs:217` (path-traversal) | (unlabelled) | FP | sites the 0.195.11 engine flags for the first time, because the xmonad and hackage preludes' re-export chains now resolve to the directory, file and Prelude functions; each reads a path from the user's own configuration, the operator's machine or the server's own temporary file (reasons in `labels-remainder.json`). No existing verdict changed. | yes: the sites were found by the scan, then read |
| 2026-11-02 | fresh | `ihp:ihp-ide/IHP/IDE/SchemaDesigner/SchemaOperations.hs:542` (partial function) | (unlabelled) | TP | a request-indexed `!!` in a schema-designer helper, the same flaw as the two Enums sites already labelled TP, reached since 0.195.11 through request text handed to the helper. No existing verdict changed. | yes |
| 2026-11-02 | fresh | `ihp:ihp-ide/Test/ServerSpec.hs:14` (XSS) | (unlabelled) | FP | an echo application in the framework's own hspec suite, test code with no HTML content type, flagged since 0.195.11 when the IHP prelude chain resolved its names. No existing verdict changed. | yes |
