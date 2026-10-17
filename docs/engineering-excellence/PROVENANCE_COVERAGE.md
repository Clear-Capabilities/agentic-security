# Finding provenance: coverage, causes and what was fixed (E7-02)

Finding provenance names the commit that introduced a finding. This page records how often that succeeds on this repository's own code, why it does not when it does not, and which causes were fixed.

## How coverage is counted

`posture/provenance/coverage.js` keeps two kinds of non-attribution apart, because one is a gap in the pipeline and the other is a property of the repository.

| Bucket | Meaning |
|---|---|
| attributed | `complete`: a commit introduced it. `uncommitted`: it is in the working tree and in no commit yet (resolved, but to no commit) |
| ineligible | git ignores the file; it is generated code; git does not track it; or there is no usable history (not a repository, no commits, a shallow clone that cut the history short) |
| eligible, unattributed | the pipeline could have attributed it and did not, with a reason: `budget_exhausted`, `project-wide` (a whole-project analysis that a single-file replay cannot reproduce), `unconfirmed`, `not_available`, `error` |

`eligibleRate` is attributed over (attributed plus eligible unattributed). `overallRate` is attributed over everything. Both are reported. The 95% target is aspirational and its status is `met`, `not_met`, or `insufficient_eligible` when there are fewer than 30 eligible findings. No author or date is invented for a finding without evidence.

## Baseline

`npm run ee:provenance-baseline -- --deep` over `scanner/src` with a 20 minute provenance budget (so the result does not depend on how busy the machine is). Data in `data/provenance-coverage-deep.json`; the same run before the fixes below is in `data/provenance-coverage-deep-before-fixes.json`.

| | Before | After |
|---|---|---|
| findings in scope | 469 | 470 |
| attributed | 384 | 393 |
| ineligible (untracked) | 1 | 1 |
| eligible rate | 82.1% (384/468) | 83.8% (393/469) |
| unattributed: project-wide analyses | 64 | 64 |
| unattributed: unconfirmed | 20 | 11 |
| unattributed: not available | 0 | 1 |

The 95% target is **not met**. The scan before and after differ by one finding because the working tree changed between the two runs.

Where the remaining 76 are: 64 are findings made by whole-project passes (a state-machine check, a concurrency check, a specification-drift check, a cross-file prompt check). Replaying one file at an old commit cannot reproduce them, so the history walk never confirms them. If those were attributed, the eligible rate would be 457/469, 97.4%. That is the next piece of work: a project-scoped replay for those detectors, whose cost on a large repository has to be bounded.

## What was fixed, and the evidence

1. **Deep-layer findings were never confirmed.** Replay re-ran the detectors without the deep (taint) layer, so a finding from that layer could not appear at any commit and ended `partial` ("predicate-never-confirmed-in-candidates"). Replay now enables the deep layer for findings from it. A flaw added by one author in a plain two-commit history went from `partial` with no origin to `complete` with the correct commit and author.
2. **Renamed and moved files lost their origin.** The history walk found the commit that introduced the code but looked for the file under its current name at that commit, where it did not exist. It now follows the file back through renames (`git log --follow`) and reads the old content under the current name so the finding keeps its identity. The provenance accuracy benchmark's rename scenario newly matches its ground truth (13 of 13, baseline 12 of 13, re-baselined); two existing tests that pinned the old limitation ("rename detected, not followed") were rewritten to assert the fixed behaviour, with real scan findings in place of hand-written ones.
3. **One `git blame` per line.** A file with many findings started a blame process per finding and per evidence line, and on large repositories that used up the 60 second provenance budget (`budget_exhausted` on 47 of 559 findings in one run of this repository's own scan). After a file's first question the whole file is blamed once and later lines come from memory. On a 23-finding sample blame processes fell from 109 to 76 and the provenance stage by about 12%, with identical statuses (`data/provenance-blame.json`). The gain is modest because blame is about a quarter of the git processes a scan starts; `git show`, `rev-parse` and `log -L` dominate the rest.

## Scenarios with tests

`scanner/test/engineering-excellence/e7-02-provenance-coverage.test.js`, each in a real temporary git repository with a real scan: multi-author history (the origin is the introducing commit's author, not a later editor), rename, move into a directory, rebase (the rewritten commit with the original author), uncommitted work (no origin invented), a shallow clone (not `complete`, classed as history-unavailable), ignored, generated and untracked files, a repository with no history, a corrupted repository (a status and a reason, no exception), the target arithmetic, and per-file blame equal to per-line blame.

## Known limits

- When a later commit edits the text of the vulnerable line itself (even only a trailing comment), the finding is credited to that edit, because the finding's identity includes the line text. A test pins this so a change is deliberate. An attempt to compare findings without trailing comments did not fix it and was removed.
- Timing results were taken on a machine that was running other work.
- Only this repository was measured. Other repositories, languages and very large histories were not.
- Cross-repository lineage, AI authorship and provider enrichment were not touched.
