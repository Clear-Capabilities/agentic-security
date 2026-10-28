# Haskell real-code development set

Measures the default scan on real Haskell projects, by hand labels. It exists because the synthetic Haskell suites
(`scanner/test/language/corpora`) are template-generated and score near 100% while the default scan on real projects was
mostly noise. Nothing here is a gate; it is the instrument the precision work was done and checked with.

This directory does **not** hold, read or run the sealed sets (`bench/dag/independent*`, `bench/language-support/corpora/unseen-v4`,
the frozen holdout). The unseen-v3 split is a development set and was used as such.

## The two sets

| Set | Projects (pinned commits in `manifest*.json`) | Haskell files | Lines | Role |
| --- | --- | --- | --- | --- |
| development | gitit, hackage-server, stackage-server, ghcup-hs, cabal2nix, stack, xmonad-contrib, pandoc | 2,166 | 359,000 | fixes were designed on it |
| fresh | ihp, dhall-haskell, hlint, summoner, scotty, ormolu | 2,047 | 197,000 | acquired after the fixes, scanned once, labelled, not tuned on |

`acquire.mjs [--set=fresh]` fetches exactly the pinned commits into `.cache/` (gitignored).

## Protocol (development set)

1. `scan-all.mjs` runs the default scan (deep analysis on, as the CLI does outside CI; no lineage graph; state writes off) and keeps the
   findings located in Haskell files (`results-before/` is the unmodified engine; `scan.mjs --engine=<dir>` runs any engine copy).
2. `sample.mjs` draws the sample: seed **20261026**, strata are the finding's vulnerability class (all path-traversal variants merged,
   capped at 45 so no class dominates), 118 of the 168 flagged sites, then **splits each stratum alternately into a tuning half (64) and
   a verification half (54)** from the seeded shuffle, before any per-site error was looked at.
3. Each sampled site was labelled by reading the code (`build-labels.mjs`; one sentence of reasoning per site), from the behaviour of the
   code only: is attacker-controlled data reachable to the dangerous operation, across a real trust boundary, without effective
   neutralisation. Comments, names and commit messages were not evidence.
4. Fixes were made for classes of error seen in the tuning half. `score.mjs` reports each half separately.

**Limits, stated plainly.** One labeller. Labelling required reading every sampled site, including the verification half, so the
verification half is not blind to the classes that were fixed (several design decisions were informed by sites of both halves). The
fresh set exists for that reason.

## The fresh set

`fresh-worklist.mjs` lists every site flagged after the fixes plus every site the original engine flagged that the engine no longer
flags (so a lost true positive is visible); `build-fresh-labels.mjs` holds the labels (all 222 read, except that 14 of the 121
`unsafe*` boundary notes were read at random and the rest labelled by the same rule); `fresh-score.mjs` scores it.

`results-fresh-before/` is the original engine, `results-fresh-after/` is the engine with the precision fixes (the FIRST measurement,
nothing was tuned on this set before it), and `results-fresh-after2/` is the engine after three follow-up fixes that the fresh
set itself motivated (IHP request accessors, a JSON sniff that read Haskell pragmas as policy, the `unsafe*` notes lowered to
information). `results-fresh-after2` is therefore **not an independent measurement**.

## Results

Numbers are from the runs recorded in this directory (`score.mjs`, `fresh-score.mjs`); the intervals are Wilson 95%.

| | flagged sites | true positives | precision |
| --- | --- | --- | --- |
| development sample, before (118 sites) | 118 | 5 | 4.2% [1.8%, 9.5%] |
| development, tuning half, before | 64 | 4 | 6.3% [2.5%, 15.0%] |
| development, verification half, before | 54 | 1 | 1.9% [0.3%, 9.8%] |
| development, tuning half, after | 10 | 4 | 40.0% [16.8%, 68.7%] |
| development, verification half, after | 4 | 1 | 25.0% [4.6%, 69.9%] |
| development, census of the 19 sites flagged after | 19 | 5 | 26.3% [11.8%, 48.8%] |
| fresh, before (every non-info finding) | 222 | 21 | 9.5% [6.3%, 14.0%] |
| fresh, first measurement after the fixes | 161 | 17 | 10.6% [6.7%, 16.3%] |
| fresh, after the follow-up fixes (not independent) | 45 | 17 | 37.8% [25.1%, 52.4%] |

Read these with the limits above: eight and six projects, one labeller, small counts. They describe these projects.

The first measurement on the fresh set is the honest generalisation figure, and it is modest (9.5% to 10.6%): 112 of its 161
remaining flagged sites were `unsafe*` boundary notes that an existing test pins at `low`. Four true positives were **lost**
(three distinct flaws: a command injection and two request-indexed `!!`, all in IHP's own development IDE, found before only because
a helper looked uncalled; after the fix the helper is called and the framework's request accessor, a project function in this
repository, is not a known source).

## Tools

| File | Purpose |
| --- | --- |
| `scan.mjs`, `scan-all.mjs`, `quick.mjs` | scan a project / every project / any directory |
| `sample.mjs`, `show.mjs`, `build-labels.mjs`, `labels.json`, `labels-remainder.json`, `score.mjs`, `remaining.mjs` | the development-set protocol |
| `fresh-*.mjs`, `fresh-labels.json` | the fresh set |
| `comment-invariance.mjs` | scans a project as written, with comments blanked and with lying comments; any difference (now including the reachability verdict) is an engine bug |
| `reach-crosstab.mjs` | cross-tabulates `finding.reachability.status` against every label; exits 1 if a true positive is in `unreachable-in-project`. Its committed output and what it showed are in `results/README.md` |
| `LABEL-CHANGES.md` | the log of label corrections (empty, and what that does and does not establish) |
| `compare-splits.mjs` | before/after of the synthetic development splits |
| `fix-real.mjs` | the fix preview over the real-code true positives |
| `irdebug.mjs`, `irdump.mjs`, `reach.mjs` | IR and reachability diagnostics |

The real-code numbers are also a gate: `bench/haskell-precision` (`npm run bench:haskell-precision:check`) compares them for equality against a recorded
baseline, and fails on a label edit.

## Second labeller (fresh set, 2026-10-28)

The fresh set's 222 sites were labelled a second time by a different LLM, in two blind sessions of 111 sites, given only project, file, line and vulnerability class (`fresh-labels-second.json`; `second-labeler-score.mjs` reproduces the numbers below). The first labeller's labels were not shown to it.

- Agreement 206 of 222 (92.8%); Cohen's kappa 0.40 on true positive against anything else. The sites are 94% false positives, so percent agreement flatters; kappa is the honest figure and it is moderate, not high.
- Of the 16 disagreements, 12 are one policy question: the first labeller called a site a true positive when the code is an example program (`scotty/examples/`) or a test server (`dhall-test-server`); the second did not count code that is not part of the shipped library or program. Under the second labeller's reading, the fresh set has 7 true positives rather than 21, so the engine's recorded fresh precision (17 of 45) would be about 7 of 45 if it were scored by that policy. Which policy is right is a product decision (an example that teaches an unsafe pattern is not nothing), and it has not been made here.
- The other 4 disagreements are readings of the code: one unbounded integer parse in IHP (second labeller: true positive, first: false positive), one deferred body read (first: true positive, second: unsure), and two partial-function sites in IHP's local development IDE (first: true positive, second: false positive).
- Limits: one pass, no adjudication; the first session used 7 tool calls for 111 sites, so how deeply it read is not established; neither labeller was given a rule on example code. The sealed independent set was not touched. These numbers are not a claim that the engine's precision improved or regressed, only that the recorded fresh precision depends on a scope policy that was never written down.
