# Haskell real-code precision gate

`npm run bench:haskell-precision:check` (in `scanner/`) makes real-code Haskell precision a gate. Before it, nothing in any script, CI job or release
check ran the real-code sets, so a precision regression was invisible, which is how the layer-recall table went stale once already.

## What it compares, and why for equality

It records what the engine does at every hand-labelled site of the development and fresh sets (`bench/dag/dev-haskell`: 345 labelled sites, 14 pinned
projects) and compares for **equality** against the committed `baseline.json`. A regression fails. So does an improvement nobody recorded: a floor that
is silent on a rise leaves the published numbers stale (the lesson `bench/layer-recall` already paid for). A deliberate change is re-recorded with
`npm run bench:haskell-precision:update`, reviewed like any other diff.

| file | what it is |
| --- | --- |
| `baseline.json` | per-set aggregates (flagged, true and false positives, lowered to `info`, the cross-tab by reachability status), a whole-report census per project, and a digest of each label set |
| `measurements/development.json` | what the engine reported at each labelled site when the baseline was recorded: severity, reachability status, original severity, parser |
| `runner.mjs` | the gate |

## The checks, cheapest first

1. The label files are the ones the baseline was recorded against (a digest per label set). Labels are the answer key.
2. The stored measurement recomputes to exactly the committed aggregates. A hand edit of either file fails here. This and the next check run
   everywhere, including a hosted runner with no clones.
3. Invariant: no site labelled a **true positive** may be in `unreachable-in-project`. It cannot be recorded either.
4. **Live**, when the 14 pinned clones exist (`node bench/dag/dev-haskell/acquire.mjs` and `... --set=fresh`): a real default scan of every project,
   compared site by site with the stored measurement, plus the whole-report census (so a new flagged site at an unlabelled place is also a difference).
   When the clones are absent the output says `live: skipped` and why; `--live` makes that a failure, `--no-live` skips it on purpose.
5. The **sealed** independent set (`bench/dag/independent-haskell`) is never scanned here. It is spent once per release by running its own `run.mjs`
   deliberately and logging that in its `USE-LOG.md`. This gate reads only the committed result of that run: the labels digest must be valid,
   `results.json` must carry it, and its overall aggregate must equal the recorded sealed baseline (`--update-sealed-baseline` records it).
   `bench:haskell-precision:release` (`--require-sealed`, used by the release check as `haskell-precision-sealed-gate`) fails while none is recorded.
   Until one is, the default check says so and does not open the sealed files at all.

Exit codes: 0 passed, 1 a check failed or nothing is recorded (a gate with nothing recorded checks nothing), 2 usage.

## The decision rule for the sealed measurement, written down before it is run

When the sealed independent set is measured for this release (once, logged in its `USE-LOG.md`), the rule is fixed now so the number cannot choose it:
**if the sealed overall precision moves by less than 2 percentage points from the last recorded figure, the result is reported as "did not generalise"
and no precision claim ships.** By the release plan's own account the sealed set has 1 true positive among 35 decided sites (Wilson 95% about 0.5% to 14.5%; not re-checked here, the set was not read), so it cannot show a small
improvement at all; that is a property of the set, not a reason to move the rule. A development-set gain is not evidence for the sealed set. This
README is where the rule lives because the gate is the only part of the repository that reads the sealed result.

## Where it is wired

`scanner/package.json` (`bench:haskell-precision:check`, `:release`, `:update`), the pre-push gate (`haskell-precision-gate`, whole-tree cache key),
the release check (`haskell-precision-gate`, and `haskell-precision-sealed-gate`), and `PROVEN_BY_PRE_PUSH` in `scripts/ship/lib.mjs` (the sealed one is
not, so the release gate always runs it). It is exercised in both directions on synthetic data in `scanner/test/bench-haskell-precision.test.js`.

## Limits

- Equality over 345 sites and 14 projects on one reader's labels. It catches change; it does not say the numbers are good, and the sets are small
  (the development census is 5 true positives of 19 flagged sites).
- The live half depends on the clones being at the pinned commits and on the engine being deterministic; it spawns the same scans as
  `bench/dag/dev-haskell/scan-all.mjs` (about a minute and a lot of memory for ihp and dhall-haskell).
- It says nothing about recall beyond "a true positive that was reported is still reported at the same severity". Recall guards are the synthetic splits
  (`bench/language-support`), the mutation bench and the layer-recall gate.
