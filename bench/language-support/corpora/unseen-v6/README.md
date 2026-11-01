# unseen-v6 (Haskell): MEASUREMENT ONLY

A frozen split of single-flaw Haskell code forms: 13 vulnerability families, 3 vulnerable and 3 safe forms each, 78 forms in all. It replaces unseen-v5 as the generalisation measure: on 2026-11-01 unseen-v5's failures were read to change the engine (its USE-LOG records the use), so from that day unseen-v5 is a development set and this split is the one no engine change has been motivated by.

## Rules

1. **Written blind to the engine rules and to every earlier set.** The author (a separate agent with no view of this repository) was given only the 13 family names with their CWE and a one-sentence meaning of each, the authoring format, and a list of ordinary Haskell libraries and frameworks to spread the forms over (the unseen-v5 brief, with a few more libraries and input channels named). It did not open any Haskell detector, rule or taint-catalog code, nor any corpus source (unseen-v4 and unseen-v5 included), nor any result file. The family meanings it was given are the CWE definitions, not the engine's patterns. It was told to report counts only, not the libraries or shapes it used, and did so; the one thing it reported beyond the counts is that two safe session-cookie forms set the `cookie` package's `setCookieSecure` field, whose name contains a banned word.
2. **Frozen.** `manifest.json` records `sourcesSha256` and `labelsSha256`. `node build.mjs --verify` recomputes both; `bench/language-support/lib.mjs` (`frozenCases`) refuses to load the split when they differ, so the detection suite fails closed on tampering. `build.mjs` refuses to rebuild once a manifest exists. `scanner/test/language/frozen-splits.test.js` checks both on every test run.
3. **Measured once, before any engine change that follows.** The baseline is `bench/language-support/results/unseen-v6-baseline.md` (and `.json`), taken on 2026-11-01 after the real-code precision changes of 0.195.9 (which were motivated by the real-code sets, not by any split) and before the unseen-v5 misses were read.
4. **Never tuned against.** Do not use these sources, labels or the baseline failures to decide how to change a rule.
5. **Usage rule.** Reading the failures (misses, strays, per-case results) while changing rules turns this into a development set. Any such use must be recorded in `USE-LOG.md` before a number from it is quoted, `manifest.json` gets `role: development` and `developmentSince`, and the numbers from then on are a development measure, not a generalisation measure. A re-measurement with no rule change needs no entry. A generalisation claim after that needs unseen-v7, written the same way.

## Layout

- `authoring/*.txt`: the forms as written (a trailing `--@@` marks the one line the label refers to; the marker is stripped from the sources).
- `sources/haskell/<id>/<path>`: the scanned code; ids are opaque, no comment names a label.
- `labels.json`: one record per form in the same shape the other splits use, plus `flawLine` (vulnerable forms) or `safeSinkLine` (safe forms). The harness does not score lines.
- `build.mjs` and `summarize.mjs`: two-line wrappers over `../frozen-split.mjs`, the shared body every frozen split uses.

## Run it

```
node bench/language-support/measure.mjs --split unseen-v6 --eco haskell --suites detection
```

Only the detection suite applies (the split has no privacy, pair, fix or parser labels).

## Limits

One author; the forms were not compiled (the library packages are not installed in this environment); per-family cells are 6 forms, so intervals are wide; "safe" means the named flaw is absent as the author reasoned, not that the module is free of other weaknesses; the split is Haskell only. The author was asked to spread the forms over many frameworks and code styles, so a miss here says the engine does not handle a shape a Haskell programmer may write, not how often real projects write it.
