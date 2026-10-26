# unseen-v4 (Haskell): MEASUREMENT ONLY

A frozen split of single-flaw Haskell code forms: 13 vulnerability families, 3 vulnerable and 3 safe forms each, 78 forms in all.

## Rules

1. **Written blind to the engine rules.** The author did not open any Haskell detector, rule or taint-catalog code, nor any existing corpus source, while writing these forms. Only the family names (from the language registry and the label files) were used. Each form is how a Haskell programmer would write that code (Scotty, Servant, Yesod, wai, process, directory, filepath, sqlite-simple, postgresql-simple, aeson, cryptonite and others).
2. **Frozen.** `manifest.json` records `sourcesSha256` and `labelsSha256`. `node build.mjs --verify` recomputes both; `bench/language-support/lib.mjs` (`unseenV4Cases`) refuses to load the split when they differ, so the detection suite fails closed on tampering. `build.mjs` refuses to rebuild once a manifest exists.
3. **Measured once, before any engine change that follows.** The baseline is `bench/language-support/results/unseen-v4-baseline.md` (and `.json`), taken on scanner 0.186.1.
4. **Never tuned against.** Do not use these sources, labels or the baseline failures to decide how to change a rule.
5. **Usage rule.** Reading the failures (misses, strays, per-case results) while changing rules turns this into a development set. Any such use must be recorded in `USE-LOG.md` before a number from it is quoted, and the numbers from then on are a development measure, not a generalisation measure. A re-measurement with no rule change needs no entry.

## Layout

- `authoring/*.txt`: the forms as written (a trailing `--@@` marks the one line the label refers to; the marker is stripped from the sources).
- `sources/haskell/<id>/<path>`: the scanned code; ids are opaque, no comment names a label.
- `labels.json`: one record per form in the same shape the other splits use (`ecosystem, family, label, group, split, nearMiss, shape, labelledBy, j, id, path, cwe, fingerprint`), plus `flawLine` (vulnerable forms) or `safeSinkLine` (safe forms: the line that is the neutralised counterpart). The harness does not score lines.
- `build.mjs`: builds and verifies. `summarize.mjs`: turns a harness result into the baseline markdown.

## Run it

```
node bench/language-support/measure.mjs --split unseen-v4 --eco haskell --suites detection
```

Only the detection suite applies (the split has no privacy, pair, fix or parser labels).

## Limits

One author; the forms were not compiled (the library packages are not installed in this environment); per-family cells are 6 forms, so intervals are wide; "safe" means the named flaw is absent as the author reasoned, not that the module is free of other weaknesses; the split is Haskell only.
