# unseen-v7 (Haskell): MEASUREMENT ONLY

A frozen split of single-flaw Haskell code forms: 13 vulnerability families, 3 vulnerable and 3 safe forms each, 78 forms in all. It is the generalisation measure
from 0.195.43 on; it exists so that unseen-v6's failures can be read for round 8 of the taint work (which turns unseen-v6 into a development set, recorded in its
USE-LOG) while a measure no engine change has been motivated by still exists.

## Rules

1. **Written blind to the engine rules and to every earlier set.** The author (a separate agent with no view of this repository) was given only the 13 family names with their CWE and a one-sentence meaning of each (the CWE definitions, not the engine's patterns), the authoring format, and a list of ordinary Haskell libraries, frameworks and input channels to spread the forms over. It did not open any Haskell detector, rule or taint-catalog code, nor any corpus source (unseen-v4 to unseen-v6 included), nor any result file. It was told to report counts only, not the libraries or shapes it used, and did so; the one thing it reported beyond the counts is a list of library API spellings it was unsure of, recorded under Limits. The engine agent copied the authoring files into this directory without reading them.
2. **Frozen.** `manifest.json` records `sourcesSha256` and `labelsSha256`. `node build.mjs --verify` recomputes both; `bench/language-support/lib.mjs` (`frozenCases`) refuses to load the split when they differ, so the detection suite fails closed on tampering. `build.mjs` refuses to rebuild once a manifest exists. `scanner/test/language/frozen-splits.test.js` checks both on every test run.
3. **Measured once, before any engine change that follows.** The baseline is `bench/language-support/results/unseen-v7-baseline.md` (and `.json`), taken on 2026-11-15 at 0.195.43, after the real-code rounds 1 to 7 (motivated by the real-code sets, not by any split) and before the unseen-v6 misses were read.
4. **Never tuned against.** Do not use these sources, labels or the baseline failures to decide how to change a rule.
5. **Usage rule.** Reading the failures (misses, strays, per-case results) while changing rules turns this into a development set. Any such use must be recorded in `USE-LOG.md` before a number from it is quoted, `manifest.json` gets `role: development` and `developmentSince`, and the numbers from then on are a development measure, not a generalisation measure. A generalisation claim after that needs unseen-v8, written the same way.

## Layout

- `authoring/*.txt`: the forms as written (a trailing `--@@` marks the one line the label refers to; the marker is stripped from the sources).
- `sources/haskell/<id>/<path>`: the scanned code; ids are opaque, no comment names a label.
- `labels.json`: one record per form in the same shape the other splits use, plus `flawLine` (vulnerable forms) or `safeSinkLine` (safe forms). The harness does not score lines.
- `build.mjs` and `summarize.mjs`: two-line wrappers over `../frozen-split.mjs`, the shared body every frozen split uses.

## Run it

```
node bench/language-support/measure.mjs --split unseen-v7 --eco haskell --suites detection
```

Only the detection suite applies (the split has no privacy, pair, fix or parser labels).

## Limits

One author; the forms were not compiled (the library packages are not installed in this environment), and the author listed the API spellings it wrote from memory
and was unsure of: base64-bytestring's `encodeUnpadded`, req's `useHttpsURI` and `/~`, scotty-cookie's `makeSimpleCookie`/`setSimpleCookie`, Spock's `lazyBytes`/`body`,
Snap's `getPostParam`/`addResponseCookie` and its `Cookie` field names, happstack's `Cookie` fields and `unauthorized`, turtle's `proc`/`procs`, cryptonite's PBKDF2
`Parameters` field order, `Crypto.Random.randomBytesGenerate`'s argument order, katip's `mkHandleScribe` shape, amqp's `rejectEnv`, sqlite-simple's `changes`,
yesod's `runRequestBody`/`fileMove`, servant-auth-server's `throwAll` and JWT instances, scotty's `rescue` handler type. A form whose sink or source the engine does
not model because of such a spelling is a miss or a stray against this split, not necessarily against Haskell; read the per-family cells with that in mind. Per-family
cells are 6 forms, so intervals are wide; "safe" means the named flaw is absent as the author reasoned, not that the module is free of others.
