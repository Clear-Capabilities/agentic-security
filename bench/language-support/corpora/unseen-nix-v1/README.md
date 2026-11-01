# unseen-nix-v1 (Nix and NixOS): MEASUREMENT ONLY

The first frozen split of single-flaw Nix and NixOS configuration forms: 12 families, 3 vulnerable and 3 safe forms each, 72 forms in all. Until it existed the Nix side had no generalisation measurement at all: the frozen holdout and the unseen-v3 shapes are template-generated (QA-001) and unseen-v3 became a development set on 2026-10-26. This split is the one no Nix engine change has been motivated by.

## Rules

1. **Written blind to the engine rules and to every earlier set.** The author (a separate agent with no view of this repository) was given only the 12 family names with their CWE and a one-paragraph meaning of each at the NixOS level, the authoring format, and a list of ordinary option spellings, services and module shapes to spread the forms over. It did not open any Nix analyzer, rule table or option catalog, nor any corpus source, nor any result file. The family meanings it was given are the CWE definitions applied to NixOS configuration, not the engine's rule tables.
2. **Frozen.** `manifest.json` records `ecosystem: nix`, `sourcesSha256` and `labelsSha256`. `node build.mjs --verify` recomputes both; `bench/language-support/lib.mjs` (`frozenCases`) refuses to load the split when they differ, so the detection suite fails closed on tampering. `build.mjs` refuses to rebuild once a manifest exists. `scanner/test/language/frozen-splits.test.js` checks both on every test run.
3. **Measured once, before any engine change that follows.** The baseline is `bench/language-support/results/unseen-nix-v1-baseline.md` (and `.json`), taken on 2026-11-01 before any Nix engine work of 0.195.9.
4. **Never tuned against.** Do not use these sources, labels or the baseline failures to decide how to change a rule.
5. **Usage rule.** Reading the failures (misses, strays, per-case results) while changing rules turns this into a development set. Any such use must be recorded in `USE-LOG.md` before a number from it is quoted, `manifest.json` gets `role: development` and `developmentSince`, and the numbers from then on are a development measure, not a generalisation measure. A re-measurement with no rule change needs no entry. A generalisation claim after that needs unseen-nix-v2, written the same way.

## Layout

- `authoring/*.txt`: the forms as written (a trailing `#@@` marks the one line the label refers to; the marker is stripped from the sources).
- `sources/nix/<id>/<path>`: the scanned code; ids are opaque, no comment names a label. A path is `configuration.nix`, `flake.nix`, or a file under `hosts/`, `modules/` or `profiles/`; each file is scanned alone.
- `labels.json`: one record per form in the same shape the other splits use (`ecosystem, family, label, group, split, nearMiss, shape, labelledBy, j, id, path, cwe, fingerprint`), plus `flawLine` (vulnerable forms) or `safeSinkLine` (safe forms: the line that is the neutralised counterpart). The harness does not score lines.
- `build.mjs` and `summarize.mjs`: two-line wrappers over `../frozen-split.mjs`, the shared body every frozen split uses (the Haskell splits unseen-v4 and unseen-v5 were frozen over the same code before it knew about ecosystems; their digests reproduce unchanged).

## Run it

```
node bench/language-support/measure.mjs --split unseen-nix-v1 --eco nix --suites detection
```

Only the detection suite applies (the split has no privacy, pair, fix or parser labels). Families are scored the way the holdout scores them (`NIX_FAMILY_ALIAS` in `lib.mjs` maps each corpus family to the detector families that answer it; `script-interpolation` is the one taint family).

## Limits

One author; the forms were not evaluated (no `nix` on the measuring host); per-family cells are 6 forms, so intervals are wide; "safe" means the named flaw is absent as the author reasoned, not that the configuration is free of other weaknesses; each file is scanned alone, so a flaw that only the effective configuration across files would show is out of scope by construction. The author was asked to spread the forms over many option spellings, services and module shapes, so a miss here says the engine does not handle a shape a NixOS administrator may write, not how often real configurations write it.
