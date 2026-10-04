# Haskell and Nix/NixOS corpora (QA-001)

Controlled fixtures plus labels, built before any detector tuning. Nothing under
`scanner/src` reads this directory; a test enforces that.

## Layout

- `data/sources/` holds the scanned code only. Directory names are opaque ids; no
  path, comment or file name carries a label.
- `data/labels/` holds the ground truth (vulnerable, safe or unknown, split, family,
  near-miss tag). It is never placed beside the sources.
- `data/manifest.json` freezes the holdout: a SHA-256 per holdout source and a rollup.
- `lib.mjs` has the independent label reviewer, the mutation transforms and the
  integrity checks. `templates.mjs` and `generate.mjs` build the data.
- `provenance.json` records the origin, license and pin of every dataset and lists
  the requirements that are not met.

Regenerate with `node test/language/corpora/generate.mjs`. Regenerating changes the
holdout hashes only if a template changed, which the suite reports as a frozen-holdout
violation. If a holdout is ever used for tuning, create a new versioned holdout and keep
the old failures recorded.

## Splits

50% train, 20% validation, 30% holdout, assigned per origin group (ecosystem, family,
label, shape, noun). Unknown cases and mutants travel with the origin they derive from,
so related copies cannot straddle train and holdout.

## Labels are reviewed twice

The generator writes a label from the template. A separately written reviewer in
`lib.mjs` reads the comment-stripped source and decides vulnerable, safe or unknown from
its own per-family patterns. The generator refuses to write a case the reviewer
disagrees with, and the suite re-checks every case.

## What is not here

- No real advisory records and no real-world canary projects. They need network access
  to fetch and pin; they are recorded as gaps in `provenance.json`, not simulated.
- Backport near misses use synthetic version-range records, marked synthetic.
- The fixtures have not been compiled or evaluated (no `ghc`, `cabal` or `nix` here).
- NIST SARD is not claimed as a source of Haskell or Nix cases. None were obtained.
