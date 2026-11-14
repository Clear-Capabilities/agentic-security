# Haskell real-code precision, remediation coverage and lost recall

> Executed inline (superpowers:executing-plans). Measured sets: `bench/dag/dev-haskell` (development and fresh, 345 labelled sites, 14 pinned clones), gated for equality by `bench/haskell-precision`. The sealed set (`bench/dag/independent-haskell`) is not read and not scanned by this plan.

**Where the numbers are (baseline.json, engine 0.195.36):** synthetic holdout is 100% on every Haskell capability, so nothing is left there. Real code: fresh set 51 flagged sites, 21 true positives, 30 false positives (precision 41.2%, Wilson 28.8% to 54.8%); development 19 flagged, 5 true positives; 20 of 27 labelled true positives have a verified patch; 2 development true positives are reported only at `info` (`tpNotFlagged`).

**The 30 fresh false positives, by cause (fresh-labels.json reasons):**

| cause | sites | sound mechanism |
|---|---:|---|
| hspec test code (`ihp-ide/Test/ServerSpec.hs`, `wai-request-params/Test/.../MiddlewareSpec.hs`) echoing requests in in-process test apps | 9 | the package manifest declares the directory as a `test-suite` component's `hs-source-dirs` (lever 1) |
| IHP's compile-time database tool (`ihp-typed-sql/.../CompileTimeDatabase.hs`): paths from the project directory and `IHP_TYPED_SQL_*` settings, executables from PATH | 14 | read the live origins first (lever 2); the trust pass should already say operator-controlled if the roots are env/cli |
| operator configuration or an internal invariant feeding a path (SchemaCompiler, Cache, Render, Middleware:276, scotty Util) | 5 | per site, after lever 2 |
| static error page read at a literal path served as HTML | 2 | already `low` by the fixed-file rule (0.195.18, deliberately not `info`); left alone |

## Rulings

- Test code is decided from the manifest only (`test-suite`/`benchmark` stanza `hs-source-dirs`, cabal or hpack), never from a path name such as `Test/` or `*Spec.hs`. A directory a runtime component also lists is not test-only; a file under an hpack component that exposes every module is not test-only. Cost if wrong: a shipped program whose manifest misdeclares its sources is lowered to `info` (never dropped; the reason names the stanza).
- A test-component finding is lowered to `info` with `originalSeverity` kept, the same convention as `operator-controlled`. It is not dropped: test code can hold a real secret or a real injection the author will copy.
- The `!!` fixer (lever 3) chooses "unchanged result" among the three options the CWE-248 class reason names, and only where that choice type-checks by construction (the result type is the indexed parameter's type). A MITIGATION with the behaviour stated.

## Levers, in order

1. **Test-component scope.** `haskell-manifests.js` `testComponentIndex(manifests)`; hpack stanzas record `source-dirs`/`main` in `fields`. `haskell-trust.js` `applyTestComponentScope(findings, manifests)`; wired in `engine.js` over every Haskell finding before each pragma pass. Expected on the fresh set: flagged 51 to 42, false positives 30 to 21, true positives 21 unchanged. Re-record `bench:haskell-precision:update` after the live check shows exactly that.
2. **CompileTimeDatabase origins.** Live deep scan of the IHP clone, read `trustBoundary`/`sourceRoots` at the 14 sites, fix the general cause (not the file).
3. **`hs-index-bounds` fixer** for `hs-partial-function-on-input` with `!!` and a caller-supplied index: a guard equation `f i xs | i < 0 || i >= length xs = xs` before the first equation, when exactly one parameter is the index, the indexed list is a parameter, and the declared result type equals that parameter's type. Effective kind `index-bounds`. Expected: 23 of 27 labelled true positives patched (the three IHP schema-designer sites).
4. **The 2 development true positives at `info`:** identify, decide whether the lowering is right.

Each lever: failing test first, regression gates (`test:haskell`, `test:language`, `bench:haskell-precision:check` live, `bench:self-scan:check`, `bench:mutation:check`), changelog with the before/after counts, its own release.

## Results (2026-11-14, released as 0.195.37)

| set | flagged before | flagged after | TP | FP before | FP after |
|---|---:|---:|---:|---:|---:|
| fresh | 51 | 32 | 21 (unchanged) | 30 | 11 |
| development (tuning, verification, remainder) | 5, 1, 6 | unchanged | 2, 1, 0 | unchanged | unchanged |

- Lever 1 moved 10 labelled fresh sites (9 flows in IHP's hspec suites and the chain built over them). Lever 2 moved 9 (IHP compile-time database: `unattributed` to `operator-controlled`, roots `lookupEnv` at lines 959 to 963). Nothing else moved; the live equality check passed after the re-record.
- Lever 3: `fix-real.mjs ihp --all` verifies `Enums.hs:72`, `Enums.hs:75`, `SchemaOperations.hs:542` (MITIGATION): 23 of 27 labelled true positives patched. Still refused with the decision named: the variable-program command, the open redirect, the chain row, `Layout.hs:92`.
- Lever 4 (the 2 development true positives at `info`) was not reached in this release.
- Remaining fresh false positives (11): operator configuration feeding a path (SchemaCompiler 360/363, Cache.hs:45, Render.hs:43, Middleware.hs:276, scotty Util.hs:46), the pid-file read (CompileTimeDatabase:811, `data-input` in a service role), the two static error pages (`low` by the fixed-file rule), one partial function (`Layout.hs:92`), one cookie.
