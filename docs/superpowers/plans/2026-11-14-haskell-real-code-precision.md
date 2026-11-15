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

## Round 2 (0.195.38), from the remaining labelled false positives

| mechanism | source of the shape | sites |
|---|---|---|
| a text parameter of a WAI-typed function (`IO ResponseReceived`, `Application`, `Middleware`) is the caller's value, not request input; the function stays an entry handler | IHP `Controller/Render.hs:43` (`renderFile filePath contentType`) | fresh 1 |
| a path operation on an uploaded part's `fileContent` reads the framework's temporary file (`tempFileBackEnd`): verdict `framework-controlled`, lowered; `fileName` stays a source | wai-request-params `Middleware.hs:276`; scotty `Action.hs:377` (unlabelled census) | fresh 1 |
| `case length xs of 3 -> xs !! 1`: the IR's `<match>` on the length scratch variable is a bounds test, and the measured expression may be a split tracked by signature | IHP `Layout.hs:92` | fresh 1 |
| an XSRF double-submit cookie is readable by design: HttpOnly is not missing on it, Secure still is | servant-auth-server `Cookie.hs:90,115,123` (discovery set) | discovery 3 |

Rulings: the cookie decision reads the cookie's NAME expression (literal, field, function or variable carrying `xsrf`/`csrf`), the protocol's own identifier, as the session-ness test already does; `fileContent` is told apart from the other upload fields by its source label, so no provenance or lineage category changes.

## Rulings recorded after round 2

- The two taint misses of the unseen-v3 development split (`hsy-161130c3fe`, `hsy-78da97a753`, both `saveUpload name content = withFile name WriteMode ..`) are the 0.195.9 `api-contract` ruling: a thin path wrapper handing its parameter on whole was a false positive on every real project that had it. They stay misses on the synthetic set by that decision; re-opening it would trade real-code precision for two synthetic cases.
- A "raw HTML from a non-literal" rule for the stored-XSS advisories (HSEC-2023-0008, HSEC-2026-0004) was examined and not built: 104 raw-HTML render sites across the clones, most of them a markdown renderer's output (cmark-gfm escapes raw HTML unless `optUnsafe`), so the rule would need per-renderer knowledge to be anything but noise. Parked, with the shapes recorded in `bench/cve-replay/real-haskell-advisories.md`.

## Round 3 (0.195.39)

| mechanism | source of the shape | sites |
|---|---|---|
| Base64 `encode` of a digest is formatting, not a signing or verifying call (`VERIFY_CALL` matched the bare `encode`) | wai-app-static ETag digests, discovery set | discovery 2 |
| a file read whose path is a project constant (resolved through the IR's `functionRef` to a definition that returns a literal) is a fixed-location read; with environment roots beside it the finding is `low`, kept | IHP schema compiler `SchemaCompiler.hs:360,363`, `Cache.hs:45` | fresh 3 (severity only; still flagged) |
| SCA import reachability for every package the Haskell advisory database names, module lists from each package's Hackage cabal file, exact matching where a prefix would claim another package | `haskell-sca.js` `PACKAGE_MODULES` | advisory findings' `reachability.import` leaves `unknown` for 18 packages |

Round 3 results (2026-11-14): fresh set unchanged at 29 flagged / 21 TP / 8 FP; `SchemaCompiler.hs:360,363` high to low (`Cache.hs:45` keeps high: its second read's path comes from the cache file's content, not a constant); discovery wai 4 to 2 flagged, both remaining sites true positives. Gates unchanged. The fixed-file pin "a path held in a name keeps its severity" was narrowed to the let-bound literal being a fixed location.
