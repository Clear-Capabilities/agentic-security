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

## Round 4 (0.195.40)

| mechanism | source of the shape | effect |
|---|---|---|
| `hs-request-body-bound` rewrites `lazyRequestBody` too (the bounded reader already returns a lazy ByteString; the body is now read eagerly up to the limit, stated) | discovery set: servant-server `Internal.hs:1047`, wai-extra `MethodOverridePost.hs:40`, wai-frontend-monadcgi `MonadCGI.hs:35` (the three labelled true positives with no patch) | `MonadCGI.hs:35` verified (MITIGATION); the other two stay refused: their files use CPP |
| a cookie record whose name is one of the enclosing function's parameters (under a conversion or not) is a helper's definition, judged at the call that passes a session name | scotty `Cookie.hs:132` (`makeSimpleCookie n v`), fresh set | fresh false positives 8 to 7; `Session.hs:180` (the caller) stays a true positive |
| an evidence-chain hop names the file its record was made in; the collector stamped the collecting function's file on every hop, so a summary finding merged into its caller put every hop in the caller's file | IHP `SchemaCompiler/Cache.hs:45` (a read at Cache.hs line 38 was looked for at SchemaCompiler.hs:38) | the fixed-file judgement now finds the read: `high` to `low` |

Ruling: the CPP refusal stands for the two remaining body sites. A rewrite inside a file with conditional compilation can change a branch the scan cannot see; the decision (which configuration the patch is for) is the operator's, and the class reason names it.

## Round 5 (0.195.41): discovery batch 2

Six more projects the engine had never been run on (PostgREST, the yesod monorepo, snap-server, keter, Spock, spacecookie; `bench/dag/discovery-haskell`,
`batch: 2`), scanned once and every flagged site labelled: 21 sites, 1 true positive (PostgREST's unbounded `strictRequestBody`), 18 false positives, 2 ambiguous.
Each mechanism below is general and pinned both ways in `scanner/test/haskell/haskell-real-code-round5.test.js`.

| mechanism | source of the shape | effect |
|---|---|---|
| `posture/api-contract.js`: a contract file under a directory a `test-suite` stanza lists is that suite's fixture, not the API (`isTestFile`, decided from the manifest through `testComponentIndex().dirOwnerOf`); a code route whose path does not start with `/` or holds whitespace is not compared | PostgREST `test/spec/fixtures/openapi.json` judged the admin routes (4 high); the text between two string literals read as `GET  ++ toS k ++` | 5 flagged sites gone |
| `hs-partial-function-on-input`: `last`/`head` on a splitter that returns a non-empty list for every input (`NONEMPTY_RESULT`: `Data.Text.split`/`splitOn`/`inits`/`tails`, `Data.List.Split.splitOn`/`splitWhen`/`splitOneOf`, `inits`/`tails`/`scanl`/`scanr`/`subsequences`/`permutations`, `NonEmpty.toList`) is total; a call under a qualifier two modules share (`T` for `Data.Text` and `Data.Text.Encoding`) is judged from the IR's `hs.candidates` when one candidate is in the set and every candidate is that module or a submodule of it | PostgREST `QueryParams.hs:191` | 1 gone; the ByteString `split` (empty for an empty input) and `words` stay reported |
| `hs-partial-function-on-input`: a partial name the function binds itself (a where-bound `fromJust = error ..`), or that the IR resolved to a project definition or a local function value, is not the library partial | yesod-core `TypeCache.hs:88` | 1 gone |
| `hs-unbounded-input-read`: a socket read repeated by a recursive loop is unbounded only when an argument of the recursive call is built from the read (`loopCarriesRead`); a loop that answers each chunk and recurses with the socket alone holds one chunk | keter `Cli.hs:93` | 1 gone; `slurp conn (acc <> chunk)` stays reported |
| `HS_HANDLER_PARAM_SOURCES.yesod.handlerName`: a Yesod text parameter is request input only on a function the routes DSL dispatches to by name (`getFooR`, `postFooR`, `handleFooR`); a `Handler`/`HandlerFor`/`Widget` helper keeps the caller-controlled label and stays an entry handler for reachability | yesod `Default/Util.hs:52` (`addStaticContentExternal`) | the root is the caller's value; the site stays flagged as `entry-parameter` (a parameter under a fixed directory, the 0.195.9 policy) |
| `assignEntryRoles`: the role follows the call PATH from `main` (a function reached only through modules that import no server library is `cli`; a path through a server module is `service`), and a function's module is found by FILE (a repository with several `Main`s kept only the first under the bare name) | yesod-bin `AddHandler.hs` (4 high: the developer's answers to `yesod add-handler`, in the binary that also runs `yesod devel`); fresh set IHP `CompileTimeDatabase.hs:811` | 4 gone on the discovery set; 1 labelled fresh-set false positive to info |

Discovery batch 2 flagged 21 to 9 (postgrest 8 to 2, yesod 10 to 5, keter 3 to 2; the true positive kept). Fresh set: false positives 7 to 6, flagged 28 to 27, precision 75.0% to 77.8%.

Not changed, each recorded in `labels.json`: keter's reverse proxy (SSRF: host, port and scheme from a configuration record; the fixed-host judgement reads a literal), keter's
function-valued configuration field applied to the host, yesod-static's lookup-served file, PostgREST's content type held in a response record's field, yesod-auth's legacy MD5
verifier beside a vendored KDF module under another name, and the two yesod-core cookie defaults (ambiguous). Ruling: the CSRF double-submit cookie without Secure keeps its severity;
the attribute is absent and the rule's title overstates the stake, which is a wording question, not a precision one.

## Round 6 (0.195.42): the sites the earlier rounds left, and discovery batch 3

Discovery batch 3 (`bench/dag/discovery-haskell`, `batch: 3`): snap, happstack-server, hakyll, clckwrks, hledger (with hledger-web) and hasura's graphql-engine
(1567 Haskell files, the largest project in any set), scanned once and every flagged site labelled: 42 sites, 4 true positives (hledger-web's unauthenticated
`POST /add`, `last` on a possibly empty string, Hasura's two unbounded request-body reads), 1 ambiguous (the admin `pg_dump` options), 37 false positives.
Seven mechanisms, each general and pinned both ways in `scanner/test/haskell/haskell-real-code-round6.test.js`.

| mechanism | source of the shape | effect |
|---|---|---|
| `fixedHostRequest` follows the sink's argument into the project function that builds the request record and accepts a destination field (host, port, secure, url) whose expression contains no request source and names nothing a request source in that function reads from (`requestBearing`); http-client's `defaultRequest` is a fixed base. Lowered to info, never refuted (the path is the client's) | keter `Rewrite.hs:135` (a reverse proxy: host, port and scheme from `ReverseProxyConfig`) | 1 gone (keter 2 to 1) |
| api-contract: a route whose path was INFERRED from a handler's name (`conventional`, carried from haskell-web through `newRoute` and `toEngineRoutes`) is not compared; a root-level contract governs a route only when the route's own package is the root or the repository holds exactly one package below the root (`loadContracts` records the package directories it walks) | hledger-web's nine UI pages against its JSON API's OpenAPI; graphql-engine's root `metadata.openapi.json` against the data-connector agent's package and the server's `/api/rest/` (eight) | 17 gone |
| `api-contract` trust verdict: the whole handoff is followed through a chain of project calls (`handsOn`, up to three hops), each hop judged in its own scope (locals resolved, pattern-bound parameters mapped to their positional names); a parameter that is the FIRST component of a path join (`joinPath (base : pieces)`, `base </> name`) hands the directory on whatever the tail is; the trace starts from the function that holds the parameter (the chain's root) when the finding was collected under a callee | snap `JsonFile.hs:144/147`, happstack `BuildingBlocks.hs:279/357/358/510`; dev set xmonad-contrib `DirExec.hs:101` (labelled FP) | 6 gone on batch 3; 1 development-set false positive to info |
| `hs-predictable-random`: a clock reading that only enters time arithmetic or a time comparison (`clockOnlyInTimeArithmetic`: `+`, `-`, comparisons, `diffUTCTime`, `addUTCTime`, numeric conversions transparent) is an expiry computation, not a security value, whatever the function is called | graphql-engine `Connection.hs:136` (`getAccessToken`), `WebSocket.hs:327` (`tokenExpiryHandler`) | 2 gone |
| a function whose declared result is a Template Haskell `Q` type (`Q Exp`, `Q [Dec]`, ...) runs at compile time: its taint findings are lowered to info (`compile-time-splice`) | hledger-web `Settings.hs:93` (`staticFileRoute`, `runIO $ doesFileExist`) | 1 gone |
| Yesod `redirect` of a TUPLE is the typed `(Route, query)` instance: this site by construction (`typed-route-redirect`, info) | hledger-web `App.hs:535` | 1 gone |
| the build runs in `scripts/build.mjs`: assembled in `dist.staging/`, swapped into `dist/` at the end | 0.195.41's push stop and a refused scorecard measurement during the warm gate's in-place rebuild | the tree is dirty for a rename, not a build |

Batch 3 flagged 42 to 15 (snap 2 to 0, happstack 5 to 1, hakyll 1, clckwrks 0, hledger 19 to 8, graphql-engine 15 to 5); the four true positives and the ambiguous site kept.
Fresh set unchanged (21 TP, 6 FP of 27, 77.8%); development-remainder flagged 4 to 3 (the xmonad-contrib directory listing). Precision baseline re-recorded.

Not changed, each with its reason in `labels.json`: hledger's five journal-path sites (one record returned by `getViewData` carries the request's query values and the
journal, and the summary taints the whole record: field-sensitive return records), happstack's multipart temp-file removal, hakyll's temp-file suffix (a tail), the
test-harness body reads (a `library` stanza of its own package), `init $ tailErr s` under a project predicate with a pattern match. Ruling: hledger-web's `POST /add`
without authentication is a true positive even though the tool documents itself as local-only; the finding states the fact and the operator decides.
