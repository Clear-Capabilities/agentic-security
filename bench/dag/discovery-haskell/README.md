# Haskell discovery set

Six projects the engine had never been run on, scanned once with the default deep scan and read site by site, so that what the scanner
finds on code nobody tuned it for is written down: the real vulnerabilities, the false positives by cause, and the engine gaps the
reading exposed. It is a DEVELOPMENT set: an engine change may follow from what was read here, and that is recorded in `USE-LOG.md`.
It is not the fresh set (`bench/dag/dev-haskell`, the precision gate's measurement) and not the sealed set (`bench/dag/independent-haskell`).

| | |
| --- | --- |
| projects | `manifest.json`: hoogle, wai (monorepo), mighttpd2, postgres-websockets, yesod-scaffold (`postgres` branch), servant (monorepo); 526 Haskell files |
| acquire | `node bench/dag/discovery-haskell/acquire.mjs` (shallow clones at the pinned commits into `.cache/`, gitignored) |
| scan | `node bench/dag/discovery-haskell/scan.mjs` (deep mode, no state writes; writes `results/<id>.json`) |
| labels | `labels.json`: every flagged (non-info) site, one labeller, reason written after reading the code |

## Result (2026-11-02, engine at the commit that adds this directory)

| project | Haskell findings | flagged | TP | FP | ambiguous |
| --- | ---: | ---: | ---: | ---: | ---: |
| hoogle | 9 | 2 | 0 | 1 | 1 |
| wai | 17 | 4 | 2 | 2 | 0 |
| mighttpd2 | 1 | 0 | | | |
| postgres-websockets | 1 | 1 | 0 | 1 | 0 |
| yesod-scaffold (postgres) | 2 | 2 | 0 | 2 | 0 |
| servant | 11 | 8 | 1 | 7 | 0 |
| **total** | **41** | **17** | **3** | **13** | **1** |

Precision over the labelled flagged sites: 3 of 16 (18.8%, Wilson 6.6% to 43.0%); the ambiguous site is counted in neither.

**The three true positives** are one class: a request body read whole with `lazyRequestBody` and no bound, in servant-server's `ReqBody`
handler (`servant-server/src/Servant/Server/Internal.hs:1047`, medium) and in two wai-extra frontends (`MethodOverridePost.hs:40`,
`MonadCGI.hs:35`, low). Each is framework code that leaves the limit to a middleware the application may not add; the same class the fresh
set labels TP in IHP's request-params middleware. `hs-request-body-bound`'s fixer rewrites `strictRequestBody` only; `lazyRequestBody` is a
shape it refuses, recorded as a remediation gap.

**No new vulnerability class was found.** Hoogle's web server validates every path segment in `readInput` before any file is served; servant
sets `HttpOnly` on its session cookie and leaves the XSRF token readable by design; the yesod scaffold's only write request is a form with
its own token.

**The false positives, by cause** (`labels.json` has each reason):

| cause | sites |
| --- | ---: |
| a monorepo's example `swagger.json` judged every package's routes (api-contract) | 78 before the fix, 3 after (the example's own routes, whose keys differ only in parameter syntax) |
| the rule reads a literal `False` on the XSRF cookie, which is readable by design | 3 |
| a conservative return: a call with a tainted argument returns tainted (err406's fixed body) | 1 |
| MD5 as an ETag | 2 |
| operator configuration (a file named by an environment setting) | 1 |
| a scaffold's demonstration form | 2 |
| validation inside a `Maybe`-returning parser the engine does not read as a guard (hoogle `readInput`) | 1 |

## What the reading changed in the engine (general, pinned on synthetic code)

- Two parser gaps hid hoogle's whole request handler: a `where` at the case alternatives' column after a `case` function body (the HS-001
  parser read it as an alternative; `haskell-parser.js` now closes the implicit block on it, as `haskell-syntax.js` already did), and
  semicolon-separated statements on one line of a nested `do` (both parsers split the enclosing block on them; a `;` now separates items of
  an implicit block only on a line that starts at the block's indent and opened no nested block before it). With those, hoogle went from
  0 flagged to 2 (both read above). Pinned in `scanner/test/haskell/haskell-discovery-shapes.test.js`.
- The API-contract detector scopes a contract to the package that holds it (`scanner/src/posture/api-contract.js` `contractScope`): servant's
  78 contract findings became 3. Cross-language; `test/api-contract-scope.test.js`.

## Batch 2 (2026-11-15; `manifest.json` entries with `batch: 2`)

Six more projects the engine had never been run on, chosen the same way (a web or input-processing surface, absent from every other set) and
read the same way: PostgREST, the yesod monorepo, snap-server, keter, Spock, spacecookie (655 Haskell files). Scanned with the engine at
0.195.39 plus round 4, every flagged site labelled (`labels.json`, keyed as before), then scanned again after the round-5 changes.

| project | Haskell findings | flagged before | TP | FP | ambiguous | flagged after round 5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| postgrest | 12 | 8 | 1 | 7 | 0 | 2 |
| yesod | 15 | 10 | 0 | 8 | 2 | 5 |
| snap-server | 2 | 0 | | | | 0 |
| keter | 8 | 3 | 0 | 3 | 0 | 2 |
| Spock | 2 | 0 | | | | 0 |
| spacecookie | 0 | 0 | | | | 0 |
| **total** | **39** | **21** | **1** | **18** | **2** | **9** |

**The one true positive** is PostgREST's `strictRequestBody` with no size limit anywhere in the application (`App.hs:232`, medium; its
documentation leaves the limit to a reverse proxy), the class the fresh set and batch 1 already hold. Spock, snap-server and spacecookie
flagged nothing; snap-server's body reads carry their own limit.

**The false positives, by cause** (each reason in `labels.json`; the round-5 column says what changed):

| cause | sites | round 5 |
| --- | ---: | --- |
| a test suite's `openapi.json` fixture judged the admin routes (api-contract) | 4 | a contract under a `test-suite` directory is that suite's fixture (decided from the manifest) |
| the text between two string literals read as a route (`" ++ toS k ++ "`) | 1 | a route whose path is not a path is not compared |
| the developer's answers to a scaffolding prompt, in a binary whose other branch serves (`yesod add-handler`) | 4 | entry roles are decided along the call path from `main` |
| a `HandlerFor` helper's parameters read as route pieces (`addStaticContentExternal`) | 1 | request input only on a dispatch-named handler; the site stays flagged as `entry-parameter` (a parameter under a fixed directory, the standing policy) |
| `last` on `Data.Text.split`, which never returns an empty list | 1 | total splitters, through a shared qualifier |
| a where-bound `fromJust` taken for `Data.Maybe.fromJust` | 1 | a name the module defines is that definition |
| a socket loop that handles each chunk and recurses with the socket alone (keter's REPL) | 1 | the recursive call must carry what it read |
| a reverse proxy: host, port and scheme from configuration, path and headers from the request (SSRF) | 1 | not changed: the fixed-host judgement reads a literal host |
| a function-valued configuration field applied to the host (the default escapes it) | 1 | not changed |
| a static file found by a path-keyed lookup, served with its own mime type | 1 | not changed |
| the content type held in a response record's field (PostgREST's `toWaiResponse`) | 1 | not changed |
| a legacy MD5 verifier beside a vendored KDF module under another name | 1 | not changed |

The two ambiguous sites are yesod-core's cookie defaults: the session cookie without Secure (`sslOnlySessions` is the documented opt-in) and
the CSRF double-submit cookie without Secure (a token, not a session credential).

## Batch 3 (2026-11-15; `manifest.json` entries with `batch: 3`)

Six more projects, chosen the same way: snap, happstack-server, hakyll, clckwrks, hledger (with hledger-web) and hasura's graphql-engine (1567 Haskell files;
graphql-engine alone is 1127 and scans in about 3.5 minutes). Scanned with the engine at 0.195.41 plus round 6's SSRF guard, every flagged site labelled, then
scanned again after the round-6 changes.

| project | Haskell findings | flagged before | TP | FP | ambiguous | flagged after round 6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| snap | 3 | 2 | 0 | 2 | 0 | 0 |
| happstack-server | 9 | 5 | 0 | 5 | 0 | 1 |
| hakyll | 8 | 1 | 0 | 1 | 0 | 1 |
| clckwrks | 0 | 0 | | | | 0 |
| hledger | 46 | 19 | 2 | 14 | 3 | 8 (6 after round 7) |
| graphql-engine | 36 | 15 | 2 | 12 | 1 | 5 |
| **total** | **102** | **42** | **4** | **34** | **4** | **15 (13 after round 7)** |

Round 7 re-read hledger's eight: the two `getViewData` record sites are gone (field-sensitive return records, below), and the three `postEditR` writes
were relabelled ambiguous, because the file is a route piece that `journalFile404 f j` checks against the loaded journal before the write, a project guard
the engine does not read.

**The four true positives:** hledger-web's `POST /add` writes the journal with no authentication (`require AddPermission` is an operator capability, not a
check of who asks; the tool documents itself as local-only, and the finding states the fact); `underline s` applies `last` to a possibly empty string; Hasura's
GraphQL endpoint and its 404 logger read the whole request body with no size limit, the class PostgREST and the earlier batches hold. The ambiguous site is
Hasura's admin `pg_dump` API, which passes request-supplied options to `pg_dump` by design.

**The false positives, by cause** (each reason in `labels.json`; the round-6 column says what changed):

| cause | sites | round 6 |
| --- | ---: | --- |
| the HTML UI's routes compared with an OpenAPI that documents only the JSON API, their paths inferred from handler names | 9 | a conventional route is not compared |
| the data-connector agent's and the server's routes compared with the repository-root `metadata.openapi.json` (a repository of many packages) | 8 | a root contract governs only the root package or a lone sub-package |
| a library's directory or file parameter handed on whole through calls, or as the base of a path join (snap's auth file, happstack's file serving) | 6 | the api-contract verdict follows the chain and the join's head |
| the journal path read from one record that also carries the request's query values (`getViewData`) | 5 | round 7: a returned record hands each field its own taint (two sites gone; the three `postEditR` writes are now labelled ambiguous) |
| a clock reading in expiry arithmetic in a token-named function | 2 | time arithmetic is not a security value |
| the test harness's own servers (a `library` package) | 2 | not changed: the manifest calls it runtime code |
| a compile-time Template Haskell file check | 1 | a `Q`-typed function is a splice |
| a typed-route redirect with query parameters | 1 | a tuple target is this site |
| the multipart parser's temporary file removed by the framework | 1 | not changed |
| a random temp-file name under the configured directory with the author's suffix (hakyll) | 1 | not changed: the parameter is the join's tail |
| `init $ tailErr s` under a project predicate whose pattern proves two characters | 1 | not changed |

## Batch 4 (2026-11-15; `manifest.json` entries with `batch: 4`)

Six projects with a network or untrusted-input surface outside the web frameworks the earlier batches lean on: simplex-chat (a messaging client and
server), matterhorn (a chat client), pandoc (a document converter reading untrusted input), shellcheck (a shell-script parser), duckling (a text parser)
and purescript (a compiler with a REPL). Scanned with the engine at 0.195.42 plus round 7's field-sensitive return records, every flagged site labelled,
then scanned again after the round-7 rule change.

| project | Haskell findings | flagged before | TP | FP | ambiguous | flagged after round 7 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shellcheck | 1 | 0 | | | | 0 |
| matterhorn | 7 | 0 | | | | 0 |
| purescript | 8 | 6 | 0 | 6 | 0 | 0 |
| pandoc | 10 | 0 | | | | 0 |
| duckling | 1 | 0 | | | | 0 |
| simplex-chat | 12 | 5 | 0 | 5 | 0 | 5 |
| **total** | **39** | **11** | **0** | **11** | **0** | **5** |

**The six false positives are one shape:** `pwd <- getCurrentDirectory`, bound into the error pretty-printer's options so paths print relative to
the working directory, logged with the errors; the sensitive-logging rule read the Unix "print working directory" name as a password. Round 7: a
credential-shaped name bound from a path producer (`System.Directory`'s directory readers and path resolvers) holds a path, not a credential, so it
neither seeds a binding nor is reported at a log sink; the same name bound from anything else is still a credential by name.

**simplex-chat's first scan did not finish.** It ran 3 hours 40 minutes at full CPU without completing, while graphql-engine's 1127 files take 3.5
minutes. Not Haskell: the inspector's sampling profiler on the live process put every sample in the ReDoS detector's Kotlin string-literal regex,
`(?:\\.|[^"\n])+`, which lets a backslash match both branches and so backtracks exponentially on a literal with many escapes in the project's
Kotlin desktop app (`apps/multiplatform`). Round 7 writes the class as `[^\\"\n]` in every extractor; the project scans in 111 s since, and the
manifest's `deferred` field (honoured by `scan.mjs`) exists for the next project whose scan is known not to finish.

**simplex-chat's five sites, all false positives, two shapes, left for round 8:** the badge service's static files are served only after
`resolveInside` canonicalises the path and checks it with a where-bound prefix predicate, a containment guard that dominates the callee's RETURN
while the sink is in the caller (two sites, one of them the existence probe before the test); and a clock read in a function named for a token
(`takeToken`, a rate limiter; `bearerToken` twice, where the clock dates a signed JWT or a cached expiry) that is handed to a project helper or
stored in a timestamp field, which the clock rule's time-arithmetic test does not follow (three sites).

## Limits

Twenty-four projects over four batches, one commit each, one labeller, one reading. Three of the first six are frameworks or libraries, whose "requests" are their users'
applications; the precision figure describes these projects and this engine, nothing wider. The sealed sets were not re-scored for this
directory.
