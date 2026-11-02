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

## Limits

Six projects, one commit each, one labeller, one reading. Three of the six are frameworks or libraries, whose "requests" are their users'
applications; the precision figure describes these projects and this engine, nothing wider. The sealed sets were not re-scored for this
directory.
