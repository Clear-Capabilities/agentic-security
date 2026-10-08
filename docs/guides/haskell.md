# Haskell

Scanning Haskell works with no GHC, Cabal, Stack, Nix or network: the scanner reads the source itself and never
runs a project's code, `Setup.hs`, Template Haskell or compiler plugins. This guide records what is analysed,
how, and where the limits are. Every statement here is backed by a test in `scanner/test/haskell/` or
`scanner/test/language/`, and every table or output block marked *generated* is produced from the code's own
registries or from a real run (`node scripts/render-language-docs.mjs --check` fails when one is stale).

**Prerequisites:** Node.js >= 24. Nothing else is needed for the default scan. Optional tools are listed under
[What needs a tool](#what-needs-a-tool).

---

## Scan a Haskell project

```bash
npx @clear-capabilities/agentic-security-scanner scan .
```

That is the whole install-and-run path. Haskell is found by file type: `.hs`, `.lhs`, `.hs-boot` and `.hsc` sources,
and by the manifests `*.cabal`, `cabal.project`, `cabal.project.freeze`, `package.yaml`, `stack.yaml` and
`stack.yaml.lock`. Build output (`dist-newstyle/`, `.stack-work/`, `.cabal-sandbox/`) is never walked; the two resolved
dependency exports below are read by exact path only.

To try it on something known, scan the examples in this repository:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/haskell-app/vulnerable
```

All the usual scan modes work unchanged: `--format` (every report format), `--set-baseline` / `--since-baseline`,
`--changed-since`, `--only sca|sast|secrets`, `ci --assurance advisory|standard|strict`, and the line-scoped suppression
`-- agentic-security-ignore: <rule>` (a `{- ... -}` block form works too). A pragma is recognised only inside a comment, so
the same words in a string or an operator such as `-->` suppress nothing. The exit code is the usual one: `0` clean,
`1` low or medium, `2` high, `3` critical, `4` the scan itself failed.

### What a scan of the vulnerable example reports

<!-- generated:ex-hs-vuln:start -->
Captured from the built bundle on `examples/haskell-app/vulnerable`: exit code **3**, scan health **partial**.

| Severity | Family | CWE | Location |
| --- | --- | --- | --- |
| high | `weak-randomness` | CWE-338 | src/Main.hs:21 |
| high | `sensitive-logging` | CWE-532 | src/Main.hs:24 |
| critical | `multi-sink-taint-chain` | CWE-20 | src/Main.hs:32 |
| critical | `sql-injection` | CWE-89 | src/Main.hs:32 |
| high | `missing-authentication` | CWE-306 | src/Main.hs:34 |
| critical | `command-injection` | CWE-78 | src/Main.hs:36 |
| high | `missing-authentication` | CWE-306 | src/Main.hs:38 |

Scan-health conditions:
- no Hackage advisory snapshot is loaded: Haskell dependency vulnerabilities were not assessed. no advisory snapshot configured (set AGENTIC_SECURITY_HACKAGE_ADVISORIES, or place hackage-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME) To fetch advisories from the OSV Hackage feed instead, set AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1 (network, opt-in).

Disclosed limits: `license-data-unavailable`, `unmodeled-imports`.
<!-- generated:ex-hs-vuln:end -->

The `fixed` counterpart of the same service, with a parameterised query, no shell, a CSPRNG token, no logged secret and
an owner check in the statement, reports one informational finding and is `partial` for a reason worth reading: no advisory
snapshot is configured, so the dependencies were not checked against anything and the scan does not call itself complete.

<!-- generated:ex-hs-fixed:start -->
Captured from the built bundle on `examples/haskell-app/fixed`: exit code **0**, scan health **partial**.

| Severity | Family | CWE | Location |
| --- | --- | --- | --- |
| info | `argument-injection` | CWE-88 | src/Main.hs:46 |

Scan-health conditions:
- no Hackage advisory snapshot is loaded: Haskell dependency vulnerabilities were not assessed. no advisory snapshot configured (set AGENTIC_SECURITY_HACKAGE_ADVISORIES, or place hackage-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME) To fetch advisories from the OSV Hackage feed instead, set AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1 (network, opt-in).

Disclosed limits: `license-data-unavailable`, `unmodeled-imports`.
<!-- generated:ex-hs-fixed:end -->

## Sources, sinks and sanitizers

The taint engine follows a value from a source to a sink through your functions (including across modules and through
`<-` binds, `$`, `.` and `>>=`) and drops it at a sanitizer that applies to that sink's class. Flows are not claimed
where a recognised guard sits on the path: an allow-list `elem`, an `isPrefixOf` on a fixed directory with `..` excluded,
a host-anchored URL prefix, or an option terminator `--` for argument injection (which lowers that class to informational).

A sink is checked at the argument that carries the dangerous value, which is not always the first: for `Network.Wreq.getWith opts url`
it is `url`, so a tainted URL is reported as SSRF and tainted *options* on a constant URL are not (the `Session` forms take the URL
after the session). When one flaw reaches two nested sinks on a line (`readCreateProcess (shell cmd)`: `shell` builds the command,
`readCreateProcess` runs it) it is reported once, at the inner sink, and the outer one is recorded on the finding (`alsoSink`,
`dedupedVulns`); two independent sinks on one line stay two findings. A request body read whole with no size limit
(`strictRequestBody`) is CWE-770, the same class as the other unbounded-read rules.

<!-- generated:hs-models:start -->
The model registry (`scanner/src/language/haskell-models.js`) holds 91 sources, 165 sinks and 27 sanitizers. Every entry names an import-qualified function, so a function of your own with the same name never matches.

| Sink family | CWE | APIs modelled | Examples |
| --- | --- | --- | --- |
| `cmd` | CWE-78 | 13 | `System.Process.Typed.shell`, `System.Process.callCommand`, `System.Process.callProcess`, ... |
| `cmd` | CWE-88 | 5 | `System.Process.callProcess`, `System.Process.proc`, `System.Process.readProcess`, ... |
| `llm-prompt` | CWE-1427 | 5 | `Network.HTTP.Conduit.setRequestBodyJSON`, `Network.HTTP.Conduit.setRequestBodyLBS`, `Network.HTTP.Simple.setRequestBodyJSON`, ... |
| `path` | CWE-22 | 39 | `Data.ByteString.Lazy.appendFile`, `Data.ByteString.Lazy.readFile`, `Data.ByteString.Lazy.writeFile`, ... |
| `sql` | CWE-89 | 28 | `Database.MySQL.Simple.execute`, `Database.MySQL.Simple.executeMany`, `Database.MySQL.Simple.execute_`, ... |
| `url` | CWE-918 | 52 | `Network.HTTP.Client.httpLbs`, `Network.HTTP.Client.httpNoBody`, `Network.HTTP.Client.parseRequest`, ... |
| `xss` | CWE-79 | 23 | `Data.Text.IO.putStr`, `Data.Text.IO.putStrLn`, `Lucid.Base.toHtmlRaw`, ... |

Source provenances: cli (1), env (3), file-read (5), header (8), http-body (10), network (2), stdin (22), url-param (40).

Sanitizer effects: * (10), other (1), path (4), xss (12).
<!-- generated:hs-models:end -->

A text-typed parameter of an **exported** function that nothing in the module calls is treated as caller-controlled text,
and a record-typed one as a customer record. A flow from such a parameter is reported with that label, which is a weaker
claim than a request or standard-input read: the scanner cannot see who calls your library.

## Web frameworks: authentication, authorization and entry points

The route model is versioned (`haskell-web-models/1`) and covers four frameworks. A route is reported with its
method, path, the handler the scanner could resolve, and what it can prove about who may call it. Warp is a
server, not an authorization control; a type annotation is not enforcement; an authentication guard that is
declared but not applied to the handler earns no credit.

<!-- web-framework-table:start -->
| Framework | Package | Tested versions | Routes read from | Authentication evidence |
|---|---|---|---|---|
| Scotty | `scotty` | 0.12, 0.20 | `get`/`post`/`put`/`delete`/`patch` calls and `middleware` | a guard function that reads a credential and rejects, a credential check written inside the handler itself (see below), `basicAuth` middleware |
| WAI/Warp | `wai` | 3.2 | `case (requestMethod req, pathInfo req) of` routers, `run` installing a middleware | a middleware that reads a credential and rejects, installed in the `run` expression |
| Servant | `servant-server` | 0.19, 0.20 | the `type API = ... :> ... :<|> ...` description | `BasicAuth`, `AuthProtect`, `Auth` combinators in the type |
| Yesod | `yesod` | 1.6 | `[parseRoutes| ... |]` text | `isAuthorized` clauses, `requireAuthId`/`requireAuth` in a handler |
<!-- web-framework-table:end -->

An unrecognised framework version is still analysed, but its findings say so (`untested-model`) and carry a lower
confidence. Routes registered at runtime (inside `forM_`, or with a computed path) cannot be listed statically;
they are reported as `unknown` coverage and as a gap, never omitted.

### What the route findings mean

| Finding | CWE | Condition |
|---|---|---|
| State-changing route without authentication | CWE-306 | no guard dominates the first sensitive operation |
| Authentication check runs after a sensitive operation | CWE-306 | the guard exists but runs late |
| Object looked up by a client-supplied id without an ownership check | CWE-639 | authenticated route, id reaches a lookup, no comparison or scoping with the principal |
| Privileged route without a role or permission check | CWE-285 | admin-shaped route, authenticated, no role check |
| State-changing route authenticated by a cookie with no CSRF protection | CWE-352 | cookie/session credential, no CSRF check (header-token APIs are not CSRF-exposed) |

**A guard written inside the handler.** A guard does not have to be a separate function. A handler that reads a credential
(`header "Authorization"`, a cookie, an API-key header) and then rejects before its first sensitive operation is
authenticated, in each of the ways this is usually written: `when (isNothing h) (status status401 >> finish)`, a `when`
with a `do` block, a `case` on the header, or `status` and `finish` as separate statements. Two things keep this from being
a loophole. In Scotty, `status status401` only sets the response code and the handler keeps running, so an inline check
counts only if a stopping call (`finish`, `raise`, ...) follows before the first sensitive operation. And the check must
read a real credential header and run *before* the write: `header "X-Request-Id"` is not authentication, and a check
after the write is reported as too late.

## Dependencies, advisories and the software bill of materials

The declared inventory comes from the manifests: every dependency with its scope (library, executable, test-suite,
benchmark, setup, build-tool), declared range and, where a freeze file or an exact pin states one, its resolved version.
Packages that ship with GHC are labelled as boot packages. Versions are compared with the Haskell Package Versioning
Policy, not SemVer (`1.10` is greater than `1.9`, and `1.9.0.0.5` has five components).

**Resolved graph.** To see the transitive packages the build actually chose, give the scanner a resolved export:

| Tool | File the scanner reads (exact path) | How to produce it |
|---|---|---|
| Cabal | `dist-newstyle/cache/plan.json` | `cabal build --dry-run all` (written by cabal itself) |
| Stack | `.stack-work/dependencies.json` | `stack ls dependencies json > .stack-work/dependencies.json` |

A plan is checked for freshness against the project (compiler, flags, local packages and versions, declared bounds). A
stale plan contributes **no versions at all** and is reported as a scan-health condition; a missing one leaves the declared
inventory and says it is not a closure. A freeze file alone is `lock_only`, never a closure.

**Advisories.** No advisory data ships inside the scanner. A scan reads its advisories from one of two places, and never from the
scanned project:

1. **A hash-pinned snapshot you provide** (the default; fully offline):

   ```bash
   export AGENTIC_SECURITY_HACKAGE_ADVISORIES=/path/to/hackage-advisories.json   # or keep it in ~/.config/agentic-security/ (operator config)
   export AGENTIC_SECURITY_HACKAGE_ADVISORIES_SHA256=<digest>                       # optional pin
   ```

2. **The live feed** (opt in; needs the network). Set `AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1` and the scan looks up the
   packages it is about to evaluate in the OSV `Hackage` ecosystem (the HSEC advisories and their aliases) before it matches
   anything, and keeps the result in `hackage-advisories.json` in the operator configuration directory (mode 0600):

   ```bash
   export AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1
   agentic-security scan .
   ```

   What it will and will not do:
   - It is off unless you turn it on, and `AGENTIC_SECURITY_OFFLINE=1` (or `--no-network`) always wins. A snapshot named by
     `AGENTIC_SECURITY_HACKAGE_ADVISORIES` is used as given and never refreshed over.
   - It looks up declared and frozen dependencies, transitive ones when a plan is present, and Haskell packages inside an
     imported [Nix closure](nix-nixos.md). A package already looked up in the last 24 hours is not asked for again.
   - **It records what it covered.** The snapshot lists each package it actually queried and when. A package it could not
     fully look up (a record that failed to download, a package with more advisories than one page) is **not covered**, and the
     scan reports it as `feed-incomplete` (unknown) with an `advisory-feed-incomplete` scan-health condition. It is never
     reported as having no advisories. A package last looked up longer ago than the age limit reads `feed-stale` for the same reason.
   - **If the feed cannot be reached,** the previous snapshot is left in place and used, with its age stated. With no previous
     snapshot the scan is `partial` and says why ("Live feed: failed, ...").
   - Everything from the network is treated as untrusted: package names and advisory ids are validated before they reach a URL,
     a record that is not the one requested is dropped, responses are size-bounded, and a cached file whose records no longer
     match their recorded hashes is discarded and fetched again.
   - It has been tested against a stand-in server that serves the real pinned HSEC records. It has not been measured against
     the live service on real projects.

A snapshot inside the scanned project (`.agentic-security/`) is **ignored and the scan says so**: a project cannot vouch for its own advisories, so a hostile repository could otherwise ship an empty feed and make itself look clean. Only the environment variable or the operator configuration directory counts.

With no snapshot the scan is `partial` and says "Haskell dependency vulnerabilities were not assessed": the absence of a
finding is not a clean result. A stale snapshot is stated too. A matched finding carries the exact version, the advisory
ids and aliases, the affected range and where the version came from, plus an import- or function-level reachability tier
that never claims more than the evidence (`unknown` unless the import is seen).

`--format cyclonedx` and `--format spdx` list the Hackage components as `pkg:hackage/<name>@<version>`, with scopes and
dependency edges when a plan is present. License data is not available for Hackage records, so no license policy is
applied to them and the scan says so (`license-data-unavailable`) instead of inventing a review finding per package.

## Fixes

```bash
agentic-security fix --finding <id> --preview     # a diff, nothing written
agentic-security fix --finding <id> --apply       # written only after every gate passes
agentic-security undo                             # restores the file byte for byte
```

A deterministic fix exists for five shapes (`hs-sql-parameterize`, `hs-process-argv`, `hs-html-escape`,
`hs-hash-sha256`, `hs-log-redact`). Each is labelled **FULL**, **MITIGATION** or **WORKAROUND** by what it really
changes, and runs the same gates: path inside the project, syntax, the rescan (the original finding is gone and no new
medium-or-higher finding appears), and an optional compile check that runs only when asked and only when a `ghc` exists.
A fix outside those shapes, or one a gate refuses, is reported as such; nothing is invented.

<!-- generated:fix-hs-sql:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 0
FULL: Moved 1 interpolated value(s) out of the SQL text into query parameters.
--- a/src/Main.hs
+++ b/src/Main.hs
@@ -10,4 +10,5 @@
-
--- | Look an order up by reference. The reference comes straight from the URL.
-lookupOrder :: Connection -> String -> IO [Only String]
-lookupOrder conn ref = query_ conn (fromString ("SELECT status FROM orders WHERE ref = '" ++ ref ++ "'"))
+import Database.PostgreSQL.Simple (execute, query, Only)
+
+-- | Look an order up by reference. The reference comes straight from the URL.
+lookupOrder :: Connection -> String -> IO [Only String]
+lookupOrder conn ref = query conn "SELECT status FROM orders WHERE ref = ?" (Only ref)
```
<!-- generated:fix-hs-sql:end -->

A mitigation says plainly what it costs. Redacting the logged password removes the secret from the log and the log line
loses that detail:

<!-- generated:fix-hs-logging:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 0
MITIGATION: Replaced 2 sensitive log argument(s) with "[REDACTED]". The value is no longer logged; the log line loses that detail.
--- a/src/Main.hs
+++ b/src/Main.hs
@@ -24,1 +24,1 @@
-logLogin user password = putStrLn ("login " ++ user ++ " password=" ++ password)
+logLogin user password = putStrLn ("login " ++ user ++ " "[REDACTED]"=" ++ "[REDACTED]")
```
<!-- generated:fix-hs-logging:end -->

A fix the gates refuse is a result, not a failure of the tool. The shell-command finding in the same example is refused
because replacing the shell string with an argument list (`callProcess "label-printer" ["--order", name, ...]`) would
introduce a new medium argument-injection finding (CWE-88): a value that starts with `-` can still be read as an option.
The scanner reports that and leaves the file alone; adding a `--` or validating the value is the human step.

<!-- generated:fix-hs-cmd:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 4
No verified fix for this finding (blocked): the patch introduces 1 new medium-or-higher finding(s)
```
<!-- generated:fix-hs-cmd:end -->

## What a partial scan looks like

Code the scanner cannot read statically is disclosed, never dropped. A module with Template Haskell splices, CPP
conditionals, a foreign import or a syntax error keeps its findings and carries a stated boundary:

<!-- generated:ex-hs-partial:start -->
Captured from the built bundle on `examples/haskell-app/partial`: exit code **3**, scan health **partial**.

| Severity | Family | CWE | Location |
| --- | --- | --- | --- |
| critical | `command-injection` | CWE-78 | src/Gen.hs:19 |

Scan-health conditions:
- no Hackage advisory snapshot is loaded: Haskell dependency vulnerabilities were not assessed. no advisory snapshot configured (set AGENTIC_SECURITY_HACKAGE_ADVISORIES, or place hackage-advisories.json in the operator configuration directory, agentic-security under XDG_CONFIG_HOME) To fetch advisories from the OSV Hackage feed instead, set AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1 (network, opt-in).

Disclosed limits: `license-data-unavailable`, `opaque-boundary:cpp`, `opaque-boundary:ffi`, `opaque-boundary:th-splice`, `opaque-boundary:th-top-level-splice`, `unmodeled-imports`.
<!-- generated:ex-hs-partial:end -->

`opaque-boundary:th-splice` means the scanner saw the construct and could not see through it; `unmodeled-imports` lists
imported modules with no security model, whose functions are analysed as ordinary calls. Unresolved constructs make the
file `unresolved` in scan health, and `ci --assurance strict` fails on that.

Four boundaries are disclosed but do **not** make the file `unresolved`, because the scanner either parsed what is behind them
or matched them against a closed pattern and states the assumption:

| Disclosed limit | What the scanner did | What it still does not know |
|---|---|---|
| `opaque-boundary:cpp` | Evaluated each `#if` / `#ifdef` / `#ifndef` / `#elif` it can decide and kept only the live branch (the dead branch is overwritten with spaces, so locations stay exact). A conditional it cannot decide keeps **every** branch, and its calls are marked conditional. | Which branch the undecided conditionals compile to. The limitation reports how many conditionals were decided and how many were not. |
| `opaque-boundary:ffi` | Parsed the foreign declaration's own Haskell signature. | The foreign code. |
| `opaque-boundary:th-safe-splice` | Recognised a declaration-level splice of a known generator applied only to names and literals, and analysed the file. | The declarations the generator produces. It is **assumed** to be the upstream generator. |
| `opaque-boundary:quasiquote-inert` | Read a raw-string or non-interpolating quasi-quote as a string literal. | Nothing about the text, which is treated like any string; the quoter is **assumed** to be the upstream one. |

What decides a CPP conditional, and on what basis (the basis is recorded on each decision):

- **The file itself.** `#define` and `#undef` in the same file, integer literals (`#if 0`, `#if 1`), `defined(X)`, and the usual
  operators with three-valued logic (`defined(X) && 0` is false whatever `X` is; `defined(X) || 1` is true; `defined(X) && 1` is
  undecided). A macro the file never mentions is **undecided**, never zero: a build flag or the compiler may define it. A `#define`
  inside an undecided branch makes the macro undecided afterwards. Function-like macros and expressions the evaluator cannot read
  are undecided.
- **The project's compiler.** `__GLASGOW_HASKELL__`, `MIN_VERSION_GLASGOW_HASKELL` and the boot-package `MIN_VERSION_base` are judged
  only against a compiler the project states: `with-compiler: ghc-X.Y.Z` in `cabal.project` is a pin, and `tested-with: GHC == X.Y.Z`
  lines in a `.cabal` file are used only when every listed version agrees and every item is an exact version (a range is never turned
  into a version). A decision resting on `tested-with` is reported as an assumption in the limitation, because the project merely
  claims it was tested there. Without a stated compiler these stay undecided. `base` is compared at major.minor only, since its patch
  level varies inside one GHC series.
- **The project's dependency bounds.** `MIN_VERSION_pkg(a,b,c)` is judged against the hull of the `build-depends` ranges of every
  component in the project's `.cabal` files (a built version must satisfy its component's range). A package with no bound, or one the
  project does not list, decides nothing.

What a safe declaration splice is, exactly. The generator must be **imported** from the module that defines it (with the import list
exposing it) and must not be defined in the file; every argument must be a name quote (`''T`), a string or integer literal, a
constructor, a documented settings value (`defaultOptions`, `sqlSettings`, `lensRules`, ...), an option-record update restricted to
documented fields with pure helper values (`drop 4`, `map toLower`), or a list of such applications. The generators are
`makeLenses`, `makeClassy`, `makeFields`, `makePrisms`, `makeClassyPrisms`, `makeWrapped`, `makeLensesWith` (lens); `deriveJSON`,
`deriveToJSON`, `deriveFromJSON` (aeson); `deriveSafeCopy`, `deriveSafeCopySimple` (safecopy); `mkPersist`, `mkMigrate`, `mkSave`,
`mkDeleteCascade`, `share` with `persistLowerCase` / `persistUpperCase` (persistent); `makeAcidic` (acid-state). Anything else stays
opaque exactly as before: `$(runIO ...)`, `$(embedFile ...)`, a user-defined splice, `qRunIO`, an argument that is a variable, a call,
a lambda or a nested splice, a generator that is shadowed, hidden or not imported, and one unsafe splice in a file keeps that file
`unresolved` even when its other splices are safe.

Quasi-quotes: `[r|...|]` (raw string) is inert whatever the body says. `[i|...|]`, `[iii|...|]`, `[__i|...|]`, `[iTrim|...|]`,
`[here|...|]` and `[hereLit|...|]` are inert only when the body has no interpolation marker (`#{`, `${`, `$(`, `$name`), because the
interpolated expression is code that can carry taint; with one, the boundary stays. The quoter must be imported from its upstream
module and not shadowed. Every other quasi-quote (a query language, a template, a router) stays opaque.

The semantic IR that drives taint and the security rules reads the same decisions: CPP directives and dead branches, a safe splice
and an inert quasi-quote are neutralised in place before it parses the file, so a flow written next to them is no longer lost to a
syntax error, a finding in a dead branch is not reported, and a finding in an undecided branch **is** (nothing is dropped because a
condition could not be decided).

## What needs a tool

| Capability | Needs | Without it |
|---|---|---|
| Parse, SAST, taint, privacy lineage, SCA, BOM, fixes, reports | nothing | n/a |
| Compile check of a fix (`compile: true`) | `ghc` on `PATH` | reported as not run |
| The criterion that every route fixture compiles (HS-006.AC01) | `ghc` | the criterion **fails**; the support registry marks `auth` as `blocked` on a host without it |
| Resolved dependency graph | a plan or Stack export in the project | declared inventory only, stated |
| Advisory matching | a snapshot you provide, or the opt-in live feed (network) | `partial`, stated |

The measured status of each capability, with its denominators, is in [Haskell and Nix support](../language-support.md).

## Limits worth knowing

- Static analysis of the source as written: no type checking, no instance resolution, no evaluation of laziness.
- A flow through an imported module with no security model is widened and disclosed on the finding.
- Template Haskell splices and quasi-quotes are boundaries except the closed set described above (known generators over names and literals, raw-string and non-interpolating quoters); those are analysed under a stated assumption that the name is the upstream one. Nothing is ever run, so what a splice generates is not modelled even when it is accepted.
- A CPP conditional is decided only from the file, a stated compiler and the project's dependency bounds; a macro set by a build flag or the environment is undecided and both branches are analysed. A `tested-with` decision is a project claim, not a pin, and is reported as an assumption: a branch dead under it was not analysed.
- Foreign calls are boundaries: the foreign code is not analysed.
- Weak-randomness detection keys on the function and time-source names; a rename of a security-shaped function can lose it.
- The live advisory feed (`AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1`) has been tested against a stand-in server that serves the real
  pinned HSEC records, not against the live service on real projects. A package it could not cover is reported unknown.
- A credential check written inside a route handler counts as a guard only for the shapes described above (a credential header read,
  then a rejection that stops the handler, before the first sensitive operation); other ways of writing one are still reported.
- The measured numbers come from a synthetic, template-generated corpus; they describe robustness over those shapes, not
  accuracy on arbitrary real projects.

