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

## Who controls the input: trust boundaries

A flow from a source to a sink is a vulnerability only when the party that controls the source is not the party the
program runs for. Every taint finding in a Haskell file carries a `trustBoundary` verdict and the origins the engine
recorded (`sourceRoots`; a value derived from a source, returned from a function or passed through several calls keeps its
origin):

| Verdict | What supplies the value | What the scan does |
| --- | --- | --- |
| `attacker-reachable` | a request parameter, body, header or cookie, a socket, a remote HTTP response | reported at its normal severity |
| `operator-controlled` | command-line arguments or environment variables; in a command-line program also the files it is pointed at | lowered to `info`, the severity it would have had is kept in `originalSeverity` |
| `api-contract` | a parameter of an exported function nothing calls, handed whole to a process (`exec exe args = callProcess exe args`) | lowered to `info`: a thin wrapper, the caller chose what to run |
| `entry-parameter` | a parameter of such a function used inside a command or path the function builds | reported |
| `data-input` | standard input, or file content in a service or library | reported |
| `unattributed` | no origin recorded | reported |

A *command-line program* is code reached only from `main` functions whose reachable modules import no server framework
or socket library; a *service* is code reachable from a `main` that does. Code no `main` reaches is a library whose callers
are unknown. This is a fact about the call graph, not about names or paths. A command-line program whose taint carries no
recorded origin at all is treated as operator-controlled and the finding says it was inferred. Standard input stays
reported everywhere: it is data the program processes, and a flow from it to a command is still a finding.

A lowered finding is not deleted. It appears at `info` with the reason, so an auditor still sees it, and it never
counts toward a severity gate. Two things this does **not** do: it does not read comments or names (a test enforces that
comments change nothing), and it does not decide that a library function is safe. A path operation on a caller-named
file (`saveUpload name content = withFile name WriteMode ...`) is still reported, because the scanner cannot see the
callers of an exported function; once something in the analysed code calls the function, its parameters take the values
those callers pass.

Other rules read the function around a call for the same reason. A weak hash (MD5, SHA-1) is a finding where a visible use
depends on it (the digest is compared with another value, a secret is hashed, the result is a credential) and an `info`
note where it only names a file or keys a cache. A generator used for a salt is not reported (a salt must be unique, not
unpredictable). A cookie whose whole value is a constant (a cleared login) is not a credential. An unbounded read is
reported for a socket handle or for an uncalled entry point that slurps standard input, not for a local file or a child
process's pipe. A partial function (`head`) on a parameter is reported for a framework handler or an uncalled function,
not inside a helper the program itself calls.

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
The model registry (`scanner/src/language/haskell-models.js`) holds 195 sources, 283 sinks and 27 sanitizers. Every entry names an import-qualified function, so a function of your own with the same name never matches.

| Sink family | CWE | APIs modelled | Examples |
| --- | --- | --- | --- |
| `cmd` | CWE-78 | 39 | `Shelly.Lifted.bash`, `Shelly.Lifted.bashPipeFail`, `Shelly.Lifted.bash_`, ... |
| `cmd` | CWE-88 | 16 | `Shelly.Lifted.run`, `Shelly.Lifted.runFoldLines`, `Shelly.Lifted.run_`, ... |
| `code` | CWE-94 | 3 | `Language.Haskell.Interpreter.eval`, `Language.Haskell.Interpreter.interpret`, `Language.Haskell.Interpreter.runStmt` |
| `llm-prompt` | CWE-1427 | 5 | `Network.HTTP.Conduit.setRequestBodyJSON`, `Network.HTTP.Conduit.setRequestBodyLBS`, `Network.HTTP.Simple.setRequestBodyJSON`, ... |
| `path` | CWE-22 | 64 | `Data.ByteString.Char8.appendFile`, `Data.ByteString.Char8.readFile`, `Data.ByteString.Char8.writeFile`, ... |
| `redirect` | CWE-601 | 13 | `Happstack.Server.movedPermanently`, `Happstack.Server.seeOther`, `Happstack.Server.tempRedirect`, ... |
| `sql` | CWE-89 | 47 | `Database.HDBC.prepare`, `Database.HDBC.quickQuery`, `Database.HDBC.quickQuery'`, ... |
| `url` | CWE-918 | 59 | `Network.HTTP.Client.Conduit.http`, `Network.HTTP.Client.Conduit.httpLbs`, `Network.HTTP.Client.Conduit.httpNoBody`, ... |
| `xss` | CWE-79 | 35 | `Data.Text.IO.putStr`, `Data.Text.IO.putStrLn`, `Lucid.Base.toHtmlRaw`, ... |

Source provenances: cli (1), cookie (2), env (3), file-read (17), header (13), http-body (51), network (7), stdin (13), url-param (88).

Sanitizer effects: * (10), other (1), path (4), xss (12).
<!-- generated:hs-models:end -->

A text-typed parameter of an **exported** function that nothing in the module calls is a source, and the finding says which
kind:

- When the module imports Scotty, Yesod, Servant or WAI **and** the function returns that framework's handler value (a
  Scotty `ActionM`/`ActionT`, a Yesod `Handler` or `Widget`, a Servant `Handler`, a WAI `Application`), the parameter is
  labelled **request input** ("route, query or body value handed to a Scotty action", and so on, provenance `url-param`):
  the framework supplies it from the request. A single-endpoint Servant `server` written as a function takes its values
  from the API type in order of appearance (`Capture`, `QueryParam`, `Header`, `ReqBody`; only the text ones, never the
  principal an `AuthProtect` hands over).
- Every other exported function keeps the weaker label ("text parameter of an exported function (caller-controlled)"),
  because the scanner cannot see who calls your library. A record of your own handed to an exported function is not a taint
  source (the Data Flow Explorer reads it as a customer record, field by field).

The request accessors a handler really uses are sources: the `Maybe`/`Either` forms of the Scotty parameter reads, the
body readers, Scotty cookies, Yesod's JSON-body and cookie readers, and WAI's body parsers and conduit body stream.

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

The same holds for a shared guard function: a named `requireAuth` that reads a credential and only calls `status status401` does not
protect the handlers that call it, because the handler keeps running; it needs a stopping call (`finish`, `raise`, `raiseStatus`,
`redirect`) in the same function. `raiseStatus status401 ...` rejects and stops by itself.

The inline shape is recognised for every framework where it is idiomatic, not only Scotty:

| Framework | Credential read | Rejection that ends the handler |
|---|---|---|
| WAI | `lookup "Authorization" (requestHeaders req)` (or `hAuthorization`, `hCookie`) | `respond (responseLBS status401 ...)`, handed back |
| Servant | a handler argument bound to `Header "Authorization"` (or `Cookie`, an API-key header), examined in the body | `throwError err401` (also `err403`, with or without a record update) |
| Yesod | `maybeAuthId`, `maybeAuth`, `lookupHeader "Authorization"`, `lookupBearerAuth`, `lookupBasicAuth` | `notAuthenticated`, `permissionDenied` |

Each keeps the same negatives: a header that is not a credential, a rejection with no credential read, a check that runs after the
first sensitive operation, and a response that is built but never handed back.

For these three frameworks the IR reports a call in tail position (the last statement, a case alternative) at the enclosing line,
so the order of the rejection and the first sensitive operation is not taken from line numbers. It is read from the handler's own
structure: statements of a `do` block in sequence, a scrutinee or condition before its branches, and `when`/`unless`/`if`/`case` as
forks (a branch that always rejects after a credential read guards its sibling branches and everything after the fork). The result
is one of three:

- the rejection comes before every sensitive operation: the route is authenticated;
- the handler reads the credential, performs the operation, and only then rejects: the route is reported as `late` (CWE-306,
  "guard ... runs after the first sensitive operation");
- the order cannot be established: the route is also reported as `late`, with the reason in the evidence, and is never credited as
  authenticated. The cases are a rejection and a sensitive operation inside one opaque expression (`maybe notAuthenticated
  (\_ -> write) m`), and a sensitive call the structural walk cannot find.

Two points of precision. `throwError`, `permissionDenied` and `notAuthenticated` stop the handler wherever they appear, but a WAI
`respond (responseLBS status401 ...)` stops it only in tail position (the value the handler hands back): a `respond` in the middle of
a block is followed by the next statement, so it is not a rejection. And, as before, the condition that guards the rejection is not
required to mention the credential. Both directions, for all three frameworks, are pinned in
`test/haskell/haskell-web-guards.test.js`.

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

**Severity comes from the advisory.** A finding's severity is the advisory's own: the CVSS v3.0/v3.1 base score is computed from the
vector the record carries (on the record or on its `affected` entry; the highest score wins) and mapped critical at 9.0 or above,
high at 7.0, medium at 4.0, low above 0. Without a usable vector, a recognised `database_specific.severity` name is used. The
finding records `severityScore` and a `severityBasis` such as "CVSS v3.1 base score 7.5 from the advisory". Nothing is invented:
a CVSS v4 vector (not scored by this tool), a malformed vector, or an unrecognised name keeps the default `medium` and the basis
says why. In a Nix closure the advisory rating applies to a package judged affected or possibly affected; a fixed or
backport-verified package keeps its lower status level and is never raised by the upstream rating.

`--format cyclonedx` and `--format spdx` list the Hackage components as `pkg:hackage/<name>@<version>`, with scopes and
dependency edges when a plan is present. License data is not available for Hackage records, so no license policy is
applied to them and the scan says so (`license-data-unavailable`) instead of inventing a review finding per package.

## Fixes

```bash
agentic-security fix --finding <id> --preview     # a diff, nothing written
agentic-security fix --finding <id> --apply       # written only after every gate passes
agentic-security undo                             # restores the file byte for byte
```

A deterministic fix exists for ten shapes (`hs-sql-parameterize`, `hs-process-argv`, `hs-html-escape`,
`hs-hash-sha256`, `hs-log-redact`, `hs-path-takefilename`, `hs-tls-validate`, `hs-cookie-attributes`,
`hs-random-os-entropy`, `hs-request-body-bound`). Each plan carries a **tier** (`full-source-edit`, or `guidance-only`
for a refusal), a **consequences** list that states what the patch changes for the running program, and a label,
**FULL**, **MITIGATION** or **WORKAROUND**, by what it really changes. Every plan runs the same gates: path inside the
project, syntax, the rescan (the original finding is gone and no new medium-or-higher finding appears), the
**effective-change** check for the attribute fixes (the value is read back from the patched file with a reader that is
independent of the editor; a rescan that goes quiet because a cookie was renamed does not pass it), and a **compile**
check. The preview, the MCP `synthesize_fix` and the LSP request the compile check: GHC type-checks the patched file
against the original, and a host with no GHC, a project whose packages are not installed here, or a patch that imports a
module this host lacks records the gate as **not-run**, never as a pass. A fix outside those shapes, or one a gate
refuses, is reported as such; nothing is invented.

| Class | CWE | Result |
| --- | --- | --- |
| SQL built by concatenation | CWE-89 | parameterized, using the database library the file already imports (`postgresql-simple` or `sqlite-simple`); any other, or two at once, is refused |
| Shell command string | CWE-78 | a direct `callProcess` with an argument list; refused when a leading option could still be read as one |
| Raw markup from a value | CWE-79 | `preEscapedToHtml` becomes `toHtml`, only in a file that imports blaze-html or a package that re-exports it |
| MD5 / SHA-1 | CWE-328 | SHA-256 when the algorithm is named on one line only; refused when a type elsewhere in the file names it |
| Sensitive value in a log | CWE-532 | redacted (a mitigation) |
| Parameter under a fixed directory | CWE-22 | `takeFileName` on a `String` or `FilePath` parameter (a mitigation: a name with subdirectories keeps its last segment; directory operations are not rewritten because `..` survives `takeFileName`) |
| Certificate validation off | CWE-295 | the literal `True` of `settingDisableCertificateValidation` (positional or record form of the `connection` package's `TLSSettingsSimple`) becomes `False`. Consequence: connections to a self-signed, expired or privately issued certificate fail until the authority is in the system trust store. An OpenSSL `VerifyNone` is refused: `VerifyPeer` verifies nothing until a CA bundle is loaded and does not check the host name |
| Cookie without `Secure` / `HttpOnly` | CWE-1004 | four recognised shapes: a `Set-Cookie` header string literal, a `Web.Cookie` `SetCookie` record update, servant-auth `cookieIsSecure = NotSecure`, scotty `setSimpleCookie` / `makeSimpleCookie` (written out as the record update they are). Consequence: the cookie is no longer sent over plain HTTP and page scripts cannot read it. `SameSite` is not changed. Anything else, or a flag set from an expression, is refused |
| Predictable generator | CWE-338 | only a one-line action `name :: IO <fixed-width integer>`, `name = randomIO`, in a file that already imports `System.Entropy`: it reads `getEntropy` bytes and decodes them big-endian. Everything else is refused (a range, a wider or non-integer type, no entropy import): the CSPRNG's result type differs, so the code around it changes, and the token's type and size are a decision |
| Request body without a limit | CWE-770 | a mitigation, only for wai `strictRequestBody <request variable>` in a file importing `Network.Wai` and `Data.ByteString.Lazy`: it becomes `boundedRequestBody`, defined in the same file, which throws past `requestBodyLimitBytes`. The limit (1 MiB) is a **declared default, not a measured need**; larger bodies now raise an `IOException`. Every other resource limit is refused |
| Fast password hash | CWE-916 | refused, always: it needs a password KDF from a library the project may not declare, and every stored hash was produced by the old function, so a swap makes every existing password fail to verify. The decision is which KDF and cost, and the migration (verify the old hash once, re-hash at the next successful login, or force a reset) |
| Server-side request forgery | CWE-918 | refused: the decision is which hosts or address ranges the service may call (checked after name resolution and on every redirect) |
| Argument injection | CWE-88 | refused: `--` helps only programs that honour it; the decision is the permitted values for the argument |
| Missing authentication, hard-coded secrets | CWE-306, CWE-798 | refused: the decision is which credential authenticates the route and what an unauthenticated caller receives; for a secret, where it is read from at run time and rotating the exposed value |

Every class-level refusal ends with `The decision needed:` and the question the operator has to answer. A refused class can still be
repaired by a reviewed patch: a patch supplied by a person or a model goes through the same gates with
`agentic-security fix --finding <id> --proposal <file>` (`verifyHaskellProposal`; it only verifies and never writes). For a
command-injection fix, `languageFixPreview(..., { witness: true })` also runs the original and the patched file under GHC's
interpreter in the confinement sandbox and reports whether the payload ran in the original and not in the patch; every
other class has no witness a program GHC runs alone could produce, and says why. Compile verification of the
library-dependent rewrites above was done in this repository against hand-written stubs of the documented API, not against
the real packages.

The SQL shape is offered only where it does not have to guess the database library. The rewrite takes the driver the
file already imports (`postgresql-simple` or `sqlite-simple`), and a patch that would add an import of a database library
the file does not use is still blocked at the preview, because a rescan cannot see a wrong library. The block below was
captured from a bundle built before the rewrite learned to read the file's own import: it shows the earlier refusal for
this `sqlite-simple` example, and is regenerated at the next build.

<!-- generated:fix-hs-sql:start -->
```text
$ agentic-security fix --finding <id> --preview     # exit 0
FULL: Moved 1 interpolated value(s) out of the SQL text into query parameters.
--- a/src/Main.hs
+++ b/src/Main.hs
@@ -13,1 +13,1 @@
-lookupOrder conn ref = query_ conn (fromString ("SELECT status FROM orders WHERE ref = '" ++ ref ++ "'"))
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
- The trust verdicts are inferences from the call graph. A program whose `main` the scan cannot reach, or whose calls are
  higher-order enough that the walk stops, is a library as far as the scan can tell, and a library's uncalled functions keep
  their findings. A file-based flow in a service (an upload directory, a shared state file) is reported even when the file is
  the program's own state, because the scan does not follow files from a write to a later read.
- A function that is exported and called nowhere in the analysed code keeps a path finding for a parameter it names directly
  (`withFile name WriteMode`): that shape is indistinguishable from a real vulnerable one without knowing the callers.
  Whether a caller can exist is now judged from the project's entry points (`reachability` on the finding: `entrypoint-reachable`,
  `external-api`, `unreachable-in-project` or `unknown`), and only the last of those, only when the finding rests on nothing but the
  assumption that a caller supplies the parameter, lowers it to `info` (the severity it would have had is kept). The verdict is
  `unreachable-in-project` only when ALL of these hold: the scan covered the whole project (not a changed-file, pull-request,
  subdirectory or caller-supplied scan, and no Haskell source was kept out by the path policy or the size limit); there is at least
  one `main`; a `.cabal` or `package.yaml` says which modules the package exposes and the function's module is not one of them (or
  re-exported by one); the function is not an instance method; the IR has no gap it cannot bound (Template Haskell or a
  quasi-quote it does not accept, a foreign export, a build step that generates modules, an entry-point override, a call to a name
  nothing defines); and nothing reachable from a `main`, a framework handler, an exposed function or an instance method calls or
  references it. Anything less is `unknown` with the reason named (`holeReason`), and the finding is untouched. A library project
  (no `main`, or no manifest) therefore keeps every finding, and a partial scan changes nothing. Code the parser could not read is
  assumed to call anything its own module can see. A project with Template Haskell in any module gets no verdict at all, by design.
  This is an inference over a call graph that typeclass dispatch, re-exports and point-free code can defeat, which is why a finding
  that rests on a real read (an environment, file or request read) is never lowered by it: it may only rank lower. It has not been
  shown to improve precision on real code: on the labelled development and fresh sets it changed no finding's severity (see
  `bench/dag/dev-haskell/results/README.md`).
- Precision on real projects was measured on a development set of eight projects (see `bench/dag/dev-haskell/README.md`)
  and one reader's labels; the numbers there describe those projects, not Haskell code in general.
- The live advisory feed (`AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1`) has been tested against a stand-in server that serves the real
  pinned HSEC records, not against the live service on real projects. A package it could not cover is reported unknown.
- A credential check written inside a route handler counts as a guard only for the shapes described above (a credential header read,
  then a rejection that stops the handler, before the first sensitive operation); other ways of writing one are still reported.
- The measured numbers come from a synthetic, template-generated corpus; they describe robustness over those shapes, not
  accuracy on arbitrary real projects.

