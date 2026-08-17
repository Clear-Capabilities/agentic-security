# scanner/src/ir/

Layer-1 intermediate representation. Per-file IR + cross-file call graph;
consumed by `scanner/src/dataflow/` for taint analysis.

## Parsers

| Language | Module                | Backend                                          |
|----------|-----------------------|--------------------------------------------------|
| JS / TS  | `parser-js.js`        | `@babel/parser`                                  |
| Python   | `parser-py-cst.js`    | Python 3.8+ stdlib `ast` via subprocess (default when available) |
| Python   | `parser-py.js`        | Hand-rolled regex parser (fallback when python3 missing) |
| Java     | `parser-java.js`      | `java-parser` npm package (**async only** — the deep path in `engine.js` therefore awaits `buildProjectIRAsync` when any `.java` file is present, and uses the sync builder otherwise).
⚠ Three defects made Java taint impossible until v0.136.3+: the sync-only call site; a CST walk looking for `blockStatement` on a `block` (java-parser nests `block → blockStatements → blockStatement`), which emptied every method CFG; and `exprFromCst` missing the `primary → primaryPrefix + primarySuffix` form that models **every** method call. Guarded by `test/java-taint-flow.test.js`. Real parameter names (previously always `params: []`, marked "deferred") plus Spring `@RequestParam`/`@PathVariable`/`@RequestBody`/`@RequestHeader` param annotations (`fn.paramAnnotations`) are extracted in one CST walk over `formalParameterList` (PRD R14(a) Task 5). Varargs parameters (`String... args`) live under a distinct `variableArityParameter` node this walk doesn't extract from — they're gracefully dropped, not corrupted or crashed on. **PRD R9 (partial): `fn.calls` is now populated** via the shared `call-sites.js#callSitesFromCfg` (the same language-agnostic helper `parser-py-cst.js` uses) — Java's CFG nodes (`call`, `assign`, `return`, `if`) already matched the documented contract. This creates real cross-file call-graph edges for Java (`callgraph.js`'s `edges`/`callersOf`/`resolveKnownCallee`, previously always empty for Java) — it does NOT change the generic tainted-call-argument fallback in `engine.js`'s `exprTaint`, which reads CFG expression args directly off `expr.args` and already worked for Java independent of `fn.calls`. However, **same-class (intra-class) method calls do not resolve, in both the bare and `this.`-qualified forms**: `parser-java.js` names functions `"App.buildCmd"` (class-qualified), but a bare call extracts `"buildCmd"` (unqualified) and `callgraph.js`'s name-based resolution cannot match them — this is the most idiomatic Java call shape (private helpers, intra-class delegation) and remains a real gap, documented here as a candidate follow-up PRD item (a per-file bare-tail fallback in `callgraph.js`, mirroring the existing `~bare~`-key collision-refusal pattern, would plausibly fix it without touching `parser-java.js`). `this.buildCmd(id)` is not merely unresolved, it's worse: `parser-java.js:76` lowers any `this.`-qualified call whose prefix isn't a plain FQN to the literal callee string `"unknown"`, so it doesn't fail closed, it fails to a fabricated name. Guarded by `test/parser-java-calls.test.js` (the test's honest caveat discloses this; the fixture shows that edges exist but unresolved) (mirrors `test/parser-rb-calls.test.js`, the identical `fn.calls` wiring, though Ruby's unqualified names make bare-call resolution work there). **PRD R8: `walkStmts` now recurses into `for`/`try`/`switch`/`do`/bare-block bodies** (previously only `if`/`while` were walked — every other braced statement kind silently dropped its body from the CFG, including try-with-resources, the single most idiomatic JDBC shape). A fix round closed two further gaps the initial review found: enhanced-for (`for (x : xs)`) now synthesizes an assign binding the loop variable to the iterated expression, so the variable itself carries taint provenance (mirroring `parser-js.js`'s `ForOfStatement` pattern); and Java 14+ arrow-form `switch` (`case 1 -> …`) is now recognized via a second CST-shape branch. Deferred, not fixed: `forInit`/`forUpdate` clauses of a basic 3-clause `for` loop are still not walked (only the loop body is); `synchronized` blocks and labeled statements are still fully dropped. Guarded by `test/parser-java-control-flow.test.js`. **Measured `bench/layer-recall` impact: unchanged, 1/25 before and after** — the fix is real and directly proven by the dedicated unit tests above, but this corpus's existing 25 Java fixtures happen not to place a sink genuinely inside a braced control-flow body (the ones with `if`/`try` syntax use it as a single-line guard clause ahead of a flat-level sink, not a nested one) — see the PRD R8 status entry for the full explanation and the same finding for C#. **Taint-recall PRD (80%) Tier 4: chained-call CST fix.** `exprFromCst`'s `primaryPrefix` handling previously used `.find(Boolean)` to grab the FIRST `methodInvocationSuffix` in a `primary` node's `primarySuffix[]` array and discarded the rest — so any 2+-level fluent chain (`DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml)`, `new SpelExpressionParser().parseExpression(expr).getValue()`) resolved to the wrong (inner, usually untainted) call, and the real sink call at the end of the chain was invisible to the taint walker. Rewritten to walk the full `primarySuffix[]` array in source order, dot-joining bare member-access segments (`{Dot, Identifier}` suffixes) into the callee name and accumulating args from every `methodInvocationSuffix` encountered — same outermost-first accumulation convention (`args.concat(soFar)`) as the `_followChain` helper shared by the other five hand-rolled parsers (this PRD's earlier, language-general fix for the identical class of bug: a trailing call/member continuation being silently dropped rather than followed). A companion catalog entry (`java-spel-getvalue`, receiver-scoped to `^parseExpression`, `argIndex: 'all'`) was added because the chain fix shifts the terminal callee segment from `parseExpression` to `getValue` — same "terminal segment shift" pattern documented for Kotlin/Go/Java elsewhere in this PRD. Fixes `CVE-2018-1000632-java-xxe` (DocumentBuilderFactory chain) and `CVE-2018-1273-java-code-injection` (SpelExpressionParser chain). Guarded by two new cases in `test/java-taint-flow.test.js`. **Separately found, NOT fixed, NOT this bug:** `CVE-2016-10033-java-cmdi`'s real-world shape `Runtime.getRuntime().exec("ping " + host)` is untouched by this fix (the chain resolves correctly) but still doesn't fire, because `engine.js`'s `literalSkeletonMatchesFamily`/`_SHELL_META` precision gate requires the STATIC literal portion of a CWE-78 concat to contain a shell metacharacter, and `"ping "` has none — a genuine, pre-existing, language-agnostic precision-vs-recall gap in the core engine (confirmed via git-stash bisection unrelated to any change in this PRD; confirmed the identical SQL-concat shape works fine, isolating the bug to `_SHELL_META` specifically), logged here as a candidate follow-up rather than silently left unmentioned. |
| Ruby     | `parser-rb.js`        | Hand-rolled. **`DEF_RE` must not let `\s*` cross a newline** — it did, and the body slice then started after the method's first statement, silently dropping it from every method (a one-statement body became empty). Guarded by `test/parser-php-rb.test.js`. ⚠ Also emitted no `fn.calls` at all (every OTHER parser does) — `callgraph.js`'s edges/callersOf/resolveKnownCallee are built entirely from `fn.calls`, so this left dead-code demotion and any interprocedural signal that depends on real call-graph resolution (rather than engine.js's generic tainted-call-argument fallback) permanently blind to Ruby. Fixed by deriving `fn.calls` from the CFG via the shared `call-sites.js#callSitesFromCfg` (the same helper `parser-py-cst.js` uses) — Ruby's node shapes already matched its documented contract. Guarded by `test/parser-rb-calls.test.js`. **Taint-recall PRD (80%): full CFG rebuild.** `_buildCfg` previously only recursed into `if`/`unless`/`while`/`until` bodies — `for`, `case`/`when`/`else`, `begin`/`rescue`/`ensure`, and any trailing block attached to a call (`xs.each do |x| … end`, the dominant Rails/ActiveRecord idiom) were silently dropped entirely, with no CFG node at all. `case`/`when` and `begin`/`rescue`/`ensure` use a recall-preserving model (every arm/clause reachable directly from the construct's own entry point, not modeled as mutually exclusive — same tradeoff `parser-kt.js`'s `_buildWhenArms` already established). A `do` block's opener also had to sit at the START of a line to be recognized at all — `_splitStatements`' depth-tracking now scans the WHOLE line (via `_rbLineDepthDelta`) rather than gating on `_RB_OPENERS.test(line)`, so a trailing `do` (mid-line, the common case) is now correctly consolidated instead of splitting its own body into independent nonsense statements. Trailing blocks recurse unconditionally and bind every named block parameter to the call's receiver (permissive by design — Ruby has no equivalent of Kotlin's implicit-this `apply`/`run` that would need to NOT bind). A recursion-depth guard (60) was added, matching every other R8-style rebuild in this codebase. Three further, independent bugs surfaced during the rebuild's own corpus-fixture debugging, all fixed: (1) `::` (Ruby's module-scope call operator, e.g. `Nokogiri::XML(x)`) was entirely invisible to `matchBalancedCall`'s `[\w.]+` callee regex — normalized to `.` on lowering; (2) a subscript-assignment on a member chain (`response.headers[key] = value`) had no assign-target branch at all and was silently dropped — lowered as a synthetic `<receiver>.[]=(key, value)` call, same shape as `parser-py.helper.py`'s `__setitem__` synthesis; (3) `_lowerExpr` checked "does this start with a quote" BEFORE checking for top-level `+` concatenation, so `"/var/data/" + name` was swallowed whole as one opaque literal — reordered, with a new `_splitTopLevelPlus` helper (string/paren/bracket-aware, so `"a+b"` is not mis-split) fixing it the same way `parser-go.js`'s R3 fix did for the identical ordering bug. Also inherits this PRD's shared chained-call fix (`_followChain`, `matchBalancedCall`-based) and keyword-argument fix from earlier in the same PRD. **Known, deliberately deferred gap:** the brace form of a trailing block (`Nokogiri::XML(xml) { |c| … }`) has its TRIGGER call correctly recognized (unlike before, where the trailing `{ }` corrupted or blocked the match), but the block BODY itself is not recursed into — only the `do...end` form got full body recursion, since it is the dominant multi-line Rails idiom and the single corpus fixture needing brace-form support only needed the trigger call's own argument, not its body. **Also known, NOT Ruby-specific:** a sink nested inside ANOTHER call's own argument (e.g. `render plain: URI.open(tainted).read`) is not independently checkable — `engine.js`'s sink-matching operates at CFG-node granularity (the outer `render` call), not on arbitrary nested sub-expressions; the SAME limitation was found via C#/Go/Kotlin corpus work earlier in this PRD, not something this task introduced or fixed. Guarded by `test/parser-rb-control-flow.test.js`. Two genuine ReDoS regexes were caught and fixed by `bench:self-scan:check` during this task — the trailing-block detector's first version had the `(.+?)\s+do` shape (an unbounded lazy prefix, NOT the "optional group between `\s*`" class every other ReDoS fix in this codebase has been; splitting into alternatives alone did not fix it — the leading capturing group itself had to go, replaced with a direct anchored search for `\bdo\b`), and the SAME detector's heuristic still flagged the replacement's residual "optional group between `\s*`" shape even though it measured linear on its own — split into two alternatives to satisfy the detector too. Measured `bench/layer-recall` impact on dataflow-shaped-subset taint recall: real, substantial movement (see `docs/TAINT_RECALL_80PCT_PRD.md`) — Ruby's own family entries moved from mostly-0% to 8/10 taint-detected. |
| PHP      | `parser-php.js`       | Regex-based, hand-rolled. ⚠ **PRD R8 was this codebase's hardest single task — a genuine 3-fix-round debugging saga, all substantially about line-number precision, not detection shape.** The core fix flushes the statement splitter on a closing `}` (previously only on `;`), and adds `try`/`switch` recognizers plus a recursion guard, so statements inside `if`/`while`/`foreach`/`try`/`switch` bodies are now real CFG nodes instead of being dropped or folded into a bogus call node — this alone also resolved a pre-existing bug where `if`/`while`/`foreach` bodies were already being mis-split even before R8 touched them. Round 1 fixed the naive `}`-flush breaking `if`/`else` and multi-clause `try` (via a continuation-keyword lookahead) and switch/case's first-statement drop (via a `:`-based flush, careful to exclude `::` so PHP 8.1 enum cases and `case Foo::BAR:` class-constant labels aren't false-positived) — but round 1's own line-tracking approach was then found wrong for comment-bearing bodies and multi-line headers, a regression the round itself introduced. Round 2 fixed that (comment-skip handlers were discarding newlines uncounted; use exact `_countNewlines`-based computation everywhere) but its own re-review found the overall "exact line" property still failed, due to a *different*, genuinely pre-existing bug in the function-body's own base-line computation (wrong for Allman-brace style, multi-line signatures, blank-line-preceded functions) plus a genuine new regression from round 1 (a comment between `}` and `else`/`catch`/`finally` dropped that continuation's body entirely). Round 3 fixed both and was confirmed clean by an 8-shape holistic sweep. Also fixed along the way: dead `finally` support (greedy regex capture bug), unrecognized `try{}finally{}` with no `catch`, and the `::` case-label false-positive — via a hand-rolled balanced-brace scanner replacing the fragile regex approach. **Known, deliberately deferred gaps** (full list + grouping in the PRD R8 status entry): the PHP 8 `match` expression is unmodeled (same class as Java's arrow-switch); `if`/`else`'s pre-existing greedy-capture bug still drops the else-body's first statement; a heredoc containing a bare `}` loses its sink entirely (a real regression from R8's original commit, not the fix rounds); `elseif`/`else if` chains are still fully unsupported (pre-existing). Guarded by `test/parser-php-control-flow.test.js`. **Measured `bench/layer-recall` impact: unchanged, 1/23 before and after — the corpus's own `1/23 → 2/23` movement is real but belongs to R14(b) (PHP `<module>` top-level lowering), not this task**, confirmed by commit-swap A/B testing (the pre-R8 parser still reproduces 2/23; the pre-R14(b) parser reproduces only 1/23). None of this corpus's `pre/` PHP fixtures place a sink genuinely inside a braced control-flow body — same explanation as the other three languages' rows.

**Taint-recall PRD (80%) Tier 4: comment-unawareness + `"literal" . $var` concat mis-parse.** Two PREVIOUSLY-DEFERRED gaps from the R8 list above, closed together (found while working the same gap class for Kotlin, below): (1) `_extractBody` (the function-BODY brace-matcher, a SEPARATE code path from `_splitStatements`'s own comment handling) had ZERO comment awareness — an apostrophe inside ANY comment ("don't", "it's") toggled its string-tracking state exactly like a real string literal, corrupting brace-depth for everything after it; depending on what followed, this either made `_extractBody` return `null` (silently dropping the **entire file's** IR — a single failed top-level function match corrupts every span downstream) or extracted the wrong body. Fixed by making `_extractBody` skip all three PHP comment forms (`//`, `#`, `/* */`) — the same fix `_splitStatements` already had for two of the three; `#`-comments (PHP's third form, previously invisible to `_splitStatements` too) are now handled there as well, careful to exclude `#[...]` PHP 8 attribute syntax from being mistaken for a comment. (2) `"literal" . $var` — arguably the single most common real-world PHP SQL-injection shape — was swallowed whole into one opaque `literal` node by TWO stacked bugs in `_lowerExpr`, each the same "unanchored prefix" defect class: the double-quoted-interpolation branch (`/^"/.test(s) && s.includes('$')`) matched on the WHOLE concat expression merely because it started with `"` and contained a `$` *anywhere* (in `$var`, outside the string, after the `.`), slicing off the wrong first/last characters as if the entire expression were one interpolated string; once that was fixed, the plain string-literal fallback (`/^"/.test(s)`) did the identical unanchored check one layer down and caught what the first fix now let through. Both are now anchored (`/^"(?:[^"\\]|\\.)*"$/`, full match required) so a concat correctly falls through to the `.`-splitting branch instead of either misreading the trailing ` . $var` as string content or swallowing the whole expression as an opaque literal. Guarded by 6 new cases in `test/parser-php-control-flow.test.js`, including an end-to-end `runScan` test proving real `$_GET`-to-PDO-sink taint flow through this exact concat shape. **Measured `bench/layer-recall` impact: real movement, PHP taint recall 2/23 (9%) → 7/23 (30%)** — the largest single per-language jump measured in this PRD, consistent with how common the `"literal" . $var` idiom is in real PHP code. |
| C#       | `parser-cs.js`        | Hand-rolled. ⚠ `_lowerExpr`'s string-concat branch **must** guard on `_splitTopLevelPlus` returning more than one part — when the `+` is nested inside parens the splitter returns the input unchanged and the branch recurses on the identical string (stack overflow, swallowed by `buildProjectIR`'s per-file catch, surfacing only as "no IR"). `new Type(args)` is lowered to a call so taint reaches constructor sinks such as `new SqlCommand`. Guarded by `test/parser-cs-kt.test.js`. **PRD R8: `_buildCfg` was rewritten from a flat linear CFG loop into a recursive builder** (ported from `parser-cpp.js`'s proven pattern) that recurses into `if`/`else`/`while`/`for`/`foreach`/`switch`/`do`/`try`/`catch`/`finally` bodies, with exact character-offset line computation and a `foreach`/`for`-init loop-variable assign (same lesson Java's for-each fix needed). Landed with one fix round: `using (...) { }` and `lock (...) { }` bodies were completely invisible (not in the recognized-keyword regex) — `using` is THE canonical ADO.NET wrapper around exactly the sinks this task targets, so this was a real, significant gap, fixed with a one-word regex addition. The task also deliberately deviated from its own brief in one place: it added a guarded `}`-flush to the statement splitter (the brief said not to; the reviewer confirmed the brief's own illustrative code would have dropped every statement following a control-flow block, and independently verified the deviation safe against collection/object initializers and lambda arguments). Deferred, not fixed: a collection-initializer-then-chained-call shape mis-splits (not a regression); the pre-existing `@"C:\"` verbatim-string escape bug (confirmed unchanged). Guarded by `test/parser-cs-control-flow.test.js`. **Measured `bench/layer-recall` impact: unchanged, 1/21 before and after** — same explanation as Java's row: this corpus's existing C# fixtures with `if`/`try`/`using` syntax use it as a guard clause ahead of a flat-level sink rather than nesting the sink inside the body, so they don't exercise the exact shape this fix targets. |
| Kotlin   | `parser-kt.js`        | Hand-rolled, parallel approach to `parser-cs.js`. **PRD R8: `_buildCfg` was rewritten from a flat linear CFG loop into a new recursive builder mirroring C#'s**, with Kotlin-specific adaptations — a `_consumeChunk` chain-consumer (Kotlin's splitter doesn't flush on `}` the way C#'s does) and dedicated `_buildWhenArms` parsing (`when`'s `else` arm would otherwise collide with `if`/`else` chaining in a generic keyword scan). This was the cleanest of the four R8 tasks — zero fix rounds — in part because the implementer was briefed on the other three tasks' hard-won lessons up front: it self-caught and fixed, before it could become a fix round, the exact same function-body-base-line-anchor bug PHP's hardest round found; it correctly identified and fixed a real gap (trailing-lambda calls like `xs.forEach { x -> ... }` genuinely fell through to `{kind:'unknown'}` before the fix); and it made a deliberate, correctly-scoped decision **not** to special-case `synchronized(lock) { }` — confirmed to be an ordinary Kotlin stdlib `inline fun`, not real keyword grammar, unlike C#'s `lock`. Statement-position control flow (`if`/`while`/`for`/`when`/`do`/`try`/`catch`/`finally`) is now covered; was previously the documented 0% Kotlin taint recall in `bench/layer-recall` (0/20). **Measured `bench/layer-recall` impact: unchanged, 0/20 before and after** — the dedicated unit tests below directly prove the fix works for a sink genuinely nested inside a control-flow body, but none of this corpus's 20 existing Kotlin fixtures happen to place a sink that way (same explanation as Java's and C#'s rows) — a candidate future item is enrolling a Kotlin corpus fixture that actually exercises this shape. **Two important, NOT-a-regression scope boundaries, worth reading before assuming Kotlin's control-flow support is complete:** (1) ~~control flow *inside* any trailing lambda... is still invisible~~ **fixed by taint-engine PRD P1, see below.** (2) expression-position `if` (`val r = if (...) {...} else {...}`, Kotlin's ternary-replacement idiom) still drops both branch bodies. Also deferred: `_extractBody`'s comment-unawareness — the same defect class as PHP's (see the PHP row), an apostrophe inside any `//` comment silently drops the whole function, confirmed possibly larger real-world impact than the CFG gap this task closed. Guarded by `test/parser-kt-control-flow.test.js`. ⚠ **`bench:self-scan:check`, run during this PRD's own Task 5 (full-gate verification), caught a genuine ReDoS this task's new trailing-lambda regex introduced** (`/^([\w.]+)\s*(\([^()]*\))?\s*\{[\s\S]*\}\s*$/` — an optional paren group sandwiched between two `\s*` quantifiers, the identical defect class R14(a)'s C# `attrRegex` ReDoS; confirmed genuinely quadratic by direct timing, not a detector false alarm). Fixed the same way that precedent was: restructured into two mutually-exclusive alternatives (no-parens / with-parens) rather than one optional group, re-verified linear and byte-identical across a 15-shape sweep; no `bench/self-scan/BASELINE.json` bump was needed once fixed. **Separately, and NOT fixed here** (pre-existing since commit `99c2b6a`, 2026-05-20 — predates this PRD entirely, already counted in the pre-R8 self-scan baseline): the variable-declaration regex a few lines above (`decl`, matching `val`/`var … : Type = expr`) has the same adjacent-`\s*`-around-ambiguous-content shape and is also confirmed genuinely quadratic — logged as a candidate future item, matching this PRD's own precedent for pre-existing bugs found incidentally (e.g. the R14(a) C# parenthesized-attribute-argument note).

**Taint-engine PRD P1: trailing-lambda BODY recursion (closing the scope boundary (1) above).** `_consumeChunk` now detects a `recv.method(args)? { … }` trailing-lambda call site via `TRAILING_LAMBDA_TRIGGER_RE`, finds the real matching `}` with `_matchDelim` (not the old `_lowerStmt` fallback's greedy `[\s\S]*\}\s*$`, which mis-captured a chained `xs.filter{}.forEach{}` as one opaque lambda), and recurses `_buildCfg` into the body — so a sink nested inside `.forEach{}`/`.use{}`/`.apply{}`/`.run{}`/etc. is now a real CFG node, not dropped. A fixed `LAMBDA_BINDABLE_METHODS` set (`forEach`/`map`/`filter`/`reduce`/`fold`/`use`/`let`/`also`) gets a synthesized taint-binding assign for the lambda parameter (implicit `it` or a named param, both accumulator+element for `reduce`/`fold`) before the body is recursed into — mirroring the for-loop's existing loop-variable binding. `.apply`/`.run` (implicit-`this`, no parameter) correctly recurse WITHOUT a binding. Chained lambdas (`.filter{}.forEach{}`) are not mis-captured; both bodies are reached. Verified via direct CFG inspection AND an end-to-end `runScan` test proving real taint flow through the binding into a sink. Guarded by `test/parser-kt-control-flow.test.js` (10 new cases) and `bench/cve-replay/deep/kt-trailing-lambda-pathtraversal-shape/` (added because, same as Java's/C#'s R8 rows, none of the *existing* 20 Kotlin corpus fixtures place a sink inside a trailing-lambda body — this new entry does, and is confirmed by direct env-var toggling to fire ONLY with `AGENTIC_SECURITY_DEEP=1`). **Measured `bench/layer-recall` impact: real movement, Kotlin taint recall 0/20 (0%) → 1/21 (5%).**

**Taint-recall PRD (80%) Tier 4: the `?.` safe-call operator gap.** Every regex-based matcher in this file — the callee-matching regexes (`[\w.]+`-style), the plain-dotted-ident check, the trailing-lambda trigger, `_followChain`'s continuation regex — keys off a character class that excludes `?`, so `str?.trim()`, `xs?.forEach { … }`, and even a bare property read `x?.y` all fell through to `{kind:'unknown'}` entirely. Unlike `::` (Ruby) or a chain continuation, this is NOT limited to a later segment of a chain — the safe-call operator can appear on the very FIRST segment of an expression — so patching individual regexes one at a time would have missed call sites this file doesn't enumerate as a list. Fixed with a single global normalization pass (`_stripSafeCallOperator`) at the very top of `parseKotlinFile`, applied to the whole file's source text before any other parsing runs: string-literal-aware (so `"a?.b"` inside a literal is untouched) and strips only a `?` immediately before a `.` (so the elvis operator `?:` and a bare nullable-type marker `String?` are both unaffected — neither is followed by `.`). Dropping the `?` outright (not replacing it with a same-length filler) is safe specifically because `_lineStarts`/`_lineAt`/`_lineForOffset` are purely newline-position-based — removing a non-newline character can shift a later character's column but never its line, and this file never relies on column offsets. Guarded by two new cases in `test/kt-taint-flow.test.js` (one proving `?.`-qualified calls now flow taint into a sink, one proving the elvis operator and nullable-type declarations are unaffected). **Measured `bench/layer-recall` impact: unchanged, 6/21 before and after** — the fix is real and directly proven by the dedicated unit tests, but none of this corpus's 21 existing Kotlin fixtures happen to use the `?.` operator in their vulnerable shape (same "corpus doesn't exercise this exact syntax" explanation as every other R8-class fix in this PRD's Java/C#/PHP rows above).

⚠ **A second, fresh ReDoS, same defect class, this time in this task's OWN new code:** the first-draft `TRAILING_LAMBDA_TRIGGER_RE` (`/^([\w.]+)\s*(\([^()]*\))?\s*\{/`) had the identical optional-group-between-two-`\s*` shape as the R8-era regex documented in the paragraph above — `bench:self-scan:check` caught it immediately (a new self-finding in this very file) and direct timing confirmed genuinely quadratic (40 000 non-matching whitespace chars: ~1 s). Fixed identically: split into two alternatives (no-args / with-args), each with its own capture group, re-verified linear (200 000 chars: 0 ms) and correctness-preserving across 6 shapes. The lesson repeats a third time in this codebase (R14(a) C#, R8 Kotlin `decl`, now this) — the "optional group flanked by two `\s*`" shape should be treated as an automatic red flag whenever writing a new statement-recognizer regex here.

**Two further gaps found while building the corpus entry above, NOT fixed (out of scope for trailing-lambda body recursion, routed around instead — same pattern as Java's chained-call CFG bug):** (a) a call with NO args made on a tainted receiver via a dotted callee string — e.g. `it.toString()`, `tainted.trim()` — does not inherit the receiver's taint. `engine.js`'s `exprTaint` for `case 'call'` checks only `expr.args` and the resolved callee's own return-taint summary (`_nestedCallReturnTainted`); a callee string like `"it.toString"` is never parsed back into a member expression to ask whether its OWN receiver (`it`) is tainted. This is not Kotlin-specific (any language whose IR lowers a method call to a bare dotted-string callee has the same exposure), so a real fix belongs in `engine.js`, not here. (b) `call.parameters` (Ktor's own cataloged `member`-type source) does not propagate taint through a subsequent `.getAll(...)` call made on top of it — `call.parameters.getAll("id")` reads as untainted, because the catalog entry matches a bare property READ, not a call whose receiver is that property. Both gaps were discovered via a fixture that initially used these exact shapes and silently produced zero findings; each was routed around (by using a no-transform binding and a `call`-type source instead) rather than fixed, to keep this task scoped to CFG body recursion. |
| C / C++  | `parser-cpp.js`       | Hand-rolled parser (functions, qualified names, CFG lowering). Dispatched by extension (`c/cc/cpp/cxx/h/hh/hpp/hxx`) in both `buildProjectIR` and `buildProjectIRAsync`. |
| Long-tail (rust/solidity/go/swift/dart) | `tree-sitter-loader.js` | **Optional** `web-tree-sitter` + `tree-sitter-wasms` (ABI-pinned 0.20.8 ↔ 0.1.13), lazy + degrades when absent. Powers `sast/tree-sitter-sinks.js` (opt-in via `AGENTIC_SECURITY_TREE_SITTER=1`). Marked `--external` in the build so the committed bundle never embeds WASM. |

## Python parser — dual-path with auto fallback

The Python pipeline has two implementations. The dispatcher in `index.js`
picks one at scan time:

```
AGENTIC_SECURITY_PY_PARSER=auto    (default) — try CST, fall back to regex
AGENTIC_SECURITY_PY_PARSER=cst     force CST; error if python3 missing
AGENTIC_SECURITY_PY_PARSER=regex   force regex
```

### Why two

The regex parser (`parser-py.js`) was the original v1. It's a hand-rolled
indentation walker with a balanced-paren expression matcher. It admits in
its own comments to dropping:

- list / dict / set / generator comprehensions
- decorators (parsed but body never lowered)
- `match` statements
- `async` / `await` (modeled as transparent unwrap)
- lambda bodies (collapsed to opaque)

Real-world Python is full of these. The taint engine silently no-ops on
every dropped function.

The CST parser (`parser-py-cst.js`) shells out to a small Python helper
script (`parser-py.helper.py`) that uses the stdlib `ast` module — zero
external dependencies, ships with every Python 3.8+ install. The helper
emits the same core IR shape (`{functions[{qid,name,line,params,cfg,file}],
topLevel}`) as the regex parser, **with one exception below.** The CFG is
built from the real AST, so:

- decorators don't drop the function record
- async def is recognized
- match statements don't drop the function (the body's `case` arms are a
  noop placeholder for now — future work — but the function is captured)
- comprehensions surface their elt expression so taint propagates through
  `[x for x in untrusted]`
- nested function defs become separate entries in `functions[]`
- `def f(x=Foo(1,2))` and `db.execute(sanitize(x))` parse correctly
- **`fn.calls` (CST path only)** — `parser-py-cst.js` derives
  `calls: [{site, callee, args, line}]` from the CFG after parsing (statement-
  position calls, plus calls embedded in an assign's RHS, a return/throw
  value, or an if condition). **The regex parser (`parser-py.js`) does not
  emit `fn.calls` at all.** In practice: a scan that falls back to the regex
  parser (no `python3` on PATH, too old, or the helper failing) still
  produces findings, but Python loses cross-function (interprocedural) taint
  tracking for that run — `tabulation.js`, `dataflow/index.js` and
  `callgraph.js` all read `fn.calls`, and an absent/empty array there means a
  function's call sites are invisible to them, same as if it called nothing.

### Cost

- One `python3` subprocess **per `runScan`** (NOT per file). All Python
  files in the project go in a single batched stdin payload, parsed in a
  single linear loop on the Python side.
- Capability probe (`python3 --version`) runs ONCE per process and is
  cached.
- When the helper crashes mid-batch, the dispatcher silently falls back
  to the regex parser. Set `AGENTIC_SECURITY_PY_PARSER_DEBUG=1` to see
  the failure on stderr.

### When `auto` falls back to regex

- `python3` / `python` not on PATH
- Python version < 3.8
- helper script's stdin JSON corruption
- helper subprocess timeout (30 s for the whole batch — generous;
  `AGENTIC_SECURITY_PY_BATCH_TIMEOUT_MS`)
- capability probe timeout (5 s; `AGENTIC_SECURITY_PY_PROBE_TIMEOUT_MS`)
- helper output isn't parseable JSON

Each of these is a real failure mode; the regex fallback keeps the scan
producing findings instead of returning empty.

### Fallbacks are recorded, not silent

Every fallback above calls `noteParserDegradation(reason)`. Read it with
`pythonParserDegradation()` and clear it with `resetPythonParserDegradation()`
(both re-exported from `./index.js`).

This exists because a silent fallback is indistinguishable from a detection
regression: no `fn.calls` means no interprocedural Python taint, so a test
that *depends* on interprocedural analysis just stops finding anything. The
CVE-replay corpus gate (`bench/cve-replay/runner.mjs`) resets the record
before each deep Python entry and checks it after, reporting `env-error` and
exiting 3 instead of scoring a phantom `pre:FN`. It had already produced a
real flake: exit 1 `REGRESSED` then exit 0 on the same clean tree, minutes
apart, purely from machine load.

Two hardening changes back this:
- The probe timeout is **not cached**. `spawnSync` reports a timeout via
  `r.error.code === 'ETIMEDOUT'` with a null status — that is a load symptom,
  not "python is missing", so it does not poison `_capability` for the rest
  of the process. Only a genuine `no-python3-on-path` is cached.
- Budgets were raised (1.5 s → 5 s probe, 10 s → 30 s batch) and made
  env-tunable for constrained runners.

If you add a new caller that requires the CST path, check
`pythonParserDegradation()` rather than assuming the parse you got is the
parse you asked for.

### What CST models (and the one remaining limit)

The helper now lowers — and the dataflow engine propagates taint through — all
of the constructs this section once listed as unmodeled. Verified end-to-end in
`test/parser-py-cst.test.js` (`#16` flow tests):

- `match` case bodies — each `case` arm lowers to an `if` (the pattern) plus its
  body block; a capture pattern (`case Foo(x)`) emits an assign for the binding.
  Taint flows source → through a case body → sink.
- walrus `:=` — the named binding is tracked as its own assign, both at statement
  position and inside `if`/`while` tests (`_emit_walrus_assigns`).
- comprehension generators — the loop-var assign from the iter AND the
  generator's own `if` filters are emitted (`for x in iter if cond`).
- destructuring assignment (`a, b = expr`) — one assign per target, sourced from
  the element (`member[]`) of the RHS.

**Remaining limit (a deep-engine collection-element trait, NOT a dropped CFG
node):** taint carried through the *element* of a destructured tuple or a
comprehension result — `a, b = src1, src2; sink(a)` or `xs = [src…]; sink(xs[0])`
— does not always reach a finding. That's the collection-element-taint limitation
tracked in `../dataflow/CLAUDE.md`; the CFG nodes are present, the element-level
propagation is the open item.

## IR shape contract

Every parser must produce this shape:

```js
{
  file: 'rel/path.py',
  functions: [
    {
      qid: 'file.py::name@line#sha',  // stable cross-file identifier
      name: 'function_name',
      line: 42,
      params: ['arg1', 'arg2', ...],
      paramAnnotations: [{index, name, decorator}],  // R14(a): OPTIONAL — present only
                                                        // when a param carries a recognized
                                                        // framework decorator/attribute.
                                                        // Populated by parser-cs.js,
                                                        // parser-js.js, parser-java.js.
      file: 'file.py',
      cfg: {
        entry: 'nodeId',
        exit:  'nodeId',
        nodes: {
          [nodeId]: {
            kind: 'entry'|'exit'|'noop'|'loop-header'|'assign'|'call'
                  |'if'|'return'|'throw'|'unknown',
            line: number,
            succ: [nodeId, ...],
            pred: [nodeId, ...],
            // kind-specific:
            // assign:  target (string or null), source (expr)
            // call:    callee (string or expr), args ([expr])
            // if:      cond (expr)
            // return:  value (expr or null)
          }
        }
      }
    }
  ],
  topLevel: null,   // qid of the synthetic <module> function wrapping
                    // top-level statements, or null if the file has none
                    // worth lowering. JS, Python (CST + regex), PHP, and
                    // Ruby all populate this (PRD R14(b)); the other IR
                    // languages still leave it null.
}
```

Expression shape (returned by `source`, `cond`, `args[i]`, etc.):

```js
{ kind: 'literal',  value: any }
{ kind: 'ident',    name: 'x' }
{ kind: 'member',   object: expr, prop: 'attr' }
{ kind: 'binary',   op: '+', left: expr, right: expr }
{ kind: 'logical',  op: 'and'|'or', left: expr, right: expr }
{ kind: 'tpl',      parts: [expr, ...] }
{ kind: 'call',     callee: string|expr, args: [expr, ...] }
{ kind: 'array',    elements: [expr, ...] }
{ kind: 'object',   props: [{value: expr}, ...] }
{ kind: 'union',    branches: [expr, expr] }
{ kind: 'unknown' }
```

Any change to this shape must update **all** parsers AND the dataflow
engine — `scanner/src/dataflow/engine.js` is the contract reader.

## Adding a Python construct

1. Add a recognizer + lowerer branch in `parser-py.helper.py`'s
   `_lower_stmt` or `_lower_expr` function.
2. Add a fixture-style test in `scanner/test/parser-py-cst.test.js`.
3. Run `npm run test:dataflow` to confirm no IR-consumer regressions.
4. Optionally: add a corresponding case to `parser-py.js` so the regex
   fallback handles the same shape (but don't block on this — the regex
   parser is a fallback, not a target).

## When to retire the regex parser

The regex parser stays as long as some customers run scans on machines
without Python 3.8+. Realistic CI / dev environments have Python; locked-
down enterprise runners sometimes don't. Targets for retirement:

- Two minor releases with zero `parser-py-cst → regex` fallbacks reported
  via the optional telemetry surface.
- Or, the `AGENTIC_SECURITY_PY_PARSER` env defaults to `cst` (strict
  mode) for one release with no customer complaint tickets filed.
- The `fn.calls` gap above is a concrete, ongoing argument for retirement:
  every fallback to the regex parser is now also a silent loss of Python
  interprocedural analysis, not just the older, vaguer "some constructs get
  dropped" cost.
