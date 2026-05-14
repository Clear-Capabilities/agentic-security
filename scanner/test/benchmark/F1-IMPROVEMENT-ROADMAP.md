# Roadmap to raise strict F1 on owasp-benchmark and sard-juliet-java

After 0.34.5 curation, two real-world benchmarks remain engine-bound:

| App                | Current strict F1 | Target | Gap analysis |
|--------------------|------------------:|-------:|--------------|
| owasp-benchmark    | 80.0%             | ≥95%   | 4 families (sqli, xss, path-traversal, command-injection) at 59–73% strict. Caused by Java flow patterns regex+AST can't distinguish — constant-folded dead branches, inner-method indirection, ProcessBuilder argv vs string-concat, prepareStatement-with-`?`-placeholders. |
| sard-juliet-java   | 25.6%             | ≥75%   | Recall problem: R=17% overall, engine emits 4,778 findings against 13,366 expected. Several CWE families have ZERO scanner rules (open-redirect, insecure-http, data-exposure). |

Ten concrete improvements, ordered by leverage / effort:

## 1. Tree-sitter Java AST integration (foundation)

Replace regex-based source/sink detection with proper AST traversal.
`tree-sitter-java` is mature, ~100k LoC/sec, ships as WASM (zero native
deps). Prerequisite for items 2–7, 9–10.

**Effort:** 1–2 weeks
**Gain:** Foundation only — itself unlocks +30–40 pp across the other items.

## 2. Constant folding for `if` conditions

OWASP Benchmark patterns like:

```java
int x = 86;
if ((7 * 42) - x > 200) bar = "safe";   // always true (208 > 200)
else bar = param;                        // dead branch — taint here is unreachable
```

Implement a static evaluator handling:
- Integer arithmetic (+, −, *, /, %, bitwise)
- Boolean logic (&&, ||, !)
- Comparison operators (<, >, ==, !=, <=, >=)
- String literal comparison (`.equals`, `==` with literal)
- `System.getProperty()` against known-fixed values

**Effort:** 3–5 days
**Gain:** OWASP Benchmark +5–10 pp; Juliet ~+1 pp

## 3. Per-argument taint analysis at sinks

Today: when a source touches a handler, all sinks in that handler fire.
Change to: walk the specific argument expression passed to each sink and
verify it transitively contains a tainted value.

Fixes:
- `res.send({ok: true})` after handler touched `req.body` (juice-shop)
- `response.getWriter().println("static")` in OWASP Benchmark
- Constant-arg overloads of any sink

**Effort:** 3–5 days
**Gain:** OWASP Benchmark +3–5 pp; juice-shop edge improvement; Juliet ~+1 pp

## 4. Inter-procedural taint propagation (single-file)

OWASP Benchmark threads taint through helper methods:

```java
String bar = new Test().doSomething(request, param);
```

Where `doSomething` returns `param` (its second arg). Build a per-file
call graph indexing `(method, input-arg-position) → return-value-taint`,
then re-run taint with this index.

**Effort:** 1 week
**Gain:** OWASP Benchmark +5–8 pp; Juliet +3 pp; enables #5

## 5. Cross-file source/sink chaining (Juliet's biggest lever)

Juliet test files use shared helpers like `juliet.support.IO.readLine()`
and `Benchmark.getCookieValue()` that return user input. Currently the
engine sees the helper call but doesn't know it's tainted.

Index every method-return across the whole scan; if a method itself
contains a known source (e.g. `request.getParameter`), mark calls to
that method as new sources.

**Effort:** 1 week
**Gain:** **Juliet +20–30 pp** (single biggest recall lift); OWASP Benchmark +3 pp

## 6. SAST rules for Juliet's unmapped CWE families

Juliet has 1,154 expected entries in families with **zero current
scanner rules**:

| CWE | Family | Juliet count | Pattern |
|---|---|---:|---|
| CWE-601 | open-redirect | 542 | `response.sendRedirect(userInput)` |
| CWE-319 | insecure-http | 612 | `new URL("http://...")`, `URLConnection` cleartext |
| CWE-315 | data-exposure | 63 | `Cookie(name, secret)` without secure flag |

Add minimal rules with file-context gating to avoid FPs on non-Java
codebases.

**Effort:** 3–5 days
**Gain:** Juliet +10–15 pp

## 7. Sanitizer-aware Runtime.exec / ProcessBuilder

Distinguish argv form (SAFE) from shell form (UNSAFE):

```java
new ProcessBuilder(new String[]{"ls", userInput})  // SAFE: argv, no shell
new ProcessBuilder("sh", "-c", userCmd)             // UNSAFE: shell
Runtime.exec(new String[]{...})                     // SAFE
Runtime.exec(singleString)                          // UNSAFE
```

Add AST check: if first arg is `new String[]{}` literal, mark as
argv-form-safe and don't flag downstream.

**Effort:** 2 days
**Gain:** OWASP Benchmark +3–5 pp (~30 cmd-injection FPs); Juliet +1 pp

## 8. Recognize parameterized-query APIs as sanitizers

Today the engine treats all `Statement.execute(arg)` as sinks regardless
of arg shape. Refine:

| Pattern | Treatment |
|---|---|
| `prepareStatement(literalSql).setX(1, userVal)` | SAFE (`?` placeholder + bind) |
| `prepareCall(literalSql)` | SAFE |
| JPA `@Query("... ?1 ...")` | SAFE |
| Hibernate `createQuery(literal).setParameter(...)` | SAFE |
| MyBatis `#{var}` | SAFE; `${var}` UNSAFE |
| jOOQ `DSL.param(...)` | SAFE |

**Effort:** 3 days
**Gain:** OWASP Benchmark +3 pp; Juliet +2 pp

## 9. HttpServletRequest wrapper / framework-source recognition

OWASP Benchmark uses `org.owasp.benchmark.helpers.SeparateClassRequest`
which wraps the request and exposes `.getTheValue(name)` as a
tainted-returning getter. Currently the engine misses this entirely.

Rule: any class whose constructor takes `HttpServletRequest` is a
wrapper type. All public String-returning getters on wrapper types are
tainted sources.

Same pattern auto-recognizes:
- Spring `@RequestParam`
- JAX-RS `@QueryParam`, `@PathParam`, `@FormParam`
- Vert.x `RoutingContext.queryParam`
- Micronaut `@QueryValue`

**Effort:** 3 days
**Gain:** OWASP Benchmark +5–10 pp (source-side recall); Juliet +3 pp

## 10. Switch-case constant folding (companion to #2)

OWASP Benchmark uses:

```java
switch (CONST_VAR) {
  case 0: bar = "safe"; break;
  case 1: bar = param;  break;   // dead if CONST_VAR is known not 1
  default: bar = "safe";
}
```

With computable scrutinee. Apply the #2 evaluator to switch — if
scrutinee is literal/constant, eliminate unreachable cases from the
taint graph.

**Effort:** 2 days (reuses #2 evaluator)
**Gain:** OWASP Benchmark +2–5 pp

---

## Estimated cumulative impact

| Improvement | OWASP-B impact | Juliet impact |
|---|---:|---:|
| #1 Tree-sitter foundation | enables #2–7, #9–10 | enables #4–5 |
| #2 If-condition constant folding | +5–10 pp | +1 pp |
| #3 Per-arg taint at sinks | +3–5 pp | +1 pp |
| #4 Single-file inter-procedural | +5–8 pp | +3 pp |
| #5 Cross-file source chaining | +3 pp | **+20–30 pp** |
| #6 Missing-CWE Juliet rules | — | +10–15 pp |
| #7 ProcessBuilder argv-form | +3–5 pp | +1 pp |
| #8 Parameterized-query sanitizers | +3 pp | +2 pp |
| #9 Request-wrapper sources | +5–10 pp | +3 pp |
| #10 Switch constant folding | +2–5 pp | +1 pp |
| **Cumulative (lower bound)** | 80% → **~95%** | 26% → **~70%** |
| **Cumulative (upper bound)** | 80% → **~99%** | 26% → **~85%** |

## Regression guard

Every change must re-bench all 30 apps currently at strict F1 = 100%.
Items most likely to introduce regressions:

- **#5 cross-file source chaining** — broadens the taint surface; will
  likely introduce FPs in juice-shop, snyk-goof, nodegoat. Plan: run
  the full strict bench after each item; if any 100% app drops more
  than 2 pp, narrow the rule or add an allowlist before merging.
- **#6 new CWE rules** — open-redirect rule may fire on test apps
  doing `res.sendRedirect("/login")` correctly. Each new rule needs a
  `_NONPROD_RE` and a fixture pair.
- **#9 wrapper source recognition** — wide net, could over-detect. Plan:
  gate on "is this class actually instantiated with an HttpServletRequest
  somewhere in the same scan?"

## Reproduction

```bash
cd scanner

# Current baselines (re-run after each improvement)
node test/benchmark/realworld/bench-realworld.js --app owasp-benchmark    --no-wildcards
node test/benchmark/realworld/bench-realworld.js --app sard-juliet-java   --no-wildcards

# Full strict regression sweep (~30 minutes locally)
node test/benchmark/realworld/bench-realworld.js --all                    --no-wildcards
```

Updated 2026-05-14 (post 0.34.5). Pick items in dependency order: #1
unlocks 2/3/4/7/9/10; #4 unlocks #5; everything else is independent.
