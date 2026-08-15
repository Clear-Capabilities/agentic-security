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
⚠ Three defects made Java taint impossible until v0.136.3+: the sync-only call site; a CST walk looking for `blockStatement` on a `block` (java-parser nests `block → blockStatements → blockStatement`), which emptied every method CFG; and `exprFromCst` missing the `primary → primaryPrefix + primarySuffix` form that models **every** method call. Guarded by `test/java-taint-flow.test.js`. **Params are still not extracted** (`params: []`, marked "deferred" in the source), so Java interprocedural summaries are limited. |
| Ruby     | `parser-rb.js`        | Hand-rolled. **`DEF_RE` must not let `\s*` cross a newline** — it did, and the body slice then started after the method's first statement, silently dropping it from every method (a one-statement body became empty). Measured as Ruby 0/20 IR-TAINT recall in `bench/layer-recall`. Guarded by `test/parser-php-rb.test.js`. ⚠ Also emitted no `fn.calls` at all (every OTHER parser does) — `callgraph.js`'s edges/callersOf/resolveKnownCallee are built entirely from `fn.calls`, so this left dead-code demotion and any interprocedural signal that depends on real call-graph resolution (rather than engine.js's generic tainted-call-argument fallback) permanently blind to Ruby. Fixed by deriving `fn.calls` from the CFG via the shared `call-sites.js#callSitesFromCfg` (the same helper `parser-py-cst.js` uses) — Ruby's node shapes already matched its documented contract. Guarded by `test/parser-rb-calls.test.js`. |
| C#       | `parser-cs.js`        | Hand-rolled. ⚠ `_lowerExpr`'s string-concat branch **must** guard on `_splitTopLevelPlus` returning more than one part — when the `+` is nested inside parens the splitter returns the input unchanged and the branch recurses on the identical string (stack overflow, swallowed by `buildProjectIR`'s per-file catch, surfacing only as "no IR"). `new Type(args)` is lowered to a call so taint reaches constructor sinks such as `new SqlCommand`. Guarded by `test/parser-cs-kt.test.js`. |
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
