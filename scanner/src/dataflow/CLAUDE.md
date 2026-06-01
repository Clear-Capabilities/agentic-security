# scanner/src/dataflow/

Layer-2 taint engine. Walks the Layer-1 IR (`../ir/`) with field-sensitive forward taint, consults a 200+ entry sources/sinks/sanitizers catalog, and emits findings tagged `parser: 'IR-TAINT'`.

## Scope — what we actually model

- **Intra-procedural field-sensitive taint** with access-path lattice (`access-paths.js`). `user.email` is distinguishable from `user.password`.
- **Value-context-sensitive interprocedural taint (FR-SEM-2).** `SummaryCache` (`summaries.js`) holds a distinct summary per distinct entry-taint-state. A pre-pass computes the empty-entry base for every function; call sites then lazily compute the summary under their actual tainted-arg context (at both assign-from-call and plain-call sites) so a helper that is clean with clean args but tainted with user input is detected per call site. Bounded by a per-function context cap (`AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`, default 16; 0 = monovariant). Over the cap → reuse the empty-entry summary.
- **Catalog-driven source/sink/sanitizer matching.** Add entries in `catalog.js`. Each entry: `kind` ∈ {source, sink, sanitizer}, plus language + framework + match shape. 200+ entries spanning Express/Flask/FastAPI/Django/Rails/PHP/Go-net-http/Gin/Echo.
- **Path feasibility.** Constant-folds `if` conditions to prune unreachable branches.
- **Per-flow source attribution.** Sources reported on a finding are the ones actually reaching the sink argument (via free-var matching in the sink expression), NOT the first source the worklist happened to see. Premortem-derived.

## Scope — now modelled (was previously listed as gaps; closed in v0.66)

- **Mutated-parameter taint at call sites.** `engine.js` consults `SummaryCache.applyAtCallSite` at both assign-from-call and plain-call sites: a callee that mutates a param (e.g. `Object.assign(target, tainted)`, `_.merge`) taints the caller's argument variable. Covered by `test/interproc-k2.test.js`.
- **Higher-order taint flow.** `_higherOrderInvocations` recorded during `analyzeFunction` are consumed in `runTaintEngine`: the callback is resolved, analyzed with a tainted parameter, and its findings merged back into the caller (`_via: 'higher-order'`, capped at `HO_CAP`). Covered by `test/closure-capture.test.js` and `test/phase6-taint.test.js`.
- **Recursion via fixed point.** `runTaintEngine` runs a multi-pass fixed-point loop (`MAX_FP_ITERS=3`) until the summary cache stabilizes, so recursive cycles and call chains converge instead of under-approximating on a single pass.

## Scope — what we still do NOT model (today)

- **Call-string (k>1) context-sensitivity.** Context is the *value* abstraction — which params are tainted at entry — not the call stack. Two call paths that reach a helper with the same tainted-arg shape share a summary. Entry-state granularity is also param-level, not arbitrary access paths (`f(obj)` with `obj.a` tainted ≡ `obj.b` tainted).
- **Contexts beyond the per-function cap.** Once a function has been computed under `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` distinct tainted-arg shapes, further shapes fall back to the empty-entry summary (an under-approximation, bounded on purpose).
- **Implicit flow.** `implicit-flow.js` exists for `if (tainted) { x = "yes" }` propagation but is conservative-by-default.

## Precision: centralized SSRF/path guard recognition

`engine.js` `dropGuardedFindings(findings, fc)` runs after all detectors and drops a CWE-918 (SSRF) finding when the sink window has a host allow/deny check (deny/allow-list, `getHost`/`hostname` comparison, RFC1918/`169.254.169.254` prefix check, `ipaddress`/`getaddrinfo`/`ssrf-req-filter`), or a CWE-22 (path) finding when the window has a containment guard (`basename`/`GetFileName`/`secure_filename`/`send_from_directory`, or canonicalize+`startsWith`). It's the single source of truth so every emitter (regex, structural, per-language flow, PY-SAST, CSHARP, GO) is treated uniformly. The window is **comment-stripped** (a "no allow-list / 169.254…" vuln comment must not read as a guard). Opt out: `AGENTIC_SECURITY_NO_GUARD_RECOGNITION=1`.

## Entry points

- `runTaintEngine(perFileIR, callGraph, opts)` — the public entry. Runs from `engine.js` when `AGENTIC_SECURITY_DEEP=1`. **R1 (PRD §5):** the CLI entry (`bin/agentic-security.js#cmdScan`) sets that env var by default for local/interactive scans (not in CI, and not when `--no-deep`/`AGENTIC_SECURITY_DEEP=0`), so the default `/scan --all` runs deep. In-process callers (tests, the cve-replay corpus) invoke `runScan()` directly without the CLI default and therefore stay deep-off unless they set the env var themselves (e.g. `test/deep-taint.test.js`).
- `applyPathFeasibility` — constant-fold pass that runs before the worklist.
- `annotateBackwardSlices` — backward-slice annotation for already-emitted findings.
- `annotateProvenClean(findings, perFileIR)` (`proven-clean.js`) — proves a SQL sink is reached only through a parameterizer; sets `provenClean`. Wired by default in `runDeepAnalysis` (opt out: `AGENTIC_SECURITY_NO_PROOF_GATE=1`).
- `annotateProofGate(findings)` (`proof-gate.js`) — the precision gate. Consolidates `provenClean` + `_provenUnreachable` into one `finding.proof = { verdict, reasons }` and applies a **recall-preserving demotion** (lowers `confidence` + `confidenceTier` + `exploitabilityTier`, never `severity`). Runs in `engine.js` after confidence/exploitability, before mitigation/composite-risk. Default on.

## Configuration / opt-in

- `AGENTIC_SECURITY_DEEP=1` — enable the deep engine.
- `AGENTIC_SECURITY_DEEP_TIMEOUT_MS` — global walltime budget (default 300_000).
- `AGENTIC_SECURITY_DEEP_FN_LIMIT` — function-count budget (default 5000).
- `AGENTIC_SECURITY_DEEP_IN_CI=1` — also enable in CI (off by default; CI runs are time-bounded).
- `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` — distinct non-empty entry contexts kept per function (default 16; 0 = monovariant).

## Gotchas

- **Path attribution.** If you're adding a sink to the catalog, set `argIndex` carefully. `'all'` means "any tainted arg fires"; a numeric index pinpoints THE arg whose taint matters. Wrong here → noisy findings with confused traces.
- **Cache invalidation.** `SummaryCache` is in-memory per-scan. Cross-scan persistence lives in `incremental.js` (FR-incremental) but it's behind a separate flag. Don't conflate the two.
- **Recursion.** The cache returns a bottom summary (`_recursive: true`) when it hits a function already on the stack. The engine relies on fixed-point iteration to refine — but `runTaintEngine` does only ONE pass today. Recursive cycles will under-approximate.
- **`AGENTIC_SECURITY_BLIND_BENCH=1` disables the deep engine** along with everything else bench-shape. If you're trying to bench taint quality, run with both `AGENTIC_SECURITY_DEEP=1` and `AGENTIC_SECURITY_BLIND_BENCH=0` (the default).
