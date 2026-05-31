# scanner/src/dataflow/

Layer-2 taint engine. Walks the Layer-1 IR (`../ir/`) with field-sensitive forward taint, consults a 200+ entry sources/sinks/sanitizers catalog, and emits findings tagged `parser: 'IR-TAINT'`.

## Scope — what we actually model

- **Intra-procedural field-sensitive taint** with access-path lattice (`access-paths.js`). `user.email` is distinguishable from `user.password`.
- **k=1 monovariant interprocedural return-taint.** `SummaryCache` (`summaries.js`) holds one summary per function under empty entry state. At an assign-from-call site, if the resolved callee's summary says `returnTainted`, the LHS becomes tainted. Premortem-derived; was previously dead code.
- **Catalog-driven source/sink/sanitizer matching.** Add entries in `catalog.js`. Each entry: `kind` ∈ {source, sink, sanitizer}, plus language + framework + match shape. 200+ entries spanning Express/Flask/FastAPI/Django/Rails/PHP/Go-net-http/Gin/Echo.
- **Path feasibility.** Constant-folds `if` conditions to prune unreachable branches.
- **Per-flow source attribution.** Sources reported on a finding are the ones actually reaching the sink argument (via free-var matching in the sink expression), NOT the first source the worklist happened to see. Premortem-derived.

## Scope — now modelled (was previously listed as gaps; closed in v0.66)

- **Mutated-parameter taint at call sites.** `engine.js` consults `SummaryCache.applyAtCallSite` at both assign-from-call and plain-call sites: a callee that mutates a param (e.g. `Object.assign(target, tainted)`, `_.merge`) taints the caller's argument variable. Covered by `test/interproc-k2.test.js`.
- **Higher-order taint flow.** `_higherOrderInvocations` recorded during `analyzeFunction` are consumed in `runTaintEngine`: the callback is resolved, analyzed with a tainted parameter, and its findings merged back into the caller (`_via: 'higher-order'`, capped at `HO_CAP`). Covered by `test/closure-capture.test.js` and `test/phase6-taint.test.js`.
- **Recursion via fixed point.** `runTaintEngine` runs a multi-pass fixed-point loop (`MAX_FP_ITERS=3`) until the summary cache stabilizes, so recursive cycles and call chains converge instead of under-approximating on a single pass.

## Scope — what we still do NOT model (today)

- **Arbitrary entry-taint-state context-sensitivity (k-CFA).** The fixed-point pre-pass computes each function's summary under the EMPTY entry state; call sites query with `entryStateFromCall`, so this is partial — but a function that is pure under empty entry yet vulnerable only under a specific tainted-arg shape is still approximated. Lifting to full context-sensitivity is tracked as FR-SEM-2 (roadmap #2).
- **Implicit flow.** `implicit-flow.js` exists for `if (tainted) { x = "yes" }` propagation but is conservative-by-default.

## Entry points

- `runTaintEngine(perFileIR, callGraph, opts)` — the public entry. Called from `engine.js` when `AGENTIC_SECURITY_DEEP=1` (or auto-enabled outside CI).
- `applyPathFeasibility` — constant-fold pass that runs before the worklist.
- `annotateBackwardSlices` — backward-slice annotation for already-emitted findings.
- `annotateProvenClean(findings, perFileIR)` (`proven-clean.js`) — proves a SQL sink is reached only through a parameterizer; sets `provenClean`. Wired by default in `runDeepAnalysis` (opt out: `AGENTIC_SECURITY_NO_PROOF_GATE=1`).
- `annotateProofGate(findings)` (`proof-gate.js`) — the precision gate. Consolidates `provenClean` + `_provenUnreachable` into one `finding.proof = { verdict, reasons }` and applies a **recall-preserving demotion** (lowers `confidence` + `confidenceTier` + `exploitabilityTier`, never `severity`). Runs in `engine.js` after confidence/exploitability, before mitigation/composite-risk. Default on.

## Configuration / opt-in

- `AGENTIC_SECURITY_DEEP=1` — enable the deep engine.
- `AGENTIC_SECURITY_DEEP_TIMEOUT_MS` — global walltime budget (default 300_000).
- `AGENTIC_SECURITY_DEEP_FN_LIMIT` — function-count budget (default 5000).
- `AGENTIC_SECURITY_DEEP_IN_CI=1` — also enable in CI (off by default; CI runs are time-bounded).

## Gotchas

- **Path attribution.** If you're adding a sink to the catalog, set `argIndex` carefully. `'all'` means "any tainted arg fires"; a numeric index pinpoints THE arg whose taint matters. Wrong here → noisy findings with confused traces.
- **Cache invalidation.** `SummaryCache` is in-memory per-scan. Cross-scan persistence lives in `incremental.js` (FR-incremental) but it's behind a separate flag. Don't conflate the two.
- **Recursion.** The cache returns a bottom summary (`_recursive: true`) when it hits a function already on the stack. The engine relies on fixed-point iteration to refine — but `runTaintEngine` does only ONE pass today. Recursive cycles will under-approximate.
- **`AGENTIC_SECURITY_BLIND_BENCH=1` disables the deep engine** along with everything else bench-shape. If you're trying to bench taint quality, run with both `AGENTIC_SECURITY_DEEP=1` and `AGENTIC_SECURITY_BLIND_BENCH=0` (the default).
