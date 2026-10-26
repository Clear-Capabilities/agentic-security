# Graph precision, completeness and scale

This page describes the graph and reachability work specified in `AGENTIC_SECURITY_DAG_IMPROVEMENTS.PRD`. Every item is **Preview**. Each is off by default or purely additive, and none changes a GA result unless an option turns it on.

## What it adds

| Area | What you get | How to turn it on |
|---|---|---|
| Completion contract | Every analysis unit says `complete`, `partial` or `cancelled`. A stopped analysis, a coarser fallback context or a construction limit shows in `graph.scanHealth`, `coverage.analysisCompletion`, the limitations list and scan health. A query that did not finish never says "no path". | Always on. |
| Query budgets | Invalid budgets (NaN, Infinity, negative, fractional, over the bound) return `status: "invalid"`. Results carry `negativeClaimAllowed`. | Always on. |
| Cancellation | `signal` and `deadline` options stop the lineage analysis and report `cancelled`. | Options on the lineage build. |
| Recursion | The call graph is condensed into strongly connected components, callees are solved first, and recursive groups iterate to a fixed point or report `partial`. | Always on for the lineage driver. |
| Typed graph views | Read-only adapters and evidence-bearing crosswalks join findings, call sites, provenance witnesses and projected flows without merging the graph schemas. | Library API (`scanner/src/graph`). |
| Call-site correlation | Value versions and call-site identity keep two calls to one helper, sibling fields and overwritten values apart. | `correlationVersion: 2` or `AGENTIC_SECURITY_LINEAGE_CORRELATION=2`. |
| Demand reverse queries | A sink-rooted selector narrows analysis to the functions that can feed one sink argument, then corroborates with the forward engine. | `AGENTIC_SECURITY_DEMAND=1` and an explicit query list. |
| Path predicates and control credit | Branch conditions travel with each witness. A control earns credit only for its sink family, value version and covered paths. | `pathEvidence: true` or `AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES=1`. |
| Dependency-complete incremental analysis | Cached summaries are invalidated through the reverse dependency closure, including deleted and renamed functions. Corrupt or interrupted caches fall back to a cold scan and say why. | `AGENTIC_SECURITY_INCREMENTAL=1`. |
| Boundary contracts | HTTP, queue and storage contracts seed a consumer parameter or record field. Declared but unbound consumers are reported as gaps. | Library API (`runBoundaryTaint`). |
| Control placement planning | Minimum cuts over the modeled flow network, a labeled approximate planner for shared controls, and scenario validation of residual bypasses. | `dataflow plan-cuts`. |
| Witness bundles | A signed, replayable record of one path with its digests, transfer-model fingerprints, completion and four separate evidence statuses. | `buildWitnessBundle`; `verify-attestation --witness-artifacts`. |

## The optional z3 solver

Path conditions are decided by the bounded abstract domains first. A real solver backend (`scanner/src/lineage/smt-z3-backend.js`, on the optional `z3-solver` dependency) can be added behind them. It is off unless a solver is passed in or `AGENTIC_SECURITY_LINEAGE_SMT=z3` is set, and it is only reached through the async entry points (`evaluatePathEvidenceAsync`, `evaluateWitnessConditionsAsync`); the synchronous graph build never calls it, so a default scan loads nothing and its output does not change.

- **Only a verified encoding may say infeasible.** The conditions are translated to SMT-LIB with numbers as Real, variables renamed `v0..vN` and an unmodeled predicate encoded as "no constraint". A problem the translator cannot express exactly (a variable used as both a number and a string, a number with no plain decimal form, an unknown operator) is `unknown`, not `unsat`. A `sat` that relied on an unmodeled predicate is also `unknown`.
- **Only `unsat` reduces anything.** An `unsat` becomes `infeasible-under-model`, and the path is then listed and excluded from the all-paths-protected claim, exactly as for an interval contradiction. `sat`, `unknown`, timeout, an unavailable solver and a memory stop leave the abstract answer unchanged. An `unsat` over two branch arms inside a loop is not trusted, because the solver cannot see iterations.
- **Where it helps.** The interval domain cannot relate two variables, so a cycle such as `a < b`, `b < c`, `c < a` is feasible to it. With `consultOnFeasible` (on by default when the z3 switch is set) a `feasible-model` answer is also put to the solver. When the abstract answer is `unknown` (an unmodeled predicate beside the contradiction) the solver is asked regardless.
- **Bounds.** A per-query timeout (default 1000 ms), a memory cap (default 256 MB), the orchestrator's own deadline, and cancellation. A context that ignores its timeout is retired and reported unavailable. Only definitive answers are cached, keyed by the SMT-LIB text; the solver seed is fixed.
- **Cost, measured once on a development machine.** Loading the backend module adds under 1 ms to an import. The first query loads and initialises z3 (about 190 ms); later distinct queries took about 6 ms and a repeated one is served from the cache.
- **Limits.** Satisfiability is relative to the stated model, not the running program, and never implies a working exploit. Comparisons are treated as total orders over Real values, so NaN and loose-equality coercion are not modeled.

## What it does not claim

- "No modeled path" means the modeled graph has none. It says nothing about the software.
- A signature on a witness bundle proves the bundle is unmodified. It does not prove the transfer models are right.
- Reachability, satisfiability and runtime observations are not exploit proof.
- Runtime support for some edges does not support a whole path unless one compatible trace covers it.
- A hypothetical control placement is never verification. Only a rescan updates a remediation item.
- Recursive convergence uses a bounded fact domain with a documented widening. Real-code recursion often converges in two rounds because the engine returns empty summaries for recursive functions without a seed.

## Measured results

Measurements live in `bench/dag/` (labels, pinned projects, synthetic graphs), `bench/dag-demand/` and `bench/dag-incremental/`. Targets are targets, not results:

- Demand queries reached 277x per query with a warm index on this repository's own source, but only 1.8x when the index is built per query. The 2x target was missed on that cold figure, and 10 of 30 queries fell back to full analysis.
- Incremental analysis met 3x in the deep stage on every project measured. End to end the median was between 1.8x and 2.9x, below the target. At the default summary budget, projects of about 5,000 functions or more run cold.
- Labeled precision on the pinned JS and Nix samples is low (5 of 25 and 6 of 17 flagged sites were true), and the multi-service fixture finds 3 of 8 labeled positives. The numbers and their limits are in `bench/dag/results/`.

See `docs/implementation-status/dag-improvements.md` for the per-requirement status.
