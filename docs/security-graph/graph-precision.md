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

## What it does not claim

- "No modeled path" means the modeled graph has none. It says nothing about the software.
- A signature on a witness bundle proves the bundle is unmodified. It does not prove the transfer models are right.
- Reachability, satisfiability and runtime observations are not exploit proof.
- Runtime support for some edges does not support a whole path unless one compatible trace covers it.
- A hypothetical control placement is never verification. Only a rescan updates a remediation item.
- Recursive convergence uses a bounded fact domain with a documented widening. Real-code recursion often converges in two rounds because the engine returns empty summaries for recursive functions without a seed.

## Measured results

Measurements live in `bench/dag/` (labels, pinned projects, synthetic graphs), `bench/dag-demand/` and `bench/dag-incremental/`. Targets are targets, not results:

- Demand queries reach 820x per query with a warm index on this repository's own source and 23x when the index is built per query (the 2x target is met). Averaged over a 30-query sample that includes the queries that take the full path, the speedup is 3.7x. Across all 982 sink sites of the repository's own source, 75 (8 percent) still take the full path, every one at the caller-depth limit.
- Incremental analysis meets 3x in the deep stage on every project measured at the raised summary budget (3.2x to 9.3x). End to end the median is 2.5x and 2.4x on the two synthetic projects, below the target, and 4.3x on this repository's own source, above it. At the default summary budget, projects of about 5,000 functions or more run cold, and the warm run is slower than the cold one.
- Labeled precision on the pinned JS and Nix samples is low (5 of 25 and 6 of 17 flagged sites were true), and the multi-service fixture finds 3 of 8 labeled positives. The numbers and their limits are in `bench/dag/results/`.

See `docs/implementation-status/dag-improvements.md` for the per-requirement status.
