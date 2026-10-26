# Graph precision, completeness and scale

This page describes the graph and reachability work specified in `AGENTIC_SECURITY_DAG_IMPROVEMENTS.PRD`. Every item is **Preview**. Each is off by default or purely additive, and none changes a GA result unless an option turns it on.

## What it adds

| Area | What you get | How to turn it on |
|---|---|---|
| Completion contract | Every analysis unit says `complete`, `partial` or `cancelled`. A stopped analysis, a coarser fallback context or a construction limit shows in `graph.scanHealth`, `coverage.analysisCompletion`, the limitations list and scan health. A query that did not finish never says "no path". | Always on. |
| Query budgets | Invalid budgets (NaN, Infinity, negative, fractional, over the bound) return `status: "invalid"`. Results carry `negativeClaimAllowed`. | Always on. |
| Cancellation | `signal` and `deadline` options stop the lineage analysis and report `cancelled`. | Options on the lineage build. |
| Recursion | The call graph is condensed into strongly connected components, callees are solved first, and recursive groups iterate to a fixed point or report `partial`. | Always on for the lineage driver. |
| Typed graph views | Read-only adapters and evidence-bearing crosswalks join findings, call sites, provenance witnesses and projected flows without merging the graph schemas. | `dataflow view` (library API: `scanner/src/graph`). |
| Call-site correlation | Value versions and call-site identity keep two calls to one helper, sibling fields and overwritten values apart. | `correlationVersion: 2` or `AGENTIC_SECURITY_LINEAGE_CORRELATION=2`. |
| Demand reverse queries | A sink-rooted selector narrows analysis to the functions that can feed one sink argument, then corroborates with the forward engine. | `dataflow sink-query` (library: `AGENTIC_SECURITY_DEMAND=1` and an explicit query list). |
| Path predicates and control credit | Branch conditions travel with each witness. A control earns credit only for its sink family, value version and covered paths. | `pathEvidence: true` or `AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES=1`. |
| Dependency-complete incremental analysis | Cached summaries are invalidated through the reverse dependency closure, including deleted and renamed functions. Corrupt or interrupted caches fall back to a cold scan and say why. | `AGENTIC_SECURITY_INCREMENTAL=1`. |
| Boundary contracts | HTTP, queue and storage contracts seed a consumer parameter or record field. Declared but unbound consumers are reported as gaps. | `dataflow contracts` (library API: `runBoundaryTaint`). |
| Control placement planning | Minimum cuts over the modeled flow network, a labeled approximate planner for shared controls, and scenario validation of residual bypasses. | `dataflow plan-cuts`; the plan carries a completion `contract`. |
| Witness bundles | A signed, replayable record of one path with its digests, transfer-model fingerprints, completion and four separate evidence statuses. | `witness build` and `witness verify` (library: `buildWitnessBundle`; also `verify-attestation --witness-artifacts`). |

## Commands

None of these runs during a default scan; each runs only when you type it, so default scan output is unchanged. Every report carries a `completion` record using the shared vocabulary `complete`, `partial`, `cancelled`, `unavailable` or `invalid`. Exit codes: `0` a report was produced (read its completion status), `1` nothing usable could be produced (unavailable data, an invalid graph reference, a failed verification), `2` a usage error. Reports go to stdout, or to `--output <file>`.

| Command | What it does | Completion behavior |
|---|---|---|
| `dataflow view [path] [--node <id> [--direction in\|out\|both] [--relations a,b] [--origins a,b]]` | Read-only typed view over the signed lineage graph (needs a scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1`). Without `--node`: view identity, completion, and the strongly connected component condensation of the data-flow relation, with every cyclic component listed and none removed. With `--node`: the neighbours the relation and origin filter allow. Declared and observed edges are walked only when you ask for those origins. | Completion is the graph's own. A dangling node id is `invalid`. `negativeClaimAllowed` is always false: a view is a lens, and an absent edge is an absent modeled edge. |
| `dataflow contracts [path] [--contracts <file>]` | Binds boundary contracts (default file `.agentic-security/boundary-contracts.json`) to parser-resolved consumer sites, seeds taint at the mapped consumer fields only, and reports findings, bindings, coverage gaps, rejected contracts and a service-level field propagation summary. | An unbound contract is a gap and never a finding. Any gap, rejection or budget stop makes the run `partial`. No contracts file is `unavailable`. Every finding is `modeledInput: true`, `observed: false`, `exploited: false`. No finding is not a clean result. |
| `dataflow sink-query [path] (--list \| --file <rel> --line <n>) [--mode demand\|full\|compare]` | Demand-driven reverse taint for one sink site: a backward frontier selects functions, and the ordinary forward engine runs over the selection. `--list` shows the recognised sink sites. `--mode compare` also runs the full analysis and states whether the findings are equal. Options: `--arg-index`, `--sink-id`, `--access-path`, `--rule-family`, `--max-work`, `--max-caller-depth`, `--on-limit full\|partial`. | Verdicts are `flow-found`, `no-flow-in-modeled-scope` and `unknown`; there is no "safe". `no-flow-in-modeled-scope` appears only when the completion envelope allows a negative claim, scoped to the modeled graph. A limit or unsupported construct widens to the full function set by default (`--on-limit full`), or reports `partial` with the claim withheld (`--on-limit partial`). An unknown site is `unavailable`. |
| `dataflow plan-cuts [path] --candidates <file> --output <file>` | Minimum-cost control placement over the modeled flow network. | The plan's `contract` is `complete` only for a finite cut over a graph known complete. No modeled path (`no-flow`) is `partial` with reason `no-modeled-path`. `negativeClaimAllowed` is always false and `verified` is always false: only a rescan through the remediation gate verifies anything. |
| `witness build [path] --out <dir> [--sink <id>] [--list-sinks]` | Re-runs the field analysis over the project (a scan does not persist the hop stream), reconstructs a bounded path, and writes `<dir>/witness.json` signed with the same Ed25519 key as `attest`, plus `<dir>/artifacts/graph.json` and `<dir>/artifacts/provenance.json`. Source files are bound by digest, not copied. | If no modeled path exists the command is `unavailable` (exit 1) and writes nothing; it never emits an empty bundle. The bundle records its own completion (`complete` or `partial`), and a partial witness prints a warning. |
| `witness verify <bundle.json> [--public-key <path>] [--artifacts <dir> --root <project>] [--json]` | Signature check with a public key; with `--artifacts` also an offline replay of every edge and call/return binding against the recorded artifacts, reading source blobs from `--root`. | Verdicts are `replayed`, `integrity-only` (no replay attempted) and `invalid`. A changed bundle, source file, artifact or key is `invalid`. A valid signature proves integrity only. |

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

- Demand queries now reach 23.4x per query on this repository's own source with the index built per query (3.7x averaged over a 30-query sample that includes fallbacks); 3 of 30 sampled queries, and 75 of 982 sink sites, still use full analysis, all at the caller-depth limit.
- Incremental analysis meets 3x end to end on this repository's own source (4.3x) and in the deep stage on every project measured, but end to end on the two synthetic projects it is 2.5x and 2.4x, below the target. At the default summary budget, projects of about 5,000 functions or more run cold.
- Labeled precision on the pinned JS and Nix samples was low (5 of 25 and 6 of 17 flagged sites were true) and is now 5 of 8 and 6 of 8 after general precision rules (see `docs/implementation-status/dag-improvements.md`; the held-out split was read while diagnosing, so it is not independent). The multi-service fixture still finds 3 of 8 labeled positives: the missing ones need the cross-service boundary join that is not wired into a normal scan. The numbers and their limits are in `bench/dag/results/`.
- Demand queries reach 820x per query with a warm index on this repository's own source and 23x when the index is built per query (the 2x target is met). Averaged over a 30-query sample that includes the queries that take the full path, the speedup is 3.7x. Across all 982 sink sites of the repository's own source, 75 (8 percent) still take the full path, every one at the caller-depth limit.
- Incremental analysis meets 3x in the deep stage on every project measured at the raised summary budget (3.2x to 9.3x). End to end the median is 2.5x and 2.4x on the two synthetic projects, below the target, and 4.3x on this repository's own source, above it. At the default summary budget, projects of about 5,000 functions or more run cold, and the warm run is slower than the cold one.
- Labeled precision on the pinned JS and Nix samples is low (5 of 25 and 6 of 17 flagged sites were true), and the multi-service fixture finds 3 of 8 labeled positives. The numbers and their limits are in `bench/dag/results/`.

See `docs/implementation-status/dag-improvements.md` for the per-requirement status.
