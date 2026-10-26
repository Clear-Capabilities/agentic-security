# DAG improvements: implementation status

Integrated at `6aae5f32` on branch `feat/dag-improvements`. 66 of 67 requirements verified; 1 in progress; 0 pending.

Verified means the requirement's acceptance tests pass in the integrated tree. All new behavior is Preview (see `docs/security-graph/graph-precision.md`), off by default or additive.

## Open items
- R07.7: the owned-worker watchdog is not wired into the scan driver.
- Performance targets missed or partly met: demand-mode sink queries (1.8x cold index on this repository, 10 of 30 queries fell back to full analysis); incremental analysis (deep stage meets 3x, end to end 1.8x to 2.9x; no benefit above about 5000 functions at the default summary budget).
- Benchmarks (`bench/dag`): evidence replay rate, false source attribution and impossible call/return witnesses are not yet measured. Labeled precision on the pinned JS and Nix samples is low and the multi-service fixture finds 3 of 8 labeled positives.
- Not wired into a normal scan: boundary contracts (library entry point), witness building (no persisted hop stream), the graph view layer, demand queries.
- SMT: an optional z3 backend now exists (`lineage/smt-z3-backend.js`, `AGENTIC_SECURITY_LINEAGE_SMT=z3`, lazy, only `unsat` over a verified encoding reduces anything). It is reached only through the async path-evidence entry points; the synchronous graph build still uses the abstract domains alone, and z3 is not part of the default scan.
- Now reachable from the command line, opt-in and off by default (a default scan is unchanged; Preview): `dataflow view` (typed graph view and SCC condensation), `dataflow contracts` (boundary contracts), `dataflow sink-query` (demand reverse taint), `dataflow plan-cuts` (already registered; now carries a completion contract and an end-to-end test) and `witness build|verify` (signed witness bundles). Each report carries a completion status and never allows a negative claim the engine did not earn. Suite: `scanner/test/cli/dag-commands.test.js`. Usage: `docs/security-graph/graph-precision.md#commands`.
- Still not wired: nothing runs during a normal scan, no MCP tool was added (the tool count is pinned), `witness build` re-runs the field analysis because a scan does not persist the hop stream, witness runtime-support and exploit-proof inputs are not exposed on the command line, and only the dataflow graph view is exposed (provenance, semantic, artifact and cross-repo views stay library API).
- No real SMT solver ships; only the cancellable orchestration interface and a stub.
- Java parser tests fail only where `scanner/vendor` is missing (worktrees); they pass in the main checkout.

## Per-workstream pointers
DAG-01 `scanner/src/graph/scc.js`, `lineage/scc-solver.js`; DAG-02 `dataflow/demand-query.js`; DAG-03 `lineage/correlation.js`; DAG-04 `lineage/path-predicates.js`, `control-credit.js`; DAG-05 `dataflow/dep-fingerprint.js`, `incremental-session.js`; DAG-06 `scanner/src/graph/`; DAG-07 `lineage/completion.js`, `continuation.js`, `owned-worker.js`; DAG-08 `lineage/boundary-contract.js`; DAG-09 `lineage/cut-planner.js`; DAG-10 `posture/witness-bundle.js`.
