# DAG improvements: implementation status

Integrated at `6aae5f32` on branch `feat/dag-improvements`. 66 of 67 requirements verified; 1 in progress; 0 pending.

Verified means the requirement's acceptance tests pass in the integrated tree. All new behavior is Preview (see `docs/security-graph/graph-precision.md`), off by default or additive.

## Open items
- R07.7: the owned-worker watchdog is not wired into the scan driver.
- Performance: the demand-query 2x target is now met on this repository (23.4x per query with the index built per query; 3 of 30 sampled queries, 75 of 982 sink sites, still use the full path). Incremental analysis meets 3x end to end on `scanner/src` (4.3x) but not on the two synthetic projects (2.5x and 2.4x); no benefit above about 5000 functions at the default summary budget. Details in the Performance follow-up section.
- Benchmarks (`bench/dag`): evidence replay rate, false source attribution and impossible call/return witnesses are measured (see `bench/dag/results/`). Labeled precision on the pinned JS and Nix samples is now 5 of 8 and 6 of 8 (was 5 of 25 and 6 of 17; see "Labeled precision work" below). The multi-service fixture still finds 3 of 8 labeled positives: the five misses need the cross-service boundary join (DAG-08, not wired into a normal scan) and a queue-consumer source model, neither of which was added.
- Performance targets, after the profiling pass recorded under "Performance follow-up" below: demand-mode sink queries now meet the 2x target on this repository (23.4x per query with the index built per query, 3.7x averaged over the 30-query sample including the queries that take the full path; 75 of 982 sink sites still take the full path, all at the caller-depth limit). Incremental analysis meets 3x in the deep stage on every project measured at the raised summary budget and 3x end to end on this repository's source (4.3x), but NOT end to end on the two synthetic projects (2.5x and 2.4x); at the default summary budget, projects of about 5000 functions or more still run cold and the warm run is slower than the cold one (0.8x in the deep stage).
- Benchmarks (`bench/dag`): evidence replay rate, false source attribution and impossible call/return witnesses are not yet measured. Labeled precision on the pinned JS and Nix samples is low and the multi-service fixture finds 3 of 8 labeled positives.
- Not wired into a normal scan: boundary contracts (library entry point), witness building (no persisted hop stream), the graph view layer, demand queries.
- SMT: an optional z3 backend now exists (`lineage/smt-z3-backend.js`, `AGENTIC_SECURITY_LINEAGE_SMT=z3`, lazy, only `unsat` over a verified encoding reduces anything). It is reached only through the async path-evidence entry points; the synchronous graph build still uses the abstract domains alone, and z3 is not part of the default scan.
- Now reachable from the command line, opt-in and off by default (a default scan is unchanged; Preview): `dataflow view` (typed graph view and SCC condensation), `dataflow contracts` (boundary contracts), `dataflow sink-query` (demand reverse taint), `dataflow plan-cuts` (already registered; now carries a completion contract and an end-to-end test) and `witness build|verify` (signed witness bundles). Each report carries a completion status and never allows a negative claim the engine did not earn. Suite: `scanner/test/cli/dag-commands.test.js`. Usage: `docs/security-graph/graph-precision.md#commands`.
- Still not wired: nothing runs during a normal scan, no MCP tool was added (the tool count is pinned), `witness build` re-runs the field analysis because a scan does not persist the hop stream, witness runtime-support and exploit-proof inputs are not exposed on the command line, and only the dataflow graph view is exposed (provenance, semantic, artifact and cross-repo views stay library API).
- No real SMT solver ships; only the cancellable orchestration interface and a stub.
- Java parser tests fail only where `scanner/vendor` is missing (worktrees); they pass in the main checkout.

## Labeled precision work

Measured by `node bench/dag/run.mjs` on the pinned projects, same labels before and after. Before is a fresh run on the base commit (it reproduced the recorded numbers exactly).

| Measure | Before | After |
| --- | --- | --- |
| JS labeled precision (express, fastify) | 20.0% (5/25), recall 5/5 | 62.5% (5/8), recall 5/5 |
| Nix labeled precision (nixpkgs subset, home-manager) | 35.3% (6/17), recall 6/6 | 75.0% (6/8), recall 6/6 |
| Haskell labeled precision | 100% (16/16) | 100% (16/16), unchanged |
| JS development / held-out precision | 3/16 and 2/9 | 3/4 and 2/4 |
| Nix development / held-out precision | 5/13 and 1/4 | 5/7 and 1/1 |
| Multi-service fixture recall | 3/8 | 3/8, not improved |

The held-out column is not held out for these changes: the baseline lists every labeled false-positive site, so all of them were read while diagnosing. What stands in for a held-out check is that every change is a general rule about what a construct can do, each with a both-directions test (`bench/mutation/cases.mjs` `DAG_PRECISION_CASES`: the new cases fail on the base engine and pass now; the near-miss of each pair keeps its verdict), and the recall gates are unchanged (`bench:cve-replay:check` 220/220, `bench:layer-recall:check` equal, `bench:provenance-accuracy:check`, `bench:protection-verdict:check`, `bench:mutation:check` 302/302 verdict-flip correct).

What changed, by cause:

- A finding carried no `line` of its own (flow-pair and structural findings keep it on `sink.line`), so a file-level matcher credited it to every same-class label in the file. `finding-defaults.js` now backfills `line` from the sink, then the source. This corrects the measurement (two JS sites stop being counted against findings that never pointed at them) and it changes a reported location: a flow-pair finding's `line` is now its sink line, where the report layer used to fall back to the source line. Pattern findings are localised by the evaluation harness too (the synthetic suite's pattern layer no longer scores zero; the documented figures were updated).
- Open redirect: a target whose literal prefix fixes the origin (`'/user/' + id`, `'https://host/' + p`) cannot be steered off-origin. `'/' + x`, `'//' + x` and a host with no closing slash still can. The old shape check treated any leading quote as a static target, which was too broad.
- Reflected input: `req.session`, `req.user`, `req.app` and similar are server state; only request-input properties count, and not inside an HTML escaper.
- Blocking I/O: a synchronous call at module load delays startup once; inside any function body (including expression-bodied arrows and class bodies) it still fires.
- File serving: `sendFile`/`download` with an inline `root` option confine the path.
- Flow-pair identifier reads: words inside string literals and property names after a dot are not reads of a variable of that name (a property called `url` matched an unrelated parameter called `url`; the repository's own scan lost one such false positive).
- Logging by name: a PII word in message prose is not a logged value; the `address` a `listen` callback receives is the bound socket address.
- Nix: a reference to an option whose declared type bounds its value (bool, int, port, package, a listed enum) is a constant, so it is neither a shell-injection value nor a credential; documentation attributes of `mkOption` are not configuration; a set-valued binding is not a credential; a hex digest is bounded; an option named `package` or `fooPackage` that is not declared in scope is a store path.

Remaining false positives, by cause: two JS findings that the engine itself marks sanitized and proven clean (they stay reported by design, since demotion never removes a finding); one JS finding where a data-store lookup keyed by request input is treated as carrying the request input; two Nix findings where a path-typed option is interpolated in double quotes (a path can contain any character, so no type fact discharges it).
## Performance follow-up

Two targets had been missed and reported (demand queries 1.8x per query on this repository's own tree with 10 of 30 sampled queries on the full path; incremental end to end 1.8x to 2.9x). This pass profiled both, changed what the profiles showed, and re-measured on the same quiet machine. Results are unchanged by every change below: demand findings equal full analysis on all 982 sink sites of `scanner/src`, warm findings equal cold findings in `bench/dag-incremental` (three edits and the unchanged re-scan are checked per project), and the call-graph resolver returns the same callee for about two million sampled (name, file) pairs. Before and after were both run on the final tree, with the original `callgraph.js`, `access-paths.js` and `demand-query.js` swapped in for the before run.

What the profiles showed and what changed:

| Bottleneck | Measured | Change |
|---|---|---|
| Name resolution in `ir/callgraph.js` scanned every file's name table for each name not defined locally, which is every library call | 0.8 s of the 2.0 s warm deep stage (dependency fingerprinting calls the resolver for every name), most of the 3.5 s demand index, and the cold engine | An index from name to candidate qids in the same order, so the same first candidate is returned (`qidsByName`; a re-export index likewise). Same answers, cold and warm both faster |
| Demand selector: `instance-field` forced a full fallback in 238 of 982 sink sites, and a fallback cost more than a full run because the frontier ran first | 10 of 30 sampled queries; 9 to 23 s each against a 7.5 s full run | A `this` read in a JavaScript or TypeScript method now selects the class's methods and the receiver's field path at their call sites (`class-sibling`); `self` and `cls` are no longer receivers in JavaScript; constructor functions and non-JavaScript receivers still fall back |
| Demand frontier step cost: every work item rescanned all assignments and calls of its function | about 2x on the largest frontiers | Views by root segment (same order, same results), definer lookups memoized per file and name, class expansion once per class and path |
| `access-paths.js` `canonicalize` tested each path against every kept path | 1.3 s of a 2.2 s mid-size demand query; also the cold engine | Looks up the path's own prefixes instead. Output equal to the original on random and odd sets (`test/canonicalize-parity.test.js`) |
| Parse to IR dominated the warm run (3.3 s of 5.2 s on this repository) | Babel parse of every file on every scan | `dataflow/ir-cache.js`: a per-file IR record for JavaScript and TypeScript, used when the cross-scan cache is on. Ids are renumbered from the parser's own counter, a file is stored only after a walk proves it survives JSON exactly, records are digest-checked. Warm IR build 3.3 s to 1.9 s on this repository (1000 files: 1.11 s to 0.60 s) |

Measured (median, this machine, raised summary budget unless stated):

| Measure | Before | After |
|---|---|---|
| Demand, this repository: one query, index built per query | 1.9x (index 3.3 s of a 6.4 s full run) | 23.4x (index 0.18 s of a 4.3 s full run) |
| Demand: mean over the 30-query sample, fallbacks included, index and digest paid once | 1.2x | 3.7x |
| Demand: sink sites on the full path, all 982 sites of `scanner/src` | 238 (all `instance-field`) | 75 (all `depth-limit`) |
| Incremental end to end, 300 files x 8 functions | 1.8x (warm 469 ms, cold 830 ms) | 2.5x (warm 277 ms, cold 695 ms) |
| Incremental end to end, 1000 files x 8 functions | 2.2x (warm 1.67 s, cold 3.63 s) | 2.4x (warm 0.97 s, cold 2.26 s) |
| Incremental end to end, this repository's `scanner/src` | 3.2x (warm 5.16 s, cold 16.6 s) | 4.3x (warm 2.81 s, cold 11.9 s) |
| Incremental deep stage, same three | 3.6x, 4.4x, 7.1x | 3.4x, 3.2x, 9.3x |

Note on the ratios: the resolver and `canonicalize` changes also speed up the cold run that every ratio divides by, so a ratio can fall while the warm run gets faster (the deep-stage ratio on the synthetic projects did, from 3.6x to 3.4x and 4.4x to 3.2x, while the absolute warm deep stage fell from 136 ms to 103 ms and from 564 ms to 358 ms).

Targets still not met, and why:
- Incremental end to end on the two synthetic projects (2.5x and 2.4x against 3x). What remains in the warm run is the IR load (0.6 s of 1.0 s at 1000 files: one JSON read, digest check and id renumber per file) and the dependency bookkeeping of the deep stage (fingerprint 0.22 s, state read 0.06 s, restore, persist 0.06 s). Cutting either further needs a different record layout (one pack file, fingerprints cached per file), not tuning.
- Incremental at the default summary budget: unchanged. The engine stops computing summaries after 5000 per scan, the run is then incomplete and is never reused, so the warm scan pays the fingerprint and persistence cost for nothing (deep stage 0.8x, end to end 1.1x to 1.2x).
- Demand: 75 of 982 sink sites still take the full path. Each reaches the caller-depth limit (parsers and evaluators called from most of the program); with the limits removed one of them still selects 7357 of 14907 functions, so the selector, not the limit, is the bottleneck. Selecting less needs call-site-sensitive argument flow in the frontier, which it does not model.
- JavaScript and TypeScript only for the IR cache; the other languages parse on every scan.

## Per-workstream pointers
DAG-01 `scanner/src/graph/scc.js`, `lineage/scc-solver.js`; DAG-02 `dataflow/demand-query.js`; DAG-03 `lineage/correlation.js`; DAG-04 `lineage/path-predicates.js`, `control-credit.js`; DAG-05 `dataflow/dep-fingerprint.js`, `incremental-session.js`; DAG-06 `scanner/src/graph/`; DAG-07 `lineage/completion.js`, `continuation.js`, `owned-worker.js`; DAG-08 `lineage/boundary-contract.js`; DAG-09 `lineage/cut-planner.js`; DAG-10 `posture/witness-bundle.js`.
