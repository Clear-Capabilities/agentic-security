# DAG improvements: implementation status

Integrated at `6aae5f32` on branch `feat/dag-improvements`. 66 of 67 requirements verified; 1 in progress; 0 pending.

Verified means the requirement's acceptance tests pass in the integrated tree. All new behavior is Preview (see `docs/security-graph/graph-precision.md`), off by default or additive.

## Open items
- R07.7: the owned-worker watchdog is not wired into the scan driver.
- Performance targets missed or partly met: demand-mode sink queries (1.8x cold index on this repository, 10 of 30 queries fell back to full analysis); incremental analysis (deep stage meets 3x, end to end 1.8x to 2.9x; no benefit above about 5000 functions at the default summary budget).
- Benchmarks (`bench/dag`): evidence replay rate, false source attribution and impossible call/return witnesses are measured (see `bench/dag/results/`). Labeled precision on the pinned JS and Nix samples is now 5 of 8 and 6 of 8 (was 5 of 25 and 6 of 17; see "Labeled precision work" below). The multi-service fixture still finds 3 of 8 labeled positives: the five misses need the cross-service boundary join (DAG-08, not wired into a normal scan) and a queue-consumer source model, neither of which was added.
- Not wired into a normal scan: boundary contracts (library entry point), witness building (no persisted hop stream), the graph view layer, demand queries.
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

## Per-workstream pointers
DAG-01 `scanner/src/graph/scc.js`, `lineage/scc-solver.js`; DAG-02 `dataflow/demand-query.js`; DAG-03 `lineage/correlation.js`; DAG-04 `lineage/path-predicates.js`, `control-credit.js`; DAG-05 `dataflow/dep-fingerprint.js`, `incremental-session.js`; DAG-06 `scanner/src/graph/`; DAG-07 `lineage/completion.js`, `continuation.js`, `owned-worker.js`; DAG-08 `lineage/boundary-contract.js`; DAG-09 `lineage/cut-planner.js`; DAG-10 `posture/witness-bundle.js`.
