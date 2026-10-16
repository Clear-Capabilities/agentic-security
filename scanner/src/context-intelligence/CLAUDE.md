# context-intelligence/

Deterministic Context Intelligence (the `context` command). Opt-in and additive: nothing in the default scan imports this directory. Guide: `docs/guides/context-intelligence.md`; architecture: `docs/architecture/context-intelligence.md`.

## Invariants (break one and a test fails)

- `build` is deterministic and makes no model or network call. Same snapshot and config give byte-identical manifests.
- Unresolved is never dropped. A material unresolved edge, a budget omission, a cap or a split prevents `complete`.
- A control that runs after the sensitive operation is `evaluated_and_ineffective`, never protection.
- Model output cannot set severity. A citation outside the bundle invalidates the review. Severity comes from the existing confirmation tier.
- Store writes are atomic and refuse links and unsafe paths. Stored packages are re-checked against their hashes.
- A job with no verified result is missing coverage, never a clean result.
- Names from the repository (route strings, file names) are data: sanitised before they are printed, never placed in prompt text outside the fence.
- Source reaches a non-loopback endpoint only with an explicit approval, and the egress policy still applies after it.
- A citation is checked for range AND for being about the cited lines. `no_issue_observed` needs a control the deterministic pass also found.
- Orderings that reach a hashed value use `cmpCodeUnit`, never the locale.
- Evaluation is synthetic. Scorecards must say so and must not state an accuracy claim. Holdout use is ledgered.

## Where things are

See the module table in the architecture doc. Tests: `test/context-intelligence/` (in the `test:discovery` scope). The capability matrix in `capabilities.js` cites test files; `build-js.test.js` checks they exist.

## Reuse, do not fork

Model calls go through `discovery/llm-invoke.js` and the egress policy. Confirmation, refutation and judging are `discovery/{confirm,disprove,judge}.js`. Grouped intervals come from `posture/evaluation/interval.js`. State paths come from `posture/state-dir.js`.
