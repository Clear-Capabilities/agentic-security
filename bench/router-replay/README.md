# router-replay

RouterBench-style evaluation of the **model-cost optimizer**
(`hooks/model-cost-advisor.js`) against a labelled corpus. It answers the
question the optimizer's unit tests can't: *is the cheaper-model advice actually
good, or is it worse than just picking one model?*

Motivated by RouterBench (arXiv:2403.12031), whose headline lesson is that LLM
routing is easy to get wrong and **must be scored against an oracle** — most
learned routers there barely beat a trivial "always one model" baseline.

## What it measures

| Metric | Meaning |
|---|---|
| **downgrade-regret** (headline) | fraction of prompts the router sent to a model *weaker* than the oracle needs — advice that would have failed |
| tier accuracy | predicted tier == true tier |
| overspend | router picked a dearer model than needed (quality fine, money wasted) |
| sufficiency (quality) | fraction where the router's pick was at least as capable as the oracle, with a Wilson 95% CI |
| **hull advantage** | router quality minus the non-decreasing convex hull of the three single-model baselines at the router's mean cost. **≤ 0 ⇒ the router is dominated by just picking one model** (RouterBench's null result) |

The oracle = the cheapest model sufficient for a prompt's *true* difficulty.

## Method (non-circular)

Each corpus entry carries a hand-authored `trueTier` (`simple|medium|complex`).
`trueTier` drives the oracle and the cost model; the classifier's *predicted*
tier (`classifyTier`) is what gets graded. The thing under test never feeds its
own ground truth.

## Run

```bash
npm run bench:router-replay                 # full report (from scanner/)
npm run bench:router-replay:check           # gate: non-zero on regret drift
npm run bench:router-replay:update-baseline # record per-entry verdicts
node ../bench/router-replay/runner.mjs --json   # machine-readable
```

The gate (`baseline.json`) records a per-entry `pass|regret` verdict and fails
the build when a previously-clean entry regresses to downgrade-regret, a new
entry has regret, or a baselined entry vanishes — same shape as
`bench/cve-replay`. Refresh intentionally with `:update-baseline`.

## Honesty / limitations

- `trueTier` labels are **hand-authored** (like `bench/cve-replay`). This grades
  the classifier against our own judgement of difficulty, **not** against measured
  per-model answer quality. It is a regression gate + a routing-value sanity
  check, not a real AIQ.
- To make the AIQ real, replace the labels with **measured** per-model
  (quality, cost) outcomes — then the hull-advantage number becomes a genuine
  cost-quality verdict. That is the next step (see
  `docs/MODEL_COST_OPTIMIZATION_PRD.md` and the RouterBench analysis plan).
- The current baseline shows the v0.120.0 heuristic is **dominated** (negative
  hull advantage) with non-trivial downgrade-regret — i.e. this harness is
  already earning its keep by flagging that the classifier needs the quality
  term and calibration work before the optimizer reliably beats a fixed default.
