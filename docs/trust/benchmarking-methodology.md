# Benchmarking methodology

<!-- seo: title="Benchmarking methodology: leakage controls and reproducibility" description="How Agentic Security measures detection quality without leaking the answer key, which gates exist, and what its published figures do and do not prove." -->

Quality claims about a security tool are easy to inflate. This page states how measurements here are made, what guards against leakage, and what the numbers do not prove.

## Principles

1. **A figure needs the command that produced it.** [METRICS](../METRICS.md) lists each number with its reproduction command.
2. **Leakage controls are central.** Benchmark inputs are stripped of vulnerability labels, CWE-bearing filenames and package or class names, comments, and good/bad naming conventions before the scanner sees them. A dedicated leakage audit fails closed on any residual answer-bearing string. Answer-key reading lives under `sast/bench-shape/` and is off by default; `AGENTIC_SECURITY_BLIND_BENCH=1` forces it off.
3. **Held-out only.** The calibration seed corpus fits the calibration table; calibration quality is never computed against the labels it was fitted on. Corpora are split into non-overlapping train, dev and test sets by structural template family, so near-duplicate variants never cross the boundary.
4. **Verdict correctness over detection count.** The mutation gate scores whether a semantics-preserving rewrite leaves the verdict alone and a semantics-changing near-miss moves it. Accumulating patterns cannot raise that score.
5. **Equality, not a floor.** The per-layer recall gate fails on both a regression and an unrecorded improvement, so a published table cannot go stale in silence.
6. **Independent accuracy is measured once, and it is low.** The only figure measured on code the engine was not built from: localized precision 6/19, recall 6/278, F1 0.040 (95% interval 0.013 to 0.075), 278 of 283 entries scored. Floors are pinned per language from the Wilson lower bound, and the release check fails a run that falls below them. Read [the evidence](../engineering-excellence/README.md) and its forensics before quoting any other number.
7. **No single-corpus score is portable.** External claims must run every auditor-verified corpus in blind mode and report macro-F1 with a Youden index and per-family confidence intervals. No benchmark scores are published in this repository; see `bench/README.md` for why.

## The gates

| Gate | What it protects |
|---|---|
| CVE replay corpus | Each entry must score pre-fix true positive and post-fix true negative |
| Mutation gate | Verdict-flip correctness |
| Per-layer recall | Which analysis layer detected each entry |
| Protection-verdict and provenance-accuracy gates | The graph's protection verdicts and Git provenance |
| Language-support gate | Haskell and Nix support, measured per capability and generated into docs |

## What the figures do not prove

- The independent measurement is one run on one population; it says the engine finds little there, not how it performs on your code.
- The regression corpus is mostly self-authored synthetic fixtures. It is a regression net, not a recall measurement on real-world code.
- The Haskell and Nix corpus is synthetic and template-generated, so 100% there describes robustness over those shapes.
- A passing gate is not a statement that the numbers are current. Check the date in [METRICS](../METRICS.md).
- None of this measures the agentic layers' discovery quality, which is advisory and not gated.

## Reproducing

```bash
cd scanner && npm run bench:layer-recall
cd scanner && npm run bench:cve-replay:check
cd scanner && npm run bench:mutation:check
```

See [METRICS](../METRICS.md) and [SCORECARD](../SCORECARD.md).
