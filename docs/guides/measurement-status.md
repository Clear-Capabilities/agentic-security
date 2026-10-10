# Measurement status: historical, new and aspirational

Three kinds of number appear around this project. They answer different questions, come from different populations and must not be
added, averaged or compared with each other. This page keeps them in three separate sections and says which one each figure
belongs to.

**No real-code accuracy gate has been met.** There is no sealed, independently adjudicated population in this repository, no
release has been measured against the preregistered thresholds, and every real-code gate reads `insufficient-population` or
`unmeasured`. The one measurement on real upstream code is old, narrow and weak (section 1). Everything newer is synthetic and
exercises machinery. Nothing on this page supports a claim of current engine accuracy, of a routing cost or quality advantage, or
of a deployment or invariant benefit on real programs.

How to read the labels:

| Label | Meaning |
|---|---|
| Historical | Measured earlier, on an older engine, and kept as a record. It does not describe the current engine. |
| New, synthetic | Produced by a command you can run now, on fixtures or generated data written by the tool's developers. It checks that a mechanism works. |
| Aspirational | A target the project proposes to meet. It is a plan, not a result. |

## 1. Historical baselines

These records were measured earlier, on an older engine, and they do not describe the current engine. They are kept so that a
future measurement has something to be compared with, and so that the starting point is not rewritten.

### The independent record for engine 0.141.0 (2026-08-23)

Real upstream code at the commit where a published advisory's vulnerability existed (`pre/`) and at the fix commit (`post/`), with
the CWE assigned by the advisory database. Scoring is CWE-only and per entry; an entry that could not be fetched or scanned is
unscored and named, not counted as a miss. Source: [bench/independent/RESULT.json](../../bench/independent/RESULT.json), method
in the [population README](../../bench/independent/README.md), published in the
[scorecard](../SCORECARD.md#independent-evaluation-population--the-number-that-matters).

| Fact | Value |
|---|---|
| Date and engine | 2026-08-23, engine 0.141.0 |
| Configuration | `pattern-only` (not the deep taint configuration the CLI uses outside CI) |
| Entries | 1004 total, 991 scored, 13 unscored (named in the file; for example a scan that exceeded its 180 second limit) |
| Precision (advisory-local) | 71/130 = 54.6% |
| Recall | 71/991 = 7.2% |
| F1 | 0.127 |
| Held-out split (never tuned against) | precision 6/20 = 30.0%, recall 6/205 = 2.9%, F1 0.053 |
| Development split | precision 22/57 = 38.6%, recall 22/786 = 2.8%, F1 0.052 |

Precision and recall on this record are over different populations from the curated corpus below. The record carries no
confidence interval: it predates the grouped interval method. The language mix is uneven (ruby 250 entries, typescript 322,
javascript 124, python 100, php 73, go 84, java 21, csharp 15, kotlin 2), so most per-language figures rest on small samples. The
set is not a sealed, double-reviewed population, so it cannot pass a gate even if the numbers were good.

### Missed findings by mechanism (2026-08-25)

Of 920 false negatives from that run, classified into exactly one mechanism each: 737 no finding at all, 162 a finding present but
suppressed downstream, 21 a finding on the wrong file or CWE. Source: [why-missed-summary.json](../../bench/independent/why-missed-summary.json).
This says where the misses were, not how many a newer engine would miss.

### The curated regression corpus

The corpus records 220 of 220 entries passing. Its fixtures and its labels were both written in this project, so a high rate is
expected by construction. It guards against regressions and says nothing about accuracy on code the project did not write. Source:
[corpus-baseline.json](../../bench/cve-replay/corpus-baseline.json).

## 2. New measurements (synthetic or generated)

Each row names the command, the population, and the figures printed by that command when this page was written. All populations
are small and authored by the tool's developers, or generated. They check that the measuring path works and tells good from bad.
They are not accuracy, and none of them is a claim about real code.

| Command | Population | Printed result |
|---|---|---|
| `npm run evaluation:synthetic` | 3 authored files | deterministic-only 5/5 completed, recall 0.0%; deep-taint 5/5, recall 100.0%, precision 66.7%, F1 80.0%; model-assisted 0/5 completed (no endpoint), recall 0.0%; real-code gates `insufficient-population` |
| `npm run evaluation -- deployment-ablation` | 7 cases, 14 instances, synthetic | source-only TP 4, FP 4, FN 3; graph-enabled TP 7, FP 2, FN 0; paired: false positives reduced 3, confirmed defects added 3, baseline defects lost 0, false positives added 1; real-code gates `unmeasured` |
| `npm run bench:invariant-ablation -- run` | 15 synthetic cases (8 defective, 7 valid) | source-only recall 0/8; inferred contract precision 4/4, recall 4/8; approved contract precision 8/8, recall 8/8; the figures exercise the comparison and are flagged synthetic |
| `npm run reproduce:mini` | 3 authored files, 5 negative controls | every control behaved; 95% interval on F1 `unmeasured`; real-code gates `insufficient-population` |
| `npm run reproduce:routing` | 240 generated tasks | verdict `unmeasured`; every control behaved; no advantage claimed (detail in the [routing policy card](routing-policy-card.md)) |
| `npm run verification:conformance:static` | 8 oracle adapters | all 8 conform to the static contract and pins; execution not requested |

Two cautions. First, a synthetic set that includes a case added because an earlier rule failed on it is not blind with respect to the
rule; the deployment guide says so. Second, the generated routing population is built so that the arithmetic can pass or fail, which
shows the gate discriminates and shows nothing about a model.

## 3. Aspirational targets

These are the release targets the programme proposes. They are registered before any evaluation result is observed, they have not
been met, and they are not claims about current performance. A resource stop or an insufficient population is reported as a blocker,
never as a reason to weaken a gate.

| Dimension | Proposed target |
|---|---|
| Real-code accuracy | per core-language F1 at least 0.80; micro and macro F1 at least 0.80; pooled precision at least 0.90 and recall at least 0.75, on independently adjudicated, grouped, sealed data |
| Population | at least 100 positives and 100 safe, fixed or near-miss negatives per core language; at least 30 positives per advertised vulnerability family |
| Uncertainty | publish 95% intervals; per-language F1 lower bound at least 0.70 |
| Completion | at least 95% target completion, with every failure kept in end-to-end scoring |
| Integrity | zero answer-key leaks; zero post-result threshold or denominator changes |
| Trusted verification | every advertised adapter passes positive, negative, inconclusive and tamper controls |
| Enforced capability mode | all mandatory canary and escape fixtures blocked on an advertised backend, zero canary leakage |
| Routing promotion | at least 200 paired adjudicated tasks overall and 30 per promoted stratum; lower 95% bound on the quality difference above -0.02; median cost at least 20% lower, or quality at least 0.05 higher at no higher median cost; p95 latency at most 1.2 times the baseline |
| Portfolio reliability | interrupted, duplicate-delivery and incremental runs converge to fresh scoped results with zero double-counted progress |

Today, for each row: not met. Where a row has a mechanism built (trusted verification, portfolio convergence, enforced canary
fixtures on the macOS development backend), the mechanism is tested on synthetic fixtures; the gate itself needs data this
repository does not contain, or a Linux backend that is unverified.

## Immutable evidence

Each headline figure above links to a committed file. The digests below are the SHA-256 of those files at the time of writing, and
a test recomputes them: if one of those files is refreshed, the page fails its check until it is updated deliberately.

| Evidence | SHA-256 |
|---|---|
| [bench/independent/RESULT.json](../../bench/independent/RESULT.json) | `cd77c0cf4d04bd90f4736867719abe5b4799954c5eae262f91c2c6e6eee0ede5` |
| [bench/independent/why-missed-summary.json](../../bench/independent/why-missed-summary.json) | `91facc5e7fc6e3a83a61cd64c0afc0ae0964ca3c1bc9691017e9443d41821c1c` |
| [scanner/test/fixtures/deployment-ablation/frozen.json](../../scanner/test/fixtures/deployment-ablation/frozen.json) | `28a5a276b8ba3268df6c9e44d1da43c9f5333df0851183e6f7f3331300073d3a` |
| [scanner/test/fixtures/invariant-benchmark/pin.json](../../scanner/test/fixtures/invariant-benchmark/pin.json) | `9122acf56c264e4123e2403a35e01123dd40c31e3c69bbf47929a97fe58715e2` |
| [scanner/test/fixtures/oracles/conformance-pins.json](../../scanner/test/fixtures/oracles/conformance-pins.json) | `e63f1efb3f1cbc0d3048647eed9e45e345eae6e5a544f42be0d92ba14b4a8d99` |

Hashes printed by the reproduction commands, which a test recomputes by running them:

| Name | Value |
|---|---|
| synthetic protocol hash | `sha256:6e8477f6e0486819431fa342d584f22867174cdf6dcf25ed8b65dfa468ffae1d` |
| deployment ablation frozen hash | `sha256:e3e380919fc49df173101a354fe7b23a76562eb667cf167d66566a0101b80909` |
| invariant benchmark manifest hash | `sha256:322d39bcd149ba14f38be47b01e7eccca77cb64f8735c6890a6983a2d9f0eb7f` |
| routing report hash | `sha256:4c985246c4ad231cadc5369653f0b5b8e908bf5781b3a4268d7d506a5caa6d1f` |
| routing policy card hash | `sha256:74eff7a47c67cf2ee3b9edb5620aab89c7b879d4d88ce0947ac75975fbc247f8` |
| routing receipts head | `sha256:f7bbcad1450c8ade5a6baa9c042a2fcee9b1eb85d4700618dc6f4ed8b22b7fe5` |

Reproduce them with the bounded commands in [offline reproduction](offline-reproduction.md). The policy cards are
[evaluation](evaluation-policy-card.md) and [routing](routing-policy-card.md).
