# unseen-v7 baseline (Haskell)

MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see the split's README.md and USE-LOG.md.

- Measured: 2026-11-15; command: `node bench/language-support/measure.mjs --split unseen-v7 --eco haskell --suites detection --out bench/language-support/results/unseen-v7-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v7/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 27 | 6 | 12 | 27 | 81.8% (65.6% to 91.4%) | 69.2% (53.6% to 81.4%) | 75.0% |
| pattern layer families (8) | sast | 17 | 3 | 7 | 16 | 85.0% (64.0% to 94.8%) | 70.8% (50.8% to 85.1%) | 77.3% |
| taint families (5) | taint | 10 | 3 | 5 | 11 | 76.9% (49.7% to 91.8%) | 66.7% (41.7% to 84.8%) | 71.4% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| html-injection | taint | 1 | 1 | 2 | 2 | 50.0% (9.5% to 90.5%) | 33.3% (6.1% to 79.2%) | 40.0% |
| object-authorization | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| parser-safety | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| path-traversal | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| resource-limits | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| route-authentication | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| sensitive-logging | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| session-cookie | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| sql-injection | taint | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| ssrf | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| weak-password-hash | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| weak-randomness | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |

Strict (cross-family findings counted as false positives): sast precision 48.6%, taint precision 62.5%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
