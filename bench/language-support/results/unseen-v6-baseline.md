# unseen-v6 baseline (Haskell)

MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see the split's README.md and USE-LOG.md.

- Measured: 2026-11-01; command: `node bench/language-support/measure.mjs --split unseen-v6 --eco haskell --suites detection --out bench/language-support/results/unseen-v6-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v6/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 22 | 9 | 17 | 32 | 71.0% (53.4% to 83.9%) | 56.4% (41.0% to 70.7%) | 62.9% |
| pattern layer families (8) | sast | 14 | 7 | 10 | 20 | 66.7% (45.4% to 82.8%) | 58.3% (38.8% to 75.5%) | 62.2% |
| taint families (5) | taint | 8 | 2 | 7 | 12 | 80.0% (49.0% to 94.3%) | 53.3% (30.1% to 75.2%) | 64.0% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| html-injection | taint | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| object-authorization | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| parser-safety | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| path-traversal | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| resource-limits | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| route-authentication | sast | 1 | 1 | 2 | 2 | 50.0% (9.5% to 90.5%) | 33.3% (6.1% to 79.2%) | 40.0% |
| sensitive-logging | sast | 2 | 3 | 1 | 0 | 40.0% (11.8% to 76.9%) | 66.7% (20.8% to 93.9%) | 50.0% |
| session-cookie | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| sql-injection | taint | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| ssrf | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| weak-password-hash | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| weak-randomness | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |

Strict (cross-family findings counted as false positives): sast precision 51.9%, taint precision 72.7%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
