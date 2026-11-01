# unseen-v5 baseline (Haskell)

MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see the split's README.md and USE-LOG.md.

- Measured: 2026-11-01; command: `node bench/language-support/measure.mjs --split unseen-v5 --eco haskell --suites detection --out bench/language-support/results/unseen-v5-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v5/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 22 | 8 | 17 | 27 | 73.3% (55.6% to 85.8%) | 56.4% (41.0% to 70.7%) | 63.8% |
| pattern layer families (8) | sast | 11 | 4 | 13 | 17 | 73.3% (48.0% to 89.1%) | 45.8% (27.9% to 64.9%) | 56.4% |
| taint families (5) | taint | 11 | 4 | 4 | 10 | 73.3% (48.0% to 89.1%) | 73.3% (48.0% to 89.1%) | 73.3% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| html-injection | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| object-authorization | sast | 0 | 0 | 3 | 3 | n/a (n/a) | 0.0% (0.0% to 56.1%) | n/a |
| parser-safety | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| path-traversal | taint | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| resource-limits | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| route-authentication | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| sensitive-logging | sast | 2 | 2 | 1 | 1 | 50.0% (15.0% to 85.0%) | 66.7% (20.8% to 93.9%) | 57.1% |
| session-cookie | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| sql-injection | taint | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| ssrf | taint | 2 | 2 | 1 | 1 | 50.0% (15.0% to 85.0%) | 66.7% (20.8% to 93.9%) | 57.1% |
| weak-password-hash | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| weak-randomness | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |

Strict (cross-family findings counted as false positives): sast precision 42.3%, taint precision 68.8%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
