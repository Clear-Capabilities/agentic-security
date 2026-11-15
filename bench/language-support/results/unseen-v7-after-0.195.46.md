# unseen-v7 measurement (Haskell)

DEVELOPMENT set since 2026-11-15: its failures were read to change the engine, so this is a regression result, not a generalisation measure.

- Measured: 2026-11-15; command: `node bench/language-support/measure.mjs --split unseen-v7 --eco haskell --suites detection --out bench/language-support/results/unseen-v7-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v7/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 35 | 3 | 4 | 32 | 92.1% (79.2% to 97.3%) | 89.7% (76.4% to 95.9%) | 90.9% |
| pattern layer families (8) | sast | 22 | 2 | 2 | 19 | 91.7% (74.2% to 97.7%) | 91.7% (74.2% to 97.7%) | 91.7% |
| taint families (5) | taint | 13 | 1 | 2 | 13 | 92.9% (68.5% to 98.7%) | 86.7% (62.1% to 96.3%) | 89.7% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| html-injection | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| object-authorization | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| parser-safety | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| path-traversal | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| resource-limits | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| route-authentication | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| sensitive-logging | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| session-cookie | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| sql-injection | taint | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| ssrf | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| weak-password-hash | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| weak-randomness | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |

Strict (cross-family findings counted as false positives): sast precision 57.9%, taint precision 76.5%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
