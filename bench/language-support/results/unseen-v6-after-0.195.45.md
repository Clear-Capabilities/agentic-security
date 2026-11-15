# unseen-v6 measurement (Haskell)

DEVELOPMENT set since 2026-11-15: its failures were read to change the engine, so this is a regression result, not a generalisation measure.

- Measured: 2026-11-15; command: `node bench/language-support/measure.mjs --split unseen-v6 --eco haskell --suites detection --out bench/language-support/results/unseen-v6-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v6/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 38 | 4 | 1 | 33 | 90.5% (77.9% to 96.2%) | 97.4% (86.8% to 99.5%) | 93.8% |
| pattern layer families (8) | sast | 24 | 4 | 0 | 19 | 85.7% (68.5% to 94.3%) | 100.0% (86.2% to 100.0%) | 92.3% |
| taint families (5) | taint | 14 | 0 | 1 | 14 | 100.0% (78.5% to 100.0%) | 93.3% (70.2% to 98.8%) | 96.6% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| html-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| object-authorization | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| parser-safety | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| path-traversal | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| resource-limits | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| route-authentication | sast | 3 | 2 | 0 | 1 | 60.0% (23.1% to 88.2%) | 100.0% (43.9% to 100.0%) | 75.0% |
| sensitive-logging | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| session-cookie | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| sql-injection | taint | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| ssrf | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| weak-password-hash | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| weak-randomness | sast | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |

Strict (cross-family findings counted as false positives): sast precision 70.6%, taint precision 93.3%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
