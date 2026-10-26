# unseen-v4 baseline (Haskell)

MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see ../corpora/unseen-v4/README.md and USE-LOG.md.

- Measured: 2026-10-26; command: `node bench/language-support/measure.mjs --split unseen-v4 --eco haskell --suites detection --out bench/language-support/results/unseen-v4-baseline.json`
- Split: 78 cases (13 families, 3 vulnerable and 3 safe forms each; 0 unknown). Digest: see corpora/unseen-v4/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| all | sast + taint | 22 | 7 | 17 | 28 | 75.9% (57.9% to 87.8%) | 56.4% (41.0% to 70.7%) | 64.7% |
| pattern layer families (8) | sast | 11 | 3 | 13 | 18 | 78.6% (52.4% to 92.4%) | 45.8% (27.9% to 64.9%) | 57.9% |
| taint families (5) | taint | 11 | 4 | 4 | 10 | 73.3% (48.0% to 89.1%) | 73.3% (48.0% to 89.1%) | 73.3% |

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
| command-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| html-injection | taint | 1 | 1 | 2 | 2 | 50.0% (9.5% to 90.5%) | 33.3% (6.1% to 79.2%) | 40.0% |
| object-authorization | sast | 0 | 0 | 3 | 3 | n/a (n/a) | 0.0% (0.0% to 56.1%) | n/a |
| parser-safety | sast | 0 | 0 | 3 | 3 | n/a (n/a) | 0.0% (0.0% to 56.1%) | n/a |
| path-traversal | taint | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| resource-limits | sast | 1 | 1 | 2 | 2 | 50.0% (9.5% to 90.5%) | 33.3% (6.1% to 79.2%) | 40.0% |
| route-authentication | sast | 1 | 0 | 2 | 3 | 100.0% (20.7% to 100.0%) | 33.3% (6.1% to 79.2%) | 50.0% |
| sensitive-logging | sast | 2 | 1 | 1 | 2 | 66.7% (20.8% to 93.9%) | 66.7% (20.8% to 93.9%) | 66.7% |
| session-cookie | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |
| sql-injection | taint | 3 | 0 | 0 | 3 | 100.0% (43.9% to 100.0%) | 100.0% (43.9% to 100.0%) | 100.0% |
| ssrf | taint | 2 | 2 | 1 | 1 | 50.0% (15.0% to 85.0%) | 66.7% (20.8% to 93.9%) | 57.1% |
| weak-password-hash | sast | 3 | 1 | 0 | 2 | 75.0% (30.1% to 95.4%) | 100.0% (43.9% to 100.0%) | 85.7% |
| weak-randomness | sast | 2 | 0 | 1 | 3 | 100.0% (34.2% to 100.0%) | 66.7% (20.8% to 93.9%) | 80.0% |

Strict (cross-family findings counted as false positives): sast precision 55.0%, taint precision 64.7%.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.

## Digest of the measured split

- sourcesSha256: 14f46672659858b173d88ac449cc098f7d11a55df030638e7ad46da783778e0a
- labelsSha256: c15099a79aab465a0dfa4332e5205bdc94134ffe7f7237f42d869582d0be4438
- Recorded in corpora/unseen-v4/manifest.json. `node bench/language-support/corpora/unseen-v4/build.mjs --verify` recomputes both and exits 1 on a mismatch, and the detection suite refuses to load the split on a mismatch.
- Engine measured: scanner 0.186.1 (this worktree's base commit a988ab71, no engine change).
