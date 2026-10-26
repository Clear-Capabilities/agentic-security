# Independent precision set

Purpose: report default-scan precision with honest denominators and intervals, on projects and labels that were not used while precision rules were written.

1. Projects (manifest.json) are absent from bench/dag/manifest.json and pinned to exact commits under `.cache/` (git-ignored; re-acquire with the recorded url and commit).
2. `flag.mjs` runs the default scan (deterministic, no state writes, no provenance) over each declared scan root and lists flagged sites: project, file, line, vuln, severity, source line. Test directories and line-0 findings are excluded.
3. `sample.mjs` draws a seeded random sample of 60 flagged sites per language; the seed was fixed before labeling.
4. Each sampled site was labeled tp, fp or ambiguous from the target project's own source only (sources, sanitizers, callers), with a one-sentence evidence note.
5. The labeler never opened detector code, the existing labels, or the existing sample.
6. `labels.json` carries a sha256 digest of its canonical labels array; `run.mjs` refuses to run on a mismatch.
7. `node run.mjs --check` re-scans, joins by project/file/line/vuln, and writes `results.json` and `results.md`.
8. precision = tp / (tp + fp) with a 95% Wilson interval. Ambiguous and unlabeled sites are reported and never counted.
9. Unlabeled means not in the sample or new since labeling; the figures estimate the flagged population, they are not a census.
10. Intervals assume simple random sampling; sites cluster by file and rule, so real uncertainty is wider.
11. Limits: one LLM labeler, no second opinion, scan roots chosen by the labeler, point-in-time acquisition.
12. MEASUREMENT ONLY. Reading labels while changing rules makes this a development set.
13. Any such use must be recorded in USE-LOG.md before numbers are quoted.
14. Do not edit labels to match the scanner; re-label only with a USE-LOG entry and a new digest.
15. Extending the set means new projects and a new draw, not re-labeling old sites.
