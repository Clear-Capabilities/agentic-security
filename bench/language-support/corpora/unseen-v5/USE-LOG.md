# Use log (unseen-v5)

Every use of these sources, labels or the baseline failures that could influence detector rules must be recorded here, newest last, before any number from the split is quoted. Measurement runs with no rule change need no entry.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-11-01 | LLM agent (creation) | Wrote the 78 forms in a separate agent session that could not see this repository, from the 13 family names, their CWE meanings and the authoring format only; froze the digest; ran the detection suite once before the 0.195.8 engine work and recorded `results/unseen-v5-baseline.md`. The engine agent read the aggregate and per-family tables only; the per-case lists exist only in the result JSON. | none |
| 2026-11-01 | lead (disclosure) | The author's completion report, which the engine agent read before the baseline was taken, carried one line per family naming the libraries, frameworks and shapes it had used (for example "Scotty + `System.Random.randomRIO` reset code"). No source, label or per-case result was in it. The engine changes that followed were motivated by unseen-v4's misses, not by that list, but a reader weighing this split's independence should know the list was seen. | none from this |
| 2026-11-01 | lead (measurement) | Measured once more after the 0.195.8 engine work, aggregate and per-family only (`results/unseen-v5-after-0.195.8.json`): SAST 12 tp / 4 fp / 12 fn, taint 11 tp / 4 fp / 4 fn; overall precision 74.2%, recall 59.0%, F1 65.7% (baseline 73.3%, 56.4%, 63.8%). One more vulnerable form found; the unseen-v4 work mostly did not generalise here. No per-case output was read. | none |
