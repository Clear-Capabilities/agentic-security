# Use log (unseen-v4)

Every use of these sources, labels or the baseline failures that could influence detector rules must be recorded here, newest last, before any number from the split is quoted. Measurement runs with no rule change need no entry.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-10-26 | LLM agent (creation) | Wrote the 78 forms without reading engine rules or existing corpus sources; froze the digest; ran the detection suite once on scanner 0.186.1 and recorded `results/unseen-v4-baseline.md`. Did not read per-case misses or strays while writing; the per-case lists exist only in the result JSON. | none |
| 2026-10-27 | lead (measurement) | Measured once more after the 0.188.0 engine work, aggregate only. The engine agent never opened this set. SAST 13 tp / 3 fp / 11 fn (recall 54.2%, unchanged); taint 10 tp / 2 fp / 5 fn (precision 83.3%, recall 66.7%, down from 73.3%). No per-case output was read. | none |
| 2026-10-27 | lead (measurement) | Measured once after the 0.189.0 reachability work, aggregate only. SAST 13 tp / 3 fp / 11 fn (recall 54.2%); taint 10 tp / 2 fp / 5 fn (recall 66.7%), unchanged from 0.188.0. No per-case output was read. | none |
