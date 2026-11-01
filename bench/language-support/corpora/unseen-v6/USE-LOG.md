# Use log (unseen-v6)

Every use of these sources, labels or the baseline failures that could influence detector rules must be recorded here, newest last, before any number from the split is quoted. Measurement runs with no rule change need no entry.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-11-01 | LLM agent (creation) | Wrote the 78 forms in a separate agent session that could not see this repository, from the 13 family names, their CWE meanings and the authoring format only; froze the digest; ran the detection suite once, after the real-code precision changes of 0.195.9 (motivated by `bench/dag/dev-haskell`, not by any split) and before the unseen-v5 misses were read, and recorded `results/unseen-v6-baseline.md` (overall precision 71.0%, recall 56.4%, F1 62.9%). The engine agent read the aggregate and per-family tables only; the per-case lists exist only in the result JSON. The author reported counts only, not the libraries or shapes it used. | none |
| 2026-11-01 | lead (measurement) | Measured once more after the unseen-v5 misses were read and the engine changed for them, aggregate only (`results/unseen-v6-after-0.195.9.json` and `.md`): SAST 17 tp / 4 fp / 7 fn, taint 8 tp / 1 fp / 7 fn, precision 83.3%, recall 64.1%, F1 72.5% (baseline 71.0%, 56.4%, 62.9%). Part of the unseen-v5 work generalised here: the Servant pairing from the end, the fixed-host request judgement, the proven-clean rule of the harness, the credential header names. No per-case output was read. | none |
