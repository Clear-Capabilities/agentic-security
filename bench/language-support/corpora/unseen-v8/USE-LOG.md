# Use log (unseen-v8)

Every use of these sources, labels or the baseline failures that could influence detector rules must be recorded here, newest last, before any number from the split is quoted. Measurement runs with no rule change need no entry.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-11-15 | LLM agent (creation) | Wrote the 78 forms in a separate agent session that could not see this repository, from the 13 family names, their CWE meanings (the CWE definitions, not the engine's patterns), the authoring format and a list of ordinary Haskell libraries, frameworks and input channels to spread the forms over; it reported counts only, plus a list of library API spellings it was unsure of (recorded in README.md as a limit; the forms were not compiled). The engine agent copied the three authoring files into this directory without opening them, froze the digest, and ran the detection suite once at 0.195.43 (round 7 of the real-code work, every change of which was motivated by `bench/dag/dev-haskell` and `bench/dag/discovery-haskell`, not by any split), recording `results/unseen-v8-baseline.md` and reading its aggregate and per-family tables only; the per-case lists exist only in the result JSON. | none |
