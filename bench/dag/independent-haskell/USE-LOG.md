# Use log (independent-haskell)

Every use of these labels that could influence detector rules must be recorded here, newest last. Measurement runs (`node run.mjs --check`) with no rule changes need no entry. Reading labels or evidence while changing rules is a development use and must be logged before any number is quoted.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-10-26 | LLM agent (creation) | Created the set: acquired four projects, ran flag.mjs, drew the seeded sample (seed 20261026, fixed before labeling), labeled 60 of 77 flagged sites from target source only. Did not read detector code, scanner/src/language, or any existing label or sample. Scanner not modified. | none |
| 2026-10-27 | lead (measurement) | Measured once after the 0.188.0 precision work. The engine agent never opened this set; only aggregate output of run.mjs --check was read, no site or label was inspected. Result: 73 flagged, 1 tp, 34 fp, precision 2.9% (0.5% to 14.5%), against 2.3% before. | none |
| 2026-10-27 | lead (measurement) | Measured once after the 0.189.0 reachability work. The engine agent never opened this set; only aggregate output of run.mjs --check was read. Result: 73 flagged, 1 tp, 34 fp, precision 2.9% (0.5% to 14.5%), unchanged. Pre-registered rule: under 2 points means no generalisation, no claim. | none |
