# Use log (unseen-nix-v1)

Every use of these sources, labels or the baseline failures that could influence detector rules must be recorded here, newest last, before any number from the split is quoted. Measurement runs with no rule change need no entry.

| date | who | use | rules changed afterwards |
|---|---|---|---|
| 2026-11-01 | LLM agent (creation) | Wrote the 72 forms in a separate agent session that could not see this repository, from the 12 family names, their CWE meanings at the NixOS level and the authoring format only; froze the digest; ran the detection suite once before any Nix engine work of 0.195.9 and recorded `results/unseen-nix-v1-baseline.md` (overall precision 84.6%, recall 61.1%, F1 71.0%). The engine agent read the aggregate and per-family tables only; the per-case lists exist only in the result JSON. The author was told to report counts only, not the services, option spellings or shapes it used, and did so. | none |
| 2026-11-01 | lead (measurement) | Measured once more after the Nix engine changes of 0.195.9, which were motivated by the unseen-v3 Nix DEVELOPMENT set (a capability set written as one string, `Defaults !authenticate`, a `*File` option handed a `writeText` literal, a TLS key path on a non-nginx service, one script-taint finding per line and origin class), aggregate only (`results/unseen-nix-v1-after-0.195.9.json`): SAST 20 tp / 4 fp / 13 fn, taint 2 tp / 0 fp / 1 fn, precision 84.6%, recall 61.1%, F1 71.0%, identical to the baseline. The development-set fixes did not generalise to this split. No per-case output was read. | none |
