# Benchmark harness

This directory hosts the measurement harness used to evaluate the scanner against external corpora. **No benchmark scores are published in this repository.** Run the harnesses locally; numbers are intentionally not committed or quoted in any user-facing document.

## Why no published numbers

Single-corpus F1 scores are easily misread. The engine ships corpus-shape-aware
analysis (precision lifters, OWASP-Benchmark labeling-rule emulation in
`scanner/src/engine.js`, Juliet folder/name heuristics) — these are gated off
under `AGENTIC_SECURITY_BLIND_BENCH=1`, but the *non-blind* code paths still
exist and influence non-blind runs. A score from any single corpus or any
single mode is not portable to other Java code, and an aggregate F1 without
per-family confidence intervals hides where the engine is weak.

External claims must:

- Run **all auditor-source-verified corpora** (OWASP Benchmark v1.2, SARD
  Juliet Java / C/C++ / C#) in **blind mode**.
- Report **F1 alongside Youden Index (TPR − FPR)** so the result is
  comparable to the official OWASP Benchmark scorecard convention.
- Carry a `docs/audit/<corpus>-<date>.md` external sign-off file. Until
  one exists for a corpus, the manifest reports
  `auditorVerifiedSource: "<provenance>"` rather than a self-attested
  "auditorVerified: true".

Curated benchmarks under `scanner/test/benchmark/realworld/expected/*.json`
(NodeGoat, JuiceShop, DVWA, etc.) were bootstrapped from the scanner's own
output and then manually filtered. They are useful as regression fixtures.
They are **not** quality evidence for marketing.

## Corpus inventory

| Corpus | Provenance | Auditor source verified | External sign-off |
|---|---|---|---|
| owasp-benchmark | Upstream CSV (`expectedresults-1.2.csv`) | Yes (CSV-derived) | None on file |
| sard-juliet-java | Directory-derived (`juliet-cwe<N>/` mapping) | Yes (folder-derived) | None on file |
| sard-juliet-csharp | Directory-derived | Yes (folder-derived) | None on file |
| juliet-c-cpp | Directory-derived | Yes (folder-derived) | None on file |
| bigvul | Upstream CSV | CSV-claimed | None on file |
| cvefixes | Upstream SQLite (Zenodo) | DB-claimed | None on file |
| nodegoat / juice-shop / dvwa / pygoat / railsgoat / *-clean / openzeppelin-contracts / ... | Bootstrapped from scanner output then filtered | Self-referential | n/a (not eligible) |
| tinymart | **Genuinely independent** — a small app hand-written for `bench/holdout-independent/tinymart/`, with ground truth authored from its own source before the scanner was ever run against it (SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem remediation, F14: every OTHER curated app above is bootstrapped from scanner output, so the external-holdout regression gate could never fail against real data). Not "bootstrapped then filtered" like its neighbors — see `bench/holdout-independent/README.md` and `expected/tinymart.json`'s own `_doc`. | Author-verified (not scanner-derived) | n/a (small, single-repo fixture; not eligible for the external-sign-off process above) |

## Running locally

```
# In-repo F1 + Youden against committed fixtures.
cd scanner && AGENTIC_SECURITY_BLIND_BENCH=1 npm run bench

# External corpus, blind mode (clones on first run).
node test/benchmark/realworld/bench-realworld.js --app owasp-benchmark --blind --json
node test/benchmark/realworld/bench-realworld.js --app sard-juliet-java --blind --json
node test/benchmark/realworld/bench-realworld.js --app sard-juliet-csharp --blind --json
node test/benchmark/realworld/bench-realworld.js --app sard-juliet-c-cpp --blind --json
```

Results go to `scanner/test/benchmark/realworld/.bench-cache/` and to the
per-CWE `.agentic-security/validator-metrics.json` history file (gitignored).

## What would unlock external claims

1. Land an external sign-off file `docs/audit/<corpus>-<YYYY-MM-DD>.md` for
   each corpus the project wants to cite. The file must name the auditor
   and date and link to whatever artifact (CSV row, folder convention,
   NVD record) backs each expected entry.
2. Populate `bench/cve-replay/cves/` with a hand-labeled corpus across the
   top CWEs and the GA languages. The runner exists; the data does not.
3. Run an ablation: full engine vs full engine minus the OWASP-shape /
   Juliet-shape labeling helpers. Publish both numbers so a reader can
   judge how much of the score comes from corpus-aware code.

Until those land, numbers stay local.
