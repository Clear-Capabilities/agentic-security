# Benchmark scorecard — status against the PRD's central technical claim

> ⚠ **READ THIS BEFORE QUOTING ANY NUMBER FROM THIS FILE.**
>
> The OWASP Benchmark F1 in this file is a **benchmark-specific** number. The
> engine ships precision lifters (`scanner/src/sast/primary-cwe-java.js`,
> `scanner/src/sast/java-constant-fold.js`) whose heuristics are tuned to the
> shape of the OWASP Benchmark test files (`@WebServlet`-annotated servlets
> ≤300 LoC, single-purpose-per-file, canonical variable names like `param`
> and `bar`). The 0.907 number **does not generalize** to "F1 ≥ 0.90 on
> arbitrary Java code." On real-world Java codebases, expect FP rates closer
> to 20-30% on the same family mix until per-customer tuning lands.
>
> The PRD's central technical claim (§10) has **two** halves:
>   1. F1 ≥ 0.90 on OWASP Benchmark v1.2 — **met on the benchmark, not yet
>      validated on real-world Java**.
>   2. F1 ≥ 0.85 on a 500-CVE replay corpus — **NOT met**. The corpus has
>      1 starter entry. This is a hand-labeling project that has not been
>      funded. Do not claim the second half is delivered.

## What's actually been measured

| Benchmark | Mode | F1 | Precision | Recall | Notes |
|---|---|---:|---:|---:|---|
| OWASP Benchmark v1.2 (Java) | blind + strict | 0.907 | 0.869 | 0.948 | **benchmark-shape-tuned** — see warning above |
| OWASP Benchmark v1.2 (Java) | non-blind + strict | 0.946 | 0.945 | 0.948 | answer-key markers in play |
| OWASP Benchmark v1.2 (Java) | non-blind + wildcard | 1.000 | 1.000 | 1.000 | family-level wildcard relaxation |
| SARD Juliet Java | blind + strict | 0.460 | 0.763 | 0.330 | recall-bound; many CWEs uncovered |
| Internal CVE-replay (500 CVEs) | — | **not measured** | — | — | corpus = 1 starter entry |
| Per-language (Python/JS/TS/Go/C#/Ruby/PHP/Kotlin) | — | **not measured** | — | — | no per-language labelled corpus |
| Real-world Java repo F1 | — | **not measured** | — | — | no labelled real-world repo yet |
| Performance @ 1M LoC | — | **not measured** | — | — | PRD §9.1 targets unverified at scale |

## Per-family OWASP Benchmark scorecard (blind, strict)

These numbers are honest for OWASP Benchmark v1.2's specific test cases.
They are NOT predictive of behavior on customer code in the same families.

| Family | Precision | Recall |
|---|---:|---:|
| weak-crypto | 1.00 | 1.00 |
| weak-rng | 1.00 | 1.00 |
| header-hardening | 1.00 | 1.00 |
| xpath-injection | 0.93 | 0.93 |
| trust-boundary | 0.92 | 0.92 |
| command-injection | 0.87 | 0.84 |
| sql-injection | 0.82 | 0.95 |
| path-traversal | 0.80 | 0.84 |
| xss | 0.74 | 0.95 |
| ldap-injection | 0.73 | 1.00 |

## Benchmark provenance audit (P2-14)

| Benchmark | Provenance | Auditor-verified |
|---|---|:---:|
| owasp-benchmark | Upstream CSV (`expectedresults-1.2.csv`) | ✅ (manifest flag) |
| sard-juliet-{java,csharp} | Directory-derived (`juliet-cwe<N>/` folder mapping) | ⚠ structural, not audited |
| juliet-c-cpp | Directory-derived | ⚠ structural, not audited |
| bigvul | Upstream CSV | ⚠ CSV-claimed |
| cvefixes | Upstream SQLite | ⚠ DB-claimed |
| nodegoat / juice-shop / dvwa / pygoat / railsgoat / *-clean / openzeppelin-contracts / ... (30 entries) | Bootstrapped from scanner output in v0.34.5 + manual source inspection | ⚠ self-referential origin |

**The 30+ curated benchmarks under `expected/*.json` carry a known weakness**:
their initial entries were derived from the scanner's own output and then
manually filtered. A rule that emits the same FP both pre- and post-curation
will look like a TP against its own bootstrapped GT.

When citing F1 numbers, prefer:
- **OWASP Benchmark v1.2** (upstream CSV, auditor-verified)
- **SARD Juliet variants** (folder-derived structural GT — independent of our engine)

When citing the curated benchmarks (NodeGoat, JuiceShop, DVWA, etc.), state the
provenance explicitly: "scanner-output-bootstrap, manually-filtered." Do not
quote those as quality evidence in marketing.

## Re-running

```
npm run bench:realworld -- --app owasp-benchmark --blind --no-wildcards --json
npm run bench:realworld -- --app sard-juliet-java --blind --no-wildcards --json
```

## What would close the open halves of the claim

To validate the OWASP F1 number transfers to real Java code:
- Hand-curate a labeled real-world Java corpus (e.g. WebGoat, JuiceShop's
  Java port, a sample of real Spring Boot OSS apps) and measure per-family
  precision in blind mode.

To deliver the CVE-replay half of the central technical claim:
- Populate `bench/cve-replay/cves/` with 500 hand-labeled entries spanning
  the top 25 CWEs and 8 GA languages, each with pre-fix and post-fix code.
  This is a labeling project; estimate ~6 person-weeks at 2 CVEs/hour.

Until both close, the README is the truthful summary: one benchmark met,
the other unmeasured. **Do not market the central technical claim as fully
delivered.**
