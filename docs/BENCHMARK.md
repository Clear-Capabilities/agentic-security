# Benchmark methodology

agentic-security is evaluated against a structured set of real-world corpora. This document
defines the three scoring modes, what each one measures, and how to reproduce every number.

## Three scoring modes

| Mode | Command flag | What it measures |
|---|---|---|
| **Default (wildcard-relaxed)** | _(none)_ | Does the scanner fire at least one finding of the correct *family* somewhere in the corpus? Family-level coverage — useful for "does the scanner know about SQL injection at all?" |
| **Strict** | `--no-wildcards` | Does every emitted finding match the expected file:line in the ground truth? Still runs all benchmark-shape suppressors (OWASP template-comment readers, Juliet folder-path filters) — honest line-level F1 with the engine's non-generalizing helpers on. |
| **Blind** | `--blind` | Same strict line-level scoring, **plus** the blinder strips NIST SARD `/* FLAW */` / `/* POTENTIAL FLAW */` comments and OWASP template-marker comments from every source file before scanning, and disables every rule that reads the answer-key (juliet-shape, OWASP dead-branch suppressors, @WebServlet category filter). **This is the defensible claim about the engine's detection capability.** |

The numbers quoted externally should always specify which mode they are measured in. A `--blind`
score is the only one that is meaningfully comparable to other tools.

## How to reproduce

```bash
cd scanner

# Default (wildcard-relaxed) — all apps
npm run bench:realworld

# Strict — all apps
npm run bench:realworld -- --all --no-wildcards

# Blind — the honest engine-only score
npm run bench:realworld -- --all --blind

# Single app in any mode
npm run bench:realworld -- --app owasp-benchmark --blind
npm run bench:realworld -- --app sard-juliet-java --blind
npm run bench:realworld -- --app juliet-c-cpp --blind
```

Scan results are deterministic: the same engine version on the same corpus always produces
the same score. Pin a corpus by sha in `manifest.json` (see "Corpus pinning" below).

## Published baseline (blind mode)

Run `npm run bench:realworld -- --all --blind` and record the output here.
**The numbers below must be updated before every release that changes a SAST rule.**

> NOTE: Run the bench and fill in the following table before releasing 0.39.3+.

| App | Language | Blind F1 | Blind P | Blind R | Engine version |
|---|---|---:|---:|---:|---|
| owasp-benchmark | Java | — | — | — | 0.39.2 |
| sard-juliet-java | Java | — | — | — | 0.39.2 |
| juliet-c-cpp | C/C++ | — | — | — | 0.39.2 |
| juice-shop | JS | — | — | — | 0.39.2 |
| snyk-goof | JS | — | — | — | 0.39.2 |
| nodegoat | JS | — | — | — | 0.39.2 |
| _(other 30+ apps)_ | _various_ | — | — | — | 0.39.2 |

## What the wildcard-relaxed score covers (and doesn't)

The wildcard-relaxed "100% F1 on 33/33 apps" historically reported means: for every vuln
family this scanner claims to detect, at least one finding of that family was emitted somewhere
in the corpus. It does **not** mean:

- Every vulnerable file was flagged.
- Every finding lands on the correct line.
- There are zero false positives on real (non-benchmark) code.

The wildcard-relaxed metric is a regression guard ("did we break SQL injection detection
entirely?"), not a precision/recall claim.

## Corpus pinning

Every entry in `scanner/test/benchmark/realworld/manifest.json` must have a `sha` field
set to a specific commit hash — never `"master"`, `"main"`, or `"HEAD"`. A CI check at
`scripts/check-bench-shas.js` enforces this on every PR.

To update a corpus, change the `sha` field to the new commit hash. The bench clones a fresh
copy keyed by `(name)-(sha)` under `.bench-cache/`.

## Auditor-verified ground truth

Eight apps carry `auditorVerified: true` in their manifest entry:

- `owasp-benchmark` — GT from `expectedresults-1.2.csv` shipped by OWASP.
- `sard-juliet-java` — GT from NIST SARD CWE directory names + `bad()` method markers.
- `juliet-c-cpp` — GT from NIST SARD CWE directory names + `bad()` / `/* FLAW */` markers.
- `juice-shop` — GT from `// vuln-code-snippet` comments in upstream source.
- `gitleaks-fixtures` — GT from upstream fixture manifests.
- `trufflehog-fixtures` — GT from upstream fixture manifests.
- `ossf-cve-benchmark` — GT from CVE-fix commit pairs.
- `hadolint-fixtures` — GT from upstream fixture manifests.

"Auditor-verified" means every GT entry traces to an upstream-published label artifact —
not to the scanner's own auto-curation (`auto-curate.py`). The auditor-verified F1 under
`--blind` is the most defensible external claim.

## Negative corpus

These apps are expected to produce **zero** scanner findings (or a vetted noise floor).
Any new emission on them is a precision regression:

| App | Language | What it tests |
|---|---|---|
| `requests-clean` | Python | Python HTTP library — zero vulns expected |
| `lodash-clean` | JavaScript | Audited utility library — zero vulns expected |
| `django-clean` | Python | Django framework source — zero vulns expected |
| `flask-clean` | Python | Flask framework source — zero vulns expected |
| `gin-gonic-gin` | Go | Go HTTP framework — zero vulns expected |
| `expressjs-express` | JavaScript | Express.js framework — zero vulns expected |
| `rails-clean` | Ruby | Rails framework — zero vulns expected |
| `laravel-clean` | PHP | Laravel framework — zero vulns expected |

Additional negative-corpus targets (Spring Boot skeleton, FastAPI, htmx, Phoenix, .NET
minimal API) should be added before those languages reach production-scanner coverage.

## Benchmark-shape rules (opt-in, not production)

Several rules read benchmark-specific markers and are not general-purpose detectors:

| Rule / module | What it reads | Where it lives |
|---|---|---|
| `juliet-shape.js` | `/* POTENTIAL FLAW: */` comments; `bad()` function declarations | `sast/bench-shape/` |
| `applyJulietJavaSuppressions` | `juliet-cwe<N>/` folder name → CWE → family | `sast/bench-shape/` |
| `applyJulietCppSuppressions` | `testcases/CWE<N>_*/` folder → family | `sast/bench-shape/` |
| `applyJulietCsSuppressions` | `testcases/CWE<N>_*/` → family | `sast/bench-shape/` |
| `_javaWebServletCategory` | `@WebServlet("/cmdi-02/")` route prefix → category | `sast/bench-shape/` |
| OWASP dead-branch suppressors | `// condition 'B', which is safe` template comments | `sast/bench-shape/` |

These are enabled by setting `AGENTIC_SECURITY_BENCH_SHAPE=1`. They are automatically
enabled inside `bench-realworld.js` when **not** running in `--blind` mode. Production scans
never set this variable.
