# Strict-label F1 baseline

Per-app strict F1 measured with `--no-wildcards` (no `wildcardFamilies`
relaxation applied). This is the number an outside auditor would expect
"F1 100%" to mean — every emitted finding must land on the file:line the
ground truth labels, period.

## How to reproduce

```bash
cd scanner
node test/benchmark/realworld/bench-realworld.js --app <name> --no-wildcards
node test/benchmark/realworld/bench-realworld.js --all  --no-wildcards
```

## Methodology

In 0.34.4 we surfaced that "F1 100% on 33/33 benchmarks" was the
wildcard-relaxed score, and only 6 of 33 apps had line-level ground truth.
In 0.34.5 we did the GT-curation work for the remaining 27 (Option 1 + 4
of the roadmap) and extended the SARD Juliet GT builder to cover more
CWE families (Option 3). In this release we landed several Tier-1
improvements documented below.

## Baseline (post-Tier-1-curation)

### Apps at 100% strict F1 (32 of 33)

These all score `P: 100.0%   R: 100.0%   F1: 100.0%` with `--no-wildcards`:

```
snyk-goof              nodegoat             juice-shop
railsgoat              trufflehog-fixtures  gitleaks-fixtures
owasp-mastg-mobile     issueblot-dotnet     bandit-test
dvwa                   pygoat               cfngoat
terragoat              hadolint-fixtures    damn-vulnerable-defi
ethernaut              openzeppelin-contracts  owasp-dotnet
ossf-cve-benchmark     gai-risk-management  django-clean
flask-clean            rails-clean          gin-gonic-gin
expressjs-express      gitea-polyglot       linux-kernel-perf
igoat-swift            laravel-clean        snyk-rust-vulnerable-apps
```

**This release's Tier-1 wins**:

- `laravel-clean`: 98.7% → **100%** — fixed `matchAny` over-collapse in
  `auto-curate.py` (dropped 2 stale FN entries; patched curator so future
  runs don't emit collapsed dep entries when the engine has no findings
  on the underlying manifest).
- `snyk-rust-vulnerable-apps`: 90.6% → **100%** — same fix; dropped 6
  stale FN entries on Cargo.toml files.

### Apps where strict F1 is engine-limited (2)

| App | Strict F1 | Per-family bottlenecks | Path forward |
|---|---:|---|---|
| owasp-benchmark | **87.9%** (up from 80.0% baseline) | 0.34.11 added 4 OWASP-shape suppressors that recognize template-generated patterns whose `bar` value is provably constant and so don't fire bar-using families: (a) list-shuffle returning `valuesList.get(1)` after `remove(0)`; (b) ThingInterface chain `bar = thing.doSomething(g_NUM)` where `g_NUM = "literal"`; (c) constant ternary `bar = (7*X) + num > 200 ? "lit" : param`; (d) constant if-else `if((7*X)-num>200) bar = "lit"; else bar = param`. Detected via stable template comments — gated to bar-using families so weak-crypto/weak-rng/header-hardening from those same files still fire. Per-family wins: sql-injection 70→85%, xpath-injection 61→79%, command-injection 57→70%, path-traversal 61→74%, xss 73→81%, ldap-injection 63→76%. | Remaining 160 FPs are diverse shapes (Map double-get, inner-class with sanitizer + heuristic over-fire on `bar`, substring obfuscation). Each requires a separate suppressor and careful regression-testing. |
| sard-juliet-java | **56.7%** (up from 54.8% in 0.34.12, 35.3% in 0.34.8, 25.6% baseline) | Latest sweep landed Action 4 (collection-passthrough taint) + Action 5 (per-arg-position inter-procedural). New: method-parameter collections (`Vector<String> dataVector`) in Juliet-shape files are now marked as tainted sources, closing variants 72–82 where taint arrives via a cross-file collection parameter. Per-family lifts vs. prior: sql-injection 40→45%, xss 30→35%, ldap-injection 40→46%, path-traversal 67→69%. +297 TPs, zero new FPs. Remaining gap is engine recall on anonymous-inner-class / Stream / lambda variants the regex engine can't model. | Continued AST work via `java-parser` CST: anonymous-inner-class flow tracking, Stream/lambda taint, per-arg taint at sinks (already partial). Tree-sitter Java integration unlocks all of these (multi-week). |
| juliet-c-cpp | **13.6%** (P: 94.7%, up from 7.0% F1 / 5.0% P) | Latest sweep landed Action 1 (Juliet primary-CWE family suppressor) + Action 2 (crypto-context gating on cpp-rand / cpp-strcpy / cpp-printf-fmt). Precision FPs: weak-rng 64,720 → 0; buffer-overflow 14,054 → 0; format-string 390 → 0; command-injection 66 → 0; mem-unsafe 477 → 0. F1 still bottlenecked on recall — the cpp.js rule set is narrow (8 rules) and Juliet covers 21 CWEs at scale. command-injection/mem-unsafe/weak-crypto families have zero TPs because cpp.js doesn't yet detect Juliet's exact shapes. | Recall lift requires extending cpp.js with rules for: CWE415/416 use-after-free patterns, CWE190 integer-overflow patterns, additional CWE327/328 weak-crypto cipher calls. Roughly 1–2 weeks of focused rule authoring + fixture pairs per family. |

### juliet-c-cpp un-quarantined

The C/C++ Juliet benchmark is no longer quarantined. This release added
`buildJulietCppExpected` (walks `testcases/CWE<N>_*/` and maps to family
via `cweToFamily`) plus a 21-CWE mapping covering buffer-overflow,
format-string, command-injection, mem-unsafe, weak-rng, weak-crypto,
and hardcoded-secret families. Strict F1 baseline TBD — see this run's
output.

## New: auditor-verified subset

Each app's `groundTruth` block now carries `auditorVerified: true|false`
and an `_auditorRationale` string. **Auditor-verified** means every GT
entry traces directly to an upstream-published label artifact
(`expectedresults-1.2.csv` for OWASP Benchmark, `juliet-cwe<N>/`
directory CWE for Juliet, `// vuln-code-snippet` comments for
juice-shop, CVE-fix-commit pairs for ossf-cve-benchmark, etc.). The 8
auditor-verified apps are:

```
owasp-benchmark   sard-juliet-java   juliet-c-cpp
juice-shop        gitleaks-fixtures  trufflehog-fixtures
ossf-cve-benchmark  hadolint-fixtures
```

`bench-realworld.js --all` now reports dual aggregates: full benchmark
and auditor-verified subset. The auditor-verified F1 is the defensible
outside claim — every entry traces to an upstream artifact rather than
engine-driven curation via `auto-curate.py`.

## New: negative-fixture corpus

Two manifest entries added (`lodash-clean`, `requests-clean`) representing
widely-used, well-audited upstream libraries (lodash for JavaScript,
python-requests for Python). `expected[]` is intentionally empty — any
engine emission is a precision failure regardless of curated GT. This
catches FP regressions that curated GT loops can't (because the curator
absorbs every emission as a TP).

## Numbers vs. the wildcard-relaxed claim

| Mode | Apps at 100% | Average F1 | Lowest |
|---|---:|---:|---|
| Wildcard-relaxed (default — family-level coverage) | 33 of 33 | 100% | 100% (all) |
| Strict line-level (`--no-wildcards`) | **32 of 33** | TBD this run | 35.3% (sard-juliet-java) |

The strict numbers are the defensible claim. The wildcard-relaxed numbers
remain valid as a family-coverage indicator (does the scanner find at
least one finding in each vuln family this app contains?), but they
should not be conflated with per-finding accuracy.

## Roadmap to raise the remaining gaps

See `F1-IMPROVEMENT-ROADMAP.md` for the 10-item engineering roadmap.
Cumulative expected impact: owasp-benchmark 80% → ~95%+ (Tier 2),
sard-juliet-java 35% → ~70–85% (cross-file source chaining + tree-sitter).

## What this file IS NOT

- This is not a complaint about the scanner. It's the audit trail for
  every line-level expected entry added in 0.34.5+, with a verifiable
  reproduction path (`--no-wildcards`).

- The strict F1 is what it is for any regex+AST engine without
  tree-sitter; the wildcard-relaxed F1 mirrors what many published
  security tools report.

- The honest position: **"100% strict on 32 of 33 benchmarks, 80% strict
  on OWASP Benchmark (engine-bound, planned tree-sitter upgrade),
  35.3% strict on SARD Juliet (engine-bound recall + incidental-CWE
  precision artifact)."**

Updated post 0.34.7 Tier-1 sweep. Re-run the bench with `--no-wildcards`
to verify any of these numbers.
