# PRD: World-Class Across All Ten Features

**Status:** Draft for review. Nothing here is implemented by writing it.
**Owner:** Ross Young / Clear Capabilities Inc.
**Date:** 2026-08-20
**Engine version measured:** 0.138.0
**Scope:** The whole product — `scanner/src/` (all layers), `bench/`, `commands/`, `agents/`, `ide/`, `scripts/`.
**Audience:** Engineering.

**Relationship to `docs/WORLD_CLASS_DETECTION_PRD.md`:** that document owns Features 1 and 2
(pattern/structural detection and the taint engine) and its themes are not restated here.
This document covers the other eight, and states the one structural problem they share.

---

## 0. Status ledger

Every item in this document, with where its evidence lives. **Items landed before
2026-08-22 were implemented in earlier commits but their bullets below were never
updated, so many still read as future work** — this table is the correction, and the
bullets themselves carry dated markers only where that session wrote them.

`this session` = 2026-08-22. Where a row says *no dedicated test names it*, treat the
item as claimed-but-unpinned and verify before quoting it.

| Item | Status | Evidence |
|---|---|---|
| F1.1 Go zero, root-caused | landed | `scanner/test/sibling-guard.test.js`; histograms in §3 |
| F1.2 Ruby zero, root-caused | landed | histogram in §3; the extension was **attempted and reverted** |
| **F1.3** first family rebuilt | **landed; confirmed on the population** | `scanner/src/sast/ruby.js`, `scanner/test/ruby-path-join.test.js` |
| **F1.4** three silent families | **this session — two were misdiagnosed** | `scanner/src/sast/convention-deviation.js`; `CODEGEN` left to the maintainer |
| **F2.1** taint instrument | **measured both configurations 2026-08-23 — taint = 1 of 28** | `bench/independent/runner.mjs`, `merge-chunks.mjs` |
| F2.2 container/collection taint | landed | `scanner/test/container-taint.test.js` |
| F2.3 entry-point breadth | landed | `scanner/test/entrypoint-breadth.test.js` |
| F2.4 hang classes | landed (commit `a8755b8`) | **no dedicated test names it** |
| F2.5 comment-strip cost | landed | `scanner/test/comment-strip-cost.test.js` |
| **F3.1** `bench/sca-replay` | **this session** | `bench/sca-replay/`, `scanner/test/dep-file-admission.test.js` |
| **F3.2** reachability as its own claim | **SCORED 2026-08-23 — 3 of 3 adjudicable demotions were false; 3 engine defects fixed** | `bench/sca-replay/reachability.mjs` |
| F3.3 SBOM conformance | landed | `scanner/test/sbom-conformance.test.js` |
| F3.4 KEV/EPSS freshness | landed | `scanner/src/engine.js` |
| F3.5 malicious-package scope | landed | agent prompt downgraded to advisory |
| **F4.1** secrets precision | **this session** | `bench/secrets-precision/`, `scanner/test/secrets-coverage.test.js` |
| F4.2 verified-vs-unverified secrets | landed | opt-in only |
| **F4.3** IaC coverage | **this session** | `bench/iac-coverage/`, `scanner/src/sast/iac-cloud-templates.js` |
| F4.4 container image scanning | landed (scoped out in README) | README statement |
| F4.5 deploy-gate telemetry | landed | `scanner/test/deploy-gate-replay.test.js` |
| **F5.1** prompt-injection corpus | **this session** | `bench/prompt-injection/`, `scanner/test/prompt-injection-payloads.test.js` |
| F5.2 MCP audit vs real servers | landed | `scanner/test/mcp-rug-pull.test.js` |
| **F5.3** agent trust-boundary taint | **delta measured 2026-08-23 — 0 of 0, undefined; 28 MCP entries, 0 localized TPs** | `bench/independent/agent-boundary-delta.mjs` |
| F5.4 raw-source carve-out test | landed | `scanner/test/comment-blindness.test.js` |
| F5.5 AI-BOM vs a standard | landed | ML-BOM validation |
| F6.1 fix quality, three axes | landed | `bench/agent-tasks` |
| F6.2 regression-test generation | landed | PoC generator |
| **F6.3** fix vs upstream | **this session — the answer is 0/6** | `bench/fix-correctness/` |
| F6.4 confinement, adversarial | landed | `scanner/test/confinement-adversarial.test.js` |
| F6.5 honest failure rate | landed | `scanner/test/fix-honesty-gate.test.js` |
| F7.1 execution-proven coverage | landed | proof-coverage reporting |
| F7.2 `INDETERMINATE_BY_CLASS` published | landed | commit `568d73d` |
| F7.3 third-party bundle verification | landed | clean-environment test |
| F7.4 calibration drift gates release | landed | commit `74a694f` |
| F7.5 sandbox escape resistance | **already satisfied when written** | `scanner/test/sandbox-escape.test.js`, 43 tests |
| F10.1 framework provenance | landed | `scanner/test/framework-provenance.test.js` |
| F10.2 measured detector strength | landed | family-producer registry |
| F10.3 no unevidenceable claims | landed | mapping audit |
| F10.4 framework version pinning | landed | `scanner/test/framework-provenance.test.js` |
| F10.5 determinism, all formats | landed | `scanner/test/format-determinism.test.js` |
| **F11.1** every surface smoked | **complete 2026-08-23 — LSP, MCP, VS Code (+type-check), Neovim, JetBrains** | `scanner/test/mcp-protocol-smoke.test.js`, `scanner/test/ide-surfaces.test.js` |
| F11.2 time-to-first-finding | landed | `bench/ttff` |
| F11.3 incremental scanning | landed | parity-gated |
| F11.4 detector liveness | landed (P0) | `scanner/test/detector-liveness.test.js` |
| F11.5 golden path per surface | landed | commit `8fe3381` |
| F12.1 CI-condition pre-push run | landed (P0) | `scanner/test/ci-parity.test.js` |
| F12.2 gates assert equality | landed (P0) | `bench/layer-recall` |
| F12.3 watchdog on every bench | landed (P0) | `bench/_lib/watchdog.mjs` |
| **F12.4** population 315 → 1004, re-measured | **landed 2026-08-23** | `bench/independent/manifest.json`, `mine.mjs` pagination fix |
| **F12.5** mutation gate expanded | **12 → 34 cases 2026-08-23; found 2 live engine bugs** | `bench/mutation/runner.mjs` |
| F12.6 honest scorecard published | landed | `docs/SCORECARD.md` |

**Open, and named as such** (2026-08-23): **Feature 8 (compliance) has no accuracy
instrument** — the last feature measured by nothing. `CODEGEN` is measured dead and
awaiting a retire-or-fix decision. **Fix-discrimination is 71.43%, below its 80% floor**,
and **taint contributes 1 of 28 localized TPs**; both are now measured, and both are in
§14. Feature 5's payload detector is scored (F5.1) and its taint delta measured (F5.3);
its code-shape modules remain unscored.

---

## 1. The thesis

This project's stated moat is *provable, measurable, reproducible* security. Measured
against its own standard, that claim is currently supported for **two** of the ten
features and unsupported for the other eight — not because those eight are bad, but
because **nothing measures them against code this project did not write.**

### 1.1 What is actually measured today

**Updated 2026-08-22.** Six of the eight unmeasured features now have an instrument, and
every one of them found real defects on its first run — which is the argument for the
rule in §1.3, restated as evidence rather than as principle.

| Feature | Accuracy instrument | Labels by | Verdict |
|---|---|---|---|
| 1. Pattern & structural (SAST) | `bench/independent` (**1004** advisories) | third party | **measured** |
| 2. IR & taint | `bench/layer-recall` + `bench/independent --deep` | third party | **measured** |
| 3. Supply chain & SCA | **`bench/sca-replay`** (13 repos, 7 ecosystems) | third party | **measured** |
| 4. Secrets | **`bench/secrets-precision`** (38 formats + 28 hard negatives) | provider docs / this project | **measured** |
| 4. IaC, containers & deploy | **`bench/iac-coverage`** (26 controls, verdict-flip) | published baselines | **measured** |
| 5. AI / LLM security | **`bench/prompt-injection`** (662 rows, Apache-2.0) | third party | **partial** — payload detector only |
| 6. Remediation | `bench/agent-tasks` + **`bench/fix-correctness`** | this project / **upstream fix commits** | **partial** |
| 7. Evidence & assurance | `bench/proof-corpus` | this project | partial |
| 8. Compliance & reporting | none | — | **unmeasured** |
| 9. Product surfaces | LSP + **MCP stdio + IDE** smoke in CI | n/a | **partial** |
| 10. Measurement & release | the gates themselves | n/a | **measured** |

**What the six new instruments cost the engine to satisfy, on their first runs:**

| instrument | first number | after the defects it found were fixed |
|---|---:|---:|
| `bench/sca-replay` (version recall) | 10.89% | **77.92%** |
| `bench/iac-coverage` (verdict flips) | 57.14% | **88.46%** |
| `bench/prompt-injection` (recall) | 6.08% | **18.25%** |
| `bench/secrets-precision` (format coverage) | 60.00% | **92.11%** |
| `bench/fix-correctness` (synthesis coverage) | — | **see F6.3** |

Not one of those jumps came from tuning. They came from a 500 KB cap that dropped every
real lockfile, an admission predicate that never ran, a `\b` after a `?`, a version
truncation that renamed modules, and three formats with no rules at all. **Every one was
invisible to a green unit-test suite**, which is the thesis of this document with numbers
attached.

`scripts/corpus-provenance-check.mjs` still reports **100.0% of `bench/cve-replay`
entries are self-authored fixtures**, and that has not changed — nor should it. It is a
regression net, and the instruments above are the accuracy measurements.

### 1.2 The measured baseline

**Re-measured 2026-08-23 — engine 0.141.0, the full 1004-entry population, 991
scored and 13 unscored.** The version string says 0.141.0 because that is what
`scanner/package.json` read at measurement time; the CODE measured is what ships
as 0.142.0 — the engine edits and these artifacts landed in the same commit and
nothing under `scanner/src/` changed after. Re-running purely to relabel is a
four-hour job and was deliberately not done. The previous figures in this section were engine
0.138.0 over 315 entries and have been replaced rather than kept alongside: a
number measured on a third of the population is not a comparison, it is a
different question.

| | 0.138.0 / 315 entries | **0.141.0 / 991 entries** |
|---|---:|---:|
| localized recall (**the claim**) | 3.56% | **28/991 = 2.83%** |
| localized precision | 44.00% | **28/77 = 36.36%** |
| fix-discrimination | 81.8% | **20/28 = 71.43%** |
| held-out localized recall | — | **6/205 = 2.93%** |

**The headline went DOWN, and that is the population working.** The corpus
tripled by paging past the first hundred advisories per ecosystem (F12.4), and
what it pulled in is recent, TypeScript-heavy, and dominated by authorization
classes — the classes §1.2 has always recorded at or near zero. A number that
falls because the question got harder is not a regression; holding it steady by
not asking the harder question would have been the failure.

Held-out (2.93%) tracks development almost exactly, so nothing here is fitted.

**Two metrics wear similar names, so read the label.** "Localized" here is the
STRICT one — a matching finding within ±3 lines of the code the fix actually
changed — and it is what this section and the per-language table below report.
`docs/SCORECARD.md` publishes **advisory-local** (a matching CWE anywhere in the
advisory's files, `71/991 = 7.2%`) as its headline, with `wide` as its
diagnostic. Neither document is wrong; they are different questions, and the
looser one is always the larger number. When comparing anything across the two,
check which column it came from.

**Per language — and the two measured zeros are no longer zero:**

| language | n | recall | was |
|---|---:|---:|---:|
| csharp | 15 | 6.67% | 6.7% |
| java | 21 | 4.76% | 9.5% |
| **ruby** | **250** | **3.20%** | **0.0%** |
| typescript | 322 | 3.11% | 13.5% |
| python | 100 | 3.00% | 8.8% |
| javascript | 124 | 2.42% | 30.0% |
| **go** | **84** | **1.19%** | **0.0%** |
| **php** | **73** | **0.00%** | 5.5% |
| kotlin | 2 | 50.00% | (none) |

Ruby and Go come off zero on populations 8× and 1.2× their old size. **PHP is
now the zero**, on 73 entries — a new fact, and the next per-language
investigation, using the same histogram method F1.1 and F1.2 used.

The large per-language *drops* (javascript 30% → 2.42%, typescript 13.5% →
3.11%) are almost entirely denominator: javascript went from 20 entries to 124,
typescript from 37 to 322. A 30% recall over 20 entries was 6 findings.

**Which layer earns a localized true positive, across all 28:**

`OWNERSHIP-AUTHZ` 4 · `RUBY` 6 · `LOGIC` 3 · `STRUCTURAL` 3 · `JS-FW` 1 ·
`CSRF` 1 · `FILE-UPLOAD` 1 · **`CONVENTION` 1** · `JAVA` 1 · `ZIP-SLIP` 1 ·
**`SIBLING-GUARD` 1** · `AUTHZ-MATRIX` 1 · `RESOURCE` 1 · `CSHARP` 1 ·
`CRYPTO-PROTO` 1 · `REGEX` 1

Two of those are this session's work, confirmed on the real population rather
than on their own fixtures: `RUBY` includes `lsegal/yard` (GHSA-pxcc-8665-phx8),
the `File.join` rule from F1.3, and **`CONVENTION` earns its first localized TP
ever** on `gitpython-developers/GitPython` — the family §3 recorded as
permanently silent until F1.4 found it was mislocalized by five lines.

**Taint's share is measured separately**, in the deep configuration, because
pattern-only mode does not run the taint engine at all and a 0 there would be
trivially true. See F2.1.

**How this was measured, and why it is not one command.** A whole-population run
**wedged** at 0.0% CPU after 24 minutes of CPU time and 4.5 hours of wall clock
— the signature the per-entry watchdog was built for, and which it cannot fix:
the watchdog bounds the awaited promise, not the handles a stalled scan holds,
so one bad entry costs the run and everything already scored with it.
`runner.mjs` now takes `--offset=` / `--limit=` and each slice runs in its own
process; `merge-chunks.mjs` reassembles them, **recomputing** every aggregate
from the per-entry rows and refusing to write unless that arithmetic reproduces
each chunk's own published numbers exactly. It caught its own first bug that
way: `survivedFix` is a count, not a boolean.

### 1.3 The rule this PRD is built on

> **No feature gets new capability until it has an instrument that can fail.**

This is not process for its own sake. It is the lesson this codebase has already paid
for three times, documented in its own history:

- `WORLD_CLASS_DETECTION_PRD.md` §8d: five detector families built across four rounds
  with no measurement in between, all five silent on the real population, because "the
  rules were written from this document's root-cause prose, not from the vulnerable
  files."
- `docs/METRICS.md`: the taint table sat ~5× stale (11% published vs 54% actual) because
  `bench:layer-recall:check` gates on a **floor** — a 31 → 116 improvement passed it
  exactly as a no-op would.
- 2026-08-19: `rate-limit.js` had silently discarded **every finding it ever produced,
  project-wide, since it was written.** Unit tests passed throughout.

Each was invisible to unit tests and visible only to an instrument scoring against code
nobody here wrote.

---

## 2. Goals and non-goals

### Goals

1. Every one of the ten features has an accuracy instrument whose labels come from
   outside this project, reported with `{n, d}` and a held-out slice.
2. The two zero-recall languages (go, ruby — a third of the population) come off zero.
3. Fix-discrimination stays ≥ 80% as recall rises; a finding that survives its own fix
   is not a detection.
4. Every published number states the configuration that produced it.

### Non-goals (stated so they are not silently attempted)

- **Raising the wide/file-scoped number.** It is the diagnostic, not the claim. Moving it
  without moving localized recall is benchmark gaming, which the mutation gate exists to
  catch and which this project refuses on principle.
- **Domain-oracle classes.** "Which npm env var enables auto-confirm", "which IPv6 textual
  form is loopback" — these need a curated dataset, not analysis. Out of scope unless a
  data source is adopted deliberately.
- **Native/protocol/parser-internal correctness** — browser internals, HTTP/2 framing,
  URI differential parsing. Genuinely outside a multi-language source analyzer.
- **Chasing every language to parity.** Go and Ruby are 104 entries; Kotlin has none in
  this population. Prioritize by measured frequency, not by symmetry.

---

## 3. Feature 1 — Pattern & structural detection (SAST)

**Measured today (0.141.0, 991 entries):** localized recall 2.83%, precision 36.36%. Owned by
`WORLD_CLASS_DETECTION_PRD.md`; only the parts that document does not cover appear here.

**The gap this document adds: the two zero languages.** Go (0/72) and Ruby (0/32) are not
a tuning problem — a rule that fires zero times across 72 real advisories is absent, not
mistuned. `sast/CLAUDE.md` documents Go and Ruby structural detectors that exist, so the
question is why they never match.

**Work.**

- **F1.1 — Root-cause the Go zero, entry by entry. FIRST HISTOGRAM PUBLISHED 2026-08-20
  (n=25 of 72).** Buckets: whether the advisory file was scanned, produced any finding,
  produced the labelled CWE, and where.

  | bucket | n | meaning |
  |---|---:|---|
  | `NO-FINDINGS` | **12 (48%)** | the vulnerable file produced no finding *of any kind* |
  | `WRONG-CWE` | **11 (44%)** | findings on the right file, none of the labelled class |
  | `WRONG-FILE` | 2 (8%) | labelled CWE fired elsewhere in the package |
  | `LOCALIZED` | **0** | — |

  **The obvious hypothesis is dead: this is not a recon, parsing or admission failure.**
  Those same packages produced 195, 380, 507 findings — the engine reads Go fine. It simply
  does not fire on the file the advisory is about, and when it does fire there, it names a
  different weakness.

  Second signal, from the CWEs that *do* land on Go advisory files: `CWE-1077` (float
  comparison), `CWE-532` (log leak), `CWE-798`, `CWE-176`. The Go findings the engine
  produces are dominated by low-value generic classes, while the labelled misses are
  injection/authz/validation — `CWE-22`, `CWE-918`, `CWE-863`, `CWE-287`, `CWE-20`,
  `CWE-129`.

  **Where to start, and why:** `CWE-22` and `CWE-918` are the tractable subset — Go
  detectors for both already exist (`go-structural.js` path traversal, `go-http-user-url`
  SSRF) and still do not match the real shapes. A detector that exists and does not match is
  a cheaper fix than a class with no rule at all, and it tests the fixture-first loop before
  spending it on the harder classes.

  **First rule off this histogram, landed 2026-08-20 — and what it exposed.**
  `sast/sibling-guard.js` (CWE-22, family `sibling-guard-omission`), written
  fixture-first from `GHSA-95cv-r8x4-vh75`, one of the 12 `NO-FINDINGS` entries. The
  shape: two fields of one request struct reach a filesystem rename and the project's
  OWN guard is applied to only one. High precision by construction — the rule never
  decides what a guard is, it observes one on a sibling, so every finding is
  falsifiable from a single screen of code and carries the guard plus both field names.
  On the real entry it fires at `server/handles/fsbatch.go:196` in `pre` and is silent
  on that file in `post`. FP budget measured across 15 real Go packages: 17 findings,
  **1.27%** of all findings, max 5 per repo.

  **The structural discovery matters more than the rule.** It fired in isolation and
  produced nothing through a scan — the `rate-limit.js` signature. Cause:
  `dropGuardedFindings` drops a CWE-22 finding when its window contains a containment
  guard, and for this family the window ALWAYS contains one, because the guard on the
  sibling IS the finding. **The centralized precision filter could never have reported
  this class, no matter how good the detector was**, and it plausibly contributes to the
  12 `NO-FINDINGS` entries: findings produced, then silently dropped. Exemption keyed on
  `family`, deliberately narrow; the window heuristic was not loosened. Recorded in
  `dataflow/CLAUDE.md` — any future "the control exists but is not applied HERE" rule
  needs the same treatment.

  **Hypothesis tested and REJECTED, 2026-08-20 — the guard filter is not eating Go
  findings.** The `sibling-guard` case above showed `dropGuardedFindings` deleting an
  entire family structurally, which raised the obvious follow-up: how much of the
  `NO-FINDINGS` bucket is findings the engine produced and then discarded? Measured by
  A/B-scanning **all 72 Go entries** with guard recognition on and off:

  | | |
  |---|---:|
  | Go entries scored (both configurations) | 72 |
  | findings suppressed anywhere | 14 |
  | **labelled-CWE findings suppressed on advisory files** | **0** |
  | entries where the filter ate a labelled finding | **0** |

  So `dropGuardedFindings` is **well-calibrated on Go**: 14 drops across 72 whole
  packages, and not one of them was a candidate true positive for its advisory. The
  sibling-guard blind spot was genuine but *structural and family-specific*, not the tip
  of a pattern.

  **This redirects the work, which is the point of running it.** The 12 `NO-FINDINGS`
  entries are a real detector gap — missing rules — not a downstream-suppression
  artifact. Effort should go into the rules themselves, and nobody should loosen the
  guard-recognition window on the theory that it is hiding recall: it measurably is not.

  **COMPLETE, 2026-08-20 — all 72 entries, and the pipeline is exonerated.** The remaining
  question was whether `NO-FINDINGS` meant "no rule exists" or "a rule fired and something
  downstream ate it" — the `rate-limit.js` failure mode, which this session produced five
  separate instances of. Method: scan each advisory file twice, once inside its package and
  once in isolation. A file that fires alone and is silent in context has been suppressed by
  package context.

  | bucket | n | % |
  |---|---:|---:|
  | `WRONG-CWE` — fires on the right file, names a different weakness | 37 | 51% |
  | `NO-RULE` — silent both alone and in context: a genuine detector gap | 31 | 43% |
  | `HIT` — labelled CWE on the advisory file | 4 | 6% |
  | **`SUPPRESSED-BY-CONTEXT`** | **0** | **0%** |

  **Nothing is being lost downstream.** Combined with the guard-recognition A/B (0 of 72),
  the pipeline does not drop a single Go finding: no cross-file pass, dedupe, reachability
  demotion, suppression or report filter is costing recall here. Every remaining miss is
  upstream, in the rules themselves.

  **This closes the diagnostic phase and leaves an unambiguous mandate.** No more pipeline
  archaeology: 43% needs rules that do not exist, 51% needs the existing Go rules to name
  the right weakness rather than a generic one. Start where §F1.1 already argues — `CWE-22`
  and `CWE-918`, where detectors exist and mismatch — since that attacks the 51% with the
  cheapest possible loop.

  **A rule was built against the 51% bucket, measured, and REVERTED. 2026-08-20.**
  Recorded because the negative is the useful part, and because the next person will
  otherwise have the same idea.

  Target: `GHSA-45pq-889g-fcgh` (rclone, CWE-22), a textbook *bypassable* guard —
  `if urlpath != "" && path.Clean(urlpath) != urlpath { reject }`. It does not work:
  `Clean("../secret")` returns `"../secret"` unchanged, so a traversing path equals its
  own cleaned form and passes the check written to stop it. The upstream fix swaps in
  `iofs.ValidPath`. This is precisely why the entry sat in `WRONG-CWE` — to every
  guard-aware path in the engine the file *looks* protected.

  `sast/weak-path-guard.js` was written fixture-first, 9 tests green including
  fix-discrimination and five refusal cases. Then measured against reality:

  | | |
  |---|---:|
  | fires on the advisory it was derived from | **no** |
  | findings across 72 real Go packages | **0** (of 11,607 total findings) |

  **Why it misses its own source advisory:** in `restic.go` the guard is present but
  `urlpath` is never used in a filesystem call *in that file* — the fix comment says so
  outright ("The backends join the path with the Fs root"). The real flow is **cross-file**.
  The rule requires the path use in the same function, and that requirement is what makes
  it precise. Deleting it to manufacture a hit on this entry would be tuning to the
  benchmark, which §2 lists as an explicit non-goal.

  **Reverted rather than shipped dormant.** A rule with tests, zero real-world hits, and a
  miss on its own source advisory is surface area without measured value — the same "ship
  dead code" pattern `no-dead-modules.test.js` exists to prevent, and the same shape as the
  `rate-limit.js` rule this session opened with.

  **What it actually establishes:** the `Clean(x) != x` idiom is real, but its real-world
  instances are cross-file, so this class needs **T3.2 (cross-file / stored taint)**, not a
  pattern rule. That is a firmer result than a dormant detector, and it re-prioritises T3.2
  above further Go pattern work for the CWE-22 family.

  **One more signal, worth its own line.** 4 entries produce the labelled CWE *on the
  advisory file* while the benchmark scores Go at **0/72 localized**. So those four fire on
  the right file with the right class and still miss the fix hunk by more than ±3 lines.
  That is a LOCALIZATION gap, not a detection gap, and it is invisible in the headline —
  a reminder that `wide` and `localized` disagree for reasons worth reading, not averaging.
- **F1.2 — Same for Ruby (32 entries). HISTOGRAM PUBLISHED 2026-08-21.** Same method as
  F1.1, parameterised by language rather than copied: scan each advisory file inside its
  package and again alone, then bucket.

  | bucket | n | % |
  |---|---:|---:|
  | `NO-RULE` — silent alone AND in context | **19** | 59% |
  | `WRONG-CWE` — fires, names a different weakness | 13 | 41% |
  | `HIT` | 0 | 0% |
  | **`SUPPRESSED-BY-CONTEXT`** | **0** | **0%** |

  **The zero-suppression result replicates Go**, on a completely different engine path —
  `parser-rb.js` is one of the hand-rolled parsers emitting flat dot-joined callees, not
  Babel. Two languages, two independent measurements, nothing lost downstream in either.
  The "the pipeline is eating findings" hypothesis is now dead twice over, and Ruby is
  *more* rule-starved than Go (59% vs 43%).

  **The largest cluster has a detector that does not cover the language.** Labelled CWEs:
  `CWE-770` ×4 and `CWE-400` ×3 — **7 of 32 (22%)**, all `NO-RULE`. `sast/resource-exhaustion.js`
  (T4.2, already landed for exactly this class) gates on `PY_RE` and `JS_RE` only.

  Confirmed against the real code rather than inferred from the CWE label, because
  recommending work from a label is the §8d mistake. `GHSA-33ph-fccm-39pj`
  (websocket-driver) ships exactly this fix:

  ```ruby
  if payload.bytesize > @max_length
    return fail(:too_large, 'WebSocket frame length too large')
  end
  ```

  An added upper-bound check — precisely the absence that detector models, and its own
  header states "a single `if (n > MAX)` silences it, and that is exactly the fix each of
  these advisories shipped." So the fix-discrimination property holds for Ruby by
  construction, as it does for Python and JS.

  **ATTEMPTED AND REVERTED, 2026-08-21 — and the reason is a finding about the detector,
  not about Ruby.** `resource-exhaustion.js` was extended to Ruby fixture-first
  (`RB_SIZE_OPS`: sized reads, `Array.new`, `.times`, repetition). Measured through the
  REAL pipeline:

  | | |
  |---|---:|
  | Ruby entries scanned | 32 |
  | resource findings | **5** |
  | target `CWE-400`/`CWE-770` entries firing | **0 of 7** |

  Four of the five landed in `examples/benchmark_*.rb`; the fifth on an unrelated CWE-22
  entry. **The motivating advisory never fired**, in either revision.

  **Root cause: the externality model is Python/JS-shaped.** `EXTERNAL_RE` is a fixed
  vocabulary (`request`, `params`, `body`, `argv`, …) plus a Python decorator heuristic.
  Ruby's signal in this advisory is `parse(chunk)` → `@frame.length` → `read(...)`: a
  network chunk flowing into protocol state. Neither `chunk` nor `@frame` is expressible in
  that vocabulary, and the module's own comment already concedes the limit ("EXTERNAL_RE's
  fixed vocabulary cannot express it"). Extending the LANGUAGE without extending the
  EXTERNALITY MODEL cannot work, and that is the real prerequisite for Ruby CWE-400/770.

  **Two measurement errors made while establishing this, both worth recording** because
  they nearly produced the opposite conclusion:

  1. The first pass walked `.rb` files directly instead of calling `runScan`, bypassing the
     ignore list. It reported 24 findings, **18 of them in `test/` and `spec/`** — code a
     real scan never reads. A measurement must run the path the product runs.
  2. A genuine FP class surfaced en route: `File.read(path)` and `io.read(n)` are identical
     syntax with different meanings, and the first version conflated them, firing on
     `File.read(File.join(__dir__, "…/data.json"))` because the PATH contained `data`.

  **Still worth doing, in this order:** `CWE-22` ×4 and `CWE-79` ×4 (injection-shaped,
  where the existing externality vocabulary does apply), and separately an evidence-driven
  widening of the externality model — which would unlock the CWE-400/770 cluster for Ruby
  and is a prerequisite, not a detail.

  **Declared out of scope:** `CWE-416` ×3 and `CWE-401` ×1 are use-after-free and memory
  leaks in C extensions. They are genuine vulnerabilities and not reachable by source
  analysis of Ruby — counted here so the denominator stays honest rather than quietly
  dropped.
- **F1.3 — Fixture-first rebuild for whichever stage dominates. FIRST FAMILY LANDED
  AND RE-MEASURED, 2026-08-22.** Per §8d the loop is one family, then a re-measure —
  never a batch — and that is what this is.

  **Baseline, measured before writing anything.** Over the cached Ruby `CWE-22` /
  `CWE-79` entries (23 at the time of the first run), through the full scan path:

  | bucket | n |
  |---|---:|
  | `HIT` (localized) | **0** |
  | `WRONG-CWE` | 5 |
  | `NO-FINDINGS` | 18 |

  **The dominant bucket splits into two very different halves, and only one is
  addressable.** A large share of real Ruby `CWE-79` is an escaping bypass *inside a
  sanitizer library* — loofah, rails-html-sanitizer, sanitize, phlex,
  prosemirror_to_html all appear. "This HTML sanitizer has a bypass" is not a shape any
  pattern rule reaches; it is the same class as the C-extension use-after-free already
  declared out of scope for Ruby, and it is counted here rather than quietly dropped.

  **The addressable half is `CWE-22`, and it has one dominant shape.**

  ```ruby
  File.join(adapter.document_root, request.path.sub(/\.html$/, '') + '.html')   # lsegal/yard
  File.join(root, tenant, folder_for(key), key)                                 # basecamp/activerecord-tenanted
  ```

  `ruby.js`'s existing `pathTraversalStructural` **cannot reach either**: it requires a
  string LITERAL as the first component (`File.read("/data/" + name)`) and the real
  advisories join variables. `scanRubyPathJoin` was written fixture-first against those
  two advisories.

  **Precision is the entire design**, because the previous Ruby attempt (F1.2) was
  reverted for firing on `File.read(File.join(__dir__, "…/data.json"))`. So the last
  component must be variable-ish, a constant root (`__dir__` / `Rails.root` / `Dir.pwd`)
  is skipped outright, the join must actually reach a filesystem operation, and any
  containment guard in the window silences it — that guard *is* the fix each advisory
  shipped.

  | | |
  |---|---:|
  | fires on `yard` `pre`, silent on `post` | **yes** (both affected files) |
  | Ruby CWE-22/79 localized hits, before → after | **0 → 1** |
  | FP budget: findings across 3,782 real `.rb` files in 128 packages | **41** (≈1 per 92 files) |

  **The bug inside the bug, recorded because it is the more useful half.** The first
  version of the rule was silent on `static_caching.rb` — one of the two advisories it
  was derived from. Cause: the sink pattern ended in `\b`, and **a word boundary after
  `?` can never match**, so `File.file?(path)` did not count as a filesystem operation.
  A rule that looks correct, has passing tests, and finds nothing, because of one
  character of regex. `test/ruby-path-join.test.js` pins all three predicate forms.

  **What is deliberately still missed.** `activerecord-tenanted` builds the path in a
  `path_for` method and uses it elsewhere — a cross-file / return-value flow. The rule
  declines rather than guessing, and that entry stays a miss. Closing it needs T3.2
  (cross-file / stored taint), which is the same conclusion F1.1 reached for Go CWE-22.

  **One family, one re-measure, one honest number.** 0 → 1 localized hit is small. It is
  also the first localized Ruby true positive in these families, obtained without
  loosening anything, and the loop that produced it is repeatable for the next family.
- **F1.4 — Close the three still-silent families. RESOLVED 2026-08-22, and two of the
  three were misdiagnosed.**

  Method: run each detector against **the advisories its own header cites** — the
  decisive experiment, and the one the `weak-path-guard.js` post-mortem in F1.1 says to
  run first. All 11 cited advisories are in the manifest and materialised. Each was
  scanned directly and again through the full pipeline.

  | family | on its own source advisories | verdict |
  |---|---|---|
  | `CODEGEN` | **0 of 5**, direct call *and* full scan | genuinely dead |
  | `CONVENTION` | fires, 4 in `pre` → 3 in `post` | not silent — **mislocalized** |
  | `REDIRECT-TOCTOU` | fires, 1 in `pre` → 0 in `post` | not silent — **architectural fix distance** |

  **`CONVENTION` was five lines away from scoring.** On `GHSA-9rj7-rf2p-w77r` it produced
  a `CWE-88` finding, on the right file, that correctly disappears once the guard is
  added — and scored zero because the finding sat on `def init(` at line 1395 while the
  fix landed at 1431, against a **±3 line** localization window. It was never a detection
  gap.

  Widening the window would be benchmark gaming. Pointing the finding at the line the
  remediation actually touches is just correct, and that is the fix: a "this function
  omits the guard its peers apply" finding now carries the **guard insertion point** —
  the first executable statement of the body, past the signature continuation and the
  docstring — rather than the `def` line. That is also the only one of the three
  candidate lines a reader can act on. **The entry now localizes.**

  **`REDIRECT-TOCTOU` is correct and cannot localize.** Its finding sits exactly on the
  `await dnsPromises.lookup(...)` that creates the check/use gap. Upstream fixed it by
  adding a whole new `installSafeDnsLookup` function 35 lines below and rewiring the
  hook. No line-proximity metric can connect a finding to a fix that is architectural,
  and no change to this detector would help. This is a stated limit of the localization
  metric, not a defect to close.

  **`CODEGEN` is the `weak-path-guard.js` shape.** It produces nothing on any of the five
  advisories in its own header, through either entry point, while passing its own tests
  against fixtures written here. By the standard this document already applied to
  `weak-path-guard.js` — "a rule with tests, zero real-world hits, and a miss on its own
  source advisory is surface area without measured value" — it should be reverted. That
  is a product decision about shipped surface rather than an engineering fact, so it is
  **recorded with its evidence and left to the maintainer** rather than deleted here.

  **The durable lesson is about the metric, not the detectors.** `LOCALIZATION_WINDOW = 3`
  is calibrated for a line-scoped finding — a tainted sink call. A **function-scoped**
  finding ("this function is missing a control") can only satisfy it by accident. Two of
  the three families here were reported as silent for weeks on that basis. Any future
  family of that shape needs to carry the line where the control belongs, or it will
  score zero no matter how right it is.

**Exit gate.** Go and Ruby each ≥ 5% localized recall, with the per-stage histogram
published for both; no regression in the six languages already non-zero; mutation gate
green.

---

## 4. Feature 2 — Intermediate Representation & taint engine

**Measured today:** 116/215 (54%) of corpus detections attributed to `IR-TAINT`; on the
real population, taint contributes **1 of 12** localized TPs at roughly 2× runtime and
+2 false positives.

That contrast is the whole story: **taint looks dominant on fixtures written here and is
nearly invisible on code that was not.** The corpus is taint-shaped because it was
written by the people who wrote the taint engine.

**Measured 2026-08-20 — taint's REACH on real code, with control languages.** Prompted by
a spot check where deep mode produced zero `IR-TAINT` findings on a real 60-finding Go
package. Two control languages were included specifically so the result could not be
misread as a Go quirk:

| language | entries | with ANY taint finding | taint findings | all findings |
|---|---:|---:|---:|---:|
| go | 20 | 3 | **87** | 3013 |
| python | 20 | 2 | 2 | 81 |
| javascript | 20 | 1 | 8 | 222 |

**The n=1 spot check did not generalise, and that correction matters:** Go has the HIGHEST
taint volume of the three. Taint is not failing on Go specifically.

What the population actually shows is **concentration**: only **6 of 60 real packages (10%)
produce any taint finding at all**, and those few produce many. Set against
`bench/layer-recall`, which attributes **54%** of corpus detections to taint, and against
the independent population, where taint accounts for **1 of 12** localized TPs.

The denominators differ — "was the labelled vuln caught by taint" is not "does this package
yield any taint finding" — so these are not one ratio. But the direction is consistent
across three independent measurements, and it is the corpus-provenance problem with numbers
attached: **the corpus is taint-shaped because the people who wrote the taint engine wrote
the corpus.** No conclusion is drawn here about whether T3.2 is correctly marked landed;
that needs the per-entry instrument in F2.1, not this aggregate.

**Work.**

- **F2.1 — A taint-specific third-party instrument. MEASURED IN BOTH
  CONFIGURATIONS 2026-08-23, and the answer is one.**

  `bench/independent` now runs pattern-only and `--deep` over the same 1004-entry
  population, so taint's contribution is a subtraction rather than an inference.

  | | pattern-only | deep |
  |---|---:|---:|
  | scored entries | 991 | 990 |
  | localized recall | 28/991 = 2.83% | 28/990 = 2.83% |
  | localized precision | 28/77 = 36.36% | 28/82 = **34.15%** |
  | fix-discrimination | 71.43% | 67.86% |
  | **taint's share of localized TPs** | — | **1 of 28** |

  **Deep mode finds exactly one thing pattern-only does not, loses one, and
  costs five false positives.** Entry by entry:

  - gained: `GHSA-g3hq-hphg-8fhh` — php, CWE-78, attributed to `IR-TAINT`. This
    is the taint engine's entire contribution to the claim, on 990 real
    advisories.
  - lost: `GHSA-fh2f-xfxc-q9cc` — go, CWE-22, found by `SIBLING-GUARD` in
    pattern-only and **not** found in deep. A deep-mode pass suppressing a
    pattern finding is a regression shape, not a trade, and it is recorded here
    rather than netted off.
  - false positives: 49 → 54.

  **Against success criterion 4 — "taint's share > 1 and rising" — this is a
  clear NO.** It was 1 of 12 at 315 entries and is 1 of 28 at 990: the absolute
  count did not move while the population tripled, so the *share* fell from 8.3%
  to 3.6%. The PRD's own instruction for this case is explicit — "If Feature 2's
  work completes and taint still contributes ~1, that is a finding to act on,
  not to explain away."

  **Per language, taint attributes 1 of 1 in php and 0 of everything else** —
  0 of 10 typescript, 0 of 8 ruby, 0 of 3 javascript, 0 of 3 python, 0 of 1 each
  in java/csharp/kotlin. Set against `bench/layer-recall`, which attributes
  **54%** of corpus detections to taint, the gap between the self-authored corpus
  and real code is now measured twice, in both configurations, and has not
  narrowed.
- **F2.2 — Finish container/collection taint.** 9 of 10 probed shapes now flow
  (`test/container-taint.test.js`); the open one is Python comprehensions
  (`[x for x in request.args.getlist(...)]`). Also unmodelled: cross-file/stored flow
  beyond the current registry, and multi-source provenance pairs (T3.4).
- **F2.3 — Entry-point breadth (T3.1 remainder).** SDK/network-response sources and
  library-mode public-API parameters. For a library the caller *is* the attacker; that
  may warrant a mode rather than a heuristic.
- **F2.4 — Kill the two remaining hang classes.** Six entries exceed the 600 s per-entry
  watchdog, all Java, all very large trees. They are excluded honestly today, but an
  engine that cannot finish a large Java repository in ten minutes is a product problem,
  not only a benchmark one. Profile before optimizing.
- **F2.5 — Reclaim the comment-stripping cost.** The comment-blindness fix cost 5.7%
  end-to-end after two optimizations (from 19.7%). `blankComments` is now on the hot path
  for every file; a lexer-level integration would remove the separate pass entirely.

**Exit gate.** Taint's attributable share of localized TPs is **> 1** and rising, measured
per phase; no per-language FP-budget regression; the 6 unscored entries drop to ≤ 2.

---

## 5. Feature 3 — Supply chain & SCA

**Measured today: nothing.** `posture/` carries `sbom.js`, `sbom-diff.js`, `epss.js`,
`license-{graph,policy,attributions}.js`, `reachability-filter.js`, `iac-reachability.js`
and OSV/KEV enrichment. There is **no bench directory for any of it.** Function-level
reachability — the headline SCA claim in the README — has never been scored against a
labelled set.

This is the largest unmeasured surface in the product, and it is the one customers most
often verify independently, because they can: an SCA result is checkable against a
public advisory database in minutes.

**Work.**

- **F3.1 — `bench/sca-replay`, third-party labelled. LANDED 2026-08-22, and it found
  four real defects on its first run.**

  13 real repositories pinned at resolved commit SHAs across 7 ecosystems; only
  manifests and lockfiles are fetched. The label is produced by `label.mjs`, which
  enumerates dependencies with **its own readers**, sharing no code with `scanner/src` —
  asking the engine for the component list and then asking the advisory database about
  it would put recall at 100% by construction, the exact defect
  `corpus-provenance-check.mjs` reports about `bench/cve-replay`.

  | slice | version recall | precision | package recall |
  |---|---:|---:|---:|
  | **all** | **307/394 = 77.92%** | **307/307 = 100%** | **306/316 = 96.84%** |
  | development | 248/324 = 76.54% | 100% | 98.80% |
  | **held-out** | **59/70 = 84.29%** | **100%** | 89.39% |

  Held-out scores *above* development, which is the number that matters: nothing was
  fitted to the entries used while building it.

  **Two denominators, both published.** The engine collapses findings sharing one
  advisory id into a single row with the rest under `dependents[]` — right for a report a
  human reads, and not a recall failure. Version-level answers "is this pinned version
  reported"; package-level answers "does the report mention this package at all".
  Publishing only the higher would be flattering; only the lower understates the tool.

  **First run: 10.89% overall, npm 0.91%, Go 2.73%, Packagist 0%.** Every point of that
  traced to a concrete defect:

  1. **`readTree` skipped any file over 500 KB before deciding what kind of file it
     was.** npm/cli's `package-lock.json` is 666 KB, next.js's `pnpm-lock.yaml` 910 KB,
     magento2's `composer.lock` 501 KB. **On every project big enough for supply-chain
     risk to matter, the lockfile was dropped** and SCA silently fell back to whatever
     exact versions appeared in `package.json` — direct dependencies only, while the
     headline claim of the feature is transitive reachability. Manifests now have their
     own, much larger cap; the code cap is untouched, because that one protects the
     analysis path.
  2. **`go.sum` was never admitted**, though `_parseGoSum` and its dispatch entry had
     always existed. The fourth instance of "wired into the dispatch, never invoked",
     after `rate-limit.js`, `k8s-admission` and `install-script`.
  3. **Only the exact basename `requirements.txt` was admitted.** flask ships
     `requirements/dev.txt` and scored 0 of 11.
  4. **Go versions were truncated in three separate places.**
     `v0.0.0-20210903162142-ad29c8ab022f` became `0.0.0` — not a shorter version but a
     different, nonexistent one, collapsing every pseudo-versioned module in a tree onto
     one key. Fixing it took **Go from 5.28% to 100%**. It also corrupted the emitted
     SBOM, which is worse: that document is written for other people to rely on.

  **And a fifth, found by the same run.** The typosquat detector produced **166
  critical/high findings across these 13 repositories, of which zero were typosquats** —
  `ms ~ ws`, `acorn ~ cors`, `ajv ~ ava`, `six ~ tox`, `arg ~ yargs`. Absolute edit
  distance is meaningless on short names, and `ms` is a top-50 npm package being reported
  at critical. Now Damerau-Levenshtein (a transposition is the commonest real typo and
  plain distance scores it worst) gated on `distance / min(len) ≤ 0.25`. The FP budget is
  pinned in `test/dep-confusion.test.js` using the names the bench surfaced.

  **What the bench itself got wrong**, recorded because a measuring instrument that hides
  its own errors is worth less than one that does not, and because all four briefly
  blamed the engine: counting `go.sum` `/go.mod`-only lines as shipped dependencies
  (prometheus looked like 1828 dependencies; it has 187, and the first published Go
  recall was an artefact of this); not reading `dependents[]`; treating each
  platform-specific build of one gem as a separate vulnerable component; and marking
  express a negative control on the theory that a project without a lockfile has only
  ranges, when express pins every dependency exactly.

  **Honest limits.** Maven scores 0/0 — the labeller refuses to resolve a version living
  in a parent POM it does not fetch, so Maven is *unmeasured*, not covered. 13 entries is
  small. Both sides consult the same advisory database, so this measures resolution and
  matching fidelity, never whether the database is right.
- **F3.2 — Score reachability as its own claim. SCORED 2026-08-23, and the first
  three adjudicable demotions were all wrong in the expensive direction.**

  `summarizeReachability` reported the demotion RATE, which is not an accuracy
  claim — and `bench/sca-replay` reported that rate as **0 for every entry**,
  because it fetches lockfiles and the analysis had no source to walk. A number
  that is structurally zero looks like a measurement and is not one.

  Source is now fetched for a subset (`withSource`), and
  `bench/sca-replay/reachability.mjs` scores the verdict against an
  **import-level oracle** computed here from the project's own source, by a
  reader sharing no code with the engine.

  **What that oracle can and cannot settle**, stated because it decides how the
  number should be read:

  | engine says | package imported | verdict |
  |---|---|---|
  | unreachable | **yes** | **wrong, and expensively** — a missed exploit |
  | reachable | no | noise |
  | reachable | yes | **NOT ADJUDICATED** — the vulnerable *function* may still be unused |

  The unadjudicated bucket is reported by name. An oracle that quietly scored it
  as correct would report near-perfect accuracy for an analysis that had never
  demoted anything.

  **First run: 3 adjudicable demotions, 3 false-unreachable — 100% wrong.**
  `express`/`cookie`, `express`/`send`, `poetry`/`requests`. Each verified by
  hand: `var cookie = require('cookie')` at the top of `lib/response.js`,
  `import requests` in `poetry/publishing/uploader.py`. All three had been
  demoted to `info` — out of the report entirely.

  **Three engine defects behind it, each fixed:**

  1. **Absence of proof was reported as proof of absence.** The verdict was
     `functionReachable ? 'reachable' : 'unreachable'`, so a site the analysis
     could not reason about became a positive claim of unreachability. Now
     `unknown` — a first-class state the code already used elsewhere.
  2. **A project with no routes was still asked "reachable from a route?"** For a
     LIBRARY that question has no answer: its callers are its users, who are not
     in the tree. `unreachable` now requires the project to have routes at all.
     This is the library-vs-application distinction §4 already flags for the
     taint engine (F2.3), surfacing here as a false demotion instead of a false
     negative.
  3. **`_enclosingFn` recognised two declaration forms out of four.** It matched
     `function name(` and `const name = (`, but not `res.cookie = function (…)` —
     how most of the JS ecosystem defines a public method. The scan walked past
     it and attributed the call site to an unrelated function further up the
     file. It now also carries whether that function is **exported**, because a
     public-API function with no in-tree caller is the normal case, not dead code.

  **After the fixes: 0 adjudicable errors — and 0 adjudicable demotions.**
  The engine now declines to claim on 68 of 70 findings in this sub-corpus. That
  is the honest result and it is not a victory: the false demotions are gone, and
  the feature currently demotes nothing here. Whether that is correct caution or
  excessive caution cannot be settled by these four entries — three of them are
  libraries. Deciding it needs applications with real routes in the source-bearing
  set, which is the next piece of work and is named rather than implied.
- **F3.3 — SBOM conformance, mechanically.** Validate emitted SBOMs against the CycloneDX
  and SPDX schemas in CI. "We emit an SBOM" is worth nothing if a consumer's parser
  rejects it; this is a cheap, binary, external check.
- **F3.4 — KEV/EPSS freshness as a gate.** The catalogs are disk-cached with no staleness
  bound. A KEV catalog six months old silently understates risk. Add an age assertion and
  surface the catalog date in every report that uses it.
- **F3.5 — Malicious-package detection, honestly scoped.** `sca-malware-analyst` emits
  CLEAN/SUSPICIOUS/MALICIOUS verdicts with no measured accuracy. Either score it against
  a labelled set of known-malicious packages, or downgrade its output to advisory until
  it is scored.

**Exit gate.** `bench/sca-replay` publishes precision/recall for vulnerable-dependency
detection and, separately, for reachability, with a held-out slice; SBOM schema
validation runs in CI; no KEV/EPSS figure is published without its catalog date.

---

## 6. Feature 4 — Secrets, IaC, containers & deploy

**Measured today: three self-authored corpus entries** (`tf-open-ingress-shape`,
`hardcoded-stripe-key`, `mcp-untrusted-install-shape`). Secrets detection has a known,
deliberate design decision — the credential scanners read **raw source**, so a key
committed inside a comment is still reported — which is correct, but has never been
scored for precision on real repositories.

**Work.**

- **F4.1 — Secrets precision against a labelled corpus. LANDED 2026-08-22.**
  `bench/secrets-precision`, reporting the two halves separately and never as one F1: a
  missed credential is one exposure, a noisy scanner is *every future* exposure, because
  nobody reads it any more.

  | | |
  |---|---:|
  | **format coverage** | **35/38 = 92.11%** |
  | **correct silence** on the hard negative set | **28/28 = 100%** |

  Recall is measured over credential formats transcribed from **provider
  documentation**, not read out of `CREDENTIAL_PATTERNS` — deriving the positive set from
  the engine's own table would put it at 100% by construction. It measures FORMAT
  COVERAGE and says so; it is not a claim about detecting real leaks in the wild, and no
  ethically assemblable corpus supports that claim.

  The negative set is the half the PRD called harder, and it is where the value is:
  lockfile integrity fields, git SHAs, UUIDs, content digests, inlined base64 images, SRI
  attributes, Docker image digests, Terraform state lineage ids, `.npmrc` env
  interpolation, and **a security rule file that defines key formats** — a secrets
  scanner reporting its own pattern library is a real and embarrassing failure mode.

  **The structural finding.** `CRED_PREFILTER` is a **whole-file gate**: `scanCredentials`
  returns early unless that one regex matches, so a pattern whose trigger token is absent
  can never fire however correct it is. That had silently disabled the generic
  "Password in URL" rule outright, and it is the fifth instance of the
  wired-but-never-invoked shape. The last test in `test/secrets-coverage.test.js` now
  enforces the invariant behaviourally.

  **What was missing, and is not now.** No database URI shape but `jdbc:` — so
  `postgres://user:pass@host/db` and `mongodb+srv://…`, among the commonest real leaks
  there are, matched nothing. Plus GitLab, DigitalOcean, Azure Storage, Supabase and
  HubSpot tokens. One false positive was found and fixed narrowly: the JWT specimen
  published in the standard's own documentation, suppressed by **decoding the payload**
  and matching the documented sample subject — as narrow as the existing
  `AKIAIOSFODNN7EXAMPLE` rule, with a test proving a real token is unaffected.

  **The bench saturated at 100%/100% and was deliberately made harder.** A gate that
  cannot fail measures nothing. Eight formats and eight negatives were added. Datadog,
  Vercel and Algolia keys stay missed **on purpose**: they are a bare run of hex or
  alphanumerics, and a pattern for "32 hex characters" would fire on every content
  digest, checksum and build hash in the negative set — three detections for thousands of
  false positives, in the feature most prone to alert fatigue. Closing that class needs
  variable-name context, not another regex.

  **The bench's own bug, recorded.** The first template syntax used bare `X`/`x`/`a`/`#`/`h`
  as placeholders and silently rewrote the *literal* text inside `da2-`, `shpat_`,
  `https`, `slack` and `key-`. Seven malformed values were generated and reported as
  ENGINE misses. Placeholders are braced now and cannot collide.
- **F4.2 — Verified-vs-unverified secrets.** A live credential and a rotated one are
  different findings with different urgency. Where a provider offers a safe validation
  endpoint, and **only with explicit opt-in**, distinguish them. Never validate by default:
  it is an outbound call carrying a secret.
- **F4.3 — IaC coverage measured against a real corpus. LANDED 2026-08-22.**
  `bench/iac-coverage`, and two design decisions make it an instrument rather than a
  checklist.

  **It runs a real scan, not the detectors.** IaC support here has failed at ADMISSION
  twice, not at detection — `k8s-admission` and `install-script` were both fully
  implemented, wired and unit-tested while returning zero through an actual scan. A bench
  that imports a detector and passes it a string would have scored both as working. Every
  case is written to a temp tree at a path a project really uses and scanned through
  `runScan`.

  **It scores VERDICT FLIP.** Each control ships a vulnerable and a hardened variant, and
  counts as covered only when the first fires and the second does not. `NO-FLIP` is its
  own outcome, distinct from `SILENT`, and is the worse of the two: it looks like
  coverage and carries no information.

  | | first run | now |
  |---|---:|---:|
  | **covered (verdict flips)** | **8/14 = 57%** | **23/26 = 88.46%** |
  | terraform | 4/4 | 6/7 |
  | kubernetes | 3/4 | 6/7 |
  | dockerfile | 1/2 | 3/3 |
  | **cloudformation** | **0/2** | 4/5 |
  | **bicep** | **0/1** | 2/2 |
  | **helm** | **0/1** | 2/2 |

  The three named gaps were whole formats with nothing at all, in either the rule set or
  the walker. `src/sast/iac-cloud-templates.js` closes them, and admission needed **both
  gates again**: a CloudFormation template is a `.yaml` no path predicate recognises, so
  `isCloudFormationTemplate` is a content predicate wired into `readTree` *and* into
  `runFullScan`'s re-filter of the same list.

  **Verdict-flip scoring caught something a recall bench never would.**
  `_ALL_FROM_RE` in `sca/container.js` matched a digest without capturing it, so
  `FROM ubuntu@sha256:…` parsed as image `ubuntu` with no tag — and a missing tag is
  treated as `latest`. **The most tightly pinned form a Dockerfile can use was reported as
  "ubuntu:latest (floating tag)."** A false positive on the *hardened* configuration is
  worse than a miss: it tells the people who did the right thing that they did the wrong
  one.

  **A corollary that cost a debugging round:** a `hardened` variant must be clean of
  everything the engine checks, not just the control under test. Matching is deliberately
  coarse — any finding on the file counts, because matching on the engine's own rule
  names would grade it against vocabulary it chose itself.

  **Saturation, twice, and honest headroom.** The bench hit 14/14 and then 22/22, at which
  points it could no longer fail. Controls now carry a `tier`; the three still open are
  `tier: hard` and are **not expected to pass**: wildcard-*equivalent* IAM
  (`Action = ["s3:*","iam:*"]`, no literal `*`), an open CIDR arriving through a
  CloudFormation Parameter default, and a missing `resources.limits` — an **absence**,
  with no string to match. `tf-sg-cidr-via-variable` was added to the same tier and
  passes, which says the Terraform variable resolution genuinely reaches the rule.

  **Known limitations, published.** Regex over template text, no YAML or Bicep parser —
  the same bundle-size argument that already rejected an XML parser here.
  `templates/*.yaml` in a chart is Go template source, not YAML, and is not read; only
  the values file is. And a `Dockerfile` kept under `build/` is never scanned, because
  `build/` is in the walker's ignore list as build *output* — recorded rather than fixed,
  since changing that list affects every scan.
- **F4.4 — Container image scanning is absent.** `scanContainer` reads Dockerfiles. It does
  not read an image. Decide deliberately: either scan built images (base-image CVEs,
  layer secrets, non-root, pinned digests) or state in the README that image scanning is
  out of scope. The current silence reads as coverage.
- **F4.5 — Deploy-time gate telemetry.** `/setup --ci` and the pre-deploy gate exist;
  nothing measures whether they *block* what they should. Replay a set of known-bad diffs
  through the gate and assert the exit code, both directions.

**Exit gate.** Secrets precision/recall published against a third-party corpus including a
negative set; IaC scored on a public corpus; container-image scanning either shipped with
a bench or explicitly declared out of scope in the README.

---

## 7. Feature 5 — AI / LLM security

**Measured today: two self-authored corpus entries.** This is the product's most
differentiated surface — 14 modules spanning prompt injection, RAG poisoning, MCP audit,
agent-tool escalation, model loading — and its least verified.

It is also the area where **the threat model is still moving**, which argues for
measuring against an external, versioned benchmark rather than a corpus written here.

**Work.**

- **F5.1 — Adopt an external prompt-injection benchmark. LANDED 2026-08-22.**
  `bench/prompt-injection`, scored against `deepset/prompt-injections` (Apache-2.0):
  **263 injections and 399 legitimate prompts**, labelled by its publishers, using the
  dataset's own train/test partition as development/held-out so nobody here chose which
  rows are hard.

  Both classes matter. A corpus of attacks alone measures recall and says nothing about
  how much ordinary text gets flagged — which is the number that decides whether anyone
  leaves the detector switched on.

  | slice | recall | precision | correct silence |
  |---|---:|---:|---:|
  | **all** | **48/263 = 18.25%** | **48/48 = 100%** | **399/399 = 100%** |
  | development | 41/203 = 20.20% | 100% | 100% |
  | held-out | 7/60 = 11.67% | 100% | 100% |

  **Per technique — the breakdown the PRD asked for, and it earns its keep:**

  | technique | first run | now |
  |---|---:|---:|
  | role-play | 82.35% | **100%** |
  | exfiltration | **0/10** | 60% |
  | override | 6.98% | 41.86% |
  | other (residual) | 0% | 6.09% |

  The taxonomy is assigned by the bench, from the corpus text, by rules that know nothing
  about the engine's patterns — so a technique the engine cannot see still gets its own
  denominator instead of disappearing into a bucket that scores well.

  First measurement was **6.08%**. Two of the three weak buckets were patterns that were
  correct and far too literal: `override` required the object noun to be one of
  instructions/directives/prompts/rules/guidelines/safety/policy, while real payloads say
  *"Forget all previous **tasks**"*, *"Ignore all preceding **orders**"*, *"Forget
  **everything** before that"*; `exfiltration` could not match *"show me all your prompt
  texts"*. **Precision and correct-silence stayed at 100% across all 399 legitimate rows
  through every change.**

  **What was deliberately not done, and why it matters more than the delta.** A bare
  `you are X` is NOT a finding — it is the normal opening line of a legitimate system
  prompt, and matching it would flag most of the instruction files this detector exists
  to protect. Much of the residual `other` bucket is that shape and should stay missed
  rather than be bought with precision.

  **German was not patched.** Per language: **en 28.57%, de 2.30%**, and that is the
  largest single gap in the table. It is structural — every pattern is English phrasing —
  and adding German alternatives *because this corpus is German* is fitting to the
  benchmark, which §2 names as an explicit non-goal. A multilingual payload detector is a
  different design, semantic rather than lexical, and needs its own instrument. Published
  as measured headroom.

  **An overfitting signal, stated rather than buried.** Development is 20.20% and held-out
  11.67%; the gap opened with the last change. Two readings are possible and n=60 cannot
  separate them, so **the held-out number is the one to quote**, and the next change here
  should be judged on whether it moves that one.

  **And the engine caught its own author.** The widened override pattern used
  `(?:all\s+|any\s+|the\s+)*` followed by a free `\s*` — the two compete for the same
  run of whitespace, which is the textbook catastrophic-backtracking shape. **This
  engine's own ReDoS detector flagged it on the self-scan gate**, and a second attempt
  (`(?:(?:all|any|the)\s+){0,3}`) was flagged again for the nested quantifier. The
  pattern was rewritten as a flat alternation under a single `?`, which the detector
  accepts and which scores **identically** — 48/263, 100% precision, unchanged per
  technique.

  A security tool shipping an exploitable regex inside its prompt-injection rule is not a
  theoretical problem, and the gate that caught it is one this project built for other
  people's code. The pattern changed; the baseline did not.

  **Scope, stated so it is not overread.** Only the payload detector
  (`scanClaudeMdPromptInjection`) is scored. The code-shape modules (`llm.js`,
  `rag-poisoning.js`, `llm-stored-prompt.js`) take source as input, not payload text, and
  **remain unmeasured**. Encoding-obfuscated and indirect-context have one corpus row
  each and are reported as 0/1 rather than pretending to a measurement.
- **F5.2 — MCP audit against real servers.** `mcp-audit.js` claims OWASP MCP Top 10
  coverage. Score it against a corpus of real published MCP servers, including
  known-malicious tool definitions. Tool-poisoning and rug-pull (a tool whose definition
  changes after approval) are the two shapes with no detector today.
- **F5.3 — Agent-trust-boundary taint, with the localized-TP delta the exit gate
  asked for. MEASURED 2026-08-23, and the delta is undefined for a reason worth
  reading.**

  The modelling landed earlier; the delta never did, so the claim was "we built
  it" rather than "it finds things". `bench/independent/agent-boundary-delta.mjs`
  measures the second.

  **The sub-population exists by accident, and that is the good news.** Until
  F12.4 fixed the miner's pagination, the population held essentially no agent
  code. It now contains **28 entries with real MCP-server code and real
  advisories** — TypeScript 17, Go 4, Python 3, JavaScript 1 — from
  `github/github-mcp-server`, `FlowiseAI/Flowise`, `dynatrace-oss/dynatrace-mcp`,
  `contentful/contentful-mcp-server` and others. Membership is computed from the
  tree on every run, never hardcoded, so it grows with the corpus.

  | | |
  |---|---:|
  | entries inspected | 1004 |
  | entries with agent-tool code | 28 |
  | scored (3 timed out, excluded by name) | 25 |
  | **localized true positives on them** | **0** |
  | **agent-boundary delta** | **0 of 0 — undefined** |

  **The delta is undefined, not zero-because-the-feature-is-useless.** There are
  no localized true positives on this sub-population at all, so there is nothing
  for the boundary modelling to have contributed to. Reporting "0%" would imply
  the feature was measured and failed; it was not measured, because the
  denominator is empty.

  **And the engine is not silent on these files — it names the wrong weakness.**
  Spot-checked by hand on two entries: 21 findings each, every one *on the
  advisory's own files*, and **none of the labelled CWE class**. That is the
  `WRONG-CWE` bucket F1.1 identified for Go, reappearing on the surface this
  product is most differentiated on. The labelled classes here are
  authorization and access control — CWE-306 ×3, CWE-862 ×2, CWE-284 ×2,
  CWE-200 ×2 — plus CWE-22 ×3 and CWE-78/CWE-77, which are precisely the classes
  §1.2 already records at or near zero.

  **What this changes about the work.** The agent trust boundary being modelled
  in the taint layer is necessary and not sufficient: a source is only useful if
  some rule names the weakness the flow reaches. The next move for Feature 5 is
  not more sources — it is the authorization classes on this sub-population,
  which now has 25 scoreable entries and a held-out slice of 4, and which can be
  re-measured with one command after every change.
- **F5.4 — The comment-blindness carve-out needs its own test.** 20 detectors deliberately
  read raw source because for an agentic tool, instructions hidden in a comment *are* the
  attack. That decision is currently protected only by a code comment. It needs a test
  asserting a prompt-injection payload inside a comment **is** still reported — the
  inverse of `test/comment-blindness.test.js`.
- **F5.5 — AI-BOM against a standard.** AI-BOM output should validate against CycloneDX's
  ML-BOM extension, mechanically, or be labelled proprietary.

**Exit gate.** Per-technique prompt-injection scores against an external corpus; MCP audit
scored against real servers; agent trust-boundary flow modelled in the taint layer with a
localized-TP delta; the raw-source carve-out pinned by a test.

---

## 8. Feature 6 — Remediation

**Measured today:** `bench/agent-tasks/security-fixer` exists — the only feature outside
detection with a task-level bench. The deterministic toolchain
(`synthesize_fix → verify_fix → apply_fix`) is the right architecture: the agent calls
tools, it does not edit files directly.

**The unmeasured claim is durability.** A fix that removes the finding is not necessarily
a fix that preserves behaviour, and nothing currently proves it does.

**Work.**

- **F6.1 — Score fixes on three axes, not one:** (a) does the finding disappear;
  (b) **does the project's own test suite still pass**; (c) does an independent verifier
  agree the vulnerability is gone. Today (a) dominates, and (a) alone is satisfiable by
  deleting code.
- **F6.2 — Regression-test generation is the durable artifact.** The PoC generator already
  emits framework-idiomatic tests. Every applied fix should land with the test that fails
  on the vulnerable revision and passes on the fixed one — that is what stops the bug
  returning, and it is checkable.
- **F6.3 — Measure fix *correctness* on the independent population. LANDED 2026-08-22,
  and the number is zero.**

  `bench/fix-correctness` reads the ground truth nobody was using: for every
  `bench/independent` entry the upstream **fix commit** is already materialised as
  `post/`. That is a genuinely third-party ground truth for REMEDIATION rather than
  detection, and nothing had ever opened it.

  Semantic equivalence between two patches is undecidable, so three checkable things are
  reported separately: **synthesis coverage** (for how many real true positives can the
  engine produce a fix at all), **location agreement** (does our patch touch the lines the
  maintainers touched), and **approach agreement** (do the two diffs fall in the same
  remediation category).

  | | |
  |---|---:|
  | entries scanned | 45 (0 unscored) |
  | localized true positives found | 6, across 2 entries |
  | **fix synthesized** | **0 / 6 = 0%** |
  | location agreement | 0/0 — undefined, nothing to compare |
  | approach agreement | 0/0 — undefined |

  **Zero is the honest answer and it was predictable from the code.**
  `posture/deterministic-fix.js` has exactly **two** rules — weak-hash → sha256, and TLS
  verification off → on — and both are JS/Python only. The independent population is
  injection, authorization and resource-exhaustion classes across seven languages. The
  two surfaces barely intersect.

  **What the maintainers actually did, on the findings we got right:**

  | remediation | findings |
  |---|---:|
  | add-guard (`assertStripeIdMatchesSession(...)`, an authorization check) | 5 |
  | rewrite-pattern (a linear-time regex, for a ReDoS) | 1 |

  Neither is a context-independent literal swap, which is the only thing the deterministic
  synthesizer is designed to do — and that design is correct. Widening it to guess at an
  authorization check would produce patches that pass `verify_fix` (the finding
  disappears) while changing behaviour, which is the failure mode F6.1 exists to catch.

  **So this is a scope result, not a bug.** The measured position is: *the engine
  synthesizes fixes for two weakness classes, and on real third-party code those classes
  did not occur.* That belongs in the published failure rate (F6.5) rather than being
  presented as a remediation capability with an unstated denominator.

  **n = 6 is small, and the note is part of the result.** 45 entries of 1004 were scanned;
  a full run is a multi-hour job. The instrument exists, runs clean (0 unscored), and
  scales with `FIX_CORRECTNESS_LIMIT`.

  **Two bugs in this bench, both of which produced a confident wrong answer**, recorded
  because each is a shape worth recognising:
  1. `changedLineRanges` takes **paths**, not contents — it shells out to `diff` — and
     returns `null` on bad input rather than throwing. Passing file bodies made every
     range null, so `isLocalized` was false for everything and the bench reported zero
     localized true positives with total confidence.
  2. Static imports are hoisted, so a top-level `import` of the engine put its module
     graph in place **before** `disableStateWrites()` ran; the first scan then wrote
     `.agentic-security/` into the corpus and the tree-integrity guard correctly refused
     to score anything. Every entry came back UNSCORED. The engine is now imported
     dynamically, after the seal — the ordering is load-bearing, not stylistic.
- **F6.4 — Confinement, adversarially tested.** `agents/_CONFINEMENT.md` defines a
  reserved-write list. Test it the way a boundary should be tested: attempt writes outside
  the tree, through symlinks, through `..` traversal, and assert refusal.
- **F6.5 — Report the honest failure rate.** Publish the proportion of findings where fix
  synthesis is declined or fails verification. A remediation feature that silently
  attempts everything is less trustworthy than one that declines 40% and says so.

**Exit gate.** Fix quality reported on all three axes with `{n, d}`; every auto-applied fix
carries a regression test; confinement has an adversarial test suite.

---

## 9. Feature 7 — Evidence & assurance

**Measured today:** the strongest-architected feature in the product. Proof tiers
(`execution-proven` / `proof-failed` / `taint-proven` / `unproven`), Ed25519 evidence
bundles verifiable by public key, per-install HMAC run attestation, and
`verification-separation.js` enforcing producer/verifier independence.

**The gap is adoption, not architecture: exactly 1 corpus entry of 215 (0.5%) is
`execution-proven`.** The tier that carries the strongest claim is almost never reached.

**Work.**

- **F7.1 — Raise execution-proven coverage.** It is the difference between "a pattern
  matched" and "we ran it and it did the thing." Target the families where a sub-minute
  sandboxed PoC is realistic (injection with a reachable entry point) and report coverage
  as a standing metric, per family, so the honest ceiling becomes visible.
- **F7.2 — Make `INDETERMINATE_BY_CLASS` a first-class, published number.** The PoC
  generator already declines classes it cannot prove. Publishing *which* classes and what
  share of findings they represent is more credible than a high proof rate.
- **F7.3 — Third-party bundle verification, tested end to end.** `verify-attestation` is
  tested in-repo. The claim is that *someone else* with only the public key can verify.
  Test it from a clean environment with no repo checkout — that is the actual claim.
- **F7.4 — Calibration on held-out data, continuously.** `holdout-eval.js` and the
  held-out discipline exist; `calibration-drift.js` exists. Wire drift detection into the
  release gate so a miscalibrated confidence surface fails the build rather than being
  noticed later.
- **F7.5 — Sandbox escape resistance. ~~Not started~~ → ALREADY SATISFIED; this entry was
  wrong when written.** Verified 2026-08-20 by reading the code rather than assuming from
  the feature list. `src/sandbox/` is a dedicated module with a 362-line `CLAUDE.md`, three
  backends (`userspace`, `namespace`, `disabled`), functional rather than presence-based
  backend detection, and **43 passing tests** across `test/sandbox-escape.test.js` and
  `test/sandbox.test.js` — including adversarial cases for out-of-root writes, filesystem
  re-binding, parent-environment leakage, outbound network, wall-clock overrun and fork
  storms. `runConfined` never throws (documented there as the classic route to unconfined
  execution). The proof evidence already records which `backend` produced an
  `execution-proven` verdict, so a third party reading a bundle can see what confinement
  actually held.

  Two limitations are **already pinned by tests that assert the gap exists** rather than
  hidden: the timeout bounds the direct child but does not reap the process tree, and fork-
  storm containment is relative to ambient load, not absolute. Those are the honest residual
  risk, and they are disclosed where a reader will find them.

  **F7.1 is therefore NOT blocked**, and the phasing below is corrected accordingly. The
  remaining work here is narrow and optional: surface the two known gaps in the
  user-facing output of an execution-proven claim, not only in the module's tests.

  *Why this entry was wrong:* it was written from the feature inventory in §1, which lists
  what each feature *is*, not from `src/sandbox/`. That is the same error §8d of
  `WORLD_CLASS_DETECTION_PRD.md` records — "the rules were written from this document's
  root-cause prose, not from the vulnerable files" — reproduced in a document whose own
  governing rule is *measure first*. Recorded rather than quietly edited, because a PRD that
  hides its own misses is worth less than one that does not.

**Exit gate.** Execution-proven coverage published per family with a stated ceiling;
third-party verification demonstrated from a clean environment; calibration drift gates
the release; sandbox threat model documented and tested.

---

## 10. Feature 8 — Compliance & reporting

**Measured today: nothing, and this is the feature where being wrong is most expensive** —
a compliance artifact is read by auditors and regulators who will not re-derive it.

Four coverage maps exist (`docs/compliance/`), and `scripts/nist-compliance/` builds the
NIST AI 600-1 catalog from its source spreadsheet with a gate asserting they match. That
gate is good and should be the template for the rest.

**Work.**

- **F10.1 — Every framework mapping gets a provenance gate.** NIST AI 600-1 has one
  (`controls.json` matches the spreadsheet). ASVS, LLM Top 10, Privacy Framework and EU AI
  Act do not. A mapping nobody can trace to its published source is an assertion, not
  evidence.
- **F10.2 — Distinguish "we check this" from "we check this well."** A control mapped to a
  detector with 5% recall is *covered* in the map and uncovered in reality. Carry the
  measured recall of the backing detector into the coverage map, or mark the control
  `partially-evidenced`. This is the single highest-integrity change in this document.
- **F10.3 — Never claim a control the scanner cannot evidence.** Audit every mapping for
  controls that are organizational rather than technical (policy, training, governance).
  Mark them explicitly out of scope rather than implying tooling satisfies them.
- **F10.4 — Framework version pinning and drift.** Frameworks are revised. Pin the revision
  in every emitted attestation and fail the gate when the upstream source changes without
  a corresponding mapping review.
- **F10.5 — Report determinism as a published property.** `--deterministic` should make
  SARIF byte-identical run to run; `bench/determinism` exists. Extend it to every emitted
  format (SARIF, JUnit, SBOM, attestation) and state it in the docs — auditors care that
  the same input yields the same artifact.

**Exit gate.** Every framework mapping traceable to a pinned published source with a
gate; coverage maps carry the measured strength of the backing detector; determinism
verified for all emitted formats.

---

## 11. Feature 9 — Product surfaces & integrations

**Measured today: nothing.** Ten slash-command dispatchers, an MCP server with 17 tools,
an LSP, three IDE distributions (JetBrains, Neovim, VS Code), and hooks. The engine is
gated heavily; **the surfaces that carry it to users are not gated at all.**

The consequence is asymmetric: a detection regression is caught by four benches, while a
broken IDE extension ships silently.

**Work.**

- **F11.1 — Smoke every surface in CI. LSP DONE 2026-08-20; MCP AND IDE DONE 2026-08-22.**
  As with F7.5, the premise was partly wrong and was checked rather than assumed: MCP
  already had ~1050 lines of tests and `test/lsp-server.test.js` covered the engine side.

  The genuine gap was narrower and worse: **`bin/agentic-security-lsp.js` — the binary
  that ships inside the JetBrains and Neovim plugins — was referenced by no test, no
  script and no workflow.** `test/lsp-protocol-smoke.test.js` now runs the shipped entry
  point as a subprocess and speaks real LSP over stdio, asserting it starts, advertises
  capabilities, yields a renderable diagnostic and exits rather than hanging the editor.
  It deliberately does not assert which rule fired: that is the engine's business,
  measured elsewhere, and coupling it here would teach people to weaken the test.

  **MCP over stdio (`test/mcp-protocol-smoke.test.js`).** `mcp.test.js` is thorough and
  almost entirely in-process, which measures the server logic and says nothing about the
  thing a user runs. The case that matters is the two WRITE tools, because the
  confinement they rely on is established in the *binary* — `_parseRoot` → `path.resolve`
  → `runStdio({ sessionRoot })` — not in the handler. Nine tests now drive the shipped
  binary over real NDJSON: `apply_fix` refusing a relative escape, an absolute out-of-tree
  path and a symlink leaving the root; `apply_sca_upgrade` refusing without confirm, on a
  SAST finding, and on unsigned scan state; a malformed frame not killing the session;
  and — the control that makes the rest mean anything — **an in-tree fix that DOES
  apply**. Every refusal is checked in both directions: the tool refused, and the
  out-of-tree file on disk is byte-identical afterwards. Verified red by neutering
  `_confine`: all three escape assertions fail, the negative control stays green.

  **The IDE distributions were broken, and had been for every release.**
  `ide/vscode/src/extension.ts` looked for the scanner bundle under

  ```
  ~/.claude/plugins/cache/clearcapabilities/agentic-security/0.1.0/scanner/dist/…
  ```

  and Claude Code caches a plugin under its **plugin** version — 0.128.2, 0.136.9,
  0.139.1 on the machine this was found on, never 0.1.0. `0.1.0` is the VS Code
  extension's own version, pasted into the wrong path. **The fallback could not resolve on
  any install**, so every user got *"scanner not found. Set agenticSecurity.scannerPath in
  settings."* Nothing tested it, because the function read `vscode.workspace` and could
  not be imported outside a VS Code host.

  The resolver is now a pure function (`ide/vscode/src/resolve-scanner.mjs`) with every
  input passed in, it **discovers** the cache version rather than hardcoding one and
  prefers `CLAUDE_PLUGIN_ROOT` when present, and `test/ide-surfaces.test.js` covers it in
  15 tests — including a regression pin that fails if any IDE source hardcodes a
  version segment again (verified red by reintroducing the original line). The same file
  gates the wiring each distribution promises the outside world: every contributed VS Code
  command is registered and vice versa, every `onCommand` activation event names a real
  command, the `agentic-security-lsp` binary that Neovim and JetBrains launch is a
  declared `bin` that exists, the install command in each README names this package, and
  the JetBrains `plugin.xml` `factoryClass` resolves to the Kotlin class. A
  `vscode-extension` CI job builds the extension and fails on a stale committed bundle.

  **The three remaining surfaces, closed 2026-08-23.**

  - **VS Code type-check.** `typescript` is now a devDependency of that tree and
    `npm run typecheck` runs in CI. Adding it found real errors on the first run:
    the tsconfig declared no `types` at all, so `process`, `setTimeout` and
    `NodeJS.Timeout` were every one of them unresolved — `@types/node` was already
    installed and nothing consumed it — plus two implicit `any` parameters on the
    `execFile` callback. The extension had never been type-checked.
  - **Neovim.** A headless job loads the plugin from runtimepath, resolves the
    module, runs `setup()` and asserts the load guard is set. No LSP server is
    started — `setup()` only registers a FileType autocmd, and starting a real
    server is `lsp-protocol-smoke`'s job. A syntax error or missing function in
    the lua presents to a user as "the plugin does nothing", the same failure the
    LSP binary had.
  - **JetBrains.** `gradle buildPlugin`, asserting a distribution zip is
    produced. **Classified INFORMATIONAL**, deliberately: it downloads a full
    IntelliJ distribution, so red is far more often the network or a JetBrains
    release than a statement about this code — and a gate that is habitually red
    stops being read, which is the lesson `realworld-bench` already taught. The
    correctness half (plugin.xml's `factoryClass` resolves to the Kotlin class it
    names) is asserted offline and BLOCKING in `test/ide-surfaces.test.js`.

  **The JetBrains job found something on its first run.** The plugin declares
  `org.jetbrains.intellij` **1.17.4**, which Gradle 9 cannot apply at all —
  `Type DefaultArtifactPublicationSet not present`. That is the superseded major
  of the plugin (the IntelliJ Platform Gradle Plugin is on 2.x), so this
  distribution can only be built against an older toolchain. Gradle is pinned to
  8.10 so the job exercises the build rather than the version negotiation, and
  the staleness is recorded here rather than hidden by the pin. Migrating is real
  work on a surface with no users yet.

  **Still open, stated rather than implied:** no `vsce package` — producing the
  marketplace artifact is a publish step, not a correctness check, and nothing
  about it has ever broken.
- **F11.2 — Time-to-first-finding as a tracked metric.** The ICP is vibecoder-first
  (`docs/POSITIONING.md`). For that user the binding constraint is how long until the
  first useful result, not aggregate F1. Measure it on a cold cache for a mid-size repo,
  and treat a regression as a gate failure.
- **F11.3 — Incremental / changed-files-only scanning.** `incremental.js` exists behind a
  flag. Full-repo scan latency is the reason the pre-commit path is painful; a measured
  incremental mode is the fix. Gate on correctness parity: incremental results must equal
  full-scan results for the changed set.
- **F11.4 — Fail loudly, not silently.** The `rate-limit.js` defect — a detector that
  discarded 100% of its own findings, project-wide, undetected — is a *class*. Add a
  startup self-check asserting every registered detector produced ≥ 1 finding on the
  polyglot fixture corpus, and fail the build when one goes dark.
- **F11.5 — One documented golden path per surface.** Each integration should have a
  single tested end-to-end walkthrough, exercised in CI, so documentation drift is a test
  failure rather than a support ticket.

**Exit gate.** Every surface has a CI smoke test; time-to-first-finding tracked with a
regression gate; a dark detector fails the build.

---

## 12. Feature 10 — Measurement & release

**Measured today:** the most mature feature, and still the source of three defects found
in a single day on 2026-08-19.

| defect | consequence |
|---|---|
| `bench/independent` had no per-entry timeout | one entry hung a run for 6 h; 129 entries unscored; **every previously published figure came from a harness that could stall silently** |
| `bench:layer-recall:check` gates on a floor | a 31 → 116 improvement passed like a no-op; published table stale ~5× for weeks |
| neither local gate nor pre-push hook sets `CI=1` | 8 tests passed locally and failed in hosted CI; the engine emits a CI-skip notice tagged `parser: 'IR-TAINT'` that the tests counted as a finding |

**Work.**

- **F12.1 — Run the suite under CI conditions in the pre-push gate.** `CI=true
  GITHUB_ACTIONS=true npm test` catches the third defect above in seconds. This is the
  cheapest item in this document and should land first.
- **F12.2 — Gates assert equality, not floors, where a rise is also news.** A floor gate
  cannot distinguish "unchanged" from "much better", which is precisely how a baseline
  rots. Either compare exactly and require deliberate re-baselining, or emit a loud
  notice on improvement.
- **F12.3 — Every long-running bench gets a watchdog.** `bench/independent` now has one.
  `layer-recall`, `proof-corpus`, `polyglot` and `realworld-recall` do not.
- **F12.4 — Grow the independent population toward 750+, enforce the held-out slice,
  AND re-measure. DONE 2026-08-23 — 315 → 1004, re-measured, §1.2 replaced.**

  **The miner was not paginating.** `mine.mjs` requested `&page=N`, and the advisories
  endpoint **ignores that parameter** — page 1 and page 2 return byte-identical results,
  verified by hand. So every run since the file was written saw only the first ~100
  advisories per ecosystem, and the population was capped there by construction. Mining
  rubygems twelve "pages" deep added exactly **one** entry and looked like scarcity. The
  endpoint paginates by an `after` cursor in the `Link` header, which the miner now
  follows; the same command then added **20 Ruby entries immediately**.

  | language | before | after |
  |---|---:|---:|
  | typescript | 37 | 322 |
  | **ruby** | **32** | **250** |
  | javascript | 20 | 124 |
  | python | 57 | 100 |
  | **go** | **72** | **84** |
  | php | 55 | 73 |
  | java | 27 | 34 |
  | csharp | 15 | 15 |
  | **kotlin** | **0** | **2** |
  | **total** | **315** | **1004** |

  Ruby — one of the two measured zeros — is now the second-largest language, and Kotlin
  is on the board. Go grew least, and that is a property of the source rather than the
  miner: most Go advisories reference a release tag rather than a single fix commit, and
  the admission rule (a CWE *and* exactly one referenced fix commit) refuses the rest
  rather than guessing. The held-out slice needs no maintenance — `isHeldOut` hashes the
  entry id, so ~20% holds automatically across the new population.

  **Re-measured 2026-08-23.** §1.2 now carries engine 0.141.0 over 991 scored entries:
  localized recall **2.83%**, precision **36.36%**, held-out **2.93%**. The headline
  fell, which is the population working — it tripled and got harder — and Ruby and Go
  came off zero in the process.

  **The re-run is why chunking exists.** A whole-population pass wedged at 0.0% CPU after
  4.5 hours, taking every already-scored entry with it. `runner.mjs --offset= --limit=`
  plus `merge-chunks.mjs` now make the measurement restartable and a wedge cost one slice:

  ```bash
  cd bench/independent && node fetch.mjs                      # materialise
  for o in $(seq 0 50 1000); do node runner.mjs --offset=$o --limit=50; done
  node merge-chunks.mjs            # + --deep for the deep configuration
  ```
- **F12.5 — Expand the mutation gate. DONE 2026-08-23 — 12 → 34 cases, and it
  found two live bugs on its first run.**

  The exit gate asked for ≥ 30. It stood at 12 while 0.141.0 shipped five new
  detector families (CloudFormation, Bicep, Helm values, Dockerfile pinning, Ruby
  `File.join`) — none of which owed a case until now, which is precisely the
  debt F12.5 exists to prevent.

  Every new family gets a baseline, a **semantics-preserving rewrite** (the
  verdict must hold) and a **semantics-changing near-miss** (the verdict must
  flip). Verdict-flip correctness now scores **34/34**.

  **What it caught, neither of which any recall measurement could see:**

  1. **The CloudFormation ingress rule was keyed on key ORDER.** It anchored on
     `- IpProtocol`, so `- CidrIp:` first — the same template, since YAML
     mappings are unordered — matched nothing. The metamorphic case failed
     immediately. Now the ingress LIST is split into items and each is read as a
     mapping.
  2. **A sanitizer could be UNDONE and the flow still read as clean.**
     `he.decode(escapeHtml(req.query.name))` reaching an HTML sink was reported
     **sanitized** — a missed XSS, because the decode restores exactly what the
     escape removed. Nothing modelled reversal: the catalog holds sanitizers, a
     decoder is the opposite, so it was never even recorded on the path.

     Fixed across three layers, and the third is the interesting one: the walk
     now collects un-sanitizer callees, `sanitizer-gate.js` maps them to the
     family they reverse (percent-decoding does not undo HTML escaping, so a
     flat list would be wrong), and the finding-projection **allowlist** in
     `dataflow/engine.js` had to learn the new field — the fix looked inert
     through three rounds of debugging because the field was being silently
     dropped there. That allowlist's own comment warns about exactly this.

  **A case was deliberately NOT added**, and the reason belongs here. Hoisting a
  sanitizer into a helper —

  ```js
  function clean(v) { return escapeHtml(v); }
  const name = clean(req.query.name);
  ```

  — is a semantics-preserving rewrite the engine gets **wrong**: sanitizer effect
  does not propagate through a summarised return, so the flow reads unsanitized.
  Adding it would make this gate permanently red, and a gate nobody can pass is
  a gate that gets deleted. It is recorded in `dataflow/CLAUDE.md` instead. The
  error direction is precision, never a missed vulnerability, which is why it is
  a documented limitation rather than a blocker.
- **F12.6 — Publish the honest scorecard, prominently.** 2.83% localized recall is a low
  number. Publishing it, with the methodology that makes it low, is a stronger market
  position than a corpus-derived F1 that does not survive contact with real code — and it
  is the only position consistent with the project's stated moat.

**Exit gate.** CI-condition run in the pre-push gate; every bench has a watchdog; no gate
is floor-only without a stated reason; population ≥ 500 with Go/Ruby prioritized;
mutation gate ≥ 30 cases.

---

## 13. Phasing

| Phase | Scope | Why here |
|---|---|---|
| **P0 — Cheap integrity** | ~~F12.1, F12.2, F12.3, F11.4, F7.5~~ — **LANDED 2026-08-20** (`2aae26e`, `243e744`) | Each closed a class of silent failure already observed. F7.5 turned out to be already satisfied (see above) and blocks nothing. |
| **P1 — Instrument the unmeasured** | ~~F3.1–F3.2, F4.1, F5.1, F6.1, F11.1~~ — **LANDED 2026-08-22** | Nothing in P2 is trustworthy without these. Published numbers did fall, then rose once the defects the instruments exposed were fixed. |
| **P2 — The measured zeros** | ~~F1.1, F1.2, F1.4, F2.1–F2.2, F12.4~~ — **LANDED**; F1.3 first family landed, more remain | Go + Ruby were a third of the population; the per-stage histograms decided the work, and two of the three "silent" families turned out to be mislocalized rather than silent. |
| **P3 — Depth per feature** | ~~F3.3–F3.5, F4.2–F4.5, F5.2–F5.5, F6.2–F6.5, F7.1–F7.4~~ — **LANDED** | Capability, once each area can prove it moved. |
| **P4 — Integrity of the claim** | ~~F10.1–F10.5, F11.2–F11.5, F12.5–F12.6~~ — **LANDED** | Compliance and surfaces last: they publish what the earlier phases establish. |

**P0 and P1 block the rest.** Running P2–P4 against the current instruments would produce
numbers nobody should trust, in either direction.

### P0 outcome, recorded 2026-08-20

Landed in `2aae26e` and `243e744`, both gated and on `origin/main` with hosted CI green:

- **F12.1** — `test:ci-parity` (104 tests, 45 s) in the pre-push gate *before* the 4-minute
  suite, plus a static invariant. The invariant's first draft was useless and **its own red
  check proved it**: it matched the bare identifier, which the `finally` restore lines kept
  present while the file was broken. It now requires an assignment.
- **F12.2** — layer-recall gates on equality; improvement fails too, verified in both
  directions against the real corpus.
- **F12.3** — shared `bench/_lib/watchdog.mjs` with 5 tests; `bench/polyglot` skipped on
  purpose (read-denied by the committed `.claude/settings.json`).
- **F11.4** — detector liveness, which **found two dead detectors on its first run** and
  both were then fixed: `k8s-admission` (the documented `kind:` content check had never been
  implemented, so Kubernetes worked only for repos naming a directory `k8s/`) and
  `install-script` (`package.json` fails `shouldScan`, so the rule was never invoked).
  `KNOWN_DARK` is empty.

**The k8s fix needed BOTH admission gates**, which is the durable lesson: `runScan` admits a
file into `fileContents`, then `runFullScan` re-filters that same list with `shouldScan()`
at `engine.js:7980`. With only the first opened, the predicate returned true, the walker
collected the files, and the scan still returned zero.

Blast radius measured rather than assumed: 16 of 1129 YAML files newly admitted (1.4%), all
in fixtures/caches; self-scan unchanged at 427 — a drift that was **predicted and did not
happen**.

---

## 14. Success criteria — scored 2026-08-23

Measured on the **held-out slice**, in both configurations, with the strict
metric. Every figure comes from a run made this day against the 1004-entry
population at engine 0.141.0.

| # | criterion | status |
|---|---|---|
| 1 | **Ten instruments, one per feature**, third-party labelled, `{n, d}`, held-out slice | **9 of 10.** Eight new instruments now exist (F3.1, F3.2, F4.1, F4.3, F5.1, F5.3, F6.3, F11.1). Feature 8 (compliance) still has none — the only feature with no accuracy measurement at all. |
| 2 | **Go and Ruby off zero** (≥ 5% each) | **off zero, below 5%.** ruby **3.20%** (8/250, was 0/32), go **1.19%** (1/84, was 0/72). PHP is the new zero at **0/73**. |
| 3 | **Fix-discrimination ≥ 80% sustained** | **NOT met — 71.43%** (20/28) pattern-only, 67.86% deep. Was 81.8% at 315 entries. |
| 4 | **Taint's share of localized TPs > 1 and rising** | **NOT met — 1 of 28.** It was 1 of 12; the count did not move while the population tripled, so the share fell 8.3% → 3.6%. See F2.1. |
| 5 | **Every compliance control carries the measured strength of its backing detector** | **met** (F10.2). |
| 6 | **No published number without its configuration** | **met.** §1.2 states engine, population size and date; F2.1 reports pattern-only and deep separately rather than merging them. |

**Three of six are unmet, and all three are now measured rather than unknown** —
which is the difference between this scoring and the previous one. The instruments
exist, they run on one command each, and they disagree with the product's
ambitions in specific, addressable places:

- **Fix-discrimination fell below its floor.** 8 of 28 localized true positives
  still fire on the code the fix produced. That is the criterion most worth
  acting on: a finding that survives its own fix has detected an API, not a
  vulnerability.
- **Taint contributes one finding.** Not a trend, not a share worth quoting — one.
  The PRD's own instruction applies: act on it, do not explain it away.
- **Feature 8 has no instrument.** Compliance is the feature where being wrong is
  most expensive, and it is the one still measured by nothing.

---

## 15. Risks

| Risk | Mitigation |
|---|---|
| Instrumenting eight features is a very large scope | Each instrument is independently shippable and ends in a published number; P0 alone is worth landing. |
| The honest numbers look like a catastrophic regression | Publish both figures with the methodology stated, exactly as `bench/independent/README.md` already did when recall fell 33.6% → 12.7%. A number that drops because it became true is the value proposition working. |
| Fitting to 315 known answers | Held-out slice never read during development; mutation gate; corpus-provenance check already refuses self-authored entries as accuracy evidence. |
| Recall work explodes false positives | Every feature carries its own FP budget; fixed upstream revisions are real-world negative controls, far stronger than synthetic clean fixtures. |
| Adding benches slows the gate past usability | Benches are measurements, not gates, unless explicitly promoted; the pre-push gate stays cheapest-fail-first. |
| Secret validation (F4.2) exfiltrates a live credential | Explicit opt-in only, never default, provider-sanctioned endpoints only, and never for a secret the user has not already flagged. |

---

## 16. Open questions

- **Does "analyze as a library" warrant a distinct mode?** For a library the public API *is*
  the trust boundary; for an application it is not. Same code, different correct answer.
- **Should container-image scanning be in scope at all?** It is a crowded space with mature
  tools. Declaring it out of scope may be stronger than a shallow implementation.
- **Is convention-deviation (Theme 6) a detector or its own product surface?** "You deviated
  from your own pattern" is a different claim from "this is exploitable" and may deserve
  its own severity model.
- **What is the honest ceiling on execution-proven?** Before investing in F7.1, estimate
  what share of findings are provable by a sub-minute sandboxed PoC. If it is 15%, that
  number should be published as the ceiling rather than pursued indefinitely.
- **Should the independent population include languages with no current detector coverage?**
  Adding Kotlin/Rust entries would lower the headline while measuring something real. This
  document's bias says yes, but it should be a deliberate decision.

---

## 17. Reproducing every number in §1

```bash
cd scanner
npm run bench:independent -- --json          # localized/wide recall, per-language, per-CWE
npm run bench:independent -- --deep --json   # taint's attributable share
npm run bench:layer-recall                   # per-layer, per-language attribution
node ../scripts/corpus-provenance-check.mjs  # self-authored share of bench/cve-replay
```

### The instruments added 2026-08-22

Each writes a committed `RESULT.json` next to its runner and carries a README stating
what it measures and, more importantly, what it does not.

```bash
cd scanner
npm run bench:sca-replay:fetch && npm run bench:sca-replay:label && npm run bench:sca-replay   # F3.1  (network)
npm run bench:secrets-precision                                                                 # F4.1  (offline, <1s)
npm run bench:iac-coverage                                                                      # F4.3  (offline)
npm run bench:prompt-injection:fetch && npm run bench:prompt-injection                          # F5.1  (network)
FIX_CORRECTNESS_LIMIT=45 npm run bench:fix-correctness                                          # F6.3
```

The offline regression nets for the defects those benches found, all inside `npm test`:
`test/dep-file-admission.test.js`, `test/dep-confusion.test.js`,
`test/secrets-coverage.test.js`, `test/iac-cloud-templates.test.js`,
`test/prompt-injection-payloads.test.js`, `test/ruby-path-join.test.js`,
`test/mcp-protocol-smoke.test.js`, `test/ide-surfaces.test.js`.

Committed artifacts: `bench/independent/RESULT.json` (2026-08-19, engine 0.138.0, 309
scored / 6 unscored), `bench/layer-recall/baseline.json`, `docs/METRICS.md`.
