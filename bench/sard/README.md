# SARD benchmark (SARD_AGENTIC_SECURITY_PRD.md)

This directory holds the **new** pieces of the SARD/Juliet benchmarking work that don't already
exist elsewhere in the repo. It deliberately does **not** duplicate the existing SARD/Juliet
harness — see "Architecture" below before adding anything here.

Status: see `IMPLEMENTATION_STATUS.md` in this directory for the authoritative, per-requirement
ledger (what's done, what's verified, what's still missing, with the exact command that produced
every number). This README describes what exists and how to run it; the ledger is the source of
truth for status.

## Why SARD

[NIST's Software Assurance Reference Dataset](https://samate.nist.gov/SARD/test-cases) (SARD)
publishes 100k+ labeled test cases across many languages and CWEs, including the Juliet Test
Suites (Java, C#, C/C++) and the PHP Vulnerability Test Suite — vulnerable/mitigated code pairs
generated from a common template family, each labeled with its CWE. It's a controlled fitness
function for measuring and improving detection recall, precision, CWE classification, and
localization — not an end in itself. See the PRD's "Core Principle": detect the vulnerability,
not the benchmark.

## Architecture — read this before adding a script here

`scanner/test/benchmark/realworld/bench-realworld.js` already implements dataset download
(shallow git clone of pinned-SHA upstream Juliet mirrors), ingestion (`buildJulietExpected`,
`buildJulietCsExpected`), and leakage-safe scanning (`--blind`, `--strip-all-comments`,
`--scramble-identifiers`, `--cwe`) for Java and C#. **Do not build a second, parallel pipeline
for those two languages.** This directory adds only what that harness doesn't do:

| Capability | Where |
|---|---|
| Download + ingest Java/C# Juliet | `bench-realworld.js` (existing) |
| Download + ingest PHP SARD | `bench/sard/scripts/ingest-php.mjs` (no existing PHP Juliet/SARD harness) |
| Leakage-safe scanning (comment strip, identifier scramble, targeted CWE subset) | `bench-realworld.js --blind [--scramble-identifiers] [--cwe CWE-89,...]` (existing + this PRD's `--cwe` addition) |
| Leakage audit | `bench/sard/scripts/leakage-audit.mjs` |
| Per-CWE TP/FP/FN | `bench-realworld.js` `score()` / `score-php.mjs` |
| Vulnerability-level (not corpus-wide-wildcard) scoring | `sard-juliet-java-strict` / `sard-juliet-csharp-strict` manifest entries |
| **Macro F1** (this PRD's primary metric), per-CWE report, CWE confusion matrix, localization accuracy | `bench/sard/scripts/macro-score.mjs` |
| Structural train/dev/test split + duplicate-crossing audit | `bench/sard/scripts/split.mjs` |
| Local regression gate (SARD numbers + external holdout) | `bench/sard/scripts/compare-baseline.mjs`, `holdout-check.mjs` |
| Evidence-based error clustering / prioritization | `bench/sard/scripts/analyze-errors.mjs` |
| CI-appropriate smoke subset | `bench-realworld.js --cwe <5 representative CWEs>`, wired as `npm run bench:sard:smoke` |
| Semantic mutation, fix verification | not yet built — see `IMPLEMENTATION_STATUS.md` |

## Quick start

```bash
cd scanner

# Fast smoke test (2-3 min, 5 representative CWEs) — the thing to run day to day.
npm run bench:sard:smoke

# Full leakage-clean, vulnerability-level run (~10-15 min per language).
npm run bench:sard:java       # sard-juliet-java-strict
npm run bench:sard:csharp     # sard-juliet-csharp-strict

# PHP (separate pipeline — see "PHP" below).
node ../bench/sard/scripts/score-php.mjs --json | node ../bench/sard/scripts/macro-score.mjs

# Structural split (once per corpus; requires the corpus already cloned by a run above).
npm run bench:sard:split -- --app sard-juliet-java-strict
npm run bench:sard:split:check -- --app sard-juliet-java-strict   # duplicate-crossing audit

# Error clustering (pure post-processing over an already-completed run's --json output).
node ../bench/sard/scripts/analyze-errors.mjs --input <path-to-a-bench-realworld---json-output>

# Local regression gates.
npm run bench:sard:update-baseline   # after macro-score.mjs has written reports/latest.json
npm run bench:sard:check-baseline
npm run bench:sard:holdout-update-baseline   # external, never-SARD-tuned corpora
npm run bench:sard:holdout-check
```

A full Java Juliet run (40,845 files after excludePaths filtering) takes roughly 8-15 minutes
depending on machine load; the `--cwe` flag (below) is how to run a fast subset instead of the
whole corpus.

## `--cwe`: targeted / smoke runs

`bench-realworld.js --cwe CWE-89,CWE-79` restricts BOTH ground-truth construction and the actual
scan surface to the listed CWE directories (unlisted directories are added to `excludePaths`, so
the scanner never reads them — a filtered run is actually faster, not just a narrower report).
CWE numbers that don't have a standalone Juliet directory (e.g. the abstract parent CWE-79 — only
its children CWE-80/81/83 exist as directories) are silently absent from the output; check the
stderr line (`--cwe ...: excluding N/M CWE directories from the scan itself`) to confirm the
filter matched what you expected. `npm run bench:sard:smoke` uses this with 5 representative CWEs
across 5 distinct families (SQLi, command injection, path traversal, XSS, weak crypto).

## Strict vs. non-strict scoring — read before quoting a number

`sard-juliet-java` / `sard-juliet-csharp` use `wildcardFamilies` in
`scanner/test/benchmark/realworld/manifest.json`: **any** finding of a covered family anywhere
in the corpus counts as a TP, and expected entries in a wildcard family are never scored as FN
at all. This mirrors the OWASP Benchmark scorecard convention and is fine for cross-version
comparability, but it is **not** a per-vulnerability measurement.

`sard-juliet-java-strict` / `sard-juliet-csharp-strict` set `wildcardFamilies: []` and
`preciseMethodScoring: true`: ground truth is one entry per `bad()` method span with a real line
range, and a finding only counts as a TP if it lands inside its own matching span.
`goodG2B()`/`goodB2G()`/other `good*()` spans are deliberately NOT expected entries — Juliet's own
convention is that these are the SAFE half of the testcase (even `goodG2B`, which pairs a
hardcoded/safe SOURCE with a structurally-dangerous SINK, exists specifically to catch a scanner
that fires on sink shape alone without real taint verification) — a finding landing there
correctly counts as an FP, not a bonus TP. **Use the `-strict` variants for any claim about
detection quality.** As of this session: Java macroF1=45.6% (P=66.5% R=36.9%), C# macroF1=8.4%
(P=8.1% R=5.7%, 26/32 CWE families have zero detector coverage at all — see
`IMPLEMENTATION_STATUS.md` Phase 6). These are local numbers, not committed or externally quoted
— see "Reports" below.

**`--scramble-identifiers` + `-strict` requires special handling, already implemented — read this
if you ever touch `buildJulietExpected`/`buildJulietCsExpected` again.** Scrambling renames the
exact `bad`/`good*` identifiers the strict-mode ground-truth builder pattern-matches on, so if the
GT builder reads from the SAME (scrambled) tree the scanner scans, every file silently falls back
to file-level scoring — a real bug found and fixed this session (see `IMPLEMENTATION_STATUS.md`'s
"corrected the ground-truth-vs-scramble conflict" entry). The fix: an optional `gtContentRoot`
parameter feeds the GT builder from a parallel, comment-stripped-but-NOT-scrambled materialization
(same line numbers, since only token text differs), while scoring still happens against the
scrambled tree the scanner actually reads. Verify any future change to this logic with
`--gt-dry-run` (builds `expected[]` and exits — seconds, not the ~10 minute full scan cost) before
trusting a real run: check the printed ratio of method-tagged vs. file-level-fallback entries.

## Leakage — what's prevented, and the one known residual

`--blind` strips `FLAW`/`POTENTIAL FLAW`/`INCIDENTAL FLAW`/OWASP marker comments.
`--scramble-identifiers` (layered on top of `--blind`) renames Juliet method/class identifiers
using general, case-insensitive, digit-suffix-aware rules (not an enumerated list — Juliet has
too many numbered flow-variant names for that to stay complete) plus a rule that hashes the
`CWE<N>_<descriptor>` tail of package statements and class declarations to an opaque token.
**Treat `--scramble-identifiers` as required, not optional, for any run meant to demonstrate
leakage-safety** — `bench:sard:java`/`bench:sard:csharp` pass it by default; a `:fast-unsafe`
variant without it exists for quick iteration only.

Verify a workspace yourself before trusting it:

```bash
node ../bench/sard/scripts/leakage-audit.mjs --app sard-juliet-java --variant scramble
```

`--app` (not `--root`) resolves the materialized path internally from `manifest.json` — the
literal `.bench-cache/**` path is on this repo's coding-agent deny-list (`.claude/settings.json`),
so a human operator can still use `--root <path>` directly, but an agent session should always use
`--app`. The audit's `SOURCE_EXT_RE` filter scopes it to files the scanner actually parses (repo
README/CI-yaml/gradle-kts plumbing is inside `scanRoot` but never scanned as vulnerability source
— flagging it would be a false positive against the audit's actual purpose); pass
`--include-non-source` to audit everything anyway, and `--show-context` to see a short excerpt
around each hit when diagnosing a failure.

**Known residual** (measured, not assumed): after the fix above, a full-tree audit still finds 3
hits (down from 907,516 pre-fix) — both in `.xml`/`.properties` "Helper" resource files, both
plain-English "CWE" mentions inside `<!-- -->`/`#`-style comments that the shared comment-stripper
doesn't recognize (it only knows `//`/`/* */`, plus `#` for `.py` specifically). Real fix would
extend `_langFor()`/`blankComments()` with XML/properties comment awareness — logged as a TODO,
not urgent (3 hits in non-code helper files, not executable test source).

## PHP

No existing PHP Juliet/SARD harness exists in this repo, so PHP has its own small pipeline
(`ingest-php.mjs` + `score-php.mjs`) rather than extending `bench-realworld.js`'s manifest, which
is Java/C#-shaped (git-mirror clone + directory-per-CWE convention that doesn't match the PHP
SARD suite's SARIF-manifest-per-archive layout). Source: the SARD PHP Vulnerability Test Suite
(NIST SARD test-suite #103), pinned with a self-computed SHA-256 in `bench/sard/dataset-lock.json`
— **never trust a checksum quoted by a third party.** `ingest-php.mjs` assigns each case an opaque
id (hash of the original numeric SARD id, so the id can't be looked up at samate.nist.gov to
reveal the answer), neutralizes the source (comment stripping, preserving line numbers so SARIF
line references still line up), and writes gold labels to `bench/sard/gold/php.json` — **never
copied into `workspace/`**, which is what the scanner actually reads. 5,000 of 42,212 total cases
ingested so far (full-corpus ingestion not yet done).

## Structural train/dev/test split (Phase 4)

`split.mjs` groups Juliet's many flow-variant files (`..._01.java`, `..._02.java`,
`..._54a.java`/`..._54b.java`, ...) into template families by stripping the trailing
`_NN[ab]` suffix from the filename, then assigns each FAMILY (not each file) to train/dev/test via
a deterministic seeded hash — so no near-duplicate variant of the same underlying vulnerability
pattern can land in both TRAIN and TEST. This reads original filenames (allowed for the trusted
benchmark controller doing dataset splitting, PRD §8.1) — it never touches what the scanner sees.
`--verify` re-derives family membership from the corpus and confirms it matches the persisted
split file, failing closed (exit 1) if not — this is a real, runnable duplicate-crossing audit,
not just a structural argument. Splits are committed (`bench/sard/splits/*.json`, NOT gitignored
— small, contain only family-key strings, no corpus content).

## Reports and the "no committed benchmark scores" policy

`macro-score.mjs`/`analyze-errors.mjs` write to `bench/sard/reports/` (gitignored — per
`bench/README.md`'s repo-wide policy, **no benchmark scores are committed**). This extends to the
regression-gate baselines too (`compare-baseline.mjs`/`holdout-check.mjs` write
`baseline.json`/`holdout-baseline.json`, also gitignored) — a deliberate deviation from this PRD's
literal assumption of a committed baseline like `bench/cve-replay/corpus-baseline.json`: a raw
SARD F1 percentage is exactly the kind of single-corpus number `bench/README.md`'s policy exists
to keep out of the repo. Every developer/CI runner builds their own local baseline
(`--update-baseline`) rather than sharing a committed one. Numbers here are for local engineering
iteration only; never quote them in a committed doc or external claim without following the
process in `bench/README.md`'s "What would unlock external claims" section.

## Adding a new SARD suite / language

- **Java/C#**: extend `manifest.json` + `bench-realworld.js`'s `buildJulietExpected`/
  `buildJulietCsExpected` family. Don't add a second ingestion path here.
- **A language with no existing Juliet ingestion (PHP today; others later)**: add an
  `ingest-<lang>.mjs` + `score-<lang>.mjs` pair under `bench/sard/scripts/`, following the gold-
  schema shape `buildJulietExpected` already uses (`{file, line, lineEnd?, family, cwe, method?}`)
  so `macro-score.mjs` can consume either corpus's `--json` output identically, and a
  `dataset-lock.json` entry recording the source URL, byte size, and a self-computed SHA-256.

## Interpreting failures

`analyze-errors.mjs` clusters FNs/FPs by Juliet's own filename descriptor (the source/sink/
propagation segment between the CWE tag and the trailing flow-variant number — the same signal
`split.mjs` uses for family grouping) and ranks clusters by volume. This is a genuine,
evidence-based signal (a plain path string already present in scan output, not raw source
content this agent can't read), but it does **not** attempt the PRD's full 23-category structural
taxonomy (INTERPROCEDURAL_FLOW, FIELD_FLOW, ...) — doing that with real confidence needs to see
*why* the engine missed a specific case, which needs source access this repo's own coding-agent
deny-list intentionally withholds. One mapping is applied with genuine confidence: a paired
`_NNa`/`_NNb` variant mechanically means MULTI_FILE_FLOW/INTERPROCEDURAL_FLOW by Juliet's own
documented generation convention, not by inference over unseen content.

## Fix verification

Not yet built (Phase 8). The deterministic MCP toolchain (`synthesize_fix` → `verify_fix` →
`apply_fix`, `scanner/src/mcp/`) and the PoC/verdict machinery (`posture/poc-generator.js`,
`posture/verifier.js`) are the reusable pieces this should wire into rather than duplicate — see
`IMPLEMENTATION_STATUS.md` Phase 8.

## Updating baselines

```bash
# SARD numbers (per-app, local-only).
node ../bench/sard/scripts/macro-score.mjs --input <run>.json   # writes reports/latest.json
node ../bench/sard/scripts/compare-baseline.mjs --update-baseline

# External holdout (dvwa, juice-shop, nodegoat, pygoat, railsgoat — never SARD-tuned).
node ../bench/sard/scripts/holdout-check.mjs --update-baseline
```

Run `holdout-check.mjs --check-baseline` after any SARD-driven engine change (a new catalog.js
source/sink informed by a SARD false negative, a detector tweak) to confirm it generalizes rather
than only moving the SARD number. Note: all 5 current holdout apps carry `requiresReAudit:true`
(curated fixtures, per `bench/README.md`'s own caveat), so today this gate is informational —
it has no real enforcement teeth until at least one holdout corpus has an external sign-off.
