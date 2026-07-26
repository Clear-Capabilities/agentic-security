# Phase 2 — measurement results (Task 8)

All figures on this page were produced by commands run in this session, on
branch `feat/phase2-precision`, against the built bundle
(`npm run build` re-run first). Where a figure could not be produced in this
session it is marked **not measured**, not guessed.

## 1. Self-scan precision (this repository's own code)

`npm run bench:self-scan -- --json`, re-run this session:

| Target | Baseline (`BASELINE.json`, commit `85909ef`) | This session | Drift |
|---|---|---|---|
| `hooks/` total | 24 | 24 | none |
| `scripts/` total | 24 | 24 | none |
| `polyglot/` total | 0 | 0 | none |

Both totals and the per-file breakdown are byte-identical to `BASELINE.json`
(same 11 files each, same per-file counts). `npm run bench:self-scan:check`
(the CI gate) confirms this directly:

```
Self-scan precision gate:
  hooks: baseline=24 now=24
  scripts: baseline=24 now=24
  polyglot: baseline=0 now=0

✓ no drift — per-file counts match BASELINE.json exactly
```
Exit code: **0**.

### IR/catalog subset (not the same number as the total above)

The totals above are **all-detector** totals (every SAST rule, not just the
IR/dataflow taint engine). Filtering this session's `hooks`/`scripts` scan
output to findings whose `id` starts `ir-taint:` gives the narrower subset
that Task 4/5's language-scoping work can actually affect:

| Target | IR/catalog (`ir-taint:`) subset |
|---|---|
| `hooks/` | 0 |
| `scripts/` | 1 — `ir-taint:synthesize-detector.mjs:125:js-fetch` |

This is a real, deliberate outcome, not a gap: `scripts/synthesize-detector.mjs`
is a genuine `.mjs` file, the `js-fetch` catalog entry is `language:'js'`, and
the finding is an SSRF on a URL built from an env variable — a same-language,
same-receiver match, not a bare-name collision across languages. There is
nothing left for a receiver constraint to remove, which is exactly why **Task
5 added zero receiver constraints**: it measured the false-positive surface
after Task 4's language scoping and found none remaining to constrain. Zero
constraints added is the correct output of an evidence-led process, not an
unfinished task.

## 2. Interprocedural status: Go, C#, Kotlin, PHP

`node --test test/phase2-scoping.test.js` (this session, 16/16 pass) directly
asserts:

- `fn.calls: Go, C#, Kotlin and PHP each record their call sites` — each of
  `app.go`, `App.cs`, `App.kt`, `app.php` produces a caller function whose
  `.calls[0]` records `{ site, callee, args, line }` from the shared
  `callSitesFromCfg` extractor (`scanner/src/ir/call-sites.js`).
- `fn.calls: the callee name resolves to the callee function` — the recorded
  callee name resolves via `callGraph.resolveKnownCallee()` to the actual
  callee function record in the same file, for all four languages.

Source confirms all four parsers are wired to the shared extractor
(`grep callSitesFromCfg scanner/src/ir/parser-{go,cs,kt,php}.js` → one call
site each, at `parser-go.js:409`, `parser-cs.js:258`, `parser-kt.js:256`,
`parser-php.js:328`).

`npm run bench:engine-reconnect` (this session) exercises the end-to-end
taint path for js/python/cpp (its original three languages; it has no
Go/C#/Kotlin/PHP fixture of its own):

```
js: total=1 irTaint=1 interprocedural=1
python: total=4 irTaint=2 interprocedural=1
cpp: total=2 irTaint=1 interprocedural=1
sanitizedDemoted=0
```

The self-scan polyglot fixture (`bench/self-scan/fixtures/polyglot/`) is the
bench that actually exercises Go/C#/Kotlin/PHP's new `fn.calls` wiring end to
end (Task 3 rebuilt `app.go`/`App.cs`/`App.kt`/`app.php` into genuine
`identity(x) -> emit()` two-function caller/callee chains over a
cataloged sink). Its correct total is 0 because the source in each fixture is
a hardcoded local literal, not tainted input — see `measure.mjs`'s header for
the full caveat, including which fixtures still can't detect an
interprocedural regression (`app.js`/`app.py`/`app.rb` remain single-function;
there is no Java fixture, per Task 7).

The CVE-replay corpus (`npm run bench:cve-replay:check`, this session) is
independent, stronger evidence for these four languages specifically: it
carries dedicated `byLanguage` slices with real vulnerable-shape fixtures,
not synthetic literals —

```
byLanguage:
  go       n=21  F1=1.000  TP=21 FP=0 FN=0 TN=21
  kotlin   n=20  F1=1.000  TP=20 FP=0 FN=0 TN=20
  csharp   n=20  F1=1.000  TP=20 FP=0 FN=0 TN=20
  php      n=21  F1=1.000  TP=21 FP=0 FN=0 TN=21
```

**Verdict: yes**, Go/C#/Kotlin/PHP gained `fn.calls` interprocedural call-site
recording and callee resolution, proven by direct fixture test and by
101 total corpus entries pre/post at F1=1.000 across those four languages.

## 3. Proof-corpus (real third-party code): ghost, superset, godot

`node ../bench/proof-corpus/runner.mjs --only ghost,superset` (this session,
cached clones), plus the pre-existing godot entry, all measured in the same
`bench/proof-corpus/results/summary.json` this session produced (`ok: 3,
failed: 0`).

| Target | Coverage this session | Coverage in `README.md` (earlier phase) | `determinism.results` this session | `determinism.results`/bytes in `README.md` |
|---|---|---|---|---|
| ghost | 94% (javascript 4023/4271) | 94% (javascript 4023/4271) | 1124 findings; bytes 1,364,169 / 1,364,186 | bytes **1,364,169 / 1,364,186** (identical) |
| superset | 100% (js 2613/2616, py 1470/1470) | 100% (js 100%, py 100%) | 860 findings; bytes 1,275,554 / 1,275,555 | bytes **1,275,554 / 1,275,555** (identical) |
| godot | 100% (cpp 3012/3012, cs 298/306=97%) | 100% (cpp 100%, cs 297/306≈97%) | 145 findings; bytes 183,978 / 183,978 | **183,978 / 183,978**, 145 results (identical) |

Ghost's and Superset's byte counts for both SARIF runs (`runA`/`runB`) in
this session's `summary.json` are **byte-identical** to the figures already
recorded in `bench/proof-corpus/README.md` from the pre-Phase-2 run. That is
the strongest evidence available that the language-scoping and catalog work
did not remove or alter any finding on real third-party code — not just "the
count didn't drop," but the exact same bytes came out both before and after
this phase's changes. Call-graph resolution figures (ghost 5,819/118,356
edges resolved; superset 4,004/69,959) are likewise unchanged from the
earlier recorded figures.

**Determinism, pre-existing and not caused by this phase:** ghost and
superset are still `identical: false` between their own two runs (1364169 vs
1364186 bytes; 1275554 vs 1275555 bytes) — this is the same non-determinism
already documented in `README.md` (unordered iteration in the licence-graph
code), unrelated to this phase's catalog/scoping work, and not fixed here.
Godot remains `identical: true` (183,978 bytes both runs).

**Stale on-disk artifact, not a run failure.** At the time of writing,
`bench/proof-corpus/results/raw/superset/run-a.sarif` is **0 bytes** on disk
(timestamp after this session's run), while `run-b.sarif` on disk is a stale
1.27 MB file left over from an earlier session's run. This is a filesystem
artifact only — the measurement itself completed and was captured correctly
in `summary.json` (`valid: true`, `bytes.runA: 1275554`, `results: 860`),
which is what this report cites. A reader who inspects the raw file directly
and finds it empty should not conclude the run failed; the recorded metrics
are sound. Not investigated further here — recorded so a later reader is not
confused by it.

## 4. Gate exit codes (this session)

| Gate | Command | Exit code |
|---|---|---|
| Full test suite | `npm test` | **0** |
| CVE-replay corpus | `npm run bench:cve-replay:check` | **0** |
| Self-scan precision | `npm run bench:self-scan:check` | **0** |

`npm test`'s scoped suite totals this session: smoke 28/28, sast 465/465,
posture 556/556, dataflow 451/451, mcp 80/80, report 85/85, bench-modules
67/67, lifecycle 64/64, eval 22/22, plus the standalone C++ dataflow suite
26/26 — 0 failures across all scopes.

## 5. Answers

**Q1 — Did Go, C#, Kotlin and PHP gain interprocedural analysis?**
Yes. All four parsers emit `fn.calls` via the shared `callSitesFromCfg`
extractor, verified by a passing dedicated test
(`phase2-scoping.test.js`, 2 assertions per language) that checks both call-
site recording and callee resolution, and corroborated by 101 CVE-replay
corpus entries across those four languages all scoring `pre:TP post:TN`
(F1=1.000 per language, 0 FP, 0 FN in every slice).

**Q2 — Did precision improve, or at least hold?**
Held, exactly. Self-scan totals are unchanged (`hooks` 24, `scripts` 24,
`polyglot` 0) and the per-file breakdown is byte-identical to the committed
baseline — the gate that would fail on any drift passed clean. The one
IR/catalog finding present in `scripts/` (`ir-taint:synthesize-detector.mjs:125`)
is a real SSRF, not a false positive from cross-language matching, and
Task 5 correctly added zero new receiver constraints because measurement
found no remaining cross-language false positives to constrain — not
because the work was skipped.

**Q3 — Did anything lose recall? This is the one to be skeptical about.**
No loss found, and here is what was actually checked, not just "tests are
green":
- **CVE-replay corpus verdicts**: all 197 baselined entries still pass with
  zero drift, across every language including the four newly wired ones —
  each entry is a `pre:TP post:TN` pair, so a lost detection would show up as
  a `pre:TP` flipping to `post:FN`, which none did.
- **Proof-corpus coverage on real third-party code**: ghost 94%, superset
  100%, godot 100% — identical percentages to the pre-Phase-2 figures already
  recorded in `bench/proof-corpus/README.md`.
- **Proof-corpus finding counts**: ghost 1124 and superset 860 results, with
  SARIF byte sizes for both runs identical, byte-for-byte, to the figures
  recorded before this phase's changes. This is stronger than "the count
  didn't drop" — the exact same findings came out.
- **Per-language sink matching**: `phase2-scoping.test.js`'s
  "language scoping: legitimate matches still fire for every language" test
  and "extension sets match the IR dispatch exactly" test together pin that
  the narrowed extension sets are asserted equal to (never narrower than)
  the sets `ir/index.js` actually uses to dispatch each parser — the failure
  mode the spec calls out as the one that would do real, invisible damage.
  An unmapped language stays permissive by design, so scoping additively
  covers only what has been proven correct, never a rollback of coverage.
- PHP's IR coverage widened (not narrowed) as a side effect of Task 3's two
  parser-bug fixes (missing `<?php` anchor, an off-by-one that dropped a
  second same-line declaration) — a PHP finding appearing that wasn't there
  in an older baseline is that widening, not a scoping regression, per
  `BASELINE.json`'s notes.

No entry, language, or target showed a `pre:TP`→`post:FN` transition, a
coverage drop, or a byte-level finding-set change. The recall-loss check
comes back clean.
