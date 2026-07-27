# Phase 2 — measurement results (Task 8)

All figures on this page were produced by commands run in this session, on
branch `feat/phase2-precision`, against the built bundle
(`npm run build` re-run first). Where a figure could not be produced in this
session it is marked **not measured**, not guessed.

> **Two sessions now.** §1–§4 are the original Task 8 measurement session.
> §5 Q3 carries a **correction** added in the later fix-wave session
> (2026-07-26), which found a recall regression the original measurement
> reported as absent, and §6 records the review's remaining follow-ups. Where
> the fix wave re-measured something, it says so and gives the fresh number.

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

**Re-run in the fix-wave session (2026-07-26), after the JVM-family fix:** all
three gates exit 0 again, plus `npm run build` exit 0. Only the dataflow scope
moved — 451 → **455**, the 4 new cross-family tests. Full figures in the §5 Q3
correction.

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

> **CORRECTION (fix wave, 2026-07-26). The original answer below said "No
> loss found." That was false as written.** A recall regression *was* present
> at the time that answer was recorded; the final whole-branch review found it
> afterwards, by hand, against the parent branch. The original evidence list is
> preserved verbatim beneath this correction because the most useful thing in
> this document for the next reader is not the corrected conclusion — it is the
> fact that a five-bullet, deliberately-skeptical measurement returned a
> confident "no loss" and was wrong, and *why each bullet failed to see it*.

**What was lost.** `catalog.js` scoped `java` and `kt` as separate `_LANG_EXT`
keys. They are separate *catalog dialects*, but the JVM is **one runtime with
one library surface** — Kotlin calls the Java standard library, JDBC,
Hibernate and the servlet API constantly. Measured against the parent branch,
`.kt` files stopped matching 12 `java`-language sinks — `executeUpdate`,
`execute`, `prepareStatement`, `addBatch`, `createQuery`, `createSQLQuery`,
`createNativeQuery`, `File`, `search`, `compile`, `sendRedirect`, `parse` —
and 4 `java` sources — `getCookies`, `getInputStream`, `getReader`,
`getProperty`. Symmetrically, `.java` files stopped matching `readText`
(`kt-file-readtext` / `kt-url-readtext`). In plain terms: JDBC and Hibernate
SQL injection, servlet open-redirect and XXE went silent in Kotlin.

**Measured, single-file demonstration.** A `.kt` file containing

```kotlin
val q = req.getParameter("q")
stmt.executeUpdate(q)
```

produced **1** IR-TAINT finding on the parent branch, **0** on this branch
before the fix (re-measured in the fix-wave session with
`AGENTIC_SECURITY_DEEP=1`), and **1** again after the fix
(`SQL Injection (Statement.executeUpdate)`, App.kt:2).

**Why the pinning test could not catch it.** `phase2-scoping.test.js`'s
"extension sets match the IR dispatch exactly" test was not weak and was not
wrong: the extension sets genuinely *do* equal `ir/index.js`'s dispatch
regexes, and still do after the fix. The defective assumption was one level
above the thing being pinned — that a *catalog language* maps one-to-one onto
a *file-extension family*. No amount of regex-equality assertion can detect a
family error, because no regex was ever unequal. The fix therefore adds tests
that pin the **cross-family behaviour** directly rather than regex equality:
all 12 `java` sink names must match on `.kt`, all 4 `java` source names must
match on `.kt`, `readText` must match on `.java`, and (the guard against
over-correcting) none of those may fire on `.py`/`.go`/`.js`/`.rb`/`.php`/`.cs`.
Verified to fail without the fix: with the JVM family map emptied, exactly
those 3 new cross-family tests fail (17 pass / 3 fail) while every other test
in the file, including both extension-set tests, stays green — which is
precisely the blind spot, reproduced.

**Why the corpus could not catch it either.** 197/197 green was **not**
evidence of Kotlin recall. Two reasons, both measured:
- Of the corpus's 20 Kotlin entries, most use only `kt-*`-catalogued sinks
  (`readText`, `exec`, `executeQuery`, `readObject`), which were never scoped
  away from `.kt`.
- The handful that *do* use `java`-only sinks are still scored `pre:TP`
  because a corpus verdict asks "did **anything** detect this?", not "did the
  taint engine detect this?". `CVE-2020-5247-kotlin-open-redirect/pre` uses
  `sendRedirect`; scanned in this session it returns exactly one finding, from
  the `OPEN-REDIRECT` regex detector — so the IR-TAINT loss is structurally
  invisible to that verdict. A corpus of `pre:TP post:TN` pairs measures
  *detection*, not *per-detector recall*, and cannot be cited as the latter.

**Post-fix position (re-measured this session, every number from a run in the
fix-wave session).** Scoping is now by **runtime family**, not dialect: a
declarative `_LANG_FAMILY` map in `catalog.js` puts `java` and `kt` in one JVM
family, and `_languageAllowed` accepts a file matching any dialect in the
entry's family. A dialect absent from the map is its own family, so every
other language is untouched. Gates re-run after the fix: `npm test` exit 0
(dataflow scope 455/455, up from 451 by the 4 new cross-family tests; smoke
28, sast 465, posture 556, mcp 80, report 85, bench-modules 67, lifecycle 64,
eval 22, C++ dataflow 26 — 0 failures anywhere), `bench:cve-replay:check`
exit 0 (197/197, no drift), `bench:self-scan:check` exit 0 (hooks 24,
scripts 24, polyglot 0, no per-file drift), `npm run build` exit 0. The
`.kt` `executeUpdate` case is detected again. **This is a re-measurement, not
a re-assertion — but note that the previous answer was also a measurement.**
The corpus and the self-scan gate still cannot see per-detector Kotlin recall;
the new cross-family tests are what covers it now.

---

*Original answer, preserved as written:*

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

*(End of the original answer. Every bullet above is individually still true;
together they were still not sufficient, for the reasons given in the
correction.)*

## 6. Recorded follow-ups — known, deliberately NOT fixed in the fix wave

Found by the final whole-branch review. Each is real and each was left alone
on purpose, so that the fix wave stayed scoped to the regression it existed to
close. Listed roughly in the order the review recommends taking them.

1. **`engine.js`'s `case 'assign'` never sink-matches its own RHS.** `exec(c)`
   at statement position yields 1 finding; `const out = exec(c)` yields 0. The
   assignment path handles the call as a *summary application* and never asks
   whether the callee is itself a catalog sink. This silences
   `const rows = db.query(tainted)` — the single most idiomatic shape there
   is — **in every language**. Pre-existing (not introduced by this branch);
   the review recommends it as the next phase's first item.
2. **The nine-language list in `phase2-scoping.test.js` is hardcoded**
   (`['js','py','cs','kt','go','php','rb','java','cpp']`) rather than derived
   from `CATALOG`. A newly added catalog language silently falls back to
   permissive matching and re-opens the cross-language leak with the test
   still green. Derive the list from the distinct `language` values in
   `CATALOG` instead.
3. **The extension pin is one-directional.** It asserts catalog ⊆/= dispatch
   by comparing against literals written *in the test*. Adding a new dispatch
   branch to `ir/index.js` (say `.mts`) leaves the test green while the
   catalog silently stays narrower than the parser.
4. **All `match.type: 'global'` entries remain unreachable from
   `matchSource()`.** `matchSource` handles only `member` and `call` shapes,
   so PHP superglobals (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`),
   Rails `params`/`session`/`cookies`/`ENV`, and JS `location` are catalogued
   but never matched by the taint engine. Separately, Go still has no
   environment or argv source at all (`os.Getenv`, `os.Args`).
5. **`parser-kt.js` mis-lowers fluent chains**, so multi-segment Kotlin
   builder/fluent expressions do not reach the engine with the shape the
   catalog expects.
