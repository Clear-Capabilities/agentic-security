# Engine metrics

Measured numbers, each with the command that produced it. A figure without a
reproduction command does not belong in this file.

---

## Per-layer recall (D1)

**What it answers.** The CVE-replay gate asks *"was this vulnerability
detected?"*. It never asks *"by which analysis layer?"* — and the two answers
diverge sharply enough to change the roadmap.

```bash
cd scanner && npm run bench:layer-recall          # print the matrix
cd scanner && npm run bench:layer-recall:check    # gate against baseline.json
```

Deep mode is **forced on for every entry**, unlike the corpus gate, which
enables it only for the 6 `deep`-tier entries. Measuring under the corpus's own
configuration would report the tier layout rather than the engine's capability,
so every entry here gets the maximal chance to be caught by taint. A zero
therefore means the taint engine cannot see the entry — not that it was never
asked. Scoring reuses `corpus-match.js`'s predicate, the same one the gate and
corpus enrolment use.

### Result — 210 entries, engine v0.136.3

| language | entries | detected (any layer) | **detected by IR-TAINT** |
|---|---:|---:|---:|
| c# | 21 | 21 (100%) | 1 (5%) |
| c/c++ | 11 | 11 (100%) | 2 (18%) |
| go | 22 | 22 (100%) | 3 (14%) |
| java | 25 | 25 (100%) | 1 (4%) |
| js/ts | 36 | 36 (100%) | 7 (19%) |
| kotlin | 20 | 20 (100%) | **0 (0%)** |
| php | 23 | 23 (100%) | 1 (4%) |
| python | 32 | 32 (100%) | 7 (22%) |
| ruby | 20 | 20 (100%) | 1 (5%) |
| **total** | **210** | **210 (100%)** | **23 (11%)** |

**java**, **ruby** and **c#** were all **0 (0%)** on the first run of this
instrument. None was a taint-engine limitation: all three were defects upstream
of it, in the IR — a sync/async mismatch, a regex that crossed a newline, and a
stack overflow. See items 2–4 below.

### What this says

1. **One of nine first-class languages still has zero taint-layer recall** —
   kotlin — and it is **not** a defect. Kotlin IR and assignment lowering both
   work, and a servlet-source → `executeUpdate` flow does produce an IR-TAINT
   finding (`test/kt-taint-flow.test.js`); its 20 corpus entries are simply not
   taint-shaped. The three languages that *were* at zero (java, ruby, c#) each
   had a different upstream defect, and **none** of them was "missing framework
   sources" — the hypothesis this instrument was built to test.

2. **Java's zero was three stacked defects, now fixed** (0 → 1). The deep path
   called the **sync** `buildProjectIR`, which has no Java branch at all because
   `parseJavaFile` is async — so no `.java` file had ever produced an IR function
   in deep mode, and `buildProjectIRAsync` had zero callers anywhere. Wiring it
   in exposed two more: the CST walker looked for `blockStatement` on a `block`
   node when java-parser nests `block → blockStatements → blockStatement`, so
   every method body lowered to an empty CFG; and `exprFromCst` had no case for
   `primary → primaryPrefix + primarySuffix`, which is how java-parser models
   **every** method call, so `req.getParameter("q")` lowered to a member access
   rather than a call and no Java source or sink could ever match. The Java
   catalog's 7 sources and 15 sinks had never had valid IR to run against.

3. **C#'s zero was a parser crash, now fixed** (0 → 1). `_lowerExpr` had no
   branch for `new Type(...)`, so `new SqlCommand("q" + name, conn)` fell through
   to the string-concat heuristic; the `+` sits inside the parens, so
   `_splitTopLevelPlus` returned the input unchanged and the branch recursed on
   the identical string until the stack overflowed. `buildProjectIR` catches
   per-file, so a hard crash surfaced only as "this file has no IR". It hit **12
   of 21** C# corpus entries — and the catalog already shipped a rule for exactly
   that shape (`cs-sqlcommand`, *"SQL Injection (new SqlCommand with concatenated
   user input)"*) which could never fire. Crashes are now **0**; 11 entries still
   produce no functions for unrelated reasons (method forms the parser does not
   recognise), which is a separate, smaller diagnosis.

4. **Ruby's zero was a parser bug, now fixed.** `DEF_RE`'s `\s*` before the
   optional parameter list matched across the newline, so the computed body
   start landed after the first statement — **every Ruby method silently lost
   its first body statement**, and a single-statement body became empty. In a
   Rails controller that first statement is almost always the `params` read,
   i.e. the taint source. The fixture recorded in `bench/engine-recall/RESULTS.md`
   as producing zero IR-TAINT findings (`params[:c]` → `system(c)`) now produces
   `Command Injection (Kernel.system)`. Corpus taint recall moved 0 → 1; the
   real-world effect is larger than the corpus shows, because the dropped
   statement affected every consumer of the Ruby CFG, not only taint.
5. **The corpus barely exercises the taint engine.** Re-running with the deep
   engine disabled, detection falls only from 210 to **204** — so 204 of 210
   entries would still pass with taint switched off entirely. The corpus is
   overwhelmingly a test of the pattern and structural layers, which is why
   defects of this size survived in it for so long.
6. `bench/engine-recall/RESULTS.md` had already recorded the Ruby case
   (`params[:c]` → `system(c)` producing zero IR-TAINT findings, detected only
   by regex) and stated that end-to-end taint recall was proven only for PHP.
   This instrument generalised that single observation into a per-language
   number, which is what made the Java and Ruby defects findable.

### How the gate behaves

`--check` compares per-language taint counts against
`bench/layer-recall/baseline.json` and fails on any decrease. Both directions
were verified on the run that produced this file:

| experiment | expected | observed |
|---|---|---|
| unchanged engine | pass | **exit 0** |
| baseline claims recall we lack (`python: 99`) | fail | **exit 1** — `python: taint recall 99 → 7` |
| deep engine disabled | fail | **exit 1** — taint 20 → **0 (0%)** |

The middle row matters: a gate that only ever passes proves nothing about the
thing it claims to protect.

### Reading it honestly

- Taint recall is computed over **all** entries for a language, not over the
  detected ones. Dividing by detected would report 100% for a language where
  taint fired once and regex carried the rest.
- A finding with no `parser` is counted as `(unattributed)`, never dropped —
  dropping it would shrink a denominator and flatter the result.
- An entry whose scan throws is **unscored**, not counted as a taint miss.
- The printed table folds low-volume detector labels into `other` and says how
  many it folded; nothing is silently truncated.
- This measures the corpus, which is a curated fixture set. It is a **lower
  bound on the gap**, not an estimate of field recall — the fixtures are small
  and single-purpose, which flatters every layer including taint.

---

## Related instruments

| Command | Measures |
|---|---|
| `npm run bench:cve-replay:check` | Detection per corpus entry (any layer), baseline-gated |
| `npm run bench:layer-recall:check` | **Which layer** detected it, per language |
| `npm run bench:mutation:check` | Verdict-flip correctness under metamorphic + adversarial rewrites |
| `npm run bench:self-scan:check` | Per-file finding counts on this repository (precision drift) |
