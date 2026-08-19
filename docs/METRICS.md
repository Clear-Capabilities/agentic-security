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

**As of the docs-overhaul-era measurement work, the printed matrix and
`docs/SCORECARD.md`'s "Taint-layer recall by language" section both report
two views, not one.** The whole-corpus view below is diluted: the large
majority of this corpus is caught by the pattern/structural layers without
needing taint at all (reproduce with `npm run bench:layer-recall`), so a
near-zero rate for a language here does not by itself mean the taint
engine cannot see that language. The **deep-tier-only** breakout — printed
as a second table by the same command, and as its own section in the
scorecard — is scoped to entries that are *required*, before they can be
committed, to be provably invisible with the deep engine off and detected
with it on. That is the number to quote for taint capability; the
whole-corpus number below is diagnostic context, not the claim.

Deep mode is **forced on for every entry**, unlike the corpus gate, which
enables it only for the 6 `deep`-tier entries. Measuring under the corpus's own
configuration would report the tier layout rather than the engine's capability,
so every entry here gets the maximal chance to be caught by taint. A zero
therefore means the taint engine cannot see the entry — not that it was never
asked. Scoring reuses `corpus-match.js`'s predicate, the same one the gate and
corpus enrolment use.

### Headline number — dataflow-shaped-subset recall (`docs/TAINT_RECALL_80PCT_PRD.md`)

Whole-corpus recall (below) is diluted by families no source→sink walker
could ever catch (hardcoded secrets, weak RNG, timing side-channels, IaC
misconfig, …). The PRD fixed the denominator to just the families a taint
engine can plausibly reach — sqli, xss, cmdi, path-traversal, xxe, ldap,
ssrf, deserialization, open-redirect, response-splitting, xpath,
code-injection, ssti, prototype-pollution (`manifest.family`-based, not a
directory-name heuristic) — and set an 80% target against that subset.

**Result: 115/137 (83.9%)**, `AGENTIC_SECURITY_BLIND_BENCH=1` forced —
target met. (The subset denominator grew from the PRD's original 134 to
137 as genuinely dataflow-shaped entries were enrolled during the PRD's own
work, e.g. `kt-trailing-lambda-pathtraversal-shape`.) By family: code-injection
6/6, ldap-injection 10/10, path-traversal 15/15, response-splitting 8/8,
ssrf 10/10, xpath-injection 8/8, xss 11/11, xxe 10/10, command-injection
18/23, deserialization 5/7, sql-injection 9/13, ssti 1/2, open-redirect 4/8,
insecure-deserialization 0/3, prototype-pollution 0/3.

Per the PRD's §4 Tier 5 gate ("only if Tiers 1–4 fall short of 80%"), Tier 5
(genuine engine depth — container/collection-element taint, k>1 call-string
context, stored/second-order taint) was **not scoped** — the target was met
without it.

> **Update 2026-08-19.** Container/collection-element taint has since landed
> anyway (PRD T3.3; see `scanner/src/dataflow/CLAUDE.md`), and this subset
> figure is **unchanged at 115/137** as a result. That is the expected outcome,
> not a disappointment: the corpus contains no container-shaped entries, which
> is precisely why the target was reachable without Tier 5 in the first place.
> The capability is pinned by `test/container-taint.test.js` rather than by this
> number, and must not be quoted as a recall gain. The remaining 22 misses (deserialization/insecure-deserialization,
open-redirect, sql-injection, ssti, prototype-pollution, and 4 C/C++
command-injection shapes) are documented as candidate future work, not a
blocker.

### Result — 215 entries, engine v0.137.1 (measured 2026-08-19)

| language | entries | detected (any layer) | **detected by IR-TAINT** |
|---|---:|---:|---:|
| c# | 21 | 21 (100%) | 12 (57%) |
| c/c++ | 11 | 11 (100%) | 2 (18%) |
| go | 22 | 22 (100%) | 13 (59%) |
| java | 25 | 25 (100%) | 13 (52%) |
| js/ts | 38 | 38 (100%) | 22 (58%) |
| kotlin | 21 | 21 (100%) | 10 (48%) |
| php | 23 | 23 (100%) | 12 (52%) |
| python | 32 | 32 (100%) | 21 (66%) |
| ruby | 20 | 20 (100%) | 11 (55%) |
| json | 1 | 1 (100%) | 0 (0%) |
| terraform | 1 | 1 (100%) | 0 (0%) |
| **total** | **215** | **215 (100%)** | **116 (54%)** |

**java**, **ruby** and **c#** were all **0 (0%)** on the first run of this
instrument. None was a taint-engine limitation: all three were defects upstream
of it, in the IR — a sync/async mismatch, a regex that crossed a newline, and a
stack overflow. See items 2–4 below.

#### Superseded: the v0.136.3 measurement this table replaced

The previous table recorded **23/210 (11%)** with kotlin at **0 (0%)**, c# 1
(5%), java 1 (4%), php 1 (4%), ruby 1 (5%). It is kept here as the prior
data point rather than deleted, because the delta is the interesting part:
taint-layer attribution rose ~5×, and the "one language still at zero" claim
that framed this whole section is no longer true.

**How it went stale without anyone noticing** is worth recording, because it is
a gate-design lesson rather than an oversight. `npm run bench:layer-recall:check`
compares against `baseline.json` as a **floor** — it fails on a *drop* in
per-language taint counts and says nothing about a rise. So the engine improving
from 31 to 116 attributed entries passed the gate silently, exactly as a
no-change run would, and the published table kept its old numbers. A floor-only
gate cannot tell "unchanged" from "much better", which is precisely the
condition under which a baseline rots.

### What this says

1. **Every first-class language now has non-zero taint-layer recall.** Kotlin
   was the last at zero and is now 10/21 (48%). It was never a defect even then:
   Kotlin IR and assignment lowering both worked, and a servlet-source →
   `executeUpdate` flow produced an IR-TAINT finding
   (`test/kt-taint-flow.test.js`); its corpus entries simply were not
   taint-shaped. The three languages that *were* at zero (java, ruby, c#) each
   had a different upstream defect, and **none** of them was "missing framework
   sources" — the hypothesis this instrument was built to test. The two
   remaining zeros, `json` and `terraform`, are correct: neither is code the
   taint engine can walk.

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
