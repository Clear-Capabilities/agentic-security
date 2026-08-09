# Recall & F1 Improvement Plan

**Status:** proposed · **Created:** 2026-08-09 · **Engine version:** 0.134.0
**Baseline:** recall **32.5%** (13/40), precision **50.0%** (13/26), F1 **0.394**
measured on `bench/independent/` with package-scope context.

> Every priority below comes from the per-CWE breakdown of a real, third-party
> labelled population — not from intuition about what a scanner "should" catch.
> That distinction is the whole reason Phase 1 was built before this plan.

---

## 1. What the data actually says

Per-CWE recall, n=40, package-scope materialisation:

| CWE | Class | n | Recall | Read |
|---|---|---|---|---|
| **CWE-22** | Path traversal | 3 | **3/3** | ✅ solved |
| **CWE-79** | XSS | 3 | **3/3** | ✅ solved |
| CWE-20 | Improper input validation | 1 | 1/1 | ✅ |
| CWE-1333 | ReDoS | 1 | 1/1 | ✅ |
| CWE-639 / 863 | Authorization | 2 | 2/2 | ✅ |
| **CWE-94** | **Code injection** | **6** | **0/6** | ❌ **biggest single gap** |
| **CWE-184** | Incomplete denylist | 3 | 0/3 | ❌ |
| CWE-918 | SSRF | 3 | 1/3 | ◐ partial |
| CWE-200 | Info exposure | 3 | 1/3 | ◐ partial |
| CWE-862 | Missing authorization | 2 | 1/2 | ◐ |
| 15 others | assorted | 1 each | 2/15 | long tail |

Three conclusions the numbers force:

**The core injection families are not the problem.** Path traversal and XSS are
at 100%. The engine does what it claims on the classes it targets. Any plan that
starts by "improving the taint engine" is starting in the wrong place.

**One class dominates the loss.** CWE-94 is 6 of 27 misses — 22% of all failures
in a single weakness class, and the largest bucket in the population.

**The long tail is a different problem in disguise.** Fifteen CWEs appear once
each and score 2/15 between them. These are authorization, logic and
protocol-semantics classes. No sink pattern finds them, which is precisely what
the discovery layer exists for — so the fix is not a detector, it is finishing
D3.

---

## 2. R-1 — Close CWE-94 (0/6) · **P0, highest ROI in the document**

### The finding, made concrete

The missed sink in `GHSA-3769-jgqc-cxm7` is:

```js
const response = await vm.run(`module.exports = async function() {${code}}()`, __dirname)
```

That is the **NodeVM / vm2 sandbox family**, not `eval` or `new Function`. The
detector models the JS built-ins and misses a library whose entire purpose is
executing supplied code. Three of the six misses are this shape; the other three
are Python code-generation paths in a different project.

### Work

- **R-1a.** Add the sandbox-VM sink family to `sast/` and the dataflow catalog:
  `vm.run`, `NodeVM#run`, `VM#run`, `vm2` entry points, and the
  `runInNewContext` / `runInThisContext` variants not already present. Audit
  what IS covered first — the last three capability claims in this project's
  planning were wrong because nobody checked the tree.
- **R-1b.** Investigate the three Python CWE-94 entries
  (`datamodel-code-generator`, a code generator, so the sink is likely a
  template or `exec`/`compile` path). Expect a different root cause from the JS
  ones; do not assume one fix covers both.
- **R-1c.** A `vulnerable/` + `clean/` fixture pair per new sink, per
  `scanner/src/sast/CLAUDE.md`, and corpus entries once the detector exists —
  **detector first, then corpus entries**, per the same-commit-coupling rule in
  `scripts/corpus-provenance-check.mjs`.

**Target:** CWE-94 from 0/6 to ≥4/6. That alone moves overall recall from 32.5%
to roughly 42%.

---

## 3. R-2 — Partial classes: CWE-918, CWE-200, CWE-184 · P1

Nine entries, currently 2/9. These are *partially* covered, which usually means
a missing source or sink variant rather than an absent capability.

- **CWE-918 (1/3)** — SSRF is a family the engine targets. Two misses suggest
  either an unmodelled HTTP client or a source the taint engine does not treat
  as attacker-controlled. Diff the miss against the hit.
- **CWE-200 (1/3)** — information exposure is broad; expect that some entries
  are genuinely out of scope for static analysis (a log line leaking a token in
  a code path with no taint relationship). Classify before building.
- **CWE-184 (0/3)** — incomplete denylist. This is a *reasoning* class: the code
  has a filter and the filter is insufficient. A pattern matcher cannot judge
  sufficiency. Route to the discovery layer rather than to a detector.

**Method for all three:** for each miss, open the entry's `pre/` tree, find the
sink by hand, and record whether the cause is (a) an unmodelled sink, (b) an
unmodelled source, (c) a path the taint engine drops, or (d) genuinely
out-of-scope. **Do not write code before that classification exists** — three of
the four causes have different fixes, and one has no fix at all.

---

## 4. R-3 — The long tail needs the discovery layer, not detectors · P1

Fifteen CWEs at n=1, scoring 2/15: authorization gaps, missing origin
validation, observable discrepancy, session fixation, cache leakage. These share
a property — the bug is *semantic*, not syntactic. There is no sink to match.

This is exactly what `scanner/src/discovery/` was built for, and the engine's
own architecture already routes such candidates through deterministic
confirmation so the model cannot invent them unchecked.

**The blocker is not capability, it is configuration.** D3's uplift harness
exists (`confirm: false`) and has never been run, because no LLM endpoint is
configured. Provisioning one is the single highest-leverage action for this
class, and it produces the number no competing harness can compute.

**Do not** attempt to pattern-match these classes. A detector for "missing
authorization" that works by regex is how a scanner earns a reputation for
noise.

---

## 5. R-4 — Precision: classify the 13 FPs before improving them · P1

Precision is 50.0% (13/26). **Do not treat that as 13 bugs.** With
package-scope materialisation, an unrelated instance of the same CWE elsewhere
in the package counts as a false positive against this advisory's label. Some
fraction of the 13 are real findings that simply are not *this* advisory's bug.

**Work, in order:**

1. Hand-classify all 13 into: (a) genuine false positive, (b) real finding,
   wrong advisory, (c) incomplete upstream fix — the finding is correct and
   `post/` is still vulnerable.
2. Only (a) is a precision defect. Fix those.
3. For (b), improve the *measurement*: match on the advisory's changed files
   rather than the whole scope, so an unrelated instance stops being scored
   against the label. That is a benchmark fix, not a detector fix, and it will
   raise precision without changing engine behaviour — which is exactly why it
   must be labelled as such in `SCORECARD.md`.

The failure mode to avoid: tuning detectors to raise a precision number whose
denominator is partly a measurement artefact. That is fitting to the benchmark,
and this project has a provenance check specifically because it has been done
here before.

---

## 6. R-5 — Scale and stabilise the measurement · P1

- **Materialise the 110-entry population.** 70 entries are mined but not
  materialised, so they currently report UNSCORED. Roughly 20 minutes to
  materialise, 30+ to score.
- **Report per-CWE with denominators in `SCORECARD.md`,** not just the headline.
  A 32.5% aggregate hides that two families are at 100% and one is at 0%, and
  the aggregate is the least actionable number in the table.
- **Watch the ecosystem mix.** The population is now 57 Python, 35 TypeScript,
  18 JavaScript across 30 repositories. Recall must be reported per language:
  the earlier JS/TS-only sample would have hidden any Python-specific weakness
  entirely.

---

## 7. Sequencing, and the expected arithmetic

```
R-1 (CWE-94)  ──> biggest single recall gain, self-contained
R-4 (classify FPs) ──> must precede any precision work
R-5 (scale)   ──> makes every subsequent number trustworthy
R-2 (partials) ──> after per-miss classification
R-3 (long tail) ──> blocked on an LLM endpoint (D3)
```

| Step | Recall | Basis |
|---|---|---|
| today | 32.5% (13/40) | measured |
| + R-1 at 4/6 | ~42% | arithmetic on the same population |
| + R-2 at 5/9 | ~50% | arithmetic |
| + R-3 | unknown | needs D3 to measure at all |

**These are projections on a 40-entry population and must be re-measured on the
110, not carried forward as claims.** The projection is a planning aid; the only
number that goes in `SCORECARD.md` is one that was measured.

## 8. What would make this plan wrong

- If the 13 FPs are mostly category (b), precision is already better than 50%
  and R-4 is a documentation change rather than engineering.
- If the Python CWE-94 misses share no root cause with the JS ones, R-1 is two
  pieces of work and only half the projected gain lands at once.
- If a class currently at 100% regresses when new sinks are added, the corpus
  gate catches it — which is the one part of this that is already safe.
