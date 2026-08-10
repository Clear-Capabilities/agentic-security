# Design — Phase 2: precision, and finishing the language rollout

**Status:** Proposed.
**Date:** 2026-07-26
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** The taint catalog's matching layer (`scanner/src/dataflow/catalog.js`), `fn.calls` emission across the remaining IR parsers (`scanner/src/ir/parser-*.js`), and the Java IR frontend.
**Audience:** Engineering (scanner core).
**Predecessor:** `docs/superpowers/specs/2026-07-25-detection-remediation-effectiveness-design.md` (Phase 1 — reconnect the engine).

---

## 1. Where Phase 1 left things

Phase 1 established that the scanner's interprocedural taint analysis produced **zero findings in every language**, fixed four defects, and demonstrated a working cross-function flow in JavaScript, Python and C++. `bench/engine-reconnect/RESULTS.md` records the before/after.

That result is narrower than it sounds, and this document exists because of what re-measuring revealed.

**Only 4 of 9 parsers emit `fn.calls`** — the per-function record of call sites that `dataflow/tabulation.js`, `dataflow/index.js` and `ir/callgraph.js` all read. Verified at runtime on 2026-07-26:

| Emit `fn.calls` | Do not |
|---|---|
| JavaScript, Python, Ruby, C++ | **Java, Go, C#, Kotlin, PHP** |

So five languages still have no interprocedural analysis at all. Phase 1 unlocked the machinery; it did not finish the rollout.

**And precision has not kept pace with recall.** `_languageAllowed` (`catalog.js:772-777`) scopes exactly two languages:

```js
if (entry.language === 'cpp') return cppExtRe().test(file);
if (entry.language === 'js')  return _JS_EXT_RE.test(file);
return true;                      // ← everything else matches everywhere
```

Meanwhile **120 of 121 call-sinks match on a bare callee name with no receiver constraint**, distributed Python 38, Java 15, JS 14, Go 12, PHP 10, C++ 9, C# 9, Ruby 7, Kotlin 6. The generic names in that set include `query`, `execute` (×3), `load` (×4), `run`, `get`, `post`, `open` and `call`.

Phase 1 already demonstrated what this costs in practice: a `language: 'js'` DOM rule fired on Python files, producing six false high-severity findings on this repository's own code. Two entries were narrowed; the other 118 were left, and every language whose `fn.calls` we add makes more of them reachable.

## 2. The finding that reshapes this phase

The original plan for Phase 2 was "add `fn.calls` to five more parsers." For four of them that is accurate and mechanical. **For Java it is not, because the Java IR frontend is a stub.**

Verified at runtime against a conventional Java class:

```
{"name":"T.helper","qid":"T.java::T::helper","line":0,"params":[],"nodes":["jn1","jn2"]}
{"name":"T.main2", "qid":"T.java::T::main2", "line":0,"params":[],"nodes":["jn3","jn4"]}
```

Four separate problems, each independently disabling:

| Observed | Consequence |
|---|---|
| CFG contains only `entry` and `exit` | No statements are lowered, so there is nothing for taint to flow through. `buildCfgFromBody` *is* called (`parser-java.js:275`) but its CST navigation yields no statement nodes. |
| `params: []`, with the source comment `// params extraction deferred` (`parser-java.js:268`) | Formal parameters can never bind to actual arguments, so interprocedural taint is impossible even with a populated CFG. |
| `line: 0` on every function | Every Java finding would be attributed to line 0. |
| `qid` is `file::Class::name`, omitting the `@line#sha` suffix every other parser emits | Breaks the shape `class-hierarchy.js` and the `stableId` machinery expect. |

**Java is not a language missing one field. It is a language whose IR frontend was never finished.** That matters beyond the code, because the Proof Corpus PRD §2.3 (removed post-implementation) lists Java in the **Deep IR** tier — "first-class parser + proven interprocedural taint" — alongside JavaScript and Python. That claim is false and has been for as long as the tier table has existed. Phase 1's own goal statement (G1) named Java as one of three languages that would produce interprocedural findings; it was never capable of it and was never measured.

Correcting that claim is part of this phase's deliverable, whether or not the Java work itself lands here.

## 3. Goals and non-goals

### Goals

- **G1 — Precision keeps pace with recall.** Catalog entries stop firing on languages and receivers they do not belong to, measured on this repository's own code and on the proof-corpus targets.
- **G2 — Interprocedural analysis reaches Go, C#, Kotlin and PHP**, taking the count from 4 languages to 8.
- **G3 — The Java claim is corrected**, and the work required to make it true is scoped honestly rather than asserted.
- **G4 — A precision regression fails the build**, rather than requiring a reviewer to notice it.

### Non-goals

- **Not new detector rules.** Same as Phase 1: reachability and precision are the constraints, not rule count.
- **Not the remediation test gate.** That is Phase 3 and is unaffected by this work.
- **Not rebuilding the Java frontend inside this phase's plan.** §5 explains why it is separated.
- **Not general k-CFA or field-sensitivity work.** Measuring propagation depth is proposed in §6 as a follow-on, not undertaken here.

## 4. Design

### 4.1 Generalise language scoping

`_languageAllowed` becomes table-driven rather than a per-language `if` chain: a map from catalog `language` value to the extension test that language's parser actually uses. The extension sets must be **derived from, or asserted equal to, the sets `ir/index.js` uses to build IR** — Phase 1's fix for `js` did this deliberately, and a reviewer confirmed the JS set was byte-identical to `ir/index.js`'s. Any divergence silently removes true positives, which is worse than the false positives being fixed.

A language with no entry in the table keeps today's permissive behaviour, so the change is additive and cannot regress a language before its mapping is added.

### 4.2 Receiver constraints where they earn their place

`match.receiver` already exists (`catalog.js:779-806`), added in Phase 1 for `js-document-write`, and correctly handles both expression callees and dotted string callees. It is applied to exactly one entry.

This phase applies it to the entries where a bare name is demonstrably ambiguous. The selection is **evidence-led, not speculative**: an entry earns a receiver constraint when it produces a measured false positive on this repository, on the proof-corpus targets, or on a purpose-built polyglot fixture. Adding constraints to all 120 on principle would be a large, unmeasured change with real recall risk.

### 4.3 One shared call-site extractor

`parser-cpp.js`'s `_callSitesFromCfg` (`:445-462`) reads only the IR contract — it walks `cfg.nodes` and collects call expressions from `call`, `assign`, `return`, `throw` and `if` nodes. Nothing in it is C++-specific.

It moves to a shared module and every parser uses it. This is deliberate and is the lesson of Phase 1: `_resolvableCalleeName` was implemented at one call site, was immediately re-broken by the next task, and had to be moved into `callgraph.js` as `resolveKnownCallee()`. Copying an extractor into five parsers would recreate exactly that failure mode. Verified 2026-07-26 that Go, C#, Kotlin and PHP already produce `assign`/`return` nodes carrying call-shaped sources, so the shared extractor works for them without parser changes beyond wiring.

### 4.4 A precision gate

This repository scans itself. Its own finding count becomes a committed baseline with a CI check, so a precision regression fails the build.

Phase 1 is the argument for this: six false high-severity findings were introduced and shipped through several task reviews before a whole-branch reviewer measured `hooks/` and `scripts/` by hand. A gate would have caught them on the commit that introduced them.

The gate must distinguish a *count* change from a *content* change — a finding moving between files matters even when the total is unchanged — so the baseline records per-file counts, not one number.

## 5. Java is separated deliberately

The Java frontend needs statement lowering, parameter extraction, real line numbers and a conforming `qid`. That is the same shape of work as the C++ IR parser, which took eight tasks and found three defects of its own along the way.

Folding it into this phase would mean one plan whose first four tasks are mechanical and whose fifth is a multi-week frontend rebuild — the decomposition failure both planning skills warn about. It gets its own spec and plan, informed by `docs/superpowers/plans/2026-07-25-cpp-ir-parser.md`, which is the closest available template.

**What this phase does about Java now:** corrects the tier claim in the Proof Corpus PRD §2.3, and records the four specific defects with their evidence so the follow-on plan starts from measurement rather than rediscovery.

## 6. Deliberately deferred, with reasons

- **Propagation depth is unmeasured.** Phase 1 proved one call hop. Whether taint survives two hops, a field write, a collection element or a callback is unknown. A depth-graded corpus would convert "we think it is shallow" into a number and would tell us whether the documented k=1 monovariant limit actually costs findings. Worth doing before any deeper engine work, and out of scope here.
- **The remaining ~118 bare-name sinks.** Constrained only as evidence demands (§4.2).
- **`_isStrcpyGuarded`** (`sast/cpp.js:77-82`) still suppresses genuine overflows via a four-line proximity heuristic.
- **The corpus runner's pre-matcher is looser than its post-matcher**, biasing future entries toward passing.

## 7. Risks

**Language scoping removes true positives.** The mitigation is §4.1's requirement that extension sets match `ir/index.js`'s exactly, plus a per-language before/after finding count on a polyglot fixture. This is the risk that would do real damage, because a lost finding is invisible.

**Receiver constraints are too narrow.** A regex that fails to match a legitimate receiver silently drops a true positive. Mitigation: constraints are added only where a false positive was measured, and each ships with a test asserting the *true* positive still fires.

**The self-scan gate becomes noise.** If it fails on unrelated churn, it will be ignored or disabled. Mitigation: it gates on per-file counts with an explicit update path, in the same shape as the existing corpus baseline, which has proven durable.

## 8. What "done" looks like

Demonstrated by commands run in the same session as the claim:

1. `hooks/` and `scripts/` self-scan counts are at or below their Phase 1 post-fix values on **both** measures — total findings (24 and 24) and IR-TAINT findings (0 and 1) — with the one remaining IR-TAINT finding still explained. The two measures answer different questions: the total catches a broad precision regression, the IR-TAINT subcount catches a taint-specific one. An earlier draft of this section quoted 0 and 1 as if they were totals; that conflated the subcount with the total and is corrected here.
2. Go, C#, Kotlin and PHP each produce a cross-function interprocedural finding in a fixture where the source is in one function and the sink in another.
3. A polyglot fixture shows no catalog entry firing on a file whose language it does not target.
4. Per-language before/after finding counts show no recall loss on the proof-corpus targets.
5. The self-scan gate is proven in both directions — passes clean, fails on an injected regression.
6. the Proof Corpus PRD §2.3 no longer claims Java has proven interprocedural taint, and the four Java defects are recorded with runtime evidence.

---

## Phase 2 outcome

Measured in `bench/self-scan/RESULTS.md` (Task 8, 2026-07-26). **Verdict: Phase 2 shipped as designed — Go/C#/Kotlin/PHP gained interprocedural `fn.calls`, self-scan and proof-corpus precision held exactly at baseline (byte-identical proof-corpus SARIF output before/after), and no recall loss was found across 197 CVE-replay corpus entries or per-language sink-matching tests.**

## Appendix — provenance

Every figure in §1 and §2 was produced by running the code on 2026-07-26 on branch `feat/engine-reconnect`: the `fn.calls` inventory by invoking each parser through `buildProjectIR`/`buildProjectIRAsync`; the 120-of-121 bare-name count by filtering `CATALOG`; and the Java stub evidence by parsing a conventional Java class and printing each function's `qid`, `line`, `params` and CFG node ids.
