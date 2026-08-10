# Design — Making detection and remediation materially more effective

**Status:** Proposed.
**Date:** 2026-07-25
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** The Layer-2 taint stack (`scanner/src/dataflow/`), the IR layer that feeds it (`scanner/src/ir/`), the taint catalog, and the remediation toolchain (`scanner/src/mcp/` + `agents/security-fixer.md`).
**Audience:** Engineering (scanner core).

---

## 1. The thesis

**This codebase's limiting factor is not missing capability. It is disconnected capability.**

`scanner/src/dataflow/` contains 36 modules including an IFDS solver, tabulation, k-CFA call-string context, points-to analysis, symbolic execution, SMT feasibility, exception flow, implicit flow, and a 325-entry source/sink/sanitizer catalog. `scanner/src/sast/` contains 110 detector modules. On paper this is a serious analysis stack.

In practice, a handful of small plumbing defects prevent most of it from ever executing. Every defect below was **reproduced by running the code during the C++ parser workstream**, not inferred from reading:

| # | Defect | Location | Consequence |
|---|---|---|---|
| 1 | `callGraph.resolve()` returns a **qid string**; five call sites test `resolved && resolved.qid` | `dataflow/engine.js:235`, `:344`, `:795`; `ifds.js:261`; `points-to.js:251` | The record is always `null`. Consequences differ per site and are spelled out in §1.1. Net effect, verified identical on JS, Python and C++: **no language produces interprocedural taint findings.** |
| 2 | `fn.calls` emitted by only 3 of 8 parsers | `parser-js.js`, `parser-rb.js`, `parser-cpp.js` emit; Go, C#, Kotlin, PHP, Python do not | Those five languages cannot do interprocedural analysis even after #1 is fixed. |
| 3 | `fn.calls` entries (objects) used as object keys | `dataflow/index.js:175-176` | Every entry collapses to the string `"[object Object]"`. |
| 4 | `callersOf` keyed by source-level name; worklist looks up qids | `tabulation.js:86-88` | The IFDS caller lookup can never match. |
| 5 | `extends` never populated for any language | `class-hierarchy.js` (pre-C++ work) | `resolveMethod`'s inheritance walk was dead code, so virtual dispatch never resolved to a base-class method. |
| 6 | Sanitizers consumed only by `proven-clean.js`, only for `appliesTo: ['sql']` | `engine.js` has no sanitizer handling | A correctly sanitized flow is still reported. This is a pure false-positive source across every language and vuln class. |
| 7 | The CVE-replay runner calls `runScan()` in-process and never sets `AGENTIC_SECURITY_DEEP` | `bench/cve-replay/runner.mjs` | All **193** corpus entries pass via syntactic regexes. The corpus exercises **zero** IR or taint code, so none of the above was ever caught. |

Item 7 explains items 1–6: the regression gate cannot see the machinery it is supposed to protect.

### 1.1 Defect 1 in precise terms

An early draft of this document said the callee-summary blocks "never execute." That is too coarse, and the real behaviour matters because it determines the fix. Reading `dataflow/engine.js:235-263`:

```js
const fn  = resolved && resolved.qid ? resolved : null;   // always null
const qid = resolved && (resolved.qid || resolved);       // correctly the string
if (typeof qid === 'string') { … }
```

The **qid** line already tolerates a string, so a *cached* summary lookup does proceed. What `fn === null` actually costs:

- `const paramNames = (fn && Array.isArray(fn.params)) ? fn.params : []` — formal parameters are never bound to actual arguments, so the entry state carries no argument taint.
- `if (!sum && fn && fn.cfg) { … analyzeFunction(fn, entry, inner) … }` — **a summary is never computed on demand.** Only a pre-existing cached summary can ever be found, and nothing populates that cache for the callee.
- At `:795`, `if (!cbFn || !cbFn.params || !cbFn.params.length) continue;` — the higher-order/callback path is **fully dead**, and `:809` is genuinely unreachable.

So the precise statement is: parameter binding is empty, on-demand summary computation never happens, and the callback path never runs. That is consistent with the observed end state — zero interprocedural findings in every language tested — and it means the fix is to hand these sites the function *record*, not to change `resolve()`'s contract.

**Fix direction.** `callgraph.js:36` does `functions.set(fn.qid, fn)`, so the record is one map lookup away. Changing `resolve()` to return the record instead would alter a contract that `edges[].callee` and the C/C++ qualified-name path both rely on being a qid string. Resolving the record at the five call sites is therefore the smaller, safer change.

**Consequence for prioritisation.** Fixing roughly six small defects plausibly unlocks more real detection capability than months of new rules would. New rules layered on a disconnected engine inherit the disconnection.

## 2. The remediation picture

The remediation *architecture* is genuinely good and should not be redesigned. `agents/security-fixer.md` is the intent layer with no `Edit` or `Write` tool; every byte goes through the MCP execution layer, which enforces path confinement, HMAC integrity, a reserved-path refusal list, an audit log, and a backup. `apply_fix`'s patch path re-verifies inline and writes only on success, so a wrong patch is refused rather than written. That is a strong safety model.

Two gaps limit what it can be trusted to do:

**2.1 Verification does not run tests.** `verify_fix` re-scans the patched files in memory and runs the project linter (`tools.js:682`). Nothing executes the project's test suite. A patch can therefore remove the finding, introduce no new finding, pass lint — and still break the application. That is precisely the property that decides whether a team dares enable automated fixing.

**2.2 Deterministic fix coverage is ~1%.** Exactly **1 of 110** SAST modules ships a `replacement:`. Every other finding takes the "agent composes the full patched-file text" path — LLM-authored bytes gated only by re-scan and lint. Raising deterministic coverage converts a class of fixes from "plausible" to "provable."

## 3. Goals and non-goals

### Goals

- **G1** — Interprocedural taint findings actually produced, for at least JS, Python and C++. *(Corrected 2026-07-26: this goal originally named **Java** rather than C++. Java was never capable of satisfying it — its IR frontend produces function names with an empty CFG, no parameters and `line: 0`, so interprocedural taint is impossible for it regardless of the defects this phase fixed. Phase 1 measured JS, Python and C++; Java was never measured. See `docs/superpowers/specs/2026-07-26-java-ir-frontend-notes.md`.)*
- **G2** — The regression corpus exercises the IR and taint stack, so the above cannot silently break again.
- **G3** — Sanitizers suppress correctly-sanitized flows, reducing false positives.
- **G4** — A fix cannot be written unless the project's tests still pass.
- **G5** — Every claim above is measured before and after, on the same corpora.

### Non-goals

- **Not a redesign of the remediation architecture.** The confined-write, verify-then-apply model stays exactly as it is.
- **Not new analysis techniques.** No new solvers, no new sensitivity dimensions. This program connects and validates what exists.
- **Not new detector rules.** Rule count is not the constraint; reachability of the existing engine is.
- **Not a performance project**, beyond not regressing.

## 4. Phased programme

Four phases, ordered by return on effort. Each is independently valuable and independently reviewable.

### Phase 1 — Reconnect the engine *(the subject of the first implementation plan)*

Fix defects 1, 3, 4, 6 and make the corpus deep-aware (7). Add `fn.calls` for the highest-value missing parser (Python) as the proof that #2 is mechanical.

The measurement that decides whether the thesis holds: **corpus entries that currently pass via syntactic rules should, after this phase, also produce `ir-taint:` findings** — and new deep-mode corpus entries should pass that could not before.

Explicitly sequenced first because every later phase is worth less on a disconnected engine.

### Phase 2 — Precision

- Language-scope catalog matching for **all** entries, not only the C/C++ ones. Today `CALLEE_INDEX` is keyed by callee name alone, so a Python `system` entry matches a Ruby file.
- Make the cross-language call-graph guard bidirectional and general. The current guard keys on `qname`, which only the C++ parser emits, so JS→Python false edges remain and C++→JS is unguarded.
- Replace proximity-based suppression heuristics with dataflow-associated ones, starting with `sast/cpp.js:77-82` `_isStrcpyGuarded`, which returns false on any `sizeof` within four preceding lines and thereby suppresses textbook `recv`→`strcpy` overflows.

Precision is sequenced second because Phase 1 raises recall, and recall without precision produces noise that destroys trust faster than missing findings do.

### Phase 3 — Remediation credibility

- Add a test-execution gate to the verification path: detect the project's test command, run it against the patched tree, and refuse the write if it fails or if it was not runnable.
- Wire the existing regression-test scaffold (`synthesize_fix` already returns one, and `security-poc-generator` produces PoCs) so the generated test is actually executed as part of the gate.
- Record, per fix, which gates passed — rescan, lint, tests — so a consumer can distinguish a proven fix from a plausible one.

### Phase 4 — Coverage

- `fn.calls` for the four remaining parsers (Go, C#, Kotlin, PHP).
- CHA `extends` for JS and Java via the language-neutral `ir.classes` input the C++ work introduced.
- Investigate Ghost's 248 genuine JavaScript parse failures (94% coverage on a mainstream Node codebase).
- Raise deterministic `fix.replacement` coverage well beyond 1 rule, prioritised by finding frequency.

## 5. Cross-cutting design decisions

**Every phase is gated by measurement, not by assertion.** Each phase states a before number and an after number drawn from a run in the same session. The project's verification discipline already requires this; this programme makes it structural by defining the metric per phase up front.

**The corpus becomes deep-aware rather than deep-only.** Making the existing 193 entries run deep would change their meaning and their runtime. The design instead adds a **deep tier** alongside the existing tiers: entries explicitly marked as requiring interprocedural analysis, run with deep enabled, gated separately. Existing entries keep their current semantics and their determinism.

**Sanitizer handling must be recall-preserving by default.** Turning on suppression can hide true positives if a "sanitizer" does not actually sanitize (the C++ work already found `strncpy`/`snprintf` mislabelled as `effect: 'strip'` when they bound length rather than sanitising content). Sanitizer suppression therefore ships behind a demotion rather than a deletion — a suppressed finding is demoted and labelled, not dropped — until measured on the corpora.

**No fix is written on an unverifiable tree.** If the test command cannot be detected or the suite cannot run, that is reported as "not verified" and the write is refused under the default policy, rather than silently falling back to the weaker gate. An explicit opt-out exists for repositories with no test suite.

## 6. Risks

**The thesis could be wrong.** It is possible that fixing `resolve()` produces few new findings because a further blocker sits behind it. Phase 1 is sequenced first precisely so this is discovered cheaply. If the after-measurement shows no new interprocedural findings, the programme stops and re-plans rather than proceeding to Phase 2.

**Raising recall raises false positives.** Interprocedural findings are harder to judge than intraprocedural ones. Mitigation: Phase 2 follows immediately, sanitizer suppression lands in Phase 1 (it is the one change that *reduces* noise), and finding density per KLOC is measured on the proof-corpus targets before and after.

**The test gate could make fixing impractical.** Running a full suite per fix is slow, and many repositories have flaky or slow tests. Mitigation: prefer a targeted test selection where the project supports it, cache the pre-patch result so only the delta is attributable to the patch, and make the policy configurable while defaulting to safe.

**Deep mode is expensive.** The deep tier will be slower than the existing corpus. Mitigation: keep it a separate tier with its own budget, and keep the existing fast tier as the pre-commit gate.

## 7. What "done" looks like

For Phase 1, all of the following demonstrated by commands run in the same session:

1. A source in one function reaching a sink in another produces an `ir-taint:` finding, in JS, Python and C++.
2. `dataflow/index.js` and `tabulation.js` caller lookups resolve to real qids, evidenced by a test asserting a non-empty caller set.
3. A correctly sanitized flow is demoted rather than reported at full confidence, with the demotion visible in the finding.
4. At least 5 new deep-tier corpus entries pass that provably could not pass before, and the whole existing 193-entry tier remains green.
5. Finding counts before and after on Ghost and Superset are recorded, so any precision regression is visible rather than discovered later.

## Phase 1 outcome

Measured and recorded in `bench/engine-reconnect/RESULTS.md`. **The thesis
held: `interprocedural` moved from zero to non-zero in JS, Python and C++ in
the same session's harness run**, via three engine defects rather than the
one originally hypothesized; the deep tier gained 4 of the asked-for 5
entries (a corpus-format limitation, not a detection gap) and the sanitizer
gate ships wired but intentionally inert; the one precision comparison
available (Ghost, indicative rather than same-commit) showed no finding-count
increase, so Phase 2 proceeds with its precision work as the standing next
priority rather than an emergency reprioritization.

---

## Appendix — provenance of every claim

Every defect in §1 was reproduced by execution during the C/C++ IR parser workstream (branch `feat/cpp-ir-parser`, PR #43), and each is recorded with its evidence in that branch's `bench/proof-corpus/GAPS.md`, the PR description, or the Proof Corpus PRD (removed post-implementation). The remediation figures in §2 come from reading `scanner/src/mcp/tools.js` (the `verify_fix` contract at line 682) and counting `replacement:` occurrences across `scanner/src/sast/*.js` (1 of 110) in this session.
