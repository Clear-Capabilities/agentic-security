# PRD: World-Class Detection — Engine, Deep Engine, and Taint

**Status:** Draft for review. Nothing here is implemented by writing it.
**Owner:** Ross Young / Clear Capabilities Inc.
**Date:** 2026-08-17
**Engine version measured:** 0.137.1
**Scope:** `scanner/src/sast/` (pattern/structural engine), `scanner/src/dataflow/` (deep engine + taint), `scanner/src/ir/` (the IR that feeds it), and `bench/independent/` (the instrument that measures all three).
**Audience:** Engineering (scanner core).

**Supersedes as the authoritative detection plan:** `docs/TAINT_ENGINE_IMPROVEMENT_PRD.md` P3/P4 (never started) and the open follow-ups in `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`. It does not retract either; it re-sequences them behind a correctness problem both missed.

---

## 1. The measured problem

Every number in this section came from a command run on 2026-08-17 against engine 0.137.1, over `bench/independent/` — 315 entries of real upstream code at the commit where a vulnerability really existed, with the CWE assigned by a public advisory database rather than by this project.

### 1.1 Headline accuracy, as the harness currently scores it

| | Pattern-only (harness default) | Deep mode forced on |
|---|---:|---:|
| True positives | 21 / 315 | 23 / 315 |
| Recall | **6.67%** | **7.30%** |
| Precision | 51.2% | 50.0% |
| F1 | 0.118 | 0.127 |

### 1.2 The three findings that matter more than the headline

**(a) The deep engine has never been measured by the benchmark meant to measure it.**
`bench/independent/runner.mjs`'s `scanDir()` calls `runScan(dir)` with no options, and `runScan()` does not default `deep: true` — only `bin/agentic-security.js` (the interactive CLI) sets `AGENTIC_SECURITY_DEEP=1`. Verified three ways: reading the call chain, inspecting `scan._scanMeta.analysisTier`, and a controlled positive-control scan proving the detection method correctly observes deep mode when it *is* on. `docs/DETECTION_GAP_REMEDIATION_PRD.md` §Theme A explicitly recommended "default `deep: true` inside `runScan()` itself (not just the CLI)" and its status log records Theme A as landed; the code shows only the CLI wrapper was changed. **Every independent-population number this project has ever published was pattern-only.**

**(b) Forcing deep mode on nets +2 true positives and +3 false positives across 315 real advisories.**
Exactly 4 entries had an `IR-TAINT` finding match the labelled CWE in an advisory file. Two were already caught by pattern detectors. Three of the four also fire on the *fixed* code. After all the machinery in `scanner/src/dataflow/` — IFDS solver, k-CFA call-string context, points-to, 655-entry catalog — the measured real-world contribution of taint analysis is approximately break-even.

**(c) The engine almost cannot tell vulnerable code from fixed code — and most "true positives" are not about the labelled bug at all.**

| Metric | Pattern-only | Deep |
|---|---:|---:|
| TPs that *also* fire on the fixed `post/` code | 19/21 (90.5%) | 22/23 (95.7%) |
| **Fix-discrimination rate** (TP correctly silent after the fix) | **9.5%** | **4.3%** |

And, scoring each TP by whether the matching finding landed on a line the fix commit actually changed (±3 lines):

| TP quality (pattern-only, n=21) | Count |
|---|---:|
| Landed inside/adjacent to the real fix hunk | **4** |
| Fired elsewhere in the file — CWE matched by coincidence | **17** |

**The honest "found the actual disclosed bug" rate is 4/315 = 1.3%, not 6.67%.** For the deep engine it is **0** — both of taint's two new true positives landed on a file the fix commit did not modify at all (empty diff hunk list), so neither can be about the vulnerability being scored.

Worked example, verified by hand (`GHSA-3cg5-48j3-v4gv`, open-webui, CWE-862): the scanner scored a true positive for "FastAPI mutating endpoint `create_folder()` has no `Security()` / `Depends()` auth dependency." The function in question visibly declares `user=Depends(get_verified_user)` and calls `await check_folders_permission(request, user, db=db)` on its first line. The claim is factually false about the code; the real fix was 200 lines away in `delete_folder()`. The finding is a false positive that scored as a true positive because the harness matches on CWE + file, and both happened to line up.

### 1.3 What this means

The project's stated moat is *provable, measurable, reproducible* security. Two of those three are currently compromised in the same place:

1. **The instrument is too lenient.** CWE + file-scope matching awards credit for findings that are demonstrably about different code. 17 of 21 headline true positives are inflation.
2. **The engine reports patterns, not vulnerabilities.** A detector that fires identically before and after the fix has not detected a vulnerability; it has detected the presence of an API. Fix-discrimination of 9.5% is the single most damning number in this document, and it is not a taint problem — it is an every-layer problem.

Neither is a reason for despair: both are precisely measurable, and both are fixable. But **no amount of new detection capability will show up as quality until the instrument stops rewarding coincidence and the engine starts distinguishing fixed from broken.** That ordering is the core argument of this PRD.

---

## 2. Goals and non-goals

### Goals

1. **Measure honestly first.** A location-aware, hierarchy-aware, layer-attributed instrument that cannot award credit for a coincidental CWE match, run in both pattern-only and deep configurations.
2. **Fix-discrimination as the primary quality metric.** Raise the rate at which a finding correctly goes silent once the vulnerability is fixed, from 9.5% toward 80%+.
3. **Real-bug recall** (fix-hunk-localized, the strict metric) from 1.3% to a double-digit figure, with taint contributing a measurable, non-zero share.
4. **Close whole vulnerability classes that have no detector at all**, prioritized by measured frequency in the real-world population, not by intuition.
5. **Every claim in `docs/SCORECARD.md` traceable to the configuration that produced it** — no taint-recall figure printed next to an independent-population figure that never ran taint.

### Non-goals (stated so they are not silently attempted)

- **Chasing the headline 6.67% number.** It is inflated; raising it without raising the strict metric would be gaming this project's own benchmark, which the mutation gate exists to prevent and which this document refuses on principle.
- **Vulnerability classes that require a domain oracle rather than analysis.** 11 of the 96 root-caused misses are "a hand-maintained allow/deny-list omitted one entry" (which npm env var enables auto-confirm; which IPv6 textual form is also loopback). Detecting these requires enumerating the dangerous set, not analyzing code. Out of scope, permanently, unless a curated data source is adopted deliberately.
- **Native code, protocol state machines, and parser-internal correctness** (C++ browser internals, HTTP/2 framing, URI-regex differential parsing — 6+ entries). Real bugs, genuinely outside a multi-language source analyzer's reach. Declared out of scope rather than counted as debt.
- **Binary/firmware analysis** — unchanged from `docs/ROADMAP.md` R15.

---

## 3. Evidence base: what the 96 root-caused misses actually are

From `docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md`, bucketed by recurring technical theme (buckets overlap; an entry can carry two):

| Recurring theme | Entries | Addressed by |
|---|---:|---|
| Business-logic authorization (BOLA/BFLA/tenant scope) | 19 | Theme 5 |
| Resource exhaustion / unbounded allocation | 14 | Theme 4 |
| Cross-file / stored / second-order flow | 12 | Theme 3 |
| Bespoke allow/deny-list completeness | 11 | *non-goal* |
| Sibling-guard omission (repo-internal inconsistency) | 10 | **Theme 6** |
| Non-web taint sources (CLI, plugin ABI, schema, SDK, decorator) | 9 | Theme 3 |
| `kwargs`/argv → CLI-flag argument injection (CWE-88) | 9 | Theme 4 |
| Redirect / header-forwarding semantics | 8 | Theme 4 |
| Guard exists but is bypassable (validate-then-decode, wrong lifecycle) | 7 | Theme 2 |
| Protocol / parser state-machine correctness | 6 | *non-goal* |
| Code-generation output as an injection sink | 5 | Theme 4 |
| TOCTOU / DNS rebinding | 3 | Theme 4 |

This table is the prioritization argument. It is derived from real advisories nobody on this side selected, not from a survey of what analyzers usually implement.

---

## 4. Themes

### Theme 0 — Make the instrument honest *(blocks everything; nothing else is measurable until this lands)*

**Problem.** `bench/independent/runner.mjs` scores an entry TP when *any* finding carrying the labelled CWE appears *anywhere in the advisory's files*. Measured consequence: 17 of 21 TPs are coincidental. It also never enables deep mode, and reports no per-layer attribution.

**Work.**

- **T0.1 — Location-aware scoring (the headline change).** Compute the fix commit's changed line ranges per advisory file (already prototyped this session via `diff -u0` over the cached `pre`/`post` trees) and score a TP only when a matching finding lands within a tunable window (start at ±3 lines, justify any widening with data). Report both figures side by side, permanently: `localized` (the claim) and `file-scoped` (diagnostic, comparable to the historical series). Precedent and rationale are exactly those `runner.mjs` already documents for the existing advisory-local vs. wide split.
- **T0.2 — Fix-discrimination as a first-class reported metric.** For every localized TP, report whether the same finding is absent from `post/`. This is the number Theme 1 moves. Publish it in `docs/SCORECARD.md`.
- **T0.3 — Score both configurations, always.** Run the population pattern-only *and* deep, and report both plus the delta. Wire `deep` through `scanDir()` explicitly rather than depending on ambient env state.
- **T0.4 — Per-layer attribution.** Record the `parser` field of the matching finding (`REGEX`, `IR-TAINT`, `JS-FW`, `LOGIC`, …) so "what did taint actually contribute" is a standing, non-negotiable column rather than a special investigation.
- **T0.5 — CWE-hierarchy-aware matching, carefully.** Accept a parent/child CWE relationship (CWE-94 satisfies a CWE-95 label) via a small committed edge table derived from MITRE's published hierarchy, applied symmetrically and disclosed in the output. Two entries are currently scored FN purely on taxonomy (`GHSA-wg86-r78f-74mp`, and `GHSA-fm2f-4339-4p2f` post-fix). **Guardrail:** hierarchy widening only ever accompanies T0.1's tightening, never precedes it — loosening the CWE axis while the location axis stays loose would manufacture recall.
- **T0.6 — Repair the sampling.** 5 of 96 entries had the actually-vulnerable file absent from the materialized scope (deleted by the fix, or dropped by `mine.mjs`'s 5-file cap on squashed commits). Either materialize the union of pre-side and post-side files, or mark such entries UNSCORED by name — never silently counted as detection failures, per the harness's own existing UNSCORED doctrine.
- **T0.7 — Grow and hold out.** Expand toward 750+ entries, and reserve a **held-out slice that is never read during development** — the calibration discipline this repo already enforces (`posture/holdout-eval.js`) applied to detection. Without it, every subsequent theme risks fitting to 315 known answers.

**Exit gate.** The scorecard publishes localized recall, file-scoped recall, fix-discrimination, and per-layer attribution, for both configurations, with a held-out slice reported separately. Expected effect on the headline: **recall drops from 6.67% to ~1.3%.** That is the point. The number becomes true.

---

### Theme 1 — Fix-discrimination: make a finding mean "this is broken", not "this API is present"

**Problem.** 90.5% of true positives survive the fix unchanged. The engine keys on the presence of a dangerous API, not on the absence of the mitigation.

**Work.**

- **T1.1 — Guard recognition must be able to silence, not merely annotate.** `dropGuardedFindings` already exists for SSRF/path with a comment-stripped window, and `sanitizer-gate.js` deliberately only *demotes* (documented rationale in `scanner/src/dataflow/CLAUDE.md`: an HTML escaper must not clear a SQL flow). That doctrine is right and stays. What is missing is the **family-matched, on-path, proven** case: when the sanitizer's declared `appliesTo` family covers the finding's threat class *and* it provably dominates every path to the sink, the finding should be suppressed to the ledger (visible via `--include-suppressed`), not merely demoted. That is the difference between 9.5% and a real number.
- **T1.2 — Framework auth-dependency recognition.** The `GHSA-3cg5` example is a plain defect: a FastAPI route declaring `user=Depends(get_verified_user)` and calling an explicit permission helper was reported as having no auth dependency. Build a shared, cross-framework "this route is authenticated/authorized" resolver (FastAPI `Depends`/`Security`, Express/Koa middleware chains — including the permission-string family fixed this session, Spring/NestJS decorators, Django decorators/mixins) and make every authz-adjacent detector consult it instead of hand-rolling regexes. **This is the single highest-yield precision fix identified**, because authz detectors produced the largest share of coincidental TPs.
- **T1.3 — Validate-then-mutate invalidation** (7 entries). Recognize that a value which passed a containment check and was subsequently *reassigned* through a transform (`unquote`, `decode`, `normalize`, `resolve`) is no longer covered by that check. Model as: a guard binds to a value-version, and re-assignment rotates the version.
- **T1.4 — Differential mode as a product capability, not just a benchmark trick.** Given two revisions, report findings *introduced* / *removed* / *unchanged*. This is directly useful in CI (the `security-material-change` agent already wants it), and it makes fix-discrimination a first-class engine feature rather than a benchmark artifact.

**Exit gate.** Fix-discrimination ≥ 60% at phase end, ≥ 80% at PRD close, with no localized-recall regression and `bench:mutation:check` green.

---

### Theme 2 — Precision audit of the highest-volume detectors

**Problem.** The 17 coincidental TPs are, definitionally, findings fired on code that is not the vulnerability. Several are outright wrong claims (T1.2's example). They are invisible today because file+CWE scoring rewards them.

**Work.**

- **T2.1 — Adversarial self-audit of the top-firing rules.** Rank detectors by finding volume across the 315-entry population, take the top ~15, and hand-adjudicate a sample of each against real code. Every rule whose claim can be falsified by reading the same file (as in T1.2) is a defect, not a tuning question.
- **T2.2 — Claim-checkable findings.** Where a finding asserts an absence ("no auth dependency", "no rate limiting", "no CSRF protection"), the detector must record *what it looked for and where*, so the assertion is falsifiable by a reviewer — and so a verifier lens (the `posture/logic-claims.js` refutation machinery already in the repo) can mechanically contradict it.
- **T2.3 — Wire the negative-control corpus harder.** `bench/self-scan/fixtures/polyglot/` holds one clean fixture per language and gates at zero. Extend with *fixed-version* fixtures: the `post/` side of localized TPs is a ready-made, real-world, third-party-authored negative-control set. A rule that fires on a known-fixed real file is a measured false positive, not a hypothetical one.

**Exit gate.** Every top-15 detector has an adjudicated sample; every falsifiable-claim defect found is fixed or the rule is narrowed; self-scan and corpus gates green.

---

### Theme 3 — Taint that reaches real code: sources, cross-file, and stored flow

**Problem.** 9 entries fail because nothing marks the value as tainted in the first place; 12 fail because the flow crosses a file, a store, or a process. `scanner/src/dataflow/CLAUDE.md` already documents the k=1 monovariant limit and the absence of stored/second-order modeling. The catalog's source set is overwhelmingly web-framework request objects.

**Work.**

- **T3.1 — Entry-point taint inference (the big one).** Generalize "what is untrusted" beyond framework request objects, each behind its own confidence tier so precision stays controllable:
  - CLI argument parsers (`argparse` `Namespace` attributes, `commander`, `clap`) — currently only bare `sys.argv` is modeled.
  - Decorator/annotation-declared handlers beyond HTTP: MCP tool methods, task/queue consumers, event handlers. Requires Python IR to emit `paramAnnotations`, which `parser-py.js` does not today (C#/Java/JS already do) — a concrete, bounded IR gap.
  - Values parsed out of an input document the tool was pointed at: schema `$ref`, XML `schemaLocation`, config fields. This is the "the file under analysis is attacker-supplied" trust model that document-processing libraries live in.
  - Third-party SDK/network responses (object-storage listings, HTTP client bodies) as a distinct, lower-confidence tier.
  - Public library API parameters, gated behind an explicit "analyze as a library" mode — for a library, the caller *is* the attacker, and `GHSA-fxqj`/`GHSA-hh9p`/`GHSA-p538` are all this shape.
- **T3.2 — Cross-file and stored (second-order) taint.** The long-deferred P4. Persist per-function summaries across files (the `SummaryCache` shape already exists; `incremental.js` already persists across scans), and model a write-then-read-back store (DB column, cache, rendered document) as a taint carrier with an explicit, conservative store-identity model.
- **T3.3 — Container/collection-element taint.** `keys.map(k => path.join(dir, k))`, `mobiledoc.cards[].payload.src`. Needed by several entries and by the still-open prototype-pollution family from the prior taint PRD.
- **T3.4 — Multi-source correlation at a sink.** `GHSA-qq9q` needs "an env-derived *secret* and a caller-controlled *destination* meet at one call". The engine tracks taint presence, not taint *provenance pairs*. Model provenance classes and allow a sink to require a combination.

**Exit gate.** Each sub-item ships with a localized-TP delta measured on the held-out slice, plus per-language FP budget held, mutation gate green.

---

### Theme 4 — Whole vulnerability classes with no detector today

Ordered by measured frequency. Each is a genuine "we have no rule for this", not a tuning gap.

- **T4.1 — Argument injection / `kwargs`→CLI-flag (CWE-88; 9 entries).** The largest single unimplemented class. Shape: a value (or an entire `**kwargs` dict) becomes command-line *flags* for a subprocess, where a flag like `--output`/`--template`/`--index-output` grants file write, file read, or code execution. Today argv-array subprocess calls are treated as blanket-safe with no per-flag inspection, and CWE-88 exists only as a label in `posture/rule-packs.js` with no implementing rule. Needs a per-tool dangerous-flag table (small, curated, versioned) plus recognition of "unvalidated kwargs splat reaches a CLI wrapper."
- **T4.2 — Resource exhaustion / unbounded allocation (CWE-400/834; 14 entries).** Attacker-influenced value used as a loop bound, allocation size, repetition count, or geometry multiplier with no cap. Distinct from ReDoS (`redos-nfa.js` covers only regex backtracking, and correctly returned "safe" for a real polynomial-`split()` DoS). Start with the highest-signal shape: a parsed-input numeric field flowing to a range/allocation without an upper-bound comparison on any path.
- **T4.3 — Code generation as an injection sink (5 entries).** Untrusted value interpolated into emitted source text (a generated `.py`, a rendered template that becomes code, a source comment that `\r` can escape) which is later imported/executed. New sink *category*, not a new sink entry: the "sink" is a file write whose content is program text.
- **T4.4 — Redirect and header-forwarding semantics (8 entries).** Today "redirect" appears only as CWE-601 open-redirect — the opposite direction. Model: (a) the client's own credential headers surviving an origin-changing redirect; (b) a redirect target re-entering SSRF-relevant space without re-validation.
- **T4.5 — TOCTOU on resolution (3 entries).** Validate-then-connect where the second resolution can differ (DNS rebinding), and validate-then-open where the path can change. Related to T1.3; share the value-version machinery.

**Exit gate.** Each class ships with vulnerable/clean fixture pairs per supported language, corpus entries proven `pre:TP post:TN`, and its own FP budget.

---

### Theme 5 — Business-logic authorization (19 entries — the largest family)

**Problem.** The biggest single cause of real-world misses is not injection at all: it is missing or inconsistent authorization — object-level (does this id belong to this caller), function-level (is this route gated like its siblings), and tenant-level (is the query scoped to the caller's workspace). Existing rules (`api-authz.js`, `authz.js`, `rbac-consistency.js`, `business-logic.js`) work at route-inventory granularity and on narrow ORM shapes; real code fails inside handlers, across service layers, and through bespoke permission models.

**Work.**

- **T5.1 — Ownership-comparison analysis.** For a handler that reads an object identifier from the request and reaches a data-layer lookup, determine whether *any* path compares the fetched object (or the query) against an identity derived from the authenticated principal. Absence of that comparison is the finding. This subsumes the current path-param-only heuristic and reaches the query/body-param cases (`GHSA-gmmw`) and service-layer forwards (`GHSA-2364`).
- **T5.2 — Tenant-scope propagation.** Model `workspaceId`/`orgId`/`tenantId` as a required query dimension: a lookup by primary key with no tenant predicate, in a codebase that elsewhere always includes one, is a defect. Pairs naturally with Theme 6.
- **T5.3 — Intra-handler branch consistency.** Several entries gate one branch and not its sibling (`GHSA-g423`'s legacy vs. native path; `GHSA-mj5r`'s ANDed condition that short-circuits). Compare authorization evidence across branches of the same handler, not just across routes.
- **T5.4 — Lifecycle/state gates.** "Archived offer still redeemable", "deleted-but-referenced" — a state-changing action reached without checking the resource's own status field, where sibling actions do check it.

**Exit gate.** Localized-TP delta on the 19-entry family measured on held-out data; FP budget explicitly set for this family (authz rules are the current largest source of coincidental findings, so it must tighten while it broadens).

---

### Theme 6 — Repo-internal consistency analysis *(the differentiator)*

**Problem — and opportunity.** 10 of 96 misses share a shape no catalog can express and no generic rule can encode: **the correct guard is already present elsewhere in the same repository, and this one site forgot it.** GitPython's `Repo.init()` lacking the `check_unsafe_options()` its five sibling entry points all call. Ghost's `LocalStorageBase.save()` skipping the validator its own `read()`/`delete()`/`exists()` all use. Flowise's PUT route missing the permission middleware its GET/DELETE siblings carry.

**Why this is worth building.** It inverts the usual model. Instead of asking "does this match a known-bad pattern?" it asks "does this deviate from what this codebase itself established as correct?" That means: no signature to maintain, no per-framework catalog, works on bespoke in-house conventions no vendor could ever enumerate, and produces findings with an unusually strong, self-evident explanation — *"every other caller of this function guards it; this one does not,"* with the siblings cited. High precision by construction, because the baseline is the project's own code.

**Work.**

- **T6.1 — Convention mining.** For each callee/sink reached from multiple sites, collect the guard evidence present at each call site (dominating validation calls, decorators, middleware, wrapper functions). Where a strong majority share a guard, the minority are candidates.
- **T6.2 — Deviation scoring.** Require a meaningful population (≥ N sites), a strong majority (≥ threshold), and structural similarity between sites, so an intentionally-public endpoint among authenticated ones is not automatically a bug. Report the supporting siblings as evidence in the finding.
- **T6.3 — Reuse the existing verification seam.** `posture/verification-separation.js` and `logic-claims.js` already provide producer/verifier separation and refutation lenses. A consistency finding is exactly the kind of claim that benefits from an independent refutation pass before it is reported.

**Exit gate.** Fires on ≥ 5 of the 10 known sibling-omission entries, with a measured FP rate on the negative-control set and on this repository's own source, before it is enabled by default.

---

## 5. Phasing

| Phase | Scope | Exit gate |
|---|---|---|
| **P0 — Honest instrument** | Theme 0 | Localized + file-scoped recall, fix-discrimination, per-layer attribution, both configurations, held-out slice. Published in `SCORECARD.md`. Headline recall expected to *fall* to ~1.3%. |
| **P1 — Precision & fix-discrimination** | Themes 1 + 2 | Fix-discrimination ≥ 60%; top-15 detectors adjudicated; no localized-recall regression; mutation + self-scan + corpus gates green. |
| **P2 — Taint reaches real code** | Theme 3 | Measured localized-TP lift attributable to `IR-TAINT` specifically, on held-out data; per-language FP budget held. |
| **P3 — Missing classes** | Theme 4 | Each class: fixtures, corpus entries `pre:TP post:TN`, own FP budget. |
| **P4 — Business logic & consistency** | Themes 5 + 6 | Localized-TP lift on the 19- and 10-entry families; consistency engine passes its FP gate before default-on. |

**P0 blocks everything.** Running P1–P4 against the current instrument would produce numbers nobody should trust, in either direction.

---

## 6. Success criteria

Measured on the **held-out slice**, in both configurations, with the strict (localized) metric:

1. **Fix-discrimination ≥ 80%** at PRD close (from 9.5%). A finding that survives its own fix is the defining failure of this engine today.
2. **Localized recall into double digits** (from 1.3%), with the file-scoped number reported alongside and the gap between them shrinking — a shrinking gap *is* the precision story.
3. **Taint's attributable share of localized TPs is non-zero and growing**, reported per phase. If Theme 3 completes and taint still contributes ~0, that is a finding to act on — the same milestone-gate discipline `DETECTION_GAP_REMEDIATION_PRD.md` specified and did not follow, applied properly this time.
4. **No regression** in: `bench:cve-replay:check` (215/215), `bench:mutation:check` (verdict-flip correctness), `bench:self-scan:check`, per-language taint FP budget.
5. **`docs/SCORECARD.md` states the configuration behind every number**, and never prints a corpus-derived taint-recall figure adjacent to an independent-population figure without labelling which analysis actually ran.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Fitting to the 315 known answers | T0.7's held-out slice, never read during development; mutation gate; corpus provenance check already refuses self-authored entries as accuracy evidence. |
| The honest metric looks like a catastrophic regression | Publish both figures with the methodology change stated plainly, exactly as `bench/independent/README.md` already did when recall fell 33.6% → 12.7% for the same class of reason. A number that drops because it became true is the project's stated value proposition working. |
| Recall work explodes false positives | Every theme carries its own FP budget; T2.3 turns real fixed code into negative controls, which is a far stronger FP signal than synthetic clean fixtures. |
| Theme 6 (consistency) produces confident nonsense | Population/majority thresholds, sibling evidence required in the finding, refutation lens, and an FP gate before default-on. |
| Suppression (T1.1) hides real bugs | Every suppression already goes to the ledger and surfaces via `--include-suppressed`; family-matched + path-dominating are both required; never severity mutation. |
| Scope is very large | Phases are independently shippable and each ends in a measured, published number; P0 alone is worth landing on its own merits. |

---

## 8. Open questions

- **How wide should T0.1's line window be?** ±3 is a starting guess. A fix that moves a guard 40 lines away from the sink is still a fix for that sink. Candidate refinement: score by enclosing function rather than line distance.
- **Should localized or file-scoped become the published headline?** Recommendation: localized is the claim, file-scoped is the diagnostic — mirroring the existing advisory-local vs. wide split, which already survived this exact debate once.
- **Does "analyze as a library" (T3.1) warrant a distinct scan mode?** For a library, the public API *is* the trust boundary; for an application it is not. Same code, different correct answer — which may be a mode rather than a heuristic.
- **Is Theme 6 a detector or a separate product surface?** Convention-deviation findings may deserve their own report section and severity model, since "you deviated from your own pattern" is a different claim from "this is exploitable."

---

## 8a. Implementation status

Updated 2026-08-17. Only items verified by a command run are marked landed.

| Item | Status | Evidence |
|---|---|---|
| **T0.1–T0.7 (whole of P0)** | **Landed** (`bac5e12`, `db3e646`) | Localized scoring, fix-discrimination, `--deep` as a runner configuration, per-layer attribution, conservative CWE hierarchy, UNSCORED repair, deterministic held-out slice. First honest measurement published: localized **6/315 (1.90%)** vs file-scoped 21/315 (6.67%); fix-discrimination 2/6; held-out 1/66 vs development 5/249 (no overfitting signal). |
| **T1.2 auth resolver** | **Landed** (`fe75dda`) | `sast/_auth-signals.js`. The real GHSA-3cg5 false positive no longer fires; a genuinely unprotected handler still does. |
| **T2.2 claim-checkable findings** | **Partial** | `checkedFor` added to the two detectors touched (fastapi-hardening, convention-deviation). Not applied across the other absence-claiming rules. |
| **T3.1 entry-point taint inference** | **Largely landed** (`07d743d`, `9f2591e`) | Python emitted 0 `paramAnnotations` against 3/4/3 in JS/C#/Java — the whole `match.type:'annotation'` mechanism was unreachable for Python. Now FastAPI param markers, `@mcp.tool()`, and argparse. A/B verified genuinely new (0 findings with the entries stripped). **Not done:** SDK/network-response sources, library-mode public-API params. |
| **T4.1 CWE-88 argument injection** | **Partial, via Theme 6** | The GitPython family is both shapes at once; no dedicated per-tool dangerous-flag table exists. |
| **Theme 6 convention deviation** | **Landed, gate NOT met** (`40bd210`, `0a7cfdc`) | Project-scoped mining implemented. Gate still 1/10 — root-caused to benchmark materialisation scope, not the detector. See below. |
| **Precision fixes found en route** | **Landed** (`640da42`, `27ebf66`, `9f2591e`) | `rate-limit.js` discarded 100% of its own findings project-wide; `scanRoutes` missed permission-string RBAC middleware; subprocess sinks labelled argv-array calls `shell=True`; `py-requests-get` reported `dict.get()` as SSRF. |
| **T1.1 family-matched guard suppression** | **ATTEMPTED, REVERTED — incompatible with a gated invariant** | See §8b. |
| T1.3 validate-then-mutate invalidation | **Not started** | 7 entries. |
| T1.4 differential mode | **Not started** | |
| T2.1 top-detector precision audit | **Not started** | The four fixes above were found incidentally, not by the systematic audit this item specifies. |
| T2.3 fixed-code negative controls | **Not started** | |
| **T3.2 cross-file / stored taint** | **Landed** | 12 entries. Registry admission moved from a closed field-name list to PROVENANCE; sink families extended beyond XSS to SSRF/path/exec with per-family CWEs and per-family guards. Also fixed the underlying comment-stripping bug that made a detector's illustrative docblock examples register as real ORM writes. |
| T3.3 container/collection-element taint | **Not started** | |
| T3.4 multi-source correlation | **Not started** | |
| **T4.2 resource exhaustion** | **Landed** (`cf9acc8`) | 14 entries. Fires only when a caller-controlled size reaches a bounded-cost operation with no upper-bound check — the check being exactly the fix each advisory shipped. Zero FPs on this repo's ~700 files. |
| **T4.3 code-generation as a sink** | **Landed** (`0595d0d`) | 5 entries. A new sink CATEGORY: no dangerous call exists — a file is written, the file is source, another process runs it later. |
| **T4.4 redirect / header-forwarding** | **Landed** (`0595d0d`) | 8 entries. The inverse of open-redirect: the app is the CLIENT and the danger is what its own request does when redirected. |
| **T4.5 TOCTOU on resolution** | **Landed** (`0595d0d`) | 3 entries. Took two precision tightenings, both forced by real FPs on this repo's own detector modules; final self-scan drift zero. |
| **T5.1–T5.4 business-logic authz** | **Landed** | 19 entries — the largest family. Four sub-rules (ownership, tenant-scope, branch-inconsistency, lifecycle gate), each recognising ANY `*Id` parameter rather than the `id`/`userId` heuristic that made the existing rules miss these. Only 1 self-scan delta, on the detector's own regex. |
| **Theme 6 JS/TS unit extractor** | **Landed** (`cf9acc8`) | 6 of the 10 sibling-omission entries are TypeScript. Adds brace-language unit extraction, JS spread option-bags, and camelCase guard recognition. |

### 8b. T1.1 was attempted and reverted — and the reason changes this PRD's plan

T1.1 proposed suppressing a finding once the proof gate has PROVEN it clean
(family-matched sanitizer dominating every reaching path), rather than merely
demoting it. It was implemented against exactly that signal —
`proof.verdict === 'proven-clean'`, never a bare label — and routed to the same
suppression ledger every other suppression uses.

**`bench:mutation:check` rejected it immediately: metamorphic correctness fell
from 5/5 to 2/5.** That gate requires a sanitized finding to remain PRESENT and
LABELLED across semantics-preserving rewrites; suppression removes it, which
reads as a verdict change. That behaviour is not an accident of the gate's
construction — it is `scanner/src/dataflow/CLAUDE.md`'s stated doctrine
("sanitizer entries are RECORDED, never trusted to kill taint"), enforced.

The change was reverted. The gate was NOT adjusted to accommodate it: the
mutation gate is this project's anti-overfitting control, and editing its
expectations so a new change can pass is precisely the failure it exists to
catch.

**Consequence for goal 2 (fix-discrimination 9.5% -> 80%).** That number cannot
be raised by suppressing findings on fixed code without breaking an invariant
the project treats as foundational. Two legitimate routes remain, and the
second is already demonstrated:

1. **Count a demoted finding as discriminated.** If the proof gate demotes a
   finding to a low-confidence tier on the fixed revision, arguably the engine
   *did* distinguish the two revisions and the metric — not the engine — is
   what should register it. That is a T0.2 measurement change, and it should be
   argued on its merits rather than assumed.
2. **Detectors that do not fire on fixed code in the first place.** Every rule
   added by Themes 4, 5 and 6 keys on the ABSENCE of the specific control its
   advisory's fix introduced, so it goes silent on the fixed revision by
   construction — no suppression, no invariant touched. This is the more
   durable route and the one remaining detector work should follow.

---

### Theme 6 — measured against its own exit gate, which it does not yet pass

The stated gate was "fires on ≥ 5 of the 10 known sibling-omission entries."
Measured result: **1 of 10** (1 of the 4 entries the detector is even eligible
for). Reported as a miss rather than adjusted after the fact.

Two distinct causes, both diagnosed rather than guessed:

1. **6 of the 10 entries are TypeScript**; the detector is Python-only today.
   A JS/TS unit extractor is the obvious next increment.
2. **Convention mining is file-scoped, and the convention is project-scoped.**
   `Git.check_unsafe_options` is called from `git/repo/base.py` (5 sites),
   `git/index/base.py` (2) and `git/objects/commit.py` (1). Project-wide that is
   a strong, unambiguous convention; per-file it fragments into populations of
   5, 2 and 1, and only the first clears `MIN_GUARDED_SIBLINGS = 3`. So
   GHSA-hh9p and GHSA-p538 are missed for a structural reason, not a tuning
   one — lowering the threshold would be the wrong fix, because it would weaken
   the precision control on every file rather than restore the population that
   actually exists.

**What did work, and is the reason to keep going:** on the entry it does fire
on, it reports `Repo.init()` on the vulnerable revision and goes **silent on the
fixed revision**. That is correct differential behaviour — the property the
engine as a whole currently exhibits only 9.5% of the time — achieved by a
detector that was given no signature for this bug class.

**Next increments, in order:** (a) cross-file convention mining, keyed on the
guard callee rather than the file, which addresses cause 2 without touching the
thresholds; (b) a JS/TS unit extractor, which addresses cause 1.

---

## 9. Reproducing every number in §1

```bash
cd scanner
# Pattern-only (harness default — what has always been published)
npm run bench:independent -- --json

# Deep mode forced (the configuration the harness never used)
node ../bench/independent/score-deep.mjs      # writes bench/independent/RESULT-deep.json
```

TP-quality (fix-hunk localization) and fix-discrimination were computed this session with throwaway scripts over the cached `pre`/`post` trees; **T0.1/T0.2 exist to make both first-class, committed, and gated** rather than a one-off investigation that has to be re-derived by the next person who asks the question.
