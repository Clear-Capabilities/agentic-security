# PRD: Taint Recall to 80% of the Dataflow-Shaped Corpus

**Status:** Approved — planning
**Owner:** Ross Young
**Created:** 2026-08-16
**Relationship to `docs/TAINT_ENGINE_IMPROVEMENT_PRD.md`:** that PRD set the strategy (Themes 1–6, phases P0–P4) and P0/P1 are partially executed (java/c#/kotlin IR fixes, the shared `return`-sink engine fix, the Kotlin trailing-lambda CFG extension). This PRD **operationalizes Themes 2–5 against a concrete, measured target** — 80% taint recall over the dataflow-shaped subset — using real per-family, per-entry data gathered from the live corpus rather than estimates. Where this document's findings sharpen or correct an assumption in the original PRD, this document is authoritative going forward; it does not replace the original's strategy or phasing structure.

---

## 1. Problem

A request to "get taint-only recall to 80%" is ambiguous until the denominator is fixed. Measured against the whole 215-entry `bench/cve-replay` corpus (`AGENTIC_SECURITY_BLIND_BENCH=1` forced, so no answer-key/bench-shape reading is possible):

| | entries | IR-TAINT-detected | recall |
|---|---:|---:|---:|
| Dataflow-shaped families (sqli, xss, cmdi, path-traversal, xxe, ldap, ssrf, deserialization, open-redirect, response-splitting, xpath, code-injection, ssti, prototype-pollution) | 134 | 32 | 23.9% |
| NOT dataflow-shaped (hardcoded-secret, weak-crypto/rng/hash, csrf, redos, timing-side-channel, iac-misconfig, prompt-injection, key-hygiene, static-IV, agent-tool-exec, mem-unsafe) | 81 | 1 | 1.2% |
| **Whole corpus** | **215** | **33** | **15.3%** |

The 81-entry non-dataflow bucket is categorically outside what a source→sink walker can or should ever catch — a hardcoded API key or a weak RNG call is a pattern/config check, not a flow. **The ceiling for whole-corpus taint recall is 62.3% (134/215), full stop, regardless of engine quality.** 80% of the whole corpus is not a capability gap to close; it is an incoherent target. **The correct, achievable target is 80% of the 134-entry dataflow-shaped subset — 107/134 — up from today's 32/134 (23.9%).**

### 1.1 It is not one gap — a per-family/per-entry audit found at least three distinct root causes

A blanket "add more sink catalog entries" plan would be premature. Direct inspection of ~50 miss entries (fixtures, not just the pass/fail bit) surfaced three structurally different failure modes, in roughly this order of prevalence:

**(a) Missing sink catalog coverage.** The straightforward case: the flow is real, the source is recognized, no catalog entry matches the sink call. Example: `CVE-2019-5477-py-respsplit` — `response["X-Trace"] = request.GET["trace"]` — `request.GET` **is** a cataloged Django source (`py-django-request-GET`) and it resolves correctly, but **no Python sink entry exists at all** for setting an HTTP response header (`response[...] =`, Flask's `resp.headers[...] =`). This is pure, clean catalog-addition work.

**(b) Fixtures with no recognized source at all — a corpus-authoring gap, not an engine gap.** Several LDAP/XPath fixtures pass a bare, unannotated function parameter straight to the sink with no framework call or annotation establishing it as attacker-controlled:

```java
// CVE-2018-1000134-java-ldap/pre — entire fixture
class Directory {
    void search(String uid, javax.naming.directory.DirContext ctx) throws Exception {
        ctx.search("ou=users", "(uid=" + uid + ")", new javax.naming.directory.SearchControls());
    }
}
```

`uid` is never assigned from `request.getParameter(...)`, never carries a `@RequestParam` annotation, is not called by anything in the fixture. The engine's refusal to taint it is **correct, doctrine-following behavior** — "ambiguous name resolution always refuses to guess rather than fabricate an edge" (root `CLAUDE.md`). Adding an LDAP sink entry for `DirContext.search` would not move this entry at all. **The fixture itself needs to be enriched with a realistic entry point** (a `@RequestParam` param, or a caller passing `request.getParameter("uid")`) before any engine change can help. This affects most of the LDAP and XPath misses (Java, C#, Go, Python) and is confirmed present in at least 6 of the 18 LDAP/XPath entries surveyed.

**(c) A property-assignment sink shape the catalog schema does not model.** `CVE-2020-1722-csharp-ldap`:

```csharp
var searcher = new DirectorySearcher();
searcher.Filter = "(uid=" + uid + ")";
return searcher.FindAll();
```

This session's own earlier `cs-directorysearcher` catalog entry (`match.callee: 'DirectorySearcher'`, `argIndex: 'all'`) matches the **constructor call**, which here takes zero arguments — the taint enters via a **property assignment** (`.Filter = …`) on an already-constructed object, and the actual dangerous call (`.FindAll()`) is a *third*, unrelated statement with no arguments to check. Verified directly: this entry does not fire on the real fixture. The catalog's `argIndex`-based sink model (check argument N of call to callee X) has no representation for "receiver's own field was tainted by an earlier statement, and *that* is what makes this later, argument-less call dangerous." This is a genuine, small, real catalog/engine extension, not a data-entry fix — see §4.4.

Every subsequent tier below is scoped against this three-way breakdown, not a single undifferentiated "catalog gap."

---

## 2. Goal

Raise `bench/layer-recall`'s taint recall over the dataflow-shaped subset from **32/134 (23.9%) to ≥107/134 (80%)**, while:

1. Holding precision — the existing self-scan FP-drift gate and the metamorphic/adversarial mutation gate stay green at every landing.
2. Never gaming the corpus — every entry that flips miss→hit must independently fail with `AGENTIC_SECURITY_DEEP=0` (Theme 1's existing rule) and must not rely on `AGENTIC_SECURITY_BENCH_SHAPE`.
3. Treating fixture enrichment (root cause (b) above) as legitimate, disclosed corpus improvement — making an under-specified fixture realistic is not the same as tuning a fixture to flatter a detector, and every enrichment is committed with a stated reason, same as any other corpus change.

## 3. Non-goals

- **80% of the whole 215-entry corpus.** Mathematically impossible (§1); not attempted.
- **Inflating recall by shrinking the denominator.** No corpus entry is removed, reclassified out of `dataflow-shaped`, or added purely to pad the count. New entries must be genuine, realistic vulnerability shapes that score `pre:TP post:TN`.
- **A new IR from scratch, or sound whole-program analysis.** Unchanged from the parent PRD — this document works within the existing Babel/ast/java-parser/hand-rolled-parser stack and the existing k-cap/timeout budgets.
- **Guaranteeing every one of the 134 entries becomes taint-detectable.** Some genuinely require capability this PRD's Tier 4 does not fully build (e.g. gadget-chain-shaped deserialization). 80% is the target, not 100%.

---

## 4. Tiers

### Tier 1 — Sink catalog completion for nearly-zero families

Families at or near 0% where root cause is confirmed or highly likely to be (a) missing sink coverage: **response-splitting (0/8), and the sink side of ldap-injection/xpath-injection/xxe/code-injection** wherever root cause (b)/(c) does not also apply.

Verified exact sink shapes per family (from direct fixture inspection — not `docs/`/comments, the actual `pre/` source):

| Family | Language | Sink call (verbatim from fixture) | Catalog action |
|---|---|---|---|
| response-splitting | py | `response["X-Trace"] = request.GET["trace"]` (Django `HttpResponse.__setitem__`) | **New sink**, `match.type: 'member'`-write or subscript-assign shape — needs engine support for member-subscript-assignment as a sink target (see §4.4, same family of gap as 4.4's property-assignment case, milder) |
| response-splitting | go | `w.Header().Set("X-Trace", r.URL.Query().Get("trace"))` (`net/http`) | New sink: `match.type: 'call', callee: 'Set', receiver: 'Header'`, argIndex 1 |
| response-splitting | php | `header("X-Trace: " . $_GET["trace"])` | New sink: `callee: 'header'`, argIndex 0 (string-concat detection already modeled elsewhere) |
| response-splitting | ruby | `response.headers["X-Trace"] = params[:trace]` (Rails) | Same subscript-assign shape as py — see §4.4 |
| response-splitting | kt | `resp.setHeader("X-Trace", traceId)` (Servlet) | New sink: `callee: 'setHeader'`, argIndex 1 (mirrors the C# `cs-response-addheader` entry already added this session) |
| response-splitting | java | `resp.setHeader("X-User", name)` (Servlet) | Same as kt — `java-response-setheader` |
| xpath-injection | php/go/py/rb/js | `DOMXPath::query`, `htmlquery.Find`, `lxml .xpath(...)`, `Nokogiri doc.xpath(...)`, `xpath.select(...)` | New sinks, all plain call-argument shapes, argIndex 0 or 1 depending on API |
| ldap-injection | js/py/go | `client.search(base, {filter}, cb)`, `conn.search_s(base, scope, filter)`, `ldap.NewSearchRequest(..., filter, ...)` | New sinks, plain call-argument shapes |
| xxe | js/py/go/rb/php | `libxml.parseXmlString(x, {noent:true})`, `ET.fromstring(x)`, `xml.NewDecoder(r); d.Strict=false`, `Nokogiri::XML(x){noent}`, `$doc->loadXML(x, LIBXML_NOENT)` | New sinks — **note:** most XXE fixtures encode the vulnerability as parser *configuration* (relaxed flags), not a tainted argument per se; argIndex should generally be `'all'` or the document-content argument specifically, not the config flags |
| code-injection | php/rb | `eval($code)` / `eval(code)` | New sinks — **verified currently uncataloged for both**; also needs root-cause (b)/(c) check per language (PHP's `$_GET` global-source reachability is flagged separately, §4.3) |
| code-injection | cs/go/kt | `DataTable.Compute(expr, "")`, `template.Parse(userTemplate)`, `ScriptEngine.eval(userCode)` | New sinks, plain call-argument shapes |

**Every new entry ships with a live-fire test** (tainted variant fires, an untainted/literal variant does not) per the existing `catalog-cs-p1.test.js` pattern from this session, and a `bench/self-scan/BASELINE.json` diff review (a new sink can fire on this repo's own code, e.g. any real LDAP/XPath/XXE code inside `scanner/src/` itself — unlikely but must be checked, not assumed).

**Estimated recovery: 15–20 entries** (lower than the response's earlier estimate of 25–35, because roughly half of the LDAP/XPath misses are root cause (b), not (a) — see Tier 2).

### Tier 2 — Fixture enrichment for source-less corpus entries

For every dataflow-shaped miss whose fixture has **no recognized source at all** (root cause (b)) — confirmed present in Java/C#/Go/Python LDAP and XPath entries, likely present in a subset of code-injection and command-injection misses too — enrich the fixture to wire a realistic, cataloged source into the tainted parameter. Two ways to do this, chosen per-entry based on which is more realistic for that language/framework:

1. **Add a caller.** Wrap the vulnerable method in a thin HTTP handler that calls it with a genuinely-sourced value (`request.getParameter("uid")`, `@RequestParam String uid`, `r.URL.Query().Get("uid")`). Preferred when the original disclosed CVE really was reached this way.
2. **Annotate the parameter.** Add the framework's own declared-source annotation directly (`@RequestParam`, `[FromQuery]`) where the corpus already relies on `paramAnnotations` for that language (java, cs, js — per `../ir/CLAUDE.md`).

This is **fixture work, not engine work** — zero risk to the taint engine itself, but it must be done correctly: an enriched fixture must still independently satisfy `AGENTIC_SECURITY_DEEP=0` → no match (§2.2) for any entries promoted into the `deep/` tier, and the `pre:TP post:TN` corpus gate for entries staying in `capability/`.

A **first step of this tier is a full audit**, not blind enrichment: script a pass over all Tier-1-target misses (and the command-injection/xss misses from Tier 3) checking whether the tainted variable is EVER assigned from a `matchSource`-recognized expression anywhere in the fixture file. Any fixture where the answer is "never" is a Tier 2 candidate; where it's "yes, but doesn't reach the sink" is an engine bug (Tier 3/4 territory) and must not be misdiagnosed as a Tier 2 fixture issue.

**Estimated recovery: 15–20 entries**, overlapping with and unblocking a chunk of Tier 1's LDAP/XPath/code-injection work (a Tier 1 sink entry is inert without a Tier 2 fixture fix on the same entry, and vice versa — these frequently ship as one combined commit per entry).

### Tier 3 — Command-injection and XSS depth audit

The two highest-volume families, both mid-single-digit-to-low-double-digit recall despite catalog coverage existing in some form everywhere:

- **command-injection: 5/23 (21.7%)** — catalog has cmdi-ish sinks in all 9 languages (3–14 per language) yet 18 entries still miss. Not yet root-caused per-entry the way LDAP/XPath was in §1.1 — **this tier's first deliverable is the same fixture-by-fixture audit** (source reachable? sink cataloged for this exact API? shape the parser actually lowers correctly?) applied to all 18 misses, before writing any fix.
- **xss: 2/11 (18.2%)** — **java and php have zero XSS sink entries in the catalog at all** (`grep -c` verified this session). This is closer to a pure Tier-1 gap once confirmed — likely candidates: JSP/Thymeleaf output sinks for Java, `echo`/`print` in an HTML-output context for PHP (harder to catalog precisely without excess FP risk — needs a framework-scoped receiver constraint, not a bare `echo`).

**Process, not a fixed list** — unlike Tier 1, this tier's exact catalog entries are not yet known; they emerge from the audit. Budget: audit all 18+9=27 misses first (cheap, no code changes), then batch the fixes by shape.

**Estimated recovery: ~15–20 entries.**

### Tier 4 — Remaining per-language IR/parser gaps

Even a complete catalog is inert if the parser doesn't lower the call correctly, or the engine doesn't propagate taint through the specific expression shape involved. Known, already-scoped items (from this session's investigation and the parent PRD's Theme 2):

- **Ruby: full CFG rebuild.** Statement-modifier bug drops whole methods from the IR (Day-1 prerequisite, described in the parent PRD's investigation); `case/when`, `begin/rescue/ensure`, `do...end` block-body recursion (recommend: recurse, per Rails/ActiveRecord idiom prevalence), multi-assignment lowering, recursion depth guard. Ruby sits at 1/11 (9.1%) within the shaped subset — the lowest of any language — and this is very likely why.
- **Java: chained-call CFG drop.** `Runtime.getRuntime().exec(...)` — the parser captures only the inner call (`Runtime.getRuntime()`, no args), silently dropping the outer `.exec(tainted)` invocation with the actual sink and argument. Found and explicitly deferred this session (`test/java-taint-flow.test.js` comments). Likely affects more than just `exec` — any two-hop chained call.
- **Kotlin: `?.` safe-call operator.** Confirmed this session: even a bare `conn?.execute(x)` — no lambda, no control flow — lowers to `{kind:'unknown'}`, dropping the entire statement. Affects every call form, not just the trailing-lambda work already landed. Given how idiomatic `?.` is in real Kotlin, this plausibly gates more recall than any single item in this tier.
- **Cross-cutting: no-arg method call on a tainted receiver.** Found this session (`it.toString()`, `tainted.trim()`): `engine.js`'s `exprTaint` for `case 'call'` checks only `expr.args` and the resolved callee's return-taint summary — a dotted callee string like `"it.toString"` is never parsed back to ask whether ITS OWN receiver is tainted. Not language-specific; fixing it in `engine.js` benefits every language whose IR lowers a method call to a bare dotted-string callee (all nine).
- **Cross-cutting: member-source-then-chained-call.** Found this session: `call.parameters` (Ktor) is a cataloged `member`-type source, but `call.parameters.getAll("id")` — a call whose *receiver* is that tainted member — reads as untainted. Same defect class as the item above; plausibly the same fix.
- **PHP: known deferred gaps** (from `../ir/CLAUDE.md`'s PHP row) — `match` expression unmodeled, `elseif`/`else if` chains unsupported, comment-unaware apostrophe bug drops entire-file IR, heredoc-with-brace regression.

**Estimated recovery: ~20–25 entries**, concentrated in ruby/java/kotlin/php given their current shaped-subset floor (ruby 9.1%, java 6.7%, kotlin 7.1%, php not yet isolated but likely similar).

### Tier 5 — Genuine engine depth (only if Tiers 1–4 fall short of 80%)

Held in reserve, not scheduled by default — Tiers 1–4 are estimated to reach roughly 70–78/134 (52–58%) if fully executed, still short of 107. Closing the remainder needs some of:

- **Container/collection-element taint** (`dataflow/CLAUDE.md`'s documented "what we still do NOT model" gap) — needed for `prototype-pollution` (3/3 currently miss) and likely several deserialization/xss entries where a tainted value passes through an array/object literal.
- **k>1 call-string context** (`AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`, built but flag-gated off) — graduate per the parent PRD's Theme 4 process (measured before/after, FP-budget gated).
- **Stored/second-order taint** (`stored-taint.js`) — widen scope if audit surfaces entries needing it.

This tier is **not detailed further here** — it should only be scoped in depth once Tiers 1–4 are measured and the actual remaining gap (not the current estimate) is known. Speculatively engineering Tier 5 before Tiers 1–4 land risks solving the wrong problem.

---

## 5. §4.4 — The property-assignment-sink schema gap (referenced above, detailed here)

`catalog.js`'s sink model is fundamentally **argument-based**: "check argument N (or all arguments) of a call to callee X." It has no representation for "a value assigned to the receiver's own field in an earlier statement is what makes this later, possibly argument-less, call dangerous." Confirmed real (not hypothetical) via `CVE-2020-1722-csharp-ldap` (§1.1(c)) and structurally likely to recur for `response["X"] = tainted` (Python/Ruby response-splitting, Tier 1 table above) and Java `Cookie`/builder-pattern APIs generally.

Two possible remedies, **not yet decided — this PRD flags the decision, does not make it**:

1. **Model it as member-write taint + a "risky state at call time" sink kind.** The engine already tracks member-write taint for field sensitivity (per `dataflow/CLAUDE.md` — `test/member-write-and-loop-taint.test.js` exists). A new sink `match.type` (e.g. `'call-with-tainted-receiver-field'`) would check, at the call site, whether a *named field* of the receiver carries taint per the existing access-path lattice, rather than an argument. This is a real, scoped engine change (`engine.js` + `catalog.js` schema), estimated small (a few hundred lines, one new match-type branch mirroring the existing `argIndex` dispatch).
2. **Treat it as a special-cased two-statement pattern per catalog entry** (assign-to-property immediately followed by a specific call) — cheaper to special-case per entry, but does not generalize and would need re-deriving for every new instance of the same shape.

**Recommendation for scoping (not final): option 1**, done once as shared engine work at the start of Tier 1, since the shape recurs across at least 3 confirmed families (LDAP via `.Filter=`, XXE via `.XmlResolver=`, response-splitting via `response[...] =`) and 4+ languages. Should land as its own dated sub-task with the same TDD + full-regression rigor as this session's `case 'return'` engine fix, before the Tier 1 entries that depend on it.

---

## 6. Phasing

| Phase | Scope | Exit gate |
|---|---|---|
| **P1 — Property-assignment sink support** (§4.4, engine change) | One shared engine extension, `engine.js` + `catalog.js` schema | New match-type works end-to-end on the C# `DirectorySearcher` case with a dedicated test; `test:dataflow`, self-scan, mutation gates green |
| **P2 — Tier 1 sink catalog completion** | All table entries in §4 Tier 1, for entries NOT blocked by Tier 2's fixture gap | Each entry: live-fire test + `pre:TP post:TN`; self-scan no-drift |
| **P3 — Tier 2 fixture enrichment** | Audit + enrich all source-less misses (LDAP/XPath primarily, cmdi/xss as surfaced by Tier 3's audit) | Enriched fixture still `pre:TP post:TN`, still `AGENTIC_SECURITY_DEEP=0` → miss where applicable |
| **P4 — Tier 3 command-injection/XSS audit + fix** | Audit all 27 misses, batch-fix by shape | Each fixed entry moves miss→hit in `bench/layer-recall`; no self-scan/mutation regression |
| **P5 — Tier 4 per-language IR/parser gaps** | Ruby CFG rebuild, Java chained-call, Kotlin `?.`, cross-cutting receiver-method-call taint, PHP deferred gaps | Each has an end-to-end taint test (source → hop → sink) per the `kt-taint-flow.test.js` model; full regression suite green |
| **P6 — Measure, and scope Tier 5 only if short of 80%** | Re-run `bench/layer-recall` with `AGENTIC_SECURITY_BLIND_BENCH=1`; if <107/134, scope Tier 5 in the same depth as Tiers 1–4 above using the then-current miss list (not this document's estimates) | Scorecard regenerated and committed either way |

Each phase lands as one or more independently-shippable commits (mirroring this session's per-language cadence), full regression gate (`npm test`, self-scan, cve-replay, mutation, layer-recall) before every push, `bench/cve-replay/corpus-baseline.json` and `docs/scorecard.json`/`docs/SCORECARD.md` regenerated whenever the corpus changes.

## 7. Success criteria

1. `bench/layer-recall`'s taint recall over the dataflow-shaped subset (134 entries, or whatever superset exists at measurement time if new genuine entries were added) is **≥80%**, measured with `AGENTIC_SECURITY_BLIND_BENCH=1` forced.
2. Every entry that flipped miss→hit is independently confirmed to score `pre:FN` (or no match) with `AGENTIC_SECURITY_DEEP=0` — no entry counts toward the target without this check.
3. No self-scan FP drift, no mutation-gate regression, at any phase boundary.
4. `docs/METRICS.md` / `docs/SCORECARD.md` report the dataflow-shaped-subset recall as the headline taint number going forward, with the whole-corpus number kept but clearly labeled as diluted by non-dataflow families (per the parent PRD's Theme 1 success criterion 5).
5. §4.4's property-assignment sink question is explicitly decided (option 1 or 2) and documented, not left ambiguous in the shipped code.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Tier 2 fixture enrichment is mistaken for corpus gaming | Every enrichment commit states which real-world pattern it restores (a caller, an annotation) and why the original fixture under-specified it; reviewed the same way any corpus change is reviewed under `bench/cve-replay/CONTRIBUTING.md` |
| §4.4's engine extension is scoped wrong and doesn't generalize | Build against 2 confirmed distinct shapes (C# LDAP, Python/Ruby response-splitting) before considering it done, not just 1 |
| Tiers 1–4 land but total recall lands well short of 80% | P6's re-measurement is honest and scopes Tier 5 from real data, not this document's estimates — the 70–78/134 mid-point estimate is explicitly flagged as an estimate, not a commitment |
| Ruby's CFG rebuild (Tier 4) is large enough to stall the whole PRD | Phases are independently shippable (§6) — P1–P4 can land and be measured before P5 starts; Ruby's rebuild does not block XSS/cmdi/catalog work in other languages |
| A new sink fires on this repo's own code (self-scan regression) | Every new catalog entry runs against `bench/self-scan:check` before commit, not just its own live-fire test |

## 9. Open questions

- §4.4: confirm option 1 vs. option 2 before P1 starts — needs a closer look at how many *additional* families beyond LDAP/XXE/response-splitting hit the same property-assignment shape (Java `Cookie` setters? C# `HttpWebRequest` builder patterns?) to judge whether the generalized engine change earns its cost.
- Tier 3's audit may surface that some xss/cmdi misses are actually root cause (b) or (c), not (a) — if so, some of Tier 3's estimated recovery moves into Tiers 2/P1 instead. The phase boundaries in §6 should be treated as ordering, not a strict partition of which entries belong to which tier.
- Should PHP's long-documented `$_GET`/superglobal `matchSource` reachability (referenced in `bench/self-scan/measure.mjs`'s own comments as a "separate, pre-existing gap") be re-verified as still-broken and folded into this PRD's Tier 4, or is it already fixed and the comment is stale? Not conclusively determined this session — `CVE-2017-12635-php-code-injection` was blocked by a missing sink regardless, so the source path was never actually isolated.
