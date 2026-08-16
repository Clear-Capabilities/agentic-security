# PRD: Best-in-Class Multi-Language Taint Engine

**Status:** Approved — planning
**Owner:** Ross Young
**Created:** 2026-08-15
**Design approved:** 2026-08-15 (brainstorm session; hybrid foundation-gated approach)

---

## 1. Problem

`docs/METRICS.md` reports **IR-TAINT detects 23 of 214 corpus entries (~11%)**, with a
per-language tail that looks alarming:

| language | taint recall | catalog entries |
|---|---:|---:|
| python | 22% | 108 |
| js/ts | 21% | 47 |
| c/c++ | 18% | 18 |
| go | 14% | 32 |
| php | 9% | 26 |
| c# | 5% | 28 |
| ruby | 5% | 15 |
| java | 4% | 36 |
| kotlin | 0% | 17 |

**Two distinct causes are tangled inside that one number, and the PRD must treat
them separately.**

1. **The corpus is not taint-shaped (measurement).** With the taint engine
   switched off entirely, corpus detection falls only 210 → 204 — 204 entries are
   caught by the pattern/structural layers and never needed taint. Kotlin reads
   0% while its taint engine demonstrably works (`test/kt-taint-flow.test.js`):
   its 20 entries simply are not source→sink flows. **The benchmark cannot rise
   on engine work alone, because it barely exercises the engine.**

2. **Real per-language gaps (capability).** The same instrument that exposed the
   measurement problem also found genuine defects: java (empty `fn.calls`,
   R9), ruby (a dropped CFG statement), and c# were each at 0% for an *upstream
   IR* reason, not a taint-algorithm reason. Ruby (15) and Kotlin (17) carry
   ~1/7 of Python's catalog.

The engine is already sophisticated — field-sensitive intraprocedural taint,
value-context-sensitive interprocedural summaries, higher-order flow, recursion
via fixed point, and a 655-entry catalog. It *also* ships IFDS, points-to, k>1
call-string context, SMT feasibility, string/numeric abstract domains, and
implicit-flow — **but most are flag-gated OFF** (`AGENTIC_SECURITY_IFDS`,
`_POINTS_TO`, `_KCFA_*`, `_SMT_FEASIBILITY`, `_FORMAL`, `_IMPLICIT_FLOW`,
`_SOFT_TAINT_*`). The frontier is less "invent new analyses" and more "mature the
per-language foundations, graduate the analyses that pay off, and measure
honestly."

## 2. Goals

1. **Genuinely best-in-class taint capability**, laggards-first: bring
   java / c# / kotlin / ruby up to the js/python bar, then deepen all nine.
2. **A benchmark that reflects real capability.** Raise measured taint recall by
   (a) making the engine better and (b) making the corpus actually taint-shaped —
   never by memorization. The mutation/anti-overfitting gate stays green
   throughout; an entry counts only if the pattern/structural layers miss it.
3. **Precision is never traded for recall silently.** Every recall gain is gated
   by a taint-specific false-positive budget and the existing self-scan +
   mutation gates.
4. **Depth lands where the IR can feed it.** Advanced analyses graduate to
   default-on per-language only after that language's IR parity is proven and a
   precision gate clears.

**Non-goals:** a new IR from scratch (we mature the Babel/ast/java-parser/
tree-sitter stack we have); sound whole-program analysis (we stay
demand-driven and bounded — the k-cap and time/function budgets remain);
guaranteeing zero false negatives (impossible; we optimize measured recall under
a precision budget); gaming the corpus (explicitly forbidden — see Theme 1).

## 3. Strategy — hybrid, foundation-gated

Per-language IR quality is the prerequisite that unlocks every downstream
analysis: a points-to pass over IR that drops statements gains nothing. So the
sequence is **fix the foundation (IR + catalog) for the laggards → graduate depth
where the foundation is ready → measure honestly throughout.** Breadth (parity)
and depth (advanced analyses) are both in scope; the ordering is what makes the
depth investment pay off.

## 4. Themes

### Theme 1 — Measurement you can trust *(cross-cutting; starts in P0, never "done")*

The number moves legitimately only when the corpus exercises taint. For each
language, add corpus entries that are **real source→sink flows** and:

- score `pre:TP post:TN` on the existing corpus gate;
- **are missed when the deep engine is off** — the load-bearing check. Re-run the
  candidate with `AGENTIC_SECURITY_DEEP=0`; if it still detects, it is a
  pattern/structural entry, not a taint entry, and does not count toward taint
  recall. This single rule is what separates honest measurement from reshaping
  the corpus to flatter the number.
- pass the metamorphic + adversarial mutation gate — a semantics-preserving
  rewrite must not flip the verdict, a semantics-changing near-miss must. An
  entry that only a memorized pattern catches fails this by construction.

Deliverables: a `taint-shaped` corpus tier (or tag) with a documented minimum
per language; a `bench/layer-recall` breakout that reports taint recall **over
the taint-shaped subset** separately from the whole corpus, so the headline
number stops being diluted by 200 non-taint entries; extend
`bench/cve-replay/CONTRIBUTING.md` with the "taint-off must miss it" rule.

### Theme 2 — Per-language IR parity for the laggards (java, c#, kotlin, ruby)

Taint is only as good as the IR it walks. For each laggard, audit and close the
IR gaps that starve the taint walker — the same class as the R9 Java `fn.calls`
defect and the Ruby dropped-statement defect:

- **Call-graph edges** — every call expression emits a resolvable `fn.calls`
  edge (the R9 fix pattern; verify no sibling parser has the same hole).
- **Assignment lowering** — every `x = <rhs>` and destructuring/multiple-assign
  form produces an IR assign node the walker's `case 'assign'` sees (Ruby's
  `f, _ = ...` and `case 'call'`-only sink checking is the known trap).
- **Member/field resolution** — access paths (`a.b.c`, subscripts) survive into
  the IR so field sensitivity actually distinguishes `user.password`.
- **Control-flow body recursion** — sinks nested in `if`/`try`/`for`/`switch`/
  `using`/`lock` bodies are reached (the R8 fix class across four languages).
- **Parameter annotations** — the `paramAnnotations` side-channel is populated
  for Spring/ASP.NET/NestJS-style declared-parameter sources (R14a).

Each language ends this theme with a committed end-to-end
`source → assignment hop → sink` taint test modeled on
`test/kt-taint-flow.test.js`, plus at least one taint-shaped corpus entry
(Theme 1). Acceptance is per-language: the test detects, and it does **not**
detect with the deep engine off.

### Theme 3 — Catalog coverage parity

Ruby and Kotlin carry ~1/7 of Python's catalog; that alone caps their recall.
Systematically cover each language's dominant frameworks for all three kinds —
`source`, `sink`, `sanitizer`:

- **Ruby** — Rails (`params`, `request.*`, `cookies`, `session`) sources; ActiveRecord raw SQL (`where("...#{}")`, `find_by_sql`, `execute`), `system`/`` ` ``/`eval`/`send`, `render inline:`, `redirect_to` sinks; Rails sanitizers (`sanitize`, `ActiveRecord::Base.sanitize_sql`, strong-params).
- **Kotlin** — Ktor (`call.parameters`, `call.receive`) and Spring-Kotlin sources; JDBC/Exposed raw SQL, `Runtime.exec`/`ProcessBuilder`, reflection sinks; the Java sanitizer set (`PreparedStatement`, encoders) shared where the ABI matches.
- **C#** — ASP.NET Core (`[FromQuery/Body/Route/Header]`, `Request.*`) sources; `SqlCommand`/`DbCommand` string SQL, `Process.Start`, `CSharpScript.EvaluateAsync`, deserializers sinks; parameterized-command + encoder sanitizers.
- **Java** — Spring MVC + Servlet sources; JDBC/JPA/Hibernate raw SQL, `Runtime.exec`, SpEL/OGNL/Groovy eval, XXE factories sinks; `PreparedStatement`/OWASP-encoder sanitizers.

Every sanitizer entry declares its `appliesTo` family so the existing
sanitizer-gate discipline holds (an HTML escaper must not silence a SQLi).
Coverage is measured against a per-language framework checklist committed
alongside the catalog, not by raw entry count.

### Theme 4 — Graduate advanced analyses to default-on (where the foundation is ready)

Take the built-but-gated analyses and turn them on by default per-language, each
behind a measured on/off decision (recall gain vs. FP-budget cost), never a
hunch:

- **k>1 call-string context** (`k2-summary-cache.js`, `AGENTIC_SECURITY_KCFA_*`)
  — distinguish two call paths that reach a helper with the same tainted-arg
  shape. Today they share a summary (k=1 value-context).
- **Points-to / aliasing** (`points-to.js`) — so `b = a; sink(b)` and container
  aliasing propagate. Prerequisite for accurate field sensitivity across
  assignments.
- **IFDS-precise** (`ifds-precise.js`, `ifds.js`) — the precise tabulation path
  for the languages whose IR can feed it.
- **Container / collection element taint** — a tainted value put into a
  list/map/array and later read out stays tainted (a top FN source in real code).
- **Better sanitizer & proof modeling** — extend `proven-clean.js` /
  `sanitizer-proof.js` beyond SQL parameterizers to per-family proofs.

Each graduation ships with: a before/after per-language recall+precision
measurement, a self-scan run (no new FP drift), a mutation-gate run, and an
explicit default-on/off recommendation. An analysis that raises recall but
blows the FP budget stays opt-in and says so.

### Theme 5 — Cross-function, cross-file, and stored (second-order) taint depth

- **Cross-file interprocedural taint** per language — flow that spans module
  boundaries, not just within a file (verify each laggard's call graph resolves
  cross-file edges after Theme 2).
- **Stored / second-order taint** (`stored-taint.js`) — user input written to a
  store (DB/file/cache) and later read into a sink. A major real-world class the
  intraprocedural model misses.
- **Higher-order / framework callback flow** — middleware, route handlers,
  event handlers, and ORM hooks where the framework, not the app, invokes the
  tainted-parameter function.

### Theme 6 — Precision as a first-class constraint *(the guardrail for 2–5)*

- **A taint-specific false-positive budget.** Extend the self-scan precision
  harness (`bench/self-scan`) with a taint-only FP ceiling per language; any
  theme that pushes recall must keep FPs under budget or the change is rejected.
- **A per-language taint scorecard** — recall (over the taint-shaped subset) and
  precision, published in `docs/METRICS.md`, updated at the end of every phase,
  and gated so a regression fails the build.
- **Recall-preserving discipline stays.** New precision gates demote confidence,
  never severity, never silent deletion — the standing convention for
  `proof-gate.js` / `falsification.js` / `sanitizer-gate.js`.

## 5. Phasing

| Phase | Scope | Exit gate |
|---|---|---|
| **P0 — Measurement + guardrails** | Theme 1 harness (taint-shaped tier + "taint-off must miss it" rule) and Theme 6 FP budget + per-language scorecard. | Scorecard publishes a per-language taint recall/precision baseline over the taint-shaped subset; FP budget enforced in a gate. |
| **P1 — Laggard IR parity** | Theme 2 for java, c#, kotlin, ruby. | Each has an end-to-end taint test that detects and is missed with deep off; ≥1 taint-shaped corpus entry each. |
| **P2 — Catalog parity** | Theme 3 for the four laggards (then a pass over go/php). | Per-language framework checklist met; sanitizer families declared; no self-scan FP regression. |
| **P3 — Depth graduation** | Theme 4: graduate k>1, points-to, container taint, per-family proofs where ready. | Each graduated analysis has a committed before/after measurement and clears the FP budget + mutation gate. |
| **P4 — Cross-file / stored / higher-order** | Theme 5. | Cross-file + stored-taint tests per language; measured recall lift on the taint-shaped subset. |

Each phase ends by regenerating the per-language scorecard and committing it, the
same discipline `npm run scorecard` already enforces for the accuracy scorecard.

## 6. Success criteria

1. **Taint recall over the taint-shaped subset** (not the diluted whole-corpus
   number) rises substantially per phase, laggards first — with java, c#,
   kotlin, and ruby each moving off the 0–5% floor to a double-digit,
   parity-track figure.
2. **Every added corpus entry is proven taint-only** — detected with the deep
   engine on, missed with it off — and the mutation gate stays green.
3. **No precision regression** — the taint FP budget holds across all nine
   languages at every phase boundary; self-scan and mutation gates green.
4. **Each graduated analysis carries its evidence** — a committed before/after
   recall+precision measurement justifying its default-on/off state.
5. **The headline metric stops lying** — `docs/METRICS.md` reports taint recall
   over the taint-shaped subset separately from whole-corpus detection, so the
   number tracks capability rather than corpus composition.

## 7. Risks

| Risk | Mitigation |
|---|---|
| "Raise the number" collapses into corpus gaming | Theme 1's "taint-off must miss it" rule + the mutation gate; an entry a memorized pattern catches cannot count. |
| Recall gains quietly cost precision | Theme 6 FP budget is a hard gate, per language, at every phase boundary. |
| Graduating an analysis (points-to, k>1) blows the time/function budget | Each stays behind the existing `DEEP_TIMEOUT_MS` / `DEEP_FN_LIMIT` / `KCFA_MAX_CONTEXTS` caps; graduation includes a walltime measurement, and an analysis that can't stay in budget stays opt-in. |
| Laggard IR fixes regress a currently-green language | Every IR change runs the full `test:dataflow` + `test:sast` + self-scan + corpus + mutation + layer-recall gates before it lands. |
| Depth work starts before IR is ready and wastes effort | Phasing forbids it: P3 depth is gated on P1 IR parity per language. |
| Scope is large and could stall | Phases are independently shippable; each delivers a measurable per-language lift and updated scorecard, so value lands incrementally. |

## 8. Open questions

- Should the taint-shaped corpus tier live inside `bench/cve-replay` as a new
  tier, or as a sibling `bench/taint-recall` corpus? (Leaning: a tagged subset
  inside cve-replay, so one gate covers it.)
- Which go/php framework gaps (Theme 3 second pass) are worth pulling earlier if
  a laggard phase finishes under budget?
- Is there appetite to add a tenth language (rust/swift via tree-sitter) once the
  nine are at parity, or is depth-on-nine the ceiling for this PRD?
