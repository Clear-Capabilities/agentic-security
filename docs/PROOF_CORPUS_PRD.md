# PRD — Proof Corpus: validating the scanner against ten real open-source projects

**Status:** Proposed — nothing in this document is implemented yet.
**Version:** 1.1
**Date:** 2026-07-25
**Author:** Ross Young / Clear Capabilities Inc.
**Scope:** A new bench (`bench/proof-corpus/`) that scans ten large, real, third-party open-source repositories and produces independently reproducible evidence about language coverage, detection quality, and operational behaviour at scale — **plus** the first-class C++ IR parser required to make one of those ten an honest result rather than a caveat.
**Audience:** Engineering (scanner core) primarily; §10 defines the derived artifacts for customer, investor, and marketing audiences.

**Changelog**
- **1.1** — Added Workstream B (§6): build a first-class C++ IR parser so C++ reaches parity with the other first-class languages instead of being reported as a shallow, opt-in result. Corrected §2.3's inventory of existing C++ assets, which v1.0 understated. Re-numbered §6–§12.
- **1.0** — Initial: breadth pass + Tier-1 CVE replay.

---

## 1. Purpose

Prove — with reproducible, machine-generated evidence — that the scanner works on real-world code across the eight languages these ten repositories exercise (JavaScript/TypeScript, Go, Python, Ruby, C#, Java, PHP, C++), several licence regimes, and codebase sizes from ~100 KLOC to several million lines.

The ten targets:

| Repository | Expected primary languages | Expected licence family |
|---|---|---|
| tryghost/ghost | JavaScript / TypeScript (Node) | permissive |
| grafana/grafana | Go + TypeScript | copyleft (network) |
| apache/superset | Python + TypeScript | permissive (foundation-governed) |
| getsentry/sentry | Python + TypeScript | source-available |
| discourse/discourse | Ruby + JavaScript | copyleft |
| jellyfin/jellyfin | C# (.NET) | copyleft |
| mattermost/mattermost | Go + TypeScript | mixed (copyleft + source-available) |
| jenkinsci/jenkins | Java | permissive |
| nextcloud/server | PHP + JavaScript | copyleft (network) |
| godotengine/godot | C++ | permissive |

**Licence and language columns above are expectations, not assertions.** The runner detects both automatically from the cloned tree (§5.4) and the scorecard reports what was actually found. If a column here turns out wrong, the generated scorecard is the source of truth and this table gets corrected — not the other way round.

### 1.1 Two workstreams, one campaign

This PRD contains three pieces of work that share a single evidence base:

- **Workstream A (§5)** — the breadth pass over all ten repositories.
- **Workstream B (§6)** — a first-class C++ IR parser, so Godot is a real result.
- **Workstream C (§7)** — CVE replay against public, patched advisories on the Tier-1 subset.

A and C are measurement. B is engineering, and it exists because measurement without it produces a scorecard with a hole in it. The sequencing in §11 deliberately runs the breadth pass **before** B lands, so the C++ improvement is a measured before/after delta rather than an unfalsifiable claim.

---

## 2. Honesty preface

Four things must be stated before any of the design, because they define what this bench can and cannot claim.

**2.1 This is the follow-through on a known open gap.** `docs/SAST_SCA_IMPROVEMENT_PRD.md` §2 states plainly that the current F1 = 1.000 figure is measured on a **185-entry, self-authored corpus where we wrote both the vulnerable and the fixed sample**, and that recommendation **R16 (independent-corpus measurement) is still partial** — the harness exists, a real corpus does not. This PRD is that corpus. Until it lands, quality claims beyond regression protection remain aspirational, and this document does not permit them.

**2.2 A new bench, not an extension of the existing one.** `bench/cve-replay/` entries are deliberately minimal — `CONTRIBUTING.md` requires "one to three files" per entry and the runner reads each as a tiny project. Its own manifest concedes that synthetic shapes "overestimate how well we'd do on the real CVE because the real CVE often had distracting context the synthetic doesn't." Real repositories are exactly that distracting context. Mixing million-line trees into a corpus whose gate assumes minimal fixtures would break the gate's meaning and its runtime. Therefore: `bench/proof-corpus/` is a sibling bench with its own manifest, runner, and baseline. Nothing in `bench/cve-replay/` changes — except that Workstream B adds C++ *fixture* entries to it, which is exactly what that corpus is for (§6.11).

**2.3 Language support is not uniform, and the bench must say so.** The IR tree has first-class parsers for JS/TS, Python, Java, Kotlin, Go, PHP, Ruby, and C# (`scanner/src/ir/parser-*.js`), but flow-engine maturity is genuinely deep only for JS, Python, and Java; the rest are primarily structural. The scorecard reports a per-language **support tier** alongside every number, so no reader can mistake "we produced findings" for "we have deep flow analysis here." The tiers:

| Tier | Meaning | Languages (before Workstream B) |
|---|---|---|
| **Deep IR** | First-class parser + proven interprocedural taint | JS/TS, Python, Java |
| **Structural IR** | First-class parser, CFG produced, flow proven shallowly | Kotlin, Go, PHP, Ruby, C# |
| **Syntactic** | Pattern/brace detectors, no CFG, no call graph | **C/C++** |
| **Opt-in AST** | tree-sitter, off by default, optional deps | Rust, Solidity, Swift, Dart, C/C++ |

**Post-Workstream-B update (Godot measurement, §6.12):** C/C++ now has a first-class parser
(`parser-cpp.js`), 100% parse coverage and 130,692 resolved cross-TU call-graph edges measured on
Godot — the parser and call-graph legs of Structural IR are real and measured at scale. The tier
stays **Syntactic** in this table because §6.12 criterion 4 (an actual interprocedural taint
finding) was not demonstrated by any run in this session, and criterion 4 is named as tier-gating.
See §6.12 for the measured numbers and the root-cause note on why criterion 4 didn't materialize.

**2.4 C++ today is better than "nothing" and worse than "supported" — v1.0 of this PRD got this wrong.** The earlier revision claimed C++ had no support at all. The accurate inventory is in §6.1: there are real, tested C/C++ assets (a banned-API detector, five intra-procedural memory-safety detectors, a preprocessor). What does not exist is a `parser-cpp.js` emitting the IR shape contract, which is the thing that connects a language to the Layer-2 taint engine, the cross-file call graph, class-hierarchy analysis, SSA, and reachability annotation. C++ is therefore *detected* but not *analysed*. Workstream B closes that specific gap and nothing wider.

---

## 3. Goals and non-goals

### 3.1 Goals

- **G1 — Breadth.** All ten repositories scan to completion, deterministically, within a declared per-repo budget, emitting findings, SBOM, and SARIF.
- **G2 — Real detection.** For a strategic subset, demonstrate `pre:TP post:TN` against **already-public, already-patched CVEs** in those projects, using the projects' own release tags.
- **G3 — Honest measurement.** Publish parse coverage, finding density, and support tier per language per repo — including where they are weak.
- **G4 — Zero manual work.** The measurement campaign is one command, re-runnable, with no human triage step anywhere in the pipeline.
- **G5 — Reusable regression asset.** The bench becomes a gated, periodically re-run artifact, not a one-off marketing exercise.
- **G6 — C++ parity.** C++ moves from *Syntactic* to at least *Structural IR* tier: a first-class parser, wired into the call graph and taint engine, with parse coverage on a real multi-million-line C++ codebase measured before and after.

### 3.2 Non-goals

- **Not a vulnerability disclosure programme.** We do not publish, report, or act on findings against the current HEAD of any of these projects (§9.1).
- **Not a competitive benchmark.** This bench measures the scanner against itself over time and against ground truth. It makes no comparative claim about any other product, and no other product is named in this bench, its outputs, or its commits.
- **Not a fix/remediation exercise.** `/fix`, PoC generation, and the LLM validator are out of scope for v1. Scanning, parsing, and reporting only.
- **Not a build integration.** We never compile these projects. We parse source trees. This is what makes historical tag checkout cheap and reliable — and it is a hard constraint on the C++ parser design (§6.3).
- **Not full C++ semantics.** Workstream B targets the security-relevant subset of C++, explicitly enumerated in §6.5. Template metaprogramming, overload resolution, and vtable-exact virtual dispatch are out of scope and stay out.

---

## 4. Tiering

### 4.1 Tier 1 — deep dive (4 repos)

Chosen for language spread across the three deepest-supported flow-engine languages plus the newest parser tier, and for having substantial public advisory history:

| Repo | Language proved | Why this one |
|---|---|---|
| jenkinsci/jenkins | Java | Deepest Java flow support; long, well-documented advisory history with clean fix tags |
| grafana/grafana | Go + TypeScript | Proves the Go parser on a large production codebase; dual-language repo |
| apache/superset | Python + TypeScript | Deepest Python flow support; foundation governance; well-tagged releases |
| discourse/discourse | Ruby | Exercises the least-proven first-class parser; strongest signal per unit of effort |

Tier 1 gets: everything Tier 2 gets, **plus** CVE replay (§7).

### 4.2 Tier 2 — breadth pass (6 repos)

Ghost (JS/TS), Sentry (Python), Mattermost (Go), Jellyfin (C#), Nextcloud (PHP), Godot (C++).

Tier 2 gets: scan-to-completion, operational metrics, parse coverage, language and licence attribution, SBOM, determinism check. **Findings content is collected but not published** (§9.1).

Tier 2 is where the surprising failures will surface — Jellyfin and Godot in particular. That is the point of including them.

### 4.3 Godot's special role

Godot is simultaneously a Tier-2 breadth target and the **acceptance test for Workstream B**. It is scanned twice: once in Phase 2 with C++ at Syntactic tier, and again in Phase 4 after the parser lands. The delta in parse coverage, call-graph node count, and finding families between those two runs is the primary evidence that the C++ work did anything. Neither run is thrown away; both appear in the scorecard.

---

## 5. Workstream A — the breadth pass

### 5.1 Layout

```
bench/proof-corpus/
  manifest.json          # the ten targets, pinned commits, tier, budgets, scope filters
  runner.mjs             # orchestrator + CLI
  lib/
    clone.mjs            # blobless shallow fetch at a pinned SHA, into an out-of-tree cache
    scan.mjs             # invoke the bundled CLI, capture exit code / timing / RSS
    irstats.mjs          # parse-coverage extraction (needs the Phase 0 scanner flag)
    licence.mjs          # SPDX / LICENSE / package-metadata detection
    replay.mjs           # Tier-1 CVE replay driver (§7)
    report.mjs           # scorecard + per-repo case-study markdown emitters
  replay/<repo>/<cve-id>/manifest.json   # one file per replay case; no fixture source
  results/               # timestamped run output (gitignored except the committed summary)
  baseline.json          # gated expectations
  README.md
  CONTRIBUTING.md
```

Clones live at `~/.claude/agentic-security/proof-corpus-cache/`, **never inside the repo**. Nothing third-party is ever committed. This also keeps the licence surface clean: we hold no copy of AGPL or source-available code in our tree.

### 5.2 Acquisition

Per target: `git init` → `git remote add origin <url>` → `git fetch --depth 1 --filter=blob:none origin <pinned-sha>` → `git checkout FETCH_HEAD`.

Pinning to a full SHA rather than a branch is what makes the whole campaign reproducible — a re-run six months from now produces the same numbers. A `--refresh-pins` mode re-resolves each default branch to its current tip and rewrites the manifest, so pin advancement is a deliberate, reviewable act rather than silent drift.

Disk budget is real: ten repos with blobless clones plus Tier-1 historical tags will run into the several-gigabyte range. The runner reports cache size and supports `--prune-cache`.

### 5.3 Scanning

The bundled CLI (`dist/agentic-security.mjs`) is invoked — not `src/` — because the bundle is what users actually run, and a bench that passes on `src/` while the bundle is stale would be exactly the class of false confidence the root `CLAUDE.md` verification rules exist to prevent. The runner asserts the bundle's SHA-256 sidecar matches before starting, and refuses to run against a stale bundle.

Fixed invocation per repo: `--deterministic`, deep taint on, SBOM and SARIF emit on, OSV cache warm. Optional-dependency flags (tree-sitter) are **off** for the headline run, because a result that depends on optional deps the shipped bundle does not embed is not a result about the shipped product. A separate, clearly-labelled `--with-optional` run may be recorded alongside it for comparison.

Each repo declares in the manifest:
- `time_budget_s` — wall-clock ceiling; exceeding it is a **recorded failure**, not a silent skip
- `scope` — optional subtree filter (e.g. Godot scans first-party trees rather than vendored `thirdparty/`). Any scope narrowing is declared in the manifest, printed in the run log, and reproduced verbatim in the scorecard. **Silent scope reduction is prohibited** — an unscoped claim over a scoped scan is the single most dishonest thing this bench could do.

### 5.4 Metrics collected per repo

| Metric | Definition | Proves |
|---|---|---|
| **Parse coverage** | files for which the parser returned an IR record (regardless of function count) ÷ files in scope for that extension | *Actual* language support, as distinct from extension recognition. The headline metric. A file with an IR record but zero functions (an `__init__.py`, a constants module) is parsed, not a failure — it is tracked separately as `functionless` so it can't be mistaken for one. |
| Support tier | Deep IR / Structural IR / Syntactic / Opt-in AST, per language (§2.3) | Honest framing of every other number |
| Language mix | LOC and file count per language | That the target exercises the languages claimed |
| Licence | detected SPDX identifier(s) + source of detection | Licence-regime breadth |
| Scan wall time, peak RSS | measured by the runner, not self-reported | Operational viability at scale |
| Finding count by severity, and per KLOC | normalised density | Noise level; cross-repo comparability |
| Parser attribution | distribution of `finding.parser` | That findings come from the language engines we claim |
| Call-graph size | resolved nodes and edges, per language | That IR is *connected*, not just produced — the metric that separates Structural from Syntactic |
| SBOM component count, ecosystems | from the emitted SBOM | Supply-chain pipeline works on real manifests |
| Determinism | two consecutive runs → byte-identical SARIF | The `--deterministic` contract holds on real input |
| Exit code | captured explicitly | Gate-ability |

**Parse coverage requires a scanner change.** No current flag exposes per-file IR success. Phase 0 adds `AGENTIC_SECURITY_IR_STATS=<path>`, which writes a per-language `{inScope, parsed, functionless, functions, failures[]}` sidecar (plus a top-level `callGraph: {functions, edges, resolvedEdges, unresolvedEdges}`, not a per-language field). This is a small, additive, default-off instrumentation surface — and it is independently useful beyond this bench, since it is also the acceptance instrument for Workstream B.

---

## 6. Workstream B — first-class C++ IR parser

### 6.1 What exists today

An accurate inventory, verified against the source tree:

| Asset | What it does | Default state |
|---|---|---|
| `src/sast/cpp.js` | Banned-API rules: `strcpy`/`strcat`/`gets`/`sprintf`, format-string, `system()`, `memcpy` bounds, weak RNG, hardcoded creds. Syntactic, with context gates. | **On** |
| `src/sast/cpp-dataflow.js` | Five intra-procedural detectors: use-after-free, double-free, missing null check, alloc-size overflow, off-by-one loop. Brace-balanced function splitting + per-variable event tracking. | **Off** (`AGENTIC_SECURITY_CPP_DATAFLOW`) |
| `src/ir/cpp-preprocessor.js` | Resolves `#include "local.h"` and object-like `#define`, plus `typedef char B[N]`, so buffer-size context crossing a header boundary is recoverable. | On, used by `cpp.js` |
| `src/sast/tree-sitter-sinks.js` | AST-accurate sink detection via a C++ grammar. | **Off** + optional deps |

This is a genuine, tested foundation. `cpp-dataflow.js`'s `_findFunctions` in particular is a brace-counting translation-unit splitter written specifically because a regex approach exhibited catastrophic backtracking on real headers — that hard-won component is directly reusable.

### 6.2 The gap, precisely

There is no `parser-cpp.js` producing the IR shape contract documented in `src/ir/CLAUDE.md`:

```
{ file, functions: [{ qid, name, line, params, file, cfg: { entry, exit, nodes } }], topLevel }
```

`src/ir/index.js` dispatches on extension to a parser for `.js/.ts`, `.py`, `.cs`, `.kt`, `.go`, `.php`, `.rb`, and (async) `.java`. **C and C++ extensions are absent from both `buildProjectIR` and `buildProjectIRAsync`.** Everything downstream of the IR therefore never sees C++:

- `dataflow/engine.js` — no interprocedural taint, no source→sink flows
- `ir/callgraph.js` — no cross-file call resolution
- `ir/class-hierarchy.js` — no virtual-dispatch refinement
- `ir/ssa.js` — no SSA
- posture reachability annotation — no route/entrypoint reachability

C++ is detected but not analysed. That is the whole gap, and it is a single well-defined integration point.

### 6.3 Design choice: hand-rolled, not tree-sitter, not libclang

Three options were considered.

**Chosen — hand-rolled parser following the `parser-cs.js` / `parser-go.js` template.** Every non-Babel first-class parser in the tree is built this way: brace/paren-aware statement splitting, a `_lowerExpr` expression lowerer, a `_lowerStmt` statement lowerer, and a `_qid` stable-identifier helper. C++ gets the same shape. It has zero new dependencies, is bundled normally, works offline, and — decisively — matches the existing conventions a future contributor will already understand.

**Rejected — tree-sitter-backed.** The C++ grammar exists and would give a real AST. But `web-tree-sitter` and `tree-sitter-wasms` are **optional dependencies excluded from the bundle** — the build script passes `-e web-tree-sitter -e tree-sitter-wasms` to `ncc` — deliberately, so the committed bundle stays self-contained. Building first-class C++ support on top of them would mean C++ support is conditional on deps the shipped product does not carry — which reproduces the exact weakness this workstream exists to remove. If the bundle policy ever changes, this decision is worth revisiting; §13 tracks that.

**Rejected — libclang.** Semantically correct, and wrong for us on three counts: native bindings (against the no-native-deps posture), a required `compile_commands.json` (against the never-compile constraint in §3.2), and per-file cost incompatible with scanning a multi-million-line tree in a time budget.

The cost of the chosen option is honest and stated up front: a hand-rolled C++ parser will be less accurate than a real compiler front-end. The target is **Structural IR tier** — CFG produced, call graph connected, taint flowing through obvious paths — not compiler-grade fidelity. §6.5 draws that line explicitly.

### 6.4 Module plan

```
src/ir/parser-cpp.js        # new — the IR frontend
src/ir/index.js             # modified — dispatch .c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx
src/ir/class-hierarchy.js   # extended — C++ class/base extraction (today: Babel-only)
src/ir/cpp-preprocessor.js  # reused — feeds macro constants into expression lowering
src/dataflow/catalog.js     # extended — C++ taint sources and sinks (§6.9)
```

`callgraph.js` consumes the generic `perFileIR` shape and its resolution rules are language-neutral in structure, though its header comment and re-export handling are JS-specific; C++ needs a qualified-name resolution rule added (§6.7). `ssa.js` operates on `cfg` alone and needs no change.

### 6.5 Scope — what v1 models, and what it does not

Following the precedent of `parser-go.js`, whose header comment enumerates its own limits honestly, this list is a contract:

**Modelled:**
- Free functions; class methods declared in-class and defined out-of-line (`Ret Ns::Class::method(args)`)
- Constructors, destructors, and `static` member functions
- Parameters including references (`T&`), pointers (`T*`), `const`, and default arguments
- Declarations and assignments, including `auto`
- Calls: free (`f()`), member (`o.f()`), pointer (`p->f()`), qualified (`Ns::f()`), and `new`
- `return`, `throw`
- `if` / `for` / `range-for` / `while` / `do` / `switch` lowered as blocks, consistent with how the Go and C# parsers treat them
- String building: `operator+` concatenation, `std::string::append`, `sprintf`/`snprintf`, and `ostringstream <<` chains — all lowered to `tpl` so taint propagates through them
- `namespace` and class scope, for qualified naming (§6.6)
- Lambdas at statement position, as nested function records
- Object-like macro constants, resolved through `cpp-preprocessor.js`

**Not modelled in v1 (and stated in the module header, the way `parser-go.js` does):**
- Templates — parsed and recorded, type parameters erased; a template function yields one IR record, not one per instantiation
- Operator overloading semantics beyond the string-building cases above
- Virtual dispatch resolution to a unique target — handled approximately via CHA (§6.8), never exactly
- Exceptions as control flow — `throw` is a node; `try`/`catch` edges are not built
- Pointer aliasing beyond direct assignment — `points-to.js` exists but wiring it to C++ is explicitly deferred
- Function-like macros, token pasting, conditional-compilation branch selection (the preprocessor unions branches by design)
- `goto`, multiple inheritance vtable layout, placement new

### 6.6 Qualified naming and `qid` stability

`qid` is the cross-file identity used by the call graph, and C++ makes name collisions the norm rather than the exception — a large engine codebase will contain dozens of `parse`, `init`, and `update` methods. The C# and Java parsers already face this; C++ intensifies it with free-standing namespaces.

Rule: `qid = <file>::<Namespace>::<Class>::<name>@<line>#<sha>`, with namespace and class omitted when absent. The `sha` component follows the existing `_qid` convention of hashing the body, so an unchanged function keeps a stable id across scans while a modified one does not — which is what incremental scanning and `stableId` finding identity depend on.

### 6.7 Header/source pairing

C++ splits declaration from definition. `Foo::bar()` is declared in `foo.h` and defined in `foo.cpp`, and callers include only the header. If the call graph resolves by file-local name alone, essentially every cross-TU call goes unresolved and the call graph is worthless.

Rule: maintain a project-wide qualified-name index (`Ns::Class::method` → defining `qid`) built after all files are parsed, and resolve unresolved call sites against it before falling back to "opaque callee". Declaration-only records from headers are indexed but marked `isDeclaration`, so they never shadow the real definition. This is the single highest-leverage correctness decision in the workstream — measured directly by the call-graph-size metric in §5.4.

### 6.8 Class hierarchy

`class-hierarchy.js` is already language-neutral: `buildClassHierarchy` reads `perFileIR` and recovers class names from the qid tail's `Class.method` shape, which any parser can emit. What it lacked was any population of `extends` — the field was set to `null` at creation and nothing, for any language, ever wrote it, leaving `resolveMethod`'s inheritance walk dead code. C++ doesn't need its own extractor for this; it needs the existing module to accept a language-neutral input: an optional `ir.classes = [{ name, bases, line }]` array on the per-file IR record, which `parser-cpp.js` populates from `class D : public B` declarations.

With `extends` populated, a virtual call `p->f()` resolves to `f` on the declared class or, failing that, up the `extends` chain — the same over-approximation the JS and Java paths already use for direct definitions. Multiple inheritance is flattened to the first listed base, not the union of bases; this is a deliberate simplification (the CHA walk in `resolveMethod` follows a single chain) and is recorded as such.

### 6.9 Sources and sinks

A CFG with no taint catalogue produces no findings. C++ entries are added to the dataflow catalogue:

- **Sources** — `argv`, `getenv`, `std::cin` / `istream >>`, `read`/`recv`/`recvfrom`, `fread`/`fgets`/`gets`, `scanf` family, and HTTP/request accessors from common server libraries
- **Sinks** — `system`/`popen`/`exec*` (command injection, CWE-78); `strcpy`/`strcat`/`sprintf`/`memcpy` (buffer overflow, CWE-120/787) — these currently fire syntactically in `cpp.js` and gain a taint-confirmed, higher-confidence variant; `fopen`/`open`/path construction (path traversal, CWE-22); SQL APIs (CWE-89); `dlopen`/`LoadLibrary` (CWE-114)
- **Sanitizers** — bounds-checked copies (`strncpy`/`snprintf` with a resolvable size), `realpath`, allow-list comparisons

The relationship with the existing `cpp.js` rules matters: syntactic detection stays (it catches bugs with no reachable source), and taint-confirmed flows *upgrade* confidence on the same finding rather than duplicating it. Deduplication is by `stableId`, which is exactly what that field is for.

### 6.10 Promoting `cpp-dataflow.js`

The five memory-safety detectors are gated off by default today and enabled only inside `npm test`. They detect a class of bug — use-after-free, double-free — that a taint engine does not model at all, so they are complementary rather than superseded.

Once the IR parser lands, they can be re-hosted on real CFGs (replacing the line-stream event tracking with CFG traversal, which gives path awareness they currently lack) and the default-off gate reconsidered. **The gate flip is a decision, not an assumption:** it happens only if false-positive density on the Godot run is measured and acceptable. If it is not, the detectors stay opt-in and that is reported. Either outcome is a valid result; silently flipping it without the measurement is not.

### 6.11 Testing — the fast inner loop

Running Godot to test a parser change is a terrible development loop. The inner loop is synthetic and fast, and only the outer loop is real:

1. **Unit** — `test/parser-cpp.test.js`, asserting IR shape directly: function extraction, out-of-line method definitions, CFG node kinds, expression lowering, `qid` stability, header/source pairing. Assigned to the `test:dataflow` scope, per `scanner/CLAUDE.md`'s rule that every new test file joins a scoped script.
2. **Fixtures** — a `vulnerable/` + `clean/` pair under `test/fixtures/` per new C++ rule, per the root convention.
3. **Corpus** — C/C++ entries added to `bench/cve-replay/capability/` covering the CWE families in §6.9. This is precisely what that corpus is designed for, and it moves the standing 500-entry target forward. Entries land in `capability/` and graduate to `regression/` under the existing five-consecutive-snapshot policy. Per the root `CLAUDE.md` corpus rule, no entry is added without confirming it scores `pre:TP post:TN`, followed by `bench:cve-replay:check` → `update-baseline` → commit the regenerated baseline.
4. **Real** — the Godot re-scan, which is the acceptance test (§6.12), run once per milestone rather than per change.

### 6.12 Acceptance criteria for Workstream B

Every one of these must be demonstrated by a command run in the same session as the claim:

1. `parser-cpp.js` produces contract-conformant IR; `npm run test:dataflow` passes.
2. Parse coverage on Godot's first-party C++ tree **≥ 85%**, measured by `AGENTIC_SECURITY_IR_STATS`, up from the Phase-2 baseline. Files that fail to parse are enumerated in `GAPS.md`.
3. Call graph on Godot resolves a non-trivial fraction of cross-TU calls — the pairing rule in §6.7 demonstrably working, reported as an absolute number against the Phase-2 baseline of effectively zero.
4. At least one end-to-end interprocedural C++ taint finding: source in one translation unit, sink in another, flowing through the call graph. This is the single claim that distinguishes Structural IR from Syntactic.
5. ≥ 10 C/C++ `bench/cve-replay/` entries scoring `pre:TP post:TN`, baseline regenerated and committed.
6. No regression: full `npm test` green, and `bench:cve-replay:check` clean for all pre-existing entries.
7. Godot scan stays within its declared time budget with the parser enabled — a parser that makes the scan time out has not shipped.

If criterion 2 or 4 fails, C++ is reported as remaining at Syntactic tier and the scorecard says so. **A missed target is published, not hidden.**

**Measured result (2026-07-25, Godot @ `159701651ad44335691dcbd632d8074307074c7b`, deep mode
confirmed active — no CI env var was set):**

1. **PASS.** `npm run test:dataflow` — 410/410 green.
2. **PASS, decisively.** C++ parse coverage on the full five-directory scope: **3012/3012 = 100%**
   (152 functionless), up from a clean same-scope baseline of 0/3012 = 0% (dispatch branch
   disabled — structurally zero, not a sampling artifact). See `bench/proof-corpus/README.md`.
3. **PASS, decisively.** Call graph resolves **130,692 of 321,800 edges** (≈40.6%) on Godot,
   against a same-scope baseline of 11 resolved edges (all non-C++; C++ contributed zero
   functions and zero edges pre-parser).
4. **NOT DEMONSTRATED — published as a shortfall, not a pass.** No `ir-taint:` finding for a
   cross-TU C++ flow appeared in the live Godot scan, nor in a minimal reproduction of the
   Task 6 test's own fixture (`Util::execute` in one file, called from `run()` in another,
   `getenv` source → `system()` sink) run through the actual assembled pipeline
   (`buildProjectIR` → `runDeepAnalysis`) rather than asserted piecewise. Root cause traced to
   `src/dataflow/engine.js`: at both the assign-position and plain-call-position call sites, the
   context-sensitive callee summary computed under a tainted entry state discards the callee's
   own findings (`findings: []` in the returned summary object) — only the higher-order/callback
   invocation path forwards `inner._findings` to the caller. This is **not C++-specific**: an
   equivalent JS fixture (`helper(taintedArg)` where the sink lives inside `helper`, called at
   statement position) reproduces the identical empty result, and the project's own
   `test/fixtures/ir-taint/interproc/app.js` fixture comment already documents the limitation for
   JS ("we don't fully implement summary-based propagation across functions yet ... to exercise
   the cross-function story, the helper takes a tainted arg and the route writes the result into
   a sink in the SAME function"). The Task 6 integration test (`cpp-integration.test.js`, "end-to-end:
   taint flows from a C++ source to a sink across the call graph") proves the three components this
   workstream owns — source recognition, sink recognition, cross-file call-graph edge resolution —
   are correctly wired, to the same standard as every other Structural-IR language. What it does not
   prove, and what no live run in this session could produce for any language, is a materialized
   finding through the shared engine's plain-call summary path. Fixing that is a change to the
   cross-language taint engine, not to the C++ frontend, and is out of scope for this workstream.
5. **Shortfall, published as such — 8 of the required ≥10.** Task 7 landed 8 C/C++ corpus entries,
   all `pre:TP post:TN`, but all passing via **pre-existing syntactic rules** in `src/sast/cpp.js` —
   none exercises the IR parser, call graph, or taint catalog added by this workstream, because
   the `bench/cve-replay/` runner never enables deep mode and two of the catalog's C sinks
   (`fopen`/path-traversal, `dlopen`/untrusted-library-load) have no syntactic-rule fallback in
   `cpp.js` to fire without it. This is the verified reason two omissions remain below 10, not an
   oversight.
6. **PASS.** `npm test`: all suites green (see `bench:cve-replay:check` output below: 193/193
   baselined entries, no drift). `npm run bench:cve-replay:check`: exit 0, "no drift — 193/193
   baselined entries still pass."
7. **PASS.** Wall time 106s against a 3600s budget; `timedOut: false`.

**Net tier decision: C/C++ stays at Syntactic tier.** Criteria 2, 3 and 7 are met decisively —
parse coverage and call-graph connectivity are Structural-IR-grade — but criterion 4 is the one
this section's own rule names as tier-gating, and it was not demonstrated by any run in this
session. Per the rule above, a missed target on criterion 2 *or* 4 keeps C/C++ at Syntactic and
says so plainly, rather than promoting on the two criteria that passed. The gap is precisely
scoped (§6.12 criterion 4's root-cause note above) rather than a vague "taint didn't work" —
closing it means fixing the shared engine's callee-finding propagation, which is real, tractable
follow-up work, not a re-do of this workstream.

---

## 7. Workstream C — Tier-1 CVE replay

This is the part that proves detection rather than execution, and it is designed so that **no human ever writes a fixture or triages a finding.**

### 7.1 The mechanism

For each replay case the manifest records only: the CVE identifier, the advisory URL, the **vulnerable tag**, the **fixed tag**, and the expected CWE/family match. Everything else is derived:

1. Check out the fixed tag; check out the vulnerable tag.
2. Compute the patch's source-file set automatically: `git diff --name-only <vulnerable-tag> <fixed-tag>`, filtered to source extensions. **This derived file set is the ground truth for "where the bug is"** — the project's own maintainers defined it when they wrote the fix.
3. Scan the vulnerable tree. **Pass condition (pre:TP):** at least one finding whose `file` is in the derived set and whose `vuln` / `family` / `cwe` matches the expected pattern.
4. Scan the fixed tree. **Pass condition (post:TN):** that finding is gone — matched by `stableId`, falling back to (file, rule, CWE) when the patch moved lines.

Deriving ground truth from the maintainers' own patch is what removes the manual step. We are not asserting where the vulnerability is; the upstream fix commit is.

### 7.2 Case selection — also automated

Rather than hardcoding CVE identifiers into this document (which would bake in whatever is believed today and be wrong somewhere), Phase 5 begins with a **discovery step**: for each Tier-1 repo, enumerate published advisories from the project's own security advisory feed, and keep only cases that satisfy every mechanical filter:

- CWE falls in a family the scanner claims to detect
- The fix is tagged in a public release, and both tags fetch cleanly
- The patch touches ≤ 25 source files (large refactor-shaped fixes make the derived ground truth too loose to mean anything)
- The vulnerable code is in a language with a first-class IR parser in that repo

Every candidate that survives becomes a replay case. Its result — pass, miss, or post-fix false positive — is recorded either way. Discovery results are snapshotted into the replay manifests so re-runs need no advisory API access.

**Target: ≥ 2 replay cases per Tier-1 repo, ≥ 8 total.** A repo where zero candidates survive the filters is itself a reportable finding about coverage, and is recorded as such rather than quietly dropped.

### 7.3 Misses are the valuable output

A `pre:FN` (we did not detect a real, disclosed CVE in real code) is the highest-signal output this entire campaign can produce. Each one becomes a rule-development ticket in the gap register (§8.2) with the patch diff attached. Per `bench/cve-replay/CONTRIBUTING.md`'s tiering philosophy, replay cases are **capability-tier by default** — informational, non-blocking — and graduate into the gated baseline only once they pass.

---

## 8. Outputs

### 8.1 Committed artifacts

- `bench/proof-corpus/results/summary.json` — aggregate metrics only, no finding content
- `bench/proof-corpus/baseline.json` — gated expectations (§8.3)
- `docs/proof/SCORECARD.md` — generated roll-up across all ten
- `docs/proof/<repo>.md` — generated per-repo case study (ten files)

All are **generated**, never hand-edited. A hand-edited scorecard is a fabricated one.

### 8.2 Gap register

`docs/proof/GAPS.md`, also generated: every miss, every timeout, every low-coverage language, every unparsed C++ file, every repo where advisory filtering yielded nothing. This file existing and being non-empty is a feature. A campaign of this size that reports zero gaps has a broken harness, not a perfect scanner.

### 8.3 Gating

`bench:proof-corpus:check` compares a fresh run against `baseline.json` and fails on regression in: repo scan success, parse coverage (beyond a per-language tolerance band), call-graph size, determinism, or any replay case that has graduated to gated status. Same update discipline as the existing corpus: change → check → `update-baseline` → commit the regenerated baseline.

Because these runs are long and network-dependent, the gate is **not** wired into `npm test`. It runs on demand and on a schedule. The C++ *unit* and *corpus* tests from §6.11 are wired into `npm test` normally — they are fast and hermetic.

---

## 9. Risks and mitigations

### 9.1 Disclosure risk — the one that matters most

Scanning ten live third-party projects produces unreviewed findings against software real people run in production. Publishing those would be irresponsible, and would also be *bad evidence*, since unreviewed static findings on well-maintained code are mostly hardening opportunities rather than vulnerabilities.

**Mitigation, enforced by the harness rather than by discipline:** the report emitters have no access to finding content for HEAD scans — they consume only aggregate counts. Raw findings JSON is written under `results/raw/`, which is gitignored, and the runner refuses to emit a case study containing a file path from a HEAD scan. Published detection evidence comes exclusively from CVE replay, where the vulnerability is already public and already patched.

If a HEAD scan does surface something that looks like a genuine, serious, previously-unknown vulnerability, that is a human decision through the project's own security contact — deliberately outside this automated pipeline, and explicitly out of scope for the published artifacts. Workstream B raises this probability for Godot specifically, since new analysis depth on a large C++ codebase is exactly the condition under which a real memory-safety bug might surface. The policy is unchanged and applies with full force.

### 9.2 Licence risk in published artifacts

The set spans permissive, copyleft, network-copyleft, and source-available licences. We never redistribute code (§5.1 keeps clones out of the tree), but *case studies quoting source* would be a redistribution question, particularly for the source-available targets.

**Mitigation:** generated case studies contain no source excerpts at all — only file paths, line numbers, CWE identifiers, and counts. This costs nothing evidentially and removes the question entirely.

### 9.3 Scale

Godot and Nextcloud are large enough that timeout or memory exhaustion is a plausible outcome, and Workstream B makes Godot strictly more expensive by adding parsing and call-graph construction where there was none. Mitigations, in order: declared per-repo time budget; incremental and parallel scan flags; declared subtree scope. All three are visible in the scorecard. A repo that can only be scanned scoped is reported as *scanned scoped* — still a useful, honest result, and a performance ticket. §6.12 criterion 7 makes the C++ time budget a hard acceptance condition rather than an afterthought.

### 9.4 The C++ parser under-delivers

The realistic failure mode is not "it doesn't work" but "it parses 60% of files and resolves few cross-TU calls," leaving C++ closer to Syntactic than Structural. Real C++ is macro-heavy and template-heavy in ways the §6.5 scope deliberately does not model.

**Mitigation:** the phasing measures the Phase-2 baseline before any parser work, so partial progress is still quantified progress rather than a binary pass/fail. §6.12 criterion 2 sets a specific numeric bar, and §6.12's closing sentence commits in advance to publishing a miss. The scope list in §6.5 is a contract precisely so that "templates aren't modelled" is a known limitation rather than a discovered disappointment.

**Measured outcome:** the realistic failure mode described above did not materialize — Godot
measured 100% parse coverage and 130,692 resolved call-graph edges (§6.12). The actual shortfall
was different from the one anticipated here: criterion 4 (an interprocedural taint finding), not
criterion 2 (parse coverage). See §6.12's criterion-4 note for the root cause, which is a
pre-existing, general limitation in the shared taint engine's callee-finding propagation, not a
C++-specific parsing gap.

### 9.5 C++ false-positive blowup

Turning on new analysis over a multi-million-line codebase can produce thousands of findings, which is worse than useless — it is the failure mode that makes people distrust scanners. Finding density per KLOC is already a §5.4 metric; for C++ it becomes a *gate*. If density is wildly out of line with the other nine repos, the correct response is to tighten rules or keep `cpp-dataflow.js` opt-in (§6.10), not to ship the noise.

### 9.6 Network dependence

SCA needs OSV; replay discovery needs advisory feeds; cloning needs GitHub. All are rate-limitable and all can be down. Mitigation: warm the OSV disk cache before the run, snapshot advisory query results at discovery time, and provide `--offline` which runs everything possible from cache and marks the rest `skipped-offline` rather than passing or failing it.

### 9.7 Upstream drift

Tags get deleted, repos get renamed or archived. Pinned SHAs plus the local clone cache absorb most of this; `--refresh-pins` makes advancement explicit.

---

## 10. Audience mapping

One generated evidence base, four framings — none of which introduce a claim the harness did not measure:

| Audience | Artifact | Core claim it supports |
|---|---|---|
| Customers | `docs/proof/SCORECARD.md` — language × licence × scale matrix | "It runs on code like yours, whatever you write it in" |
| Investors | Replay results + the C++ before/after delta, plus §2's honest framing | "It finds real, disclosed vulnerabilities in real production code — and when we found a gap, we closed it and measured the difference" |
| Internal quality | `GAPS.md` + the gated baseline | Prioritised, evidence-backed rule and performance backlog |
| Marketing | Per-repo case studies | Ten concrete, named, verifiable reference points |

The investor framing is deliberately the one that leads with the limitation. A scorecard that lists its misses is far more credible than one that does not — and it is the only version consistent with §2. The C++ workstream strengthens this rather than weakening it: "we measured, found C++ shallow, built a parser, and re-measured" is a more compelling story about engineering discipline than a uniformly green table would have been.

---

## 11. Phasing

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0 — Instrumentation** | `AGENTIC_SECURITY_IR_STATS` sidecar; licence detector | Unit-tested; parse coverage and call-graph size computable on an existing fixture |
| **1 — Harness skeleton** | `manifest.json`, `clone.mjs`, `scan.mjs`, runner CLI; two easy targets (Ghost, Superset) | Both scan end-to-end; metrics emitted; determinism check passes |
| **2 — Breadth pass** | All ten targets; scorecard v1; gap register | Every repo has a recorded outcome — success, scoped success, or explicit failure. **Godot's pre-parser C++ baseline is captured and committed.** |
| **3 — C++ parser core** | `parser-cpp.js`; dispatch wiring; unit tests | Contract-conformant IR; `test:dataflow` green |
| **4 — C++ integration** | Header/source pairing, CHA extension, taint catalogue, corpus entries | §6.12 criteria 1–6 |
| **5 — Replay** | Advisory discovery + replay driver; Tier-1 cases | ≥ 8 replay cases executed with recorded verdicts |
| **6 — Reporting** | Case-study and scorecard emitters; Godot re-scan and before/after delta | All eleven documents generated, zero hand-editing; §6.12 criterion 7 |
| **7 — Gating** | `baseline.json`, `bench:proof-corpus:*` scripts, scheduled run | Gate proven in both directions: passes clean, fails on injected regression |

Phase 1 deliberately proves the harness on the two easiest targets before spending time on the hard ones. Phase 2 can publish before anything else exists — breadth evidence stands on its own, and it is what makes the C++ delta measurable later. Phases 3–4 are the only ones that touch `scanner/src/`; every other phase is bench and reporting work.

### 11.1 New npm scripts (`scanner/package.json`)

```
bench:proof-corpus                  node ../bench/proof-corpus/runner.mjs
bench:proof-corpus:breadth          … --tier breadth
bench:proof-corpus:replay           … --tier replay
bench:proof-corpus:check            … --check-baseline
bench:proof-corpus:update-baseline  … --update-baseline
bench:proof-corpus:report           … --emit-report
```

Plus `test/parser-cpp.test.js` added to the existing `test:dataflow` scope.

---

## 12. Acceptance criteria

The campaign is complete when all of the following are **verified by a command run in the same session as the claim** (root `CLAUDE.md` verification discipline applies in full):

1. 10/10 repos have a recorded terminal outcome; ≥ 8/10 scan successfully within budget, unscoped or with a declared scope.
2. Parse coverage ≥ 85% for every language on a first-class IR parser, measured on a real repo — **including C++ on Godot** once Workstream B lands. Languages below that threshold are listed in `GAPS.md` with the failing files.
3. 10/10 repos produce byte-identical SARIF across two consecutive runs.
4. 10/10 repos have an auto-detected licence and language mix in the scorecard.
5. ≥ 8 replay cases executed across the 4 Tier-1 repos, each with a recorded `pre` and `post` verdict. **The pass rate is reported, not required** — a low pass rate is a valid, publishable, honest outcome that generates backlog.
6. All seven Workstream B acceptance criteria in §6.12 are individually demonstrated, or the shortfall is published in the scorecard and `GAPS.md`.
7. `bench:proof-corpus:check` demonstrated to exit 0 on a clean run and non-zero on a deliberately corrupted baseline.
8. `npm test` and `bench:cve-replay:check` are green after all `scanner/src/` changes.
9. Eleven generated documents exist and contain no hand-written numbers.
10. No published artifact contains a finding against any repo's HEAD, and no published artifact contains third-party source.

---

## 13. Open questions

1. **Scheduled cadence** — weekly or monthly? Ten large scans is real compute. Recommendation: monthly, plus on-demand before a release that touches IR or detectors.
2. **Do replay cases graduate into `bench/cve-replay/`?** Recommendation: no. Keep the two benches separate — one synthetic and fast enough to gate CI, one real and slow. Cross-reference instead of merging. (Note this is distinct from §6.11's C++ *fixtures*, which are synthetic and do belong there.)
3. **Godot scope** — full tree including vendored `thirdparty/`, or first-party only? Recommendation: first-party only, declared, with a note that vendored code is an SCA concern rather than a SAST one.
4. **Does Godot get promoted to Tier 1 after Workstream B?** A C++ CVE replay would be the strongest possible proof the parser works on real vulnerable code. Recommendation: attempt discovery (§7.2) against Godot's advisories once the parser lands; promote only if candidates survive the mechanical filters.
5. **Does C support ship alongside C++?** The parser handles `.c` and `.h` by construction, and `cpp.js` already treats them together. Recommendation: yes, ship both, but only claim C++ in the scorecard unless a C-specific target is measured.
6. **Should the tree-sitter path be revisited if the bundle policy changes?** Recorded here so the §6.3 rejection is understood as contingent on the current `--external` build policy rather than permanent.
7. **Is Jellyfin's C# worth the same treatment?** C# is Structural tier today. Out of scope for this PRD; noted because the breadth pass will produce the evidence to decide.
