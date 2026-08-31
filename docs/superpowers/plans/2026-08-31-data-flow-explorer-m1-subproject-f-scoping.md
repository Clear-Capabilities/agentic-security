# Sub-project F — scoping report (JS/TS lineage benchmark corpus)

**Status:** research/scoping only, no implementation code or fixtures. Written
to ground a subsequent real implementation plan for `bench/data-lineage/`.

**Binding starting points:** PRD §22.2 ("Benchmark expansion," lines 1529-1541),
§25's AC-01/AC-02/AC-07/AC-11 (lines 1596-1652), §26's Milestone 1 exit gate
("AC-01, AC-02, AC-07, AC-11, and schema completeness pass on the
supported-language corpus," line 1796), and the parent Milestone 1 scoping
doc's own §3/§5/§6 recommendation to treat this as its own sub-project
"modeled on `bench/cve-replay/`'s baseline-gated pattern."

---

## 1. What `bench/data-lineage/` contains today — confirmed unchanged

```
bench/data-lineage/
  README.md
  fixtures/
    js-api-to-external-http-cleartext/{source.js, expected.json}
    js-api-to-log-masked/{source.js, expected.json}
    js-api-to-log-raw/{source.js, expected.json}
  perf/
    generate-synthetic-graph.mjs
    runner.mjs
```

**Exactly 3 fixtures**, confirming the parent scoping doc's own "nowhere near
this scale" measurement is still accurate. Each is a directory with:
- `source.js` — a minimal, single-flow JS file.
- `expected.json` — hand-labeled ground truth: `language`, `dataClass[]`,
  `sourceCategory`, `sinkCategory`, `expectedProtection` (an object keyed
  `transit`/`handling`), `expectedTransformKind`, `notes`.

Example (`js-api-to-log-masked/expected.json`, AC-02's own worked example):
```json
{
  "language": "js", "dataClass": ["PCI"],
  "sourceCategory": "http-body", "sinkCategory": "log",
  "expectedProtection": { "handling": "protected" },
  "expectedTransformKind": "mask",
  "notes": "maskCard() applied to every feasible path before logger.info()"
}
```

**No runner exists yet.** The README's own closing line names it explicitly:
*"Milestone 1's DFG-018 mass-authors the remaining ~194+ entries against it,
plus the runner/checker script (`bench/data-lineage/runner.mjs`, mirroring
`bench/cve-replay/runner.mjs`'s pre/post scoring shape) once the lineage
engine exists to score against."* That engine (Sub-project E) now exists.
This IS "DFG-018" in the PRD's own numbering — Sub-project F is the increment
that closes it.

`perf/generate-synthetic-graph.mjs` + `perf/runner.mjs` already exist and are
unrelated to corpus construction — they synthesize an arbitrary-size graph for
performance testing, not accuracy scoring. This is Sub-project G's asset
("light performance harness"), already partially built; not F's job.

---

## 2. §22.2's 9 bullets, checked against what's actually shipped

| # | Requirement | Achievable with A-E as shipped? |
|---|---|---|
| 1 | 100 positive field flows | ✅ Yes — fixture authoring, no engine gap |
| 2 | 100 clean/negative or protected flows | ✅ Yes — same |
| 3 | Every supported language | ✅ JS/TS only per §22.1's implementation order (Milestone 1 has not attempted Python/Java/C#/Go/Kotlin/Ruby/PHP for lineage) — **scope this corpus to JS/TS only**, matching the engine's own current support surface. Not a gap; a correctly-scoped boundary. |
| 4 | Every source and sink category | ✅ Partially yes, with a measured ceiling. D2/D3 shipped 14/21 reachable `SOURCE_CATEGORIES` and 10/29 reachable `SINK_CATEGORIES` (`DESIGN_REGISTRIES.md` §7.2, re-confirmed by D5). A corpus entry per REACHABLE category is achievable; per UNREACHABLE category it is definitionally not (there is no catalog entry to trigger it) — mirrors D5's own corrected exit criterion exactly. |
| 5 | direct/aliased/cross-file/interprocedural/serialized/DB/queue/API/AI paths | ⚠️ Mixed. direct/aliased/cross-file/interprocedural/DB/queue/API: ✅ achievable (Sub-projects A-D shipped real field-identity, interprocedural summaries, and store/queue/external categories). **serialized**: not directly modeled — no dedicated "serialization boundary" node/edge concept exists in `schema.js`'s `MAPPING_TYPES` beyond `serialization`/`deserialization` as an edge mapping type (noted in D4's own module row: "`JSON.stringify`/`JSON.parse` are NOT cataloged as `encode`/`decode`... `MAPPING_TYPES` already carries `serialization`/`deserialization`"), so a serialized-path fixture is buildable and should reach that mapping type, but has never been proven end-to-end. **AI**: source-side reachable (3 categories via 8 MCP entries); sink-side **NOT reachable at all** — see §4 below, this is AC-07's blocker. |
| 6 | masked/hashed/tokenized/encrypted/weakly-encrypted/branch-partial/reversed transformations | ⚠️ Mostly yes, one gap. D4's `transform-catalog.js` recognizes `mask`/`hash`/`tokenize`/`encrypt`/`decrypt`/`encode`/`decode`/`truncate`/`redact`/`aggregate`/`normalize` — covers masked/hashed/tokenized/encrypted directly. **"weakly-encrypted" and "reversed"** are not `TRANSFORM_KINDS` values at all (the enum has no confidence-graded encryption strength, and "reversed" — i.e., a transform later undone — has no representation) — these need either a corpus entry using an already-weak algorithm recognized generically as `encrypt` (accepting the corpus can only assert `kind: 'encrypt'`, not "weak," since D4 deliberately never emits a strength judgment) or are simply unsatisfiable as literally worded until a later increment adds that judgment. **"branch-partial"** (§6.2's AC-12 shape: one branch encrypts, one doesn't) IS structurally representable via two flows to the same sink sharing a `dataElementId` with different `transformationIds` — the graph has no single field asserting "this data element reached this sink via a mix," but a corpus checker can compute it from the flow list. |
| 7 | HTTPS/cleartext/cert-disabled/dynamic-scheme/proxy-terminated/unknown transport | ❌ **Not achievable at all.** `edge.protection` is unconditionally `emptyProtection()` (`graph-builder.js:425`) and `edge.protocol.destinationResolution` is always `'unknown'` (`graph.limitations` already discloses "External destinations are not resolved (FR-202 is Milestone 2)"). None of these six transport states can be asserted against real engine output today — this bullet is **entirely Milestone 2's job** (Milestone 2's own deliverables list "transit, at-rest, and handling analyzers" and "cross-boundary normalization"). A corpus entry can be AUTHORED now (fixture + `expected.json`'s `expectedProtection` field, exactly as the 3 seed fixtures already do) but cannot be SCORED until Milestone 2 ships. |
| 8 | dynamic destinations and unsupported-candidate cases | ✅ Achievable today. FR-203 (destination-unresolved, E4) and the `unsupported`/`process` node kind (D2/D3, AC-11's coarse half) are both real, shipped mechanisms with real assertable output shapes. |
| 9 | policy-permitted and policy-prohibited flows | ❌ **Not achievable at all.** `flow.policyVerdict` is unconditionally `'not_evaluated'` (`graph-builder.js:463`, confirmed by direct read) — there is no policy-evaluation capability anywhere in `src/lineage/`. Milestone 2's own deliverables list "policy and governance integration" as future work. Same treatment as bullet 7: author now, score later. |

**Net measured conclusion:** of §22.2's 9 bullets, **6 are fully achievable
against Sub-projects A-E's shipped output today** (1, 2, 3-as-scoped, 4-as-
reachable, 5-except-AI-sink, 8), **1 is mostly achievable with one enum gap**
(6), and **2 are structurally unscoreable until Milestone 2** (7, 9) — not a
corpus-authoring problem, an engine-capability gap. This mirrors exactly the
kind of "checklist item not satisfiable by construction" finding D1 made for
D5's exit criterion and E1 made for its own escalations — recorded here so
Sub-project F's own scoping doesn't rediscover it mid-implementation.

---

## 3. `bench/cve-replay/`'s pattern — the named model, and how it maps

Read `bench/cve-replay/CONTRIBUTING.md` in full. Its shape:
- Three tiers by directory: `regression/` (CI-gated, must stay F1=1.0),
  `capability/` (tracked, not gated — work targets), `deep/` (needs
  `AGENTIC_SECURITY_DEEP=1`).
- Each entry: `manifest.json` (cve/cwe/family/language/summary/`expected:
  {file, vuln_match}`/source/added_at) + `pre/` + `post/` fixture pairs.
- **Scoring is binary presence/absence**: pre MUST produce a finding matching
  `vuln_match` against `finding.vuln`/`.family`/`.cwe`; post MUST NOT.
  `runner.mjs`'s `_tally` hardcodes this exact TP/FN shape — there is
  **no way to express an inverted "expect clean" entry today** (confirmed by
  CONTRIBUTING.md's own documented, still-open blocker on this point).
- Baseline-gated: `corpus-baseline.json` records the expected verdict per
  entry; `npm run bench:cve-replay:check` fails on drift; graduation from
  `capability/` to `regression/` is a 5-consecutive-pass manual promotion.

**Lineage needs a structurally different scoring model, not a copy.**
CVE-replay asks "is this vulnerable, yes or no" (binary). A lineage corpus
entry asks "does the graph correctly REPRESENT this flow's category/
transform/coverage" (a shape-match, not a boolean). The 3 existing seed
fixtures already got this right independently: `expected.json` names the
exact fields a passing check must find in the built graph
(`sourceCategory`, `sinkCategory`, `expectedTransformKind`,
`expectedProtection` — the last of which, per §2's finding, is currently
unscoreable and should be treated as forward-looking/Milestone-2-deferred
metadata, not asserted by F's own runner).

**Recommended lineage scoring contract** (for the subsequent implementation
plan to formalize, not decided here): for each fixture, run
`buildGraphWithCoverage` (or `buildLineageGraph` from the now-shipped
`lineage/index.js`), then assert:
1. A node exists whose `subtype === expected.sourceCategory` with a
   `dataElementIds` entry matching a data element whose `dataClasses`
   intersects `expected.dataClass`.
2. A node exists whose `subtype === expected.sinkCategory`.
3. A flow connects them (`flow.source`/`.sink` resolve to those two node
   ids) — or, for a deliberately-disconnected fixture, NO such flow exists
   AND the sink/source node is still present with a coverage reason (AC-11).
4. If `expected.expectedTransformKind` is non-null, the flow's
   `transformationIds` resolve to a transformation with that `kind`.
5. `expected.expectedProtection` is recorded but NOT asserted against
   `flow.protectionSummary`/`edge.protection` until Milestone 2 — asserting
   it now would either always fail (protection is never assessed) or force
   the corpus to lie about what Milestone 1 can prove.
Tiering: mirror cve-replay's `regression/`/`capability/` split — categories
already proven end-to-end by D5's real-code tests are `regression/`
candidates (should score clean immediately); anything touching the two
Milestone-2-blocked bullets (7, 9) or the AC-07 AI-sink gap (below) is
`capability/`, tracked but not gated, exactly like cve-replay's own treatment
of "entries we're working toward."

---

## 4. AC-01/AC-02/AC-07/AC-11 as concrete, checkable assertions

**AC-01 (PCI to multiple sinks).** "req.body.card_number flows to a logger, a
database column, and an external payment API... each sink shows its own
handling/transit/at-rest verdict." The FLOW-MULTIPLICITY half is fully
provable today: one `dataElementId` (or three data elements sharing a
`dataClasses: ['PCI']` tag) reaching three DIFFERENT sink nodes is exactly
what `buildGraphWithCoverage` already produces on a real 3-sink fixture (D5's
own real-code tests already exercise `database`/`log`/`external-api`
categories independently; a combined fixture just needs to route ONE seed
into all three). The "each sink shows its own... verdict" half is the SAME
Milestone-2 gap as §2 bullet 7 — the verdict fields exist on the schema and
are populated with the correctly-honest `not_assessed`/`unknown` placeholder,
which IS itself checkable (a corpus assertion can require `protectionSummary
=== 'not_assessed'` today, proving the placeholder is honestly disclosed
rather than silently omitted) but cannot assert a REAL verdict value.
**AC-01 is satisfiable at the "graph correctly shows 3 distinct paths from
one field" level; the per-sink verdict clause is Milestone 2's.**

**AC-02 (masked vs raw log differ).** Already proven, twice: `graph-builder.js`
CLAUDE.md row + this session's own E1 escalation fix (`engine.js`'s
receiver-identity bug) both used this EXACT fixture (`js-api-to-log-masked`)
as the worked example, and it now produces two real, structurally-distinct
flows (masked: `mappingType: 'transformation'`, `transformationIds:
[<mask-transform-id>]`; raw: `mappingType: 'identity'`, empty
`transformationIds`) via `source-seeding.test.js`'s own `E2/6a`/`E2/6b`
regression tests. **AC-02 is fully satisfiable and already has a proof
point** — F's job is to formalize this specific fixture pair into the corpus
format with a runner assertion (`masked.transformationIds.length > 0 &&
raw.transformationIds.length === 0`), not to build new capability.

**AC-07 (AI + regulated data intersection).** See §5 — currently blocked.

**AC-11 (disconnected sources/sinks stay visible with a coverage reason).**
Already proven structurally: `graph-builder.js`'s own header states "AC-11's
coarse half: a sink node exists whether or not anything reached it. A
disconnected sink is a node with no flow, never absent" and this is backed
by `graph.coverage.sinks.disconnected`/`.sinks.unsupportedSites` (E4) plus
every minted node's own non-null `coverageReason`/`reason` field. **AC-11 is
fully satisfiable today** — F needs one or two dedicated fixtures (a matched
sink nothing reaches; a matched-but-unsupported/`process`-kind sink) plus a
runner assertion that the node exists in `graph.nodes` with
`coverageStatus`/reason populated even though no flow connects it.

---

## 5. AC-07 — the real, quantified blocker, and a genuine scope-reducing finding

**Confirmed, re-measured against the live registries (not copied from
`DESIGN_REGISTRIES.md`'s own prose):**
```
$ grep -n "ai-model-provider\|ai-agent\|ai-tool\|ai-vector-store\|ai-memory\|ai-training\|ai-evaluation\|ai-telemetry\|ai-local-model" src/lineage/sink-registry.js
```
All nine `ai-*` values appear ONLY inside `CATEGORY_NODE_KIND`/
`CATEGORY_EXTERNALITY` (the vocabulary tables) — **zero rows in `CWE_MAP`**
map to any of them. `dataflow/catalog.js` (the underlying source of truth
`sink-registry.js` reclassifies) has **zero** entries mentioning
`anthropic`/`openai`/`bedrock` at all (`grep` returns nothing). This confirms
`DESIGN_REGISTRIES.md`'s own finding exactly: **AC-07 is not satisfiable by
reclassification — there is no existing sink detection to reclassify.**

**The scope-reducing finding: real AI-provider call-site detection already
exists elsewhere in this codebase, just not integrated with `dataflow/`.**
`scanner/src/posture/aibom.js`'s `PROVIDER_PATTERNS` (regex-based, source-text
matching, not IR/CFG-based) already recognizes real call shapes:
```js
{ provider: 'openai', re: /(?:openai|client|oai)\.(?:chat\.)?completions\.create\s*\(\s*[{(]\s*[^{}]*?model\s*[:=]\s*['"]([^'"]+)['"]/g }
{ provider: 'anthropic', re: /(?:anthropic|client|claude)\.(?:messages|completions)\.create\s*\(\s*[{(]\s*[^{}]*?model\s*[:=]\s*['"]([^'"]+)['"]/g }
{ provider: 'bedrock', re: /InvokeModelCommand\s*\(\s*\{[^{}]*?modelId\s*:\s*['"]([^'"]+)['"]/g }
```
plus Vercel AI SDK, LangChain, and several more, and a separate package-name
allowlist for AI-BOM inventory purposes. **This is a real, proven catalog of
the exact callee SHAPES (`.messages.create`, `.chat.completions.create`,
`InvokeModelCommand`) AC-07's own worked example needs** — but it is a
disconnected posture module (regex over raw source text for inventory/BOM
purposes), not a `dataflow/catalog.js` entry the lineage sink registry can
reclassify. **Closing AC-07 does NOT require inventing AI-sink detection from
scratch; it requires PORTING `aibom.js`'s already-validated provider patterns
into `dataflow/catalog.js` as real CATALOG sink entries** (receiver-scoped,
matching this catalog's existing `match.receiver`/`match.callee` convention
— e.g. `{callee: 'create', receiver: '^anthropic', receiverBase: '.messages'}`
or the flat-string equivalent other parsers use), each with a CWE (there is
no natural CWE for "sent regulated data to an AI provider" — a new synthetic
family/CWE convention, or reuse of an existing sensitive-data-exposure CWE
like CWE-359, needs a deliberate choice), then a `CWE_MAP` row mapping that
CWE to `ai-model-provider`. This is bounded, scoped engineering work — a
real increment, not a research problem — but it is **new catalog + registry
work, squarely outside Sub-project F's own "author fixtures against what
already exists" charter.** `sast/llm-app.js` was found in the same search
and may carry additional, currently-unread AI-call detection worth checking
before this work starts, but was not read in this pass (flagged, not
resolved).

**Recommendation: this bridging work is Sub-project H's job, not F's.** F
authors and scores everything §2's table marks achievable; the AI-sink half
of AC-07 is a `capability/`-tier corpus entry (source-side already partially
provable via the 3 reachable `ai-*` SOURCE categories; sink-side blocked)
until H — or a dedicated increment H spins off — closes the catalog gap
identified above. This report does NOT recommend H attempt it silently;
H's own scoping must decide explicitly whether AC-07 blocks Milestone 1's
exit gate or whether the gate's own wording ("AC-07... pass on the
supported-language corpus") gets a disclosed, documented exception the way
D5's own corrected exit criterion did for unreachable categories.

---

## 6. Recommended increment breakdown

**Sub-project F is corpus construction + a scoring runner — nothing here
touches `src/lineage/` production code.** Recommended increments:

- **F1 (design + the runner/checker script).** Formalize §3's scoring
  contract above into `bench/data-lineage/runner.mjs` (mirroring
  `cve-replay/runner.mjs`'s CLI/exit-code shape, NOT its pre/post tally
  logic — a genuinely different scorer, per §3's finding) plus a
  `corpus-baseline.json` equivalent. Absorb the 3 existing seed fixtures as
  the first proof the runner works end-to-end. This is a design-and-
  implementation task needing real judgment (the exact assertion contract),
  matching this session's own precedent for D1/D4/E1-shaped increments.
- **F2-Fn (fixture authoring by category, batched).** Given the diversity
  requirement (direct/aliased/cross-file/interprocedural/DB/queue/API × 14
  reachable source categories × 10 reachable sink categories × transform
  kinds), a SMALL NUMBER of large, batched "author N fixtures for dimension
  X" increments is the right shape, not 194 individual tasks — mirrors this
  session's own "batch small same-shape work" SDD precedent. **A fully
  programmatic generator (like `fixtures/build-flagship-fixture.mjs`) is
  NOT recommended for the corpus's diversity dimensions** — `build-flagship-
  fixture.mjs` generates ONE deterministic reference graph from a fixed
  design, not many independently-labeled ground-truth fixtures; the
  diversity axes here (aliased vs. direct, same-file vs. cross-file,
  intra- vs. inter-procedural) are exactly the axes this codebase's own
  real-parser test suites (`engine-integration.test.js`, etc.) already prove
  needs hand-authored source shapes to genuinely exercise, not templated
  substitution. A LIGHTWEIGHT generator could plausibly help for the sheer
  volume of near-identical "one category, one language, minimal shape"
  entries (the 100+/100+ floor), but the STRUCTURALLY interesting fixtures
  (aliasing, cross-file, interprocedural chains) need real authorship.
  Recommend: hand-author the structurally-distinct fixtures first (roughly
  matching D5's own 24-category real-code proof set, ~30-40 entries),
  measure how much of the 200-entry floor remains, THEN decide whether a
  generator closes the volume gap for the remainder.
- **F-final (exit-gate wiring).** Wire `npm run bench:data-lineage:check`
  into the same places `cve-replay`'s check is wired (package.json script,
  eventually the pre-push gate once the corpus is mature enough not to be
  perpetually red on `capability/`-tier entries) — likely folds into H
  rather than being F's own last step, since H owns "exit-gate closure."

**Sub-project G** (comparison report + light performance harness) is
explicitly NOT F's job — `bench/data-lineage/perf/` already has a head
start (`generate-synthetic-graph.mjs`/`runner.mjs`) that F should leave
untouched.

**Sub-project H** (exit-gate closure) inherits: the AC-07 catalog-bridging
work (§5), the explicit ruling on whether Milestone 2-blocked bullets 7/9
constitute a disclosed gate exception or a hard blocker, and wiring the
`capability/`→`regression/` graduation policy once F's corpus stabilizes.

---

## 7. Open questions for the implementation plan

1. **The exact runner scoring contract** (§3's sketch) needs to be a binding
   design decision, not left implicit — likely needs its own short design
   pass (F1) rather than being assumed correct from this report alone.
2. **CWE/family convention for AC-07's future catalog entries** (§5) — not
   this sub-project's decision, but F's corpus format should reserve a way
   to mark an entry `capability/`-tier-pending-a-named-blocker (mirroring
   cve-replay's own tier semantics) so AI-sink fixtures can be authored NOW
   and merely fail to score until H closes the gap, rather than waiting.
3. **Does "weakly-encrypted"/"reversed" (§2 bullet 6) get a corpus waiver
   or a `TRANSFORM_KINDS` enum extension?** Not decided here — a real
   product/scope call, not an engineering-only one.
4. **Tier semantics**: should F reuse cve-replay's literal `regression/`/
   `capability/`/`deep/` directory names, or invent lineage-appropriate ones
   (e.g. `proven/`/`pending/`)? Cosmetic but should be decided once, not
   organically drift.
5. **`sast/llm-app.js`** was found alongside `aibom.js` in the AI-detection
   search but not read in this pass — worth a quick check before H's own
   scoping, in case it duplicates or extends `aibom.js`'s provider patterns.
