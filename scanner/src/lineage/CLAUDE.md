# scanner/src/lineage/

Data Flow Explorer's canonical `DataFlowGraph v1` contract package
(PRD section 18.1 — an untracked root working document, per this repo's
convention of not committing in-progress PRDs; ask the maintainer for the
current copy if you need it).
Isolated by design from `scanner/src/dataflow/`'s taint engine — see that
package's own CLAUDE.md for why (D-0047's precedent: a second, independent
engine sharing only pure, stateless utilities, never mutable taint state —
e.g. `access-paths.js`'s `accessPathOf`/`pathIsCoveredByPrefix`/`isCoveredBy`,
never `engine.js`'s live taint state).

## What's here

**Milestone 0 (contract and fixture):**

| Module | Responsibility |
|---|---|
| `schema.js` | Envelope shape, `SCHEMA_VERSION`, node/mapping/transform/coverage/policy/evidence enums |
| `ids.js` | Deterministic stable-ID functions (`nodeId`, `edgeId`, `dataElementId`, `flowId`, `transformationId`, `evidenceId`, `graphId`) — sha256-over-canonicalized-material, same shape as `posture/stable-id.js`'s finding IDs |
| `protection.js` | Protection verdict model: `PROTECTION_VERDICTS` × `EVIDENCE_GRADES` per dimension (`transit`/`atRest`/`handling`), plus `aggregateVerdicts()`'s risk-precedence reduction (PRD 8.4) |
| `classification.js` | Data classes (reuses `dataflow/privacy-taxonomy.js` + adds `CONFIDENTIAL`) and the 15 AI processing contexts (PRD 9.2) — AI is modeled as orthogonal to data class, never a mutually-exclusive label |
| `validate.js` | Hand-rolled structural validator (`validateGraph`) — no new npm dependency; `dataflow-graph.schema.json` is the JSON-Schema-dialect twin, kept in parity by `test/lineage/json-schema-parity.test.js`. Checks id-prefix format (regex per entity kind), every risk-bearing enum (`node.kind`, `node.externality.value`, `node.coverageStatus`, `dataElement.dataClasses`/`.aiContexts` array *contents*, `edge.protocol.destinationResolution`, `flow.policyVerdict`/`.protectionSummary`, `transformation.kind`/`.reversibility`, `evidence.evidenceType`, `graph.scope.source`) against `schema.js`/`classification.js`, not just array/field presence — each gap was closed after an initial pass let a made-up value validate cleanly (see git history on `validate.js`). Also checks duplicate-id uniqueness across the four top-level entity arrays (nodes/edges/dataElements/flows) — a real gap until it was closed alongside the enum gaps above. |
| `dataflow-graph.schema.json` | Authoritative JSON Schema (2020-12) document for external interop/documentation |
| `fixtures/build-flagship-fixture.mjs` | Deterministic generator for the payments-platform reference fixture (PRD Appendix D.2/D.3) — re-run and re-commit `flagship-graph.json` if you change the generator; a diff test (`flagship-fixture.test.js`) enforces idempotence. Entity-id discriminators (see `ids.js`) must include every field that can vary between two otherwise-similar entities (e.g. an edge's `dataElementIds`) — two edges over the same node pair carrying different payloads collided on id once before this was tightened; `flagship-fixture-semantics.test.js` now pins uniqueness of every id array as a regression guard. |

**Milestone 1, Sub-project A (field-identity engine core — design spike + intraprocedural, single-function only):**

| Module | Responsibility |
|---|---|
| `DESIGN_INTRAPROCEDURAL.md` | Design record: the field-identity state shape (`Map<accessPath, Set<dataElementId>>`, replacing boolean taint so FR-301's multi-label requirement holds), the exact reuse boundary against `scanner/src/dataflow/` (what's pure-reusable vs. must-be-reimplemented), and per-construct handling rules (object literals attribute each property to its own sub-path; template literals/string concatenation propagate identity normally, not as a widened/implicit flow; unresolved calls ARE flagged as widened). Read this before touching `field-identity.js` or `engine.js` — it's the binding reference both were built against. |
| `field-identity.js` | Pure state module: `emptyState`/`identitiesAt`/`addIdentity`/`removeIdentitiesAt`/`joinStates`/`statesEqual`/`hashState` over the `Map<path, Set<dataElementId>>` shape. `identitiesAt` is bidirectional (corrected from an original one-directional design that shipped a real FR-301 bug — see the ADR §3's "Corrected design" note): an ancestor's identity is visible when querying a descendant path, AND querying a container as a whole aggregates every identity recorded under it — sibling paths never leak into each other, since aggregation only follows an actual prefix relationship. Imports `pathIsCoveredByPrefix` from `dataflow/access-paths.js` (the one function from that package currently reused in practice; see this file's header for the full allowed-reuse list). Unit-tested in `test/lineage/field-identity.test.js`, including the FR-301 "two distinct fields coexist without merging" case and the bidirectional-aggregation regression cases. |
| `engine.js` | `resolveExprIdentities(state, expr)`: recursively resolves which data-element identities a parsed JS/TS expression carries. `byPath` is populated not just by object literals but by ANY path reference (`ident`/`member`) that resolves to a state path with recorded descendant structure — an alias like `const copy = user;` is structurally indistinguishable from a fresh object literal for this purpose (a round-2 fix; round 1 only handled the object-literal case, and the same coarse-merge bug survived through one level of aliasing until this closed it). A shared `residualFlat(flat, byPath)` helper is applied consistently everywhere a `flat`+`byPath` pair gets written to a target/key: every `byPath` entry is written at its own sub-path, and only the RESIDUAL (whatever in `flat` isn't already captured by `byPath`'s union) is written coarsely at the target's own root — never the full `flat` when `byPath` has structure, since that recreates the coarse-merge bug one level up. **The general invariant (broadened in round 4 — don't scope this to just "which switch cases produce `byPath`"): a structured value's `byPath` must survive every hop it passes through — anywhere structure is built, selected out of, or written to a target — losing it (via an empty fallback, a fabricated key, or a coarse merge) at ANY of these three hop types is this bug class, regardless of which specific construct triggers it.** Check any new/changed code against all three hops, don't hand-count sites (a fixed-count claim is exactly what let round 3's gap survive two rounds of review) and don't limit the check to `resolveExprIdentities`'s own switch (that's exactly what let round 4's gap survive three rounds of review before it was found):
  - *Production* (a switch case building a value's structure) — every case falls into one of two categories: *structure-preserving* (its result could genuinely BE an existing structured value from `state`, by reference/selection — must forward `byPath`) covers `ident` and `object` (round 1/2), `member` when its base is a pure ident/member chain (round 2), plus `union` (ternary — selects one branch verbatim), `logical` (`\|\|`/`&&`/`??` — short-circuit evaluation can return an operand verbatim, unlike `binary`) and `assign-expr` (simple pass-through of its resolved source, including its `widened` flag — round 4 fixed `assign-expr` recomputing `widened` from `flat.size > 0` instead of forwarding the source's real value, which falsely flagged a plain no-call assignment as an `unresolved-call` widening), all three added in round 3 after the same coarse-merge bug was found surviving there, confirmed via the real parser (`flag ? user : other` merging `user`'s and `other`'s fields together). *Structure-flattening, correctly and by design* (stays flat-only) covers `literal`/`unknown` (nothing to preserve), `tpl` (a template literal always produces a new string), `binary` (arithmetic/comparison operators always produce a new primitive — this is why `binary` and `logical` are separate cases, not shared, as of round 3), `array` (**not** "no index-sensitive access paths" — round 4 found that claim false, since `accessPathOf`/the parser DO extract literal computed keys and can build paths like `arr.0`; the real reason is that the parser transparently unwraps `SpreadElement`, so `[...xs, user]` and `[xs, user]` are byte-identical in the IR and naive per-index attribution would actively misattribute a spread source's contents to a literal index — worse than staying flat; fixing this properly needs the parser to distinguish spread from literal elements first, out of scope here), and `call` (an unresolved call's return is genuinely unknown structure — flat + `widened: true`, not laundered).
  - *Selection* (reading a field off an already-produced structured value, round 4) — `member`'s base isn't always a pure ident/member chain (`accessPathOf` returns `null` for a ternary, a logical expression, an object literal, an assign-expr, a call). Before round 4, that fell straight to `noIdentity()`, silently dropping the identity: `(user ?? other).email` returned `[]` even though `const c = user ?? other; return c.email;` correctly returned `[email]` — same semantics, two forms, two different answers, the exact tell every prior round used to find its bug. Fixed by giving `member` a second path: resolve the base recursively and select `prop` out of the base's `byPath` (plus its residual), mirroring how `object`'s construction attributes a property to its own key.
  - *Write-out* (writing a resolved value to a target path that must itself be a valid, non-fabricated path, round 4) — `step()`'s `assign` case passed `node.target` straight through to `removeIdentitiesAt`/`addIdentity` with no guard it was a string. Assignment-expression-form destructuring (`({a} = obj)`, as opposed to declaration-form `const {a} = obj`) is lowered by the real parser into one `assign` CFG node whose `target` is the raw pattern object, not a string — this implicitly stringified to the literal `"[object Object]"`, so every such destructuring anywhere in a function collided onto one fabricated key, silently merging unrelated statements' fields. Fixed by guarding `node.target` to be a string before writing anything (skip rather than fabricate a key), matching a precedent `scanner/src/dataflow/engine.js`'s own `assign` case already established that this package hadn't inherited.

  See the ADR §3's "The residual principle" and "The structure-preserving vs. structure-flattening invariant (round 3)" notes, and the ADR's "The three hop types the invariant covers (round 4)" note, for the full worked examples. `analyzeFunctionFieldIdentity(fn, entryState)`: a forward-worklist CFG analysis over a single function, structurally mirroring `dataflow/engine.js`'s `analyzeFunction` (same fixed-point/join algorithm, entirely different state type — never imports or touches that file's taint state) — returns `{exitState, returnFacts, mutatedParams, widenings}`. `returnFacts` accumulates per-node in a `Map` during the worklist and unions on revisit before materializing to an array, so a `return` node revisited before its incoming join settles gets exactly one, fully-unioned entry (a final whole-branch review found and fixed a real duplicate-stale-entry bug here). `mutatedParams` is computed via a direct `identitiesAt` call per param, relying on `identitiesAt`'s bidirectional aggregation to see both the param's own path and any descendant a mutation wrote to. No interprocedural resolution, no path DAG, no registry/graph-output wiring yet — see the ADR §5 for the explicit scope line. Unit-tested against hand-built fixtures in `test/lineage/engine-expr-resolver.test.js` and `test/lineage/engine-walker.test.js`, and against real parsed JS/TS source (via `scanner/src/ir/parser-js.js`) in `test/lineage/engine-integration.test.js`. |

## What is NOT here yet (later milestones / later sub-projects)

- Interprocedural summaries, the path DAG, source/sink registries,
  transformation-kind recognition, and any `DataFlowGraph v1` graph
  output — Milestone 1, Sub-projects B through H (see
  `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`).
  Sub-project A (above) is intraprocedural-only, by design.
- External destination resolution, database/queue field mapping,
  transit/at-rest/handling ANALYZERS (this package only defines the
  verdict *model*, not what decides a verdict) — Milestone 2.
- The local API/server and any UI — Milestone 3.
- Decision-intelligence extensions (stories, scenarios, snapshots/diffs,
  obligations, runtime twin, recipients, impact/remediation) —
  Milestones 4/5.

## Conventions

- Every enum here is a single source of truth for its concept. If you add
  a new node kind, mapping type, transform kind, etc., you MUST update
  three places: `schema.js` (or `protection.js`/`classification.js`),
  `dataflow-graph.schema.json`'s matching `enum` array, and
  `validate.js` if the new value needs a structural check —
  `json-schema-parity.test.js` fails loudly if the first two drift apart.
- Stable IDs are content hashes, not counters — see `ids.js`'s header.
  Never construct an id string by hand; always call the exported
  function, so a discriminator-shape change only has one call site to fix.
  Include every field that distinguishes two entities in the discriminator
  — omitting one (e.g. `dataElementIds` on an edge) produces a silent
  collision that `validateGraph()` currently cannot catch on its own.
- The flagship fixture is the ONE place fixture-specific facts (node
  names like "Payments Service", synthetic commit hashes, etc.) are
  allowed to live. No other module in this package — and per PRD Appendix
  D.1, no UI code in a later milestone — may special-case a fixture name.
  The generic hook is `graph.scope.source === 'fixture'`.
