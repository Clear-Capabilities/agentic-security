# Milestone 2, Sub-project D, increment 1: single-path handling classification (FR-403 taxonomy only)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`,
Sub-project D ("Handling analyzer + FR-307 control-credit," Large),
Decision 1. This increment is a first slice: it produces FR-403's handling
TAXONOMY label for one already-reconstructed path. It deliberately does NOT
implement FR-307's multi-path control-credit rule (AC-12: "a transform on
one branch cannot make the full flow green") — that needs comparing MULTIPLE
paths to the same sink, a distinct, larger follow-up (D2), named here and
not silently attempted.

## What already exists (confirmed by direct read, this session)

- `transform-catalog.js`'s `recognizeTransformation(calleeDescriptor)` —
  `{type:'call', callee}` or `{type:'member-call', object, method}` ->
  `{kind, reversibility, algorithm, confidence, evidence}` or `null`. Never
  throws. 11 non-fallback kinds including `mask`/`hash`/`tokenize`/`encrypt`/
  `redact`/`encode`/`decode`.
- `path-query.js`'s `reconstructPaths(store, startNodeId, opts)` returns
  `{paths: [{hops: [...], ...}], ...}`; each hop (`hopOf` in `path-query.js`)
  carries `siteNodeId` — the CFG node id of the call/assignment site that
  produced this edge — plus `scope` (the function qid the site lives in).
- `registry-real-code.test.js` (D5) and `graph-builder.js`'s
  `enumerateSinkSites` already establish the pattern for resolving a
  `siteNodeId` back to a real call descriptor: look up
  `callGraph.functions[scope].cfg.nodes[siteNodeId]`, read its `.callee`
  expression (already the shape `transform-catalog.js`'s descriptor forms
  expect after rendering).
- `flow-grade.js`'s `gradeHop`/`gradePath` are a SEPARATE vocabulary
  (`explicit`/`widened`/`implicit`/`severed`/`ambiguous`) — grading how
  EXPLICIT a recorded movement is, never how the DATA was handled. This
  increment must not conflate the two; a handling verdict is additional
  information alongside a flow grade, not a replacement for it.
- `schema.js`'s flow/edge shape does not yet have a dedicated FR-403
  handling-taxonomy field — this increment adds one (see below), following
  the same "add to the schema, validate it, document the addition" pattern
  Sub-project A increment 1 used for `destination`.

## Scope for this increment

1. **Design note** (`scanner/src/lineage/DESIGN_HANDLING_ANALYZER.md`,
   short, mirroring `DESIGN_DESTINATION_RESOLVER.md`'s scale): define the
   handling-verdict shape: `handling` (one of `raw`, `masked`, `redacted`,
   `hashed`, `tokenized`, `encrypted`, `aggregated`, `unknown` — FR-403's own
   8-value taxonomy, add this exact array to `schema.js` as
   `HANDLING_VALUES`), `recognizedTransform` (the `transform-catalog.js`
   decision object that produced the verdict, or `null` for `raw`/`unknown`),
   `hopIndex` (which hop in the path the transform was found at, or `null`).
   Map `transform-catalog.js`'s `kind` values onto `HANDLING_VALUES`:
   `mask`->`masked`, `redact`->`redacted`, `hash`->`hashed`,
   `tokenize`->`tokenized`, `encrypt`->`encrypted`, `encode`/`decode`/
   `truncate`/`normalize`/`decrypt`->`unknown` (none of these is itself a
   PROTECTIVE handling state for FR-403's purposes — decoding/truncating/
   normalizing doesn't protect a field, and a `decrypt` immediately before a
   log sink is actively the OPPOSITE of protection; disclose this mapping
   choice explicitly, don't silently drop these five kinds). A path with NO
   recognized transform on any hop and a literal/direct field reaching the
   sink is `raw`. Explicitly name what's deferred: FR-307 control-credit
   (multi-path "applies on every feasible path" — D2), `aggregate`'s own
   verdict (needs shape-level reasoning about a WHOLE collection, not a
   single hop — also D2 or later), any UI/display concern.
2. **`scanner/src/lineage/handling-analyzer.js`** (new module): exports
   `classifyHandling(path, callGraph)` where `path` is one `reconstructPaths`
   result path (the caller picks which path — this increment does not
   iterate multiple paths to the same sink). Walks `path.hops` in order;
   for each hop, resolves `callGraph.functions[hop.scope]?.cfg?.nodes?.[hop.siteNodeId]`
   defensively (never throws on a missing/malformed lookup — mirrors every
   other lineage module's defensiveness), and if that CFG node is a `call`-
   kind node, builds a descriptor from its `.callee` (reuse
   `source-seeding.js`'s already-shipped `walkExpr`/callee-rendering
   convention if it fits directly — check before writing a third copy of
   callee-descriptor construction; `graph-builder.js`/`registry-real-code.test.js`
   already have two, don't add an uncoordinated fourth) and calls
   `recognizeTransformation`. Returns the FIRST recognized transform found
   walking from source to sink (source-to-sink order, not reversed) mapped
   per the table above, or `{handling: 'raw', recognizedTransform: null, hopIndex: null}`
   when none is found on any hop.
3. **Wire into `coverage.js`'s ledger or `graph-builder.js`'s flow
   projection** — the plan leaves the exact integration point to the
   implementer's judgment (read how `protection.js`'s `emptyProtection()` is
   currently attached to a `flow` object in `graph-builder.js` and follow
   that same attachment point), but the requirement is: every emitted
   `flow` reaching a `log`/`external-api`-with-telemetry-shaped sink (or,
   more simply for this increment, every flow at all — a flow whose sink
   category has no natural "handling" concept just gets `handling: null`,
   never a fabricated `'raw'`) gains a `flow.handling` field populated by
   `classifyHandling` called on that flow's own reconstructed path.
4. **`validate.js`**: add `HANDLING_VALUES` to `schema.js`, structural check
   on `flow.handling` when non-null (must be one of `HANDLING_VALUES`).
5. **Do NOT touch**: `flow-grade.js`, `protection.js`, `path-store.js`,
   `path-query.js` (read-only consumer), `transform-catalog.js` (read-only
   consumer), `resolve-destination.js`/Sub-project A's own files.

## Test plan

- New `scanner/test/lineage/handling-analyzer.test.js`: unit tests with
  hand-built paths/callGraphs for each mapped `handling` outcome, plus
  malformed-input safety.
- Real-parsed-code test (reuse the `maskCard()`-before-`logger.info()` vs.
  raw-log AC-02 fixture shape already proven in `bench/data-lineage/fixtures/
  js-api-to-log-masked/` and `js-api-to-log-raw/`): build the real graph via
  `buildGraphWithCoverage`, confirm the masked flow's `flow.handling ===
  'masked'` and the raw flow's `flow.handling === 'raw'`.
- `validate.js` test for the new `HANDLING_VALUES` check.
- Full `npm test` and `npm run test:lineage` must stay green, exit 0,
  verified by the implementer with real captured exit codes, not inferred.

## Explicitly deferred (name it, don't silently drop it)

FR-307's multi-path control-credit rule (AC-12) — needs enumerating every
path to a sink and checking a transform applies on ALL of them, not one;
`aggregate`-kind verdicts (shape-level, not hop-level); any UI/display of
the handling taxonomy; re-deriving `handling` for a flow whose reconstructed
path changes after a later Sub-project A/E change (this increment computes
it once, at graph-build time, consistent with how every other flow field
is computed today).
