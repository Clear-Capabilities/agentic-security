# Milestone 2, Sub-project C, increment 1: application-layer at-rest protection (`edge.protection.atRest`)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-c-scoping.md`.
That document already found the application-layer evidence source needs
no new detection — `flow.handling === 'encrypted'` (Milestone 1,
Sub-project D, increment 1) already answers the exact question FR-402
asks — and identified the precise wiring point. This plan implements it.

## What already exists (confirmed by direct read, this session, HEAD `42ca9313`)

- `graph-builder.js`'s flow-construction loop already computes
  `handling: classifyHandling(p, callGraph).handling` (line ~724) inside
  the `for (const [, group] of [...groupsByFlowKey.entries()]...)` loop,
  where `p`, `snk`, `edgeIdStr` are all already in scope (destructured
  from `group[0]` earlier in the same loop). **Re-verify these exact line
  numbers and variable names against the CURRENT file before writing
  code** — this codebase's own plan-writing convention, carried forward
  from every prior increment's own citation caveat.
- `edgesById` (a `Map<edgeIdStr, edge>`) already holds the fully-minted
  edge object by the time this loop runs — confirmed by Sub-project D,
  increment 2's own precedent (`transformsById.get(tid).appliesToAllPaths
  = ...`, the SAME "look up an already-minted entity by id, mutate one
  field in place, in a later pass" pattern this increment reuses, not
  invents).
- `sink-registry.js`'s `CATEGORY_NODE_KIND` (re-verified this session):
  `database`/`file`/`object-storage`/`cache`/`client-storage`/`backup`/
  `export` all map to `kind: 'store'`. `queue` has its own distinct
  `kind: 'queue'`. This increment filters on `snk.kind === 'store'`.
- `protection.js`'s `emptyProtection()` — unchanged, still the default
  every edge starts with; this increment's own job is narrower than
  Sub-project B's (no new module, no new hook signature — a direct,
  in-loop mutation, since the evidence and the target are already both in
  scope at the SAME point, unlike B2's `resolveTransitProtection` which
  needed a whole new opts-hook because its evidence came from OUTSIDE the
  graph-builder loop entirely).

## Scope for this increment

1. **`graph-builder.js`**: immediately after (or alongside) the existing
   `handling: classifyHandling(p, callGraph).handling,` line, inside the
   SAME flow-construction loop iteration:

   ```js
   const handlingResult = classifyHandling(p, callGraph).handling;
   if (handlingResult === 'encrypted' && snk.kind === 'store') {
     const edge = edgesById.get(edgeIdStr);
     if (edge) edge.protection.atRest = { verdict: 'protected', evidenceGrade: 'code' };
   }
   ```

   (Written as a snippet showing the exact logic — the implementer's own
   job is to place this correctly relative to the EXISTING `classifyHandling`
   call without calling it twice; reuse ONE call's result for both
   `flow.handling` and this new check, don't invoke `classifyHandling`
   a second time.) `edge` should always be found (`edgesById.get(edgeIdStr)`
   — the SAME id this exact flow object's own `edgeIds: [edgeIdStr]` uses,
   minted earlier in the SAME `buildDataFlowGraph` call) — the defensive
   `if (edge)` guard is precautionary, matching this package's own
   established "never assume, guard defensively" convention, not evidence
   this could realistically be missing.
2. **Do NOT touch** `handling-analyzer.js` itself (read-only — this
   increment consumes its existing output, never modifies its logic),
   `transform-catalog.js`, `sink-registry.js`'s `CATEGORY_NODE_KIND` (read
   only, to confirm the filter), `transit-protection.js`/Sub-project B's
   own files (a DIFFERENT protection dimension, `.transit`, never
   touched here), `node.storeDetail`/`node.queueDetail` (Sub-project E,
   entirely unrelated fields).
3. **No new module, no new design doc separate file needed** — add a
   short section directly to `DESIGN_HANDLING_ANALYZER.md` (the design doc
   that already owns `classifyHandling`'s own contract) documenting this
   NEW consumer of its output, rather than creating a
   `DESIGN_AT_REST_PROTECTION.md` for what is, this increment, a five-line
   wiring addition — matching this package's own "a genuinely small
   addition to an existing capability documents itself in that
   capability's own design doc" precedent (Sub-project A's own
   `resolveDestination` additions to already-existing design docs, where
   proportionate). If C2/C3 (the genuinely new storage/IaC detection work)
   later warrant their own dedicated design doc, that's their own call,
   not pre-decided here.

## What this does NOT do

Anything for a NON-`'encrypted'` `handling` value (a `'masked'`/`'hashed'`/
`'raw'`/etc. flow's `atRest` stays the honest default `not_assessed`/
`none` — this increment has NO opinion on those, they are not at-rest
PROTECTION evidence, per FR-402's own text, only `encrypt` is). Storage/IaC
encryption configuration detection (C2, genuinely new, unbuilt, its own
future scoping pass). Database column/transparent-encryption configuration
(C3, same). AC-12's "mixed" aggregate. Any language beyond JS/TS (unchanged
— `classifyHandling`'s own scope, not this increment's to widen).

## Test plan

New `scanner/test/lineage/at-rest-protection.test.js` (a NEW file — this is
its own coherent property of `edge.protection.atRest`, distinct from
`handling-analyzer.test.js`'s own `flow.handling` tests and from
`transit-protection.test.js`'s own `.transit` tests):

1. **The positive case**: a real fixture where a `mask`/`encrypt`-style
   function genuinely recognized by `transform-catalog.js` (reuse
   `handling-analyzer.test.js`'s own already-proven `maskCard`-style
   fixture shape, but with an ENCRYPT-recognized callee instead — check
   `transform-catalog.js`'s own `examples[]` for a real `encrypt`-kind
   entry to copy verbatim, e.g. `crypto.createCipheriv`/`crypto.subtle
   .encrypt` — don't invent an unrecognized name) applied before a
   `db.query(...)`-shaped write (or another real `store`-kind sink shape)
   → `edge.protection.atRest === {verdict: 'protected', evidenceGrade:
   'code'}`, AND `flow.handling === 'encrypted'` on the SAME flow (proving
   both fields are consistent, derived from the one `classifyHandling`
   call, not two divergent computations).
2. **The negative case — no encryption**: the same shape with NO
   recognized transform (a bare, unencrypted write) → `edge.protection
   .atRest` stays the DEFAULT `{verdict: 'not_assessed', evidenceGrade:
   'none'}`.
3. **The anti-pattern-guard proof (AC-06's own core property, and this
   increment's single most important test)**: a fixture with an
   `encrypt`-recognized call present in the SAME FILE/FUNCTION but NOT on
   the actual flow's own path to the store sink (e.g. two independent local
   variables, one encrypted-then-discarded, one written raw to the store)
   → the store-write edge's `protection.atRest` stays the DEFAULT — proving
   FR-402's own "a cipher present anywhere in the same file/repository
   cannot alone establish protection for an unrelated store" property
   live, not just architecturally implied by reusing `classifyHandling`.
4. **A non-`store`-kind sink** (a `log`/`external-api` sink reached by an
   `encrypt`-shaped flow) → `edge.protection.atRest` stays the DEFAULT,
   proving the `snk.kind === 'store'` filter.
5. **Every OTHER `HANDLING_VALUES` member on a store sink** (`masked`,
   `hashed`, `tokenized`, `raw`, `unknown`, `redacted`, `aggregated`) →
   `edge.protection.atRest` stays the DEFAULT for every one of them —
   proving only `'encrypted'` triggers this increment's own logic, not a
   broader "any recognized transform" rule.
6. Full `npm run test:lineage`, `npm run test:dataflow` (confirm
   `transform-catalog.js`'s own tests unaffected — you're not modifying
   it, but confirm), and `npm test` stay green, real captured exit codes.

## Explicitly deferred

C2 (storage/IaC encryption detection — genuinely new, its own scoping
pass). C3 (database column/transparent-encryption configuration — same).
AC-12's at-rest aggregate. Widening `store`-kind to `queue`/`vector-store`/
`model`/`training` (named in the scoping doc's own corrected "What this
does NOT do" section).
