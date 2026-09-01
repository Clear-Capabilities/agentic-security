# Milestone 2, Sub-project F, increment 1: edge provenance tag (`edge.provenance`, closes the first clause of FR-304)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-f-scoping.md`.
That document found FR-304's four provenance categories have exactly ONE
real producer today (`code`-derived — every edge, unconditionally) and
recommended starting with the small, honest slice: add the missing
vocabulary and tag every edge `graph-builder.js` mints. This plan
implements F1 only. F2 (bridging `cross-lang-openapi/grpc/graphql.js`
into real schema-derived edges) and F3 (a declared-service-graph
ingestion mechanism) are explicitly deferred, each needing its own future
scoping pass — this increment does not attempt either.

## What already exists (confirmed by direct read, this session, HEAD `9bd4c3e9`)

- `graph-builder.js`'s edge-construction block, inside the flow-loop's
  `if (!edgesById.has(edgeIdStr))` branch (re-verify against the current
  file before trusting line numbers — this block has been extended by
  Sub-project B2 already):
  ```js
  edgesById.set(edgeIdStr, {
    id: edgeIdStr, from: src.id, to: snk.id, relationship: 'data_flow',
    fieldMappings: [{ fromPath, toPath, dataElementIds: [de.id], mappingType, transformationIds: sortedT }],
    protocol: { name: 'in-process', destinationResolution: site.destination?.resolutionStatus ?? 'unknown' },
    boundaryCrossings: [],
    // ... protection: {...} follows, set by Sub-project B2's own hook
  });
  ```
  This is the ONLY place `edgesById` entries are minted — confirmed by
  the scoping doc's own full-file read: every edge originates here, with
  no other mint site anywhere in the module.
- `schema.js` has `DESTINATION_RESOLUTION_VALUES` (line ~51) as the
  precedent pattern for a small frozen string-array export, and
  `EVIDENCE_TYPES` (line ~83: `['code', 'ir', 'configuration', 'iac',
  'schema', 'service_declaration', 'policy', 'manual', 'runtime']`) as
  the vocabulary this increment's own 4 values are deliberately aligned
  with (a subset: `'code'`, `'schema'`, `'manual'`, `'runtime'` — the
  scoping doc's own naming-decision note applies: FR-304 says "manually
  declared," mapped to `EVIDENCE_TYPES`'s existing `'manual'`, not
  `'service_declaration'`, since no real declared-service-graph producer
  exists yet to test that distinction against).
- `validate.js`'s `_validateEdge` (confirmed, current file) already has
  the exact template to copy, right where `edge.protocol
  .destinationResolution` is checked:
  ```js
  if (edge.protocol && typeof edge.protocol === 'object') {
    if (!DESTINATION_RESOLUTION_VALUES.includes(edge.protocol.destinationResolution)) {
      _err(errors, path('.protocol.destinationResolution'), `unrecognized destinationResolution "${edge.protocol.destinationResolution}"`);
    }
  }
  ```
  `edge.provenance` is a top-level edge field (not nested under
  `protocol`), so its own check is a plain top-level `if`, not nested —
  do not copy the `typeof === 'object'` wrapper, which is specific to
  `protocol` being an optional sub-object; `provenance` is a required
  plain string.
- `dataflow-graph.schema.json`'s `edge` `$def` (confirmed, current file):
  `"required": ["id", "from", "to", "relationship", "fieldMappings",
  "protocol", "boundaryCrossings", "protection", "evidenceRefs",
  "coverageStatus"]` — `provenance` is always set unconditionally by this
  increment (never omitted), so it belongs in BOTH the `properties` block
  AND this `required` array, matching `boundaryCrossings`'s own
  always-present precedent (not `protocol`'s optional-nested-object
  pattern).
- `test/lineage/json-schema-parity.test.js`'s existing test (confirmed,
  current file) is the template for the new parity assertion:
  ```js
  test('coverage status, destination resolution, policy state, evidence type enums match schema.js', () => {
    const schema = loadSchema();
    assert.deepEqual([...schema.$defs.node.properties.coverageStatus.enum].sort(), [...COVERAGE_STATUS_VALUES].sort());
    assert.deepEqual([...schema.$defs.protocol.properties.destinationResolution.enum].sort(), [...DESTINATION_RESOLUTION_VALUES].sort());
    // ...
  });
  ```
  Add one more `assert.deepEqual` line to this SAME test (matching its
  own established "one test, every enum-vs-schema pair" shape), not a
  new test — re-verify the current test's exact name/shape before
  editing, don't assume the citation above is still verbatim.

## Scope for this increment

1. **`scanner/src/lineage/schema.js`**: add
   ```js
   // Milestone 2, Sub-project F, increment 1 (FR-304): which mechanism
   // discovered this edge. Deliberately value-aligned with (but a
   // distinct field from) EVIDENCE_TYPES — 'code'/'schema'/'manual'/
   // 'runtime' are FR-304's own four categories, reusing EVIDENCE_TYPES's
   // existing spellings rather than inventing a second vocabulary for the
   // same four concepts. Only 'code' has a real producer today
   // (graph-builder.js sets it unconditionally); 'schema'/'manual'/
   // 'runtime' are reserved for Sub-project F2/F3, not yet implemented —
   // see scanner/src/lineage/CLAUDE.md.
   export const EDGE_PROVENANCE_VALUES = Object.freeze(['code', 'schema', 'manual', 'runtime']);
   ```
   placed near `DESTINATION_RESOLUTION_VALUES`, not inside it — a
   separate export, since `edge.provenance` and
   `edge.protocol.destinationResolution` are unrelated fields that
   happen to sit on the same entity.
2. **`scanner/src/lineage/graph-builder.js`**: in the edge-construction
   object literal (the exact block cited above), add `provenance:
   'code',` as a new top-level key — place it near `boundaryCrossings`
   (both are always-present, currently-static-value fields at this
   increment), not inside `protocol`. Do NOT make this conditional on
   anything — every edge minted by this function today genuinely is
   code-derived, confirmed by the scoping doc's own investigation, so an
   unconditional literal is the honest, correct value, not a
   simplification that hides a gap.
3. **`scanner/src/lineage/validate.js`**: in `_validateEdge`, add:
   ```js
   if (!EDGE_PROVENANCE_VALUES.includes(edge.provenance)) {
     _err(errors, path('.provenance'), `unrecognized provenance "${edge.provenance}"`);
   }
   ```
   placed as its own top-level check (not nested under the `protocol`
   block), and add `EDGE_PROVENANCE_VALUES` to this file's existing
   `schema.js` import line (confirm the current import list before
   editing — it already destructures several exports, mirroring
   `DESTINATION_RESOLUTION_VALUES`'s own entry in that same import).
4. **`scanner/src/lineage/dataflow-graph.schema.json`**: in the `edge`
   `$def`, add `"provenance": { "type": "string", "enum": ["code",
   "schema", "manual", "runtime"] }` to `properties`, and add
   `"provenance"` to the `required` array (alongside `boundaryCrossings`,
   per the always-present rationale above).
5. **`test/lineage/json-schema-parity.test.js`**: extend the existing
   enum-parity test (cited above) with one more line: `assert.deepEqual(
   [...schema.$defs.edge.properties.provenance.enum].sort(),
   [...EDGE_PROVENANCE_VALUES].sort());`. Add `EDGE_PROVENANCE_VALUES` to
   this test file's own `schema.js` import line.
6. **New or extended test** proving the real behavior (place in
   `test/lineage/graph-builder.test.js`, alongside `E1/12`'s own reuse-
   boundary test, or a new small block — implementer's judgment, no new
   dedicated file needed for a field this small):
   - A real fixture through `buildDataFlowGraph`/`buildGraphWithCoverage`
     → every edge in `graph.edges` reads `provenance === 'code'`.
   - `validateGraph` accepts a real graph unchanged (no regression).
   - A validator-level proof that `'schema'`/`'manual'`/`'runtime'` are
     each individually VALID values (a hand-built graph fixture with one
     of them set on an edge passes `validateGraph`) but that NONE of them
     is ever produced by a real `buildDataFlowGraph` call on any existing
     fixture — an explicit completeness-accounting assertion, mirroring
     Sub-project C1's own `'aggregated'`-is-unreachable precedent, so
     this increment's own honest gap (F2/F3 not built) is pinned and
     visible in the test suite, not silently true by omission.
   - A validator-level negative proof: an edge with an unrecognized
     `provenance` value (e.g. `'guessed'`) fails `validateGraph` with a
     `.provenance`-pathed error.

## Do NOT touch

`cross-lang-openapi.js`/`cross-lang-grpc.js`/`cross-lang-graphql.js`
(read-only reference in the scoping doc only — F2's future territory,
not this increment's). `edge.boundaryCrossings` (a different,
still-unimplemented field — do not conflate with `provenance` or attempt
to populate it). `edge.protocol.destinationResolution`'s
`'declared_service'`/`'runtime_corroborated'` values (Sub-project A's own
territory, a different field despite similar-sounding strings).
`graph.evidence[]`/`EVIDENCE_TYPES` itself (read-only reference for the
value-alignment decision — never modify that array or its existing
Sub-project G1 usage). `MAPPING_TYPES` (confirmed unrelated, do not
touch).

## Test plan (full picture — item 6 above plus regression)

1. The four items in scope item 6.
2. `npm run test:lineage` full run, green.
3. No `test:dataflow`/full-gate impact expected (this increment touches
   only `lineage/` files and their own tests) — still run `npm test`
   before the final commit, real captured exit code, per this
   repository's own verification discipline.

## Explicitly deferred

F2 (bridging `cross-lang-openapi/grpc/graphql.js` into real
schema-derived graph edges — Large, its own future scoping pass). F3 (a
declared-service-graph ingestion mechanism, closing FR-304's "manually
declared"/"cross-repository or federated" clauses — Large, its own
future scoping pass). `edge.boundaryCrossings`. Any language beyond
JS/TS.
