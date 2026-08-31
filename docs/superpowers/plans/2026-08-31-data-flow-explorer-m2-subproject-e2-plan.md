# Milestone 2, Sub-project E, increment 2: table/column/operation extraction (`node.storeDetail`)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e-scoping.md`'s
revised increment breakdown (E2, "Medium"). Increment 1 (`8e733fe9`) shipped
ORM-write SITE RECOGNITION only — `resolveOrmWriteAtCallSite` already
confirms `args[0].kind === 'object'` as a hard gate, but extracts and keeps
nothing from the call beyond that boolean fact. This increment extracts
FR-204's structured facts from a site increment 1 already recognizes, and
attaches them to the sink node.

**PRD text (FR-204, verbatim):** *"When supported evidence exists, a
database sink must include provider, host/config reference, database,
schema, table/collection, operation, column/field mapping. Unknown
portions remain `unknown`; the entire store must not be omitted."*

## What already exists (confirmed by direct read, this session, HEAD `e700ede2`)

- `resolveOrmWriteAtCallSite` (`graph-builder.js`) already has, in scope,
  everything E2 needs to extract `table`/`operation`/`columns`:
  `calleeExpr` (a `kind: 'member'` node whose `object.name` IS the model
  identifier, e.g. `'User'` — already regex-tested by
  `_ormReceiverIsCapitalizedIdent` in `orm-write-catalog.js`, but that
  name is never RETAINED anywhere today), the matched entry's own
  `match.callee` (`'create'`/`'save'`/`'update'`/`'upsert'`), and `arg0`
  (already confirmed `kind: 'object'`).
- `parser-js.js`'s `ObjectExpression` lowering (confirmed by direct read,
  lines ~116-159) produces `{kind: 'object', props: [...]}` where each
  entry is EITHER `{key: <string>, value: <exprDesc>}` (a real or
  literal-computed property — `resolveObjectKey(p)` already resolves a
  non-literal computed key to the literal string `'*'`, the SAME
  computed-unknown-key convention Milestone 1's `field-identity.js`
  engine already established) OR `{spread: true, value: <exprDesc>}` (an
  object spread — no key at all). Column extraction must filter OUT
  spread entries (no key to report) and `'*'`-keyed entries (a genuinely
  unknown column name, not a literal column named "*" — reporting it as a
  real column name would be a fabrication) — collect only entries with a
  real, non-`'*'` string `key`.
- `schema.js` has NO `table`/`column`/`operation`/`provider`/`host`
  fields anywhere (confirmed by grep, per the E-scoping doc's own Finding
  2) — unlike Sub-project A's `destination`, which Milestone 1 pre-stubbed
  at `null` on every node. This increment adds a genuinely new field,
  `node.storeDetail`, mirroring `node.destination`'s own shape/wiring
  pattern exactly (both are "extra facts about a sink node, set once at
  mint time, `null` when never attempted").
- `graph-builder.js`'s `mintNode` already accepts an optional `destination`
  param (default `null`), passed through only by `sinkNodeFor` — the exact
  wiring point `storeDetail` should mirror, NOT the node-identity
  discriminator (same disclosed coarsening `destination` already
  accepted: two sites colliding onto one registry-decision node share one
  node, and that node's `storeDetail` is whichever site's resolution
  landed first).

## Scope for this increment

1. **`schema.js`**: add `STORE_OPERATION_VALUES = Object.freeze(['create',
   'read', 'update', 'delete', 'upsert', 'unknown'])`. Method-name mapping
   (define in `graph-builder.js`, not `schema.js` — `schema.js` holds
   enums, not mapping logic, per this package's own established
   separation): `create` → `'create'`, `update` → `'update'`, `upsert` →
   `'upsert'`. **`save` → `'upsert'`, not `'create'` — a deliberate,
   disclosed judgment call**: Mongoose's `.save()` performs an INSERT on a
   new document but an UPDATE on one loaded from the database, which is
   genuinely undecidable statically from the call site alone; `'upsert'`
   is the honest umbrella covering both, not a guess at which one. State
   this reasoning in the new field's own doc comment, don't silently pick
   one.
2. **The `storeDetail` object shape** (document in a short new section
   appended to `DESIGN_HANDLING_ANALYZER.md`... no — this is Sub-project
   E's own concern, unrelated to that file's FR-403/FR-307 subject matter.
   Create a new, short `DESIGN_STORE_DETAIL.md`, mirroring
   `DESIGN_DESTINATION_RESOLVER.md`'s own scale (that file is ~155 lines
   for a comparably-sized first slice — match that, not
   `DESIGN_GRAPH_BUILDER.md`'s much larger scope) — following this
   package's established "new schema surface gets its own short design
   record" convention):
   ```
   {
     provider: string | null,   // deferred to a later increment — always null in E2
     host: string | null,       // deferred — always null in E2
     database: string | null,   // deferred — always null in E2 (DB/cluster name, not the table)
     schema: string | null,     // deferred — always null in E2 (SQL schema/namespace)
     table: string | null,      // the model/receiver identifier name (e.g. 'User'), or null if unavailable
     operation: string | null,  // one of STORE_OPERATION_VALUES, or null if unavailable
     columns: string[],         // real, non-'*' property key names from the object-literal argument; [] if none
   }
   ```
   `table`/`operation`/`columns` are the only fields this increment ever
   populates (from JS/TS ORM-write sites only); `provider`/`host`/
   `database`/`schema` stay `null` unconditionally in every case E2
   produces — name this explicitly as FR-204's own "unknown portions
   remain unknown" clause in action, not a gap to silently fill later
   without saying so.
3. **`resolveOrmWriteAtCallSite`** (`graph-builder.js`): extend its return
   shape with a `storeDetail` object built as above — `table` from
   `calleeExpr.object.name` (already confirmed a string by
   `_ormReceiverIsCapitalizedIdent`'s own check, re-verify defensively
   rather than assume the shape survived from `orm-write-catalog.js`'s
   own internal check into this file unchanged), `operation` from the
   entry's own `match.callee` via the mapping in step 1, `columns` from
   `arg0.props.filter(p => !p.spread && typeof p.key === 'string' && p.key !== '*').map(p => p.key)`,
   deduplicated (`[...new Set(...)]`) since two distinct-value properties
   sharing a key would otherwise report the same column name twice — that
   IS possible in real (if unusual) source (`{email: a, email: b}`,
   whichever Babel keeps).
4. **`mintNode`/`sinkNodeFor`** (`graph-builder.js`): mirror `destination`'s
   own wiring EXACTLY — `mintNode` gains an optional `storeDetail` param
   (default `null`), `sinkNodeFor` passes `site.storeDetail ?? null`
   through. NOT added to the node identity discriminator, matching
   `destination`'s own disclosed coarsening precedent.
5. **`validate.js`**: a structural check for `node.storeDetail` when
   non-null, mirroring `node.destination`'s own "only checked when the
   parent object is present" shape exactly: `operation` must be `null` or
   a live `STORE_OPERATION_VALUES` member (imported, not hardcoded);
   `columns` must be an array of strings when present.

## Do NOT touch

`orm-write-catalog.js`/`matchOrmWrite` (its signature stays
callee-only — the plan already established this in increment 1 and E2
does not need to change it, since all the new extraction happens in
`graph-builder.js`, which already has `arg0` in scope), `sink-registry.js`
(`reclassifyOrmWrite`'s own return shape is unrelated to `storeDetail`),
`resolve-destination.js`/Sub-project A's own files (that's a DIFFERENT
sink-node field, `node.destination`, for external-api-category nodes —
`storeDetail` is specific to database-category ORM-write sites and the
two must never be conflated), general `CATALOG`/raw-SQL `database` sinks
(their own table/column extraction would need SQL parsing — explicitly
out of scope per the E-scoping doc's own Finding 2, not attempted here or
ever without a dedicated increment naming that tradeoff).

## Test plan

Extend `test/catalog-orm-write.test.js` (the existing precision-proof file
for this whole ORM-write feature — do not create a new test file, this is
one more property of the same site-recognition mechanism):

1. `User.create({ email: x, password: y })` → `storeDetail.table === 'User'`,
   `storeDetail.operation === 'create'`, `storeDetail.columns` contains
   exactly `['email', 'password']` (order doesn't matter — sort before
   comparing, or use a Set-equality assertion).
2. `Order.save({...})` → `storeDetail.operation === 'upsert'` — the
   disclosed `save`-ambiguity proof, with a comment explaining why (per
   step 1's own reasoning, don't just assert the value without the
   "why").
3. A spread argument mixed with real keys — `User.create({ email: x,
   ...extra })` — `storeDetail.columns` contains `'email'` only, never a
   fabricated key for the spread.
4. A computed, non-literal key — `` User.create({ [dynamicKey]: x, email:
   y }) `` → `storeDetail.columns` contains `'email'` only, `'*'` is
   NEVER a reported column name.
5. `validateGraph()` stays clean on a real graph containing an ORM-write
   node with a populated `storeDetail`.
6. A `validate.js`-level test for the new structural check (valid/invalid
   `operation`, `columns` type check) — mirror
   `test/lineage/validate.test.js`'s own `destination` test pattern
   (Sub-project A, increment 1) exactly; this new test belongs in THAT
   file, not `catalog-orm-write.test.js`, since it is testing
   `validate.js`'s own generic structural-check machinery, not ORM-write
   recognition specifically.
7. Full `npm run test:lineage`, `npm run test:dataflow`, and `npm test`
   stay green, real captured exit codes.

## Explicitly deferred

`provider`/`host`/`database`/`schema` extraction — needs config-chain
resolution (Sub-project A's own still-open scope) or a schema-correlation
mechanism neither this increment nor any prior one builds. Table/column
extraction for raw-SQL `database` sinks (needs SQL parsing, out of scope
per the E-scoping doc). Python/Java/Go/Ruby/PHP ORM shapes (increment 1's
own JS/TS-only scope boundary, unchanged). Queue/topic mapping (E3).
