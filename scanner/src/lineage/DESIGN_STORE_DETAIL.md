# DESIGN_STORE_DETAIL.md — Sub-project E's binding design record (increment 2)

**Status:** landed as Milestone 2, Sub-project E, increment **2** — a
small, focused slice, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e2-plan.md`.
Binding on later Sub-project E increments the same way `DESIGN_
DESTINATION_RESOLVER.md` binds Sub-project A — but this record covers its
own, unrelated field: `node.storeDetail` is specific to database-category
ORM-write sink nodes, never to be conflated with `node.destination`
(Sub-project A's own field, for external-api-category nodes).

---

## 1. What this increment actually is

Increment 1 (`8e733fe9`) shipped ORM-write SITE RECOGNITION only: a call
site like `User.create({ email: x })` is recognized as an ORM-write sink
candidate, but nothing about the call is extracted or retained beyond that
boolean fact — no table name, no operation, no column list. This increment
extracts FR-204's structured facts from a site increment 1 already
recognizes, and attaches them to the sink node as a new field,
`node.storeDetail`.

**PRD text (FR-204, verbatim):** *"When supported evidence exists, a
database sink must include provider, host/config reference, database,
schema, table/collection, operation, column/field mapping. Unknown portions
remain `unknown`; the entire store must not be omitted."*

No new detection. Every fact extracted here was already in scope at the
recognized call site — `resolveOrmWriteAtCallSite` already has, in scope,
the callee expression (whose `object.name` is the model identifier), the
matched catalog entry's own `callee` (`create`/`save`/`update`/`upsert`),
and the confirmed object-literal first argument. This increment reads three
of those facts it was already holding and never recording.

---

## 2. The `storeDetail` object shape

```
{
  provider: string | null,   // deferred to a later increment — always null in E2
  host: string | null,       // deferred — always null in E2
  database: string | null,   // deferred — always null in E2 (DB/cluster name, not the table)
  schema: string | null,     // deferred — always null in E2 (SQL schema/namespace)
  table: string | null,      // the model/receiver identifier name (e.g. 'User'), or null if unavailable
  operation: string | null,  // one of schema.js's STORE_OPERATION_VALUES, or null if unavailable
  columns: string[],         // real, non-'*' property key names from the object-literal argument; [] if none
}
```

`table`/`operation`/`columns` are the only fields this increment ever
populates, and only from JS/TS ORM-write sites recognized by increment 1's
own catalog. `provider`/`host`/`database`/`schema` stay `null`
unconditionally in every case this increment produces — this is FR-204's
own "unknown portions remain unknown" clause in action, not a gap silently
left to be filled later without saying so.

## 3. `table` — the receiver identifier

`calleeExpr.object.name`, already confirmed a string by
`_ormReceiverIsCapitalizedIdent`'s own check inside `orm-write-catalog.js`
before a site is even recognized. Re-verified defensively at the extraction
site rather than assumed to have survived unchanged — a `typeof` guard, not
a re-implementation of that check.

## 4. `operation` — the method-name mapping

The mapping lives in `graph-builder.js`, not `schema.js` — `schema.js`
holds enums, not mapping logic, per this package's own established
separation (the same split `sink-registry.js`'s `CWE_MAP` vs.
`schema.js`'s `SINK_CATEGORIES` already establishes).

| catalog `callee` | `operation` |
|---|---|
| `create` | `'create'` |
| `update` | `'update'` |
| `upsert` | `'upsert'` |
| `save` | `'upsert'` |

**`save` → `'upsert'`, not `'create'` — a deliberate, disclosed judgment
call.** Mongoose's `.save()` performs an INSERT on a new document but an
UPDATE on one loaded from the database, which is genuinely undecidable
statically from the call site alone; `'upsert'` is the honest umbrella
covering both, not a guess at which one it is. Any catalog `callee` outside
this table (there are none today — `ORM_WRITE_CATALOG` has exactly these
four entries) maps to `null`, never a fabricated guess.

## 5. `columns` — the object-literal property keys

`arg0.props`, filtered and mapped:

```js
[...new Set(
  arg0.props
    .filter((p) => !p.spread && typeof p.key === 'string' && p.key !== '*')
    .map((p) => p.key),
)]
```

Two exclusions, both load-bearing (per `parser-js.js`'s real
`ObjectExpression` lowering, confirmed by direct read, ~line 116-159):

- **A spread entry** (`{spread: true, value: <expr>}`, no `key` field at
  all — `{...extra}`) has no key to report. Reporting one would be a
  fabrication.
- **A `'*'`-keyed entry** (a non-literal computed key, `resolveObjectKey`'s
  established convention — `{[dynamicKey]: x}`) is a genuinely UNKNOWN
  column name, not a literal column named `"*"`. Reporting `'*'` as a real
  column name would be the exact fabrication `field-identity.js`'s own
  `object` case already refuses to commit one level up (see
  `scanner/src/lineage/CLAUDE.md`'s "Round 5" note).

Deduplicated via `[...new Set(...)]` since two distinct-value properties
can share a key in real (if unusual) source — `{email: a, email: b}` — and
without dedup that would report `'email'` twice, a differently-shaped
version of the same over-counting bug increment 1's own precision work
elsewhere in this package has repeatedly guarded against.

## 6. Wiring — mirrors `destination`'s own precedent exactly

`mintNode` gains an optional `storeDetail` param (default `null`).
`sinkNodeFor` passes `site.storeDetail ?? null` through — the exact wiring
point `destination` already established. `storeDetail` is set once, at node
MINT time, and is deliberately **NOT** part of the node identity
discriminator (`ids.nodeId`'s inputs are unchanged) — the same disclosed
coarsening `destination` already accepted: two sites colliding onto one
registry-decision node (same `kind`/`subtypeKey`/`coverageStatus`/
`externality`) still collide onto one node, and that node's `storeDetail`
is whichever site's resolution landed first, not a set/union of every
site's own facts.

## 7. Explicitly deferred (named, not silently skipped)

- **`provider`/`host`/`database`/`schema` extraction** — needs config-chain
  resolution (Sub-project A's own still-open scope) or a schema-correlation
  mechanism neither this increment nor any prior one builds.
- **Table/column extraction for raw-SQL `database` sinks** — needs SQL
  parsing, out of scope per the E-scoping doc's own Finding 2. This
  increment is JS/TS ORM-write-site-only.
- **Python/Java/Go/Ruby/PHP ORM shapes** — increment 1's own JS/TS-only
  scope boundary, unchanged.
- **Queue/topic mapping** — Sub-project E, increment 3.
