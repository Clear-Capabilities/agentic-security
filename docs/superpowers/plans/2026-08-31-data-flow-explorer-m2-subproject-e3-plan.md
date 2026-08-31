# Milestone 2, Sub-project E, increment 3: queue/topic mapping (`node.queueDetail`)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e3-scoping.md`.
That document already answered the reachability question (queue sinks are
already matched via the existing `privacy-catalog.js` entries, already
wired into `enumerateSinkSites` via `matchPrivacySink` — no new isolated
catalog needed) and named the one open design question this plan now
resolves.

## Design decision: a NEW `node.queueDetail` field, not `storeDetail` reuse

Confirmed by direct read: `schema.js`'s `NODE_KINDS` lists `'queue'` as its
own distinct value, separate from `'store'` (the database node kind) —
`sink-registry.js`'s `CATEGORY_NODE_KIND['queue'] === 'queue'`. A queue
node is never a store node. Reusing `storeDetail`'s `table`/`database`/
`schema` fields for a queue's topic/queue-URL identity would be a
semantic mismatch (a queue has no table, no schema) — the same reasoning
that gave `node.destination` (Sub-project A, external-api nodes) and
`node.storeDetail` (Sub-project E, increment 2, database nodes) each their
own field rather than one shared "extra facts" blob. This increment mints
a THIRD, parallel field: `node.queueDetail`, populated only on `kind:
'queue'` nodes.

## The `queueDetail` object shape

```
{
  provider: string | null,   // deferred — always null in this increment (AWS/GCP/etc. — needs config-chain resolution, Sub-project A's own still-open scope, same reasoning storeDetail's provider/host stay null)
  topic: string | null,      // the queue URL / topic / stream name, when extractable — see §3 below for which shapes this increment can and cannot extract
  operation: string | null,  // one of schema.js's new QUEUE_OPERATION_VALUES, or null
}
```

Add `QUEUE_OPERATION_VALUES = Object.freeze(['publish', 'unknown'])` to
`schema.js`, right after `STORE_OPERATION_VALUES`. Only two values,
deliberately — both real catalog entries (`sendMessage`, `publish`) are
unambiguously a WRITE/publish operation, unlike the database case's real
`create`/`update`/`upsert` spread; there is no `read`/`delete`/`create`
ambiguity to disclose here. Every queue site this increment recognizes
gets `operation: 'publish'` — never `'unknown'` in practice today (no
catalog entry produces anything else), but the value exists so
`validate.js`'s structural check has a real enum to check against, the
same "define the vocabulary even if only one value is reachable today"
precedent `HANDLING_VALUES`/`STORE_OPERATION_VALUES` both already
established.

## `topic` extraction — two real shapes, one honestly unsupported

Both real `PRIVACY_SINK_CATALOG` entries (`dataflow/privacy-catalog.js`,
already read this session):

1. **`privacy-js-queue-sendMessage`** (`sqs.sendMessage({QueueUrl: '...',
   MessageBody: ...})`): the queue identity is a `QueueUrl` FIELD inside
   the call's own object-literal first argument. Directly extractable by
   the SAME `props`-filtering shape increment 2's `ormWriteColumns`
   already established (`scanner/src/lineage/graph-builder.js` — read that
   function directly before writing this one; reuse its exact filter
   logic — exclude spread entries, exclude `'*'`-keyed computed entries —
   but this increment wants the VALUE of one specific matching key, not
   every key name, so it is a different, smaller function, not a call to
   `ormWriteColumns` itself). Look for a property whose `key` matches one
   of `['QueueUrl', 'TopicArn', 'topic', 'queueName']` (a short, disclosed
   alias list — name it exactly this size, do not invent additional
   aliases speculatively) and, when found AND that property's own `value`
   is itself a `kind: 'literal'` expression (reuse `resolve-destination.js`'s
   `isLiteral`-equivalent check — a non-literal value, e.g. a variable,
   stays `topic: null`, never a guess), extract `String(value.value)` as
   `topic`. When no matching key is found, or the matching key's value
   isn't a literal, `topic` stays `null` — this call site genuinely
   recognized as a queue sink, just without an extractable identity, the
   same honest-absence discipline `storeDetail.table` follows when a
   receiver name is somehow unavailable.
2. **`privacy-js-queue-publish`** (`topic.publish(...)` /
   `producer.publish(...)`): the topic identity is typically NOT in this
   call's own arguments — it lives in a SEPARATE, earlier statement that
   constructed the receiver (`const topic = pubsub.topic('my-topic-name');
   topic.publish(...)`). This increment does **not** attempt a
   cross-statement lookup (finding the receiver identifier's own defining
   assignment elsewhere in the function/file) — no primitive for that
   exists anywhere in `src/lineage/` today, and building one is real,
   undecided scope bigger than this increment. For THIS shape, `topic`
   stays `null` unconditionally — an honest, disclosed gap, not a
   half-attempt. State this explicitly in the design doc and in a code
   comment at the extraction site, so a future reader doesn't mistake the
   `null` for a bug.

## Implementation

**`schema.js`**: add `QUEUE_OPERATION_VALUES` as specified above.

**New short design doc**, `scanner/src/lineage/DESIGN_QUEUE_DETAIL.md`,
mirroring `DESIGN_STORE_DETAIL.md`'s own scale — cover the shape, the two
real extraction cases, and the explicitly-deferred cross-statement lookup.

**`graph-builder.js`**: a new function, e.g. `extractQueueDetail(args)`
(only needs `args` — `operation` is always `'publish'` when this is called
at all, so no `calleeExpr`/callee-name parameter is needed, unlike
`resolveOrmWriteAtCallSite`'s `table`/`operation` extraction which DID need
the callee). Wire it into `enumerateSinkSites`'s existing statement-call
branch (`scanner/src/lineage/graph-builder.js`, read the CURRENT file
before assuming line numbers — the function you're extending has grown
across two prior increments): immediately after the existing
`const r = resolveSinkAtCallSite(node.callee, fn.file); if (r) sites.push(...)`
line, add `if (r && r.decision.category === 'queue') { const site =
sites[sites.length - 1]; site.queueDetail = extractQueueDetail(node.args ??
[]); }` — a conditional POST-step on the already-pushed site object, not a
change to `resolveSinkAtCallSite`'s own signature (that function has no
`args` parameter today and adding one would be a wider, unnecessary
change for a fact only the queue category needs). Verify this exact
insertion point and variable names against the real current file before
writing code — this plan's own citation may already be one increment
stale by the time you read it (D2's own plan had this exact problem and
its implementer caught it by re-reading first; do the same).

**`mintNode`/`sinkNodeFor`**: gain a `queueDetail` param mirroring
`destination`/`storeDetail`'s own wiring EXACTLY — optional, default
`null`, passed through only by `sinkNodeFor`, never part of the node
identity discriminator.

**`validate.js`**: a structural check for `node.queueDetail` when
non-null, mirroring `node.storeDetail`'s own check shape: `operation` must
be `null` or a live `QUEUE_OPERATION_VALUES` member; `topic` must be
`null` or a string (no array-of-strings shape here, unlike `storeDetail
.columns` — a queue site names exactly one topic, not a set of columns).

## Do NOT touch

`orm-write-catalog.js`, `sink-registry.js`'s `reclassifyOrmWrite`,
`resolveOrmWriteAtCallSite`, `node.storeDetail`'s own extraction/wiring
(that's the DATABASE-side field from increment 2 — this increment adds a
parallel, separate field, never modifies that one), `resolve-destination.js`
(read-only reference for its `isLiteral`-equivalent pattern, per §3 above,
never imported/modified), `privacy-catalog.js`'s own two queue entries
(already correct, already reachable — nothing to change there).

## Test plan

New `scanner/test/lineage/queue-detail.test.js` (a NEW file, mirroring
`handling-analyzer.test.js`'s own file-per-feature precedent — this is
its own coherent property, not an extension of `catalog-orm-write.test.js`,
which is specifically about the ORM-write catalog):

1. `sqs.sendMessage({QueueUrl: 'https://sqs.../my-queue', MessageBody: x})`
   on a real parsed fixture (receiver named to match
   `privacy-js-queue-sendMessage`'s own `receiverTypeIn: ['queue|sqs|SQS']`
   — e.g. a variable literally named `sqs`) → `queueDetail.topic ===
   'https://sqs.../my-queue'`, `queueDetail.operation === 'publish'`.
2. The same shape with `QueueUrl` given a NON-literal value (a variable)
   → `queueDetail.topic === null`, still `operation: 'publish'` (the site
   is still a real, recognized queue sink — only the identity is
   unavailable).
3. `topic.publish(x)` (receiver named `topic` to match
   `privacy-js-queue-publish`'s own alternation) → `queueDetail.topic ===
   null` (the honestly-deferred cross-statement case), `operation ===
   'publish'` — WITH a test comment explicitly stating this is the
   expected, disclosed gap, not a bug to fix later without updating this
   test.
4. `validateGraph()` stays clean on a real graph containing a queue node
   with a populated `queueDetail`.
5. A `validate.js`-level test (in `test/lineage/validate.test.js`,
   alongside the existing `storeDetail` tests, not a new file) for the new
   structural check.
6. Full `npm run test:lineage`, `npm run test:dataflow` (the privacy
   catalog's own existing tests must stay unaffected — confirm, don't
   assume), and `npm test` stay green, real captured exit codes.

## Explicitly deferred

The cross-statement topic-name lookup for `publish`-on-a-constructed-topic
(named above, real future work, no primitive exists for it today).
`provider` extraction (needs config-chain resolution, Sub-project A's own
scope). Any language beyond JS/TS. Any queue SDK shape beyond the two
`privacy-catalog.js` already recognizes (Redis streams, RabbitMQ, etc. are
NOT in `PRIVACY_SINK_CATALOG` today — widening queue RECOGNITION itself is
real, separate scope this increment does not attempt).
