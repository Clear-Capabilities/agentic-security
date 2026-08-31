# DESIGN_QUEUE_DETAIL.md — Sub-project E's binding design record (increment 3)

**Status:** landed as Milestone 2, Sub-project E, increment **3** — a
small, focused slice, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e3-plan.md`
and its own scoping document. Binding on later Sub-project E increments the
same way `DESIGN_STORE_DETAIL.md` binds increment 2 — but this record
covers its own, unrelated field: `node.queueDetail` is specific to
queue-category sink nodes (`kind: 'queue'`), never to be conflated with
`node.storeDetail` (increment 2's own field, for database-category `store`
nodes — a queue node is never a store node) or `node.destination`
(Sub-project A's own field, for external-api-category nodes).

---

## 1. What this increment actually is

Queue sinks were already reachable before this increment: `sink-registry.js`'s
`PRIVACY_CATEGORY_MAP` already maps the `'queues'` privacy-catalog category
to `{category: 'queue', status: 'modeled'}`, and `graph-builder.js`'s
`enumerateSinkSites` already calls `matchPrivacySink` for every statement-
call site — the same matcher call increment 1/2's ORM-write work had to
build a whole new isolated catalog to avoid touching. A queue sink node
already existed in the graph, with `kind: 'queue'`, whenever a real fixture
reached one of `dataflow/privacy-catalog.js`'s two real queue entries
(`privacy-js-queue-sendMessage`, `privacy-js-queue-publish`). This
increment adds only the missing piece: the queue's own topic/queue-name
IDENTITY, extracted where extractable and attached to the sink node as a
new field, `node.queueDetail`.

## 2. The `queueDetail` object shape

```
{
  provider: string | null,   // deferred — always null in this increment (AWS/GCP/etc. — needs config-chain resolution, Sub-project A's own still-open scope, same reasoning storeDetail's provider/host stay null)
  topic: string | null,      // the queue URL / topic / stream name, when extractable
  operation: string | null,  // one of schema.js's new QUEUE_OPERATION_VALUES, or null
}
```

Every queue site this increment recognizes gets `operation: 'publish'` —
both real catalog entries (`sendMessage`, `publish`) are unambiguously a
WRITE/publish operation, unlike the database case's real
`create`/`update`/`upsert` spread. `QUEUE_OPERATION_VALUES = ['publish',
'unknown']` — only two values, deliberately, the same "define the
vocabulary even if only one value is reachable today" precedent
`HANDLING_VALUES`/`STORE_OPERATION_VALUES` both already established.

## 3. `topic` extraction — two real shapes, one honestly unsupported

### 3.1. `privacy-js-queue-sendMessage` (SQS-shaped)

`sqs.sendMessage({QueueUrl: '...', MessageBody: ...})`: the queue identity
is a field INSIDE the call's own object-literal first argument. Directly
extractable by the same `props`-filtering shape increment 2's
`ormWriteColumns` already established (`graph-builder.js` — exclude spread
entries, exclude `'*'`-keyed computed entries), but this increment wants
the VALUE of one specific matching key, not every key name, so it is a
different, smaller function (`extractQueueDetail`), not a call to
`ormWriteColumns` itself.

A short, disclosed alias list — `['QueueUrl', 'TopicArn', 'topic',
'queueName']`, checked in that order — names the property key to look for.
When a matching key is found AND that property's own value is itself a
`kind: 'literal'` expression (the same check shape as
`resolve-destination.js`'s `isLiteral`, replicated locally per this
package's own "small local copy over cross-module dependency" precedent,
not imported), `String(value.value)` is extracted as `topic`. When no
matching key is found, or the matching key's value isn't a literal, `topic`
stays `null` — this call site is genuinely recognized as a queue sink, just
without an extractable identity, the same honest-absence discipline
`storeDetail.table` follows when a receiver name is somehow unavailable.

### 3.2. `privacy-js-queue-publish` (SNS/Kafka-shaped) — deferred, honestly

`topic.publish(...)` / `producer.publish(...)`: the topic identity is
typically NOT in this call's own arguments — it lives in a SEPARATE,
earlier statement that constructed the receiver (`const topic =
pubsub.topic('my-topic-name'); topic.publish(...)`). This increment does
**not** attempt a cross-statement lookup (finding the receiver identifier's
own defining assignment elsewhere in the function/file) — no primitive for
that exists anywhere in `src/lineage/` today, and building one is real,
undecided scope bigger than this increment. For this shape, `topic` stays
`null` unconditionally. This is an honest, disclosed gap, not a
half-attempt — see `test/lineage/queue-detail.test.js`'s own test comment
for the same disclosure at the point a future reader is most likely to
encounter it.

## 4. Wiring — mirrors `storeDetail`'s own precedent exactly

`mintNode` gains an optional `queueDetail` param (default `null`).
`sinkNodeFor` passes `site.queueDetail ?? null` through — the exact wiring
point `storeDetail` already established. `queueDetail` is set once, at node
MINT time, and is deliberately **NOT** part of the node identity
discriminator (`ids.nodeId`'s inputs are unchanged) — the same disclosed
coarsening `destination`/`storeDetail` already accepted: two sites
colliding onto one registry-decision node (same
`kind`/`subtypeKey`/`coverageStatus`/`externality`) still collide onto one
node, and that node's `queueDetail` is whichever site's resolution landed
first, not a set/union of every site's own facts.

`enumerateSinkSites` applies extraction as a conditional POST-step,
immediately after a general/privacy site is pushed: `if (r.decision
.category === 'queue') { site.queueDetail = extractQueueDetail(node.args ??
[]); }` — not a change to `resolveSinkAtCallSite`'s own signature, which has
no `args` parameter today and would gain one only for a fact solely the
queue category needs.

## 5. Explicitly deferred (named, not silently skipped)

- **The cross-statement topic-name lookup** for the
  `publish`-on-a-constructed-topic shape (§3.2) — real future work, no
  primitive exists for it today.
- **`provider` extraction** — needs config-chain resolution, Sub-project
  A's own still-open scope.
- **Any language beyond JS/TS.**
- **Any queue SDK shape beyond the two `PRIVACY_SINK_CATALOG` already
  recognizes** — Redis streams, RabbitMQ, etc. are not in the catalog
  today; widening queue RECOGNITION itself is real, separate scope this
  increment does not attempt.
