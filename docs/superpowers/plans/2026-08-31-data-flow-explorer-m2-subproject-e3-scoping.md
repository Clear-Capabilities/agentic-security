# Milestone 2, Sub-project E, increment 3 scoping: queue/topic mapping

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e-scoping.md`'s
own E3 row, which deliberately left this open pending a reachability check
("verify, don't assume, when E3 is actually scoped"). This document is
that check, plus the resulting scope correction.

## Finding: queue sinks are ALREADY reachable — unlike E1's database situation

Confirmed by direct read (2026-08-31, HEAD `72d2a5b0`): `sink-registry.js`'s
`PRIVACY_CATEGORY_MAP` already has a `'queues': {category: 'queue', status:
'modeled', ...}` row (line 221), and `dataflow/privacy-catalog.js` already
ships two real, matched entries — `privacy-js-queue-sendMessage`
(`sendMessage` on a `queue|sqs|SQS`-named receiver) and
`privacy-js-queue-publish` (`publish` on a `queue|sns|SNS|topic|pubsub|
kafka|producer`-named receiver). `graph-builder.js`'s `enumerateSinkSites`
already calls `matchPrivacySink` for every statement-call site — the SAME
matcher call increment 1/2's ORM-write work had to build a whole NEW
isolated catalog to avoid touching. **A queue sink node already exists in
the graph today, with `kind: 'queue'`, whenever a real fixture reaches one
of these two call shapes — no new catalog, no new isolation architecture,
no new precision-guard design question, unlike E1.** This is why E3 is
genuinely smaller than E1/E2 combined, not a comparable-sized third
increment.

## What's still missing: topic/queue NAME extraction

`node.destination` (Sub-project A) does NOT currently capture a queue's
topic/queue name. Confirmed by reading `coverage.js`'s FR-203 gates
directly: `'queue'` is in `FR203_ELIGIBLE_KINDS` (so the RECEIVER signal —
literal vs. dynamic receiver — applies), but `'queue'` is NOT in
`FR203_ARG0_DESTINATION_CATEGORIES` (so the ARGUMENT signal never runs for
a queue site). This matters because the two real entries name the topic/
queue identity in TWO STRUCTURALLY DIFFERENT places, neither of which
today's `resolveDestination` looks at:

1. **SQS `sendMessage`**: the queue identity is a `QueueUrl` FIELD inside
   the call's object-literal argument (`sqs.sendMessage({QueueUrl: '...',
   MessageBody: ...})`) — an object-literal-property extraction, the SAME
   shape E2's `columns` extraction already solved for ORM writes. This
   part is directly reusable know-how, not a new problem.
2. **SNS/Kafka `publish`**: the topic identity is typically NOT in this
   call's own arguments at all — it's baked into the RECEIVER's own prior
   construction (`const topic = pubsub.topic('my-topic-name'); topic.
   publish(...)`), a SEPARATE call site increment 3 cannot see from
   `publish`'s own `calleeExpr`/`args` alone. Extracting this would need
   either (a) a second, cross-statement lookup — finding the `object`
   identifier's own defining assignment elsewhere in the function/file and
   inspecting THAT call's argument, real new complexity this package has
   no existing primitive for — or (b) accepting `topic: null` for this
   shape as an honest, disclosed gap, matching FR-204's own "unknown
   portions remain unknown" clause exactly.

## Recommended scope for increment 3

**Small**, smaller than E1 or E2 individually:

1. Extract the `QueueUrl` field (or, more generally, the FIRST matching
   key from a short, disclosed alias list — `QueueUrl`/`TopicArn`/`topic`/
   `queueName` — covering the shapes the two real catalog entries'
   `match.receiverTypeIn` alternations imply) from the object-literal
   argument, when present, reusing the exact `props`-filtering shape E2's
   `ormWriteColumns` already established (exclude spreads, exclude `'*'`
   computed keys).
2. Populate it onto `node.storeDetail.table` (renaming the field's own
   MEANING is real, undecided scope — `storeDetail`'s own `table` field
   was named for the database case; whether a queue's "table" is better
   read as its own `topic` field on a possibly-renamed/generalized shape,
   or whether `storeDetail` should stay database-specific and a NEW
   `node.queueDetail` mirrors it, is this increment's own first design
   decision, not resolved here) or a new dedicated field — **decide this
   before writing the implementation plan**, don't improvise it mid-task.
3. For the SNS/Kafka `publish` shape (topic identity elsewhere in the
   file), ship it honestly returning `null`/`unknown` — do NOT attempt the
   cross-statement lookup in this increment; name it as explicitly
   deferred, the same discipline every other increment this session has
   applied to a genuinely harder sub-case.
4. `operation` for a queue sink is simpler than the database case — both
   real entries are unambiguously a WRITE (`sendMessage`/`publish`), no
   `save`-style ambiguity exists here to disclose.

## What this does NOT do

Extend queue RECOGNITION beyond the two entries `privacy-catalog.js`
already ships (no new catalog entries, no new languages — JS/TS only,
continuing the whole session's scope boundary). Does not solve the
cross-statement topic-name lookup for the `publish`-on-a-constructed-topic
shape (named above as explicitly deferred). Does not touch
`orm-write-catalog.js`, `sink-registry.js`'s `reclassifyOrmWrite`, or
anything E1/E2 shipped — this is queue-side work only.
