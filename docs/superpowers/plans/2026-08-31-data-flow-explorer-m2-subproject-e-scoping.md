# Milestone 2, Sub-project E scoping correction: DB/table/column + queue/topic mapping

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-scoping.md`
§5's row E: *"Reclassifies `cross-lang-orm.js`'s table.column-registry
matching mechanism and `cross-lang-queues.js`'s topic-pairing mechanism
(Decision 4 — logic reused, chain-finding state not) into `DataFlowGraph v1`
store/queue node fields... Medium."* This document corrects that framing
after reading both modules and the current sink catalog directly — the
same "PRD/scoping-doc wording doesn't fit reality" discipline Milestone 1's
Sub-project D applied to AC-07 ("not satisfiable by reclassification alone")
and Sub-project G applied to the "flagship demo repo" comparison target.

## The real gap, confirmed by direct read (2026-08-31, HEAD `090c78d1`)

**Finding 1 — `cross-lang-orm.js`/`cross-lang-queues.js` are raw-text,
whole-project regex scanners, architecturally incompatible with the
lineage engine's per-call-site IR model.** Both modules' real entry points
(`findOrmWrites`/`findOrmReads` in `cross-lang-orm.js`;
`PRODUCER_PATTERNS`/`CONSUMER_PATTERNS` in `cross-lang-queues.js`) operate
on `fileContents` — raw source TEXT across the whole scanned tree — via
hand-rolled regexes (`/\b([A-Z]\w+)\s*\.\s*(?:create|save|update...)\s*\(...)/g`),
building a project-wide `table.column` / `topic-name` registry and pairing
writes with reads/producers with consumers by matching STRING content
across files. The lineage engine's `graph-builder.js`/`coverage.js` operate
on ALREADY-PARSED per-call-site data (`site.calleeExpr`, `site.args`, a real
expression tree from `parser-js.js`) for ONE recognized sink call at a time
— there is no "whole project registry" concept anywhere in `src/lineage/`,
and Milestone 1 deliberately never built one (Sub-project C's path-DAG is
per-function/per-call-graph, not per-project-text). **"Decision 4 — logic
reused, chain-finding state not" undersells the real gap**: the two
modules' regex PATTERNS are useful reference material for which ORM/queue
API shapes exist across languages, but neither module exposes a
"given this one already-classified sink call site, extract its
table/column/topic facts" function — that function does not exist anywhere
in this codebase today and has to be newly written against the lineage
engine's own parsed IR, the same way `resolve-destination.js` (Sub-project
A, increment 1) newly wrote destination extraction against parsed IR rather
than reusing anything text-regex-shaped.

**Finding 2 — the lineage engine's `database`-category sinks are ALL
raw-SQL-string calls; NONE are ORM method calls.** Confirmed by grepping
`dataflow/catalog.js`: every one of the 39 `CWE-89`/`CWE-943`-tagged sink
entries (`sink-registry.js`'s own `CWE_MAP` maps both to `category:
'database'`) is a `db.query(sql)`/`cursor.execute(sql)`/
`Statement.executeQuery(sql)`-shaped call, where the tainted argument is a
SQL STRING (often built via concat/template) — never a structured ORM call
like `Mongoose.create({field: value})`, `Model.objects.create(field=value)`,
or Prisma's `prisma.model.create({data: {...}})`. `js-sql-query`/
`js-sql-execute` DO accept `sequelize`/`prisma`/`knex` as receiver names,
but ONLY for their `.query()`/`.execute()` raw-SQL escape hatches — never
for `.create()`/`.save()`/`.findOne()`. `.create()` was in fact recently
confirmed EXCLUDED as a false positive for a DIFFERENT catalog family
(Sub-project H's AC-07 precision fix, `receiverBase` constraints on the
AI-provider entries, closed because `db.messages.create()`/
`prisma.messages.create()` are ordinary ORM row-inserts, not AI calls) —
this repo has already had to actively defend against ORM `.create()` being
mistaken for something else, and it is not itself cataloged as anything.

**Consequence:** FR-204's own headline data ("table/collection, operation,
column/field mapping") is exactly the data ORM writes carry and raw SQL
strings do NOT structurally expose without a SQL parser — a scope this
repo's own `CLAUDE.md` conventions have twice rejected adding for other
detectors ("same bundle-size argument that rejected an XML parser here,"
`iac-cloud-templates.js`'s own precedent). **Extracting table/column data
from a `db.query('SELECT ... FROM users ...')`-shaped sink would require
SQL parsing — out of scope, not attempted.** Extracting it from an ORM call
IS tractable (the model name and field names are literal source-text
tokens in the call's own arguments, exactly like `resolve-destination.js`
extracts a literal URL from a `fetch()` call's own argument) — but no
sink-catalog entry recognizes an ORM write as a `database` sink at all yet.

## Recommended increment breakdown (revised)

The scoping doc's own "Medium" sizing assumed a straightforward
reclassification; the real first increment is closer in shape to
Sub-project H's AC-07 catalog bridge (Milestone 1) than to Sub-project
D2/D3's registry reclassification (Milestone 1) — new catalog entries
first, THEN new per-call-site extraction logic, not a pure relabeling pass.

- **E1 (catalog bridge, Small-Medium):** add new `dataflow/catalog.js` sink
  entries for the JS/TS ORM write shapes `cross-lang-orm.js`'s own
  `findOrmWrites` regex already names as prior art (Mongoose
  `.create/.save/.update/.insert/.upsert`, Sequelize, Prisma's `data: {...}`
  wrapper form) — reusing the API-SHAPE KNOWLEDGE from that module (which
  method names, which argument shape), never its raw-text regex mechanism
  itself. Needs a `receiverBase`-style precision guard exactly like AC-07's
  own fix, since `.create()` is a dangerously generic name. Add the new
  `CWE_MAP`/category row this needs in `sink-registry.js` (likely a NEW
  category value, since `database` today means "raw SQL string sink" — a
  literal ORM row-write is a materially different evidence shape FR-204
  itself distinguishes; deciding whether to reuse `database` or mint a new
  category, e.g. `orm-write`, is E1's own design call, grounded against
  `schema.js`'s existing `SINK_CATEGORIES` enum, not decided here).
- **E2 (structured extraction, Medium):** for a sink site the E1 catalog
  entries recognize, extract `model` (→ FR-204's `table/collection`) from
  the call's receiver/first-arg identifier and `field` names (→ FR-204's
  `column/field mapping`) from the call's own object-literal argument keys
  — parsed-IR extraction, mirroring `resolve-destination.js`'s own literal-
  argument handling, never regex-over-text. Needs a new node-level schema
  field (this repo has no `table`/`column`/`operation` fields anywhere in
  `schema.js` today — unlike Sub-project A's `destination`, which Milestone
  1 pre-stubbed at `null`; this is genuinely NEW schema surface, e.g. a
  `node.storeDetail` object, parallel to `node.destination`, on
  `database`/`object-storage` category nodes). `provider`/`host` (FR-204's
  remaining two facts) stay `unknown` in E2 — those need config-chain
  resolution, Sub-project A's own still-open scope, not duplicated here.
- **E3 (queue/topic mapping, Medium):** the queue-side equivalent —
  `cross-lang-queues.js`'s `PRODUCER_PATTERNS`/`CONSUMER_PATTERNS` regex
  ARE genuinely reusable as literal reference data (per-tech topic-name
  extraction shapes for Kafka/SQS/RabbitMQ/Redis streams/Pub-Sub), same
  "prior art, not a callable function" caveat as E1. Whether queue SINKS
  even exist as a reachable `SINK_CATEGORIES` value today needs confirming
  before scoping this increment's own plan (`sink-registry.js`'s own
  `queue` row was noted in Milestone 1's D3 table as reachable via
  `PRIVACY_SINK_CATALOG` only, not general `CATALOG` — verify, don't
  assume, when E3 is actually scoped).

E1 is the true prerequisite for E2 (no sink site to extract from without
the catalog entry existing first); E3 is independent of E1/E2 and could be
built first if a coordinator prefers, but is scoped last here because its
own "is a queue sink even reachable today" question is unresolved and needs
its own direct-read pass before a real plan can be written, the same
discipline this document just applied to the DB half.

## What this does NOT change

Milestone 2's own scoping doc (`...-m2-scoping.md`) and its sub-project
table stand as written for everything else — this document narrows and
corrects ONLY Sub-project E's own row, the same way Sub-project D's own
Milestone-1-era AC-07 finding narrowed only that one acceptance criterion
without touching the rest of that milestone's scoping. `scanner/src/lineage/CLAUDE.md`'s
own "Milestone 2 status note" (added alongside Sub-project D's completion,
commit `090c78d1`) should be read alongside this document — E1/E2/E3 above
replace that note's one-line "Sub-projects... E... entirely unstarted"
mention with real, buildable increments once E1 actually lands.
