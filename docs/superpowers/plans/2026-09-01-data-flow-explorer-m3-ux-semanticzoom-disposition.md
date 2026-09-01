# M3-UX, sub-project SemanticZoom: disposition (not a scoping+plan — genuinely blocked)

Per the M3-UX parent scoping doc's own SemanticZoom row: *"does any node
carry function/field-level detail beyond what's already surfaced
(`node.storeDetail.columns`, `node.queueDetail.topic`)? Not investigated
this pass; a real, disclosed open question for a future, separate
scoping increment."* This document IS that investigation. It is
deliberately NOT a scoping+plan+SDD cycle, because the investigation's
own conclusion is that there is nothing buildable on the frontend today —
see below.

## PRD text (two genuinely different meanings of "semantic zoom")

- **§21's own closing sentence** (performance): *"Large graphs must use
  semantic zoom, server-side or worker-side projections, clustering, and
  visible-element limits."* — in context, this means progressively
  revealing more NODES as a user zooms in on a dense area.
- **§7.3/DFG-030** (richer, UI-detail sense): *"reveal endpoint,
  function, and field detail"* as a user zooms into ONE node.

## Investigation (confirmed this session, direct read of `scanner/src/lineage/`)

- **§21's own "semantic zoom" requirement is ALREADY satisfied** — by
  M3-Render's own level-of-detail clustering (`computeClusteredLayout`),
  which is exactly "reveal more nodes as you zoom/expand." This is not a
  new finding; M3-Render's own CLAUDE.md section already named this
  distinction explicitly.
- **§7.3/DFG-030's own richer sense is NOT buildable on the frontend
  today, confirmed by direct grep of the real schema/graph-builder**:
  - `node.location` is UNCONDITIONALLY `null` for every node
    `graph-builder.js` mints (confirmed by direct read, including its
    own comment: *"A category-granular node has no single source
    location. The flagship fixture sets `location: null` on all 14 of
    its own nodes."*). A node represents a whole CATEGORY (e.g. "all
    calls to `pg.query`" collapse into one `PostgreSQL` node), not one
    real call site — there is no per-node function/endpoint/line to zoom
    into.
  - `node.storeDetail`/`node.queueDetail` are the ONLY per-node "extra
    detail" mechanisms in the entire schema (confirmed: no
    `functionName`/`fieldDetail`/`endpointDetail`/`symbolDetail` field
    exists anywhere in `schema.js`/`validate.js`/`graph-builder.js`),
    and both are narrowly scoped to store/queue KIND nodes only —
    `storeDetail.columns` and `queueDetail.topic` ARE already the
    richest per-node detail this schema carries, and both are already
    fully surfaced (Inventory's own Stores table, the Evidence
    Inspector).
  - Real per-call-site detail (file/line/symbol) DOES exist, but lives
    on `graph.evidence[]` entries, not on nodes — and it's keyed to
    EDGES/FLOWS (which claim proves which edge), not to "this node,
    zoomed in." The Evidence Inspector (PRD §16, already shipped) is
    already the real UI for this data — it is not a "zoom" interaction,
    it is a "select and inspect" one, and it already works.

## Disposition

**Genuinely blocked on backend/scanner work, not a frontend UX
increment.** Building semantic zoom in §7.3/DFG-030's own richer sense
would require the `DataFlowGraph v1` SCHEMA and `graph-builder.js` to
carry real, per-call-site child detail under each category-granular
node (e.g. `node.callSites: [{file, line, function}, ...]`) — a genuinely
new graph-construction capability, not a rendering change. This is:

- Real, substantial, backend (`scanner/src/lineage/`) work — outside
  `frontend/`'s own scope entirely, unlike every other M3-UX increment.
- A real schema-version-bumping change (per `scanner/src/lineage/
  schema.js`'s own header convention — "a change to any array below is a
  schema-version-bumping change" applies equally to a new required node
  field).
- Not attempted here. No frontend UI is built to fake or gesture at this
  capability — that would be exactly the "misleading facet with no real
  data behind it" problem this whole M3-UX effort has consistently
  avoided (Filters' own deferred dimensions, Query's own disclosed
  vocabulary gaps).

**M3-UX's own sub-project table is therefore closed out honestly**:
Query (COMPLETE), Filters (COMPLETE), SemanticZoom (investigated,
confirmed blocked on real backend work not undertaken this pass — not
silently dropped, not faked, named exactly what would be needed).

## What a future increment would need

1. A scanner-side design pass (own scoping doc, own `DESIGN_*.md`,
   matching this repo's established convention) deciding: does a
   category node gain a `callSites` array, or does the graph mint one
   node PER REAL call site instead (a much bigger architectural change,
   likely reopening M3-Render's own clustering-budget math, since real
   scans could then have far more real nodes than today's category-
   collapsed model)?
2. `graph-builder.js` changes to populate whichever shape is chosen,
   for at least `store`/`sink`/`source` kinds initially.
3. `validate.js`/`dataflow-graph.schema.json` updates, a schema version
   bump, and the usual real-fixture-vs-real-scan-output audit this
   session has repeatedly found necessary (a hand-authored fixture can
   trivially carry illustrative call-site data that real scan output
   does not yet produce).
4. Only then would a frontend "zoom into a node, see its real call
   sites" interaction have real data to render.
