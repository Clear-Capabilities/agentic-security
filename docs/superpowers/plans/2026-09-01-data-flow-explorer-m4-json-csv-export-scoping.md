# Milestone 4, sub-project JSON/CSV export: deterministic graph exports

Per the M4 top-level scoping doc's own sub-project table: *"JSON/CSV
export... Small–Medium. The graph is already JSON; CSV is a flat
projection of flows/nodes."* Depends on nothing; is itself a real
dependency for #3 (self-contained HTML report), #4 (PNG/SVG/PDF export),
#6 (Regulatory Overlay evidence packs), #10 (DPIA/RoPA export).

## Correction to the M4 top-level doc's own citation

That doc's row for this sub-project said "the real work is AC-14's
reproducibility guarantee and AC-23's 'presentation-ready' framing." Having
now read AC-23 in full (§26 acceptance criteria), **AC-23 is scoped
specifically to PNG/SVG image export** ("presentation-mode PNG or SVG...
diagram structure... layout seed... viewport... theme") — it belongs to
sub-project #4, not this one. Only **AC-14** (export reproducibility: stable
IDs and semantic content across repeated exports of the same scan) applies
here. Corrected in this doc; the top-level doc's row is stale on this point
and should be fixed when this sub-project ships.

## What the PRD actually requires (§17.5, "Self-contained export")

§17.5 describes JSON/CSV export as part of a bundled HTML export deliverable
("provide print/PDF, PNG/SVG diagram, JSON graph, CSV inventory, DPIA, and
RoPA exports"), not a standalone CLI feature. This sub-project deliberately
narrows to the underlying JSON/CSV SERIALIZATION FUNCTIONS only — pure,
testable, format-producing code — leaving CLI/slash-command wiring to
sub-project #5 and HTML-bundling to sub-project #3, matching the
decomposition this session has used throughout (e.g. Query's parser/
evaluator shipped before Filters' UI, Filters' shared matcher shipped before
either view's wiring). §17.5's other real requirements this sub-project
DOES need to satisfy at the serialization level:

- embed the filtered OR full graph according to caller choice;
- default to redacted snippets and no complete source files;
- include scan health, scope, versions, limitations, and generated
  timestamp;
- include a tamper-evident graph digest (and existing attestation when
  available);
- clearly indicate whether the artifact includes confidential repository
  metadata.

## What already exists (confirmed by direct read this session)

- **`scanner/src/report/index.js`'s `toCSV(scan)`** (line 795) — the real,
  established CSV-writer precedent for THIS repo: a plain `esc(v)` escaper
  (quotes a field only when it contains `,`/`"`/newline, doubles embedded
  quotes), one row per finding, explicit header array. This sub-project
  follows the exact same escaping convention for a flow-shaped CSV, not a
  new one.
- **`scanner/src/mcp/dataflow-tools.js`'s `_redactNode`/`_redactEvidence`/
  `_redactGraph`** (shipped this session, M4's MCP-tools sub-project) — the
  ALREADY-FIXED, tested redaction logic for exactly the fields §17.5 asks
  this export to redact by default: `node.destination.raw`/`.literalValue`
  and `evidence[].claim`/`.snippet`/`.location.note`. **These functions are
  currently private to `mcp/dataflow-tools.js`.** Building a second,
  separate redaction pass for the export path would be exactly the
  "two near-identical copies" bug class this session already found and
  fixed twice (M3-UX-Filters' `rowMatchesFilters`; this same MCP-tools
  sub-project's own initial redaction gap, found by the whole-branch
  review). This sub-project's own first decision (below) is to extract
  and share this logic instead.
- **`graph.graphId`** — already a real, populated field on every graph
  (confirmed via `wrapResponse`'s own `digest: graph?.graphId` mapping in
  `server/routes.js`, and via the MCP tools' own tests). **Confirmed NOT a
  content digest**: `ids.js`'s `graphId({repository, commit, configHash})`
  returns `dfg:<repository>:<commit>:<configHash>` — scan-metadata-derived,
  not a hash of nodes/edges/flows. See decision 4.
- **`posture/attestation.js`'s `computeRunAttestation`/`verifyRunAttestation`**
  — the existing, real tamper-evidence mechanism for scan output (HMAC,
  canonicalized field allowlist). **Confirmed it runs over `scan.findings`
  only** (`bin/agentic-security.js`, both call sites) — never the lineage
  graph. §17.5's "existing attestation when available" has nothing to
  attach to today; see decision 4.
- **`scanner/src/lineage/dataflow-graph.schema.json`** already declares
  `scope`, `coverage`, `limitations`, `generatedAt`, `schemaVersion` at the
  graph's top level (confirmed via `routes.js`'s own `wrapResponse`/
  `handleScan` field mapping) — §17.5's "scan health, scope, versions,
  limitations, generated timestamp" requirement is largely ALREADY real,
  populated data; this sub-project surfaces it in the export formats, it
  does not need to invent new fields.

## Decisions this scoping makes explicitly

1. **Extract `_redactNode`/`_redactEvidence`/`_redactGraph` out of
   `scanner/src/mcp/dataflow-tools.js` into a new shared module,
   `scanner/src/lineage/redact-graph.js`.** `mcp/dataflow-tools.js` imports
   it going forward (a small, behavior-preserving refactor — confirm the
   MCP tools' own 150 tests stay green after the move, since this changes
   only where the functions live, not what they do). The new JSON/CSV
   export module imports the same functions. This directly answers §17.5's
   "default to redacted snippets and no complete source files" bullet with
   already-proven code rather than a second implementation.
2. **JSON export is the graph itself, filtered or full, through the shared
   redaction pass, plus an explicit envelope** — NOT a bespoke new JSON
   shape. `exportGraphJSON(graph, {filter, redact = true} = {})` returns
   `{exportedAt, schemaVersion, digest, scope, coverage, limitations,
   confidential: <bool>, graph: <redacted, optionally filtered graph>}`.
   `filter` accepts the same `{nodeIds, edgeIds}`-shaped selection Focus
   Controls (`frontend/src/lib/focus-controls.js`) already produce — no new
   filter-representation is invented; if a caller wants "the graph visible
   after applying query X," it computes that selection using the EXISTING
   frontend logic and passes the resulting id sets in, keeping this
   sub-project backend-only and reuse-only, matching the MCP-tools
   sub-project's own "wrap, don't reimplement" discipline.
3. **CSV export is flows, one row per flow** (not nodes, not edges) —
   matching `toCSV`'s own "one row per finding" precedent (a flow is this
   domain's closest analogue to "one reportable unit"). Columns, grounded
   in real, confirmed-populated flow fields only (per M3-UX-Query's own
   field audit, reused here rather than re-derived): `id`, `source`,
   `sink`, `dataClasses` (from linked data elements — needs one join step,
   confirm the real join path before implementing), `transitVerdict`,
   `atRestVerdict`, `handlingVerdict` (via the same `worstVerdict()` M3-UX-
   Filters already uses), `policyVerdict`, `coverageStatus`. Node/edge CSV
   exports are explicitly NOT built this increment (real, disclosed,
   deferred — §17.5 only names "CSV inventory" singular, and a flow-level
   CSV already answers the dominant real use case: "what's exposed,
   through what verdicts").
4. **Digest — confirmed, not provisional.** Read `ids.js`'s
   `graphId({repository, commit, configHash})` directly: it returns
   `dfg:<repository>:<commit>:<configHash>` — an IDENTIFIER built from scan
   METADATA, never a hash of the graph's actual node/edge/flow content. It
   is NOT a content digest, and `graphId` collides for two different scans
   of the same repo/commit/config even if their content differs (e.g. a
   partial vs. a complete scan). Also confirmed: `computeRunAttestation`
   (`bin/agentic-security.js`, two call sites) runs over `scan.findings`
   only — never the lineage graph — so "existing attestation when
   available" (§17.5) has nothing to attach to for a graph export today.
   This sub-project therefore computes its OWN content digest, reusing
   `posture/attestation.js`'s canonicalization discipline (sorted,
   allowlisted fields → SHA-256) rather than a fourth hashing convention:
   `computeGraphDigest(graph)` over a fixed field allowlist (`nodes`/
   `edges`/`flows`/`dataElements` ids + risk-bearing fields, excluding
   `generatedAt` and anything timestamp-shaped) — this is also what makes
   AC-14 provable (same graph in twice → same digest out). A real
   `verifyGraphDigest` counterpart is out of scope this increment (no
   consumer needs to verify yet); named for a future increment once one
   does.
5. **`confidential` flag**: `true` whenever the export is unredacted
   (`redact:false` was passed) OR the graph's own `scope` names a real
   repository path/identifier (always true today, per every confirmed real
   graph). This is deliberately a conservative, disclosed-by-default
   posture — §17.5 asks the export to "clearly state" this, not to make a
   judgment call about what counts as sensitive.

## Scope for this increment

1. `scanner/src/lineage/redact-graph.js` (new) — `_redactNode`/
   `_redactEvidence`/`_redactGraph` moved here verbatim from
   `mcp/dataflow-tools.js`, exported. `mcp/dataflow-tools.js` updated to
   import from here instead of defining them locally. Re-run
   `npm run test:mcp` (150 tests) to confirm zero behavior change from the
   move alone, before adding anything new.
2. `scanner/src/lineage/export-json.js` (new) — `exportGraphJSON(graph,
   opts)` per decision 2.
3. `scanner/src/lineage/export-csv.js` (new) — `exportFlowsCSV(graph)` per
   decision 3, reusing `toCSV`'s own `esc()` escaping convention (confirm
   whether to import it from `report/index.js` or duplicate the ~4-line
   function — `report/index.js` is a large module with heavy imports;
   duplicating 4 lines may be more appropriate than adding a cross-package
   dependency edge, matching this session's own "duplicate small test
   helpers rather than import across an unrelated boundary" precedent from
   the MCP-tools test file. Implementer's judgment, disclosed either way).
4. Tests: redact-graph.js's move is covered by the existing MCP test suite
   staying green; `export-json.js`/`export-csv.js` get their own new tests
   against the real flagship fixture (`frontend/src/data/flagship-graph.js`
   or the scanner-side lineage fixture — confirm which is the right one to
   import from `scanner/` without a `scanner/` → `frontend/` dependency
   edge; likely `scanner/src/lineage/fixtures/build-flagship-fixture.mjs`
   is the right one since it already lives in `scanner/`).
5. `scanner/src/lineage/CLAUDE.md` — document the new modules.

## Do NOT touch (real, disclosed deferrals)

- Any CLI/slash-command wiring (`agentic-security dataflow export ...`) —
  sub-project #5's job, once #2/#3/#4 exist to wire together.
- PNG/SVG/PDF export — sub-project #4, its own real open technical
  question (headless SVG serialization).
- HTML report bundling — sub-project #3, consumes this sub-project's JSON
  export as an embedded payload.
- Node/edge CSV exports — deferred (decision 3).
- DPIA/RoPA — depends on sub-project #6 (Regulatory Overlay), which this
  sub-project's own exports will later feed.

## Test plan

1. `redact-graph.js` move: `npm run test:mcp` stays 150/150 green
   (behavior-preservation check).
2. `exportGraphJSON`: real-fixture tests for `redact:true` (default —
   secrets shapes redacted, matching the MCP-tools regression tests'
   own real secret fixtures) and `redact:false` (raw content preserved,
   `confidential:true` asserted), `filter` (a real nodeIds/edgeIds subset
   narrows the returned graph), and AC-14 reproducibility (same graph in
   twice → byte-identical JSON out, excluding only the documented
   `exportedAt` timestamp field).
3. `exportFlowsCSV`: real-fixture test asserting exact expected rows
   against the REAL flagship fixture's own real flow data (grounded, not
   guessed — matching this session's own "read the real data before
   writing an expected value" discipline that has repeatedly caught real
   bugs), plus an escaping test (a flow whose data touches a field
   containing a comma/quote/newline — may need a synthetic fixture
   addition if no real flow exercises this).
4. Full `scanner/npm test` green.
