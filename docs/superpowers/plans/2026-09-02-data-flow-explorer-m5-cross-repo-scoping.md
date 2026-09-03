# M5, Cross-repository/federated graph import (deliverable #8): scoping

Per the M5 top-level scoping doc's own deliverable #8 row: `DFG-025`,
explicitly P2 (the lowest backlog tier), framed by FR-304 as "declared
or imported" cross-repo edges, not automatic graph merging. This
document independently re-verifies that recommendation against the real
current code — `ids.js`, `schema.js`, `validate.js`,
`recipient-profile.js`/`recipient-registry.js`, `graph-snapshot.js`,
`graph-loader.js`, `export-json.js`, `governance-edit.js` — before
committing to a plan, the same discipline every prior M5 sub-project in
this series applied to its own parent row. **The narrow "declared edge"
direction is confirmed correct, with one real correction found by this
investigation and not in the parent row: FR-304's "declared or
imported" is not one mechanism but two, with genuinely different
dependency profiles, and this document's own recommended scope covers
only the "declared" half** — see "The real correction" below.

## What FR-304 actually asks for (full text, for the scope-line record)

> **FR-304: Cross-boundary correlation.** Reuse and normalize evidence
> from OpenAPI, gRPC, GraphQL, ORM, queues, and the declared service
> graph. Cross-repository or federated edges may be declared or
> imported, but the graph must identify whether an edge is
> code-derived, schema-derived, manually declared, or
> runtime-corroborated.

`DFG-025`'s own backlog row: **P2**, "Federated/cross-repository
lineage import," depends on **`DFG-002`** (stable IDs) and **`DFG-007`**
(external destination resolver).

## What already exists (confirmed by direct read this session)

- **`ids.js`'s own header is confirmed, verbatim**: "Stable-ID spec for
  DataFlowGraph v1 (PRD 10.1: 'Stable within the repository/commit;
  independent of visual layout')." None of `nodeId`/`edgeId`/`flowId`/
  `dataElementId`'s discriminator arrays include a `repository` field —
  confirmed by reading every one of those four functions directly.
  `graphId({repository, commit, configHash})` IS repository-scoped
  (`dfg:<repo>:<commit>:<config>`).
- **`validate.js`'s `_validateEdge` makes naive array-merging
  structurally impossible, not merely risky — a stronger finding than
  the parent row's own "would silently id-collide" framing.**
  `_validateEdge` requires `nodeIds.has(edge.from)` and
  `nodeIds.has(edge.to)`, where `nodeIds` is built from **the one
  graph's own** `graph.nodes[]` array (confirmed at `validate.js:148-149`,
  called from `validateGraph`'s own single-graph traversal). A plain
  `graph.edges[]` entry whose `to` names a node id minted by a
  DIFFERENT repo's build would fail `validateGraph()` outright, every
  time, regardless of whether that id happens to collide with a local
  one or not. This settles the design question the parent row leaves
  implicit: **a cross-repo edge cannot ever be a core-schema
  `DataFlowGraph v1` edge object** — it must be a new, separate
  extension-contract record, the same shape `RecipientProfile`
  established as the "graph-attached array, not a core entity"
  precedent (see below), not an edge dressed up to pass validation.
- **Because of that same fact, the collision risk the parent row names
  ("an extremely common node shape like a plain `file` sink would
  collide across almost any two repos") never actually materializes
  under a correctly-scoped design — not because of discipline, but
  because of what gets checked and against what.** A cross-repo link
  record's own two endpoint references are each looked up against
  their OWN originating graph's `nodeIds` set — never a merged,
  repo-blind set — so a bare `node:<hash>` string is never used as a
  key into anything but the one graph that minted it. The real design
  requirement this surfaces is narrower than "make node ids
  repo-aware": it is "always carry `(graphId, graphDigest)` alongside
  any foreign node id reference" — which `recipientProfileId`'s own
  `(graphId, graphDigest, recipientKey)` discriminator already
  establishes as this package's precedent for exactly this shape of
  problem (see `ids.js`'s own comment on `recipientProfileId`, quoted
  above in the tool-call output: "no real caller supplies `graphId`'s
  own `configHash` component... two records against genuinely
  different base graphs... collided onto one id without `graphDigest`
  in the material"). The new construct's own id function inherits this
  discriminator shape directly (see Design, below) — `nodeId`/`edgeId`/
  `flowId`/`dataElementId` themselves need **zero** changes.
- **Three pieces of schema vocabulary are already reserved for exactly
  this deliverable, unused by anything shipped so far — confirmed
  directly, not inferred:**
  - `schema.js`'s `EDGE_PROVENANCE_VALUES = ['code', 'schema', 'manual', 'runtime']`
    — its own header comment states "Only `'code'` has a real producer
    today... `'schema'`/`'manual'`/`'runtime'` are reserved for
    Sub-project F2/F3, not yet implemented." Grepping every producer of
    `edge.provenance` in the tree (`graph-builder.js`'s unconditional
    `provenance: 'code'` literal) confirms `'manual'` has never been
    written by any shipped code, on any edge-shaped record, anywhere —
    the M5 Digital Twin deliverable (#7) explicitly named this same
    fact and explicitly declined to close it ("Setting
    `edge.provenance = 'runtime'` — deferred"). **This deliverable, if
    it ships a `provenance: 'manual'` field on its own new record
    (never on a core-schema edge, per the finding above), is the first
    real producer of that value anywhere in this codebase** — the
    parent row's own citation of the Digital Twin scoping doc's "zero
    consumers" note is correct and this document extends it: it is
    "zero producers," specifically, that this deliverable would close
    first.
  - `SOURCE_CATEGORIES`/`SINK_CATEGORIES` both end in a `'declared'`
    entry (confirmed directly in `schema.js`). `DESIGN_REGISTRIES.md`'s
    own §6.5 (quoted in `scanner/src/lineage/CLAUDE.md`'s Sub-project D1
    row) states plainly: `'manual'` coverageStatus "is reserved for the
    operator-declaration path, pairing with the `declared` category —
    which is itself unreachable today for exactly that reason." Three
    independent, already-designed vocabulary slots
    (`coverageStatus: 'manual'`, `SOURCE_CATEGORIES`/`SINK_CATEGORIES`'
    `'declared'`, and `EDGE_PROVENANCE_VALUES`' `'manual'`) all sit
    unused, all pointing at the identical operator-declaration
    use case — a real, concrete signal (not just PRD prose) that a
    narrowly-scoped declared-edge mechanism is exactly the gap this
    codebase's own schema authors already anticipated, not a novel
    invention this document is proposing cold.
- **`recipient-profile.js` + `recipient-registry.js` + `graph-builder.js`'s
  own wiring is the real, load-bearing precedent for "graph-attached
  extension array referencing the graph's own node ids, populated by an
  additive build-time hook":** `graph.recipientProfiles[]` is,
  per `scanner/src/lineage/CLAUDE.md`'s own words, "the FIRST §10.10
  extension-record array ever attached directly to the graph object" —
  never in `dataflow-graph.schema.json`, never routed through
  `validateGraph()`, populated via `opts.buildRecipientProfile(site, graph)`
  wired additively into `graph-builder.js`'s main loop, composed by
  `coverage.js`'s default-hook pattern, loaded once per
  `buildLineageGraph` call by `index.js`. This is the closest existing
  precedent for the new construct this deliverable needs, confirming
  the task brief's own instruction to look here — a `CrossRepoLink`
  record is structurally the SAME shape (a graph-attached array, id'd
  via an object-argument `ids.js` function, validated by a pure,
  `{valid, errors}`-returning validator with zero graph access), with
  one real, disclosed departure from `RecipientProfile`'s own shape:
  every field on a `CrossRepoLink` is uniformly operator-declared (no
  code-derived half), so it needs no `RecipientProfile`-style per-field
  `fieldEvidence` map — a single record-level `provenance` field
  suffices, closer to `ObligationMapping`'s single `factType` shape
  than to `RecipientProfile`'s per-field one.
- **`graph-snapshot.js` is NOT the reusable primitive for "load graph
  A's summary, reference it from graph B" — a real correction against
  the task brief's own framing, found by reading the file directly.**
  `persistGraphSnapshot`/`loadSnapshot(scanRoot, commitKey)` key
  strictly by the LOCAL project's own git commit, inside the SAME
  scanRoot's `.agentic-security/lineage-snapshots/` directory — this is
  "compare two scans of the same repo over time" (the Time Machine's
  own job, FR-503), not "reference a DIFFERENT repo's own graph." Its
  real, transferable lesson is narrower and structural: a directory of
  independently-readable, immutable, keyed JSON files, each self-
  describing its own `graphId`/`schemaVersion`/`commit` — the general
  "point at a local file for another already-built artifact" shape —
  but the actual mechanism this deliverable needs to READ a foreign
  repo's graph is a different, already-shipped module: `graph-loader.js`.
- **`graph-loader.js`'s `loadSignedGraph(scanRoot)` is a real, working,
  already-tested "read another already-scanned graph artifact from a
  local path" primitive — but it carries a genuine, disclosed trust
  problem for the cross-repo case that nothing in the parent row (or
  the task's own framing) surfaces, found by reading `posture/integrity.js`
  directly.** `loadSignedGraph` reads `<scanRoot>/.agentic-security/lineage-graph.json`
  + its `.sig` sibling and calls `verifyLastScan`, which authenticates
  the signature against a **per-install** HMAC key
  (`$XDG_CONFIG_HOME/agentic-security/scan-key`, 32 random bytes,
  generated once per machine/install — confirmed at
  `posture/integrity.js`'s own header and `_keyPath()`) unless
  `$AGENTIC_SECURITY_HMAC_KEY` is explicitly shared. **Two repos scanned
  on two different machines (the overwhelmingly common cross-repo case
  — different teams, different CI runners, different laptops) sign
  under two different keys by default, so pointing `loadSignedGraph` at
  a second repo's checkout on a shared filesystem would, in the common
  case, correctly report `'tampered'` even though nothing was actually
  tampered with** — a real, load-bearing operational gotcha this
  document surfaces for the first time in this M5 series. The safer,
  genuinely portable artifact for the REMOTE side is `export-json.js`'s
  `exportGraphJSON(graph, opts)` output (the `dataflow export --format json`
  artifact): confirmed directly that its return object embeds
  `digest: computeGraphDigest(graph)` (`export-json.js:206-221`), a
  deterministic content hash independent of any local install key,
  excluding only `generatedAt`/`scanHealth`/`timestamp` (confirmed at
  the file's own `EXCLUDE_KEYS` constant) — self-consistency-checkable
  by any reader (recompute `computeGraphDigest` over the embedded
  `graph` field and compare to the embedded `digest`) without needing
  the two repos to share an install or a key at all. This is real,
  useful, but it is NOT authentication — an export file is a plain
  JSON artifact anyone can hand-edit and re-consistency-check (a
  self-consistent digest only proves internal consistency at the time
  of reading, never who produced it) unlike `lineage-graph.json`+`.sig`'s
  real signature. See Design, below, for how this deliverable resolves
  that gap using an already-shipped mechanism rather than inventing a
  new one.
- **`governance-edit.js` + `bin/agentic-security.js`'s `cmdGovernancePropose`
  is the real precedent for "safely write a small operator-declared
  config file via a CLI verb," and its own placement as a NEW
  TOP-LEVEL dispatcher (not a `dataflow` subcommand) is itself a real,
  reasoned precedent this deliverable should follow, not just borrow
  code from.** `commands/governance.md`'s own stated reason: "this
  edits operator config, never the scanned graph" — the identical
  reasoning applies to a cross-repo link declaration (it is config
  the operator is asserting, not a query/derivation over an
  already-built graph the way `dataflow scenario apply`/`dataflow impact assess`/
  `dataflow diff` all are). `remediation.md` is the SECOND already-shipped
  top-level dispatcher for exactly this reason (13 dispatchers total
  today, confirmed via `ls commands/` and the root `CLAUDE.md`'s own
  count) — a real, repeated pattern, not a one-off. The concrete,
  reusable mechanism `governance-edit.js` established: preview/version-
  guard/backup/audit as PRD line 1324's own 5-part write contract, a
  version guard checked BEFORE validation and BEFORE any write, a
  backup written to a dedicated subdirectory before the new content
  lands, and a real hash-chained/audited write via `src/mcp/audit.js`'s
  `auditCall` — all directly reusable, unmodified, for this
  deliverable's own write path.
- **A pre-existing, differently-named, differently-scoped "cross-repository"
  mechanism already exists in this codebase — checked, and confirmed NOT
  reusable here, a real finding not surfaced by the parent row or the
  task brief.** `git log --oneline --all | grep -i cross-repo` surfaces
  `scanner/src/posture/provenance/repo-lineage.js` ("Cross-repository
  lineage declaration," Finding Provenance PRD M4 §4.2 — a wholly
  different PRD than the Data Flow Explorer's own). It reads
  `.agentic-security/repo-lineage.json` (`{ "linkedFrom": { "path":
  "../old-repo-clone", "atCommit": "<sha>" } }`) so `origin-resolver.js`
  can keep walking git-blame-style commit history across a repo
  split/rename — confirmed, via `coordinator.js`/`origin-resolver.js`'s
  own imports, to be consumed ENTIRELY inside `posture/provenance/`, with
  zero reference anywhere in `scanner/src/lineage/`. It is
  structurally a different shape from what this deliverable needs: ONE
  declared link per repo (a repo continues from exactly one prior
  clone), keyed by git commit, answering a TEMPORAL question ("which
  commit really introduced this"); this deliverable needs MANY declared
  links between two independent, contemporaneous peer repos' own
  `DataFlowGraph v1` node ids, answering a SPATIAL/architectural
  question ("does data flow from this node in repo A to that node in
  repo B"). Confirmed not reusable, not extendable-in-place, and
  deliberately given a differently-named artifact
  (`cross-repo-links.json`, not `repo-lineage.json`) specifically so the
  two are never confused by a future reader grepping for
  "cross-repo" in this codebase — the same naming-collision discipline
  the root `CLAUDE.md` already documents for `annotateGitProvenance` vs.
  `annotateProvenance`/`annotateFindingProvenance`.
- **`runtime-observation.js`'s closed-world validation precedent is the
  right model for reading the REMOTE side's export file, not the
  open-world precedent every other §10.10 contract uses.** Every other
  extension-contract validator in this package (`recipient-profile.js`,
  `scenario.js`, `obligation-mapping.js`, `impact-assessment.js`,
  `graph-snapshot.js`) validates a record THIS codebase itself
  constructed from its own already-vetted graph content — open-world,
  checks only the fields it cares about. A remote repo's exported
  graph JSON is, by the identical reasoning `runtime-observation.js`'s
  own header comment gives for operator-supplied telemetry, "built from
  an OPERATOR-SUPPLIED [artifact] this codebase never generated and
  cannot vouch for." It should be treated with the same discipline —
  confirm it parses as a well-formed `DataFlowGraph v1` document via
  the EXISTING `validateGraph()` (already open-world over the graph's
  own real schema, which is what's actually needed here — the remote
  file is a real graph, not an arbitrary payload, so `validateGraph()`
  is the right existing tool, not a new closed-world sweep) and treat
  everything beyond "does the referenced node id exist in this
  document's own `nodes[]`" as opaque, never copied into the local
  artifact.

## The real correction: FR-304's "declared or imported" is two mechanisms, not one

The parent row reads FR-304's "may be declared or imported" as a single
undifferentiated phrase and recommends scoping to "the PRD's own
literal text — cross-repository or federated edges may be declared or
imported." Read against `DFG-025`'s own two named dependencies
(`DFG-002` stable IDs, `DFG-007` external destination resolver), this
collapses two genuinely different mechanisms with two genuinely
different dependency profiles:

1. **Declared** — an operator explicitly names both endpoints (a local
   node id, a remote node id in a specific remote graph) and asserts
   the relationship exists. This needs only stable, `(graphId,
   graphDigest, nodeId)`-disambiguated references — `DFG-002` alone.
   Nothing about resolving a destination is involved; the operator
   already knows which two things they mean to connect.
2. **Imported** (read as: automatically or semi-automatically
   CORRELATED, not hand-named) — e.g., matching repo A's own resolved
   `external-api` destination (a hostname/route) against repo B's own
   HTTP route source, the way M2 Sub-project F2/F3's still-unbuilt
   schema-derived-edge bridging is scoped to do for OpenAPI/gRPC/
   GraphQL contracts, extended across a repo boundary. This genuinely
   needs `DFG-007`'s fuller destination resolution (hostname/port/route/
   SDK-provider extraction — today only literal/dynamic resolution is
   built, per Sub-project A's own status in this file's sibling
   `CLAUDE.md`) AND the still-unbuilt M2 Sub-project F2/F3 bridging work
   this package's own `CLAUDE.md` already discloses as "genuinely new,
   unbuilt work" with no exit-gate AC depending on it.

`DFG-025`'s own listed dependencies make complete sense once read this
way — they cover BOTH sub-flavors, not just the narrow one the parent
row recommends. **This document's own scope ruling, below, covers only
flavor 1 ("declared").** Flavor 2 ("imported"/auto-correlated) is
explicitly out of scope, both because it needs prerequisite work that
does not exist yet (M2 F2/F3, and the remaining Sub-project A
increments) and because it is a materially different, larger design
problem (destination-matching heuristics, false-positive risk across
repo boundaries) that deserves its own dedicated scoping pass once its
prerequisites ship. This sharpens, rather than overturns, the parent
row's own "Medium if scoped narrowly" sizing — the Medium estimate is
correct specifically because it only ever meant the "declared" half,
whether or not the parent row said so explicitly.

## Final scope ruling

**Ship the "declared" half of FR-304 only: a new, graph-attached
extension record, `CrossRepoLink`, naming one local node id and one
remote node id (in a separately-loaded, already-scanned remote graph
export), asserted by an operator via a new top-level CLI command.**
Each repo's own graph stays its own separate, unmodified,
independently-`validateGraph()`-clean artifact — no array merge, no
change to `nodeId`/`edgeId`/`flowId`/`dataElementId`, no change to
`dataflow-graph.schema.json`'s `edges[]`/`nodes[]` definitions. Sized
**Medium**, matching the parent row's own conclusion, now on a
concretely narrower and more defensible basis (see the correction
above).

## Design

### The `CrossRepoLink` extension contract (new file: `scanner/src/lineage/cross-repo-link.js`)

Mirrors `recipient-profile.js`'s file shape (pure module, `{valid,
errors}` validator, zero graph access at construction time) with the
one real, disclosed departure noted above: no per-field `fieldEvidence`
map, since every field here is uniformly operator-declared.

```
{
  id,                  // crossRepoLinkId(...) — see ids.js addition below
  version,
  provenance,          // schema.js's EDGE_PROVENANCE_VALUES — always
                        // 'manual' for this deliverable's own CLI (the
                        // ONLY real producer of that value anywhere in
                        // the codebase, confirmed above); 'schema' is
                        // reserved on the SAME field for a future
                        // "imported"/auto-correlated producer (flavor 2,
                        // out of scope here) without a shape change
  relationship,         // fixed 'data_flow' — mirrors edge.relationship's
                         // own single legal value; no new taxonomy
  local: {
    graphId, graphDigest, nodeId,
  },
  remote: {
    repository,          // operator-supplied label — no code-derived
                          // signal exists to name "which repo" a bare
                          // exported JSON file came from
    sourceFile,           // the path --remote-graph pointed at, kept
                           // for re-validation, never assumed stable
    graphId, graphDigest, nodeId,
  },
  rationale,             // operator free text — escaped on render via
                          // the same _mdInline/_mdCell/_mdCode local-
                          // helper convention every other Markdown
                          // exporter in this package already
                          // establishes for operator-supplied prose
  declaredBy, declaredAt,
}
```

`validateCrossRepoLink(record) -> {valid, errors}` — structural only:
`id` prefix, required strings, `provenance` a real
`EDGE_PROVENANCE_VALUES` member, `local`/`remote` each a plain object
with three non-empty strings. Never confirms the referenced node ids
actually exist anywhere — that needs real graph content, which this
pure module deliberately has no access to (mirrors `scenario.js`'s own
"structural-only, zero graph access" boundary exactly).

### `ids.js` addition (purely additive — zero change to any existing function)

```js
export function crossRepoLinkId(
  { localGraphId, localGraphDigest, localNodeId, remoteGraphId, remoteGraphDigest, remoteNodeId, relationship },
  discriminatorParts = [],
) {
  return `crosslink:${_hash(_canon([
    localGraphId, localGraphDigest, localNodeId,
    remoteGraphId, remoteGraphDigest, remoteNodeId,
    relationship, ...discriminatorParts,
  ]))}`;
}
```

Mirrors `recipientProfileId`'s own `(graphId, graphDigest, ...)`
discriminator shape, doubled for both endpoints — this is the concrete
mechanism that makes the "id collision is impossible by construction"
finding above real rather than aspirational: two links between
structurally identical node shapes in two different repo pairs cannot
collide, because both graphs' own `graphId`+`graphDigest` are baked
into the id material on both sides.

### Reading the remote side (new file: `scanner/src/lineage/federation-loader.js`)

`loadRemoteGraphExport(filePath) -> {ok, graph, digest, digestMatches, reason, message}`:
reads and JSON-parses the file at `filePath` (an `exportGraphJSON`
output — `dataflow export --format json`'s own artifact, chosen over
`loadSignedGraph` for the cross-machine reason found above), recomputes
`computeGraphDigest(parsed.graph)` and compares it to the file's own
embedded `digest` field (`digestMatches: boolean` — a self-consistency
check, explicitly documented as NOT authentication, per the trust-
boundary finding above), then runs the existing `validateGraph(parsed.graph)`
to confirm it is a well-formed document before anything reads
`parsed.graph.nodes` for the referenced remote node id. Four failure
reasons mirroring `graph-loader.js`'s own four-reason discipline:
`missing`, `malformed` (not valid JSON, or not an `exportGraphJSON`-
shaped envelope), `invalid-graph` (`validateGraph()` failed), and
`digest-mismatch` (parses and validates, but the embedded digest and
the recomputed one disagree — surfaced as a warning the CLI must show,
not silently ignored, since it is the one integrity signal this
mechanism has for a file that traveled outside this install's own
signing chain).

### Graph-attachment (extends `graph-builder.js`/`coverage.js`/`index.js`, all additively)

Mirrors `RecipientProfile`'s own wiring exactly: `buildDataFlowGraph`
gains `opts.crossRepoLinks(graph) -> CrossRepoLink[]`, applied once
after `graph.nodes` is populated (so the hook can validate a declared
`local.nodeId` against the CURRENT graph's own real node set — a stale
declaration, from before a node was renamed/removed in a later rescan,
is DROPPED and reported, never silently kept stale, matching
`applyScenario`'s own "skippedOperations, never thrown" honesty
precedent). Populates `graph.crossRepoLinks[]` — never in
`dataflow-graph.schema.json`, never routed through `validateGraph()`,
the second §10.10 extension array ever attached directly to the graph
object (after `graph.recipientProfiles[]`). `coverage.js` composes a
default hook over a pre-loaded `opts.crossRepoLinkRecords` array
(mirroring `opts.recipientConfig`'s own precedent exactly);
`index.js` loads `.agentic-security/cross-repo-links.json` once per
`buildLineageGraph` call, gated on `fs.existsSync` (mirroring the
`privacySinkPolicy` gate, not the `recipientConfig` unconditional-call
one, since a missing file here means "no links declared," a real,
distinguishable-from-empty state worth keeping honest the same way
`privacy-policy.json`'s absence is).

### The CLI: a new top-level dispatcher, `federate` (NOT a `dataflow` subcommand)

Per the finding above (mirrors `governance`'s/`remediation`'s own
reasoning: this writes operator-declared config, not a query over an
already-built graph) — a 14th top-level dispatcher, `commands/federate.md`,
new frontmatter matching the other 13 exactly.

- **`agentic-security federate declare [path] --local-node <node-id>
  --remote-graph <file> --remote-node <node-id> [--repository <label>]
  [--relationship data_flow] [--rationale <text>] [--yes]
  [--base-digest <hex>]`** — `cmdFederateDeclare` in `bin/agentic-security.js`.
  Reuses `governance-edit.js`'s exact 5-part write contract: (1) version
  guard on `.agentic-security/cross-repo-links.json` (`--base-digest`
  vs. its current SHA-256, checked BEFORE any read of the remote file
  or any validation); (2) loads and validates the remote export via
  `federation-loader.js` (a `digest-mismatch` is printed as a warning,
  never silently swallowed, and does not by itself block `--yes` — the
  operator is explicitly asserting this file, matching this codebase's
  own "operator-declared" trust model throughout §10.10); (3) confirms
  `--local-node` exists in the CURRENT locally-scanned graph
  (`loadSignedGraph(targetAbs)`, the correct use of that mechanism here
  — it is the LOCAL side, same install, same machine) and
  `--remote-node` exists in the loaded remote export's own `nodes[]`;
  (4) on `--yes`: backs up the current `cross-repo-links.json` (if any)
  to a dedicated `cross-repo-links-backups/` subdirectory (mirroring
  `recipient-profiles-backups/`'s own precedent exactly), writes the
  new content atomically, appends a real, hash-chained audit event via
  `auditCall` (`tool: 'federate_declare'`); without `--yes`, prints a
  dry-run preview and writes nothing. Exit codes mirror
  `cmdGovernancePropose`'s own scheme (0 success incl. preview, 1
  validation failure, 2 usage/version-guard/node-not-found, 4 I/O
  error).
- **`agentic-security federate list [path]`** — read-only
  (`cmdFederateList`), mirrors `dataflow observations list`'s own
  precedent: reads `cross-repo-links.json`, and for each entry reports
  whether `local.nodeId` still resolves against the current
  `loadSignedGraph` output and whether `remote.sourceFile` still
  exists/parses/digest-matches — never fabricates "still valid" when it
  cannot check (e.g. the remote file has moved).
- Both registered in `posture/artifact-registry.js`
  (`cross-repo-links.json`: `operator-config`; `cross-repo-links-backups/`:
  `generated`/`backup`) so `reset` sweeps the backups and preserves the
  declaration, mirroring the governance-editing deliverable's own I5/M6
  fix exactly — a real, easy-to-miss step the M5 series has now found
  and fixed twice (recipient-profiles-backups, and previously the
  runtime-observations trace-name registration gap) and should not be
  missed a third time here.

### `commands/federate.md`

New top-level dispatcher markdown, same frontmatter/Options-table/
Examples/Implementation-block shape as `commands/governance.md`. States
plainly: CLI-only, "declared" flavor of FR-304 only (see the
correction above — the "imported"/auto-correlated flavor is
out of scope and named as a future increment blocked on M2 F2/F3 and
the remaining Sub-project A destination-resolver increments), every
write backs up the prior file and appends a real audit event, and the
remote-side trust model (a self-consistency digest check, never
cryptographic authentication of the remote install).

## Files to create/modify

**New:**
- `scanner/src/lineage/cross-repo-link.js` — the `CrossRepoLink`
  contract + `validateCrossRepoLink`.
- `scanner/src/lineage/federation-loader.js` — `loadRemoteGraphExport`.
- `commands/federate.md`.

**Modified, all additively:**
- `scanner/src/lineage/ids.js` — new `crossRepoLinkId(...)` function
  only; zero change to `nodeId`/`edgeId`/`flowId`/`dataElementId`.
- `scanner/src/lineage/graph-builder.js` — new `opts.crossRepoLinks`
  hook, byte-identical when omitted (same proof discipline
  `M2A1/hook-1` established for `resolveDestination`).
- `scanner/src/lineage/coverage.js` — default-hook composition over
  `opts.crossRepoLinkRecords`, mirroring `opts.recipientConfig`.
- `scanner/src/lineage/index.js` — one more single-load-per-call
  (`cross-repo-links.json`), mirroring the `privacySinkPolicy`
  existence-gated pattern.
- `scanner/bin/agentic-security.js` — `cmdFederateDeclare`,
  `cmdFederateList`, `case 'federate':` dispatch.
- `scanner/src/posture/artifact-registry.js` — two new entries
  (`cross-repo-links.json`, `cross-repo-links-backups/`).
- `CLAUDE.md` (root) — one new row in the `commands/` table entry (14
  dispatchers, not 13) — a real, easy-to-forget doc-drift point given
  this repo's own `session-stop-drift-check.js` Stop hook watches
  `scanner/src/{sast,posture,dataflow}/` specifically, NOT `commands/`
  or the dispatcher count in root `CLAUDE.md`, so nothing catches this
  automatically.
- `scanner/src/lineage/CLAUDE.md` — a new module-table section for this
  sub-project, matching every sibling deliverable's own documentation
  discipline in this file.

**Explicitly NOT modified:** `dataflow-graph.schema.json`, `validate.js`'s
`validateGraph()` (the new record is never routed through it, mirroring
`RecipientProfile`), any file under `frontend/src/` (no UI — see Out of
scope).

## Global constraints for a future implementation plan

- No frontend/UI work — CLI/JSON export only, matching every M4/M5
  decision-intelligence deliverable's own established backend-first
  precedent.
- No live/network fetch of a remote graph, ever — `--remote-graph` is
  always a local file path the operator has already placed there (a
  copied CI artifact, a shared drive, a manual scp) — this codebase's
  own "no runtime cloud calls" convention (root `CLAUDE.md`) applies
  here exactly as it does everywhere else.
- No change to `nodeId`/`edgeId`/`flowId`/`dataElementId` or their
  discriminator shapes.
- No array-merge of two graphs' `nodes[]`/`edges[]` under any
  circumstance — each repo's graph stays independently
  `validateGraph()`-clean, unmodified, forever.
- `provenance: 'manual'` only — this deliverable never writes `'schema'`
  to `CrossRepoLink.provenance` (that value stays reserved for a future
  "imported"/auto-correlated producer, per the correction above).
- The remote-side digest check is a self-consistency check, never
  authentication — the CLI and `commands/federate.md` must both say so
  plainly, never imply a stronger trust guarantee than exists.

## Out of scope (disclosed, not built)

- **FR-304's "imported"/auto-correlated flavor** — destination- or
  schema-based automatic cross-repo edge correlation. Needs M2
  Sub-project F2/F3 (schema-derived edges, currently unbuilt) and the
  remaining Sub-project A destination-resolver increments (currently
  only literal/dynamic resolution exists) as real prerequisites — see
  "The real correction," above. A future increment, not this one.
- **Full graph merge** of any kind — never recommended, per the parent
  row and this document's own confirmation that it is unnecessary for
  what FR-304 actually asks for.
- **Any cryptographic cross-machine authentication of a remote graph
  export.** The existing `agentic-security attest`/`verify-attestation`
  Ed25519 mechanism (root `CLAUDE.md`'s "Signed, portable evidence"
  section) is the right existing tool for a future increment that wants
  real third-party verifiability of a remote export — wiring it in here
  was judged out of proportion to a P2, narrowly-scoped first cut and is
  named, not silently skipped.
- **Automatic cross-repo `RecipientProfile` consolidation** — the
  parent row's own disclosed gap ("zero automatic cross-repo
  consolidation... a real, disclosed gap if this and FR-506's own
  'concentration view' are ever expected to compose") is CONFIRMED
  still real and still open by this investigation: a `CrossRepoLink`
  connects two NODES, and says nothing about whether two
  `RecipientProfile` records (one per repo) describe the same
  real-world vendor. Composing the two remains a real, separate,
  disclosed future increment, not attempted here.
- **A live-refresh / auto-resync mechanism.** `federate list`'s own
  validity check is read-only and on-demand; nothing watches the
  remote file for changes or re-validates automatically on every scan
  beyond the existing build-time re-validation against the LOCAL side
  (see Design, "Graph-attachment," above) — a stale `remote.sourceFile`
  is only caught the next time `federate list` or a rebuild runs.
- **Any language-specific work.** This construct is entirely
  graph-level (operates on already-minted node ids from two already-
  built graphs) — genuinely language-agnostic, unlike most other M5
  deliverables in this series.

## Summary of corrections against the parent M5 doc's own row 8

1. **The referential-soundness finding is new and stronger than the
   parent row's own framing.** The parent row frames the risk as "naive
   array-merge would silently id-collide" (a risk to avoid via
   discipline); this investigation found `validate.js`'s
   `_validateEdge` makes a cross-repo entry in `graph.edges[]`
   **structurally impossible to pass `validateGraph()` at all**,
   collision or not — settling, rather than merely motivating, the
   design decision that the new construct must be a separate extension
   record, never a core-schema edge.
2. **The id-collision risk, as stated, does not actually threaten a
   correctly-scoped design.** Under the recommended design (never
   merging node arrays; always pairing a foreign node id with its own
   `graphId`+`graphDigest`), the collision scenario the parent row
   names cannot occur — not because it's avoided by convention, but
   because nothing ever looks up a bare node id against a merged or
   ambiguous set. This is a sharpening of the parent row's own
   reasoning, not a reversal of its conclusion.
3. **`graph-snapshot.js` is not the right existing primitive for
   "reference another repo's graph," despite being named as a
   plausible candidate to check.** It is strictly local-repo,
   commit-keyed history for the Time Machine (FR-503) — a different
   problem. The actual precedent this deliverable needs is
   `graph-loader.js`'s `loadSignedGraph`, and even that needs a real,
   disclosed caveat (see next item) rather than being reused as-is for
   the remote side.
4. **A genuinely new finding not present anywhere in the parent row or
   the task brief: `loadSignedGraph`'s signature is authenticated by a
   per-install HMAC key, which is the WRONG trust model for a file that
   crossed a repo/machine boundary in the common case.** This
   deliverable's design routes the remote side through
   `exportGraphJSON`'s portable, embedded-digest artifact instead
   (self-consistency, not authentication — disclosed as such, not
   oversold), and uses `loadSignedGraph` correctly only for the LOCAL
   side, where the per-install-key model is exactly right (same
   install, same machine, matching every other CLI verb in this
   package that reads the local scan artifact).
5. **FR-304's "declared or imported" is two mechanisms with two
   different dependency profiles, not one phrase to scope narrowly as
   a unit.** `DFG-025`'s own two named dependencies (`DFG-002` +
   `DFG-007`) only make full sense once this split is made explicit —
   the parent row's "Medium if scoped narrowly" conclusion is CONFIRMED
   correct, but only because it implicitly meant the "declared" half;
   this document makes that boundary explicit and names the "imported"
   half as its own, separate, currently-blocked future increment.
6. **The CLI shape should be a new top-level dispatcher (`federate`),
   not a `dataflow <noun> <verb>` subcommand**, contrary to the task
   brief's own suggested example (`dataflow federate declare`) — this
   deliverable writes operator-declared config (an assertion, not a
   query/derivation over an already-built graph), the identical
   reasoning `commands/governance.md` and `commands/remediation.md`
   both already establish as this codebase's own real, twice-repeated
   precedent for exactly this shape of capability. The task brief
   explicitly allowed "or similar," and this is the "similar" this
   investigation's own reading of the real precedent recommends
   instead.
7. **`RecipientProfile`'s own "zero automatic cross-repo consolidation"
   gap, named by the parent row, is independently CONFIRMED still real
   and not addressed by this deliverable** — not a correction, a
   verification that the parent row's own disclosed limitation still
   holds after this design is applied.
8. **A same-named-in-spirit but structurally unrelated existing
   mechanism was found and ruled out — not mentioned anywhere in the
   parent row or the task brief.** `posture/provenance/repo-lineage.js`
   ("Cross-repository lineage declaration") already exists, for an
   entirely different PRD (Finding Provenance) and an entirely
   different question (temporal git-history continuity across a repo
   split, one link per repo). Confirmed via its real consumers
   (`origin-resolver.js`/`coordinator.js`) to have zero reference from
   `scanner/src/lineage/` and zero structural fit for this deliverable's
   own many-links, spatial/architectural question — disclosed here so a
   future reader who finds it via grep doesn't mistake it for a partial
   implementation of this deliverable, and so this deliverable's own new
   artifact is deliberately named `cross-repo-links.json`, not
   `repo-lineage.json`, to keep the two permanently distinguishable.
