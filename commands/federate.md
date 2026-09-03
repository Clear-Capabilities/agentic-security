---
description: Declare (or list) a CrossRepoLink between a node in this repo's scanned graph and one in a remote repo's graph export.
argument-hint: "declare|list [path] [flags]"
---

## Federate

The "declared" half of FR-304 (cross-repository/federated graph edges) —
M5 deliverable #8, the FINAL item of the Data Flow Explorer PRD. An
operator explicitly names a local node and a remote node and asserts
that data flows between them; nothing is inferred or auto-correlated.

**CLI-only, this half only.** FR-304's "imported"/auto-correlated flavor
— matching a repo's own resolved destination against another repo's own
source, the way a future schema-derived-edge bridge would — needs
prerequisite work that does not exist yet (M2 Sub-project F2/F3's
schema-derived edges, and the remaining Sub-project A destination-
resolver increments) and is a materially larger, separately-scoped
design problem. Not attempted here.

**No array-merge, ever.** Each repo's own `DataFlowGraph v1` document
stays its own separate, unmodified, independently-`validateGraph()`-clean
artifact. A `CrossRepoLink` is a new, graph-attached extension record
(`graph.crossRepoLinks[]`) naming one local node id and one remote node
id — never a core-schema edge. `validate.js`'s `_validateEdge` makes a
cross-repo entry in `graph.edges[]` structurally impossible to pass
`validateGraph()` at all, which is why this deliverable never attempts
one.

**The remote-side trust model is a self-consistency check, never
authentication.** `--remote-graph` points at a local file — always a
copied CI artifact, a shared drive, a manual `scp`, never a live network
fetch (this codebase's own "no runtime cloud calls" convention applies
here exactly as it does everywhere else). The remote export's own
embedded digest is recomputed and compared against its own content; a
mismatch is printed as a WARNING and does not by itself block `--yes`
(the operator declaring the link is explicitly asserting that file's
authenticity, not this tool). `loadSignedGraph`'s per-install HMAC key
(the mechanism the LOCAL side uses) is deliberately never used for the
remote side — two repos scanned on two different machines sign under two
different keys by default, so authenticating the remote file that way
would, in the common case, incorrectly report tampering that never
happened.

**`provenance: 'manual'` only.** This deliverable is the first real
producer of that value anywhere in this codebase — `'schema'` stays
reserved on the same field for a future "imported"/auto-correlated
producer.

### `declare`

Declares a link between a node in the current, already-scanned local
graph and a node in a remote repo's graph export.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--local-node <node-id>` | Yes | Must exist in the CURRENT locally-scanned graph (`.agentic-security/lineage-graph.json`, verified via the same signed-graph loader `explore`/`dataflow export` use). |
| `--remote-graph <file>` | Yes | A local file — the output of `dataflow export --format json` run in the REMOTE repository, copied here by any means (CI artifact, shared drive, `scp`). Never fetched over the network. |
| `--remote-node <node-id>` | Yes | Must exist in the remote export's own `nodes[]`. |
| `--repository <label>` | No | An operator-supplied label naming the remote repository — no code-derived signal exists to determine this from a bare exported JSON file. Defaults to `"(unspecified)"` when omitted. |
| `--relationship data_flow` | No | The only legal value — mirrors `edge.relationship`'s own single legal value. Any other value is a usage error. |
| `--rationale <text>` | No | Operator free text explaining the link. |
| `--output <file>` | No | Where the preview/result report is written. Omitting prints to stdout. |
| `--yes` | No | Perform the real write (backup + atomic write + audit event). Omitted, this is a dry-run preview only. |
| `--base-digest <hex>` | No | A SHA-256 digest of the `cross-repo-links.json` content the declaration was computed against. A mismatch refuses the write as a concurrent-edit conflict (exit 2) before any validation or write happens. When the project has no `cross-repo-links.json` yet, the digest to compute is `sha256('{"links":[]}')` (the compact, no-whitespace literal). |

Exit codes: `0` success (both the dry-run-preview path and the real
write path, including a digest-mismatch warning on the remote export);
`1` the constructed record fails structural validation (should not
normally happen — every field is derived from already-validated inputs);
`2` a usage/argument error (a missing required flag, an unreadable
`--remote-graph`, `--local-node`/`--remote-node` not found on their
respective sides), a version-guard rejection, or the target not looking
like a real project directory; `4` an unexpected I/O error during the
write itself — nothing was written, and no audit event is recorded for a
failed attempt.

### `list`

Read-only. Reads `cross-repo-links.json` and, for each entry, reports
whether `local.nodeId` still resolves against the current locally-scanned
graph and whether `remote.sourceFile` still exists/parses/digest-matches
and still names the declared remote node — never fabricates "still
valid" when it cannot check (e.g. the remote file has moved, or no local
graph exists yet).

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--output <file>` | No | Where the listing is written. Omitting prints to stdout. |

Exit codes: `0` success (including an empty list); `2` a malformed
`cross-repo-links.json`.

### Examples

```
/federate declare --local-node node:sink:abc123 \
  --remote-graph ../other-repo/remote-export.json \
  --remote-node node:source:def456 \
  --repository payments-service --rationale "Order events flow in from payments-service" \
  --yes
/federate list
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs federate "$@"
exit $?
```
