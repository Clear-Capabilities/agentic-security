# Cross-repository graph federation: contract

<!-- seo: title="Federation contract: declaring a link between two repositories' graphs" description="The commands, exit codes and record fields for declaring and listing a cross-repository link, and the guarantees that keep each graph unmodified." -->

**Maturity:** GA

Federation lets you state that data flows between a node in this repository's scanned graph and a node in another repository's graph export. You name both nodes. Nothing is inferred, and neither graph is changed. The graphs it links are [Code Boundaries](../security-graph/code-boundaries.md) graphs. Scale and Trace context: [Scale](../scale/README.md).

## Commands

```bash
agentic-security federate declare [path] --local-node <id> --remote-graph <file> --remote-node <id> [--repository <name>] [--rationale <text>] [--base-digest <sha256>] [--yes] [--output <file>]
agentic-security federate list [path] [--output <file>]
```

`declare` is a dry run unless you pass `--yes`. `--remote-graph` is always a local file, such as a copied CI artifact from `dataflow export --format json`; federation never fetches over the network.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | The report was written to standard output or `--output` (a dry run included) |
| `1` | `declare`: the local scanned graph could not be loaded, or the constructed record failed validation |
| `2` | A command-line problem, a node that is not in its graph, a remote export that is missing or not a valid graph, a links file that is not valid, a `--base-digest` that no longer matches, or a refusal to write outside a project directory |

## Declared link record

A compatibility test (`scanner/test/contracts/federation.contract.test.js`) holds the record, the `declare` report and the `list` report to the tables below in both directions: a field cannot be added or removed without changing this page.

**Link record**

| Field | Meaning |
|---|---|
| `id` | `crosslink:` plus a digest of both graphs, both nodes and the relationship. The same fact always gets the same id |
| `version` | The record contract version |
| `provenance` | `manual`: a person declared it |
| `relationship` | `data_flow`, the only value defined |
| `local` | The local endpoint (below) |
| `remote` | The remote endpoint (below) |
| `scope` | Per side, the analysis scope and limitations copied from the node, plus any `--local-target` or `--remote-target` label |
| `evidence` | Always `{ declared: true, observed: false }`. A declared link is never an observed data flow |
| `rationale` | Your note, or `null` |
| `declaredBy` | The user who declared it |
| `declaredAt` | When |

**Endpoint fields.** Both endpoints carry `graphId`, `graphDigest` and `nodeId`. The remote endpoint also carries `repository` (your label, or `(unspecified)`) and `sourceFile` (the absolute path of the export you pointed at).

**`declare` report**

| Field | Meaning |
|---|---|
| `currentDigest` | The digest of the links file before this call, for `--base-digest` |
| `record` | The link that was, or would be, written |
| `digestMatches` | Whether the remote export's embedded digest matches its own content |
| `written` | `true` only with `--yes` |
| `backupPath` | The backup of the previous links file, or `null` |

**`list` report**

| Field | Meaning |
|---|---|
| `links` | One entry per declared link, each with `id`, `local`, `remote`, `scope`, `evidence`, `rationale`, `declaredBy` and `declaredAt` |
| `localGraphAvailable` | Whether the local scanned graph could be loaded to check against |

Each `list` entry's `local` has `nodeId` and `stillValid`; its `remote` has `sourceFile`, `nodeId`, `checked`, and then `ok` with `digestMatches` and `nodeStillPresent`, or `ok: false` with `reason` and `message`. `stillValid` is `null`, not `true`, when the local graph cannot be loaded: it never claims a check it did not make.

## Guarantees

- **Neither graph is modified.** The local graph file and the remote export are byte-identical before and after `declare --yes` and `list`. A link lives in its own file, `cross-repo-links.json`.
- **A dry run writes nothing.** Only `--yes` writes, and a write first backs up the previous links file and records an audit entry.
- **The same fact is one link.** Declaring it again replaces the existing entry in its original position instead of adding a second one.
- **A concurrent edit is refused.** With `--base-digest`, a links file that changed since you read it is not overwritten.
- **A declaration is never evidence of flow.** The validator rejects any record whose `evidence` says otherwise.

## What federation does not do

<!-- limits-verified: 2026-10-19 -->

- **It does not find links.** Nothing is matched or inferred between repositories. A flow nobody declared is not in the result.
- **It does not authenticate the remote file.** The embedded digest is a self-consistency check only. A mismatch prints a warning and does not block `--yes`, because you are asserting that file. Two repositories scanned on two machines sign under different keys, so the remote side is deliberately not checked with this machine's key.
- **It does not fetch.** `--remote-graph` is a file you copied. A link to a graph that has since moved reports `remote.ok: false` in `list`; it is not repaired.
- **It does not say a flow happens.** `observed` is always `false`. For observed behavior see [runtime corroboration](../guides/runtime-twin.md).
- **It inherits the graphs' limits.** Each graph carries its own per-language coverage tier; a link between two partial graphs is a declaration about partial pictures.
