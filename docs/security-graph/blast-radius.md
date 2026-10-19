# Blast radius

<!-- seo: title="Blast radius: what a compromised component can reach" description="Read-only impact assessment over the scanned security graph: affected nodes, edges, data classes and recipients, plus a fleet-level dependent query." -->

**Maturity:** GA

Blast radius answers: *if this node, edge, flow or data element is compromised, what else is exposed?* It reads the already-scanned [security graph](code-boundaries.md). It never re-scans and never changes anything.

## Within one repository

```bash
agentic-security dataflow impact assess . --target node:store:eb1543b84778 --output impact.md --format markdown
```

Real captured output, abridged, from the demo app (`--target` is any `node:*`, `edge:*`, `flow:*` or `data:*` id from the graph):

```text
Target: `node:store:eb1543b84778` (node)
Scope: possible (traceKind: topology_reachable)

## Affected nodes (3)
- node:source:7cffae1f4efb
- node:source:b7d4254bb384
- node:store:eb1543b84778

## Affected data classes
- CREDENTIALS
- PII

## Coverage limitations
- js: coverage tier 'partial' (58% measured recall)
- python: coverage tier 'partial' (66% measured recall)
```

Note what it keeps: `Scope: possible` (a topology fact, not an exploit), and the coverage limitations that bound the answer.

## Across repositories

`fleet query --depends-on <repo-id>` (Preview) lists which of a declared set of repositories depend, directly or transitively, on a given one by declared package name. It answers the dependency-reachability half only; it has no Internet-facing or regulated-data overlay.

## Contract

`dataflow impact assess [path] --target <id> --output <file> [--format json|markdown]` writes one record. A compatibility test (`scanner/test/contracts/blast-radius.contract.test.js`) holds the output to the tables below in both directions, so a field cannot be added or removed without changing this page.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | The record was written |
| `1` | The signed graph could not be loaded, or it loaded but is structurally malformed |
| `2` | A command-line problem: `--target` or `--output` missing, `--format` not `json` or `markdown`, a `--target` with no recognized prefix, or an unwritable `--output` |

**Record fields (`--format json`)**

| Field | Meaning |
|---|---|
| `id` | `impact:` plus a digest of graph, target and time |
| `version` | The record contract version |
| `graphId` | The graph the answer was read from |
| `graphDigest` | A digest of that graph, so the answer names the exact graph |
| `targetId` | The id that was assessed |
| `targetKind` | `node`, `edge`, `flow` or `dataElement` |
| `scope` | `possible` (topology) or `observed`. Only `possible` is produced today |
| `traceKind` | `topology_reachable` for a node, `flow_restricted` for an edge, flow or data element |
| `affectedNodeIds` | Sorted node ids |
| `affectedEdgeIds` | Sorted edge ids |
| `affectedDataClasses` | Sorted data classes carried by the affected flows |
| `affectedRecipientProfileIds` | Sorted recipient profiles that include an affected node |
| `coverageLimitations` | Plain-text limits that bound the answer, such as a language at a partial tier |
| `generatedAt` | When the record was computed |

**What each target kind means**

- A `node:` target is treated as compromised: the node, everything reachable downstream by directed edges, everything that reaches it upstream, and the data classes of every flow that uses an edge on those paths.
- An `edge:`, `flow:` or `data:` target is restricted to the flows that carry it: their endpoints, their edges, and the data they carry. A sibling flow that merely shares a node is not swept in.
- An id that is well formed but not in the graph returns empty arrays, never a node that is not there.

## Tracking the work

`remediation open` records a blast-radius item with an owner, a due date and required evidence. `remediation verify` closes it only against real rescan evidence, and a later regression reopens it.

## What blast radius does not establish

<!-- limits-verified: 2026-10-19 -->

- A `possible` scope is reachability in the graph, not a demonstrated attack path.
- It is bounded by scan coverage; a partial language tier means a partial answer.
- Dollar figures elsewhere in the product are scenario defaults, not outputs of this assessment.
- **It agrees with its specification, not with every real program.** On 300 seeded graphs (7856 targets) the assessment matched an independent reference on every node, edge, data class and recipient, and reported no node that is not in the graph. The graphs are generated, so this is agreement with the definitions above and not recall against real code. How well a real graph reflects a real program is bounded by the coverage tiers it carries.
- **A node target is deliberately pessimistic.** Everything reachable counts, whether or not an attacker could really traverse it.
- **It reads one graph.** It does not look across repositories; that is the separate, Preview, fleet query.
