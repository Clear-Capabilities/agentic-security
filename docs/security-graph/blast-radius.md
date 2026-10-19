# Blast radius

<!-- seo: title="Blast radius: what a compromised component can reach" description="Read-only impact assessment over the scanned security graph: affected nodes, edges, data classes and recipients, plus a fleet-level dependent query." -->

**Maturity:** Preview

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

`fleet query --depends-on <repo-id>` (Labs) lists which of a declared set of repositories depend, directly or transitively, on a given one by declared package name. It answers the dependency-reachability half only; it has no Internet-facing or regulated-data overlay.

## Tracking the work

`remediation open` records a blast-radius item with an owner, a due date and required evidence. `remediation verify` closes it only against real rescan evidence, and a later regression reopens it.

## What blast radius does not establish

- A `possible` scope is reachability in the graph, not a demonstrated attack path.
- It is bounded by scan coverage; a partial language tier means a partial answer.
- Dollar figures elsewhere in the product are scenario defaults, not outputs of this assessment.
