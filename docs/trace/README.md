# Trace

<!-- seo: title="Trace: How does risk connect through code, data, architecture, provenance, and artifacts?" description="Stage 7 of the Agentic Security assurance lifecycle: How does risk connect through code, data, architecture, provenance, and artifacts?" -->

**Stage 7 of 10.** How does risk connect through code, data, architecture, provenance, and artifacts?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Trace is where individual findings meet the connected picture, grounded in [Code Boundaries](../security-graph/code-boundaries.md) and provenance.

- **Security graph.** Field-level flows with sources, sinks, protection state and sensitive-data classes. See [Code Boundaries](../security-graph/code-boundaries.md).
- **Blast radius.** What a compromised node can reach. See [blast radius](../security-graph/blast-radius.md).
- **Provenance.** Which commit introduced a finding, and whether a built image still contains it (images from archives, a local Docker or Podman engine, or one named registry reference; the engine, registry and signing paths are exercised by a hosted job against the real tools). See [provenance](../security-graph/provenance.md).
- **Federation.** A declared link between two repositories' graphs.
- **Compliance evidence.** Automated technical-control evidence mapped to bundled frameworks, with unassessed and manual controls kept out of the satisfied count.

**Evidence this stage creates:** A signed graph artifact, an impact assessment, a provenance record, and control evidence.

## Capabilities at this stage

<!-- generated:capabilities:trace:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Cross-repository graph federation](../reference/federation.md) | Scale, Trace | **GA** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
| [Code Boundaries security graph](../security-graph/code-boundaries.md) | Trace | **Preview** | Field-level sources, sinks, protection state, sensitive-data classes and findings as one signed graph, browsable locally. Opt-in at scan time. |
| [Blast-radius assessment](../security-graph/blast-radius.md) | Trace | **GA** | What a compromised graph node can reach, including affected data classes and recipients, read from the already-scanned graph. |
| [Finding provenance from Git history](../guides/finding-provenance.md) | Trace | **Preview** | Which commit introduced a finding, resolved from Git history, with the resolution quality stated. |
| [Graph precision, completeness and scale](../security-graph/graph-precision.md) | Trace | **Preview** | Whether a graph analysis finished, and how far its answer reaches. Adds completion status, recursion handling, call-site correlation, demand queries, path conditions, incremental invalidation, boundary contracts, control-placement planning and replayable witness bundles, each with its limits stated. The typed graph view, boundary contracts, demand sink queries, control-placement planning and witness bundles are reachable from the CLI (`dataflow view|contracts|sink-query|plan-cuts`, `witness build|verify`), each opt-in and each reporting a completion status. Targets not yet met: incremental analysis is 2.5x and 2.4x on the two synthetic projects against a 3x target, 75 of 982 sink sites still take the full path in demand queries, the multi-service fixture finds 3 of 8 labeled positives, the optional z3 backend is not used by a default scan, and the precision figures come from a development sample; on an independent sample of the whole default scan the measured precision was 11.7% for JavaScript and TypeScript and 6.8% for Nix (one LLM labeler, wide intervals; bench/dag/independent). |
| [Source-to-artifact provenance](../guides/artifact-provenance.md) | Trace | **GA** | Whether a finding is present in a built container image and whether a fix in source reached it. Images come from OCI or Docker archives, a local Docker or Podman engine, or one named registry reference; the engine, registry and signing paths are exercised by a hosted job against a real container engine, a real registry and a real signing tool. |
| [Compliance control evidence](../guides/compliance.md) | Trace | **Preview** | Automated technical-control evidence mapped to bundled frameworks, with unassessed and manual controls kept out of the satisfied count. Not a certification. |
<!-- generated:capabilities:trace:end -->

## Read more

- [Code Boundaries](../security-graph/code-boundaries.md)
- [Data flow](../security-graph/data-flow.md)
- [Blast radius](../security-graph/blast-radius.md)
- [Provenance](../security-graph/provenance.md)
- [Compliance](../guides/compliance.md)

---

Previous: [Observe](../observe/README.md) · Next: [Fix](../fix/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
