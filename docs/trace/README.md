# Trace

<!-- seo: title="Trace: How does risk connect through code, data, architecture, provenance, and artifacts?" description="Stage 7 of the Agentic Security assurance lifecycle: How does risk connect through code, data, architecture, provenance, and artifacts?" -->

**Stage 7 of 10.** How does risk connect through code, data, architecture, provenance, and artifacts?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Trace is where individual findings meet the connected picture, grounded in [Code Boundaries](../security-graph/code-boundaries.md) and provenance.

- **Security graph.** Field-level flows with sources, sinks, protection state and sensitive-data classes. See [Code Boundaries](../security-graph/code-boundaries.md).
- **Blast radius.** What a compromised node can reach. See [blast radius](../security-graph/blast-radius.md).
- **Provenance.** Which commit introduced a finding, and whether a built image still contains it (images from archives, a local Docker or Podman engine, or one named registry reference; the engine and registry paths were tested against stand-ins). See [provenance](../security-graph/provenance.md).
- **Federation.** A declared link between two repositories' graphs.
- **Compliance evidence.** Automated technical-control evidence mapped to bundled frameworks, with unassessed and manual controls kept out of the satisfied count.

**Evidence this stage creates:** A signed graph artifact, an impact assessment, a provenance record, and control evidence.

## Capabilities at this stage

<!-- generated:capabilities:trace:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Cross-repository graph federation](../guides/data-flow-explorer.md) | Scale, Trace | **Preview** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
| [Code Boundaries security graph](../security-graph/code-boundaries.md) | Trace | **Preview** | Field-level sources, sinks, protection state, sensitive-data classes and findings as one signed graph, browsable locally. Opt-in at scan time. |
| [Blast-radius assessment](../security-graph/blast-radius.md) | Trace | **Preview** | What a compromised graph node can reach, including affected data classes and recipients, read from the already-scanned graph. |
| [Finding provenance from Git history](../guides/finding-provenance.md) | Trace | **Preview** | Which commit introduced a finding, resolved from Git history, with the resolution quality stated. |
| [Source-to-artifact provenance](../guides/artifact-provenance.md) | Trace | **Preview** | Whether a finding is present in a built container image and whether a fix in source reached it. Images come from OCI or Docker archives, a local Docker or Podman engine, or one named registry reference; the engine and registry paths were tested against stand-ins, not a real daemon or registry. |
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
