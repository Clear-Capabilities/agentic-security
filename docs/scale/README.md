# Scale

<!-- seo: title="Scale: Where else does this weakness exist?" description="Stage 5 of the Agentic Security assurance lifecycle: Where else does this weakness exist?" -->

**Stage 5 of 10.** Where else does this weakness exist?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Two scopes, at two different maturities.

**Within a repository (GA).** After a confirmed finding, the root-cause sweep looks for sibling instances the detectors missed and reports honest `N found / M candidate / K mitigated` counts.

**Across repositories (Preview).** `fleet` plans one idempotent job per repository in a local SQLite store (lease, heartbeat, retry count, timeout, result hash), runs each scan in a supervised child process under a hard timeout with bounded workers, and reuses a content-addressed cache. A repository that failed to scan is counted as failed, never dropped from the denominator. `fleet query --depends-on <repo-id>` lists which repositories depend on a given one, `fleet edges` finds references in code, and `fleet scan --lineage` adds data classes and destinations from each repository's own Code Boundaries graph.

```bash
agentic-security fleet init
agentic-security fleet scan fleet.yaml
agentic-security fleet query --depends-on shared-auth-lib fleet.yaml
```

Limits, stated up front: dependency matching is by declared package name and a version pin is matched as text; there is no PostgreSQL or remote-worker store and no distributed queue; the lineage contribution is summarized, not joined node for node, so one data element cannot be followed across a repository boundary; `fleet explore` is a static listing; scaling was measured once, on one machine, on a toy workload.

Federation of two repositories' graphs is a separate, declared link (`federate declare`), GA, covered under [Trace](../trace/README.md).

**Evidence this stage creates:** Sibling-instance counts, a fleet rollup, and a dependents list.

## Capabilities at this stage

<!-- generated:capabilities:scale:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Repository-wide sibling sweep](../reference/root-cause-sweep.md) | Scale | **GA** | Other instances of the same weakness in the repository, with found, candidate and mitigated counts reported separately. |
| [Fleet scanning and dependency blast radius](../guides/fleet.md) | Scale | **Preview** | Idempotent, leased scan jobs for a declared set of repositories in a local SQLite store, an honest per-repository rollup, and which repositories depend on, or reference in code, a given one. Dependency matching is by declared package name; no remote workers or distributed queue. |
| [Cross-repository graph federation](../reference/federation.md) | Scale, Trace | **GA** | A declared link between a node in this repository's graph and a node in another repository's graph export. Each graph stays unmodified. |
<!-- generated:capabilities:scale:end -->

## Read more

- [Fleet](../guides/fleet.md)
- [Fleet implementation status](../implementation-status/fleet.md)

---

Previous: [Learn](../learn/README.md) · Next: [Observe](../observe/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
