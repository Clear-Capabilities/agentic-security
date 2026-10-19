# Observe

<!-- seo: title="Observe: What has actually occurred at runtime?" description="Stage 6 of the Agentic Security assurance lifecycle: What has actually occurred at runtime?" -->

**Stage 6 of 10.** What has actually occurred at runtime?

**Maturity of this stage:** see the table below. Every capability carries its own label.

**Today: offline import (Preview).** `runtime ingest` takes exported telemetry and matches it to nodes in the scanned graph. Supported adapters: `otel-json`, `envoy-access-log`, `k8s-audit-log`, `http-access-log`, `native-jsonl`. The result carries an honest `complete`, `partial` or `unavailable` assurance status, and absence of telemetry is never read as absence of risk.

```bash
agentic-security runtime ingest --adapter otel-json <path>
agentic-security runtime status
```

Metadata only: no payloads are captured. Beyond matching, the twin derives six edge states (observed, blocked, policy violation, exploit correlated only with explicit evidence, not observed, static only), stores identity only as a keyed-hash token when asked, answers queries such as vulnerable functions exercised in a trace and runtime flows absent from the static graph, and writes the five Explorer views as a static, script-free page (`explore . --runtime`). The adapters match destinations; the graph carries no route or function symbol, so function evidence attaches to scan findings, not to graph edges. An identity query is only as complete as the identity telemetry.

**Not shipped (Roadmap).** Continuous collection of production behavior, and corroboration at the function level, are not part of the product. Nothing on this page should be read as describing them as available.

**Evidence this stage creates:** Observations matched to graph nodes, with `complete`, `partial` or `unavailable` assurance.

## Capabilities at this stage

<!-- generated:capabilities:observe:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Runtime corroboration of the scanned graph](../guides/runtime-twin.md) | Observe | **Preview** | Whether imported runtime telemetry (OpenTelemetry, Envoy, Kubernetes audit, HTTP access logs) matches nodes in the scanned graph, edge states (observed, blocked, policy violation, not observed, static only), identity tokens stored only as keyed hashes, and a static page of the five Explorer views. A complete, partial or unavailable status; telemetry is imported, not collected live. |
| [Continuous production runtime observation](../roadmap/README.md) | Observe | **Roadmap** | Live collection of production behavior and exercised vulnerable functions. Not shipped; today's runtime support is offline telemetry import. |
<!-- generated:capabilities:observe:end -->

## Read more

- [Runtime-Corroborated Security Twin](../guides/runtime-twin.md)
- [Runtime corroborated twin implementation status](../implementation-status/runtime-corroborated-twin.md)

---

Previous: [Scale](../scale/README.md) · Next: [Trace](../trace/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
