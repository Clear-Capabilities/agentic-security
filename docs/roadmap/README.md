# Roadmap

<!-- seo: title="Roadmap: what Agentic Security does not do yet" description="Strategic directions that are not shipped: continuous runtime observation, connected production detection and the security learning rate metric." -->

**Roadmap** means strategic direction, **not shipped**. Nothing on this page describes something the product does today. Each item below is in [the registry](../capabilities.yaml) as Roadmap with no implementation evidence, and each will move only when code lands.

| Direction | Lifecycle stage | What would be true when it ships | What exists today instead |
|---|---|---|---|
| Continuous production runtime observation | Observe | Live collection of production behavior and exercised vulnerable functions would corroborate static findings | Offline import of exported telemetry, edge states and a static explorer page |
| Connected production detection | Detect | Detections would be deployed to and read back from a connected SIEM or EDR, and exploitation observed in live telemetry | The Preview `dnr` loop generates and hunts locally; every renderer is text-only |
| Security learning rate | Learn | A measured share of novel confirmed weakness patterns converted into reusable rules, tests or controls | The Labs promotion machinery, with no metric over it |

Other non-goals of the current positioning work: universal exploit proof, fleet-wide scanning as a supported capability, and promoting any Labs feature to GA.

## The engineering roadmap

The engineering-level capability roadmap, with its own thesis, gates and what they do not prove, is [docs/ROADMAP.md](../ROADMAP.md). The registry decides maturity; that file explains direction.
