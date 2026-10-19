# Detection engineering

<!-- seo: title="Detection engineering guide: today's evidence exports and the Detect roadmap" description="What a detection team can use from Agentic Security today, and the production hunting and detection generation that is not yet shipped." -->

**Primary question:** What evidence can I use today, and what is not built?

**Core workflow:** [Vulnerability response](../workflows/vulnerability-response.md)

This lane draws the line between what exists (a local, Labs detection loop plus exported evidence) and what does not (connection to production systems), in one place.

## Exists today (Labs): `dnr`

`agentic-security dnr generate|validate|hunt|window|show|status <finding-id>` turns a *proven* vulnerability into a validated detection, hunts local historical logs, and scopes the exposure window. Everything is local and text-only: no network call, no model call.

| Step | What it does | Honest limit |
|---|---|---|
| Generate | Sigma, a generic HTTP rule, a detect-only WAF suggestion, structured log queries, YARA for deserialization, Splunk, Sentinel and CloudWatch text | Built only from what the proof established; no endpoint recorded means no request-level rule; eight payload classes only |
| Validate | Synthetic exploit requests must fire it, lookalikes must not | A detection is never enabled before it validates |
| Hunt | Searches local logs for exploit-shaped requests: `OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE`, `TELEMETRY_UNAVAILABLE` | `NOT_OBSERVED` never means not exploited; compressed logs are skipped and make the verdict `INCONCLUSIVE` |
| Window | When the flaw entered the code, when a build with it first ran, when the fix deployed, and what your telemetry covers | Only the span your telemetry covers is observable |

Elastic, Google SecOps (YARA-L) and Datadog renderers translate exactly or say why not, so most payload classes are not expressible there, and their syntax was not run against a live product. Without a proof, `dnr generate` refuses; with `--allow-unproven` it drafts a static-only detection at low confidence that is marked not validated and not enabled. See [Detection and response](../guides/detection-and-response.md).

## Other evidence you can use today

| Artifact | What it is | How to get it |
|---|---|---|
| Findings in SARIF, JSON, CSV, JUnit | The weakness, its location, CWE, family and evidence | `agentic-security scan . --format sarif` |
| Source-to-sink shape | Which entry point reaches which sink, and the data classes at risk | `agentic-security dataflow export . --format json --output graph.json` |
| Attack shape | `attackPlaybook` and `poc` fields: the payload class that would exercise the flaw | In the finding JSON |
| Signed evidence | A per-finding Ed25519 bundle that proves its contents are unmodified | `agentic-security attest` |
| Runtime match | Imported telemetry matched to graph nodes, with edge states | `agentic-security runtime ingest` (offline, Preview) |
| Image provenance | Whether a finding is in a shipped image | `agentic-security image scan` and `provenance trace` (Preview) |

## Not built (Roadmap)

- Deploying detections to, and reading results back from, a live SIEM or EDR.
- Observing exploitation in live production telemetry.
- Live runtime collection.

When any of these ships it will be added to [the registry](../capabilities.yaml) with implementation evidence, and this page will change. See [Detect](../detect/README.md) and the [roadmap](../roadmap/README.md).

## How to contribute to the loop

A weakness you prove and fix can be encoded as a deterministic rule with the Labs rule compiler (`rules synthesize`, then `evaluate` and `promote`), so the next scan finds it without a model. See [the rule compiler](../guides/rule-compiler.md).
