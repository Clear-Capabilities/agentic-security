# Detect

<!-- seo: title="Detect: Was exploitation observed and can recurrence be detected?" description="Stage 10 of the Agentic Security assurance lifecycle: Was exploitation observed and can recurrence be detected?" -->

**Stage 10 of 10.** Was exploitation observed and can recurrence be detected?

**Stage maturity:** Labs for what exists, Roadmap for what does not. Every capability below carries its own label.

**What exists (Preview).** `dnr` turns a *proven* vulnerability into a validated detection and hunts local historical logs for it. Everything runs locally and is text-only; it makes no network call and no model call.

- **Generate** a detection from the facts the proof established: Sigma, a generic HTTP rule, a detect-only WAF suggestion, structured log queries, YARA for the deserialization class, and Splunk, Sentinel and CloudWatch text. Elastic, Google SecOps (YARA-L) and Datadog renderers translate exactly or say why they cannot.
- **Validate** it before it is enabled: synthetic exploit requests must fire it and lookalikes must not.
- **Hunt** local logs for requests with the shape of the exploit. The verdicts are `OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE` and `TELEMETRY_UNAVAILABLE`, and `NOT_OBSERVED` never means the flaw was not exploited elsewhere.
- **Scope** the exposure window: when the flaw entered the code, when a build containing it first ran, when the fix was deployed, and which part of that span your telemetry covers.
- **Keep** the rule after the fix, so a recurrence is detectable.

A detection is built only from what the proof established. With no proof the loop refuses, and with `--allow-unproven` it drafts a static-only detection at low confidence that is explicitly not validated and not enabled. Captured from the demo app:

```text
no exploit proof for 008b65bd9c0f372d: prove it first (triage exploit 008b65bd9c0f372d --prove), or pass --allow-unproven to build a lower-confidence detection from the static finding alone
```

```text
Detection det-78cc8d803d6e for 008b65bd9c0f372d: sql-injection (static-only, confidence 0.1)
Validation: NOT_VALIDATED (0/0 synthetic cases); NOT enabled
```

**What does not exist (Roadmap).** Connecting detections to a live SIEM or EDR and reading results back, and observing exploitation in production telemetry. The renderers' syntax was not run against a live Elastic, Google SecOps or Datadog. There is no MCP tool for the loop, compressed logs are skipped (which makes a hunt `INCONCLUSIVE`), and a payload class beyond the eight supported ones gets no detection rather than a guessed one.

Other exported evidence a detection team can use today: the signed per-finding bundle (`agentic-security attest`), SARIF and JSON findings, and the exported security graph. See [the detection engineering lane](../roles/detection-engineering.md).

**Evidence this stage creates:** Nothing yet. When implemented: an observed-exploitation record and a recurrence detection tied to the finding.

## Capabilities at this stage

<!-- generated:capabilities:detect:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Detection and response (dnr)](../guides/detection-and-response.md) | Detect | **Preview** | A validated detection generated from a proven vulnerability (Sigma, a generic HTTP rule, a detect-only WAF suggestion, structured log queries, YARA, and Splunk, Sentinel and CloudWatch text), a bounded hunt of local historical logs (observed, not observed, inconclusive, telemetry unavailable) and the observable exposure window. All local and text-only; no SIEM connection. |
| [Connected production detection](./README.md) | Detect | **Roadmap** | Detections deployed to and read back from a connected SIEM or EDR, and exploitation observed in live production telemetry. Not shipped; today's detections are generated and hunted locally. |
<!-- generated:capabilities:detect:end -->

## Read more

- [Detection engineering lane](../roles/detection-engineering.md)
- [Roadmap](../roadmap/README.md)
- [Assurance lifecycle](../how-it-works/assurance-lifecycle.md)

---

Previous: [Verify](../verify/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
