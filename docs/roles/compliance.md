# Compliance

<!-- seo: title="Compliance guide: control evidence without a certification claim" description="Generate framework control evidence, understand the gap, not assessed, manual and satisfied buckets, sign findings, and avoid overstating results to an auditor." -->

**Primary question:** What evidence do I have for an auditor, and what does the tool admit it could not check?

**Core workflow:** [Compliance evidence](../workflows/compliance-evidence.md)

## What you can produce

| Need | Command |
|---|---|
| List frameworks | `agentic-security compliance --list` |
| Auditor narrative | `agentic-security compliance --walkthrough <id>` |
| Only failing controls | `agentic-security compliance --gap` |
| OSCAL assessment results | `agentic-security compliance --format oscal` |
| Signed evidence per finding | `agentic-security attest` |
| Verify a bundle with only a public key | `agentic-security verify-attestation <bundle.json> --public-key <path>` |

Workflow and honesty model: [compliance evidence](../workflows/compliance-evidence.md).

## What to say to an auditor

- Say: "automated technical-control evidence mapped to <framework> controls", with the not-assessed and manual counts.
- Do not say that the tool made you compliant or that it certified you. Neither is a statement this tool can make.
- A NIST SP 800-171 report is not a CMMC assessment, an SPRS score or a certification. A certified third-party assessor does that.

## Coverage maps

Per-control maps exist for [NIST AI 600-1](../compliance/nist-ai-600-1-coverage.md), [NIST SP 800-171 Rev. 3](../compliance/nist-800-171-r3-coverage.md), [NIST Privacy Framework 1.1](../compliance/nist-privacy-1-1-coverage.md), [OWASP ASVS](../compliance/owasp-asvs-coverage.md) and [OWASP LLM Top 10](../compliance/owasp-llm-top10-coverage.md). The other bundled frameworks have none yet, tracked as a known gap.

## Three separate vocabularies

The framework report, the Data Flow Explorer's obligation overlay and the custom compliance-policy gate are three differently named systems that are never unified. See [Compliance](../guides/compliance.md#three-separate-compliance-state-vocabularies--not-one-unified-model) and the [glossary](../reference/glossary.md#the-three-compliance-vocabularies).

## Read more

- [OSCAL](../OSCAL.md)
- [Risk in dollars](../guides/risk-dollars.md)
- [State and retention](../governance/state-and-retention.md)
