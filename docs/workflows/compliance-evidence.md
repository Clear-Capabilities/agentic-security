# Compliance evidence

<!-- seo: title="Compliance evidence workflow: automated technical-control evidence without a certification claim" description="Generate framework control evidence from a scan, keep unassessed and manual controls out of the satisfied count, and sign findings for portable verification." -->

Agentic Security produces **automated technical-control evidence mapped to a framework's controls**. It never says "compliant", "certified" or "audit-passed".

## The workflow

| Step | Command | Result |
|---|---|---|
| See the frameworks | `agentic-security compliance --list` | The bundled and bring-your-own frameworks |
| Scan first | `agentic-security scan .` | `compliance` reads the last scan rather than re-scanning |
| Report | `agentic-security compliance --walkthrough <id>` | An auditor narrative with per-control evidence mapping |
| Only the gaps | `agentic-security compliance --gap` | The failing controls |
| Gate | `agentic-security compliance --fail-on gap` | Exit 1 when a control is failing |
| Machine-readable | `agentic-security compliance --format oscal` | A NIST OSCAL assessment-results document |
| Sign evidence | `agentic-security attest` | Ed25519-signed bundles per finding, verifiable with only the public key |

Bundled frameworks include NIST AI 600-1, NIST SP 800-171 Rev. 3, NIST CSF 2.0, NIST Privacy Framework 1.1, OWASP ASVS 5.0, OWASP Top 10 for LLM Applications 2025, the EU AI Act, GDPR, the HIPAA Security Rule and CCPA. Five have a per-control coverage map under [docs/compliance](../compliance/nist-ai-600-1-coverage.md).

## The honesty model

Every control lands in one of four buckets, and the bucket is always shown:

| Bucket | Meaning |
|---|---|
| **Gap** | A mapped signal is failing |
| **Not assessed** | Code-testable, but this engine has no signal for it |
| **Manual** | Governance or policy, outside any scanner's reach |
| **Satisfied** | A mapped signal passes |

*Not assessed* and *manual* controls are never counted as satisfied. The satisfied rate is reported over the controls actually assessed, never over all of a framework's controls. A scan that examined no files reports everything as *not assessed*. A control the engine could not decide carries no finding in OSCAL output, rather than a fabricated verdict.

## What a signed bundle proves

A bundle proves its contents are unmodified since signing. It does not prove the finding is real; both statements are inside the signature, so neither can be dropped in transit. Per-install run attestation is a symmetric key and is tamper-evidence for the operator, not third-party non-repudiation.

## What it is not

NIST SP 800-171 evidence is not a CMMC assessment, an SPRS score or a certification. Only a certifying assessor issues one. See [Compliance](../guides/compliance.md), [OSCAL](../OSCAL.md) and [the CISO lane](../roles/ciso.md).
