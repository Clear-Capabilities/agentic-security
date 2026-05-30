---
description: Compliance + auditor flows. Framework attestation, walkthrough, buyer-facing badge, stack audits, PR augmentation.
argument-hint: "[--report <fw>|--walkthrough <fw>|--attestation|--audit <target>|--pr]"
---

# /compliance

Compliance + auditor flows dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--report <framework>` | Generate auditor-ready compliance attestation. Frameworks: `nist`, `asvs`, `llm`, `eu-ai-act` |
| `--walkthrough <framework>` | Step-by-step auditor narrative with evidence mapping per control. Frameworks: `nist-csf-2`, `nist-ai-600-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, `gdpr`, `hipaa-security-rule`, `ccpa` (or BYO at `.agentic-security/compliance/<id>/controls.json`) |
| `--attestation` | Render buyer-facing security posture artifact. `--format badge|onepager|page` |
| `--audit <target>` | Stack-specific security audits. Targets: `db`, `auth`, `rate-limit`, `webhook`, `env`, `csp-cors`, `deploy`, `launch`, `llm-cost`, `prompt` |
| `--pr` | Generate PR-description block (security delta vs base + ATT&CK + reviewers + artifacts) |

## Examples

```bash
/compliance --report nist                       # NIST AI 600-1 attestation
/compliance --walkthrough owasp-asvs-5          # OWASP ASVS auditor walkthrough
/compliance --attestation --format onepager     # buyer-facing one-pager
/compliance --audit db                          # database posture audit
/compliance --pr                                # PR-description block
```

## Implementation

Routes to the posture modules (`compliance-policy.js`, `auditor-walkthrough.js`, `pr-augment.js`) and the scanner CLI.
