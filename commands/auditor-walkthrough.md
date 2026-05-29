---
description: Generate auditor-ready walkthrough for a compliance framework — evidence mapping per control, status, remediation.
argument-hint: "<framework-id> [--write]"
---

# /auditor-walkthrough

Generate a step-by-step narrative an engineering team can follow to demonstrate evidence for a compliance framework's controls to an external auditor.

## Bundled frameworks (public-domain — no copyrighted text reproduced)

| ID | Framework |
|---|---|
| `nist-csf-2` | NIST Cybersecurity Framework 2.0 |
| `nist-ai-600-1` | NIST AI 600-1 — Generative AI Profile |
| `owasp-asvs-5` | OWASP Application Security Verification Standard 5.0 |
| `owasp-llm-top-10` | OWASP Top 10 for LLM Applications 2025 |
| `eu-ai-act` | EU AI Act (Regulation 2024/1689) |
| `gdpr` | General Data Protection Regulation |
| `hipaa-security-rule` | HIPAA Security Rule (45 CFR Part 164) |
| `ccpa` | California Consumer Privacy Act |

## Proprietary frameworks — bring your own

The following frameworks contain copyrighted control text that we cannot bundle. Drop your own license-compliant control mapping at:

```
.agentic-security/compliance/<framework-id>/controls.json
```

…using the same JSON shape as a bundled framework. The auditor-walkthrough will render evidence against it.

Common candidates: SOC 2 (AICPA Trust Services Criteria), ISO 27001 / 27002, PCI-DSS, HITRUST CSF, CSA STAR.

## What the walkthrough contains

For each control:
- The control's summary (one sentence — non-copyrighted)
- The evidence an auditor would expect
- The scanner's observation against your current state
- Remediation pointer when evidence is missing or partial

## Example

```bash
/auditor-walkthrough owasp-asvs-5
```

Generates `.agentic-security/auditor-walkthroughs/owasp-asvs-5.md`:

```
# Auditor walkthrough — OWASP Application Security Verification Standard 5.0

> Publisher: OWASP Foundation
> License: Creative Commons Attribution-ShareAlike 4.0

> **This walkthrough organizes scanner evidence into a narrative for an
> external auditor.** It does NOT certify compliance. A licensed assessor
> is responsible for the final attestation.

## Summary

Controls evaluated: 10
- ✅ Evidence present: 7
- 🟡 Partial evidence: 2
- ⛔ No evidence: 0
- 📝 Manual attestation required: 1

## Controls — step by step

### ✅ V2.1 — Verify that authentication is performed for protected functions.

**Evidence the auditor expects:**
- Zero open critical findings in family auth-missing on the current scan.

**Current state:**
- ✓ auth-missing: no open critical/high findings.

### 🟡 V5.1 — Verify input validation for type, length, and content.

**Evidence the auditor expects:**
- Zero open critical findings in sqli/xss/command-injection/...

**Current state:**
- ✓ sqli: no open critical/high findings.
- ✗ 2 open xss finding(s) at high/critical.
- ✓ command-injection: no open critical/high findings.

**Remediation:** address the bullet(s) above, then re-run /auditor-walkthrough owasp-asvs-5.
```

## Implementation

```js
import {
  listFrameworks, loadFramework, evaluateFramework,
  renderWalkthrough, persistWalkthrough,
} from '@clear-capabilities/agentic-security-scanner/posture/auditor-walkthrough.js';

const fw = loadFramework(scanRoot, 'owasp-asvs-5');
const scan = readLastScan(scanRoot);
const evaluation = evaluateFramework(scanRoot, fw, scan);
const body = renderWalkthrough(fw, evaluation);
persistWalkthrough(scanRoot, fw, body);
```

## Disclaimer

This command organizes scanner evidence into a narrative for an auditor's review. It is not a compliance certification. A licensed CPA / DPO / external assessor is responsible for the final attestation. Use of bundled framework names (NIST, OWASP, EU AI Act, GDPR, HIPAA, CCPA) is descriptive and does not imply endorsement by their publishers.
