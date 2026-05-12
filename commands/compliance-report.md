---
description: Generate an auditor-ready compliance attestation for NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2, or OWASP LLM Top 10 (2025).
argument-hint: "[nist|asvs|pci|soc2|llm] [path] [--format md|csv|json] [--output <file>]"
---

Run the compliance attestation scanner for the chosen framework.

```bash
FRAMEWORK="${1:-}"
PATH_ARG="${2:-.}"
FORMAT="${FORMAT:-md}"
OUTPUT=""

case "$FRAMEWORK" in
  nist|"nist ai 600-1"|"nist-ai-600-1")
    OUTPUT="${OUTPUT:-nist-ai-600-1-attestation.md}"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/nist-compliance/scan.py "$PATH_ARG"
    ;;
  asvs|"owasp-asvs")
    OUTPUT="${OUTPUT:-owasp-asvs-attestation.md}"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/owasp-asvs/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  pci|"pci-dss")
    OUTPUT="${OUTPUT:-pci-dss-attestation.md}"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/pci-dss/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  soc2|soc)
    OUTPUT="${OUTPUT:-soc2-attestation.md}"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/soc2/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  llm|"owasp-llm"|"owasp-llm-top10"|"llm-top-10"|"llm-top10")
    OUTPUT="${OUTPUT:-owasp-llm-top10-attestation.md}"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/owasp-llm-top10/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  *)
    echo "Usage: /compliance-report [nist|asvs|pci|soc2|llm] [path] [--format md|csv|json]"
    echo ""
    echo "  nist   — NIST AI 600-1 (122 GenAI controls; auditor-ready attestation)"
    echo "  asvs   — OWASP ASVS Level 1+2 (multi-signal evidence model)"
    echo "  pci    — PCI-DSS 4.0 (12 code-testable controls)"
    echo "  soc2   — SOC 2 Common Criteria CC6–CC9 (12 controls)"
    echo "  llm    — OWASP LLM Top 10 (2025) — 10 GenAI/LLM risk controls with per-control remediation"
    exit 1
    ;;
esac
```

## Frameworks

**`nist`** — NIST AI 600-1: 122 code-testable controls for GenAI systems. Writes three files: `.md` for auditors, `.csv` for spreadsheet review, `.json` for CI gating. Edit `scripts/nist-compliance/evidence-rules.json` to teach the scanner your project's vocabulary.

**`asvs`** — OWASP ASVS Level 1+2: multi-signal evidence model (manifest → import → path → code/config/doc terms, with negation filter). Edit `scripts/owasp-asvs/evidence-rules.json` to extend controls.

**`pci`** — PCI-DSS 4.0: strong cryptography, TLS, MFA, audit logging, account lockout, vulnerability scanning automation. Pure-organisational controls are out of scope by design.

**`soc2`** — SOC 2 Common Criteria: logical access, MFA, encryption, monitoring, change management, vendor risk via SBOM, incident-response runbooks. For a full vendor questionnaire, also run:
- `/posture-management --sbom --format cyclonedx` (CC9.2 evidence)
- `/scan --pipeline --format pbom` (CC8.1 evidence)
- `/posture-management --mttr` (CC7.x — proves SLA tracking)
- `/posture-management --api --format openapi` (CC6.x — proves access surface documented)
- `/compliance-report nist` (if the product uses GenAI)

**`llm`** — OWASP LLM Top 10 (2025): 10 risk controls specific to LLM and Generative AI applications. Covers prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, and unbounded consumption. Every Not Compliant or Partial control includes a detailed remediation checklist of concrete code changes. Aliases: `owasp-llm`, `owasp-llm-top10`, `llm-top-10`. Edit `scripts/owasp-llm-top10/evidence-rules.json` to extend the signal vocabulary for your project.
