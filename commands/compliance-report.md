---
description: Generate an auditor-ready compliance attestation. Built-in frameworks include NIST AI 600-1, OWASP ASVS, OWASP LLM Top 10 (2025), SOC 2 Common Criteria, ISO/IEC 27001 Annex A, ISO/IEC 42001 AIMS, and EU AI Act Articles 9–15.
argument-hint: "[nist|asvs|llm|soc2|iso27001|iso42001|eu-ai-act] [path] [--format md|csv|json] [--output <file>]"
---

Run the compliance attestation scanner for the chosen framework.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
FRAMEWORK="${1:-}"
PATH_ARG="${2:-.}"
FORMAT="${FORMAT:-md}"
OUTPUT=""
FW_SHORT=""

case "$FRAMEWORK" in
  nist|"nist ai 600-1"|"nist-ai-600-1")
    OUTPUT="${OUTPUT:-nist-ai-600-1-attestation.md}"
    FW_SHORT="nist"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/nist-compliance/scan.py "$PATH_ARG"
    ;;
  asvs|"owasp-asvs")
    OUTPUT="${OUTPUT:-owasp-asvs-attestation.md}"
    FW_SHORT="asvs"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/owasp-asvs/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  llm|"owasp-llm"|"owasp-llm-top10"|"llm-top-10"|"llm-top10")
    OUTPUT="${OUTPUT:-owasp-llm-top10-attestation.md}"
    FW_SHORT="llm"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/owasp-llm-top10/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  soc2|"soc-2"|"soc2-cc"|"soc-2-cc")
    OUTPUT="${OUTPUT:-soc2-attestation.md}"
    FW_SHORT="soc2"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/soc2/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  iso27001|"iso-27001"|"iso27k")
    OUTPUT="${OUTPUT:-iso-27001-attestation.md}"
    FW_SHORT="iso27001"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/iso-27001/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  iso42001|"iso-42001"|"aims")
    OUTPUT="${OUTPUT:-iso-42001-attestation.md}"
    FW_SHORT="iso42001"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/iso-42001/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  eu-ai-act|"eu_ai_act"|"euaiact"|"ai-act")
    OUTPUT="${OUTPUT:-eu-ai-act-attestation.md}"
    FW_SHORT="eu-ai-act"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/eu-ai-act/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  *)
    echo "Usage: /compliance-report [nist|asvs|llm|soc2|iso27001|iso42001|eu-ai-act] [path] [--format md|csv|json]"
    echo ""
    echo "  nist       — NIST AI 600-1 (122 GenAI controls; auditor-ready attestation)"
    echo "  asvs       — OWASP ASVS Level 1+2 (multi-signal evidence model)"
    echo "  llm        — OWASP LLM Top 10 (2025) — 10 GenAI/LLM risk controls with per-control remediation"
    echo "  soc2       — SOC 2 Common Criteria (CC-series) — v0 code-detectable subset"
    echo "  iso27001   — ISO/IEC 27001:2022 Annex A — v0 code-detectable subset"
    echo "  iso42001   — ISO/IEC 42001:2023 AI Management System — v0 code-detectable subset"
    echo "  eu-ai-act  — EU AI Act Articles 9–15 (high-risk AI obligations) — v0 code-detectable subset"
    echo ""
    echo "Note: soc2 / iso27001 / iso42001 / eu-ai-act are v0 mappings. Process controls"
    echo "(vendor management, training records, legal applicability) are owned by GRC and"
    echo "must be evidenced separately."
    exit 1
    ;;
esac

# After a successful scan, offer the auto-router. The router re-scans with
# --json, so we don't try to count gaps here — keep the offer unconditional
# and let compliance-fix decide there's nothing to do.
if [ -n "$FW_SHORT" ]; then
  echo ""
  echo "📋 Want to close these gaps automatically?"
  echo "   Run: /agentic-security:compliance-fix $FW_SHORT $PATH_ARG"
  echo "   It re-scans, then routes every Not-Compliant control to the agentic-security"
  echo "   command that fixes it (and flags any that require manual / process work)."
fi
```

## Frameworks

**`nist`** — NIST AI 600-1: 122 code-testable controls for GenAI systems. Writes three files: `.md` for auditors, `.csv` for spreadsheet review, `.json` for CI gating. Edit `scripts/nist-compliance/evidence-rules.json` to teach the scanner your project's vocabulary.

**`asvs`** — OWASP ASVS Level 1+2: multi-signal evidence model (manifest → import → path → code/config/doc terms, with negation filter). Edit `scripts/owasp-asvs/evidence-rules.json` to extend controls.

**`llm`** — OWASP LLM Top 10 (2025): 10 risk controls specific to LLM and Generative AI applications. Covers prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, and unbounded consumption. Every Not Compliant or Partial control includes a detailed remediation checklist of concrete code changes. Aliases: `owasp-llm`, `owasp-llm-top10`, `llm-top-10`. Edit `scripts/owasp-llm-top10/evidence-rules.json` to extend the signal vocabulary for your project.

**`soc2`** — SOC 2 Common Criteria (v0). Covers the CC-series controls that are mechanically inspectable from code: logical access (CC6.1), encryption in transit/at rest (CC6.6/6.7), monitoring + logging (CC7.1/7.2), incident response artifacts (CC7.3), vulnerability identification (CC7.4), change management (CC8.1). Process-only controls (vendor management, training records) are out of scope by design. Edit `scripts/soc2/evidence-rules.json` to extend coverage. **v0 mapping — requires GRC sign-off before audit use.**

**`iso27001`** — ISO/IEC 27001:2022 Annex A (v0). Covers the Annex A.8 (Technological) controls inspectable from code, plus a handful of A.5 organizational controls: access control (A.5.15), cloud security (A.5.23), MFA (A.8.5), configuration management (A.8.9), logging (A.8.15), monitoring (A.8.16), cryptography (A.8.24), secure coding (A.8.28). Edit `scripts/iso-27001/evidence-rules.json` to extend. **v0 mapping — requires GRC sign-off before audit use.**

**`iso42001`** — ISO/IEC 42001:2023 AI Management System (v0). Covers AIMS clauses with code shadows: risk assessment (6.1.3), AI objectives (6.2), impact assessment (8.2), data governance (8.3), human oversight (8.4), monitoring (9.1), documentation A.6.2.6 (model/system cards). Edit `scripts/iso-42001/evidence-rules.json` to extend. **v0 mapping — the broader management system is organizational, not code-shaped; this overlay is a starting point.**

**`eu-ai-act`** — EU AI Act Articles 9–15 (v0). Covers the high-risk AI obligations with code-detectable signals: risk management system (Art. 9), data governance (Art. 10), technical documentation (Art. 11), record-keeping (Art. 12 — the most code-detectable), transparency (Art. 13), human oversight (Art. 14), accuracy/robustness/cybersecurity (Art. 15). Applicability (whether your system is in scope of Annex III) is a legal determination — Counsel owns it, not this scanner. Edit `scripts/eu-ai-act/evidence-rules.json` to extend. **v0 mapping — requires Counsel + GRC sign-off before regulator use.**

## Closing the gaps

After the report is written, the command offers `/agentic-security:compliance-fix <framework>`. That command re-scans, then routes every Not-Compliant or Partial control to the `/agentic-security:*` command that closes it — deduplicated, ordered, and tagged with which controls each step fixes. Controls that no scanner can patch (incident response plans, model evaluation policies, etc.) are listed separately with a note explaining what they require.
