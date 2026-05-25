---
description: Generate an auditor-ready compliance attestation. Built-in frameworks include NIST AI 600-1 (122 controls), OWASP ASVS (144 requirements), OWASP LLM Top 10 (2025), and EU AI Act (72 controls).
argument-hint: "[nist|asvs|llm|eu-ai-act] [path] [--format md|csv|json] [--output <file>]"
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
  eu-ai-act|"eu_ai_act"|"euaiact"|"ai-act")
    OUTPUT="${OUTPUT:-eu-ai-act-attestation.md}"
    FW_SHORT="eu-ai-act"
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/eu-ai-act/scan.py "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT"
    ;;
  *)
    echo "Usage: /compliance-report [nist|asvs|llm|eu-ai-act] [path] [--format md|csv|json]"
    echo ""
    echo "  nist       — NIST AI 600-1 (122 GenAI controls; auditor-ready attestation)"
    echo "  asvs       — OWASP ASVS Level 1+2 (144 requirements across 14 chapters)"
    echo "  llm        — OWASP LLM Top 10 (2025) — 10 GenAI/LLM risk controls with per-control remediation"
    echo "  eu-ai-act  — EU AI Act (72 controls: Art. 5 prohibited practices, Art. 9-15, Art. 17 QMS, Art. 43/49, Art. 51-55 GPAI, Art. 72-73)"
    echo ""
    echo "Note: Many controls are organizational/process-based and will show as Not Compliant"
    echo "unless evidenced through documentation. GRC sign-off required before audit/regulator use."
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

**`eu-ai-act`** — EU AI Act comprehensive mapping. 72 controls covering prohibited practices (Art. 5), high-risk system obligations (Art. 9-15 at sub-article granularity), quality management system (Art. 17), conformity assessment (Art. 43), EU database registration (Art. 49), GPAI model obligations (Art. 51-55 including copyright, training data summaries, systemic risk, energy tracking), post-market monitoring (Art. 72), and serious incident reporting (Art. 73). Annex III applicability is a legal determination — Counsel owns it, not this scanner. Edit `scripts/eu-ai-act/evidence-rules.json` to extend. **Requires Counsel + GRC sign-off before regulator use.**

## Intellectual property note

This tool references standard control identifiers and uses independently authored descriptions. It does not reproduce copyrighted standard text from any standards body.

## Closing the gaps

After the report is written, the command offers `/agentic-security:compliance-fix <framework>`. That command re-scans, then routes every Not-Compliant or Partial control to the `/agentic-security:*` command that closes it — deduplicated, ordered, and tagged with which controls each step fixes. Controls that no scanner can patch (incident response plans, model evaluation policies, etc.) are listed separately with a note explaining what they require.
