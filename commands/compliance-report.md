---
description: Generate an auditor-ready compliance attestation for NIST AI 600-1, OWASP ASVS, or OWASP LLM Top 10 (2025).
argument-hint: "[nist|asvs|llm] [path] [--format md|csv|json] [--output <file>]"
---

Run the compliance attestation scanner for the chosen framework.

```bash
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
  *)
    echo "Usage: /compliance-report [nist|asvs|llm] [path] [--format md|csv|json]"
    echo ""
    echo "  nist   — NIST AI 600-1 (122 GenAI controls; auditor-ready attestation)"
    echo "  asvs   — OWASP ASVS Level 1+2 (multi-signal evidence model)"
    echo "  llm    — OWASP LLM Top 10 (2025) — 10 GenAI/LLM risk controls with per-control remediation"
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

## Closing the gaps

After the report is written, the command offers `/agentic-security:compliance-fix <framework>`. That command re-scans, then routes every Not-Compliant or Partial control to the `/agentic-security:*` command that closes it — deduplicated, ordered, and tagged with which controls each step fixes. Controls that no scanner can patch (incident response plans, model evaluation policies, etc.) are listed separately with a note explaining what they require.
