---
description: List every agentic-security command organized by category, with one-line descriptions and example invocations.
---

Print the full agentic-security command catalog.

```
agentic-security commands — 35 total

SCANNING & FIXING
  /security-scan-all         Full SAST + SCA + secrets + IaC sweep
  /security-fix              Patch a single finding (by id) via the fixer subagent
  /security-fix-all          Batch-fix every finding at or above --severity
  /security-fix-pr           Bundle critical fixes into a feature branch + PR
  /security-report           Self-contained HTML report (also json/md/sarif/sbom)
  /security-triage           Validate findings; suppress confirmed false positives
  /security-sca              Dependency CVE audit only (OSV.dev-backed)
  /security-secrets          Hardcoded credential / API key scan only

AI-NATIVE CAPABILITIES
  /security-chain            Synthesize multi-finding exploit chains
  /security-poc              Generate adversarial PoC for a specific finding
  /security-logic-review     Intent-vs-implementation business logic review
  /security-threat-model     STRIDE coverage table from the last scan
  /security-mcp-audit        Audit MCP server configs (agent-host risks)
  /security-authz            Deep auth/authZ audit (OWASP A01)
  /security-kev              List CVEs in CISA Known Exploited Vulnerabilities
  /security-aibom            AI/ML Bill of Materials — models, prompts, frameworks, vector stores
  /security-llm-threat-model OWASP LLM Top 10 (2025) coverage map

POSTURE MANAGEMENT
  /security-material-change  Score a git diff by architectural risk
  /security-drift            Compare two scans (--from a.json --to b.json)
  /security-sbom             CycloneDX 1.6 or SPDX 2.3 software bill of materials
  /security-api-inventory    Export full API surface map (md/json/openapi)
  /security-pipeline         Audit GitHub Actions; emit a PBOM
  /security-license          Enforce license allow/deny policy on deps
  /security-mttr             Show findings older than per-severity SLA

COMPLIANCE ATTESTATION
  /nist-ai-600-1             NIST AI 600-1 attestation (122 GenAI controls)
  /owasp-asvs                OWASP ASVS Level 1+2 (15 controls)
  /pci-dss                   PCI-DSS 4.0 code-testable controls (12)
  /soc2                      SOC 2 Common Criteria CC6–CC9 (12 controls)

PROJECT META
  /security-setup            Install short-form commands in this project
  /security-status           Plugin & project health snapshot
  /security-help             This command
  /security-badge            Print a markdown badge for your README
  /security-share            Copy-paste posts (Twitter/LinkedIn/Discord)
  /security-recap            Year-in-Security recap card

USAGE NOTES
  - Every command works as /agentic-security:<name> too (the long form).
  - Most commands accept a [path] argument to limit scope.
  - First run /security-scan-all once. Most other commands read its output
    from .agentic-security/last-scan.json.
  - PostToolUse hook scans every Edit/Write automatically. Throttled per-file
    to one scan / 5s.
  - Set AGENTIC_SECURITY_OFFLINE=1 to skip all outbound calls (OSV, EPSS, KEV).

WHERE THINGS LIVE
  Project state:  .agentic-security/last-scan.json, rules.yml, license-policy.yml
  CVE cache:      ~/.claude/agentic-security/osv-cache/  (24h–7d TTL)
  Plugin bundle:  ~/.claude/plugins/cache/clearcapabilities/agentic-security/
```

Print the entire block above verbatim. The user wants the full catalog as a single screen, not a follow-up question. Do not summarize.
