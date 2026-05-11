---
description: List every agentic-security command organized by category, with one-line descriptions and example invocations.
---

Print the full agentic-security command catalog.

```
agentic-security commands

EASY MODE — three commands. The whole product.
  /scan --all                One-screen "safe to deploy?" verdict
  /show-findings             Interactive HTML report of findings
  /fix --all                 Batch-fix every finding at or above --severity

DEVELOPER MODE — full catalog below.

SCANNING & FIXING
  /scan --all                Full SAST + SCA + secrets sweep (one-screen verdict)
  /scan --sca-only           Dependency CVE audit only (OSV.dev-backed)
  /scan --secrets-only       Hardcoded credential / API key scan only
  /fix --one <id>            Patch a single finding via the fixer subagent
  /fix --all [--critical|--high|--medium|--low]  Batch-fix by severity tier
  /fix --pr [--apply]        Bundle fixes into a feature branch + PR
  /security-triage           Validate findings; suppress confirmed false positives

AI-NATIVE CAPABILITIES
  /security-chain            Synthesize multi-finding exploit chains
  /security-poc              Generate adversarial PoC for a specific finding
  /security-logic-review     Intent-vs-implementation business logic review
  /security-threat-model     Threat model from last scan (--stride or --llm for OWASP LLM Top 10)
  /security-mcp-audit        Audit MCP server configs (agent-host risks)
  /security-authz            Deep auth/authZ audit (OWASP A01)
  /security-kev              List CVEs in CISA Known Exploited Vulnerabilities
  /security-aibom            AI/ML Bill of Materials — models, prompts, frameworks, vector stores

POSTURE MANAGEMENT
  /security-material-change  Score a git diff by architectural risk
  /security-drift            Compare two scans (--from a.json --to b.json)
  /security-sbom             CycloneDX 1.6 or SPDX 2.3 software bill of materials
  /security-api-inventory    Export full API surface map (md/json/openapi)
  /security-pipeline         Audit GitHub Actions; emit a PBOM
  /security-license          Enforce license allow/deny policy on deps
  /security-mttr             Show findings older than per-severity SLA

COMPLIANCE ATTESTATION
  /produce-compliance-report [nist|asvs|pci|soc2]  Auditor-ready attestation for any framework

PROJECT META
  /security-setup            Install short-form commands in this project
  /security-status           Plugin & project health snapshot
  /security-help             This command
  /security-grade            Letter grade (A–F) + README badge snippet
  /security-share            Posts (Twitter/LinkedIn/Discord/recap) about your security progress

USAGE NOTES
  - Every command works as /agentic-security:<name> too (the long form).
  - Most commands accept a [path] argument to limit scope.
  - First run /scan once. Most other commands read its output
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
