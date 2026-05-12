---
description: List every agentic-security command organized by category, with one-line descriptions and example invocations.
---

Print the full agentic-security command catalog.

```
agentic-security commands

EASY MODE — four commands. The whole product.
  /scan --all                One-screen "safe to deploy?" verdict
  /show-findings --all       Triage FPs then open interactive HTML report
  /fix --all                 Batch-fix every finding at or above --severity
  /find-and-fix-everything   Scan + fix every finding at every severity in one shot

DEVELOPER MODE — full catalog below.

SCANNING
  /scan --all                Full SAST + SCA + secrets sweep (one-screen verdict)
  /scan --sca           Dependency CVE audit only (OSV.dev-backed)
  /scan --secrets       Hardcoded credential / API key scan only
  /scan --authz              Deep auth/authZ audit — JWT, OAuth2, IDOR, session fixation
  /scan --mcp                Audit MCP server configs for agent-host risks
  /scan --pipeline           Audit GitHub Actions; --format pbom for Pipeline BOM
  /scan --logic              Semantic business-logic review (intent vs. implementation)
  /scan --diff               Score git diff by architectural risk (--since <ref>)

VIEWING & ANALYSIS
  /show-findings --all       Triage FPs then open interactive HTML report (default)
  /show-findings --kev       Show only CISA KEV (actively weaponized) findings
  /show-findings --chains    Synthesize multi-finding exploit chains
  /show-findings --threat-model  STRIDE table (add --llm for OWASP LLM Top 10)

FIXING
  /find-and-fix-everything   Scan + fix every finding at every severity in one shot
  /fix --one <id>            Patch a single finding via the fixer subagent
  /fix --all [--critical|--high|--medium|--low]  Batch-fix by severity tier
  /fix --pr [--apply]        Bundle fixes into a feature branch + PR

DEEP ANALYSIS
  /exploit-poc              Generate adversarial PoC for a specific finding
  /explain          Plain-English explanation of any finding
  /launch-check     Pre-deploy 10-item checklist

POSTURE MANAGEMENT
  /posture-management --sbom   CycloneDX 1.6 or SPDX 2.3 software bill of materials
  /posture-management --aibom  AI/ML Bill of Materials — models, prompts, frameworks
  /posture-management --api    Full API surface map annotated with auth status + data classes
  /posture-management --license  Enforce license allow/deny policy on deps (--init to create)
  /posture-management --drift  Compare two scans — lost auth, new findings, new deps
  /posture-management --mttr   Show findings exceeding per-severity SLA thresholds

COMPLIANCE ATTESTATION
  /compliance-report [nist|asvs|pci|soc2]  Auditor-ready attestation for any framework

PROJECT META
  
  /status           Plugin & project health snapshot
  /help                  This command
  /report-card            Letter grade (A–F) + README badge snippet
  /social-media            Posts (Twitter/LinkedIn/Discord/recap) about your security progress

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
