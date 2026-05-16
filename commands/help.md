---
description: List every agentic-security command, ICP-segmented (Vibecoder lane / Pro lane / Both). For builders or security engineers — pick the lane that matches what you do all day.
---

Print the full agentic-security command catalog, segmented by ICP.

```
agentic-security commands

EASY MODE — four commands. The whole product.
  /scan --all                One-screen "safe to deploy?" verdict
  /show-findings --all       Triage FPs then open interactive HTML report
  /fix --all                 Batch-fix every finding at or above --severity
  /find-and-fix-everything   Scan + fix every finding at every severity in one shot

═══════════════════════════════════════════════════════════════
🎨 VIBECODER / BUILDER LANE
═══════════════════════════════════════════════════════════════
You ship features fast. You want plain English, $-cost framing, one-button
fixes, and bodyguards that prevent foot-guns BEFORE they hit production.

  Smart entry
    /secure                    Routes you to the right next action
    /tutorial                  First-run walkthrough with one real finding

  Scan & fix (vibecoder framing)
    /scan --uncommitted        Scan only files you've changed since last commit
    /supply-chain-check        One-screen "is npm install safe?" verdict
    /find-and-fix-everything   Scan + fix every severity in one shot
    /report-card               A–F letter grade + one concrete next action
    /risk-in-dollars           Each finding's $ exposure (best/likely/worst)

  Understand it
    /story-explain             4-act attack story (vibecoder default)
    /attack-surface            3-5 realistic attack scenarios as narrative
    /explain                   Plain-English explanation of one finding

  Bodyguards (set once, run forever)
    /ai-bodyguard              Intercept insecure AI code BEFORE it hits disk
    /destructive-guard         Block rm -rf, DROP TABLE, force push to main…
    /predeploy-gate            Block vercel --prod / fly deploy on findings
    /cve-alerts                Daily Slack/Discord ping on new CVE in your deps

  Secrets (the panic button)
    /rotate-key-auto           Revokes + scrubs + pushes replacement
    /rotate-secret             Provider-aware rotation guide
    /vault-wizard              Migrate .env to Doppler / Infisical / platform

  Stack-specific
    /stack-playbook            Copy-paste security checklist for your stack
    /harden                    Headers + .gitignore + SECURITY.md + audit hook
    /db-audit                  Supabase RLS, service-role exposure
    /auth-audit                Clerk / NextAuth / Auth0 / Lucia misconfig
    /rate-limit-check          Find unrate-limited auth/AI/payment endpoints
    /webhook-audit             Stripe/GitHub/Clerk signature verification
    /env-check                 NEXT_PUBLIC_ leaks, hardcoded fallbacks
    /csp-cors                  Generate CSP + CORS headers for your stack
    /llm-cost-ceiling          Auto-patch max_tokens + $-spend tracker
    /prompt-firewall           LLM defense gaps (user input in system prompt)
    /deploy-check              Vercel/Railway/Fly/Netlify/CF checklist
    /launch-check              10 things builders typically miss

  Customer / investor artifacts
    /security-badge            Shields.io badge + posture paragraph
    /security-onepager         "How we keep your data safe" PDF-ready
    /trust-page                /.well-known/security.txt + /security page
    /privacy-docs              PRIVACY.md + cookie banner from your stack
    /disaster-playbook         DISASTER.md with the commands you'll need
    /social-media              X / LinkedIn / Discord posts about progress

═══════════════════════════════════════════════════════════════
🔧 PRO / APPLICATION SECURITY LANE
═══════════════════════════════════════════════════════════════
You triage findings for a living. You need depth, integration with the stack
you already run, customization, and audit-defensible output.

  Deep scanning
    /scan --all                Full SAST + SCA + secrets sweep
    /scan --sca                OSV-backed dep CVE audit
    /scan --secrets            60+ provider patterns + entropy
    /scan --authz              JWT, OAuth/PKCE, IDOR, multi-tenant scope
    /scan --mcp                MCP server config audit
    /scan --pipeline           GitHub Actions integrity
    /scan --logic              Semantic business-logic review (subagent)
    /scan --diff [--since ref] Architectural-risk score on git diff
    agentic-security scan --pr [ref]    Diff-aware: only changed files
    agentic-security scan --deterministic  Byte-stable for CI baselines

  Validation & triage
    /validate-findings         Build a PoC + regression test for one finding
    /show-findings --all       Interactive HTML triage report
    /show-findings --kev       Filter to actively-exploited CVEs
    /show-findings --chains    Multi-finding attack chains
    /show-findings --threat-model [--stride|--llm]

  Rule authoring & customization
    agentic-security rule list             List custom YAML rules
    agentic-security rule test <glob>      Test rules against fixtures
    agentic-security rules validate        Lint rules.yml
    agentic-security rules lock            Pin rule-pack hash
    agentic-security packs list            Curated rule packs

  Integrations
    /ci-gate                   GitHub Actions workflow + SARIF upload
    /fix --pr                  Bundle fixes into a feature branch + PR
    agentic-security tickets sync --provider github|linear|jira
    agentic-security org-scan --repos <list>   Fleet scan across N repos
    agentic-security triage list|assign|transition|trend
    /security-tests            Generate failing security regression tests

  Posture & compliance
    /posture-management --sbom   CycloneDX 1.6 / SPDX 2.3 SBOM
    /posture-management --aibom  AI/ML BOM — models, prompts, frameworks
    /posture-management --api    API surface with auth + data classes
    /posture-management --license  License allow/deny enforcement
    /posture-management --drift  Compare two scans
    /posture-management --mttr   Findings exceeding SLA thresholds
    /security-trend            Rolling history + regression detection
    /compliance-report [nist|asvs|llm]   Auditor-ready attestation

  Pro framing of dual-ICP commands
    /story-explain --post-mortem   Past-tense narrative for incident write-ups
    /rotate-key-auto --scrub-history   git filter-repo / BFG history rewrite

  LLM red-teaming
    /llm-redteam               30+ adversarial prompts × 7 mutations
    /jailbreak-detector        Canonical jailbreak families, per-family verdict
    /llm-eval                  Generate promptfoo YAML eval suite

═══════════════════════════════════════════════════════════════
🤝 BOTH LANES USE THESE
═══════════════════════════════════════════════════════════════

  Dependency depth
    /supply-chain-check        Roll-up verdict across six dep audits
    /dep-pinning               Loose ranges (^, ~, *) allowing silent injection
    /dep-freshness             Score how stale your direct deps are
    /install-script-audit      postinstall / preinstall hooks
    /vendor-audit              Copy-pasted third-party code (invisible to SCA)
    /trim-dependencies         Installed but never imported
    /dep-alternatives          Lighter / safer replacements

  Project meta
    /status                    Plugin & project health snapshot
    /help                      This command
    /find-and-fix-everything   The "I have 10 min" mode

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
