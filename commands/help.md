---
description: List every command, ICP-segmented (Vibecoder / Pro / Both). Pick the lane that matches your role.
---

Print the full agentic-security command catalog, segmented by ICP.

```
       ╭───╮ ╭───╮
       │ ◉ │ │ ◉ │        agentic-security  ·  by Clear Capabilities Inc.
       ╰─┬─╯ ╰─┬─╯        Tiny. Bright. Watching.
      ╭──┴─────┴──╮       https://clearcapabilities.com
      │  ·  ⌣  ·  │
      ╰───────────╯

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
    /explain                   Plain-English explanation of one finding
    /explain --narrative       4-act attack story
    /threat --view surface     3-5 realistic attack scenarios as narrative

  Stack-specific audits (one command, many targets)
    /audit --target db         Supabase RLS, SQL injection, service-role exposure
    /audit --target auth       Clerk / NextAuth / Auth0 / Lucia misconfig
    /audit --target rate-limit Unrate-limited auth/AI/payment endpoints
    /audit --target webhook    Missing signature verification
    /audit --target env        NEXT_PUBLIC_ leaks, .env hygiene
    /audit --target csp-cors   Generate CSP + CORS headers for your stack
    /audit --target deploy     Vercel / Railway / Fly / Netlify / CF checklist
    /audit --target launch     Pre-launch 10-item go/no-go checklist
    /audit --target llm-cost   Auto-patch missing max_tokens + spend tracker
    /audit --target prompt     Prompt injection + LLM output → SQL/exec
    /audit --all               Run every target in sequence

  Bodyguards (set once, run forever)
    /ai-bodyguard              Intercept insecure AI code BEFORE it hits disk
    /destructive-guard         Block rm -rf, DROP TABLE, force push to main…
    /ci --predeploy            Block vercel --prod / fly deploy on findings
    /cve-alerts                Daily Slack/Discord ping on new CVE in your deps

  Secrets (the panic button)
    /rotate-secret             Provider-aware rotation guide
    /rotate-secret --auto      Revoke + scrub + push replacement
    /vault-wizard              Migrate .env to Doppler / Infisical / platform

  Hardening & docs
    /harden                    Headers + .gitignore + SECURITY.md + audit hook
    /stack-playbook            Copy-paste security checklist for your stack

  Customer / investor artifacts
    /security-attestation                    Default: README badge
    /security-attestation --format onepager  "How we keep your data safe" doc
    /security-attestation --format page      /.well-known/security.txt + page
    /generate --type privacy   PRIVACY.md + cookie banner from your stack
    /generate --type disaster  DISASTER.md incident-response playbook
    /generate --type social    X / LinkedIn / Discord posts about progress

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
    agentic-security scan --deterministic  Byte-stable for CI baselines

  Validation & triage
    /validate-findings         Build a PoC + regression test for one finding
    /show-findings --all       Interactive HTML triage report
    /show-findings --kev       Filter to actively-exploited CVEs
    /show-findings --chains    Multi-finding attack chains
    /triage                    Interactive TP/FP marking
    /three-agent-review        Red / blue / auditor review of one finding

  Finding inquiry (one command, three modes)
    /explain --finding <id>    Plain-English explanation
    /explain --provenance --finding <id>   Full provenance graph (was /why-fired)
    /explain --gap <CWE>       Why a CWE didn't fire (was /why-not)

  CI & deploy integration (one command, three modes)
    /ci                        GitHub Actions workflow + SARIF upload
    /ci --provider gitlab      Other providers (gitlab|circleci|buildkite|jenkins)
    /ci --predeploy            Block vercel/fly/wrangler deploys
    /ci --hooks                Pre-commit + pre-push git hooks

  Threat modeling (one command, eight views)
    /threat                    Auto-derived STRIDE — assets, boundaries, findings
    /threat --view personas    Per-persona priority matrix (5 adversary classes)
    /threat --view playbook    Copy-paste attack scripts (curl / Nuclei)
    /threat --view bounty      Predicted HackerOne / Immunefi USD payouts
    /threat --view adversary   Multi-step LLM exploit agent
    /threat --view surface     Plain-English attack narrative
    /threat --view boundary    Auto-Mermaid trust-boundary diagram
    /threat --view spof        Single-point-of-failure counterfactual

  LLM red-teaming (one command, three modes)
    /llm                       Static scan of LLM-calling code (default)
    /llm --endpoint URL        Active red-team (30+ prompts × 7 mutations)
    /llm --mode jailbreak      Jailbreak families only (fast verdict)
    /llm --mode eval           Generate promptfoo YAML eval suite

  Posture & compliance
    /posture-management --sbom   CycloneDX 1.6 / SPDX 2.3 SBOM
    /posture-management --aibom  AI/ML BOM — models, prompts, frameworks
    /posture-management --api    API surface with auth + data classes
    /posture-management --license  License allow/deny enforcement
    /posture-management --drift  Compare two scans
    /posture-management --mttr   Findings exceeding SLA thresholds
    /security-trend            Rolling history + regression detection
    /compliance-report [nist|asvs|llm|eu-ai-act]   Auditor-ready attestation
    /compliance-fix            Route every Not-Compliant control to its fix

  Scanner engineering
    /scanner --self-test       Adversarial self-test — scanner attacks itself
    /scanner --diff            Compare two scanner versions (catches regressions)
    /scanner --baseline        Compare two scan outputs (what did this PR break?)
    /scanner --concurrency     Missed unlocks, deadlocks, fire-and-forget async
    /scanner --spec-drift      Function name vs. body intent-drift detector

  Code generation
    /generate --type tests     Failing security regression tests per finding
    /generate --type privacy   Privacy policy from detected processors
    /generate --type disaster  Incident-response playbook

  Forensics
    /archaeology --finding <id>      When did this become vulnerable?

═══════════════════════════════════════════════════════════════
🤝 BOTH LANES USE THESE
═══════════════════════════════════════════════════════════════

  Dependency depth
    /supply-chain-check                       Roll-up verdict across six dep audits
    /supply-chain-check --show pinning        Loose version ranges
    /supply-chain-check --show freshness      Stale deps
    /supply-chain-check --show alternatives   Lighter / safer replacements
    /supply-chain-check --show install-scripts  postinstall / preinstall hooks
    /supply-chain-check --show vendored       Copy-pasted third-party code
    /trim                                     deps + dead code in one pass
    /trim --what deps                         deps only
    /trim --what code                         dead code only

  Project meta
    /status                    Plugin & project health snapshot
    /help                      This command
    /find-and-fix-everything   The "I have 10 min" mode

USAGE NOTES
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
