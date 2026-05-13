# AGENTIC-SECURITY

```
NAME
       agentic-security — local-first SAST + SCA + secrets + IaC + LLMSecOps
       scanner with audit-grade suppressions, machine-readable output, and
       integrations for the security stack you already run.

SYNOPSIS
       agentic-security [--profile pro] COMMAND [ARGS] [OPTIONS]

       Claude Code slash commands (preferred interface):
       /scan [PATH] [--all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff]
       /fix [--one <id>] [--all [--severity]] [--pr [--apply]]
       /show-findings [--all|--kev|--chains|--threat-model]
       /validate-findings <finding-id>
       /explain <finding-id|CWE-N|vuln-name>
       /compliance-report [nist|asvs|pci|soc2|llm]
       /trim-dependencies [path] [--dry-run] [--include-dev]
       /posture-management [--sbom|--aibom|--api|--license|--drift|--mttr]
       /status
       /report-card
       /launch-check
       /social-media

DESCRIPTION
       agentic-security is a Claude Code plugin and standalone CLI for catching
       the security defects that AI-assisted development introduces and the
       traditional ones the AI inherits from training data. It runs locally
       (no cloud, no signup), emits SARIF + JSON + CSV every scan, and
       supports the workflow security engineers actually use: triage state,
       audit-grade suppressions, org-wide fleet scans, and custom rules.

       Coverage pillars:

         SAST        Taint analysis (regex + AST) for JS/TS, Java, Python.
         SCA         OSV + CISA KEV + EPSS, function-level reachability,
                     dep confusion, typosquat detection, deprecated
                     packages (npm, PyPI, Packagist, crates.io,
                     RubyGems, pub.dev).
         Secrets     60+ credential patterns, high-entropy heuristic,
                     allowlist-aware.
         IaC         Dockerfile, docker-compose, GitHub Actions, Kubernetes.
         LLM         OWASP LLM Top 10 (2025): prompt injection, sensitive
                     disclosure, system prompt leakage.
         MCP         Agent-tool audit for over-privileged MCP servers.
         Pipeline    GitHub Actions: floating tags, secret echoes,
                     OIDC misconfig, write-all permissions.
         Auth/AuthZ  Broken access control, IDOR, mass assignment,
                     session fixation, JWT confusion, OAuth2 PKCE.
         Container   Base-image EOL, exposed ports, runtime mode.
         Compliance  NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2,
                     OWASP LLM Top 10 (2025).
```

---

## SETUP

```
       agentic-security profile set pro
```

Flips the defaults: full taxonomy visible (CWE/CVSS/OWASP/MITRE/CAPEC),
confidence threshold lowered (≥0.3 vs. ≥0.9 in vibecoder mode), all
commands and flags accessible, SARIF + CSV written on every scan,
suppression schema upgraded to audit-grade.

Confirm with:

```
       agentic-security profile show
```

---

## COMMANDS

```
       scan [PATH]
              Full SAST + SCA + secrets + IaC sweep. PATH defaults to cwd.
              Writes findings.{json,sarif,csv} to .agentic-security/.

       fix --one <id>
              Emit the canonical patch template for one finding. The
              security-fixer subagent applies it to the affected file.

       fix --all [--critical|--high|--medium|--low]
              Batch-fix every finding at or above the severity tier.
              Cumulative: --high fixes critical + high. Default: --critical.

       fix --pr [--apply] [--branch <name>] [--severity critical|high|all]
              Bundle fixes into a feature branch and open a pull request.
              Default is dry-run; pass --apply to commit changes.

       triage list | assign | transition | trend
              Per-finding state machine. List by status, severity, or
              assignee. Trends compute MTTR + opened/closed deltas.

       org-scan --repos <list> [--workers N]
              Fleet scan. Workspace-aware (Nx, Turborepo, pnpm).
              Per-repo + rolled-up JSON output.

       rules validate
              Lint .agentic-security/rules.yml for schema errors, invalid
              regex, severity overrides, and disabled rules.

       trim-dependencies [PATH] [--dry-run] [--include-dev]
              Find installed packages never imported in source code.
              Reports per-package on-disk size and transitive dep count.
              Default is --dry-run; pass --apply to execute removals.

       digest --slack <url> | --discord <url>
              POST a structured digest payload to a Slack/Discord webhook.

       profile show | set | detect
              Persona master switch. detect uses heuristic signals
              (SECURITY.md, CI workflow named *security*, etc.).

       packs list
              List available rule packs (owasp-top-10, cwe-top-25,
              llm-security, supply-chain).
```

---

## OPTIONS

```
       --format FORMAT
              Output: cli, json, md, sarif, csv, html, cyclonedx, spdx,
              pbom, aibom, aibom-md.

       --columns SET
              Pro-mode column profile for the cli renderer:
                standard  CWE + CVSS + OWASP
                mitre     ATT&CK technique + tactic
                capec     CAPEC attack-pattern number
                owasp     OWASP Top 10 category

       --confidence N
              Override the per-profile confidence threshold (0.0–1.0).

       --firehose
              Show ALL findings (ignore confidence threshold). Useful for
              audits, debugging, or feeding a downstream filter.

       --honest
              High-confidence-only view (≥0.9). Strict subset of
              --firehose.

       --severity {critical|high|medium|low|info}
              Exit-code threshold for CI gating.

       --only {sast|sca|secrets}
              Limit to one pillar.

       --sca-reachable-only
              Drop SCA findings where the vulnerable function is not
              reachable from any route handler.

       --ingest-sarif <glob>
              Merge external SARIF (gitleaks, Trivy, Checkov, Bandit)
              into this scan. Findings dedupe by fingerprint.

       --scorecard
              Enrich SCA components with OSSF Scorecard scores.

       --no-network
              Skip OSV / registry / EPSS / KEV queries (offline mode).

       --pack <name>[,<name>...]
              Focus on a CWE allowlist: owasp-top-10, cwe-top-25,
              llm-security, supply-chain. Multiple packs union their sets.

       --output FILE
              Write the rendered report to FILE.
```

---

## OUTPUT FILES

Every scan writes to `.agentic-security/` in the project root:

```
       findings.json    Normalized findings, programmable schema.
       findings.sarif   SARIF 2.1.0 for GitHub Security tab, GitLab, etc.
       findings.csv     Spreadsheet / BigQuery / executive reports.
       last-scan.json   Live state consumed by /fix, /show-findings,
                        /posture-management.
       suppressions.yml Audit-grade suppression records.
       rules.yml        Custom rules, severity overrides, version pins.
       triage.json      Triage state machine.
       integrations.yml Webhooks + API tokens (gitignored).
       profile.yml      Persona profile (pro|vibecoder).
       streak.json      Security grade history.
```

---

## EXIT STATUS

```
       0   Clean — no findings at or above --severity
       1   Findings at low or medium severity
       2   Findings at high severity
       3   Findings at critical severity
       4   Engine error (parse failure, IO, malformed config)
```

CI gating example — blocks the pipeline on any critical finding:

```bash
       agentic-security scan . --severity critical
```

---

## SUPPRESSIONS

Suppressions are structured, reviewed, and auditable. Stored in
`.agentic-security/suppressions.yml`:

```yaml
       - finding_id: c14d...
         file: lib/admin.js
         line: 47
         cwe: CWE-798
         rule_version: 0.16.0
         reason: |
           Hardcoded credential is in a test fixture, not a production
           code path. Verified via call-graph analysis (no production
           caller).
         justification_signed_by: alice@team.example.com
         reviewer: bob@team.example.com
         reviewed_at: 2026-05-10T14:30:00Z
         expires_at: 2026-11-10T00:00:00Z
         ticket: SEC-1247
```

Validation rules:
- signer must differ from reviewer (two-person rule)
- expires_at must be in the future
- critical-severity findings cannot be suppressed without `--accept-critical`
- rule_version is pinned: a newer scanner re-surfaces the finding unless
  the suppression is re-approved

Lint with:

```
       agentic-security rules validate
```

---

## TRIAGE

State machine: `open` → `in-progress` → (`fixed` | `wont-fix` | `false-positive`).
Findings auto-transition to `fixed` when the scanner no longer detects them.

```
       agentic-security triage list --status open --severity critical
       agentic-security triage assign SEC-0042 alice@team
       agentic-security triage transition SEC-0042 in-progress
       agentic-security triage transition SEC-0042 fixed \
              --comment "Patched in PR #94"
       agentic-security triage trend --since 30
```

`trend` output:

```
       Opened:  47
       Closed:  52
       Net:     -5 (improving)
       Open:    critical=2 high=8 medium=15 low=4
       MTTR median: 3.2 days
```

State is persisted to `.agentic-security/triage.json`.

---

## CUSTOM RULES

`.agentic-security/rules.yml`:

```yaml
       version: 0.16.0

       severityOverrides:
         "Hardcoded Credential Check": medium

       disable:
         - "Verify x-powered-by Header is Disabled"

       custom:
         - id: internal-auth-bypass
           regex: 'if\s*\(\s*request\.headers\[\s*[''"]x-internal-bypass[''"]'
           vuln: "Internal Auth Bypass Header"
           severity: critical
           cwe: CWE-287
           description: "x-internal-bypass is debug-only. Never in prod."
           fix: "Remove the x-internal-bypass header check."
```

---

## INTEGRATIONS

Configuration in `.agentic-security/integrations.yml` (gitignored).

```
       Jira / ServiceNow
              Body builders produce issue payloads; pipe to your
              existing client.

       GitHub Security tab / GitLab
              SARIF auto-written every scan. Upload via
              github/codeql-action/upload-sarif@v3.

       Slack / Discord
              Webhook digest with critical/high/medium counts +
              top 3 findings.

       SIEM (Splunk / Datadog / Elastic)
              One JSON event per finding, with source_attribution and
              rule_version for correlation.
```

---

## CI/CD

Single-command CI runner (auto-detects PR base ref):

```bash
       npx @clearcapabilities/agentic-security-scanner ci . --fail-on critical
```

Raw scan with SARIF upload to GitHub Security tab:

```yaml
       - uses: actions/checkout@v4
       - uses: actions/setup-node@v4
         with: { node-version: '20' }
       - run: |
           npx @clearcapabilities/agentic-security-scanner scan . \
             --format sarif --output security.sarif
       - uses: github/codeql-action/upload-sarif@v3
         with: { sarif_file: security.sarif }
```

Pre-commit framework hook (`.pre-commit-config.yaml`):

```yaml
       - repo: https://github.com/clearcapabilities/agentic-security
         rev: v0.25.0
         hooks:
           - id: agentic-security
```

Runs `agentic-security ci --baseline HEAD --fail-on high` against
staged changes and blocks the commit on any high or critical finding.

Rule packs for focused scans:

```bash
       agentic-security scan --pack owasp-top-10 .
       agentic-security scan --pack cwe-top-25 .
       agentic-security scan --pack llm-security .
       agentic-security scan --pack supply-chain .
       agentic-security packs list
```

---

## ENVIRONMENT

```
       AGENTIC_SECURITY_OFFLINE=1
              Skip OSV / EPSS / KEV / Scorecard fetches.

       AGENTIC_SECURITY_SCORECARD=1
              Enable OSSF Scorecard enrichment (outbound API calls).

       AGENTIC_SECURITY_POC=1
              Demote findings the engine cannot generate a PoC for.

       DEBUG_BENCH_FILTER=1
              Verbose logging for the benchmark category filter.
```

---

## COMPLIANCE

Framework attestations (Claude Code slash commands):

```
       /compliance-report nist    NIST AI 600-1 (122 GenAI controls)
       /compliance-report asvs    OWASP ASVS Level 1+2
       /compliance-report pci     PCI-DSS 4.0
       /compliance-report soc2    SOC 2 Common Criteria CC6–CC9
       /compliance-report llm     OWASP LLM Top 10 (2025) — 10 LLM/GenAI risk controls
```

Bill of materials formats:

```bash
       agentic-security scan --format cyclonedx     # CycloneDX 1.6 SBOM
       agentic-security scan --format spdx          # SPDX 2.3
       agentic-security scan --format aibom         # CycloneDX 1.7 ML-BOM
       agentic-security scan --format pbom          # Pipeline BOM
```

Posture management artifacts:

```
       /posture-management --sbom           CycloneDX 1.6 or SPDX 2.3
       /posture-management --aibom          CycloneDX 1.7 ML-BOM (AI components)
       /posture-management --api            API surface map (md/json/openapi)
       /posture-management --license        License allow/deny policy enforcement
       /posture-management --drift          Diff two scan snapshots
       /posture-management --mttr           SLA breach report
```

---

## SEE ALSO

```
       commands/            Slash-command definitions for the Claude Code plugin.
       agents/              Sub-agent system-prompt definitions.
       scripts/             Compliance helper scripts (NIST, SOC 2, PCI-DSS, OWASP ASVS).
       .claude-plugin/      Plugin manifest.
       LICENSE              Full license terms.
```

---

## AUTHOR

Built by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
Maintainer: Ross Young <ross@clearcapabilities.com>.

---

## BUGS

Report at <https://github.com/clearcapabilities/agentic-security/issues>.

---

---

# TUTORIAL

The following exercises walk through the tool from first scan to auditor-ready
compliance evidence. Work through them in order; each exercise builds on the
state left by the previous one.

---

## Exercise 1 — First scan

**Goal:** run a full scan, understand the output, and know what files were
written.

```
/scan --all
```

Or from the CLI:

```bash
agentic-security scan .
```

**What to look for:**

- The one-line verdict at the top: `SAFE TO DEPLOY` (green) or `NOT SAFE` (red).
- The severity breakdown: `critical=N high=N medium=N low=N`.
- The three output files written to `.agentic-security/`:
  - `findings.json` — full machine-readable results
  - `findings.sarif` — for GitHub / GitLab Security tabs
  - `findings.csv` — for spreadsheet or executive review

**Checkpoint:** open `.agentic-security/findings.json` and confirm it has a
`findings` array. Note one finding ID — you'll use it in Exercise 3.

---

## Exercise 2 — Focused scans

Each pillar can be run independently. Run each of these and compare output.

**Dependency CVE audit only:**

```
/scan --sca
```

Backed by OSV.dev. Look for `kev: true` entries — these are on the CISA Known
CISA KEV catalog and should be treated as P0.

**Secrets sweep:**

```
/scan --secrets
```

Covers 60+ provider patterns (AWS, GCP, GitHub, Stripe, etc.) and high-entropy
heuristics. Any hit: rotate immediately, move to a secrets manager, audit git
history with `git log -S <value>`.

**Auth/AuthZ deep audit:**

```
/scan --authz
```

Covers JWT algorithm confusion, hardcoded JWT secrets, missing `algorithms:[]`
constraint, OAuth2 PKCE absent on public clients, `redirect_uri` from request
without allowlist, session fixation, multi-tenant queries missing `tenantId`.

**MCP server audit:**

```
/scan --mcp
```

Reads `claude_desktop_config.json`, `.mcp.json`, `mcp_servers.json`. Flags
untrusted install vectors (`curl | sh`), hardcoded API keys in `env:` blocks,
filesystem servers granted `/` or `$HOME`, dangerous capability names.

**GitHub Actions pipeline audit:**

```
/scan --pipeline
```

Finds floating tags (`@latest`, `@main`), secret echoes, `write-all`
permissions, OIDC misconfigurations, `github.event.*` script injection.
Add `--format pbom` to emit a Pipeline Bill of Materials.

**Business-logic review:**

```
/scan --logic
```

Invokes the `security-logic-reviewer` subagent on route handlers from the last
scan inventory. Finds broken authorization tier checks, race conditions,
state-machine bypasses. Run `/scan --all` first to populate the route inventory.

**Diff review (before merging a branch):**

```
/scan --diff
/scan --diff --since main
```

Scores the git diff by architectural risk. Risk levels:
- `critical` — auth removed, new shell call → run `/validate-findings` + `/fix --one`
- `high` → run `/validate-findings`
- `medium`/`low`/`none` → safe to merge

---

## Exercise 3 — Understand a finding

Use the finding ID you noted in Exercise 1.

```
/explain <finding-id>
```

You can also explain by CWE or by name fragment:

```
/explain CWE-89
/explain SQL Injection
```

The output is a plain-English card with four sections:
1. What this means
2. How an attacker abuses it
3. Worst case if not fixed
4. How to fix it

**Advanced:** compare the plain-English explanation to the raw finding fields:

```bash
jq '.findings[] | select(.id == "<your-id>")' .agentic-security/findings.json
```

Fields to understand: `cwe`, `cvss`, `toxicityScore`, `owaspCategory`,
`attackTechnique` (MITRE ATT&CK), `capecId`, `kev`, `epss`.

---

## Exercise 4 — Validate before fixing (PoC workflow)

Do not fix a finding the team cannot reproduce. This exercise generates a
concrete proof-of-concept payload first.

```
/validate-findings <finding-id>
```

Three possible verdicts:

| Verdict | Meaning | Next step |
|---------|---------|-----------|
| `TP_CONFIRMED` | Real. Payload + regression test produced. | Write the test to `tests/security/`, then `/fix --one <id>`. |
| `PROBABLE_FP` | No viable attack path found. Suppression entry offered. | Review the blocker; apply suppression if you agree. |
| `INDETERMINATE` | Cannot determine. | Apply `/fix --one <id>` if you accept residual risk. |

If the verdict is `TP_CONFIRMED`, the subagent offers to write the regression
test. Accept. The test lives in CI and re-fires if the bug comes back.

---

## Exercise 5 — Fix a single finding

```
/fix --one <finding-id>
```

The `security-fixer` subagent reads the affected file, applies the canonical fix
template adapted to the surrounding code, and runs the project test suite. It
will not declare success until:

1. A re-scan of the file no longer reproduces the finding.
2. Existing tests still pass.

**Verify by re-scanning:**

```
/scan --all
```

The finding should no longer appear.

---

## Exercise 6 — Batch-fix by severity tier

For a project with accumulated findings, fix all critical and high findings
in one pass:

```
/fix --all --high
```

Behavior:
- Dispatches `security-fixer` per finding, in sequence (not parallel).
- Order: critical first, then high, then by `toxicityScore` DESC within each tier.
- After each fix, re-scans the affected file.
- If tests fail, stops and reports — does not auto-revert.

**Before running:** ensure your git tree is clean. The batch cannot be safely
rolled back with uncommitted changes mixed in.

```bash
git status   # must be clean
/fix --all --high
```

Final summary line:

```
Applied N fixes, M skipped (tests failed), K regressions introduced.
```

---

## Exercise 7 — Bundle fixes into a pull request

```
/fix --pr --severity high
```

Default is dry-run — it prints the bundle plan and waits for confirmation.
To actually apply:

```
/fix --pr --severity high --apply
```

Workflow:
1. Verifies clean working tree, `gh auth status`, `last-scan.json` exists.
2. Filters findings by severity, groups by shared helper.
3. Creates branch `security/auto-fix-<date>`.
4. For each finding: invokes `security-fixer`, runs tests.
   - Tests pass → commits `security: fix <vuln> in <file>:<line> (finding <id>)`.
   - Tests fail → reverts the file, labels finding `INDETERMINATE`, continues.
5. Pushes branch and opens PR via `gh pr create`.

---

## Exercise 8 — Triage workflow

Triage is the state machine that turns a raw scan result into a managed backlog.

**List open critical findings:**

```bash
agentic-security triage list --status open --severity critical
```

**Assign a finding to an engineer:**

```bash
agentic-security triage assign SEC-0042 alice@team
```

**Move through the state machine:**

```bash
agentic-security triage transition SEC-0042 in-progress
agentic-security triage transition SEC-0042 fixed --comment "Patched in PR #94"
```

**Review velocity over the last 30 days:**

```bash
agentic-security triage trend --since 30
```

Target state: `Net` is negative (more closed than opened) and `MTTR median`
is inside your SLA thresholds.

---

## Exercise 9 — False-positive suppression

**Review findings in the HTML report:**

```
/show-findings --all
```

Opens a self-contained HTML report in the browser with severity charts,
a filterable findings list, per-finding code evidence, and fix templates.

**Triage and suppress false positives inline:**

```
/show-findings
```

For each finding, the command reads ±20 lines around the flagged line and
evaluates true positive vs. false positive. Confirmed FPs are appended to
`.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "Hardcoded Credential Check"
    files: ["test/fixtures/mock-credentials.js"]
    reason: "Test fixture; no production caller. Verified via call-graph."
```

**Validate the suppression file:**

```bash
agentic-security rules validate
```

---

## Exercise 10 — Custom rules

Add a project-specific rule that the built-in patterns cannot cover.

Edit (or create) `.agentic-security/rules.yml`:

```yaml
version: 0.16.0

custom:
  - id: internal-auth-bypass
    regex: 'if\s*\(\s*request\.headers\[\s*[''"]x-internal-bypass[''"]'
    vuln: "Internal Auth Bypass Header"
    severity: critical
    cwe: CWE-287
    description: "x-internal-bypass is a debug header. Never deploy to prod."
    fix: "Remove the x-internal-bypass header check entirely."
```

Validate:

```bash
agentic-security rules validate
```

Re-scan:

```
/scan --all
```

Verify the custom rule fires against any file that matches the pattern.

**Override a built-in severity:**

```yaml
severityOverrides:
  "Hardcoded Credential Check": medium
```

**Disable a noisy rule entirely:**

```yaml
disable:
  - "Verify x-powered-by Header is Disabled"
```

---

## Exercise 11 — Threat modelling from scan results

View findings mapped to OWASP LLM Top 10 (2025):

```
/show-findings --threat-model --llm
```

View findings mapped to STRIDE:

```
/show-findings --threat-model --stride
```

The STRIDE table shows which categories are under-covered. A blank row means
the scanner found no matching findings — good news, or a signal to look harder.

**Find multi-step attack chains:**

```
/show-findings --chains --severity high
```

The `security-chain-synthesizer` subagent combines individual findings into
multi-step chains (e.g., IDOR + missing auth = account takeover). For each
chain it identifies:
- The weakest link (the one fix that breaks the whole chain)
- The full attack path narrative
- Which findings to pass to `/validate-findings` for validation

**List only actively weaponized CVEs:**

```
/show-findings --kev
```

Any `kevRansomware: true` entry means CISA has linked the CVE to active
ransomware campaigns. Treat as P0.

---

## Exercise 12 — Posture management: SBOM and AI-BOM

**Software Bill of Materials (CycloneDX 1.6):**

```
/posture-management --sbom
```

Every component includes `purl`, license, scope, CVE IDs, CVSS vectors, EPSS
scores, and `agentic-security:functionReachable` annotations. Required for
FedRAMP, EU CRA, NIST SSDF, EO 14028.

**SPDX 2.3 format:**

```
/posture-management --sbom --format spdx --output sbom.spdx.json
```

**AI/ML Bill of Materials (CycloneDX 1.7 ML-BOM):**

```
/posture-management --aibom
```

Captures every model, prompt template, inference framework, and vector store.
Required by EU AI Act and enterprise security questionnaires.

**API surface map:**

```
/posture-management --api --format openapi --output api-surface.json
```

Each endpoint is annotated with auth status (locked / warning) and data
classifications (PII / PHI / PCI / Confidential).

**License policy enforcement:**

```
/posture-management --license --init
```

`--init` creates a default policy at `.agentic-security/license-policy.yml`
(MIT, Apache-2.0, BSD-*, ISC allowed; GPL-3.0, AGPL-3.0, SSPL denied;
LGPL, MPL, EPL flagged for review). Edit to match your org policy, then:

```
/posture-management --license
```

Violations appear as `kind: 'license'` findings: `high` for denied licenses
in closed-source projects, `low` for review-required or missing entries.

---

## Exercise 13 — Drift analysis and SLA tracking

**Capture a baseline snapshot:**

```bash
cp .agentic-security/last-scan.json .agentic-security/scan-baseline.json
```

Make some code changes, then re-scan:

```
/scan --all
```

**Compare the two snapshots:**

```
/posture-management --drift --from .agentic-security/scan-baseline.json
```

The diff report shows:
- Auth boundaries lost
- New endpoints added
- New CVEs introduced
- Severity deltas
- Newly exposed data classes

**SLA breach report:**

```
/posture-management --mttr
```

Default thresholds: critical=7d, high=30d, medium=60d, low=90d. Override:

```
/posture-management --mttr --sla-days '{"critical":3,"high":14,"medium":45,"low":90}'
```

Any finding past its SLA threshold appears in the breach list with its age
in days. This is the artifact that proves SLA tracking to an auditor.

---

## Exercise 14 — NIST AI 600-1 Compliance Evidence

NIST AI 600-1 defines 122 code-testable controls for Generative AI systems.
This exercise walks through generating an auditor-ready attestation package.

**Step 1 — Run the compliance scan:**

```
/compliance-report nist .
```

The Python scanner at `scripts/nist-compliance/scan.py` evaluates the codebase
against all 122 controls and writes three evidence files:

```
nist-ai-600-1-attestation.md    Human-readable attestation for auditors
nist-ai-600-1-attestation.csv   Spreadsheet for control-by-control review
nist-ai-600-1-attestation.json  Machine-readable for CI gating
```

**Step 2 — Interpret the attestation table:**

Each row in the attestation covers one NIST AI 600-1 measure. Columns:

| Column | Meaning |
|--------|---------|
| Control ID | e.g., `GV-1.1`, `MS-2.5` |
| Status | PASS / FAIL / PARTIAL / NOT-APPLICABLE |
| Evidence | File paths, line numbers, or "not found" |
| Finding IDs | Cross-references to scanner findings |
| Remediation | Concrete code change needed if FAIL/PARTIAL |

**Step 3 — Extend the evidence rules:**

The scanner's vocabulary is defined in `scripts/nist-compliance/evidence-rules.json`.
If your project uses project-specific naming conventions, add them here so the
scanner recognises your controls:

```json
{
  "GV-1.1": {
    "description": "AI risk governance policy documented",
    "patterns": [
      "ai-risk-policy",
      "model-governance",
      "YOUR_CUSTOM_POLICY_FILE"
    ]
  }
}
```

Then re-run:

```
/compliance-report nist .
```

**Step 4 — Collect supporting posture artifacts:**

NIST AI 600-1 auditors typically request corroborating evidence beyond the
attestation. Generate the full evidence package:

```bash
# AI Bill of Materials (maps to MS-2.x model inventory controls)
/posture-management --aibom --output nist-evidence/aibom.md

# Software Bill of Materials (maps to MS-2.x supply-chain controls)
/posture-management --sbom --format cyclonedx --output nist-evidence/sbom.json

# API surface map (maps to MG-2.x access controls)
/posture-management --api --format openapi --output nist-evidence/api-surface.json

# SLA tracking report (maps to MG-3.x incident response controls)
/posture-management --mttr --output nist-evidence/sla-report.md

# Secrets scan (maps to GV-6.x credential management controls)
/scan --secrets

# Pipeline integrity audit (maps to MS-2.x supply-chain controls)
/scan --pipeline --format pbom --output nist-evidence/pipeline-bom.json
```

**Step 5 — Review the LLM-specific controls:**

NIST AI 600-1 includes controls that map directly to the OWASP LLM Top 10.
After running `/compliance-report nist`, cross-check with:

```
/show-findings --threat-model --llm
```

The LLM Top 10 coverage map shows which categories have open findings. Any
`LLM01` (Prompt Injection) or `LLM06` (Excessive Agency) findings require
remediation before a NIST AI 600-1 audit will pass.

**Step 6 — Gate CI on the attestation:**

Add a CI job that fails if any critical NIST control is FAIL:

```yaml
- name: NIST AI 600-1 gate
  run: |
    python3 scripts/nist-compliance/scan.py . --format json \
      --output nist-attestation.json
    python3 -c "
    import json, sys
    a = json.load(open('nist-attestation.json'))
    fails = [c for c in a['controls'] if c['status'] == 'FAIL' and c['severity'] == 'critical']
    if fails:
        print(f'{len(fails)} critical NIST AI 600-1 controls failing')
        sys.exit(1)
    "
```

**Full evidence package summary:**

```
nist-ai-600-1-attestation.md    Primary attestation (hand to auditor)
nist-ai-600-1-attestation.csv   Control-by-control spreadsheet
nist-ai-600-1-attestation.json  Machine-readable (CI gate input)
nist-evidence/aibom.md          AI/ML component inventory (MS-2.x)
nist-evidence/sbom.json         Software supply chain (MS-2.x)
nist-evidence/api-surface.json  Access surface documentation (MG-2.x)
nist-evidence/sla-report.md     Incident response SLA tracking (MG-3.x)
nist-evidence/pipeline-bom.json CI/CD integrity (MS-2.x)
findings.sarif                  SAST/SCA/secrets findings (GV-6.x)
```

---

## Exercise 15 — Other compliance frameworks

**OWASP ASVS Level 1+2:**

```
/compliance-report asvs . --format md --output owasp-asvs-attestation.md
```

Multi-signal evidence model: manifest → import → path → code/config/doc
terms, with negation filter. Extend controls in
`scripts/owasp-asvs/evidence-rules.json`.

**PCI-DSS 4.0:**

```
/compliance-report pci . --format csv --output pci-dss-attestation.csv
```

Covers strong cryptography, TLS, MFA, audit logging, account lockout,
vulnerability scanning automation. Pure-organisational controls are out
of scope by design.

**SOC 2 Common Criteria (CC6–CC9):**

```
/compliance-report soc2 . --format md --output soc2-attestation.md
```

For a full SOC 2 vendor questionnaire, run the supporting artifact set:

```bash
/posture-management --sbom --format cyclonedx    # CC9.2 — vendor risk
/scan --pipeline --format pbom                   # CC8.1 — change management
/posture-management --mttr                       # CC7.x — SLA tracking
/posture-management --api --format openapi       # CC6.x — access surface
/compliance-report nist                          # if product uses GenAI
```

**OWASP LLM Top 10 (2025):**

```
/compliance-report llm . --format md --output owasp-llm-top10-attestation.md
```

Aliases: `owasp-llm`, `owasp-llm-top10`, `llm-top-10`.

Scans for evidence of mitigations across all 10 LLM/GenAI risks:

| Control | Risk |
|---------|------|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

Every Not Compliant or Partial control includes a remediation section
with concrete, actionable steps — specific libraries to add, patterns to
implement, and architectural decisions to make. This differentiates it
from the other frameworks, which only report compliance status.

**Extend the signal vocabulary:**

Edit `scripts/owasp-llm-top10/evidence-rules.json`. Each control has
`manifest_deps`, `imports`, `paths`, and `terms` arrays. Add your
project's naming conventions so the scanner recognises your mitigations:

```json
{
  "id": "LLM01",
  "title": "...",
  "terms": [
    "sanitizePrompt",
    "YOUR_CUSTOM_GUARD_CLASS"
  ]
}
```

**CI gate on LLM Top 10:**

```bash
python3 scripts/owasp-llm-top10/scan.py . --format json \
  --output llm-attestation.json
python3 -c "
import json, sys
a = json.load(open('llm-attestation.json'))
fails = [c for c in a['controls'] if c['status'] == 'Not Compliant']
if fails:
    print(f'{len(fails)} LLM Top 10 controls Not Compliant:')
    for f in fails: print(f'  {f[\"id\"]}: {f[\"title\"]}')
    sys.exit(1)
"
```

---

## Exercise 16 — Org-wide fleet scan

Scan multiple repos in parallel and roll up results:

```bash
agentic-security org-scan \
  --repos /repos/api,/repos/web,/repos/admin \
  --workers 8
```

Output:
- Per-repo `findings.json` in each repo's `.agentic-security/`
- Rolled-up `org-scan-summary.json` in the working directory

Pipe critical findings from all repos to a Jira opener:

```bash
jq -s '[.[].findings[] | select(.severity=="critical")]' \
  /repos/*/agentic-security/findings.json | \
  ./scripts/open-jira-issues.sh
```

---

## Exercise 17 — Advanced output and integrations

**MITRE ATT&CK column view:**

```bash
agentic-security scan --columns mitre
```

**CAPEC attack-pattern view:**

```bash
agentic-security scan --columns capec
```

**Merge external SARIF from other tools:**

```bash
agentic-security scan . \
  --ingest-sarif 'reports/*.sarif' \
  --format sarif --output merged.sarif
```

Findings dedupe by fingerprint. Useful for combining output from
Trivy, Checkov, Bandit, or gitleaks into one unified report.

**Enrich SCA with OSSF Scorecard:**

```bash
AGENTIC_SECURITY_SCORECARD=1 agentic-security scan --scorecard .
```

Adds an OSSF Scorecard score to each SCA component. Useful for
identifying unmaintained dependencies before a CVE is assigned.

**Slack digest:**

```bash
agentic-security digest --slack https://hooks.slack.com/services/...
```

Posts a structured payload: critical/high/medium counts + top 3 findings
with file:line references.

**CI gate with custom exit code handling:**

```bash
agentic-security scan . --severity high
STATUS=$?
case $STATUS in
  0) echo "Clean" ;;
  1) echo "Low/medium findings — review before next sprint" ;;
  2) echo "High findings — block merge" && exit 1 ;;
  3) echo "Critical findings — block merge" && exit 1 ;;
  4) echo "Engine error" && exit 1 ;;
esac
```

---

## Exercise 18 — Status and health snapshot

```
/status
```

Prints a one-screen project and plugin health snapshot:
- Plugin version
- Last scan timestamp and finding counts
- Cache size (OSV/KEV data)
- Hook activation status
- Active suppression rules

```
/report-card
```

Single letter grade (A–F) with one sentence explaining why and one
concrete next action. Designed for a 10-second morning check.

```
/launch-check
```

Pre-deploy checklist of the 10 things developers most commonly miss
before going live. Each item is green (pass), yellow (warning), or
red (block) with a one-line explanation.

---

## Quick reference

```
First scan:          /scan --all
CVE audit:           /scan --sca
Secrets:             /scan --secrets
Auth deep-dive:      /scan --authz
MCP audit:           /scan --mcp
Pipeline audit:      /scan --pipeline
Logic review:        /scan --logic
Diff review:         /scan --diff --since main

Explain a finding:   /explain <id|CWE-N|name>
Validate it's real:  /validate-findings <finding-id>
Fix one:             /fix --one <finding-id>
Fix by tier:         /fix --all --high
Fix as PR:           /fix --pr --severity high --apply

HTML report:         /show-findings --all
Weaponized CVEs:     /show-findings --kev
Attack chains:      /show-findings --chains
Threat model:        /show-findings --threat-model --llm

Trim bloat deps:     /trim-dependencies

SBOM:                /posture-management --sbom
AI-BOM:              /posture-management --aibom
API surface:         /posture-management --api
License policy:      /posture-management --license
Drift:               /posture-management --drift
SLA report:          /posture-management --mttr

NIST AI 600-1:       /compliance-report nist
OWASP ASVS:          /compliance-report asvs
PCI-DSS 4.0:         /compliance-report pci
SOC 2:               /compliance-report soc2
OWASP LLM Top 10:    /compliance-report llm

Health check:        /status
Grade:               /report-card
Pre-deploy:          /launch-check
```

---

*agentic-security · created by [ClearCapabilities.Com](https://clearcapabilities.com)*
