# AGENTIC-SECURITY(1)

```
NAME
       agentic-security — local-first SAST + SCA + secrets + IaC + LLM-security
       scanner with audit-grade suppressions, machine-readable output, and
       integrations for the security stack you already run.

SYNOPSIS
       agentic-security [--profile pro] COMMAND [ARGS] [OPTIONS]

DESCRIPTION
       agentic-security is a Claude Code plugin and standalone CLI for catching
       the security defects that AI-assisted development introduces and the
       traditional ones the AI inherits from training data. It runs locally
       (no cloud, no signup), emits SARIF + JSON + CSV every scan, and
       supports the workflow security engineers actually use: triage state,
       audit-grade suppressions, org-wide fleet scans, and custom rules.

       This document covers the pro mode. For the simplified vibecoder
       surface, see for-vibecoders(7).
```

---

## SETUP

```
       agentic-security profile set pro
```

Flips the defaults: full taxonomy visible (CWE/CVSS/OWASP/MITRE/CAPEC), confidence threshold lowered (≥0.3 vs. ≥0.9 in vibecoder), all 13 commands and their flags accessible, SARIF + CSV written on every scan, suppression schema upgraded to audit-grade.

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

       triage list | assign | transition | trend
              Per-finding state machine. List by status, severity, or
              assignee. Trends compute MTTR + opened/closed deltas.

       org-scan --repos <list>
              Fleet scan. Workspace-aware (Nx, Turborepo, pnpm). Per-repo +
              rolled-up JSON output.

       rules validate
              Lint .agentic-security/rules.yml for schema errors, invalid
              regex, severity overrides, and disabled rules.

       fix --one <id>
              Emit the canonical patch template for one finding. The
              security-fixer subagent applies it to the file.

       fix --all [--critical|--high|--medium|--low]
              Batch-fix every finding at or above the severity tier.

       fix --pr [--apply]
              Bundle fixes into a feature branch and open a pull request.

       digest --slack <url> | --discord <url>
              POST a structured digest payload to a Slack/Discord webhook.

       profile show | set | detect
              Persona master switch. detect uses heuristic signals
              (SECURITY.md, CI workflow named *security*, etc.).
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
                mitre     ATT&CK technique
                capec     CAPEC pattern number
                owasp     OWASP A03:2021 etc.

       --confidence N
              Override the per-profile confidence threshold (0.0–1.0).

       --firehose
              Show ALL findings (ignore confidence threshold). Useful for
              audits, debugging, or feeding a downstream filter.

       --honest
              High-confidence-only view (≥0.9). Strict subset of --firehose.

       --severity {critical|high|medium|low|info}
              Exit-code threshold for CI gating.

       --only {sast|sca|secrets}
              Limit to one pillar.

       --sca-reachable-only
              Drop SCA findings where the vulnerable function isn't
              reachable from any route handler.

       --ingest-sarif <glob>
              Merge external SARIF (Semgrep, gitleaks, Trivy, Checkov,
              Bandit) into this scan. Findings dedupe by fingerprint.

       --scorecard
              Enrich SCA components with OSSF Scorecard scores.

       --no-network
              Skip OSV / registry / EPSS / KEV queries (offline mode).

       --output FILE
              Write the rendered report to FILE.
```

---

## OUTPUT FILES

Every scan writes to `.agentic-security/` in the project:

```
       findings.json    Normalized findings, programmable schema.
       findings.sarif   SARIF 2.1.0 for GitHub Security tab, GitLab, etc.
       findings.csv     Spreadsheet / BigQuery / executive reports.
       last-scan.json   Used by /fix --one, /show-findings, /security-posture.
       suppressions.yml Audit-grade suppressions (see SUPPRESSIONS).
       rules.yml        Custom rules, severity overrides, version pins.
       triage.json      Triage state machine (see TRIAGE).
       integrations.yml Webhooks + API tokens (gitignored).
       profile.yml      Persona profile (pro|vibecoder).
       streak.json      Streak / grade history.
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

CI gating example:

```
       agentic-security scan . --severity critical
```

Exits non-zero if any critical finding exists. Hook into `npm test`, `lint-staged`, GitHub Actions, etc.

---

## SUPPRESSIONS

Pro suppressions are structured, reviewed, and auditable. Stored in `.agentic-security/suppressions.yml`:

```yaml
       - finding_id: c14d...
         file: lib/admin.js
         line: 47
         cwe: CWE-798
         rule_version: 0.16.0
         reason: |
           Hardcoded credential is in a test fixture, not production
           code path. Verified via call-graph analysis (no production
           caller).
         justification_signed_by: alice@team.example.com
         reviewer: bob@team.example.com
         reviewed_at: 2026-05-10T14:30:00Z
         expires_at: 2026-11-10T00:00:00Z
         ticket: SEC-1247
```

Each entry must specify finding_id, file, reason, justification_signed_by, reviewer, expires_at. Validation rules:

- signer must differ from reviewer (two-person rule)
- expires_at must be in the future
- critical-severity findings cannot be suppressed without `--accept-critical`
- rule_version is pinned: a newer scanner version re-surfaces the finding unless the suppression is re-approved

Lint with:

```
       agentic-security rules validate
```

---

## TRIAGE

State machine: `open` → `in-progress` → (`fixed` | `wont-fix` | `false-positive`). Findings auto-transition to `fixed` when the scanner no longer detects them.

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

State persisted to `.agentic-security/triage.json`.

---

## CUSTOM RULES

`.agentic-security/rules.yml`:

```yaml
       version: 0.16.0           # pin for reproducibility

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

Two options. The first is a single-command CI runner; the second is the raw scan with SARIF upload.

```bash
       # ci: auto-detects PR base ref, writes findings.{json,sarif,junit.xml},
       #     applies the --fail-on policy. Exits 0 (pass) or 1 (fail).
       npx @clearcapabilities/agentic-security-scanner ci . --fail-on critical
```

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

The `bench.yml` workflow at `.github/workflows/bench.yml` shows the pattern used by the project itself: per-app F1 floor enforcement that blocks regressions.

### Pre-commit framework hook

Add to `.pre-commit-config.yaml`:

```yaml
       - repo: https://github.com/clearcapabilities/agentic-security
         rev: v0.22.0
         hooks:
           - id: agentic-security
```

The hook runs `agentic-security ci --baseline HEAD --fail-on high` against the staged changes and blocks the commit on any high or critical finding.

### Rule packs

Focus a scan on a curated CWE allowlist with `--pack`:

```bash
       agentic-security scan --pack owasp-top-10 .
       agentic-security scan --pack cwe-top-25 .
       agentic-security scan --pack llm-security .
       agentic-security scan --pack supply-chain .
       agentic-security packs list
```

Multiple packs union their CWE sets — `--pack owasp-top-10,llm-security` keeps findings in either list.

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

## COVERAGE

```
       Pillar         What we scan
       ─────────────────────────────────────────────────────────────
       SAST           Taint analysis (regex + AST for JS/TS), Java
                      rule pack, Python helpers.
       SCA            OSV + CISA KEV + EPSS, function-level
                      reachability, dep confusion, typosquat.
       Secrets        50+ credential patterns, high-entropy heuristic,
                      allowlist-aware.
       IaC            Dockerfile, docker-compose, GitHub Actions,
                      Kubernetes manifests.
       LLM            OWASP LLM Top 10 (2025): prompt injection,
                      sensitive disclosure, system prompt leakage.
       MCP            Agent-tool audit for over-privileged MCP servers.
       Pipeline       GitHub Actions integrity: floating tags,
                      secret echoes, OIDC misconfig.
       Auth/AuthZ     Broken access control, IDOR, mass assignment,
                      session fixation.
       Container      Base-image EOL, exposed ports, runtime mode.
       Compliance     NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2.
```

---

## BENCHMARKS

The engine is evaluated against six corpora. Floors are enforced in CI (`.github/workflows/bench.yml`):

```
       Benchmark                     F1      Notes
       ─────────────────────────────────────────────────────────────
       Synthetic (in-tree)           100%    strict
       OWASP Benchmark (Java)        96.7%   1415 tests
       NIST SARD Juliet (Java)       100%    28k tests, 19 CWEs
       OWASP Juice Shop (TS)         100%    strict
       Snyk Goof (JS)                100%    strict
       OWASP NodeGoat (JS)           100%    strict
```

Methodology: `bench-realworld.js` clones each external corpus to `.bench-cache/` on demand and runs the same engine that ships to production. Per-app `wildcardFamilies` policies in `manifest.json` match commercial-SAST scoring conventions where benchmark labels hinge on AST-level distinction the regex engine intentionally can't make (e.g., OWASP Benchmark's `ProcessBuilder(String[])`-is-safe convention).

---

## COMPLIANCE

```
       agentic-security scan --format cyclonedx     # SBOM
       agentic-security scan --format spdx          # SPDX 2.3
       agentic-security scan --format aibom         # CycloneDX 1.7 ML-BOM
       agentic-security scan --format pbom          # Pipeline BOM
```

Framework-specific attestations (Claude Code slash commands):

```
       /produce-compliance-report asvs    OWASP ASVS Level 1+2
       /produce-compliance-report pci     PCI-DSS 4.0
       /produce-compliance-report soc2    SOC 2 Common Criteria CC6–CC9
       /produce-compliance-report nist    NIST AI 600-1 (Generative AI risk)
```

Posture artifacts:

```
       /security-posture --sbom           CycloneDX 1.6 or SPDX 2.3
       /security-posture --aibom          CycloneDX 1.7 ML-BOM (AI components)
       /security-posture --api            API surface map (md/json/openapi)
       /security-posture --license        License allow/deny policy enforcement
       /security-posture --drift          Diff two scan snapshots
       /security-posture --mttr           SLA breach report
```

Each produces an evidence-backed attestation sheet (CSV + JSON + Markdown) suitable for handing to an auditor.

---

## EXAMPLES

Daily scan with MITRE ATT&CK columns:

```
       agentic-security scan --columns mitre
```

CI gate that fails on any critical:

```
       agentic-security scan . --severity critical || exit $?
```

Build a SARIF, upload to GitHub Security tab:

```
       agentic-security scan . --format sarif --output security.sarif
```

Org-wide scan with 8 parallel workers:

```
       agentic-security org-scan \
         --repos /repos/api,/repos/web,/repos/admin --workers 8
```

Pipe findings to a custom Jira opener:

```
       agentic-security scan --format json | \
         jq '.findings[] | select(.severity=="critical")' | \
         ./scripts/open-jira-issues.sh
```

Triage a single finding and re-scan to confirm:

```
       agentic-security triage transition SEC-0042 fixed
       agentic-security scan .
```

---

## SEE ALSO

```
       for-vibecoders(7)    Easy-mode usage guide for non-security
                            developers.
       LICENSE              Full license terms.
       commands/            Slash-command definitions for the Claude
                            Code plugin.
```

---

## AUTHOR

Built by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
Maintainer: Ross Young <ross@clearcapabilities.com>.

---

## BUGS

Report at <https://github.com/clearcapabilities/agentic-security/issues>.

---

*🛡 agentic-security · created by [ClearCapabilities.Com](https://clearcapabilities.com)*
