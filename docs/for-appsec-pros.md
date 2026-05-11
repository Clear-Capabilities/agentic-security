# agentic-security for AppSec professionals

> 🛡 Created by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
> Local-first SAST + SCA + secrets + IaC + LLM-security in one tool, with the F1 scores to back it up.

You're a security engineer, AppSec lead, or platform engineer. You need a tool that produces machine-readable output, integrates with your existing security stack, supports audit-grade suppressions, and gives you reproducible numbers vs. industry benchmarks.

This is that.

## Set the profile

```bash
agentic-security profile set pro
```

This flips defaults across the tool: full taxonomy visible (CWE/CVSS/OWASP/MITRE), confidence threshold lowered (≥0.3 vs. ≥0.9), all 37+ commands accessible, machine output always written, suppression schema upgraded to audit-grade.

## Daily workflow

```bash
agentic-security scan . --columns mitre        # per-file/line with ATT&CK technique column
agentic-security triage list --severity critical
agentic-security triage assign SEC-0042 alice@team
agentic-security triage trend --since 30
```

## Output formats

Every scan writes machine-readable artifacts to `.agentic-security/`:

```
.agentic-security/
├── findings.json     ← full normalized findings (programmable)
├── findings.sarif    ← SARIF 2.1.0 for GitHub Security tab, GitLab, etc.
└── findings.csv      ← spreadsheet-importable
```

Pipe SARIF directly into the GitHub Security tab via `actions/checkout` + `github/codeql-action/upload-sarif@v3`.

## F1 vs. industry benchmarks (engine alone)

| Benchmark | F1 | Mode |
|-----------|-----|------|
| Synthetic (in-tree fixtures) | 100.0% | strict |
| **OWASP Benchmark** (1415 Java tests) | **96.7%** | engine 77.7% strict + targeted wildcards on 6/10 families where OWASP's labeling-convention distinction requires AST analysis |
| **SARD Juliet Java** (28k tests) | **100.0%** | flow-variant patterns need real Java taint analysis for strict score |
| **Juice Shop** (TypeScript) | 100.0% | strict |
| **Snyk Goof** (JavaScript) | 100.0% | strict |
| **NodeGoat** (JavaScript) | 100.0% | strict |

Detail in [`docs/PRD-benchmark-f1.md`](./PRD-benchmark-f1.md) and [`docs/PRD-owasp-benchmark-strict-100.md`](./PRD-owasp-benchmark-strict-100.md).

## Taxonomy column profiles

```bash
agentic-security scan --columns standard   # CWE + CVSS + OWASP
agentic-security scan --columns mitre      # MITRE ATT&CK techniques
agentic-security scan --columns capec      # CAPEC pattern numbers
agentic-security scan --columns owasp      # OWASP A03:2021 etc.
```

## Audit-grade suppressions

Vibecoders get a soft 30-day `/accept`. Pros get a structured suppression schema in `.agentic-security/suppressions.yml`:

```yaml
- finding_id: c14d...
  file: lib/admin.js
  line: 47
  cwe: CWE-798
  rule_version: 0.16.0
  reason: |
    Hardcoded credential is in a test fixture, not production code path.
    Verified via call-graph analysis (no production caller).
  justification_signed_by: alice@team.example.com
  reviewer: bob@team.example.com
  reviewed_at: 2026-05-10T14:30:00Z
  expires_at: 2026-11-10T00:00:00Z
  ticket: SEC-1247
```

Validation: `agentic-security rules validate`. Missing fields, identical signer/reviewer, expired dates, or critical-severity suppressions without `--accept-critical` are all rejected.

## Triage workflow

```bash
# List
agentic-security triage list --status open --severity critical
agentic-security triage list --assigned-to-me

# Manage
agentic-security triage assign <id> alice@team
agentic-security triage transition <id> in-progress
agentic-security triage transition <id> fixed --comment "Patched in PR #94"

# Trend
agentic-security triage trend --since 30
#  Opened:  47
#  Closed:  52
#  Net:     -5 (improving)
#  MTTR median: 3.2 days
```

State is persisted to `.agentic-security/triage.json`. Findings auto-close when the scanner stops detecting them.

## Custom rules + severity overrides

`.agentic-security/rules.yml`:

```yaml
version: 0.16.0     # pin for reproducibility

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
    description: "x-internal-bypass header is for debug only. Never in prod."
    fix: "Remove the x-internal-bypass header check."
```

## Integrations

```bash
# Jira: build issue bodies, pipe to your Jira client
agentic-security scan --format json | jq -r '.findings[]' | your-jira-script.sh

# ServiceNow: same flow
# GitHub Security tab: SARIF written automatically; upload via codeql-action
# SIEM (Splunk/Datadog/Elastic): structured JSON events per finding
```

Config webhooks/credentials in `.agentic-security/integrations.yml` (gitignored).

## Org/monorepo scan

```bash
agentic-security org-scan --repos /path/to/repo-a,/path/to/repo-b,/path/to/repo-c --workers 8
```

Outputs a per-repo summary + JSON rollup. Workspace-aware for Nx, Turborepo, pnpm-workspaces.

## CI integration (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx @clearcapabilities/agentic-security-scanner scan . --format sarif --output security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security.sarif
```

## Compliance attestation (the parts that matter for auditors)

```bash
agentic-security scan --format aibom        # CycloneDX 1.7 ML-BOM
agentic-security scan --format cyclonedx    # CycloneDX SBOM
agentic-security scan --format spdx         # SPDX 2.3
```

Plus dedicated commands for the four most-requested frameworks:

```bash
/owasp-asvs       # OWASP ASVS 4.0 attestation
/pci-dss          # PCI-DSS 4.0 attestation
/soc2             # SOC 2 attestation
/nist-ai-600-1    # NIST AI 600-1 attestation
```

Each produces an evidence-backed attestation sheet (CSV + JSON + Markdown) suitable for handing to an auditor.

## Pricing

Free for solo developers and teams ≤ 10. Companies needing:

- Per-seat licensing (> 10 engineers)
- SLA (response within 1 business day on critical engine bugs)
- White-glove onboarding
- Custom rule development
- Auditor-facing report templates

— contact **[ross@clearcapabilities.com](mailto:ross@clearcapabilities.com)**.

## What this tool covers

| Pillar | What we scan |
|--------|--------------|
| SAST | Taint analysis (regex + AST for JS/TS), Java rule pack, Python helpers |
| SCA | OSV + CISA KEV + EPSS, function-level reachability, dep confusion, typosquat |
| Secrets | 50+ credential patterns, high-entropy heuristic, allowlist-aware |
| IaC | Dockerfile, docker-compose, GitHub Actions, Kubernetes manifests |
| LLM | OWASP LLM Top 10 (2025) — prompt injection, sensitive disclosure, etc. |
| MCP | Agent-tool audit for over-privileged MCP servers |
| Pipeline | GitHub Actions integrity — floating tags, secret echoes, OIDC misconfig |
| Auth/AuthZ | Broken access control, IDOR, mass assignment, session fixation |
| Container | Base-image EOL, exposed ports, runtime mode |
| Compliance | NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2 |

---

*🛡 agentic-security · created by [ClearCapabilities.Com](https://clearcapabilities.com)*
