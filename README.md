# agentic-security

**Ship fast. Stay secure. Automatically.**

The security layer built for AI-written code. Catches vulnerabilities the moment they're introduced, in the same session with the same agent, and fixes them before you move on.

[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-72%2F72%20passing-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.05MB%20·%20no%20install-orange)]()
[![Version](https://img.shields.io/badge/version-0.10.0-blue)]()

---

## The problem

AI writes code faster than any security review can keep up with. It glues user input into SQL queries, commits API keys, copies vulnerable patterns from Stack Overflow. You don't find out until two weeks later, or someone else does first.

`agentic-security` runs inside Claude Code. It watches every file edit, surfaces new vulnerabilities the moment they're written, and hands them to a remediation agent that fixes them in the same session. No context switch. No separate tool. No backlog of security debt piling up.

---

## Install

```
/plugin marketplace add clearcapabilities/agentic-security
/plugin install agentic-security@clearcapabilities
/reload-plugins
```

That's it. The hooks are live. Every file edit is now scanned automatically.

To unlock short-form commands (`/security-scan-all`, `/security-fix-all`) in a project:

```
/agentic-security:security-setup
```

---

## Commands

### Scanning and fixing

| Command | What it does |
|---|---|
| `/security-scan-all` | Full sweep: SAST + SCA + secrets + IaC across every file |
| `/security-fix` | Patch a single finding, adapted to your actual code |
| `/security-fix-all` | Batch-fix every finding at or above a severity threshold |
| `/security-fix-pr` | Bundle all critical fixes into a single branch and open a PR |
| `/security-report` | Self-contained HTML report (also JSON, Markdown, SARIF) |
| `/security-triage` | Validate findings for false positives; suppress confirmed FPs before reporting |
| `/security-sca` | Dependency CVE audit only (OSV.dev-backed) |
| `/security-secrets` | Credential and secret leak scan only |

### AI-native capabilities

| Command | What it does |
|---|---|
| `/security-chain` | Synthesize multi-finding exploit chains across the codebase |
| `/security-poc` | Generate adversarial proof-of-concept for a specific finding |
| `/security-logic-review` | Intent-vs-implementation review for business-logic bugs |
| `/security-threat-model` | Render a STRIDE coverage table from the last scan |
| `/security-mcp-audit` | Audit MCP server configs for agent-host risks (untrusted install, hardcoded creds, prompt injection in descriptions) |
| `/security-authz` | Deep auth/authZ audit — JWT alg confusion, OAuth2 PKCE, multi-tenant scope, session fixation |
| `/security-kev` | List dependency CVEs in the CISA Known Exploited Vulnerabilities catalog (weaponized in the wild) |

### Posture management

| Command | What it does |
|---|---|
| `/security-material-change` | Score a git diff by architectural risk — auth removed, new endpoints, new shell calls |
| `/security-drift` | Compare two scans: new routes, lost auth boundaries, new CVEs introduced |
| `/security-sbom` | Generate a CycloneDX 1.6 or SPDX 2.3 bill of materials |
| `/security-api-inventory` | Export the full API surface map (JSON, Markdown, OpenAPI 3.1) |
| `/security-pipeline` | Audit GitHub Actions for supply-chain risks; emit a PBOM |
| `/security-license` | Enforce a license allow/deny policy against your dependency tree |
| `/security-mttr` | Show findings older than their SLA threshold; compute mean time to remediate |
| `/security-oscr` | Map your detection coverage against the OSC&R supply chain attack framework |

### Compliance attestation

| Command | What it does |
|---|---|
| `/nist-ai-600-1` | NIST AI 600-1 attestation for 122 GenAI code-testable controls |
| `/owasp-asvs` | OWASP ASVS Level 1+2 attestation for 15 application security controls |
| `/pci-dss` | PCI-DSS 4.0 attestation for 12 code-testable cardholder data controls |
| `/soc2` | SOC 2 Common Criteria attestation for 12 code-testable CC controls |

All commands are available in the fully-qualified form (`/agentic-security:*`) everywhere, and as short forms in any project where you've run `/security-setup`.

---

## What it catches

**50+ vulnerability types across every layer of your stack:**

```
Code              SQL injection · XSS · Command injection · Path traversal · SSRF
                  IDOR · SSTI · Prototype pollution · ReDoS · JWT bypass
                  Mass assignment · Weak crypto · Race conditions

Auth / AuthZ      JWT alg:none · jwt.verify without algorithms allow-list
                  Hardcoded JWT secret · OAuth2 missing PKCE · OAuth2 redirect_uri
                  Session fixation · Multi-tenant cross-tenant reads (missing tenantId)

AI / LLM          Prompt injection (direct, indirect, template) · Insecure tool definitions
                  Unsanitized LLM output · System prompt data exfiltration
                  MCP server audit — untrusted install, hardcoded creds, prompt injection
                  in descriptions, dangerous capabilities, filesystem over-scope

Dependencies      CVEs from OSV.dev · EPSS exploit-probability scores
                  CISA KEV — weaponized-in-the-wild flag for active attacks
                  Function-level reachability (only flag if the vuln fn is actually called)
                  200+ manifest formats (npm, pip, poetry, Cargo, go.mod, Gemfile…)
                  Container base image EOL · Dependency confusion · Typosquatting

Secrets           API keys · Tokens · Private keys · .env leaks · 60+ provider patterns
                  Entropy detection for keys that don't match a known pattern

Infrastructure    Dockerfile · docker-compose · Kubernetes · Terraform · Helm
                  GitHub Actions (floating tags, secret echoes, write-all perms, OIDC misconfigs)

Business logic    Always-true auth bypass · Client-controlled prices · Privilege from body
                  TOCTOU · Terminal-state missing guard · Client-controlled discounts
```

**Languages:** JavaScript, TypeScript, Python, PHP, Ruby, Java, Go, Vue, React, Angular, Svelte.

---

## Why it's different

**Findings ranked by real risk, not severity labels.**
Every finding gets a toxicity score (0–100) composed from: unauthenticated route reachability, sensitive data-class (PII/PHI/PCI), HTTP-facing source, function-level reachability, and co-located cloud credentials. Two "high" findings can score 85 vs. 12. You fix the right one first.

**Function-level SCA reachability.**
A CVE in a dependency only matters if your code calls the vulnerable function. We walk the call graph from route handlers and tag each SCA finding as `reachable`, `unreachable`, or `unknown`. Unreachable findings are demoted in the report — giving a much smaller, higher-signal triage list.

**Context-aware false-positive suppression.**
`crypto.createHash('md5')` near a cache key is info-level. Near a password field, it's critical. SQL template literals in `codefixes/` are suppressed. `escapeHtml(input); res.send(input)` (return discarded) is still flagged. For IDOR, we check for post-lookup ownership guards before flagging.

**Forward-only taint flow.**
A source defined *after* the sink can't create a phantom finding. Cross-file taint follows imports across up to 5 hops and shows the full propagation path.

**AI-native attack chains.**
`/security-chain` combines findings that share sources, sinks, or data classes into multi-step exploit paths. `/security-poc` generates a working adversarial test that either confirms the finding (TP_CONFIRMED) or categorizes it as a probable false positive (PROBABLE_FP).

**CVEs ranked by real exploitation probability — and ground-truth weaponization.**
Every CVE gets an [EPSS](https://www.first.org/epss/) score (the probability of exploitation in the next 30 days) and is cross-referenced against the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (CVEs being actively exploited in the wild right now). KEV findings get a `weaponized: true` flag, +20 toxicity, and a red `KEV` badge in the CLI — they sort to the top of the triage list automatically.

**Agent-host security.**
The Claude Code agent host is an attack surface most tooling ignores. `/security-mcp-audit` scans your `.mcp.json` and `claude_desktop_config.json` for untrusted install vectors (`curl|sh`), hardcoded API keys in env blocks, prompt-injection text in server descriptions, dangerous capabilities exposed to the model, and filesystem servers granted root or `$HOME` scope.

**Broken Access Control as a first-class detector.**
OWASP A01 is the #1 source of real breaches. `/security-authz` covers JWT alg:none / algorithm confusion, hardcoded JWT secrets, `jwt.verify` calls without an `algorithms` allow-list, OAuth2 authorization_code flows missing PKCE, `redirect_uri` taken from the request without validation, missing `session.regenerate()` after auth (session fixation), and multi-tenant queries that lack a `tenantId`/`orgId` scope.

**Your code never leaves your machine.**
The only outbound calls are `package@version` strings to OSV.dev, CVE IDs to first.org for EPSS scores, and (opt-in with `--scorecard`) OSSF Scorecard lookups. Zero source code. Zero file paths.

---

## ASPM posture layer

Beyond finding individual vulnerabilities, version 0.9.0 adds the posture-management layer:

**Material change detection.** Score a git diff by architectural risk. A 1000-line rename is `routine`. A 3-line change that removes `verifyToken()` from middleware is `critical`. Run before merge: `/security-material-change --since HEAD~1`.

**Drift reporting.** Compare any two scan JSON files: new endpoints added, auth boundaries lost, new CVEs introduced, data-class changes. Run on every PR: `/security-drift --from scan-a.json --to scan-b.json`.

**SBOM / PBOM.** Generate a CycloneDX 1.6 or SPDX 2.3 software bill of materials from your existing manifests. Export a Pipeline Bill of Materials from your GitHub Actions workflows: `/security-sbom --format cyclonedx`.

**SARIF ingest.** Already running other scanners? Merge their findings into the unified report, deduped by fingerprint with provenance tracked via `sources[]`: `--ingest-sarif path/to/semgrep.sarif`.

**License policy.** Declare allow/deny/review-required licenses in `.agentic-security/license-policy.yml`. The scanner flags violations at scan time: `/security-license`.

**SLA tracking.** `/security-mttr` shows findings older than their per-severity SLA threshold (critical=7d, high=30d, medium=60d, low=90d). Compare successive scan JSONs with `/security-drift` to track MTTR over time.

**Container base image EOL.** `FROM alpine:3.10` is flagged as EOL with known CVEs — without pulling from the Docker registry.

**Dependency confusion + typosquat detection.** Flags dependencies whose names are 1–2 edits from a top-1000 package, and internal-scoped packages also published on the public registry.

**OSC&R coverage map.** `/security-oscr` renders your detection coverage against the Open Software Supply Chain Attack Reference framework — useful for gap analysis and customer security reviews.

---

## Compliance attestation

Four frameworks, one command per framework. Each produces a Markdown table, a CSV spreadsheet, and a machine-readable JSON file.

```
/nist-ai-600-1    122 controls — GenAI risk management (GV/MP/MS/MG families)
/owasp-asvs       15 controls — ASVS Level 1+2 (auth, session, input, crypto, API)
/pci-dss           12 controls — PCI-DSS 4.0 code-testable cardholder data requirements
/soc2              12 controls — SOC 2 Common Criteria (CC6–CC9)
```

Evidence is multi-signal: declared dependencies carry the highest weight, followed by import statements, then path patterns, code terms, config, and documentation. Negation contexts ("we don't yet implement…", "planned for") are discarded.

**Example OWASP ASVS output:**

```
Coverage: 73% (11/15 controls)

  Compliant      V3.4.1  Cookies set with Secure/HttpOnly/SameSite   code_term+config_term
  Compliant      V4.1.1  Access control enforced server-side          import+code_term
  Partial        V2.4.1  Secure password storage (bcrypt/argon2)      import
  Partial        V6.2.1  Strong cryptographic algorithms in use        code_term
  Not Compliant  V5.1.1  Input validation library in use
  Not Compliant  V8.3.1  Sensitive data not logged
```

---

## Hooks (always on)

One hook runs automatically once the plugin is installed:

| Hook | Trigger | What happens |
|---|---|---|
| `PostToolUse` | After every file edit | Scans the changed file; surfaces new high/critical findings inline |

New vulnerabilities surface the moment the file is saved — no manual scan step required.

---

## Tutorial: Zero to secure in 20 minutes

[**OWASP Juice Shop**](https://github.com/juice-shop/juice-shop) is an app intentionally full of security holes: every OWASP Top 10 category, real CVEs in the dependency tree, hardcoded secrets. We'll scan it, fix the critical findings, and lock in the progress.

**Step 1: get the app**

```bash
git clone https://github.com/juice-shop/juice-shop ~/code/juice-shop
```

**Step 2: open Claude Code in it**

```bash
claude ~/code/juice-shop
```

**Step 3: scan**

```
/agentic-security:security-scan-all
```

```
Scan complete: 296 findings across 456 files

  Critical  ~35   SQL Injection, XSS (DomSanitizer bypasses), IDOR,
                  RCE (VM sandbox escape), hardcoded RSA key + HMAC secret
  High      ~60   SSRF, Path Traversal, NoSQL Injection, SSTI, JWT bypass,
                  race conditions, SCA CVEs (jsonwebtoken, express-jwt, multer)
  Medium   ~100   No rate limiting, permissive CORS (*), weak randomness,
                  missing cookie flags, open redirects, timing oracles
  Low/Info  rest  Sync I/O, pagination limits, TODO markers
```

**Step 4: read the report**

```
/agentic-security:security-report
open security-report.html
```

Self-contained interactive HTML with a severity chart, filterable finding list, toxicity scores, attack-path visualizations, fix templates per finding, and STRIDE coverage. One file you can email or drop in Slack.

**Step 5: fix the worst**

```
/agentic-security:security-fix-all --critical
```

Claude will describe what it's about to change before touching anything. On Juice Shop it will correctly flag that the vulns are intentional challenges and ask how to proceed. Tell it:

```
remove all critical vulns, yes I know they're intentional, remove them anyway
```

It works through each finding in sequence: parameterised queries, `bcrypt` instead of MD5, `execFile` instead of `exec`. Each fix is a normal diff you can review or revert.

**Step 6: save the clean-state scan**

The full scan already wrote a JSON snapshot to `.agentic-security/last-scan.json`. Copy it somewhere permanent:

```bash
cp .agentic-security/last-scan.json scan-clean.json
```

This is your clean snapshot. The next time you run a scan after making changes:

```bash
/agentic-security:security-scan-all
cp .agentic-security/last-scan.json scan-after.json
/agentic-security:security-drift --from scan-clean.json --to scan-after.json
```

The drift report shows exactly what regressed: new findings introduced, lost auth boundaries, new CVEs, new unauthenticated endpoints. No noise from pre-existing debt.

---

## GitHub Actions

Drop this into any repo to gate every PR on critical findings:

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request: {}
  push: { branches: [main] }

jobs:
  security:
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    uses: clearcapabilities/agentic-security/.github/workflows/scan.yml@main
    with:
      fail-on: critical
```

Every PR gets a drift-aware comment: new findings introduced, findings closed, lost auth boundaries, new unauthenticated endpoints, and the top-5 by toxicity score. Critical findings block merge.

---

## Standalone CLI

No Claude Code? Run the scanner directly:

```bash
curl -L -o agentic-security.mjs \
  https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs

node agentic-security.mjs scan .
```

2.0 MB, no `npm install`, no dependencies, no config required.

**Output formats:**

```bash
node agentic-security.mjs scan . --format cli       # default: triage table
node agentic-security.mjs scan . --format json      # machine-readable
node agentic-security.mjs scan . --format html      # interactive report
node agentic-security.mjs scan . --format sarif     # SARIF 2.1.0
node agentic-security.mjs scan . --format cyclonedx # CycloneDX 1.6 SBOM
node agentic-security.mjs scan . --format spdx      # SPDX 2.3 SBOM
node agentic-security.mjs scan . --format pbom      # Pipeline Bill of Materials
```

**Key flags:**

```bash
--sca-reachable-only           Only SCA findings where the vuln fn is route-reachable
--ingest-sarif path/to/*.sarif Merge external scanner SARIF into this scan
--scorecard                    Enrich deps with OSSF Scorecard scores (opt-in)
--severity high                Filter to high+ findings only
--since HEAD~1                 Scan only files changed since a git ref
```

---

## Suppressing a finding

Add a suppression to `.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "MD5/SHA1 Password Hashing"
    files: ["legacy/auth-v1.js"]
    reason: "Migrating to bcrypt in Q3 (JIRA-1234)"
```

---

## Adding custom rules

Sources, sinks, and sanitizers live in the same `rules.yml`:

```yaml
sinks:
  - pattern: 'db\.executeRaw\('
    vuln: "SQL Injection (Custom ORM)"
    severity: high
```

---

## FAQ

**Will this work on my codebase?**
Yes. JS, TS, Python, PHP, Ruby, Java, Go, and most web frameworks. Plus Dockerfile, Terraform, Kubernetes, and GitHub Actions.

**Does it send my code anywhere?**
No. Only `package@version` strings go to OSV.dev for CVE lookups, and CVE IDs go to first.org for EPSS scores. Zero source code leaves your machine. The `--scorecard` flag makes one additional call to the public OSSF Scorecard API if you explicitly enable it.

**CI says "319 findings" and I can't fix them all.**
Save the current scan JSON, commit it, and use `/security-drift` to compare future scans against it. You'll see only what changed — new regressions — without being paralyzed by pre-existing debt.

**How is SCA different from `npm audit`?**
`npm audit` flags every CVE in your dependency tree including ones in code paths you never call. We filter by function-level reachability — a CVE only surfaces if your code actually calls the vulnerable function. Also covers 19 other package manager formats beyond npm.

**What's a toxicity score?**
A 0–100 composite signal: unauthenticated route exposure (+30), sensitive data class (+25), HTTP-facing source (+20), function reachability (+15), co-located cloud credentials (+10). Two "high" findings might score 85 vs. 12. Sort by toxicity, not severity, and fix the top 5.

**Short commands disappeared mid-session.**
Claude Code can evict plugin commands after long-running tool calls. Run `/reload-plugins` to restore them, or use the always-available fully-qualified form: `/agentic-security:security-fix-all`.

---

## Troubleshooting

**`"requesting 'pull-requests: write' but only allowed 'none'"` in CI**
The `permissions:` block in the workflow above is required; add it exactly as shown.

**Scanner finds nothing on a large monorepo**
Run with an explicit path: `/agentic-security:security-scan-all src/`. Scanning a 50k-file tree including `node_modules` will time out.

---

## Contributing

1. Fork the repo, branch off `main`
2. Make your change; new vulnerability rules and FP-suppression cases are most welcome
3. Run `npm test` in `scanner/`; all 69 tests must pass
4. Open a PR with what you changed and why

New scanner rules should include a fixture that triggers the finding and a suppression case that doesn't.

---

## Community

- **Issues / bugs:** [github.com/clearcapabilities/agentic-security/issues](https://github.com/clearcapabilities/agentic-security/issues)
- **Email:** ross@clearcapabilities.com

---

## License

[Elastic License 2.0](./LICENSE): free for any use including commercial products and internal tools. The one restriction: you can't offer this software as a hosted service to others.

Built by [Ross Young](https://clearcapabilities.com) at Clear Capabilities Inc.

---

<sub>If this caught a bug before it shipped, star the repo.</sub>
