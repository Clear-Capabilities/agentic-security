# 10 recommendations to support both vibecoders and AppSec professionals

**Status:** Draft
**Owner:** Ross Young <ross@clearcapabilities.com>
**Last updated:** 2026-05-10
**Companion:** `docs/PRD-vibecoder-ux.md` (covers persona 1 only)

---

## Why this document exists

The existing vibecoder PRD makes the tool more approachable but also more *opinionated* — it hides taxonomy, demotes compliance commands, defaults to "honest" mode, restates the license in vibecoder-friendly terms. If we ship that PRD as-is, we will alienate a second, equally important audience:

**Professional developers and Application Security professionals** — security engineers, AppSec leads, software engineers on platform/infra teams, consultants, pentesters. They:

- Want CWE / CVSS / STRIDE / MITRE ATT&CK / OWASP categories *visible by default* — it's how they communicate.
- Use the tool in CI/CD pipelines, not interactively. They want SARIF, exit codes, and machine-readable output.
- Care about per-rule precision/recall. F1 scores in the README are credibility, not noise.
- Need audit-grade suppression with justification, reviewer sign-off, and expiry — not a 30-day `/accept`.
- Pull findings into Jira / ServiceNow / GitHub Security tab / Splunk — not Slack digests.
- Scan fleets of repos, not single projects.
- Are professionally responsible for the false-negative rate. A missed critical = a career problem.

**The two personas have opposite failure modes:**

| | Vibecoder | AppSec Pro |
|---|---|---|
| Unacceptable failure | False positives (they abandon) | False negatives (they get fired) |
| Trust signal | "It just works" | Reproducible F1, signed evidence |
| Vocabulary | Plain English | CWE / CVSS / STRIDE / MITRE ATT&CK |
| Default verbosity | One line | Full taxonomy |
| Workflow | Interactive `/ship` | CI/CD batch, scheduled scans |
| Suppression model | Soft 30-day | Justified, reviewed, audit-trail |
| Integrations | Slack digest, GitHub PR comment | Jira, ServiceNow, GitHub Security tab, SARIF, SIEM |
| Scope | Single repo | Org-wide, monorepo, fleet |
| Reporting | Investor PDF, share badge | Audit evidence, regression trends |
| License model | Free for solo | Company license + SLA + support |

This document proposes 10 recommendations that let the *same engine* serve both audiences without compromise to either. The engine's F1 floors (Synthetic 100%, OWASP/SARD 95%, JS/TS apps 100%) stay locked.

---

## R1 — Profile-aware operational mode (the master switch)

Every other recommendation hangs off this one. Add a single profile config that determines defaults across the whole tool.

```yaml
# .agentic-security/profile.yml
profile: vibecoder      # or: pro
stack: next-supabase-clerk    # detected or set by /security-onboard
audience: self                 # or: cofounder | investor | auditor | team
```

When `profile: vibecoder`:
- Default output mode is `--honest` (high-precision only)
- Default rendering hides CWE/STRIDE/CVSS
- `/help` shows 5 commands
- README quick-start UX
- Soft 30-day `/accept` available
- One repo at a time

When `profile: pro`:
- Default output mode is `--firehose` (all findings, ranked by exploitability)
- Default rendering shows CWE/CVSS/OWASP/MITRE ATT&CK columns
- `/help` shows all 37+ commands
- AppSec quick-start UX
- Suppression requires justification + reviewer + expiry
- Org-scan / monorepo mode available

`/security-onboard` asks one extra question:

```
What's your role?
  [1] I build apps — I want the tool to tell me what to fix
  [2] I'm responsible for app security — I want full taxonomy + integrations
```

**Why both personas win:** Vibecoders get the simplified UX of PRD-vibecoder-ux. Pros get the engine's full power surface, not a dumbed-down view. Neither sees UX optimized for the other.

**F1 guard:** Pure renderer/config change. CI bench runs in pro mode (full firehose).

---

## R2 — Dual rendering: human + machine output, always

Today's scan emits findings to a single terminal output. Make every scan emit BOTH a human-readable view AND a machine-readable artifact, every time.

```
$ /security-scan-all
  ... scan runs ...
  
  Human output:   (rendered to terminal per profile)
  Machine output:
    • SARIF:    .agentic-security/findings.sarif
    • JSON:     .agentic-security/findings.json
    • CSV:      .agentic-security/findings.csv  (pro only)
    • Markdown: .agentic-security/findings.md
```

**Vibecoder:** never opens the machine files. The terminal verdict is enough.

**AppSec pro:** pipes SARIF directly into the GitHub Security tab, GitLab security dashboard, or their existing SIEM. JSON for custom scripts. CSV for executive spreadsheets.

The SARIF output is already implemented; this recommendation makes it *always-on* and adds CSV. JSON schema gets versioned and documented.

**Pro-specific:** `agentic-security export --jira --project SEC` opens Jira tickets for each finding above a threshold, with the SARIF location, snippet, and fix snippet pre-populated.

**F1 guard:** Renderer-only. Add an assertion: SARIF output's `results[]` count equals the findings count after policy filtering. No silent drops.

---

## R3 — Confidence-scored findings with dual thresholds

The scanner already computes `toxicityScore` and `exploitabilityScore` per finding. Expose them as a single `confidence` field (0.0–1.0) and let each persona threshold differently.

```
$ /security-scan-all --profile pro
  Finding: routes/login.ts:34
    SQL Injection (CWE-89)
    Severity: Critical | CVSS 9.8 | Confidence 0.96 | OWASP A03:2021
    Tainted path: req.body.email → sql.query(...)
    Fix: parameterized query (see /fix 1)

$ /security-scan-all --profile vibecoder
  ✗ routes/login.ts:34 — User input goes straight into a database query
    Apply this fix:                                /fix 1
```

**Vibecoder default threshold:** `confidence ≥ 0.9` (high-precision, no surprises).
**Pro default threshold:** `confidence ≥ 0.3` (high-recall, ranked by exploitability so triage works).

Both render the *same* findings — just at different thresholds. Pros can drill into low-confidence findings to manually validate; vibecoders never see them.

**Why both personas win:** Vibecoders never see "advisory noise." Pros never have to wonder "did the tool hide a finding from me?" — they see everything, just ranked.

**F1 guard:** All benchmark F1 calculations use confidence ≥ 0.3 (the pro default). The vibecoder threshold is purely a renderer filter — strict-subset of full output, asserted by an existing CI test.

---

## R4 — Two suppression schemas: soft and audit-grade

The vibecoder PRD adds `/accept` — a 30-day soft suppression. AppSec pros need something different.

**Vibecoder suppression (`profile: vibecoder`):**

```json
// .agentic-security/accepted.json
{
  "accepted": [
    {
      "id": "abc123",
      "file": "lib/admin.js",
      "line": 47,
      "vuln": "Hardcoded Credential Check",
      "reason": "vibecoded for now",
      "accepted_at": "2026-05-10",
      "expires_at": "2026-06-09"
    }
  ]
}
```

**Pro suppression (`profile: pro`):**

```yaml
# .agentic-security/suppressions.yml
- finding_id: abc123
  file: lib/admin.js
  line: 47
  cwe: CWE-798
  rule_version: 0.15.2
  reason: |
    Hardcoded credential is in a test fixture, not production code path.
    Verified via call-graph analysis (no production caller).
  justification_signed_by: alice@team.example.com
  reviewer: bob@team.example.com
  reviewed_at: 2026-05-10T14:30:00Z
  expires_at: 2026-11-10T00:00:00Z
  ticket: SEC-1247
```

Pro suppressions:
- Require a non-empty `reason` (rejected if missing).
- Require a `reviewer` distinct from `signed_by`.
- Pin to a `rule_version` so a new version of the rule re-surfaces the finding (no silent persistence).
- Track in version control; a CI gate fails the build if a suppression is added without code review approval.
- Auto-render in compliance reports as the "exception register" SOC 2/ISO 27001 audits want.

**Critical findings cannot be suppressed in pro mode** without an additional `--accept-critical --i-am-the-security-owner` flag. Soft suppression of criticals is unsafe at any company > 10 people.

**Why both personas win:** Vibecoders get a frictionless "this is fine for now" path. Pros get the audit trail their job requires.

**F1 guard:** Suppression is a finding-level filter, not a detection-level filter. The benchmark always sees pre-suppression findings.

---

## R5 — Persona-aware taxonomy: hide for vibecoders, surface for pros

Every finding carries metadata: CWE, CVSS vector, OWASP category, MITRE ATT&CK technique, STRIDE category, SARIF ruleId. Vibecoders never see these. Pros see them by default.

```
$ /security-scan-all --profile pro --columns standard

  File              Line  Severity  CVSS  CWE     OWASP    Confidence  Vuln
  ──────────────────────────────────────────────────────────────────────────
  routes/login.ts   34    Critical  9.8   CWE-89  A03:2021  0.96       SQL Injection
  lib/auth.ts       18    High      7.5   CWE-330 A02:2021  0.88       Weak Random Token
```

```
$ /security-scan-all --profile pro --columns mitre

  File              Line  ATT&CK Technique             Vuln
  ──────────────────────────────────────────────────────────
  routes/login.ts   34    T1190 Exploit Public-Facing  SQL Injection
  lib/auth.ts       18    T1110.003 Password Spraying  Weak Token
```

```
$ /security-scan-all --profile pro --columns capec

  ... CAPEC pattern numbers ...
```

For vibecoders, the same finding renders as:

```
✗ routes/login.ts:34 — User input goes straight into a database query
```

**Implementation:**
- Add `taxonomy: { cwe, cvssV3, owasp2021, owaspLlm2025, mitreAttack, capec, sarifRuleId }` to every finding.
- Renderer respects `--columns` flag (pro mode) or hides entirely (vibecoder mode).
- CWE / OWASP / MITRE mappings already partially present; complete the coverage.

**Why both personas win:** Vibecoders aren't drowned in vocabulary they don't understand. Pros get exactly the columns they need for board reports, SOC analyst handoffs, or vendor risk assessments.

**F1 guard:** Taxonomy is metadata, not detection. New unit test asserts every finding emitted has a complete `taxonomy` object.

---

## R6 — Pro-only triage layer (assign / track / trend)

AppSec pros don't just scan — they manage findings over time. Add a triage state machine that vibecoders never see.

```
$ /security-triage list --status open --severity critical
  ID       File                 Line  Vuln               Assigned          Age
  ─────────────────────────────────────────────────────────────────────────
  SEC-001  routes/login.ts      34    SQL Injection      alice@team        2d
  SEC-002  lib/auth.ts          18    Weak Random Token  (unassigned)      5d
  SEC-003  api/admin.js         92    Mass Assignment    bob@team          1d

$ /security-triage assign SEC-002 alice@team
  Assigned to alice@team. Notification sent.

$ /security-triage trend --since 30d
  Open critical:   3 → 5    (+2)
  Open high:       12 → 8   (−4)
  MTTR critical:   3.5d
  New findings introduced by PR (90 days): 47
  Fixed (90 days): 52
  Net: −5 (improving)
```

**Implementation:**
- New `.agentic-security/triage.db` (SQLite) tracking finding state, assignments, comments, transitions.
- New `/security-triage` skill family: `list`, `assign`, `comment`, `transition`, `trend`, `export`.
- Findings have stable IDs (already exist as `id` field on every finding).
- Triage events get auto-recorded so MTTR and trend metrics are computable.
- Optional sync to Jira via `--jira` (R7).

**Vibecoder mode:** This command is gated to `profile: pro`. Help text never shows it. They see their findings as a flat list with `/fix` actions.

**Pro mode:** This becomes the daily workflow. Mornings start with `/security-triage list --assigned-to-me`.

**Why both personas win:** Vibecoders get a clean UX. Pros get the workflow tool they otherwise build in spreadsheets.

**F1 guard:** Triage is post-finding state, not detection. The bench operates on raw scan output.

---

## R7 — Integration adapters: Jira / ServiceNow / GH Security / SIEM (pro) vs. Slack/PR-comment (vibecoder)

Each persona has different integration targets.

**Vibecoder integrations** (already in PRD-vibecoder-ux):
- Slack/Discord daily digest webhook
- GitHub PR comment status check
- Vercel/Netlify/Cloudflare deploy gate

**Pro integrations** (this recommendation):
- **Jira ticket sync**: `/security-jira sync` opens/updates tickets per finding. Tickets carry the SARIF location, snippet, fix, and a back-link to the next scan. Custom field mapping (severity → priority, CWE → labels).
- **ServiceNow incident creation** for critical findings on production-tagged repos.
- **GitHub Security tab upload** via the existing SARIF flow (R2); pro mode auto-uploads.
- **GitLab security dashboard** (same SARIF, different upload endpoint).
- **Splunk / Datadog / Elastic** via syslog or HTTP event collector — each scan emits a structured log event per finding.
- **OpenCRE crosswalk export** for the policy-mapping crowd.
- **STIX 2.1 export** for threat-intel-platform users.

Implementation: a new `scanner/src/integrations/` directory with one module per target. Each module reads `.agentic-security/integration.yml` for credentials and field mappings (gitignored secrets).

**Why both personas win:** Vibecoders don't need any of this and never see it. Pros get the tool to push into their existing security stack rather than building a parallel one.

**F1 guard:** Output-only. Adapters can't change detection.

---

## R8 — Single-repo (vibecoder) vs. org/monorepo (pro) scan modes

Vibecoders scan one repo. AppSec pros scan dozens or hundreds.

```
$ /security-org-scan --org my-company --include-private
  Discovering repositories in my-company...
  Found 47 repos. Filtering for those with code in supported languages...
  Scanning 32 repos in parallel (8 workers)...
  
  Done in 4m 12s.
  
  Org-wide summary:
    Critical findings:    14 across 8 repos
    High:                 67 across 19 repos
    Repos with no findings: 13
    Repos failing to scan:  2 (auth/permission issues)
  
  Top 5 repos by exploit-path count:
    1. payments-api       (3 critical, 12 high)
    2. user-service       (2 critical, 8 high)
    3. internal-admin     (2 critical, 5 high)
    ...
  
  Full report: ./org-scan-2026-05-10.html
```

**Monorepo support:**
- Detect Nx, Turborepo, Lerna, Rush, pnpm workspaces.
- Scan each workspace package independently with isolated rule context.
- Roll up findings into a single report keyed by owner (via CODEOWNERS).

**Implementation:**
- New `bin/agentic-security-org` entry point (separate from the per-repo CLI).
- Concurrency control via `--workers N`.
- Auth: GitHub PAT, GitHub App, or local git clone of pre-cloned repos.
- Roll-up rendering: per-repo, per-owner, per-severity, trend over time.

**Why both personas win:** Vibecoders get the single-repo experience they need. Pros get the fleet-mode scanner they need without a separate product.

**F1 guard:** Same engine, just orchestrated. Per-repo F1 is unchanged. Org-scan acceptance test: scanning two known repos produces the union of their individual scans (no findings invented or lost).

---

## R9 — Tunable rule packs: custom rules, severity overrides, rule-version pinning (pro only)

Vibecoders accept defaults. Pros want to:
- Disable a rule that's noisy on their codebase.
- Override severity per rule (e.g., demote one rule to medium across the org).
- Write custom rules for their internal patterns (e.g., "internal helper `auth.has_role()` is the only valid authorization gate").
- Pin to a specific rule version for reproducibility across CI runs.

```yaml
# .agentic-security/rules.yml  (pro mode)
version: 0.15.2          # pin rule versions for reproducibility

# Override severity globally
severityOverrides:
  "Hardcoded Credential Check": medium
  "Reflected XSS (User Input in Response)": high

# Disable rules
disable:
  - "Verify x-powered-by Header is Disabled"

# Custom rule definitions
custom:
  - id: internal-auth-bypass
    regex: 'if\s*\(\s*request\.headers\[\s*[''"]x-internal-bypass[''"]'
    vuln: "Internal Auth Bypass Header"
    severity: critical
    cwe: CWE-287
    description: "Our internal auth gate uses x-internal-bypass for debug. Must NEVER be in prod code."
    fix: "Remove the x-internal-bypass header check before merging."
```

**Vibecoder mode:** `rules.yml` is hidden / generated automatically based on stack-preset. Editing it is not surfaced.

**Pro mode:** `rules.yml` is THE configuration file. Documented, schema-validated, fully overrideable.

**Implementation:**
- Extend the existing custom-rule loader.
- Add severity override + version pin + rule disable to the config schema.
- New `/security-rules validate` command checks the rules.yml file.
- Pin field rejects scans run with newer rule versions unless `--accept-version-drift`.

**Why both personas win:** Vibecoders never confront a config file. Pros get the tool to be customizable to their codebase.

**F1 guard:** Built-in benchmarks run with `rules.yml: {}` (empty config). Custom rules can't affect the canonical F1 numbers. New CI test: a `rules.yml` with `disable: ['SQL Injection']` produces a scan with zero SQL findings (validates the override mechanism).

---

## R10 — Dual landing page + dual licensing model

The README currently mixes audiences. Separate them.

**README top-of-page:**

```
agentic-security

The boring copilot that catches what your AI assistant misses.

  > I'm building an app                    [vibecoder path]
  > I'm responsible for app security       [appsec pro path]
```

Each path leads to a tailored quick-start, value prop, and pricing.

**Vibecoder path:**
- "Ship safely without learning what XSS means"
- `/ship` quick-start
- Free forever for solo / teams ≤ 10
- Sample badges, share buttons

**AppSec pro path:**
- "Local-first SAST + SCA + secrets + IaC + LLM-security in one tool"
- F1 scores vs. OWASP Benchmark, SARD, etc. (the credibility table)
- SARIF, Jira, ServiceNow integration screenshots
- Compliance attestation samples (SOC 2, ISO 27001, PCI-DSS 4.0)
- **Pricing model:**
  - Per-developer seat for companies > 10 engineers
  - Annual contract with SLA: response within 1 business day on critical engine bugs
  - Optional white-glove onboarding
  - Optional custom rule development
  - Optional auditor-facing report templates

The free PolyForm Internal Use license stays for solo developers. Companies pay for support, integrations, and SLA — not for the engine itself.

**Why both personas win:** Vibecoders never see the pricing page. AppSec pros never see the "share your security badge on Twitter" CTA. Both feel like the product was built for them.

**Implementation:**
- README split into a top-of-funnel selector + two landing pages (`docs/for-vibecoders.md`, `docs/for-appsec-pros.md`).
- One pricing page (`docs/pricing.md`) accessed only from the pro path.
- License language stays the same but is *positioned* differently per audience.

**F1 guard:** Documentation only.

---

## Cross-cutting principles

Beyond the 10 recommendations, three load-bearing principles:

### Principle 1 — Same engine, different surface

Every recommendation works because the engine is shared. We never fork the detection logic. Profile mode = different rendering, filtering, integration, and config validation — but the same `runFullScan()`. This keeps F1 scores deterministic regardless of persona.

### Principle 2 — Default to the persona's failure mode

Vibecoders fail by abandoning the tool after FPs → default to high-precision.
Pros fail by missing a critical → default to high-recall + show every metadata column.
Each persona's default optimizes for the failure they fear most.

### Principle 3 — No drive-by deprecations

Nothing in the existing tool gets *removed* to make room for either persona. Compliance attestations, threat models, SBOMs, AI-BOMs — all stay. They're demoted (vibecoder) or surfaced (pro) by profile, but never deleted.

---

## Acceptance criteria for "supports both personas"

A change qualifies as PRD-complete when ALL of:

1. `profile: vibecoder` and `profile: pro` produce the same set of underlying findings (asserted by integration test).
2. Vibecoder profile renders zero CWE / CVSS / STRIDE / SARIF references in default output.
3. Pro profile shows full taxonomy + machine output by default + Jira/SARIF integration paths are documented.
4. Pro-only commands (`/security-triage`, `/security-org-scan`, `/security-jira`, etc.) are hidden from vibecoder `/help`.
5. Vibecoder-only UX (`/ship`, `/accept`, `--for cofounder`) is hidden from pro `/help` *unless* explicitly requested.
6. All 6 benchmark F1 floors hold (Synthetic 100%, OWASP/SARD 95%, JS/TS apps 100%, new vibecoder-nextjs 100%).
7. Pro suppressions require justification + reviewer + expiry; missing fields rejected at validate time.
8. `/security-onboard --pro` and `/security-onboard --vibecoder` set the profile correctly and don't bleed defaults.
9. README quick-start has two clear paths, selected within the first 5 visible lines.
10. License language is unified across personas — same legal terms, two different framings of what those terms mean for each audience.

---

## Risks

| Risk | Mitigation |
|------|------------|
| Pros feel patronized by default vibecoder mode | Profile asked during `/security-onboard`; explicit `--profile pro` always available |
| Vibecoders accidentally land in pro mode and get scared off | Default profile is vibecoder; pro requires explicit opt-in or detection (e.g., a `SECURITY.md`, a CI workflow, `.security/` dir) |
| Two suppression schemas confuse maintainers | Codify the schemas in a JSON schema file; lint at scan time |
| Pro features bloat the bundle for vibecoders | Lazy-load pro modules (`scanner/src/integrations/`, triage DB, org-scan) — vibecoder bundle stays slim |
| Custom rules introduce FPs that affect benchmarks | Canonical benchmark runs override `rules.yml` to empty — custom rules can never affect headline F1 numbers |
| Persona detection misfires | First-run prompt confirms detected persona; user can switch with `agentic-security profile set pro` |
| Org-scan exposes private repos via misconfig | Org-scan requires explicit `--include-private` flag and respects GitHub's repo visibility ACLs |

---

## Quick-reference matrix

| Capability | Vibecoder default | Pro default | Source of truth |
|-----------|-------------------|-------------|-----------------|
| Output rendering | `/ship` verdict | SARIF + JSON + terminal table | R2 |
| Confidence threshold | ≥ 0.9 | ≥ 0.3 | R3 |
| Taxonomy columns | hidden | CWE+CVSS+OWASP+MITRE+CAPEC | R5 |
| Suppression schema | soft 30-day | audit-grade, reviewed | R4 |
| Suppress criticals | one-click | requires special flag + role | R4 |
| Triage workflow | not visible | full state machine + trends | R6 |
| Integrations | Slack/PR-comment | Jira/ServiceNow/GH-Security/SARIF | R7 |
| Scan scope | single repo | org-wide, monorepo, fleet | R8 |
| Rule configuration | auto / hidden | full override + custom rules | R9 |
| Help screen | 5 commands | full 37+ | R1 |
| License framing | "free for solo" | "per-seat for companies" | R10 |
| Failure-mode optimization | precision | recall | Principles |

---

## Summary

These ten recommendations let the same scanner serve a college student vibecoding a side project at 2 AM AND a Fortune 500 AppSec team scanning their fleet — without either feeling like the tool was built for someone else. The engine doesn't fork. The F1 scores stay locked. The product just learns who's looking at it.
