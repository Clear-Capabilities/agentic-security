# Product Requirements Document — `agentic-security` Claude Code Plugin

**Author:** Ross Young, Clear Capabilities Inc.
**Status:** Draft v1.0
**Last updated:** 2026-05-05

---

## 1. Overview

`agentic-security` is an official Claude Code plugin that gives any Claude Code session first-class **application-security analysis** capabilities, but specialized for **defensive security**. The plugin lets a developer (or Claude itself, while editing code) run a **SAST + SCA + Secret-scanning** sweep over the working tree, get findings annotated with CWE / STRIDE / fix guidance, and trigger automated remediation suggestions — all without leaving the terminal.

The scanning engine is a port of the proven analyzer in `attacksurface.html` (~4,150 lines, 50+ vulnerability sinks, 60+ secret patterns, 20 dependency-manifest parsers, OSV-backed CVE lookup, taint analysis, and supply-chain malware verdicts). The HTML tool runs entirely in a browser today; this plugin will repackage that analyzer as a Node-based CLI invoked through Claude Code commands, hooks, agents, and skills.

### 1.1 Why this matters

- AI-assisted code generation accelerates shipping, but it also accelerates shipping vulnerabilities. Developers using Claude Code today have **no native security feedback loop**.
- A plugin that runs **inside** the Claude Code session means findings can be acted on by the same agent that produced the code — closing the loop in seconds, not weeks.

### 1.2 Comparison with `superpowers`

| Dimension | `superpowers` | `agentic-security` |
|---|---|---|
| Scope | Generalist productivity (planning, brainstorming, web research) | Specialist: AppSec (SAST, SCA, Secrets) |
| Distribution | Claude Code marketplace plugin | Claude Code marketplace plugin |
| Surface | Slash commands, agents, skills | Slash commands, hooks, agents, skills |
| Differentiator | Breadth of dev workflows | Depth of vulnerability detection + autofix |

---

## 2. Goals & Non-Goals

### 2.1 Goals

1. **One-command full scan** — `/security-scan` on any repo produces a triaged finding list (Critical → Info) within ~30s for a typical 10k-LOC project.
2. **Per-file, just-in-time scanning** — when Claude edits a file, an `PostToolUse` hook silently scans the diff and surfaces *only new* high/critical findings to the agent.
3. **Three pillars, one report** — SAST findings, SCA findings, and Secret findings render in a single unified output with severity, CWE, STRIDE, and a copy-pasteable fix.
4. **Remediation agent** — a dedicated `security-fixer` subagent that takes a single finding and produces a code patch with explanation.
5. **Zero-network default** — SAST and Secret scanning run fully offline; SCA optionally calls `api.osv.dev` (user-configurable, defaults to on).
6. **Drop-in install** — `/plugin install agentic-security@clearcapabilities` and the user is scanning within 60s.

### 2.2 Non-Goals

- We are **not** building a generic linter, formatter, or style enforcer.
- We are **not** building a runtime/DAST tool, fuzzer, or exploit generator.

---

## 3. Users & Use Cases

### 3.1 Personas

- **P1 — Solo developer using Claude Code.** Wants to know whether the code Claude just wrote is safe. Triggers `/security-scan` after a feature is built.
- **P2 — Security engineer auditing an LLM-generated PR.** Runs the plugin against a branch, exports findings as JSON, attaches to PR review.
- **P3 — Claude Code itself (the agent).** Reads scan results from a hook, auto-fixes findings before declaring the task complete.

### 3.2 Primary use cases

| ID | Use case | Trigger |
|---|---|---|
| UC-1 | Full repo audit | User runs `/security-scan` |
| UC-2 | Edited-file delta scan | `PostToolUse` hook fires after `Edit`/`Write` |
| UC-3 | Pre-commit gate | `PreToolUse` hook on `Bash(git commit*)` |
| UC-4 | Single-finding fix | User runs `/security-fix <finding-id>` |
| UC-5 | Dependency audit only | User runs `/security-sca` |
| UC-6 | Secret-only sweep | User runs `/security-secrets` |
| UC-7 | Threat-model brief | User runs `/security-threat-model` (uses STRIDE coverage map) |

---

## 4. Functional Requirements

### 4.1 Scanning capabilities (port from `attacksurface.html`)

#### 4.1.1 SAST (Static Application Security Testing)

- **AST-based taint analysis** for JS/TS via `@babel/parser`. Track sources → sinks across statements (port of `performASTAnalysis`, line 192).
- **Cross-file taint** with multi-hop BFS up to 3 files deep (port of `crossFileTaint`, line 59).
- **Regex fallback scanner** for non-JS/TS files (port of `performRegexAnalysis`, line 579).
- **50+ sink patterns** covering at minimum: SQLi, NoSQL injection, XSS, DOM XSS, Command Injection, SSRF, Path Traversal, SSTI, Code Eval, Deserialization, Mass Assignment, IDOR, Prototype Pollution, ReDoS, JWT confusion, Open Redirect, Header Injection, Weak Crypto/PRNG, Log Injection, XXE, VM sandbox escape, Angular DomSanitizer bypass — all with CWE + STRIDE tags (port of `SINK_PATTERNS`, line 133).
- **Logic vulnerabilities**: race conditions, TOCTOU, account-enumeration oracles, timing oracles, missing positive-integer validation, basket/ownership IDOR, coupon reuse (port of `scanLogicVulns`, line 852).
- **Structural patterns**: SQLi via template literal, JWT decode without verify, JWT `none` algo, Angular `bypassSecurityTrust*`, `process.env` exposed in HTTP response, etc. (port of `scanStructuralVulns`, line 820).
- **Combined / chained vulnerabilities**: detect when two findings amplify each other (e.g. SSRF + Hardcoded Secret = cloud creds exfiltration) (port of `crossFindingChain`, line 970).
- **Cipher analysis** at-rest and in-transit — flag MD5/SHA1/RC4/3DES/TLS1.0/ECB; pass AES-GCM/SHA256+/bcrypt/argon2/PBKDF2 (port of `scanCiphers`, line 1805).
- **Route/auth coverage**: enumerate Express/Koa/Fastify/Flask/Django/Rails/Laravel/Spring routes, flag missing-auth and missing-rate-limit (port of `scanRoutes`, line 606).
- **GraphQL scanner** for `.graphql`/`.gql` (port of `scanGraphQL`, line 1013).
- **Reachability annotation**: only escalate findings on paths actually called from a route handler (port of `annotateReachability`, line 1089).
- **Sanitizer learning**: detect project-local sanitizer functions and downgrade findings that pass through them (port of `inferSanitizers`/`applySanitizerEffectiveness`, lines 1426/1541).
- **Multi-language coverage**: JS/TS, Python, PHP, Ruby, Java, Go, Laravel — already encoded in pattern table.

#### 4.1.2 SCA (Software Composition Analysis)

- **Manifest parsers** for 20 ecosystems (port from `_parsePackageJson` … `_parsePubspecLock`, lines 1843-2161): `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `composer.json`, `composer.lock`, `Gemfile`, `Gemfile.lock`, `go.mod`, `Cargo.toml`, `Cargo.lock`, `pom.xml`, `build.gradle(.kts)`, `pubspec.yaml`, `pubspec.lock`.
- **OSV.dev integration**: batch query `https://api.osv.dev/v1/querybatch`, hydrate per-vuln details from `https://api.osv.dev/v1/vulns/{id}` (port of OSV engine, line 1831). Cache results on disk (`~/.claude/agentic-security/osv-cache/`) instead of `sessionStorage`.
- **Vulnerable-function-call depth**: only escalate a CVE if the project actually imports/calls the vulnerable export (port of `markUsedVulnFunctions`, line 1608).
- **Lockfile-presence check**: warn when manifest exists but lockfile is missing.
- **Malware verdict per component** (LLM-assisted, opt-in): produce `CLEAN | SUSPICIOUS | MALICIOUS` label with strict grounding rules already encoded (line 2521 prompt). Calls Claude API; user supplies key in plugin config or relies on the active Claude Code session.
- **Aggregate deployment verdict** (`PASS / WARN / FAIL`) based on per-component analyses (line 2530 prompt).

#### 4.1.3 Secret scanning

- **60+ provider patterns**: Stripe, Square, Shopify, GitHub PAT, AWS, Slack, Dynatrace, WordPress salts, etc. (port of secret patterns table starting line 2837).
- **Entropy-based detection** for high-entropy strings not matching a named pattern (port of `scanEntropySecrets`, line 1328 + `shannonEntropy`, line 1320).
- **Hardcoded-credential heuristics** (port of `scanCredentials`, line 1807): assignments to vars named `password`/`secret`/`api_key`/`token`/`auth` with literal RHS.
- **Output is masked by default** (`sk_live_xx****xx12`); raw values never written to disk or printed unless `--unmask` is passed.
- **TODO-near-security scanner** to surface `// TODO: fix auth` style comments next to security-sensitive code (port of `scanTodosNearSecurity`, line 1357).

#### 4.1.4 Data-classification overlay

- Tag findings whose touched fields match **PII / PHI / PCI / Confidential** patterns (port of `DATA_CLASSES` + `classifyEndpoint`, lines 52-54). Findings that touch regulated data classes are auto-bumped one severity tier.

### 4.2 Plugin surface (Claude Code integration)

The plugin will ship the standard Claude Code plugin layout:

```
agentic-security/
  .claude-plugin/
    plugin.json              # name, version, author=Ross Young / Clear Capabilities Inc.
    marketplace.json         # for marketplace listing
  commands/                  # user-invokable slash commands
    security-scan.md
    security-sca.md
    security-secrets.md
    security-fix.md
    security-fix-all.md
    security-threat-model.md
    security-report.md
    security-baseline.md
  hooks/
    hooks.json               # PostToolUse, PreToolUse(git commit), SessionStart wiring
  agents/
    security-fixer.md        # remediation subagent
    security-triager.md      # severity/exploitability scorer
    sca-malware-analyst.md   # per-component CLEAN/SUSPICIOUS/MALICIOUS verdict
  skills/
    sast-scan/SKILL.md
    sca-scan/SKILL.md
    secret-scan/SKILL.md
    fix-vulnerability/SKILL.md
  scanner/                   # the ported engine (Node 20+, ESM)
    package.json
    src/
      sast/
      sca/
      secrets/
      report/
      cli.ts
    test/
  README.md
  PRD.md                     # this document
  LICENSE
```

#### 4.2.1 Slash commands

| Command | Args | Behavior |
|---|---|---|
| `/security-scan` | `[path]` | Full scan of cwd or `path`; prints triaged report; writes `.agentic-security/last-scan.json` |
| `/security-sca` | `[path]` | SCA only |
| `/security-secrets` | `[path]` | Secret scan only |
| `/security-fix` | `<finding-id>` | Invokes `security-fixer` subagent on a single finding |
| `/security-fix-all` | `[--severity critical]` | Loops `security-fixer` over all findings at or above given severity |
| `/security-threat-model` | — | Renders STRIDE coverage table from last scan |
| `/security-report` | `[--format json\|md\|sarif]` | Re-renders the last scan in the chosen format |
| `/security-baseline` | `save\|diff` | Save current findings as baseline; later runs diff against it |

#### 4.2.2 Hooks

- **`PostToolUse` on `Edit`/`Write`/`MultiEdit`** — runs an incremental scan of just the touched file(s), adds a system-message-style note to the agent context if a new high/critical finding appears. Throttled to ≤1 invocation per 5s per file.
- **`PreToolUse` on `Bash` matching `git commit*`** — blocks the commit if any *new* critical finding appears versus baseline. User can override with `AGENTIC_SECURITY_BYPASS=1` in env.
- **`SessionStart`** — checks `.agentic-security/baseline.json` exists; if not, prints a one-line tip about running `/security-baseline save`.
- All hooks are **opt-in** via `plugin.json` settings; default install enables only the `PostToolUse` hook.

#### 4.2.3 Agents (subagents)

- **`security-fixer`** — receives a single finding (file, line, vuln, fix template). Reads the file, produces an Edit to remediate, runs `Bash(npm test)` or equivalent if test commands are configured. Mirrors the existing `FIXES` table (line 2730) for canonical patches.
- **`security-triager`** — given the raw finding list, scores exploitability (port of `scoreExploitability`, line 1563), dedupes (port of `dedupeFindingsWithEvidence`, line 1582), and applies sanitizer effectiveness (line 1541). Returns a sorted, deduped list.
- **`sca-malware-analyst`** — runs the per-component CLEAN/SUSPICIOUS/MALICIOUS prompt (line 2521) using the strict-grounding template already in `attacksurface.html`. Used by `/security-sca` when malware analysis is enabled.

#### 4.2.4 Skills

Skill files live under `skills/<name>/SKILL.md` and are auto-discovered by Claude Code. Each skill bundles knowledge of when to act and the exact CLI invocation.

- `sast-scan` — "Use when the user asks to find SQLi/XSS/RCE/IDOR/etc. in code."
- `sca-scan` — "Use when the user references CVEs, dependency vulnerabilities, or asks 'is this lib safe?'"
- `secret-scan` — "Use when the user asks about leaked credentials, hardcoded API keys, .env exposure."
- `fix-vulnerability` — "Use when the user wants Claude to remediate a finding."

### 4.3 Scanner CLI contract

The Node CLI is the engine; commands shell out to it.

```
agentic-security scan         [--path .] [--only sast|sca|secrets] [--format json|md|sarif] [--no-network]
agentic-security fix          --finding <id> [--apply]
agentic-security baseline     save|diff
agentic-security version
```

- Exit codes: `0` clean, `1` low/medium findings, `2` high, `3` critical, `4` execution error.
- JSON schema: `{ scanId, startedAt, durationMs, scanned: { files, lines }, findings: [{ id, kind: 'sast'|'sca'|'secret'|'logic'|'cipher'|'route', severity, vuln, cwe?, stride?, file, line, snippet, masked?, fix: { description, code }, dataClasses?: ['PII'|'PHI'|'PCI'|'Confidential'], reachable?: boolean, exploitability: 0..10 }] }`.
- SARIF output for GitHub Advanced Security / VS Code Problems pane compatibility.

### 4.4 Configuration

`~/.claude/agentic-security/config.json`:

```json
{
  "network": { "osv": true, "claudeMalwareAnalyst": false },
  "thresholds": { "blockCommitAt": "critical" },
  "ignore": [".min.js", "vendor/**", "third_party/**"],
  "ruleOverrides": { "Reflected XSS": "info" },
  "fileSizeLimitBytes": 500000,
  "maxLineAvgChars": 400
}
```

Repo-local overrides via `.agentic-security/config.json`.

---

## 5. Non-Functional Requirements

| # | Requirement | Target |
|---|---|---|
| NFR-1 | Cold scan throughput | ≥ 5,000 LOC/sec on M-series Mac |
| NFR-2 | Memory ceiling | ≤ 512 MB for ≤ 100k LOC repo |
| NFR-3 | False-positive rate | ≤ 15 % on a representative test corpus (matched against attacksurface.html baseline) |
| NFR-4 | Offline mode parity | SAST + Secrets identical to online; SCA gracefully degrades to stale cache |
| NFR-5 | Plugin install time | < 30 s (npm-installed scanner deps amortized once) |
| NFR-6 | First scan output | < 30 s on a 10k-LOC repo end-to-end |
| NFR-7 | No code transmitted off-machine | Source code never sent to OSV; only `purl` query strings. Malware-analyst LLM calls only fire when explicitly enabled in config. |
| NFR-8 | Reproducibility | Same input → same finding IDs (stable hash of `file:line:rule`) |

---

## 6. Engine port plan

The browser HTML embeds the scanner as a single `<script type="text/babel">` block. We will:

1. **Extract the JS** between line 50 (start of constants) and the end of `runFullScan` (~line 2700) into a Node ESM module.
2. **Replace browser-only deps**: `sessionStorage` → disk cache (`~/.claude/agentic-security/osv-cache/`); `JSZip` file iteration → `fast-glob` + `fs.promises.readFile`.
3. **Re-target Babel parser**: keep `@babel/parser` (works in Node) for the AST path; the regex path is environment-agnostic.
4. **Split into modules** under `scanner/src/`: `sast/`, `sca/`, `secrets/`, `report/`. Each function in §4.1 maps to one file with the same name.
5. **Tests**: snapshot-test the JSON output of each scanner against a fixture corpus checked into `scanner/test/fixtures/` (vulnerable + clean variants per rule).

---

## 7. Reporting & UX

- **CLI report**: ANSI-colored table grouped by severity, then by file. Each row shows `[SEV] CWE-XX  file:line  vuln-name` and a one-line fix hint. Full fix code is folded; user expands with `--verbose`.
- **Markdown report** (for paste into a PR): table per severity, code blocks for fixes, footer with scan metadata.
- **SARIF**: emit standard 2.1.0 format with `rules`, `results`, and `partialFingerprints` for stable diffing.
- **STRIDE coverage view** (`/security-threat-model`): table of S/T/R/I/D/E categories × counts, sourced from finding `stride` field.

---

## 8. Distribution & Branding

- **Plugin name:** `agentic-security`
- **Author:** Ross Young
- **Vendor:** Clear Capabilities Inc.
- **Marketplace listing:** `clearcapabilities/agentic-security` (or owner-of-record on the official Claude Code marketplace).
- **License:** Elastic License 2.0 — permits free use, modification, and redistribution but prohibits offering the software as a hosted/managed service to third parties.
- **`plugin.json` minimum:**

```json
{
  "name": "agentic-security",
  "version": "0.1.0",
  "description": "Defensive AppSec for Claude Code: SAST, SCA, and Secret scanning with auto-remediation.",
  "author": { "name": "Ross Young"},
  "vendor": "Clear Capabilities Inc.",
  "homepage": "https://github.com/clearcapabilities/agentic-security",
  "keywords": ["security", "sast", "sca", "secrets", "cve", "osv", "claude-code"]
}
```

---

## 9. Milestones

| M | Deliverable | Target |
|---|---|---|
| M0 | Scaffold plugin layout (`plugin.json`, dirs) and import the HTML scanner code into `scanner/src/` | Week 1 |
| M1 | Working `agentic-security scan` CLI; SAST + Secrets parity with `attacksurface.html` on fixture corpus | Week 2-3 |
| M2 | SCA online + offline; OSV cache on disk; vulnerable-function-call depth | Week 4 |
| M3 | `/security-scan`, `/security-sca`, `/security-secrets` slash commands wired up; `PostToolUse` hook | Week 5 |
| M4 | `security-fixer` agent with `FIXES` table; `/security-fix` command | Week 6 |
| M5 | SARIF + Markdown reporting; baseline + diff | Week 7 |
| M6 | Public 0.1 release on Claude Code marketplace | Week 8 |

---

## 10. Verification

- **Unit / snapshot tests** per scanner module against `scanner/test/fixtures/` (vulnerable + safe variants for every CWE in `SINK_PATTERNS` and `STRUCTURAL_PATTERNS`).
- **Parity test**: run both `attacksurface.html` (via headless browser) and the new Node CLI on a corpus of public vulnerable apps (Juice Shop, DVWA, NodeGoat, Vulpy) — finding sets must match within ±5 %.
- **Performance test**: scan a 100k-LOC monorepo; assert NFR-1/NFR-2.
- **Plugin smoke test**: `claude --print "/security-scan"` in a known-bad fixture repo; assert exit code == 3 (critical) and JSON output validates against schema.
- **Hook test**: simulate an `Edit` introducing `eval(req.body.x)`; assert PostToolUse hook fires and finding surfaces.

---

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| OSV API rate limits | SCA stalls on large repos | Disk-cache results 7 days; batch in chunks of 1000 (already in source) |
| Babel parser fails on exotic syntax | SAST loses AST path, falls back to regex | Already implemented in `performAnalysis` (line 588) |
| Plugin permission prompts annoy users | Adoption friction | Ship a recommended `permissions.allow` list for the scanner CLI |
| HTML extraction introduces bugs | Regression vs. proven analyzer | Snapshot-parity test gate in CI |
| LLM malware-analyst calls cost money | Surprise billing | Off by default; clearly gated by config |
| Source code leakage via OSV calls | Privacy violation | Only purls (package@version) sent — no source ever — and `--no-network` flag |

---

## 12. Open Questions

1. Should the plugin offer auto-fix at commit time (block + propose patch) or only on explicit `/security-fix`? *Recommendation: explicit only in v1, opt-in auto-fix in v2.*
2. Do we ship the full `FIXES` corpus inline, or fetch it from a versioned remote? *Recommendation: inline in v1.*
3. Should `security-fixer` run tests after each fix? *Recommendation: yes, when a `test` script is detected in `package.json` / `pyproject.toml`.*
4. Marketplace listing: under `clearcapabilities` org or under Ross's personal namespace? *Pending decision.*
5. Telemetry — opt-in anonymized counts of findings (no source, no paths)? *Recommendation: deferred to v2.*

---

## 13. References

- Source analyzer: `attacksurface.html` (4,146 lines, repo root) — all engine logic ported from here.
- OSV API docs: https://google.github.io/osv.dev/api/
- Claude Code plugin docs: https://docs.claude.com/en/docs/claude-code/plugins
- SARIF 2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html