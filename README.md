# agentic-security 🛡

**The Claude Code Plugin that Catches what your AI Assistant Misses.**

> Created by **[ClearCapabilities.Com](https://clearcapabilities.com)** · runs inside Claude Code · local-first · free for solo devs

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.16.0-blue)]()

---

## What is this?

Your AI assistant is fast. It is also confidently wrong about security. It glues `req.body.userId` into SQL queries, commits API keys to `.env.example`, and writes JWT code that accepts the `none` algorithm. You don't find out until much later. Or someone else does first.

`agentic-security` lives inside Claude Code. Every time you (or Claude) saves a file, it checks. Every time you say "am I done?", it can tell you with a single verdict. Most fixes it can apply for you, automatically.

```
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
  • 0 critical · 0 high · 2 advisory
  🛡  agentic-security · created by ClearCapabilities.Com
```

That's the whole pitch. Two paths to use it, depending on what you are.

---

## 🎨 Path 1 — "I just want to ship" (vibecoders)

You build apps with Claude. You don't know what STRIDE means and you don't want to. You want one command that tells you you're good, or tells you exactly what to fix.

#### Three commands, that's the whole tool

```bash
/security-onboard         # 30-second wizard, sets things up
/ship                     # safe to deploy? yes/no
/fix 1                    # if not safe, apply the fix it suggested
```

That's it. Skip everything else on this page.

#### Example: Claude just wrote a login route

```javascript
// Claude wrote this. Looks fine?
app.post('/login', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
  // ...
});
```

You run `/ship`. It says:

```
❌  Not safe to deploy

1 thing to fix:

  1. routes/login.ts:34  —  User input goes straight into a database query
     - db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
     + db.query('SELECT * FROM users WHERE email = $1', [req.body.email])
     Why: Lets an attacker dump your entire users table.

  Run /fix 1 to apply the fix automatically.
```

You run `/fix 1`. The code is patched. The next `/ship` says ✅. You deploy.

#### The five things this tool catches that Claude misses most

1. **SQL injection** — user input glued into queries. The #1 AI-generated bug.
2. **Hardcoded secrets** — API keys in `.env.example` or right in code.
3. **Authorization holes** — `req.body.userId` used as the "owner check."
4. **JWT misuse** — weak secrets, missing algorithm pinning, `none` allowed.
5. **Prompt injection** — user input concatenated into your LLM's system prompt.

You don't need to remember these. The tool does.

**[Full vibecoder guide →](docs/for-vibecoders.md)**

---

## ⚙️ Path 2 — "I'm a software developer"

You know how to code. You may or may not know deep AppSec, but you know what false positives feel like. You want CI/CD integration, SARIF, real numbers vs. industry benchmarks, and the ability to write your own rules.

#### Set the mode

```bash
agentic-security profile set pro
```

That flips the defaults: full taxonomy visible (CWE/CVSS/OWASP/MITRE), confidence threshold lowered (0.9 → 0.3), all 37+ commands accessible, machine output always written.

#### Daily workflow

```bash
agentic-security scan                              # human-readable terminal table
agentic-security scan --columns mitre              # add ATT&CK technique column
agentic-security triage list --severity critical   # state machine across scans
agentic-security org-scan --repos a,b,c            # fleet scan
```

Every scan automatically writes:

```
.agentic-security/
├── findings.json     ← normalized, programmable
├── findings.sarif    ← upload to GitHub Security tab
└── findings.csv      ← spreadsheet / BigQuery / executive reports
```

#### CI/CD in one snippet

```yaml
- run: npx @clearcapabilities/agentic-security-scanner scan . --format sarif --output security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: security.sarif }
```

#### F1 vs. industry benchmarks

| Benchmark | F1 |
|---|---|
| Synthetic (in-tree) | 100.0% |
| OWASP Benchmark (Java, 1415 tests) | 96.7% |
| NIST SARD Juliet (Java, 28k tests) | 100.0% |
| OWASP Juice Shop (TypeScript) | 100.0% |
| Snyk Goof (JavaScript) | 100.0% |
| OWASP NodeGoat (JavaScript) | 100.0% |

Methodology and per-family numbers in [docs/PRD-benchmark-f1.md](docs/PRD-benchmark-f1.md).

**[Full developer guide →](docs/for-appsec-pros.md)**

---

## Install (both paths)

#### As a Claude Code plugin

```bash
# In your Claude Code session:
/plugin install agentic-security
```

That installs the slash commands (`/ship`, `/security-scan-all`, `/fix`, etc.) and the file-edit hook that scans changed files on save.

#### As a standalone CLI

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

No install. Runs offline after the first OSV pull. Works in any project, any language, any CI.

---

## How it actually works (the curious dev's version)

Behind the friendly verdict is a real scanner:

- **SAST** — taint analysis on JS / TS / Python / Java. Tracks user input from HTTP source to dangerous sink (database, shell, response).
- **SCA** — dependency CVEs from [OSV.dev](https://osv.dev), with function-level reachability so you only see bugs in code you actually call.
- **Secrets** — 50+ credential patterns plus high-entropy heuristics. Allowlist-aware so it doesn't fire on test fixtures.
- **IaC** — Dockerfile EOL base images, GitHub Actions floating tags, K8s privileged containers.
- **LLM security** — OWASP LLM Top 10 (2025): prompt injection, sensitive disclosure, system prompt leakage.

Each finding ships with three things: where it is, why it's bad, and the patch to fix it. No 50-tab spreadsheet of "advisory" findings.

---

## Things you can do once you're hooked

| Want to | Run |
|---|---|
| Get a single A–F grade | `/security-grade` |
| Generate an HTML report | `/security-report` |
| Bundle fixes into one PR | `/security-fix-pr` |
| Get a CycloneDX SBOM | `/security-sbom` |
| Map your scan to OWASP LLM Top 10 | `/security-llm-threat-model` |
| Generate a SOC 2 attestation | `/soc2` |
| Get a NIST AI 600-1 attestation | `/nist-ai-600-1` |
| Build an exploit demo | `/security-poc` |
| Audit your GitHub Actions | `/security-pipeline` |
| Show off a badge in your README | `/security-badge` |

Run `/security-help` to see all of them organized by category.

---

## License

Free for solo developers and teams of ≤ 10. Bigger teams emailing about a per-seat license: **[ross@clearcapabilities.com](mailto:ross@clearcapabilities.com)**.

Full legal terms in [LICENSE](./LICENSE). The one-sentence version: *don't resell this, don't reverse-engineer it, otherwise use it however you want.*

---

## Built with care by ClearCapabilities

🛡 **[ClearCapabilities.Com](https://clearcapabilities.com)** — we build security tooling that gets out of your way.

If you find a bug, [open an issue](https://github.com/clearcapabilities/agentic-security/issues). If you need enterprise support, integrations, or custom rules — email us.

Stay shipping. Stay safe. ✨
