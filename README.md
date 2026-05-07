# agentic-security

**The easy button for AI-coded apps that don't get hacked.**

You ship fast. Your AI writes great code, most of the time. But sometimes it writes a login endpoint that anyone can break in 30 seconds, or hardcodes an API key that ends up on GitHub. Two weeks later you get a security report — or worse, a *very* angry email.

`agentic-security` runs **inside your Claude Code session**, scans your code for the kinds of mistakes AI agents (and humans) make, and **fixes them** — same session, same agent, before you've moved on.

```
You:    Add a /search endpoint that lets users query products by name.
Claude: (writes code; one of the queries glues user input straight into SQL)
agentic-security: ⚠ 1 new high-severity finding from this edit
                  [HIGH] CWE-89 SQL Injection (routes/products.js:42)
You:    /security-fix-all --severity high
Claude: (rewrites to use a parameterized query, re-runs the scan, finding gone)
```

That's the whole pitch. Below: install, the 5 commands you'll actually use, and a hands-on tutorial that takes a famous-for-being-broken app and fixes it live.

[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-24%2F24%20passing-success)]()
[![Bundle](https://img.shields.io/badge/bundle-1.9MB%20single%20file-orange)]()

---

## What this protects you from, in plain English

| Thing it catches | Why you care |
|---|---|
| **SQL injection** | Someone types `' OR 1=1` into your login form and reads your entire user table. |
| **Hardcoded secrets** | Your Stripe key ends up on GitHub. You wake up to a $4,000 bill from someone fraud-charging your account. |
| **Cross-site scripting (XSS)** | A "comment" on your blog runs JavaScript in every visitor's browser and steals their session cookie. |
| **Path traversal** | Someone asks for a file called `../../../etc/passwd` and your server happily serves it up. |
| **Command injection** | A "search" form lets users run shell commands on your server. Game over. |
| **Weak password storage** | You hashed passwords with MD5 like it's 1999. Attacker who steals your DB can crack them all in minutes. |
| **Vulnerable dependencies** | A package you `npm install`'d six months ago has a remote-code-execution bug. You don't even know which line of yours uses it. |
| **Privileged containers / public S3 buckets / IAM `*` policies** | Your Terraform/Dockerfile/Kubernetes manifest accidentally puts your data on the public internet. |

40+ vulnerability types covered out of the box. Catches them in your code, your dependencies, your secrets, *and* your infrastructure files.

---

## Install (60 seconds)

If you use **Claude Code**:

```
/plugin marketplace add clearcapabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

That's it. Now run one more command **in the project you want to protect** to unlock the short command names:

```
/agentic-security:security-setup
```

This creates project-level shortcuts so you can type `/security-scan` instead of `/agentic-security:security-scan`. Run it once per project — it takes about a second and just writes a few files into `.claude/commands/`.

> **Why the extra step?** Claude Code mounts plugin commands under a namespace (`/agentic-security:...`). The setup command installs plain shortcut files at the project level so the short names work. This is a one-time thing per project.

If you want to run it from the terminal (CI, pre-commit, scripts):

```bash
curl -L -o agentic-security.mjs \
  https://raw.githubusercontent.com/clearcapabilities/agentic-security/main/scanner/dist/agentic-security.mjs
chmod +x agentic-security.mjs
node agentic-security.mjs scan .
```

It's one self-contained 1.9 MB file. No `npm install`, no dependencies on the target machine.

---

## The 5 commands you actually need

```
/security-scan                     ← scan everything, see what's broken
/security-fix-all --severity high  ← let Claude fix the high-severity stuff
/security-baseline save            ← "this is my starting point — only show NEW problems"
/security-report --format html     ← make a pretty report you can share
/security-secrets                  ← just look for leaked passwords / API keys
```

That's the whole UI. The other commands (`/security-fix <id>`, `/security-sca`, `/security-threat-model`, `/security-report`) are useful but you can ignore them until you need them.

---

## Tutorial: Take a deliberately-broken app and fix it

There's a project called [**OWASP Juice Shop**](https://github.com/juice-shop/juice-shop) — an app *intentionally* full of security mistakes, used to teach hacking. We're going to point our scanner at it, find a few hundred real bugs, fix some, and watch the score drop.

You'll need: Claude Code with this plugin installed, and a terminal.

### Step 1 — grab the broken app

```bash
git clone https://github.com/juice-shop/juice-shop ~/code/juice-shop
cd ~/code/juice-shop
```

### Step 2 — scan it

In Claude Code:

```
/security-scan ~/code/juice-shop
```

You'll see something like this:

```
Agentic Security — 302 findings across 455 files       (18.8s scan)

  Critical    102
  High        118
  Medium      81
  Low         1

  Top problems:
    33×  Unsafe Reflection / Remote Code Execution
    33×  IDOR — anyone can read anyone else's stuff
    26×  SQL Injection
    15×  Cross-site scripting
    12×  Hardcoded passwords / API keys
```

302 real bugs found. Don't panic — most of them are clustered in a handful of files. Welcome to a real codebase.

### Step 3 — see them in a pretty report

```
/security-report --format html --output ~/code/juice-shop/before.html
open ~/code/juice-shop/before.html
```

Your browser opens a self-contained page with:
- A severity bar chart
- A filterable list (search by file, vuln name, or CWE — type "SQL" to see all SQL injections)
- Click any finding to expand and see the code, the fix, and what to do
- A "STRIDE" overview showing what categories of attack you're vulnerable to

It's one HTML file with no external dependencies. Email it, drop it in Slack, attach to a PR — works anywhere.

### Step 4 — let Claude fix the worst stuff

Now the magic. Pick a category — let's say all the **critical** ones — and have Claude fix them in one go:

```
/security-fix-all --severity critical
```

Claude reads each finding, finds the file, applies the canonical fix (parameterized queries instead of string concatenation, `bcrypt` instead of `MD5`, `execFile` with an args array instead of `exec` with a string), and re-runs the relevant tests. It works through them serially because fixing one bug can change another.

You'll see Claude work through dozens of fixes. Each one shows up as a normal Edit you can review or revert.

### Step 5 — see the score drop

```
/security-scan ~/code/juice-shop
```

You should see the critical count drop from **102** to a much smaller number — sometimes 0, depending on how many edge cases the fixer hit. Some critical findings need human judgment (the fixer subagent declines them and says why); those stay as TODOs for you.

### Step 6 — lock in your progress

```
/security-baseline save
```

This captures the current set of findings as your "I know about these, don't yell at me about them again" list. Future scans only report **new** findings that show up after this point. The pre-commit hook (if you enable it) will block commits that introduce new critical bugs.

### Step 7 — generate the after-report

```
/security-report --format html --output ~/code/juice-shop/after.html
open ~/code/juice-shop/after.html
```

Open `before.html` and `after.html` side by side. The graphs tell the whole story.

### What just happened

In about 10 minutes, you:

1. Took an app with 302 known security holes.
2. Found them all automatically.
3. Got a sharable report showing exactly what was wrong and why.
4. Had your AI assistant fix the worst category in batch.
5. Generated a "before" and "after" you can show your team / boss / clients.

The same loop works on your real code. Try it on whatever you're shipping next.

---

## What makes this different from the other security scanners?

A lot of scanners exist (Snyk, Semgrep, npm audit, gitleaks). Most of them yell at you. Ours is built to actually be useful in an AI-assisted workflow. Concretely:

### It knows the difference between a real bug and a false alarm

```js
// Most scanners scream "CRITICAL — weak password hashing!"
const cacheKey = crypto.createHash('md5').update(JSON.stringify(args)).digest('hex');

// Our scanner: "info — this MD5 is a cache key, not a password. Carry on."
```

We look at the variable names and surrounding code to figure out if the weak-crypto call is actually doing something security-sensitive (hashing a password) or something benign (generating a cache key, ETag, or content fingerprint).

### It catches sneaky mistakes that name-matching scanners miss

```js
// Most scanners: "downgraded — looks like there's an escapeHtml call here"
escapeHtml(req.query.q);
res.send(req.query.q);   // ← but the unsanitized version is what actually gets sent!

// Our scanner: "high severity — sanitizer return was thrown away"
```

We follow the actual data flow. Calling a sanitizer doesn't help if you don't use the result.

### It doesn't yell about your test fixtures, translations, or example values

```js
// __tests__/auth.spec.js
const mockUser = { password: "test" };       // ← naive scanners flag this

// locales/fr.json equivalent
labels.password = "Mot de passe oublié?";   // ← and this

// docs/sample.md
api_key: "your-api-key-here"                 // ← and this

// All three: silently suppressed.
```

We have a four-layer filter that covers paths (test/, locales/, examples/, etc.), variable names (`placeholder`, `label`, `mockUser`...), values (`"your-..."`, `"changeme"`, `"<...>"`, `"TODO"`), and JSX/HTML attribute context.

### It tells you which CVEs are actually being exploited right now

When a vulnerable dependency CVE shows up, we pull the **EPSS** (Exploit Prediction Scoring System) score from FIRST.org. So instead of two CVEs both labeled "high":

```
[high] CVE-2024-0123  exploitability: 87%   ← attackers are using this RIGHT NOW
[high] CVE-2024-0456  exploitability: 2%    ← theoretical, fix later
```

You know which one to fix first.

### It works on more than just your JavaScript

Code: JS, TypeScript, Python, PHP, Ruby, Java, Go, Vue, React, Angular, Svelte.
Dependencies: npm, yarn, pnpm, pip, poetry, Pipfile, composer, Gemfile, go.mod, Cargo, Maven, Gradle, pubspec — 20 manifest formats.
Infrastructure: Dockerfile, docker-compose, Kubernetes manifests, Terraform, Helm charts, GitHub Actions workflows.

### It never sends your code to a server

The only network call we make is to OSV.dev for known-CVE lookup, and we send only `package@version` strings — never your source. You can disable even that with `--no-network`. Compare to most cloud-based scanners which require uploading your entire codebase.

---

## Common workflows

### Pre-commit: block bad code from ever landing

After running `/security-baseline save` once, set up the pre-commit gate so any *new* critical bugs fail the commit:

```bash
# .git/hooks/pre-commit (already wired up if you use the Claude Code plugin)
#!/bin/sh
node /path/to/agentic-security.mjs baseline diff "$(git rev-parse --show-toplevel)"
```

Or just enable the `PreToolUse` hook from the plugin (it does the same thing for any `git commit` Claude tries to run).

### Pull-request gate (GitHub Actions)

Add to `.github/workflows/security.yml`:

```yaml
name: Security
on:
  pull_request: {}
  push: { branches: [main] }

jobs:
  security:
    permissions:
      contents: read
      security-events: write   # for the SARIF upload to GitHub Security
      pull-requests: write     # for the PR comment with findings
    uses: clearcapabilities/agentic-security/.github/workflows/scan.yml@main
    with:
      fail-on: critical
      baseline: ${{ github.event.pull_request.base.sha || 'HEAD~1' }}
```

You get a comment on every PR with the severity counts and top critical/high findings, plus findings show up in the GitHub Security tab.

> **Common stumbling block:** if your CI fails with "Error calling workflow ... is requesting 'pull-requests: write' but is only allowed 'pull-requests: none'" — the `permissions:` block above is required. GitHub's reusable workflows can only use permissions the calling job grants.

### Scan only what changed (fast monorepo mode)

Don't re-scan your whole 100k-LOC monorepo on every commit:

```bash
node agentic-security.mjs scan . --changed-since HEAD~5
```

It uses `git diff` to figure out what's new and only scans those files. Drops scan time from minutes to seconds.

---

## Frequently asked questions

**Will this work on my codebase?**
If you're writing JavaScript, TypeScript, Python, PHP, Ruby, Java, Go, or any modern web framework — yes. Plus your Dockerfiles, Terraform, K8s manifests, and CI workflows.

**Does it run in the cloud? Will my code leave my machine?**
No. The scanner runs entirely on your machine. The only network call is to a public CVE database (OSV.dev), and we send only package names + versions, never source code. Pass `--no-network` to skip even that.

**What if it tells me there's a bug but I disagree?**
Two options. (1) Run with `--include-suppressed` to see what we're already filtering out, so you trust the recall. (2) Add a `.agentic-security/rules.yml` file to your repo with custom suppressions:

```yaml
suppressions:
  - rule: "MD5/SHA1 Password Hashing"
    files: ["legacy/auth-v1.js"]
    reason: "Migrating to bcrypt in Q3; tracked in JIRA-1234"
```

We'll skip that finding on those files and log the reason for audit.

**Can I add my own rules?**
Yes. Same `rules.yml` file:

```yaml
sources:
  - pattern: 'getCurrentUser\(\)'
    label: 'session.user'
sinks:
  - pattern: 'db\.executeRaw\('
    vuln: 'SQL Injection (Custom)'
    severity: high
```

**The scanner thinks `https://example.com/{user_input}` is a SSRF risk but it's actually fine because we allowlist the host.**
Tell us which sanitizer you use:

```yaml
sanitizers:
  - pattern: 'isAllowedHost\('
    type: 'custom-host-allowlist'
```

**What happens if I disagree with a fix Claude applies?**
Just `git diff` and revert. Every fix is a normal edit you can review.

**How is this different from `npm audit`?**
`npm audit` reports every CVE in your dependency tree, including ones in code paths you don't actually use. We filter by *vulnerable-call-depth* — if your code never imports the affected function, the CVE gets downgraded. Result: a lot less noise. We also cover 19 other dependency formats besides npm.

**My CI just told me "302 findings."**
Yeah, that's a real codebase. That's why `/security-baseline save` exists. Run it once, commit the baseline file, and from that day forward you only see *new* problems.

**Does this work on legacy code I didn't write?**
Yes — that's actually where it shines. Run a scan, save a baseline, fix the easy stuff, and the gate prevents regressions while you tackle the hard stuff over time.

---

## Troubleshooting

**"Unknown command: /security-scan"** — you haven't run the setup step yet. In the project where you're seeing the error, run:
```
/agentic-security:security-setup
```
This installs the short-form shortcuts. You only need to do it once per project.

**"Cannot find package 'fast-glob'"** — your plugin install is from before v0.2.0. Update:
```
/plugin marketplace update clearcapabilities
/plugin install agentic-security@clearcapabilities
```

**The CI workflow is rejected** with `requesting 'pull-requests: write' but only allowed 'none'` — add the `permissions:` block to your job (see the GitHub Actions example above). Reusable workflows can only use permissions the calling job has granted.

**The scan is slow on a huge monorepo** — pass `--changed-since HEAD~5` (or whatever git ref makes sense) to scan only modified files.

**I want to see what got filtered out** — run with `--include-suppressed --format json` and look at the `suppressed` array. Each entry has a `reason` code so you know why.

---

## For the security folks (the depth is here when you need it)

Everything above is the friendly version. If you're a security engineer who wants the technical specs, the comparison table vs Snyk / Semgrep / Checkmarx, the per-CWE coverage list, the architecture, and the algorithmic details — see the [GitHub issues](https://github.com/clearcapabilities/agentic-security/issues?q=is%3Aissue+label%3Afp-reduction) for the 8 false-positive-reduction PRDs (each is a self-contained spec showing exactly what we do differently and why).

Topline numbers:

- **AST-based taint tracking** for JS/TS via `@babel/core` (cross-file BFS up to 5 hops, with a `chain` field showing the full source→propagation→sink path).
- **In-file inter-procedural taint** for Python via regex propagation.
- **Vulnerable-call-depth filter** on every CVE — only flag CVEs in code paths you actually call.
- **EPSS + CVSS overlay** so CVEs sort by real-world exploitation probability, not just catalog severity.
- **4-gate FP filter** on hardcoded credentials (path / variable name / value heuristic / JSX-attr context).
- **Structural recognizers** for high-entropy non-secrets (UUIDs, hex digests, integrity hashes, JWT samples).
- **MD5/SHA1 context-aware** classifier (security vs fingerprint vs unknown).
- **Sanitizer effectiveness by data-flow** — bare `escapeHtml(s);` doesn't trigger a downgrade if the return is discarded.
- **Single self-contained 1.9 MB ESM bundle** (`scanner/dist/agentic-security.mjs`); no npm install, no node_modules at runtime.
- **CWE coverage**: 22, 78, 79, 89, 94, 113, 200, 204, 208, 209, 250, 307, 311, 321, 327, 330, 338, 347, 362, 367, 434, 470, 489, 502, 601, 611, 614, 620, 639, 732, 798, 829, 840, 862, 863, 915, 916, 918, 942, 943, 1004, 1321, 1333, 1336.
- **STRIDE coverage** auto-tagged on every finding (Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege).

---

## License & author

[**Elastic License 2.0**](./LICENSE) — free for any use including commercial products and internal tools. The one thing you can't do is offer the software as a hosted service to other people. Email if you want a different arrangement.

Built by **Ross Young** at [**Clear Capabilities Inc.**](https://clearcapabilities.com) — ross@clearcapabilities.com.

Built specifically for the moment in software where AI agents write most of the code. The same agent that writes your code should be the one that secures it.

---

<sub>If this saved you from shipping a vulnerability, star the repo on [GitHub](https://github.com/clearcapabilities/agentic-security) and tell another vibe coder.</sub>
