# Quickstart — your first 15 minutes

By the end of this you'll have scanned a real (deliberately vulnerable) app,
read the verdict, fixed a finding with the fix verified before it touched disk,
and exported a shareable report. No security background needed.

**You need:** Node.js ≥ 24. That's it. (Claude Code is recommended but not
required — both paths are shown at each step.)

---

## 1. Install

**In Claude Code (recommended):**

```text
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
/plugin install agentic-security@clearcapabilities
```

The first line registers the marketplace; the second installs the plugin. Then
restart Claude Code or run `/reload-plugins`.

**In your terminal (no Claude Code):**

Nothing to install — every command below can run through `npx`:

```bash
npx @clear-capabilities/agentic-security-scanner --help
```

---

## 2. Scan the demo app

This repo ships a small, intentionally insecure app at
[`examples/demo-app/`](../../examples/demo-app/) so your first scan is
guaranteed to find something. Clone this repo (or point the scanner at it) and
run:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app
```

In Claude Code, the equivalent is `/agentic-security:scan examples/demo-app`.

---

## 3. Read the verdict

You'll see something like this:

```text
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  • 1 critical · 6 high · 20 advisory

  How many do you want to fix?

     1. Critical only                (1 fix)
     2. Critical + High              (7 fixes)
     4. All                          (14 fixes)

  Coverage: 6 files · flow=[js,py]
```

What each part means:

- **The verdict line** — `❌ Not safe to deploy` when at least one *critical*
  or *high* finding is open. A clean project shows `✅ Safe to deploy`. If zero
  findings remain but the scan finished incompletely (e.g., a file timeout), the
  verdict is `⚠️  Scan incomplete — cannot confirm safe to deploy`, which fires
  when `scanHealth.status !== 'complete'` even with no findings.
- **Severity counts** — `critical` and `high` are what you act on first;
  `advisory` (medium/low/info) is everything else, folded into one number so the
  headline stays readable.
- **Coverage** — which files and which flow-analysis languages were exercised,
  so you can see it looked at the whole app, not just where a finding happened
  to fire.

**Exit codes** (useful in scripts/CI): `0` clean · `1` low/medium ·
`2` high · `3` critical · `4` the scan itself errored. So a critical finding
makes the command exit `3`, not `0`.

To see every finding with its id, add `--format json` (or, in Claude Code, run
`/agentic-security:triage --show`):

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app --format json --output findings.json
```

Each finding explains itself in plain English — the stakes and the fix, not a
CVE number. For example, the SQL injection in `server.js`:

```text
[high] SQL Injection (db.query)          server.js:11
  The order id from the URL is put straight into the SQL query, so a crafted
  id can read or change any row in the table.
  Fix: use a parameterized query — db.query('… WHERE id = ?', [req.params.id])
```

---

## 4. Fix a finding — verified before it's written

The demo app hashes passwords with MD5 (`auth.js:11`). Here's the loop.

**In Claude Code** (the guided path):

```text
/agentic-security:triage --explain crypto-weak-hash:auth.js:11
/agentic-security:fix --finding crypto-weak-hash:auth.js:11
```

`--explain` shows why it fired, the data-flow trace, and the recommended fix.
`fix` composes the patch and — this is the important part — **runs it through a
verification gate before writing anything**: the file is re-scanned to confirm
the finding is gone, the change must introduce no new finding of medium
severity or higher, and your linter must still pass. A patch that fails the
gate is never written. If the scan built a proof-of-concept for the finding, a
regression test ships with the fix — it fails before the patch and passes
after.

**In the terminal:** the bare CLI applies a fix only when the finding carries a
ready-made replacement:

```bash
npx @clear-capabilities/agentic-security-scanner fix --finding <id> --preview --root examples/demo-app
```

For findings that need a composed patch (most of them), the verified fix loop
runs inside Claude Code via the command above — that's the primary path.

Everything is revertible: `agentic-security undo` rolls back the most recent
applied fix.

> The demo app is a fixture — don't commit fixes to it. Practice the loop, then
> run it on your own code (step 6).

---

## 5. Export a shareable report

Any scan can emit a self-contained HTML page — severity charts, a filterable
findings table, no external resources — that you can hand to a teammate:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app --format html --output report.html
# open report.html
```

Other formats: `json`, `md`, `sarif` (for GitHub Code Scanning / IDE SARIF
viewers), `csv`.

---

## 6. Now your own project

```bash
cd your-project
npx @clear-capabilities/agentic-security-scanner secure .
```

`secure` looks at your project and tells you the single best next step — scan,
fix, or (if it's already clean) prove it. In Claude Code, just run
`/agentic-security:secure`.

**Working on a large or legacy codebase?** A first scan can surface a lot at
once. Snapshot the existing findings as a baseline and see only what's *new*
from then on:

```bash
npx @clear-capabilities/agentic-security-scanner scan . --set-baseline
# … later …
npx @clear-capabilities/agentic-security-scanner scan . --since-baseline
```

---

## Troubleshooting

**`sh: agentic-security-scanner: command not found` (from `npx`)** — usually a
stale `npx` cache from an earlier interrupted install. Clear it and pin the
version so `npx` can't silently reuse a broken cached copy:

```bash
npx clear-npx-cache   # or: rm -rf ~/.npm/_npx
npx -y @clear-capabilities/agentic-security-scanner@latest scan .
```

If it still fails, install globally instead — this sidesteps `npx`'s
package-to-command resolution entirely:

```bash
npm install -g @clear-capabilities/agentic-security-scanner
agentic-security scan .
```

**`node @clear-capabilities/agentic-security-scanner ...` →
`Cannot find module '.../@clear-capabilities/agentic-security-scanner'`** —
`node` takes a file path, not a package name; that's what `npx` (or the
`agentic-security` bin, once installed) is for. Use one of the two commands
above, not `node` directly, unless you're running from a local clone of this
repo — see [`scanner/CLAUDE.md`](../../scanner/CLAUDE.md) for that case.

---

## Where to next

- [Scanning in depth](scanning.md) — every scan mode, output format, and how to read findings
- [Fixing vulnerabilities](fixing-vulnerabilities.md) — the triage → fix → verify loop in full
- [SBOM & AI-BOM](sbom-and-ai-bom.md) — inventory your dependencies and AI components
- [Compliance reports](compliance.md) — technical-control evidence for compliance frameworks
- [CI setup](ci-setup.md) — gate every pull request
- [Responding to a leaked secret](leaked-secrets.md) — the rotation playbook
