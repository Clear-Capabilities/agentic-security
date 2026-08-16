# demo-app — deliberately vulnerable. Never deploy this.

> ⚠️ **This tiny app is intentionally insecure.** It exists so the
> [quickstart](../../docs/guides/quickstart.md) and every how-to guide have a
> guaranteed, reproducible set of findings to scan, triage, and fix. Do not
> copy patterns from it. Do not run it anywhere reachable from a network you
> care about. There are no real credentials in here.

A ~10-file "mini SaaS" — an Express API with a checkout flow, an AI product
assistant, a Python reporting job, and a Dockerfile. Every file demonstrates
at least one vulnerability class the scanner detects:

| File | What it demonstrates |
|---|---|
| `server.js` | SQL injection (string concat into a query), missing auth on a state-changing route (every other route checks, `DELETE /orders/:id` doesn't), `eval` on user input |
| `auth.js` | Passwords hashed with MD5 (a deterministic zero-LLM fix — the quickstart fixes this one), a hardcoded API key |
| `ai-assistant.js` | Prompt injection — untrusted user input interpolated straight into an LLM prompt |
| `report.py` | SQL injection in Python (f-string into `cursor.execute`) |
| `Dockerfile` | Container hygiene — unpinned base image, `ADD` of a remote URL, runs as root |
| `package.json` | A dependency pinned to a version with a known published vulnerability (SCA / SBOM / CVE-alert demos) |

Scan it from the repo root:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app
```

The expected findings are pinned by `scanner/test/demo-app.test.js` — if a
detector change would alter what this app produces, CI fails rather than
letting the tutorials drift.
