---
name: secret-scan
description: Use when the user asks about leaked credentials, hardcoded API keys, .env exposure, or "are there any secrets committed to this repo?". Also use before a public release or before committing a config file. Skip when the user is asking about generic vulnerabilities (use sast-scan) or CVEs (use sca-scan).
---

# Secret scanning with agentic-security

60+ provider patterns + entropy-based detection. Output is **always masked** by default (`sk_live_xx****xx12`); raw values are never written to disk or printed unless `--unmask` is set.

## When to invoke

- User asks about leaked / hardcoded / exposed secrets
- User adds a new `.env`, `config.yaml`, or credential-shaped file
- User runs `git log -p -S "<provider-prefix>"` and finds something
- User is about to publish to npm / PyPI / Docker Hub

## How to invoke

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <path> --only secrets --format cli
```

For machine-readable output:
```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan <path> --only secrets --format json | jq '.findings[] | select(.kind=="secret")'
```

## What gets detected

- Provider patterns: Stripe, Square, Shopify, AWS, GitHub PAT, Slack, Dynatrace, WordPress salts, OAuth secrets, JWT tokens, private keys (PEM headers), and ~50 more
- Entropy-based catch-all for high-entropy literals not matching a named pattern
- Hardcoded-credential heuristic for `password = "..."` / `api_key: "..."` style assignments
- TODO-near-security: surfaces `// TODO: rotate` style comments adjacent to credential code

## What to do with a real hit

1. **Treat the credential as compromised.** Rotate it at the provider IMMEDIATELY — do not wait for cleanup.
2. **Move the value out of source.** Use environment variables, a secrets manager, or .env (gitignored).
3. **Audit history.** `git log -p -S "<masked-fragment>"` to find prior exposure.
4. **Force-push only if you understand the consequences** — the credential is already public the moment it hit a remote.
