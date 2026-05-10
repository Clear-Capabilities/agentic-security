---
description: Deep auth/authZ audit — JWT algorithm confusion, hardcoded JWT secrets, OAuth2 PKCE/redirect_uri validation, multi-tenant cross-row reads, session fixation. Covers OWASP A01 (Broken Access Control) — the #1 source of real breaches.
argument-hint: "[path]"
---

Run a focused authorization audit on application code.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format cli
```

The detector covers seven canonical broken-access-control patterns:

| Pattern | Severity | Why it matters |
|---|---|---|
| `jwt.verify(…, { algorithm: 'none' })` | critical | Disables signature verification — any token is accepted |
| Hardcoded JWT secret in source | critical | Secret leaks into git history; treat it as compromised |
| `jwt.verify` without `algorithms: […]` | high | Algorithm-confusion attack: HS256 forge using RS256 public key |
| OAuth2 `response_type: 'code'` with no PKCE | high | Authorization code interception attack on public clients |
| `redirect_uri` taken from request, no allow-list | high | Open-redirect or auth-code interception |
| Authentication step without `session.regenerate(…)` | high | Session fixation — pre-auth session id retained post-login |
| Multi-tenant query without `tenantId`/`orgId` filter | high | Cross-tenant data read by id collision |

## Why this exists

OWASP A01: Broken Access Control is consistently the #1 source of real breaches. Generic taint analysis catches IDOR-by-id; this detector adds the higher-level patterns that pure data-flow misses — JWT misconfiguration, OAuth2 client mistakes, multi-tenant scope leakage, session fixation. F1 = 1.00 against the labelled fixture set.
