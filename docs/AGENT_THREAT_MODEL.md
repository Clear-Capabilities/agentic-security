# Agent surface threat model (meta-security)

**Scope:** this document enumerates how *untrusted content* moves through the
scanner and its agent surface, and the hardening each path requires. It is the
engineering companion to `scanner/src/util/untrusted.js` (the shared mitigation
primitives) and its test suites `scanner/test/untrusted.test.js` (unit) and
`scanner/test/agent-hardening.test.js` (threat-mapped).

## What "untrusted" means here

The scanner runs *on adversary-authored input by design*. Two content classes
are attacker-controlled and must be treated as hostile everywhere they flow:

1. **Scanned code** — the repository under analysis. A malicious author fully
   controls file contents, file paths, and therefore any finding field lifted
   from them: `vuln`, `description`, `snippet`, `title`, `file`, and any URL
   embedded in a dependency manifest or advisory.
2. **Finding text** — because finding fields are derived from (1), the rendered
   finding is itself untrusted. It reaches humans (issue/PR/ticket bodies),
   models (triage/dedup/fix LLM calls), the filesystem (state + audit logs), and
   the network (enrichment fetches).

The trust boundary is crossed the moment finding text is **interpolated into a
prompt, a rendered document, a shell/argv, a path, or an outbound URL.** Every
such crossing is a sink that must route through a primitive below.

## Untrusted-content → sink paths and their mitigations

| # | Source (untrusted) | Sink | Threat | CWE | Mitigation primitive |
|---|--------------------|------|--------|-----|----------------------|
| 1 | `vuln` / `title` / `description` / `snippet` | Rendered issue / PR / ticket **markdown body** | Markup / stored-XSS injection, phishing links, fake UI | CWE-79, CWE-116 | `escapeMarkdown()` |
| 2 | Metadata / advisory URL from a manifest | Outbound `fetch()` for enrichment | SSRF to cloud metadata (`169.254.169.254`), loopback, RFC1918 | CWE-918 | `isAllowedFetchHost()` |
| 3 | `description` / `snippet` handed to a model | **LLM prompt** for triage / dedup / fix synthesis | Prompt injection — the text forges a close-delimiter and issues new instructions | CWE-1427 (LLM prompt injection), CWE-77 | `fenceUntrusted()` (nonce delimiter) |
| 4 | `file` / path-shaped finding fields | Filesystem write path or subprocess **argv** | Path traversal, argument injection into a fixer/writer | CWE-22, CWE-88 | Path confinement (`agents/_CONFINEMENT.md`, `mcp/tools.js`) + `escapeMarkdown` for display |
| 5 | Any finding text containing a credential | **Audit log** / LLM context | Secret leakage into logs or model context | CWE-532 | `redactSecrets()` |
| 6 | Audit log / scan-state artifact | Filesystem (mode/umask) | World-readable secrets, tampering | CWE-732, CWE-276 | `writeSecure()` + `secureFileMode` / `secureDirMode` (0600 / 0700) |

## The primitives (`scanner/src/util/untrusted.js`)

- **`escapeMarkdown(s)`** — entity-encodes `& < >` and backslash-escapes
  `` ` `` `[` `]` `!` `\`. Neutralizes tag injection, code spans, and
  `[text](url)` / `![img](url)` links. Non-strings → `''`. Use at **every**
  interpolation of untrusted finding text into a rendered markdown body.
- **`fenceUntrusted(s, label)`** — wraps text in a delimiter carrying a nonce
  derived from `sha256(content)` (first 8 hex). Because the nonce depends on the
  bytes an attacker would have to author, they cannot pre-compute it to forge a
  matching close-delimiter. Use when passing untrusted text into an LLM prompt so
  the model treats the span as inert data. Returns `{ text, nonce }`.
- **`isAllowedFetchHost(url, allowlist)`** — fail-closed SSRF guard. Rejects
  link-local (`169.254.0.0/16`, incl. the metadata IP), loopback (`127.0.0.0/8`,
  `localhost`, `::1`), and RFC1918 (`10/8`, `192.168/16`, `172.16–31/12`), and
  anything not on the explicit allowlist. Malformed URL / empty allowlist →
  `false`.
- **`redactSecrets(s)`** — masks URL basic-auth passwords, `Authorization:
  Bearer` tokens, `?access_token=` / `&token=` query values, and raw provider
  prefixes (`ghp_ gho_ ghu_ ghs_ github_pat_ sk-ant-`), **preserving the
  prefix** so a triager knows what class leaked without seeing the value.
- **`writeSecure(path, data)` / `secureFileMode` (0600) / `secureDirMode`
  (0700)** — writes owner-only regardless of umask (`openSync` mode + explicit
  `chmod`). Use for audit logs, scan state, and anything carrying finding text
  or secrets.

## Wiring status

The finding-rendering modules are the highest-traffic instance of path #1:

- **`scanner/src/pr-comment.js`** — advisor-tone PR comment renderer. The
  per-finding fallback title (`f.vuln`, used when the CWE has no built-in
  narrative) now routes through `escapeMarkdown`. The static `CWE_NARRATIVE`
  table is trusted and rendered as-is.
- **`scanner/src/integrations/tickets.js`** — GitHub / Linear / Jira issue
  bodies. `findingTitle` (`vuln` / `title`) and `findingBody` (`description`,
  `snippet`) route untrusted fields through `escapeMarkdown`.

Any **new** surface that interpolates finding text into a rendered body, a
prompt, a path/argv, or a URL MUST route through the matching primitive above.
The LLM-prompt paths (path #3) and the enrichment-fetch paths (path #2) are the
next wiring targets; `fenceUntrusted` and `isAllowedFetchHost` exist and are
tested so those call sites can adopt them without new design work.

## Non-goals

- This layer does not replace the MCP/subagent **path-confinement** contract
  (`agents/_CONFINEMENT.md`) — that governs *where* an edit-capable agent may
  write; this governs *how* untrusted text is neutralized once it is emitted.
- `escapeMarkdown` targets markdown/HTML renderers. A sink with different
  metacharacters (a shell, an SQL string, an LDAP filter) needs its own
  context-correct encoder — do not reuse `escapeMarkdown` there.
