# Agent threat model

<!-- seo: title="Agent threat model: can the repository you scan attack the scanner?" description="How Agentic Security treats malicious repository content, prompt injection, hostile tool output, generated code and MCP or plugin attack surfaces." -->

A security tool that reads attacker-authored code is itself a target. Agentic Security assumes the repository under analysis is hostile and treats everything derived from it as untrusted input. The engineering reference is [AGENT_THREAT_MODEL.md](../AGENT_THREAT_MODEL.md); this page is the map.

## Malicious repository content

Scanned code is attacker-controlled, including file contents, file paths, and any finding field lifted from them (`vuln`, `description`, `snippet`, `title`, `file`) and any URL in a manifest or advisory. The rendered finding is therefore untrusted too.

| Untrusted source | Sink | Threat | Mitigation |
|---|---|---|---|
| Finding text | Issue, PR or ticket markdown body | Markup injection, phishing links | `escapeMarkdown()` |
| Manifest or advisory URL | Outbound enrichment fetch | SSRF to metadata services, loopback, private ranges | `isAllowedFetchHost()` |
| Finding text | A model prompt | Prompt injection | `fenceUntrusted()` (nonce delimiter) |
| Path-shaped fields | Filesystem write or subprocess argv | Path traversal, argument injection | Path confinement (`agents/_CONFINEMENT.md`, MCP tools) |
| Finding text with a credential | Audit log or model context | Secret leakage | `redactSecrets()` |
| Scan-state artifacts | Filesystem | World-readable secrets, tampering | Secure file modes (0600 and 0700) |

Project code is never run in a default scan. For Haskell and Nix that means no `Setup.hs`, Template Haskell, compiler plugin or `nix` evaluation or build; an optional evaluation runs only when selected and a sandbox probe proved isolation.

## Prompt injection

Text that reaches a model is fenced with a per-call nonce so it cannot forge a close-delimiter and issue instructions. Model output cannot widen a fix beyond the verification gates, cannot set severity, and cannot declare an exploit confirmed. Agentic discovery candidates are routed back through the deterministic engine, where a three-angle panel prompted to refute them gets a vote.

## Hostile tool output

Tool and subprocess output is treated as data. Rescan, lint and test legs report pass, fail or skip. A tampered stored proof record is detected by its own digest and reported, never silently trusted. Rules overrides that reduce coverage take effect only with a verifying signature or an explicit opt-out.

## Generated code

Code written by an AI agent is checked before it reaches disk: the `bodyguard` pre-edit hook blocks injectable SQL, hardcoded keys and `eval` on user input, and the destructive-command guard blocks deletions outside the allowed root. Generated patches go through the verification legs in [verified remediation](verified-remediation.md) before they are written, with a backup and an `undo`.

## MCP and plugin attack surfaces

The MCP server is hardened against the OWASP MCP Top 10. It exposes 17 tools, of which two write (`apply_fix`, `apply_sca_upgrade`); the write tools share the path-confinement contract with the edit-capable agents. The scanner also audits the MCP servers and agent tools a project itself exposes. See [MCP tool contract](../reference/mcp-tool-contract.md).

Runner-level capability enforcement (filesystem, structured commands, outbound network) exists as a **Labs** capability. It is off by default and operator-only, and Linux is only partially verified, so do not treat it as a boundary you have verified.

## What this does not claim

- It does not claim an unbreakable boundary. The proof sandbox without a container runtime is a lower-assurance local confinement, and says so.
- It does not replace reviewing what an agent is allowed to do in your environment.
- The wiring of the model-prompt and enrichment-fetch primitives is tracked in the engineering reference; read its wiring-status section before relying on a specific path.
