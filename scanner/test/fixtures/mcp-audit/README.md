# MCP-audit fixtures

Labeled fixtures for the MCP / agent-tool security detector (`sast/mcp-audit.js`),
evaluated by `scanner/test/mcp-audit.test.js`.

- `vuln-*.mcp.json` — **intentionally insecure** MCP server configs, each a
  positive test case for one detector rule (hardcoded credential, curl-pipe-sh
  install, floating tag, filesystem over-scope, dangerous capability,
  prompt-injection description).
- `safe-*.mcp.json` — clean configs that must NOT fire (negative cases).

## Note for secret scanners (secretlint / repomix / etc.)

`vuln-hardcoded-cred.mcp.json` contains a GitHub-token-shaped string
(`ghp_…`) **on purpose** — it is the input that proves the hardcoded-credential
rule fires. It is a synthetic test vector, **not a real credential**; there is
nothing to rotate. It must keep a realistic token shape or the detector test
no longer tests detection. Secret-scanning tools that flag this file are
producing a false positive on intentional test data.
