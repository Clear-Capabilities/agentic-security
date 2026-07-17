# Harness Compatibility

The MCP server is harness-agnostic — same binary, different manifest:

| Harness        | Manifest                          | Install path |
|----------------|-----------------------------------|--------------|
| **Claude Code**| `.claude-plugin/plugin.json`      | `/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security` then `/plugin install agentic-security@clearcapabilities` |
| **Codex CLI**  | `.codex-plugin/plugin.json`       | search Codex marketplace for `agentic-security`, then `codex plugin install` (validated against MCP spec; not yet against a live Codex install) |
| **Cursor**     | `.cursor-plugin/plugin.json`      | clone repo + point Cursor's MCP config at `scanner/bin/agentic-security-mcp.js` |
| **Gemini CLI** | `gemini-extension.json` (root)    | `gemini extensions install https://github.com/Clear-Capabilities/agentic-security` |

## What you get per harness

- **Claude Code**: full surface — 17 MCP tools, 10 slash commands, 7 auto-activating skills, 5 hook events, 9 subagents, the full audit log + scratchpad + AGENTS.md continual-learning ladder.
- **Codex / Cursor / Gemini**: the 17 MCP tools (deterministic write toolchain, scan, find, lookup) wired directly into the harness's agent. Slash commands + skill activation are Claude-Code-specific today; the underlying MCP behavior is identical across all four harnesses.

If you want a harness not listed here, the MCP server speaks the standard JSON-RPC-over-NDJSON protocol — any MCP-aware client can use it.
