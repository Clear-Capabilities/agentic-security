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

## Haskell and Nix files

| Surface | Behavior |
|---|---|
| VS Code | activates on Haskell, Literate Haskell, Cabal and Nix files and on workspaces containing `*.cabal`, `flake.nix` or `configuration.nix` |
| JetBrains | Haskell and Nix language mappings plus file-name patterns (`*.hs`, `*.nix`, `*.cabal`, `cabal.project*`, `stack.yaml*`, `package.yaml`, `flake.lock`) because the plugins that provide those languages vary |
| Neovim | the `haskell`, `lhaskell`, `cabal`, `cabalproject` and `nix` filetypes; project roots include `cabal.project`, `stack.yaml`, `package.yaml`, `flake.nix` and `configuration.nix` |
| LSP, on save | scans the saved file with its imported modules and the manifests as context, reports only that file, and offers a code action only for a fix that passed the gates |
| MCP tools | `scan_diff`, `verify_fix` and `synthesize_fix` add the same context; `apply_fix` writes with a backup |
| Edit hook | recognises Haskell and Nix credentials (including a literal split across `++`, `<>`, `+`) and a few high-precision rules before the write |
| Commands | the slash commands call the same CLI, so every flag above behaves identically |
