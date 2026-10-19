# Integrations

<!-- seo: title="Integrations: Claude Code, Codex, Cursor, Gemini CLI, IDEs and CI" description="Where Agentic Security runs: the Claude Code plugin, other agent harnesses, IDEs, CI providers, the MCP server, ticket systems and SARIF consumers." -->

Agentic Security is a CLI and a Claude Code plugin, and the same engine is reachable from several places.

| Integration | What it is | Read |
|---|---|---|
| Claude Code plugin | Slash commands, hooks, agents and the MCP server | [README install](../../README.md#install) |
| Codex, Cursor, Gemini CLI | Harness configuration, and an audit of those harnesses' own config files (`agentic-security harness`) | [Harness setup](../HARNESS_COMPATIBILITY.md) |
| Editors | JetBrains, Neovim and VS Code, via a language server wrapping the scan | `ide/` in the repository |
| CI providers | GitHub Actions, GitLab, CircleCI, Buildkite, Jenkins | [CI gating](../workflows/ci-gating.md), [CI setup](../guides/ci-setup.md) |
| MCP server | 17 tools for agents, two of which write | [MCP tool contract](../reference/mcp-tool-contract.md) |
| Findings consumers | SARIF with code flows for GitHub Code Scanning and other viewers; JSON, JUnit, CSV, Markdown, HTML, OSCAL | [Scanning](../guides/scanning.md) |
| Ticket systems | Two-way sync of findings with GitHub Issues, Linear and Jira (`agentic-security tickets sync --provider <p>`) | [CLI reference](../reference/cli.md) |
| Local models | Ollama on loopback | [Local AI with Ollama](../guides/ollama.md) |

Every integration obeys the same egress policy and the same trust rules. See [trust and limitations](../trust/trust-and-limitations.md).
