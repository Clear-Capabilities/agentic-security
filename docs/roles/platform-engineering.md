# Platform engineering

<!-- seo: title="Platform engineering guide: CI/CD gates, state and retention" description="Wire Agentic Security into CI/CD with severity and assurance gates, control the state it writes to disk, and run it across harnesses." -->

**Primary question:** How do I wire it into CI/CD and control what it writes?

**Core workflow:** [CI gating](../workflows/ci-gating.md)

## Wire it in

1. Generate the job: `/agentic-security:setup --ci`. See [CI gating](../workflows/ci-gating.md).
2. Choose a severity threshold (`--fail-on`) and an assurance mode (`advisory`, `standard`, `strict`).
3. Use baselines so the gate fails only on new findings.
4. Publish SARIF to your provider's security view.

## Control what it writes

- Runtime state lives under `.agentic-security/`. Every toggle and file is in [Configuration](../reference/configuration.md).
- Retention TTLs, opt-in encryption, `export` and `legal-hold`: [State and retention](../governance/state-and-retention.md).
- Scan-state files are signed with a per-install key, so a tampered file is detected.

## Run it where your agents run

The scanner and hooks run on Node.js 24 or later. Claude Code is the primary integration; Codex, Cursor and Gemini CLI are covered by [harness setup](../HARNESS_COMPATIBILITY.md). The JetBrains, Neovim and VS Code integrations wrap the same engine through a language server.

## Scale it

`fleet` (Preview) runs idempotent, leased scan jobs for a declared set of repositories from a local SQLite store, each scan in a supervised child process under a hard timeout. See [Fleet](../guides/fleet.md). Dependency matching is by declared package name; there is no remote-worker store.

## Read more

- [CI setup](../guides/ci-setup.md)
- [Scan health troubleshooting](../troubleshooting/scan-health.md)
- [CLI reference](../reference/cli.md)
