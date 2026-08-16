# CLI reference

Every command runs as `npx @clear-capabilities/agentic-security-scanner <command>`
(or, if installed, `agentic-security <command>`). In Claude Code the common ones
have slash-command equivalents (`/agentic-security:<name>`).

This page is a map; the task guides in [`../guides/`](../guides/) show each in
context. Run any command with `--help` for its live flags.

---

## Commands

| Command | What it does |
|---|---|
| `secure [path]` | Smart router — inspects project state and names the single best next action. `--launch` for pre-deploy intent, `--run` to auto-execute, `--json` to pipe. |
| `scan [path]` | The full SAST + SCA + secrets + IaC + LLM sweep. The workhorse — see options below. |
| `ci [path]` | Baseline-aware CI scan: auto-detects the PR base ref, writes SARIF + JUnit + JSON, applies the `--fail-on` policy. |
| `fix --finding <id>` | Show (`--preview`) or apply (`--apply`) a fix for one finding. |
| `undo` | Revert the most recent applied fix. `--list` shows history; `--all` reverts everything; `--compact` archives terminal entries. |
| `accept --finding <id>` | Soft-suppress a finding for 30 days. |
| `compliance` | Assess the last scan against a framework. `--list`, `--walkthrough <id>`, `--gap`, `--privacy`, `--format cli\|json\|md`, `--fail-on gap`. See [compliance guide](../guides/compliance.md). |
| `setup [dir]` | Install the `/security-*` shortcut commands into a project. |
| `harness [path]` | Multi-harness config audit: scans `.claude/`, `.cursor/`, `.codex/`, `.gemini/`, and more. `--include-home` also sweeps `~/`. |
| `hunt --root <dir>` | LLM discovery over the call-graph partition (advisory; needs `AGENTIC_SECURITY_LLM_ENDPOINT`). `--lens a,b` narrows the angles. CLI-only. |
| `digest --slack <url>` | Post a security digest to Slack (or `--discord <url>`). Reads the last scan. |
| `cve-watch --root <dir>` | One-shot check for new CVEs against installed dependencies. |
| `verify [--finding <id>]` | Re-run the verifier loop on last-scan findings. `--live --target <url>` executes PoCs. |
| `scan-baseline --current <f> --previous <f>` | Finding-level diff between two scan JSON outputs. |
| `reset` | Wipe accumulated learned state under `.agentic-security/` (preserves operator-authored config). `--yes`, `--keep <...>`. |
| `mcp` | Start the MCP stdio server. See [MCP tools](../../scanner/src/mcp/CLAUDE.md). |
| `version` / `banner` | Print the version / the mascot lockup. |

Pro/advanced: `org-scan`, `triage list\|assign\|trend`, `rules validate`,
`packs list`, `rule list\|test`, `tickets sync`, `validator-cache`,
`rule-synth`, `profile set\|show`.

---

## Key `scan` options

**Scope**

| Flag | Effect |
|---|---|
| `--only sast\|sca\|secrets` | Limit to one pillar |
| `--changed-since <ref>` / `--pr [ref]` | Scan only files changed since a git ref |
| `--pack <name>` | Focus a curated rule pack: `owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain` (repeatable) |

**Baseline**

| Flag | Effect |
|---|---|
| `--set-baseline` | Snapshot current findings as the baseline |
| `--since-baseline` | Show only findings not in the baseline |
| `--baseline <ref>` | (ci) diff against a git ref |

**Output**

| Flag | Effect |
|---|---|
| `--format <fmt>` | `cli` · `json` · `md` · `sarif` · `stix` · `junit` · `csv` · `html` · `cyclonedx` · `spdx` · `pbom` · `aibom` · `aibom-md` |
| `--output <file>` | Write to a file instead of stdout |
| `--machine-output` | Always write `.agentic-security/findings.{sarif,json,csv}` |
| `--verbose` | Include fix bodies + taxonomy |

**Filtering / triage**

`--firehose` (show all, ignore confidence), `--honest` (≥0.9 only),
`--confidence <0..1>`, `--exposed-only`, `--mitigated-only`,
`--unreachable-only`, `--sca-reachable-only`, `--hide-proven-safe`,
`--persona <name>`.

**CI policy**

`--fail-on critical|high|medium|low|none` (default `critical`),
`--fail-on-new` (block only newly introduced findings),
`--policy <file.rego>` (policy-as-code gate).

**Network / reproducibility**

`--no-network` / offline, `--deterministic` (stable sort, no network,
lockfile-checked), `--incremental` (reuse taint summaries).

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | highest severity low/medium |
| `2` | high present |
| `3` | critical present |
| `4` | the scan errored |

The `compliance` subcommand differs: `0` report produced, `2` no scan to
assess, `1` only with `--fail-on gap` and a failing control.

---

## Related

- [Configuration & env vars](configuration.md)
- [Guides](../guides/) — every command shown in context
