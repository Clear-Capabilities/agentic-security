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
| `attest [--id <finding>]` | Write signed evidence bundles to `.agentic-security/attestations/`. `--provenance [<finding-id>]` signs [finding-provenance](../guides/finding-provenance.md) records instead of ordinary finding evidence — bare `--provenance` signs every finding that has one, `--provenance <finding-id>` scopes to one (note: this is a *different* argument shape from `--id` above, and from `scan`'s own `--provenance <standard\|deep>` — `attest --provenance deep` looks for a finding literally named `deep`, not a mode). |
| `verify-attestation <bundle.json> --public-key <path>` | Verify a signed bundle (finding evidence, a run attestation, or a provenance record — auto-detected) with only the public key. Exits `0` valid, `1` invalid. |
| `scan-baseline --current <f> --previous <f>` | Finding-level diff between two scan JSON outputs. |
| `explore [path] [--port <n>] [--keep-open]` | Serve the already-scanned Data Flow Explorer graph as a local, read-only, loopback-only web UI. Needs a scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` first — see the [Data Flow Explorer guide](../guides/data-flow-explorer.md). CLI-only, no slash-command equivalent. |
| `dataflow export\|diff\|scenario apply\|impact assess\|observations import\|observations list\|twin` | Export the Data Flow Explorer graph (png/pdf/svg/json/csv/html/dpia/ropa/briefing/recipients/coverage), diff two scans, simulate a hypothetical change, assess blast radius, or layer in runtime observations. See the [Data Flow Explorer guide](../guides/data-flow-explorer.md) and `/dataflow --help`. |
| `governance propose-edit --patch <file.json> [--yes]` | Propose a validated, reviewable edit to `recipient-profiles.json` (preview → confirm → audit-logged write). |
| `remediation open\|update\|verify\|accept-risk\|reopen-check\|list` | Track a remediation item against a blast-radius assessment. Closing it requires a clean rescan or an explicitly permitted manual attestation; a later regression reopens it automatically. |
| `federate declare\|list` | Declare (or list) a link between a node in this repo's scanned graph and a node in a separately-scanned remote repo's graph — each repo's graph stays its own separate, unmodified artifact. |
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

**Provenance** (which commit introduced each finding — on by default in a
git repo; see the [finding provenance guide](../guides/finding-provenance.md))

`--provenance <standard|deep>`, `--no-provenance`, `--provenance-since <ref>`,
`--provenance-timeout <ms>`, `--include-author-email`,
`--pseudonymize-authors`, `--require-provenance` (flags unresolved provenance
as a scan-health condition; `ci`'s own `--assurance strict` is what can
actually fail the build on it).

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
- [Data Flow Explorer guide](../guides/data-flow-explorer.md) — `explore`/`dataflow`/`governance`/`remediation`/`federate` in context
