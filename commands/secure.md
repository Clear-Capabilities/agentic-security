---
description: Security router — inspects project state and routes to the single best next action. Vibecoder entry point.
argument-hint: "[path] [--launch]"
---

Smart router for security work. Picks the right next step from project state — vibecoders don't have to choose between `/scan`, `/fix`, `/posture --report-card`, `/find-and-fix-everything`.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs secure ${1:-.} ${@:2}
```

## How it decides

| Project state | Recommended action |
|---|---|
| No prior scan | `agentic-security scan .` |
| Critical findings open | `agentic-security fix --finding <id> --preview` |
| High findings open | `/triage --show` |
| Mediums only | `/posture --report-card` |
| All clean | `/compliance --attestation` |
| Last scan > 7 days ago | re-scan |
| `--launch` flag set | pre-deploy gate (or block if criticals) |

The router is **trend-aware**: when two or more scans exist it compares the latest two and shows a `↑ / → / ↓` arrow ("2 fewer critical+high than last scan — keep going" / "new risk crept in"). It never invents a trend from a single scan.

## Flags

- `--launch` — pre-deploy intent. Blocks if any critical finding open.
- `--json` — emit decision as JSON for piping.
- `--run` — auto-execute the recommended `agentic-security ...` command.

## Consolidated modes

`/secure` also routes:

| Flag | Behaviour |
|---|---|
| `--tour` | Walk through the plugin's main capabilities with example commands (below) |
| `--help` | Task-oriented command guide + old→new alias map (below) |
| `--daily` | Post the security digest to Slack or Discord (below) |

## `--tour` (guided walkthrough)

Give the user a short guided tour — conversational, not a wall of text. Walk
through these five stops in order, one short paragraph each with the example
command, then offer to run stop 1 for them:

1. **Scan** — `/scan` runs the 12-pillar scan; findings land in
   `.agentic-security/last-scan.json` and every other command reads from there.
2. **Understand** — `/triage --show` ranks what the scan found;
   `/triage --explain <id>` explains one finding in plain English with the
   dollar-cost estimate.
3. **Fix** — `/fix --finding <id> --preview` shows the patch first; every
   applied fix is re-verified (rescan-clean, no new ≥ medium, lint) before it
   touches disk. `/find-and-fix-everything` is the one-shot version.
4. **Guard** — `/setup --hooks` installs the write-time bodyguard;
   `/setup --ci` generates a CI gate so regressions can't merge.
5. **Prove** — `/posture --report-card` grades the project;
   `/compliance --report <framework>` produces an auditor-ready attestation.

If the project has never been scanned, end by offering to run `/scan` now.

## `--daily` (digest to Slack / Discord)

Runs the real CLI digest against the last scan (requires a prior scan — it
does not scan):

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs digest --slack <webhook-url>
# or: … digest --discord <webhook-url>
```

Ask for the webhook URL if the user didn't provide one, and suggest wiring it
into CI (`/setup --ci`) for a genuinely daily cadence — this command posts
once per invocation.

## `--help` (task-oriented)

Organize help by **what the user wants to do**, not by command name:

| I want to… | Command |
|---|---|
| Just make it safe (scan + fix everything) | `/find-and-fix-everything` |
| Not sure where to start | `/secure` |
| Run a scan | `/scan` (`--pick` for a menu) |
| Understand / triage findings | `/triage` |
| Fix something | `/fix` (`--checkpoint` for a revertible batch) |
| Check my posture / grade / trend | `/posture` |
| Prove compliance | `/compliance` (`--gap` for the worklist) |
| Vet dependencies | `/supply` |
| Install hooks / CI / guards | `/setup` (`--all` for one pass) |
| Generate a CI gate | `/setup --ci` |
| Deep-dive one finding (red/blue/auditor) | `/triage --deep <id>` |
| Experimental / AI-driven analyses | `/labs` |
| Export the Data Flow Explorer graph (PNG/PDF/SVG/JSON/CSV/HTML) | `/dataflow export --format <fmt> --output <file>` |
| Diff two scanned snapshots + drift policies | `/dataflow diff --format <fmt> --output <file>` |
| Propose a validated edit to recipient-profiles.json | `/governance propose-edit --patch <file.json> [--yes]` |
| Open a remediation work item from an impact assessment | `/remediation open --assessment <report.json> --owner <id> --due <YYYY-MM-DD> --control <text> --required-evidence <flowIds> [--yes]` |
| Verify a remediation item against a fresh lineage scan | `/remediation verify --id <itemId> [--yes]` |
| Reopen verified items whose control regressed | `/remediation reopen-check [--drift-policy <file>] [--yes]` |

### Legacy alias map (removed in v0.86.0)

The 44 old single-purpose commands are gone, but the **legacy-alias-redirect** hook catches an old command and points you at the new mode automatically. The full mapping (`/status` → `/posture --status`, `/show-findings` → `/triage --show`, `/harden` → `/fix --harden`, …) lives in `hooks/legacy-alias-redirect.js`.

🛡  agentic-security · created by ClearCapabilities.Com
