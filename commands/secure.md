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
| `--tour` | Walk through the plugin's main capabilities with example commands |
| `--help` | Task-oriented command guide + old→new alias map (below) |
| `--daily` | Post daily security digest to Slack / Discord / webhook |

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

### Legacy alias map (removed in v0.86.0)

The 44 old single-purpose commands are gone, but the **legacy-alias-redirect** hook catches an old command and points you at the new mode automatically. The full mapping (`/status` → `/posture --status`, `/show-findings` → `/triage --show`, `/harden` → `/fix --harden`, …) lives in `hooks/legacy-alias-redirect.js`.

🛡  agentic-security · created by ClearCapabilities.Com
