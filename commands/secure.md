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

## Flags

- `--launch` — pre-deploy intent. Blocks if any critical finding open.
- `--json` — emit decision as JSON for piping.
- `--run` — auto-execute the recommended `agentic-security ...` command.

## Consolidated modes

`/secure` also routes:

| Flag | Behaviour |
|---|---|
| `--tour` | Walk through the plugin's main capabilities with example commands |
| `--help` | List the primary commands and the modes each one routes |
| `--daily` | Post daily security digest to Slack / Discord / webhook |

🛡  agentic-security · created by ClearCapabilities.Com
