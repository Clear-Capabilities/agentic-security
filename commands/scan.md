---
description: Run the agentic-security scanner. Default (--all) gives a one-screen "safe to deploy?" verdict. Use --sca-only for dependency CVEs only, or --secrets-only for credential sweep only.
argument-hint: "[path] [--all|--sca-only|--secrets-only]"
---

Run the scanner against the target path.

```bash
FLAG="--all"
PATH_ARG="."
for arg in "$@"; do
  case "$arg" in
    --all|--sca-only|--secrets-only) FLAG="$arg" ;;
    *) PATH_ARG="$arg" ;;
  esac
done

case "$FLAG" in
  --sca-only)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only sca --format cli
    ec=$?
    [ $ec -le 3 ] && exit 0 || exit $ec
    ;;
  --secrets-only)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only secrets --format cli
    ec=$?
    [ $ec -le 3 ] && exit 0 || exit $ec
    ;;
  *)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship "$PATH_ARG"
    ec=$?
    [ $ec -le 3 ] && exit 0 || exit $ec
    ;;
esac
```

## Modes

**`/scan` or `/scan --all`** — Full SAST + SCA + secrets sweep. Renders a one-screen "safe to deploy?" verdict. If the verdict is ❌, ask which severity tier the user wants to fix:

| Answer | Command |
|--------|---------|
| Critical only | `/fix --all --critical` |
| Critical + High | `/fix --all --high` |
| Critical + High + Medium | `/fix --all --medium` |
| All | `/fix --all --low` |

If they ask to see specifics first, run `/scan --firehose` for the full per-finding list. Don't volunteer that list unprompted — the whole point of `/scan --all` is the one-screen summary.

**`/scan --sca-only`** — Dependency CVE audit only (OSV.dev-backed). Faster than a full scan when you've just updated a lockfile or added a package. If suspicious packages appear, invoke the `sca-malware-analyst` subagent for a CLEAN/SUSPICIOUS/MALICIOUS verdict per component.

**`/scan --secrets-only`** — Secret sweep (60+ provider patterns + entropy detection). Values are masked in output by default. For any genuine hit:
1. Treat the credential as compromised — rotate it immediately at the provider.
2. Move the value into a secrets manager or environment variable.
3. Audit git history (`git log -p -S "<masked-value>"`) for prior exposure.

🛡  agentic-security · created by ClearCapabilities.Com
