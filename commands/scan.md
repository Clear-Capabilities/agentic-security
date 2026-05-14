---
description: Run the agentic-security scanner. Default (--all) gives a one-screen "safe to deploy?" verdict. Focused modes: --sca, --secrets, --authz, --mcp, --pipeline, --logic, --diff.
argument-hint: "[path] [--all|--sca|--secrets|--authz|--mcp|--pipeline [--format pbom|cli|json]|--logic [--max <N>]|--diff [--since <git-ref>]]"
---

## Step 0 — Auto-update plugin (do this FIRST, before scanning)

Before running the scan, refresh the plugin to the latest version so the user gets the newest detection rules and fixes.

**Check the throttle first.** Read `.agentic-security/auto-update.json` (if it exists):

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/auto-update-check.js
```

The helper script exits with one of three codes:
- `0` — update check is due. Proceed to the next paragraph.
- `1` — auto-update is disabled (user set `{"enabled": false}`). Skip Step 0 entirely; go to Step 1.
- `2` — within throttle window (default: 4 hours since last check). Skip Step 0; go to Step 1.

**When exit code is 0**, invoke the Claude Code slash command:

```
/plugin marketplace update agentic-security
```

This refreshes the marketplace listing for the plugin. If a newer version is available, Claude Code will tell the user. Do NOT block on the result — if the update fails (offline, marketplace down, etc.), print a brief one-line notice and continue to Step 1 anyway. The scan must still run.

After invoking the marketplace update, run the helper one more time with `--mark` to record the timestamp:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/auto-update-check.js --mark
```

This ensures subsequent `/scan` calls within the throttle window skip the update.

**To disable auto-update entirely:** create/edit `.agentic-security/auto-update.json` with:

```json
{ "enabled": false }
```

**To change the throttle:** set `"throttleHours": <N>` in the same file (default: 4).

## Step 1 — Run the scanner

```bash
FLAG="--all"
PATH_ARG="."
EXTRA=""
i=1
for arg in "$@"; do
  case "$arg" in
    --all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff) FLAG="$arg" ;;
    *) [ "$FLAG" = "--all" ] && PATH_ARG="$arg" || EXTRA="$EXTRA $arg" ;;
  esac
done

case "$FLAG" in
  --sca)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only sca --format cli
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --secrets)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only secrets --format cli
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --authz)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format cli
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --mcp)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format cli
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --pipeline)
    FORMAT=$(echo "$EXTRA" | grep -o -- '--format [a-z]*' | awk '{print $2}')
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format ${FORMAT:-cli}
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --diff)
    SINCE=$(echo "$EXTRA" | grep -o -- '--since [^ ]*' | awk '{print $2}')
    node -e "
import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/material-change.js').then(m => {
  const r = m.classifyGitDiff(process.cwd(), '${SINCE:-HEAD~1}');
  process.stdout.write(JSON.stringify(r, null, 2));
});
" ;;
  --logic)
    echo "Invoking logic reviewer — reading last-scan route inventory..."
    ;;
  *)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship "$PATH_ARG"
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
esac
```

## Modes

**`/scan` or `/scan --all`** — Full SAST + SCA + secrets sweep. One-screen "safe to deploy?" verdict. If ❌, ask which tier to fix:

| Answer | Command |
|--------|---------|
| Critical only | `/fix --all --critical` |
| Critical + High | `/fix --all --high` |
| Critical + High + Medium | `/fix --all --medium` |
| All | `/fix --all --low` |

**`/scan --sca`** — Dependency CVE audit only (OSV.dev-backed). If suspicious packages appear, invoke the `sca-malware-analyst` subagent for a CLEAN/SUSPICIOUS/MALICIOUS verdict.

**`/scan --secrets`** — Secret sweep (60+ provider patterns + entropy detection). For any hit: rotate the credential immediately, move to a secrets manager, audit git history.

**`/scan --authz`** — Deep auth/authZ audit (OWASP A01). Covers: JWT algorithm confusion, hardcoded JWT secrets, missing `algorithms:[]` constraint, OAuth2 PKCE absent on public clients, `redirect_uri` from request without allowlist, session fixation, multi-tenant queries missing `tenantId`/`orgId` filter.

**`/scan --mcp`** — Audit MCP server configs (`claude_desktop_config.json`, `.mcp.json`, `mcp_servers.json`). Covers: untrusted install vectors (`curl | sh`), hardcoded API keys in `env:` blocks, prompt-injection in server descriptions, filesystem servers granted `/`/`~`/`$HOME`, dangerous capability names (`shell`, `exec`, `eval`), floating tags (`@latest`, `@main`).

**`/scan --pipeline`** — Audit GitHub Actions workflows for supply-chain risk: floating tags, secret echoes, `write-all` permissions, OIDC misconfigurations, `github.event.*` script injection. Add `--format pbom` to emit a Pipeline Bill of Materials.

**`/scan --logic [--max <N>]`** — Semantic business-logic review using the `security-logic-reviewer` subagent. Reads route handlers from the last scan's route inventory (run `/scan --all` first). Finds: broken authorization tier checks, race conditions, state-machine bypasses, intent vs. implementation gaps. Reads up to `--max` (default 8) handler files. For each finding, quotes the offending code, states the inferred intent, explains why it fails, describes the attacker move, and proposes a fix. Cross-references with engine pattern findings to avoid double-listing.

**`/scan --diff [--since <git-ref>]`** — Score the git diff between `--since` (default `HEAD~1`) and `HEAD` by architectural risk. Passes the diff to the `security-material-change` subagent which emits a per-file findings report and a "what to verify before merging" checklist. Risk levels: `critical` (auth removed, new shell call) → recommend `/fix --one` + `/validate-findings`; `high` → recommend `/validate-findings`; `medium`/`low`/`none` → safe to merge.

🛡  agentic-security · created by ClearCapabilities.Com
