---
description: Run the agentic-security scanner. Default (--all) gives a one-screen "safe to deploy?" verdict. Focused modes: --sca, --secrets, --authz, --mcp, --pipeline, --logic, --diff, --uncommitted.
argument-hint: "[path] [--all|--sca|--secrets|--authz|--mcp|--pipeline [--format pbom|cli|json]|--logic [--max <N>]|--diff [--since <git-ref>]|--uncommitted]"
---

## Step 0 — (Optional, user-initiated) Plugin update

The plugin auto-updates via Claude Code's marketplace mechanism. **You (Claude) do not need to invoke `/plugin marketplace update` from inside this slash command** — it's a built-in UI command and cannot be invoked via the Skill tool. If the user wants the latest detection rules, they should run `/plugin marketplace update agentic-security` themselves at any time. Skip this step and go straight to Step 1.

## Step 1 — Run the scanner

> **Important: exit codes 1, 2, and 3 are NORMAL verdict signals, not errors.**
> The scanner reports severity via exit code: `0=clean`, `1=low/medium`, `2=high`, `3=critical`, `4=actual engine error`.
> Each command below wraps the call so any verdict exit (≤3) becomes shell-success (`exit 0`); only a real engine error (`4`) propagates. **Do not interpret a "Not safe to deploy" output as a failure of the slash command — it IS the answer the user asked for.**

```bash
FLAG="--all"
PATH_ARG="."
EXTRA=""
i=1
for arg in "$@"; do
  case "$arg" in
    --all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff|--uncommitted) FLAG="$arg" ;;
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
  --uncommitted)
    CHANGED=$( { git diff --name-only HEAD 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null; } | sort -u | grep -v '^$' )
    if [ -z "$CHANGED" ]; then
      echo "✅  No uncommitted changes — nothing to scan. Working tree is clean."
      exit 0
    fi
    N=$(echo "$CHANGED" | wc -l | tr -d ' ')
    echo "Scanning $N uncommitted file(s)..."
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format json --output .agentic-security/_uncommitted.json --no-network >/dev/null 2>&1 || true
    node -e "
      const fs = require('fs');
      const changed = new Set((process.argv[1]||'').split('\n').map(s=>s.trim()).filter(Boolean));
      let scan = {}; try { scan = JSON.parse(fs.readFileSync('.agentic-security/_uncommitted.json','utf8')); } catch {}
      const all = scan.findings || [];
      const f = all.filter(x => { const rel = (x.file||'').replace(/^\.\//,''); return changed.has(rel) || [...changed].some(c => rel.endsWith('/'+c) || c.endsWith('/'+rel)); });
      const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const x of f) sev[x.severity] = (sev[x.severity]||0) + 1;
      console.log('');
      if (f.length === 0) {
        console.log('✅  No findings in your uncommitted changes. Safe to commit.');
      } else {
        console.log('❌  ' + f.length + ' finding(s) in uncommitted changes');
        console.log('    ' + sev.critical + ' critical · ' + sev.high + ' high · ' + sev.medium + ' medium · ' + sev.low + ' low');
        console.log('');
        for (const x of f.slice(0, 20)) {
          console.log('    [' + x.severity.toUpperCase() + '] ' + (x.vuln || x.title) + '  ' + x.file + ':' + x.line + (x.kev ? '  🔥 KEV' : ''));
        }
        if (f.length > 20) console.log('    ... and ' + (f.length - 20) + ' more');
        console.log('');
        console.log('Fix:  /fix --all --critical    (or --high, --medium, --low)');
      }
    " "$CHANGED"
    rm -f .agentic-security/_uncommitted.json
    exit 0 ;;
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

**`/scan --uncommitted`** — Vibecoder-friendly: scans only files you've changed since the last commit (staged + unstaged + untracked). No git-ref vocabulary required. Returns the same one-screen verdict, scoped to "what did I just change."

**`/scan --diff [--since <git-ref>]`** — Score the git diff between `--since` (default `HEAD~1`) and `HEAD` by architectural risk. Passes the diff to the `security-material-change` subagent which emits a per-file findings report and a "what to verify before merging" checklist. Risk levels: `critical` (auth removed, new shell call) → recommend `/fix --one` + `/validate-findings`; `high` → recommend `/validate-findings`; `medium`/`low`/`none` → safe to merge.

🛡  agentic-security · created by ClearCapabilities.Com
