---
description: Run the scanner. --all gives a one-screen verdict. Focused modes per surface; --show-X for supplementary blocks.
argument-hint: "[path] [--all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff|--uncommitted] [--show-personas|--show-bounty|--show-playbook]"
---

## Step 0 — (Optional, user-initiated) Plugin update

The plugin auto-updates via Claude Code's marketplace mechanism. **You (Claude) do not need to invoke `/plugin marketplace update` from inside this slash command** — it's a built-in UI command and cannot be invoked via the Skill tool. If the user wants the latest detection rules, they should run `/plugin marketplace update agentic-security` themselves at any time. Skip this step and go straight to Step 1.

## Step 1 — Run the scanner

> **Important: exit codes 1, 2, and 3 are NORMAL verdict signals, not errors.**
> The scanner reports severity via exit code: `0=clean`, `1=low/medium`, `2=high`, `3=critical`, `4=actual engine error`.
> Each command below wraps the call so any verdict exit (≤3) becomes shell-success (`exit 0`); only a real engine error (`4`) propagates. **Do not interpret a "Not safe to deploy" output as a failure of the slash command — it IS the answer the user asked for.**

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
FLAG="--all"
PATH_ARG="."
EXTRA=""
PASSTHROUGH=""
for arg in "$@"; do
  case "$arg" in
    --all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff|--uncommitted|--concurrency|--spec-drift|--harness) FLAG="$arg" ;;
    --exposed-only|--mitigated-only|--unreachable-only|\
    --show-personas|--show-bounty|--show-playbook|--show-spof|\
    --show-trust-boundary|--show-threat-model|--show-drift|--firehose|--honest)
      PASSTHROUGH="$PASSTHROUGH $arg" ;;
    --persona)
      PASSTHROUGH="$PASSTHROUGH $arg" ;;
    script-kiddie|opportunistic-criminal|apt-nation-state|supply-chain-attacker|malicious-insider)
      PASSTHROUGH="$PASSTHROUGH $arg" ;;
    *) [ "$FLAG" = "--all" ] && PATH_ARG="$arg" || EXTRA="$EXTRA $arg" ;;
  esac
done

case "$FLAG" in
  --sca)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only sca --format cli $PASSTHROUGH
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --secrets)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only secrets --format cli $PASSTHROUGH
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --authz)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format cli $PASSTHROUGH
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --mcp)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format cli $PASSTHROUGH
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --harness)
    # Multi-harness sweep: audit .claude/.cursor/.codex/.gemini/.kiro/...
    # config files at the project root. Add --include-home to also sweep ~/.
    INCLUDE_HOME=""
    case " $@ " in *" --include-home "*) INCLUDE_HOME="--include-home" ;; esac
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs harness "$PATH_ARG" $INCLUDE_HOME
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --concurrency)
    # v3 next-gen: surface only concurrency-bug family findings.
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format json --output .agentic-security/_concurrency-scan.json >/dev/null 2>&1
    node -e "
const fs=require('fs');
const d=JSON.parse(fs.readFileSync('.agentic-security/_concurrency-scan.json','utf8'));
const items=(d.findings||[]).filter(f=>f.family==='concurrency-bug');
console.log('Concurrency-bug findings: '+items.length);
console.log('');
for(const f of items.slice(0,40)){
  console.log('  ['+(f.severity||'').toUpperCase()+'] '+f.vuln+'  '+f.file+':'+f.line);
  if(f.remediation) console.log('    fix: '+f.remediation);
}
"
    rm -f .agentic-security/_concurrency-scan.json
    exit 0 ;;
  --spec-drift)
    # v3 next-gen: surface only specification-drift findings.
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format json --output .agentic-security/_spec-drift-scan.json >/dev/null 2>&1
    node -e "
const fs=require('fs');
const d=JSON.parse(fs.readFileSync('.agentic-security/_spec-drift-scan.json','utf8'));
const items=(d.findings||[]).filter(f=>f.family==='spec-drift');
console.log('Specification-drift findings: '+items.length);
console.log('');
for(const f of items.slice(0,40)){
  console.log('  ['+(f.severity||'').toUpperCase()+'] '+f.vuln+'  '+f.file+':'+f.line);
  if(f.description) console.log('    why: '+f.description);
}
"
    rm -f .agentic-security/_spec-drift-scan.json
    exit 0 ;;
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
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship "$PATH_ARG" $PASSTHROUGH
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

**`/scan --diff [--since <git-ref>]`** — Score the git diff between `--since` (default `HEAD~1`) and `HEAD` by architectural risk. Passes the diff to the `security-material-change` subagent which emits a per-file findings report and a "what to verify before merging" checklist. Risk levels: `critical` (auth removed, new shell call) → recommend `/fix --one` + `/triage --validate`; `high` → recommend `/triage --validate`; `medium`/`low`/`none` → safe to merge.

**`/scan --concurrency`** *(v3)* — Surface only concurrency-bug findings: missed unlocks, unguarded locks on early-return paths, fire-and-forget async, 2-lock deadlock cycles. Covers Go (`sync.Mutex`, channels), Java (`synchronized`, `Lock`), JS/TS (workers, promises), and Python (`asyncio.Lock`, `with`).

**`/scan --spec-drift`** *(v3)* — Surface only specification-drift findings: functions whose names claim a behavior the body doesn't deliver (e.g., `validateOwnership()` whose body never references `req.user.id`). Catches the bug class no pattern matcher reaches.

**`/scan --harness [--include-home]`** *(v4)* — Multi-harness configuration audit. Scans `.claude/`, `.cursor/`, `.codex/`, `.gemini/`, `.kiro/`, `.opencode/`, `.trae/`, `.qwen/`, `.zed/`, `.continue/`, `.aider/` at the project root. Catches: `Bash(*)` allow-rules, missing deny-lists, `dangerouslySkipPermissions` flags, hardcoded API keys in `CLAUDE.md` / `AGENTS.md`, prompt-injection / auto-run directives in instruction files, `${file}` / `${args}` interpolation in shell hooks, silent-error-suppression in security hooks, outbound HTTP from hooks. Add `--include-home` to also sweep `~/.claude/`, `~/.cursor/`, etc. for org-level hygiene.

## v3 production-aware filters

These flags compose with any mode above. They demote findings the customer's production stack already mitigates:

**`--exposed-only`** — Show only findings whose composite verdict is `exposed-in-prod` (not blocked by WAF / auth / network policy / feature flag, and reachable). The single biggest precision lifter — typical projects see 30–60% fewer findings to triage.

**`--mitigated-only`** — Inverse. Useful for verifying that your defenses cover the surface you think they cover.

**`--unreachable-only`** — Findings on code paths not reachable from any production entry.

**`--persona <name>`** — Filter to findings where the named attacker persona is in the finding's top-2 ranked personas. Personas: `script-kiddie`, `opportunistic-criminal`, `apt-nation-state`, `supply-chain-attacker`, `malicious-insider`.

## v3 supplementary output blocks

Add any of these to extend the report with extra blocks (the verdict and exit code are unchanged):

| Flag | What it adds |
|------|--------------|
| `--show-personas` | Per-persona top-3 findings — what each attacker class would target |
| `--show-bounty` | Predicted HackerOne / Immunefi USD payout bands per finding |
| `--show-playbook` | Copy-paste curl / Nuclei attack playbooks for high+ findings |
| `--show-spof` | Single-point-of-failure defensive controls (counterfactual analysis) |
| `--show-trust-boundary` | Mermaid diagram of the architecture with findings rendered on it |
| `--show-threat-model` | Auto-derived STRIDE threat model summary |
| `--show-drift` | Calibration-drift alarms — when self-reported confidence diverges from triage accuracy |

For deep dives on any v3 capability there is a dedicated slash command (now consolidated under `/posture`, `/triage`, etc).

## Consolidated modes

`/scan` also routes:

| Flag | Behaviour |
|---|---|
| `--watch` | Continuous incremental scan, writes `.agentic-security/watch-status.{md,json}` on every change |
| `--baseline` | Set / view / refresh the scan baseline |
| `--archaeology` | Historical analysis — when was each line of code authored, by whom, against which prompt |
| `--scanner-meta` | Scanner self-test / version diff / concurrency check / spec-drift check |

🛡  agentic-security · created by ClearCapabilities.Com
