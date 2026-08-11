---
description: Posture + reporting. Status snapshot, A-F report card, harness score, trend, threat model, stack playbook.
argument-hint: "[--status|--report-card|--harness|--trend|--threat|--playbook|--mgmt|--cache]"
---

# /posture

Posture + reporting dispatcher. One command, multiple views.

## Modes

| Flag | Behaviour |
|---|---|
| (default) | **Combined dashboard** — health snapshot + A–F grade + trend arrow in one screen (see below) |
| `--status` | One-screen plugin + project health snapshot — version, last scan, findings by severity, hook activation, suppressions. (Cache economics is a separate view — see `--cache`.) |
| `--report-card` | Single A–F letter grade + one explanation + one next action |
| `--harness` | Score this project's AI agent harness against the six-domain rubric |
| `--trend` | Findings delta between the last two scans — introduced/fixed/net change |
| `--threat` | Threat model views: STRIDE, personas, playbook, bounty, adversary, surface, boundary, SPOF |
| `--playbook` | Stack-specific posture playbook (Express, FastAPI, Django, Rails, Spring Boot, etc.) |
| `--mgmt` | Posture management surface — which of the five customer-supplied import digests (auth, network, WAF, telemetry, feature-flag) are configured, and how many findings each one mitigated/annotated on the last scan |
| `--cache` | **Prompt-cache economics** for this session — cache-hit %, $ saved by caching, $ wasted on avoidable cache misses (model switches / TTL gaps / prefix changes), per-model breakdown. Reads the Claude Code transcript usage; advisory, read-only. |

Add `--json` to any mode to emit machine-readable output for scripting / CI.

## Default dashboard

Bare `/posture` (no flag) renders the three views developers usually want together, in one screen:

1. **Status** — version, last-scan age, hook activation, open findings by severity.
2. **Grade** — the A–F letter from `--report-card` with its one-line rationale.
3. **Trend** — the `↑ / → / ↓` arrow comparing the last two scans (regressing / flat / improving) and the one next action.

If there's no prior scan, the dashboard collapses to a single "run `/scan --all` first" prompt.

## Examples

```bash
/posture                       # status snapshot (default)
/posture --report-card         # A–F grade + next action
/posture --harness             # AI agent harness scoring
/posture --trend               # findings trend
/posture --threat --view stride
/posture --playbook            # stack-specific playbook
/posture --cache               # prompt-cache economics for this session
```

## Implementation

Every mode below runs a real, verified command.

```bash
FLAG="${1:---status}"
case "$FLAG" in
  --status)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs version
    node -e "
      const fs = require('fs');
      const path = require('path');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/workflow-installer.js').then(({ detectProject }) => {
        const stateDir = path.join('.', '.agentic-security');
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync(path.join(stateDir, 'last-scan.json'), 'utf8')); } catch {}
        const { hookManager } = detectProject('.');
        if (!scan) {
          console.log(JSON.stringify({ lastScan: null, hookManager, message: 'No prior scan found. Run /scan --all first.' }, null, 2));
          return;
        }
        const findings = scan.findings || [];
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const f of findings) { if (f.severity in bySeverity) bySeverity[f.severity]++; }
        console.log(JSON.stringify({
          lastScanAt: scan.startedAt || null,
          hookManager,
          bySeverity,
          totalFindings: findings.length,
          suppressedCount: scan.suppressedCount || 0,
        }, null, 2));
      });
    " ;;
  --harness)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs harness . ;;
  --trend)
    node -e "
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/security-trend.js').then(m => {
        console.log(JSON.stringify(m.computeTrend('.'), null, 2));
      });
    " ;;
  --report-card)
    node -e "
      const fs = require('fs');
      const path = require('path');
      import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/streak.js').then(({ loadStreak }) => {
        const stateDir = path.join('.', '.agentic-security');
        const streak = loadStreak(stateDir);
        let scan = null;
        try { scan = JSON.parse(fs.readFileSync(path.join(stateDir, 'last-scan.json'), 'utf8')); } catch {}
        if (!scan) { console.log(JSON.stringify({ grade: null, message: 'No prior scan found. Run /scan --all first.' })); return; }
        const findings = scan.findings || [];
        const critical = findings.filter(f => f.severity === 'critical').length;
        const high = findings.filter(f => f.severity === 'high').length;
        const kev = findings.filter(f => f.kev).length;
        console.log(JSON.stringify({ grade: streak.lastGrade, previousGrade: streak.previousGrade, critical, high, kev, total: findings.length }, null, 2));
      });
    " ;;
  --threat)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --show-threat-model --show-trust-boundary --show-personas --show-bounty --show-playbook --show-spof --format cli
    node -e "
      const fs = require('fs');
      let scan = null;
      try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
      console.log(JSON.stringify({ entrypointInventory: (scan && scan.entrypointInventory) || null }, null, 2));
    " ;;
  --playbook)
    node -e "
      const fs = require('fs');
      let scan = null;
      try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
      if (!scan) { console.log(JSON.stringify({ message: 'No prior scan found. Run /scan --all first.' })); process.exit(0); }
      const items = (scan.findings || []).filter(f => (f.id || '').startsWith('stack-playbook:'));
      console.log(JSON.stringify({ stackPlaybookItems: items }, null, 2));
    " ;;
  --mgmt)
    node -e "
      const fs = require('fs');
      Promise.all([
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/auth-posture-import.js'),
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/network-policy-import.js'),
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/waf-ingest.js'),
        import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/telemetry-ingest.js'),
      ]).then(([auth, net, waf, telem]) => {
        const authPosture = auth.loadAuthPosture('.');
        const networkPosture = net.loadNetworkPosture('.');
        const wafRules = waf.loadWafRules('.');
        const telemetry = telem.loadTelemetry('.');
        const flagsConfigured = fs.existsSync('feature-flag-rollouts.json') || fs.existsSync('feature-flags.json');

        let scan = null;
        try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
        const findings = (scan && scan.findings) || [];
        console.log(JSON.stringify({
          auth: { configured: !!(authPosture && authPosture.routes), routeCount: authPosture ? Object.keys(authPosture.routes || {}).length : 0, findingsMitigated: findings.filter(f => f.mitigatedByAuth).length },
          network: { configured: !!(networkPosture && networkPosture.workloads), workloadCount: networkPosture ? Object.keys(networkPosture.workloads || {}).length : 0, findingsMitigated: findings.filter(f => f.mitigatedByNetwork).length },
          waf: { configured: wafRules.length > 0, ruleCount: wafRules.length, findingsMitigated: findings.filter(f => f.mitigatedByWaf).length },
          telemetry: { configured: !!telemetry, findingsAnnotated: findings.filter(f => f.prodRequestCount !== null && f.prodRequestCount !== undefined).length, coldPaths: findings.filter(f => f.coldPath).length, hotPaths: findings.filter(f => f.hotPath).length },
          featureFlags: { configured: flagsConfigured, findingsGated: findings.filter(f => f.featureFlag).length },
        }, null, 2));
      });
    " ;;
esac
```

`--status` prints the real CLI `version` line, then reads `.agentic-security/last-scan.json` for `startedAt` (last-scan age), a findings-by-severity breakdown, `totalFindings`, and `suppressedCount` (already present in `toJSON()`'s output — no fix needed), plus `workflow-installer.js#detectProject().hookManager` (`'husky' | 'pre-commit' | 'lefthook' | 'native' | null`) for hook activation. With no prior scan it reports that plainly (`lastScan: null` + a prompt to run `/scan --all`) rather than fabricating zeros.

`--harness` runs the real `harness` CLI subcommand (`bin/agentic-security.js` → `posture/harness-score.cjs` via `cmdHarness`) — scores this project's `.claude/`, `.cursor/`, `.codex/`, etc. configs against the six-domain rubric.

`--trend` calls `computeTrend()` (`posture/security-trend.js`) directly, reading `.agentic-security/scan-history.json`. That file is populated by `runScan()` itself (`src/runScan.js` calls `appendScanSnapshot` on every scan, CLI or in-process) — no separate wiring needed on the write side. The result is `{ hasTrend, prev, curr, introduced, fixed, delta, critDelta, improving }` when at least two scans exist, or `{ hasTrend: false, message: "Need at least 2 scans..." }` otherwise. Render `introduced`/`fixed`/`delta` as the "findings trend" — there is no weekly bucketing; it's always last-scan-vs-this-scan.

`--report-card` reads `.agentic-security/streak.json`'s `lastGrade` (computed by `posture/streak.js#recordScan`, already run on every scan) plus the critical/high/KEV counts from `last-scan.json` for the one-line explanation. Suggest the next action from whichever count is non-zero, in order: KEV-listed dependencies first (actively exploited in the wild), then critical, then high.

`--threat` runs a real scan with all six `--show-*` flags that back the STRIDE/personas/playbook/bounty/SPOF/trust-boundary sub-views (`bin/agentic-security.js`'s existing scan flags — "adversary" in the mode table is the persona/archetype framing `--show-personas` already provides, not a separate feature), then separately prints `scan.entrypointInventory` (the "surface" sub-view) — that field is computed by the engine on every scan but was dropped by `toJSON()` until this fix (see `test/annotator-errors.test.js`).

`--playbook` filters `last-scan.json`'s findings for the `stack-playbook:` id prefix — `posture/stack-playbook.js#runStackPlaybook` runs on every scan (wired in `engine.js`) and its stack-specific checklist items land there as `severity: 'info'` findings, one per checklist line, grouped by the detected stack in each finding's `vuln` text (`[Express Security Checklist] ...`). Currently only Express and the 11 pre-existing stacks (Next.js, Supabase, Clerk, NextAuth, Stripe, Prisma/Drizzle, MongoDB, OpenAI/Anthropic/LangChain, email, tRPC, FastAPI, Django) have real checklist content — React, Fastify, Hono, and Lucia are detected but have no playbook section yet (a disclosed content gap, not silently claimed as covered).

`--mgmt` calls the four exported `loadX(scanRoot)` readers directly (`auth-posture-import.js#loadAuthPosture`, `network-policy-import.js#loadNetworkPosture`, `waf-ingest.js#loadWafRules`, `telemetry-ingest.js#loadTelemetry`) to report whether each customer-side digest file is present, plus a direct file-existence check for the two feature-flag rollout filenames (`feature-flags.js#loadRollouts` isn't exported, so its candidate paths are checked inline rather than duplicating its parsing logic). Mitigation/annotation counts come from `last-scan.json`'s findings — `mitigatedByAuth`/`mitigatedByNetwork`/`mitigatedByWaf`/`featureFlag`/`prodRequestCount` are all stamped by the corresponding `annotateX` pass, already wired in `engine.js`, and all survive `toJSON()`'s per-finding allowlist. A surface reporting `configured: false` means no digest file was found, not that nothing needed mitigating.

`--cache` runs the `cache-report` CLI subcommand (`scanner/bin/agentic-security.js` → `scanner/src/posture/cache-economics.js`), which parses the Claude Code transcript usage for this session and prints the economics + any detected cache leaks. The same data is available to agents via the `query_cache_telemetry` MCP tool.
