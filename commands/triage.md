---
description: Interactive triage. Mark each finding TP / FP / wontfix. Feeds the active-learning loop for next scan.
argument-hint: "[<finding-id>] [--verdict tp|fp|wontfix] [--reason \"...\"]"
---

Walks every finding in the last scan ranked by exploitability + confidence, one at a time. Pass a `<finding-id>` to triage a single finding directly.

The user's verdicts are persisted to `.agentic-security/triage-feedback.json` and read by the engine's active-learning loop on the next scan (FR-PREC-4): findings whose `stableId` was previously marked `fp` are suppressed; findings marked `tp` get a confidence boost.

**This is a two-step, assistant-driven loop, not a blocking terminal prompt.** An earlier version used a Node `readline` interface and blocked on `rl.question()` — that only works with a live TTY attached to stdin, which the harness that actually runs this command does not provide, so it silently produced nothing (S6, Stage-0 audit: reproduced live — closed stdin makes it print the prompt once and exit 0 with zero verdicts recorded). The real interactive layer is this conversation: **you** (the assistant) list the findings, present each one to the user via normal conversation or `AskUserQuestion`, then invoke the record step below with their answer. Nothing here blocks waiting on stdin.

### Step 1 — list findings needing triage

This step's stdout is machine-readable JSON — no banner or other decoration mixed in.

```bash
node -e "
const fs = require('fs');
const arg = (process.argv[1] || '').trim();
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch (e) { console.error('No last-scan.json found. Run /scan --all first.'); process.exit(1); }
let findings = (scan.findings || []).slice();
if (arg) findings = findings.filter(f => f.id === arg || (f.id || '').includes(arg) || f.stableId === arg);
if (!findings.length) { console.error('No findings to triage.'); process.exit(0); }
findings.sort((a,b) => (b.exploitability||0) - (a.exploitability||0) || (b.confidence||0) - (a.confidence||0));
console.log(JSON.stringify(findings.map(f => ({
  id: f.id, stableId: f.stableId || null, vuln: f.vuln || '(unnamed)',
  file: f.file || null, line: f.line || null, severity: f.severity,
  exploitability: f.exploitability ?? null, confidence: f.confidence ?? null,
  cwe: f.cwe || null, snippet: (f.snippet || '').slice(0, 80),
})), null, 2));
" -- "$1"
```

Present each finding in the returned list to the user (in conversation, or via `AskUserQuestion` with options `tp`/`fp`/`wontfix`/`skip`) one at a time. After each answer, call Step 2 to record it before moving to the next finding — do not batch all findings into one question.

### Step 2 — record one verdict

```bash
node -e "
const fs = require('fs');
const path = require('path');
const [stableIdOrId, vuln, file, line, family, snippet, verdict, ...reasonParts] = process.argv.slice(1);
const reason = reasonParts.join(' ').slice(0, 280);
if (!['tp','fp','wontfix'].includes(verdict)) { console.error('verdict must be tp|fp|wontfix, got: ' + verdict); process.exit(1); }

// Premortem 2R3.3 / 2R-11: write path gated symmetrically with read path so
// an attacker who runs /triage can't poison the file in advance of an
// AGENTIC_SECURITY_LEARN flip. Default OFF — verdicts only persist when the
// operator explicitly says so.
const LEARN_ENABLED = process.env.AGENTIC_SECURITY_LEARN === '1' || process.argv.includes('--learn');
if (!LEARN_ENABLED) {
  console.log('· (verdict NOT recorded — read-only mode; set AGENTIC_SECURITY_LEARN=1 or pass --learn to persist)');
  process.exit(0);
}

const FEEDBACK = '.agentic-security/triage-feedback.json';
let feedback = { entries: [] };
try { feedback = JSON.parse(fs.readFileSync(FEEDBACK, 'utf8')); } catch {}
feedback.entries = feedback.entries || [];
feedback.entries.push({
  stableId: stableIdOrId || null,
  verdict, reason,
  family: family === '-' ? null : family,
  file: file === '-' ? null : file,
  line: line === '-' ? null : Number(line),
  vuln: vuln === '-' ? null : vuln,
  sinkSnippet: (snippet === '-' ? '' : snippet).slice(0, 200),
  at: new Date().toISOString(),
});
fs.mkdirSync(path.dirname(FEEDBACK), { recursive: true });
fs.writeFileSync(FEEDBACK, JSON.stringify(feedback, null, 2));
// Premortem 2R-7: also record into per-CWE production-triage metrics so
// /posture --trend can surface real-world precision trends.
(async () => {
  try {
    const { recordTriage } = await import(path.join(process.env.CLAUDE_PLUGIN_ROOT || '.', 'scanner/src/posture/validator-metrics.js'));
    recordTriage(process.cwd(), { family: family === '-' ? null : family, verdict, stableId: stableIdOrId || null });
  } catch { /* best-effort telemetry */ }
  console.log('✓ recorded ' + verdict + ' — ' + feedback.entries.length + ' total entries, applied on next /scan run.');
})();
" -- "${STABLE_ID:--}" "${VULN:--}" "${FILE:--}" "${LINE:--}" "${FAMILY:--}" "${SNIPPET:--}" "$VERDICT" "$REASON"
```

Set `STABLE_ID`/`VULN`/`FILE`/`LINE`/`FAMILY`/`SNIPPET`/`VERDICT`/`REASON` env vars (or pass `-` for any field you don't have) before invoking this block for each finding the user gives a verdict on. `skip`/`next`/`prev` need no write at all — just move to the next finding in the Step 1 list without calling Step 2.

Tell the user how many verdicts were recorded and remind them the suppressions take effect on the next `/scan`.

## Tournament mode

Pass `--tournament` to walk findings ranked by `compositeRisk` (descending) instead of by exploitability + confidence. Each finding is presented one at a time with the past-decision lookup (`query_triage_memory` MCP tool) — surfaces "we already decided on something like this" before you re-decide.

```bash
/triage --tournament                         # all findings
/triage --tournament --severity critical     # criticals only
/triage --tournament --family sqli           # only SQLi
/triage --tournament --limit 10              # cap at 10
```

Tournament mode produces the same final state (`triage-feedback.json` + cross-repo memory bridge writes), but the ordering + one-keystroke-decision UI is the cleaner workflow for a focused triage pass.

## Consolidated modes (v0.85.0+)

`/triage` now also routes:

| Flag | Behaviour |
|---|---|
| `--show` | View findings table / HTML report. `--all|--kev|--chains|--threat-model` |
| `--explain` | Plain-English explanation of a finding. `--narrative|--provenance|--gap` |
| `--validate` | Verify a finding is exploitable. PoC + adversarial variants + verdict |
| `--red-team` | Roleplay an attacker: exploit narrative + fuzz inputs + defender evaluation |
| `--exploit` | Build PoC in chosen format. `--format curl|jest|pytest|burp|sqlmap` |
| `--query` | Write a security check in natural language; emits YAML rule + preview |
| `--tournament` | Ranked walk-through |
| `--deep` | Full **red-team → blue-team → auditor** cascade on ONE finding — the deepest single-finding review. Hash-chained transcript trio; auditor verdict is canonical. `--target <url>`, `--max-calls`, `--max-wall-ms` |

Add `--json` to any mode for machine-readable output.

## Deep review — red / blue / auditor (`--deep`)

`/triage --deep <finding-id>` runs the full red-team → blue-team → auditor cascade on a
single finding — the deepest review the plugin offers. Each phase emits a hash-chained
transcript; the auditor's verdict is canonical (`exploit-confirmed` / `exploit-mitigable` /
`exploit-uncertain` / `exploit-rejected`). Without `--target` the red team runs dry (static
reasoning only); without `AGENTIC_SECURITY_LLM_ENDPOINT` every phase short-circuits to its
static-analysis equivalent — still a useful verdict, offline.

This is the most expensive command in the plugin — it honors a call/wall budget.

```bash
FINDING=""; TARGET=""; MAX_CALLS="30"; MAX_WALL_MS="480000"; NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    finding) FINDING="$arg"; NEXT=""; continue ;;
    target) TARGET="$arg"; NEXT=""; continue ;;
    max-calls) MAX_CALLS="$arg"; NEXT=""; continue ;;
    max-wall-ms) MAX_WALL_MS="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --deep) ;;
    --finding) NEXT="finding" ;;
    --target) NEXT="target" ;;
    --max-calls) NEXT="max-calls" ;;
    --max-wall-ms) NEXT="max-wall-ms" ;;
    --*) ;;
    *) [ -z "$FINDING" ] && FINDING="$arg" ;;   # positional finding id
  esac
done

if [ -z "$FINDING" ]; then
  echo "Usage: /triage --deep <finding-id> [--target <url>] [--max-calls 30] [--max-wall-ms 480000]"
  echo "Without --target the red team runs dry (static reasoning only)."
  exit 1
fi

mkdir -p .agentic-security/three-agent-transcripts
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  triage --deep · budget for this run"
echo "    Finding:        ${FINDING}"
echo "    Max LLM calls:  ${MAX_CALLS}  (red + blue + auditor, combined)"
echo "    Max wall time:  $((MAX_WALL_MS / 1000))s"
echo "    Target:         ${TARGET:-(none — red team runs dry/static)}"
echo "  Each phase short-circuits to static analysis without an LLM endpoint."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

node -e "
const fs = require('fs');
const path = require('path');
const { runThreeAgentReview } = require('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/three-agent-pipeline.js');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json','utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const id = process.env.FINDING;
const target = process.env.TARGET;
const maxCalls = parseInt(process.env.MAX_CALLS || '30', 10);
const maxWallMs = parseInt(process.env.MAX_WALL_MS || '480000', 10);
const f = (scan.findings || []).find(x => x.id === id || x.stableId === id);
if (!f) { console.log('No finding matches ' + id); process.exit(0); }
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', RED='31', YELLOW='33', GREEN='32', CYAN='36';
(async () => {
  console.log('');
  console.log(W('Three-agent review', BOLD));
  console.log(W('  Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
  console.log(W('  Target:  ' + (target || '(none — dry-run)'), DIM));
  const result = await runThreeAgentReview(f, { target, maxCalls, maxWallMs });
  console.log(W('▼ Phase 1 — Red Team', RED));
  console.log('  outcome:        ' + result.red.outcome);
  console.log('  transcript:     ' + result.red.transcriptHead);
  console.log(W('▼ Phase 2 — Blue Team (defender)', CYAN));
  console.log('  mode:           ' + result.blue.mode);
  for (const r of result.blue.recommendations) console.log('    • ' + r);
  const VC = result.auditor.verdict === 'exploit-confirmed' ? RED
           : result.auditor.verdict === 'exploit-mitigable' ? YELLOW
           : result.auditor.verdict === 'exploit-rejected' ? GREEN : DIM;
  console.log(W('▼ Phase 3 — Auditor', BOLD));
  console.log('  ' + W('VERDICT: ' + result.auditor.verdict, VC + ';' + BOLD));
  console.log('  rationale: ' + result.auditor.rationale);
  const out = path.join('.agentic-security', 'three-agent-transcripts', (f.stableId || f.id || 'transcript') + '.json');
  fs.writeFileSync(out, JSON.stringify(result, null, 2));
  console.log(W('Full envelope: ' + out, DIM));
})();
" FINDING=\"$FINDING\" TARGET=\"$TARGET\" MAX_CALLS=\"$MAX_CALLS\" MAX_WALL_MS=\"$MAX_WALL_MS\"
```

| Auditor verdict | Meaning |
|---|---|
| `exploit-confirmed` | Red team reached data-exfil / priv-esc / account-takeover AND no static hardening exists. Manual remediation required. |
| `exploit-mitigable` | Red team confirmed but blue team's recommendations would close it. Apply + re-run. |
| `exploit-uncertain` | Red team did not reach business impact (aborted-budget / timeout / no LLM endpoint). Re-run longer or with a live target. |
| `exploit-rejected` | Defense appears adequate against the modeled attacker. |

Use it before promoting a finding to "blocker," or after a `/fix` to confirm the auditor flips to `exploit-rejected`.

## FP-first ordering

When presenting findings for triage (default and `--show`), order them **likely-false-positive first** using this project's `triage-memory.json` history: for each finding's `family` + rule, compute the historical FP rate from prior verdicts and sort descending. Rationale — clearing the cheap, obvious FPs first builds momentum and shrinks the list before the user reaches the judgement-heavy true positives. Findings from families with no history fall back to `compositeRisk` ascending. Show the inferred FP-likelihood as a hint column (`likely-fp` / `unknown` / `likely-tp`) so the user knows why the order is what it is.
