---
description: Interactive triage. Mark each finding TP / FP / wontfix. Feeds the active-learning loop for next scan.
argument-hint: "[<finding-id>]"
---

Interactive triage. By default cycles through every finding in the last scan ranked by exploitability + confidence. Pass a `<finding-id>` to triage a single finding directly.

The user's verdicts are persisted to `.agentic-security/triage-feedback.json` and read by the engine's active-learning loop on the next scan (FR-PREC-4): findings whose `stableId` was previously marked `fp` are suppressed; findings marked `tp` get a confidence boost.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const argv = process.argv.slice(1);
const arg = (argv.find(a => !a.startsWith('--')) || '').trim();
const learnFlag = argv.includes('--learn');

// Premortem 2R3.3 / 2R-11: write path gated symmetrically with read path so
// an attacker who runs /triage can't poison the file in advance of an
// AGENTIC_SECURITY_LEARN flip. Default OFF — verdicts only persist when the
// operator explicitly says so.
const LEARN_ENABLED = process.env.AGENTIC_SECURITY_LEARN === '1' || learnFlag;
if (!LEARN_ENABLED) {
  console.error('agentic-security: triage verdicts will NOT be persisted.');
  console.error('  To enable: set AGENTIC_SECURITY_LEARN=1 in your env, or pass --learn.');
  console.error('  (Read-only triage mode — you can still walk findings.)');
}

let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch (e) { console.error('No last-scan.json found. Run /scan --all first.'); process.exit(1); }

let findings = (scan.findings || []).slice();
if (arg) findings = findings.filter(f => f.id === arg || (f.id || '').includes(arg) || f.stableId === arg);
if (!findings.length) { console.error('No findings to triage.'); process.exit(0); }

findings.sort((a,b) => (b.exploitability||0) - (a.exploitability||0) || (b.confidence||0) - (a.confidence||0));

const FEEDBACK = '.agentic-security/triage-feedback.json';
let feedback = { entries: [] };
try { feedback = JSON.parse(fs.readFileSync(FEEDBACK, 'utf8')); } catch {}
feedback.entries = feedback.entries || [];

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(res => rl.question(q, ans => res(ans.trim())));

(async () => {
  const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
  let i = 0;
  while (i < findings.length) {
    const f = findings[i];
    console.log('');
    console.log(W('─'.repeat(72), '2'));
    console.log(\`[\${i+1}/\${findings.length}] \` + W(f.vuln || '(unnamed)', '1'));
    console.log(\`  File:           \${f.file || '(none)'}:\${f.line || '?'}\`);
    console.log(\`  Severity:       \${f.severity}  ·  Exploitability: \${f.exploitability ?? '?'}  ·  Confidence: \${f.confidence ?? '?'}\`);
    if (f.cwe) console.log(\`  CWE:            \${f.cwe}\`);
    if (f.stableId) console.log(\`  Stable ID:      \${f.stableId}\`);
    if (f.snippet) console.log(\`  Snippet:        \${(f.snippet || '').slice(0, 80)}\`);
    console.log('');
    const ans = (await ask('  [t]p · [f]p · [w]ontfix · [n]ext · [p]rev · [s]kip · [q]uit ? ')).toLowerCase();
    if (ans === 'q') break;
    if (ans === 'n' || ans === 's') { i++; continue; }
    if (ans === 'p') { i = Math.max(0, i - 1); continue; }
    if (['t','f','w'].includes(ans)) {
      const reason = (await ask('  Reason (optional): ')).slice(0, 280);
      const verdict = ans === 't' ? 'tp' : ans === 'f' ? 'fp' : 'wontfix';
      if (!LEARN_ENABLED) {
        console.log(W('  · (verdict NOT recorded — read-only mode; pass --learn or set AGENTIC_SECURITY_LEARN=1 to persist)', '33'));
        i++; continue;
      }
      feedback.entries.push({
        stableId: f.stableId || null,
        verdict, reason,
        family: f.family || null,
        file: f.file || null, line: f.line || null, vuln: f.vuln || null,
        sinkSnippet: (f.sink?.snippet || f.snippet || '').slice(0, 200),
        at: new Date().toISOString(),
      });
      fs.mkdirSync(path.dirname(FEEDBACK), { recursive: true });
      fs.writeFileSync(FEEDBACK, JSON.stringify(feedback, null, 2));
      // Premortem 2R-7: also record into per-CWE production-triage metrics so
      // /posture --trend can surface real-world precision trends.
      try {
        const { recordTriage } = await import(path.join(process.env.CLAUDE_PLUGIN_ROOT || '.', 'scanner/src/posture/validator-metrics.js'));
        recordTriage(process.cwd(), { family: f.family, verdict, stableId: f.stableId });
      } catch { /* best-effort telemetry */ }
      console.log(W('  ✓ recorded ' + verdict, '32'));
      i++; continue;
    }
    console.log('  (unrecognized — try t/f/w/n/p/s/q)');
  }
  rl.close();
  console.log('');
  console.log(W('Triage feedback saved to ' + FEEDBACK, '2'));
  console.log(W(\`\${feedback.entries.length} total entries — applied on next /scan run.\`, '2'));
})();
" -- "$1"
```

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
