---
description: Run the multi-step adversary-agent (FR-ADV-1) — a bounded-budget LLM agent that simulates a real attacker against ONE finding. Produces a hash-chained transcript showing what data was reached, what permissions were obtained, what business actions were performed.
argument-hint: "--finding <id> --target <url> [--max-calls 20] [--max-wall-ms 300000]"
---

For a single finding, spawn an authorized-attacker LLM that operates against a live target URL with a bounded tool budget. Tools are ACL-restricted: `http.get`, `http.post`, `db.read_sandbox_copy`, `record_outcome`. The transcript is hash-chained for tamper evidence.

**Prerequisites** (the agent is a no-op without these):
- `AGENTIC_SECURITY_LLM_ENDPOINT` — OpenAI-compatible chat completions URL
- `AGENTIC_SECURITY_LLM_API_KEY` — bearer token
- `--target <url>` — a sandboxed copy of your app (see `/scan` for `verifier-ephemeral` Docker driver)
- **Authorization** — you own the target or have explicit pen-test permission

```bash
FINDING=""
TARGET=""
MAX_CALLS="20"
MAX_WALL_MS="300000"
NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    finding) FINDING="$arg"; NEXT=""; continue ;;
    target) TARGET="$arg"; NEXT=""; continue ;;
    max-calls) MAX_CALLS="$arg"; NEXT=""; continue ;;
    max-wall-ms) MAX_WALL_MS="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --finding) NEXT="finding" ;;
    --target) NEXT="target" ;;
    --max-calls) NEXT="max-calls" ;;
    --max-wall-ms) NEXT="max-wall-ms" ;;
  esac
done

if [ -z "$FINDING" ] || [ -z "$TARGET" ]; then
  echo "Usage: /adversary --finding <id> --target <url> [--max-calls 20] [--max-wall-ms 300000]"
  echo ""
  echo "Required env:"
  echo "  AGENTIC_SECURITY_LLM_ENDPOINT  OpenAI-compatible chat completions URL"
  echo "  AGENTIC_SECURITY_LLM_API_KEY   bearer token"
  echo ""
  echo "Run /scan first to populate .agentic-security/last-scan.json."
  exit 1
fi

if [ -z "$AGENTIC_SECURITY_LLM_ENDPOINT" ]; then
  echo "❌  AGENTIC_SECURITY_LLM_ENDPOINT not set. The adversary agent is a no-op without it."
  echo ""
  echo "Set it to an OpenAI-compatible endpoint:"
  echo "  export AGENTIC_SECURITY_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions"
  echo "  export AGENTIC_SECURITY_LLM_API_KEY=sk-..."
  exit 1
fi

mkdir -p .agentic-security/adversary-transcripts

node -e "
const fs = require('fs');
const path = require('path');
const { runAgent } = require('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/adversary-agent.js');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }

const id = process.env.FINDING;
const target = process.env.TARGET;
const maxCalls = parseInt(process.env.MAX_CALLS || '20', 10);
const maxWallMs = parseInt(process.env.MAX_WALL_MS || '300000', 10);

const f = (scan.findings || []).find(x => x.id === id || x.stableId === id);
if (!f) { console.log('No finding matches ' + id); process.exit(0); }

const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', RED='31', GREEN='32';

console.log('');
console.log(W('Adversary-agent run', BOLD));
console.log(W('  Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
console.log(W('  Target:  ' + target, DIM));
console.log(W('  Budget:  ≤' + maxCalls + ' calls, ≤' + (maxWallMs/1000) + 's wall time', DIM));
console.log(W('  AUTHORIZED USE ONLY — you have asserted permission to test ' + target, DIM));
console.log('');

(async () => {
  const result = await runAgent(f, { target, maxCalls, maxWallMs });
  const transcript = result.transcript;
  const outcome = result.outcome;
  console.log(W('Tool calls:', BOLD));
  for (const e of transcript.entries) {
    if (e.tool) {
      const status = e.refused ? W('refused', RED) : (e.result && e.result.status ? String(e.result.status) : 'ok');
      console.log('  ' + e.tool.padEnd(20) + ' ' + status.padEnd(10) + ' ' + JSON.stringify(e.args || {}).slice(0, 60));
    } else {
      console.log('  ' + W('phase:', DIM) + ' ' + (e.phase || '?') + '  ' + (e.reason || ''));
    }
  }
  console.log('');
  const color = outcome.startsWith('aborted') || outcome === 'unverified-no-llm-endpoint' ? DIM
              : outcome === 'failed' ? RED
              : RED;
  console.log(W('Outcome: ', BOLD) + W(outcome, color));
  console.log('');
  const out = path.join('.agentic-security', 'adversary-transcripts', (f.stableId || f.id || 'transcript') + '.ndjson');
  const lines = [JSON.stringify({ seedFinding: transcript.seedFinding, target: transcript.target, startedAt: transcript.startedAt })]
    .concat(transcript.entries.map(e => JSON.stringify(e)));
  fs.writeFileSync(out, lines.join('\n') + '\n');
  console.log(W('Full transcript: ' + out, DIM));
  console.log(W('Hash-chained for tamper evidence (final head: ' + (transcript.chainHead || '') + ')', DIM));
})();
" FINDING="$FINDING" TARGET="$TARGET" MAX_CALLS="$MAX_CALLS" MAX_WALL_MS="$MAX_WALL_MS"
```

## What the agent does

Operating against the target URL, the LLM agent chooses tool calls within the ACL:

| Tool | Purpose |
|---|---|
| `http.get(path, headers?)` | Reconnaissance + read-only probing |
| `http.post(path, body, headers?)` | State-changing requests |
| `db.read_sandbox_copy(query)` | Read against a sandboxed DB copy (caller must supply) |
| `record_outcome({outcome, evidence})` | Terminate with a verdict |

Outcomes: `data-exfil`, `priv-esc`, `account-takeover`, `financial-loss`, `cleanup-traces`, `failed`, `aborted-budget`, `aborted-timeout`.

## Safety

- Default-deny network — the agent's container only sees `${TARGET}`
- Tool ACL is hard-coded outside LLM control
- Budget enforcement is server-side (the runner refuses calls past the limit)
- Hash-chained transcript is tamper-evident — verify with the integrity helper

## Related

- **`/playbook --finding <id>`** — The static curl/Nuclei version of the same probe, no LLM needed.
- **`/validate-findings --finding <id>`** — Single-step PoC + regression test generator.

🛡  agentic-security · created by ClearCapabilities.Com
