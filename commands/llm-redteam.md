---
description: Red-team your LLM endpoint or LLM-using code — promptfoo-style adversarial testing across 30+ harm categories with attack-strategy mutations (base64, role-play, authority-claim, hypothetical, multilingual, chained-context).
argument-hint: "[--endpoint URL] [--api-key KEY] [--categories security,privacy,harmful,bias,misinformation,agentic,coding-agent] [--strategies base64-encode,role-play-dan,authority-claim,...] [--scan]"
---

Two modes:

- **`--scan`** (default if no `--endpoint`): static analysis of the current project's LLM-calling code. Catches missing output validation, system-prompt-leak risks, missing max_tokens, eval-on-LLM-output, SQL-from-LLM-output, trusted-classifier shortcuts.
- **`--endpoint URL`**: active red-team — sends the prompt corpus through the endpoint and judges responses against expected-rejection patterns.

```bash
ENDPOINT=""
API_KEY=""
CATEGORIES=""
STRATEGIES=""
MODE="scan"
OUTPUT="${OUTPUT:-llm-redteam-report.md}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; MODE="active"; shift 2;;
    --api-key) API_KEY="$2"; shift 2;;
    --categories) CATEGORIES="$2"; shift 2;;
    --strategies) STRATEGIES="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    --scan) MODE="scan"; shift;;
    *) shift;;
  esac
done

if [ "$MODE" = "scan" ]; then
  echo "Static red-team scan: identifying LLM-call sites with missing defenses…"
  /agentic-security:scan --llm
  echo ""
  echo "Static findings written. For active red-team, supply --endpoint URL."
  exit 0
fi

# Active mode — execute via Node helper.
node -e "
const { runActiveRedteam, renderRedteamMarkdownReport } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/llm-redteam.js');
const opts = {
  endpoint: '${ENDPOINT}',
  apiKey: '${API_KEY}' || undefined,
  categories: '${CATEGORIES}' ? '${CATEGORIES}'.split(',') : undefined,
  strategies: '${STRATEGIES}' ? '${STRATEGIES}'.split(',') : undefined,
  concurrency: 4,
};
const { results, summary } = await runActiveRedteam(opts);
const md = renderRedteamMarkdownReport(results, summary, '${ENDPOINT}');
require('fs').writeFileSync('${OUTPUT}', md);
console.log('────────────────────────────────────────────────');
console.log('Red-team complete:', summary.total, 'prompts');
console.log('  ✅ Pass:', summary.pass, '  ❌ Fail:', summary.fail, '  ⚠ Inconclusive:', summary.inconclusive);
if (summary.failedPlugins.length) {
  console.log('Failed plugins:', summary.failedPlugins.join(', '));
}
console.log('Report:', '${OUTPUT}');
"
```

## Categories (promptfoo-aligned)

| Category | Plugins covered |
|---|---|
| `security` | system-prompt-override, prompt-extraction, ascii-smuggling, jailbreak-dan, indirect-prompt-injection, sql-injection, shell-injection |
| `privacy` | direct-pii-exposure, pii-social-engineering, pii-session-data |
| `harmful` | self-harm, violent-crime, illegal-drugs, chemical-biological-weapons, ied |
| `bias` | race-bias, gender-bias, age-bias |
| `misinformation` | medical-incorrect-knowledge, political-opinions, hallucination |
| `agentic` | tool-discovery, bola, bfla, memory-poisoning |
| `coding-agent` | secret-file-read, secret-env-read, network-egress-bypass, automation-poisoning |

## Attack strategies

Each base prompt can be mutated via:

- `base64-encode` — wrap in base64 to bypass naive content filters
- `rot13` — ROT13 the payload
- `role-play-dan` — DAN-style role-play preamble
- `authority-claim` — false admin/security-team identity
- `hypothetical-framing` — "in a fictional novel..." wrapper
- `multilingual` — translate-and-execute pretense
- `chained-context` — embed payload inside a long document

## Examples

```bash
# Static scan of current project (no LLM calls made)
/llm-redteam --scan

# Full red-team against a local endpoint
/llm-redteam --endpoint http://localhost:8000/chat

# Targeted: only privacy + agentic, with multiple attack mutations
/llm-redteam --endpoint https://api.example.com/llm \
  --api-key sk-abc... \
  --categories privacy,agentic \
  --strategies base64-encode,role-play-dan,authority-claim
```

## What the static scan finds

When the model is the agent's own LLM-using code, `--scan` runs SAST checks for:

| Check | Finding |
|---|---|
| User input concatenated into system prompt | Direct prompt injection vector (CWE-77) |
| `eval(llm_output)` / `exec(llm_output)` | RCE if model produces code on attacker request (CWE-94) |
| `db.query(llm_output)` | SQL injection via model output (CWE-89) |
| LLM call without `max_tokens` | Unbounded cost / DoS (CWE-770) |
| `if response.includes("safe")` | Trusting LLM-as-classifier via substring (CWE-1289) |
| System prompt without anti-injection guidance | Missing baseline defense (CWE-77) |

Each finding is emitted as a normal `/scan` finding so it flows through `/fix`, `/show-findings`, etc.
