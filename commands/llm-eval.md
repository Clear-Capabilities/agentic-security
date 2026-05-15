---
description: Generate a promptfoo-style YAML eval suite for an LLM endpoint. Drops in CI-ready test files with red-team prompts pre-loaded so you can run via `promptfoo eval` or our built-in runner.
argument-hint: "[--endpoint URL] [--out promptfoo.yaml] [--corpus full|jailbreak|bias|harmful]"
---

Writes a promptfoo-compatible YAML eval file (the corpus is also runnable directly via our `/llm-redteam` command). Use this when you want to integrate with existing promptfoo tooling, or commit the eval suite as a regression gate in CI.

```bash
ENDPOINT="${1:-http://localhost:8000/chat}"
OUT="${OUT:-promptfoo.yaml}"
CORPUS="${CORPUS:-full}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --corpus) CORPUS="$2"; shift 2;;
    *) shift;;
  esac
done

node -e "
const { RED_TEAM_PROMPTS } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/llm-redteam-prompts.js');
const corpus = '${CORPUS}';
let prompts = RED_TEAM_PROMPTS;
if (corpus === 'jailbreak') prompts = prompts.filter(p => p.category === 'security');
if (corpus === 'bias') prompts = prompts.filter(p => p.category === 'bias');
if (corpus === 'harmful') prompts = prompts.filter(p => p.category === 'harmful');

// Emit promptfoo-compatible YAML.
const yaml = [
  'description: agentic-security red-team suite (auto-generated)',
  '',
  'prompts:',
  '  - \"{{prompt}}\"',
  '',
  'providers:',
  '  - id: http',
  '    config:',
  '      url: \"${ENDPOINT}\"',
  '      method: POST',
  '      headers:',
  '        Content-Type: application/json',
  '      body:',
  '        prompt: \"{{prompt}}\"',
  '      transformResponse: \"json.response || json.text || json.choices?.[0]?.message?.content || json\"',
  '',
  'tests:',
];
for (const p of prompts) {
  yaml.push('  - description: \"[' + p.category + '/' + p.plugin + '] ' + p.description.replace(/\"/g, '\\\\\"') + '\"');
  yaml.push('    vars:');
  yaml.push('      prompt: |');
  yaml.push('        ' + p.prompt.split('\\n').join('\\n        '));
  yaml.push('    assert:');
  // Convert JS regex source to a YAML-safe matches assertion
  const pattern = p.expectedRejection.source.replace(/\\\\/g, '\\\\\\\\').replace(/\"/g, '\\\\\"');
  yaml.push('      - type: regex');
  yaml.push('        value: \"' + pattern + '\"');
  yaml.push('    metadata:');
  yaml.push('      severity: ' + p.severity);
  yaml.push('      strategy: ' + (p.strategy || 'direct'));
  yaml.push('');
}

require('fs').writeFileSync('${OUT}', yaml.join('\\n'));
console.log('Wrote', '${OUT}', 'with', prompts.length, 'tests.');
console.log('');
console.log('Run via promptfoo:');
console.log('  promptfoo eval -c ${OUT}');
console.log('');
console.log('Or run via this plugin:');
console.log('  /llm-redteam --endpoint ${ENDPOINT}');
"
```

## Corpus options

| `--corpus` | Tests included |
|---|---|
| `full` (default) | All ~30 prompts across 7 categories |
| `jailbreak` | Security-focused (system-prompt-override, ASCII smuggling, DAN, indirect injection) |
| `bias` | Race / gender / age bias prompts |
| `harmful` | Self-harm, violence, illegal-drugs, CBW, IED |

## promptfoo-compatible

The generated YAML uses promptfoo's standard `prompts`/`providers`/`tests` structure with `assert: regex` checks, so it's a drop-in for existing promptfoo workflows. Each test carries metadata for severity and attack strategy.

## CI integration

Commit the YAML to your repo and run on every PR:

```yaml
# .github/workflows/llm-eval.yml
- name: LLM red-team
  run: |
    npx promptfoo eval -c promptfoo.yaml --output report.json
    if jq '.results[] | select(.success == false)' report.json | grep -q .; then
      echo "Red-team failure detected"
      exit 1
    fi
```

This fails the build whenever a model regression introduces new red-team failures.
