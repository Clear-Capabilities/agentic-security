---
description: Re-run the LLM validator with a different model and show the delta — what the newer model catches that the older missed.
argument-hint: "[--model <model-id>] [--against <prior-model>]"
---

# /model-rescan

Re-validate the current scan with a different LLM and surface the delta. The tool gets smarter as the underlying models improve — this command lets you opt into that improvement immediately rather than waiting for an upgrade cycle.

## Use cases

- A new Claude model dropped (Opus 5, Sonnet 5) → see which prior FPs become TPs with better reasoning
- A/B test against gpt-5 / a custom finetune
- Verify a "false positive" verdict from a smaller model on a critical finding
- Build confidence before lowering a per-family confidence floor

## Implementation

```bash
# Re-run with a specific model
AGENTIC_SECURITY_LLM_VALIDATE=1 \
AGENTIC_SECURITY_LLM_MODEL=claude-opus-5 \
  node bin/agentic-security.js scan

# Compare against the prior validator run
node -e '
  import { diffValidatorRuns, persistRescanReport, summarizeDelta } from "@clear-capabilities/agentic-security-scanner/posture/model-rescan.js";
  import * as fs from "node:fs";
  const a = JSON.parse(fs.readFileSync(".agentic-security/llm-validator/last-claude-sonnet-4.json"));
  const b = JSON.parse(fs.readFileSync(".agentic-security/llm-validator/last-claude-opus-5.json"));
  const changed = diffValidatorRuns(a, b);
  persistRescanReport(".", a.model, b.model, changed);
  console.log(summarizeDelta(changed));
'
```

Or as a single command:

```bash
/model-rescan --model claude-opus-5 --against claude-sonnet-4
```

## Output

```
12 verdict change(s) between models:
  9 finding(s) now confirmed TP (newer model caught what older missed)
  3 finding(s) now FP (newer model recognized as safe)

Detail at .agentic-security/model-rescan/claude-sonnet-4-vs-claude-opus-5.json
```

## Costs

The LLM validator is opt-in via `AGENTIC_SECURITY_LLM_VALIDATE=1`. Re-running with a new model is the same cost as the first run — one API call per finding. For a 500-finding scan against Claude Opus, expect ~$0.20-$0.40 depending on the model.

Consider using `--limit critical` to re-validate only the highest-stake findings.

## Safety

The LLM validator only sends finding text (vuln description, file path, snippet) — never source code or scan history. The model output adjusts severity / verdict on findings but never modifies source files.
