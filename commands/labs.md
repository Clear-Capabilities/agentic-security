---
description: Experimental + AI-driven. Self-audit, model rescan, rule synth, cross-repo, risk/time quantification.
argument-hint: "[--claude-audit|--model-rescan|--synthesize-rule|--cross-repo|--risk-dollars|--time-to-fix|--llm]"
---

# /labs

Experimental + AI-driven analyses dispatcher. Modes that don't fit cleanly under scan / fix / triage / posture / compliance / supply / setup land here.

## Modes

| Flag | Behaviour |
|---|---|
| `--claude-audit` | Analyze patterns in Claude-introduced findings + draft CLAUDE.md stanzas to pre-empt them |
| `--model-rescan` | Re-validate the current scan with a different LLM and show the delta |
| `--synthesize-rule` | Draft a custom SAST detector from natural-language description, runs in shadow mode |
| `--cross-repo` | Look up sibling-repo fixes + triage decisions for the same family from this developer's cross-repo history |
| `--risk-dollars` | Expected-value-of-exploitation in USD per finding (EV = EPSS × Impact × Reachability) |
| `--time-to-fix` | Estimate engineering hours per finding from family base + patch shape + reachability |
| `--llm` | LLM-specific risk surface: prompt injection, model loading, MCP audit, AI-BOM |

## Examples

```bash
/labs --claude-audit                             # AI self-reflection report
/labs --model-rescan --model claude-opus-5       # re-validate with newer model
/labs --synthesize-rule "flag any use of legacyDb.*"
/labs --cross-repo <finding-id>                  # sibling-repo lookup
/labs --risk-dollars --top 10                    # money-priority view
/labs --time-to-fix --summary                    # eng-hour rollup
/labs --llm                                      # LLM/MCP risk surface
```

## Implementation

Routes to existing posture modules: `claude-authorship.js`, `model-rescan.js`, `scripts/synthesize-detector.mjs`, `cross-repo-memory.js`, `risk-dollars.js`, `time-to-fix.js`.
