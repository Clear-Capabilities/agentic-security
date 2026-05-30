---
description: Posture + reporting. Status snapshot, A-F report card, harness score, trend, threat model, stack playbook.
argument-hint: "[--status|--report-card|--harness|--trend|--threat|--playbook|--mgmt]"
---

# /posture

Posture + reporting dispatcher. One command, multiple views.

## Modes

| Flag | Behaviour |
|---|---|
| (default) or `--status` | One-screen plugin + project health snapshot — version, last scan, cache size, hook activation, suppressions |
| `--report-card` | Single A–F letter grade + one explanation + one next action |
| `--harness` | Score this project's AI agent harness against the six-domain rubric |
| `--trend` | Findings trend over time — added/closed/wont-fix by week |
| `--threat` | Threat model views: STRIDE, personas, playbook, bounty, adversary, surface, boundary, SPOF |
| `--playbook` | Stack-specific posture playbook (Express, FastAPI, Django, Rails, Spring Boot, etc.) |
| `--mgmt` | Posture management surface — auth, network, WAF, telemetry, feature-flag imports |

## Examples

```bash
/posture                       # status snapshot (default)
/posture --report-card         # A–F grade + next action
/posture --harness             # AI agent harness scoring
/posture --trend               # findings trend
/posture --threat --view stride
/posture --playbook            # stack-specific playbook
```

## Implementation

Dispatches to existing command implementations based on the flag. All modes preserved — no functional regression.
