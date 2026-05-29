---
description: Walk through findings ranked by risk; accept/reject/snooze each in one keystroke. Conversational triage.
argument-hint: "[--severity critical|high] [--family <name>] [--limit <n>]"
---

# /triage-tournament

Conversational triage. Claude presents findings one at a time, ranked by risk, and you accept / reject / snooze each in a single response. Replaces the dashboard-style triage workflow with a terminal-native dialogue.

## Flow

1. Reads `.agentic-security/last-scan.json` and sorts by `compositeRisk` (descending)
2. For each finding, presents:
   - The vuln class + file:line
   - The exploitability tier
   - Recommended fix (one sentence)
   - Past similar decisions (via `query_triage_memory` MCP tool)
3. You respond with one of:
   - `accept` / `a` — mark accepted, queue for `/fix`
   - `reject` / `r <reason>` — mark wont-fix with reason (writes to `triage-memory.jsonl` + AGENTS.md)
   - `false-positive` / `fp <reason>` — mark false-positive with reason
   - `snooze` / `s` — defer to next session
   - `explain` / `e` — Claude explains in more depth before you decide
   - `skip` / `n` — leave open, move to next
   - `stop` / `q` — exit the tournament

## Why a tournament

- **Constrained context**: one finding at a time keeps the LLM focused on the right code
- **One-keystroke decisions**: typing `r tutorial demo` is faster than clicking through a dashboard
- **Memory-aware**: past decisions surface automatically so you don't re-litigate

## Filters

```bash
/triage-tournament --severity critical            # only criticals
/triage-tournament --family sqli                  # only SQLi
/triage-tournament --limit 10                     # cap at 10 findings
/triage-tournament --new-since main               # only findings introduced on this branch
```

## Implementation

The command reads `.agentic-security/last-scan.json`, filters per flags, sorts by `compositeRisk`, and loops:

```js
import { transition, comment } from '@clear-capabilities/agentic-security-scanner/posture/triage.js';
import { queryMemory } from '@clear-capabilities/agentic-security-scanner/posture/triage-memory.js';

for (const finding of sortedFindings) {
  const past = queryMemory(scanRoot, finding.vuln);
  // ... present the finding, read user response
  switch (decision) {
    case 'accept':         transition(scanRoot, finding.id, 'open', userComment); break;
    case 'reject':         transition(scanRoot, finding.id, 'wont-fix', reason); break;
    case 'false-positive': transition(scanRoot, finding.id, 'false-positive', reason); break;
  }
}
```

Each `reject` / `false-positive` call automatically updates `triage-memory.jsonl` + AGENTS.md (the triage transition bridge from item #4).

## Summary at end

```
Tournament complete. 23 findings reviewed.
  ✓ accepted:        12  (queued for /fix)
  ✗ wont-fix:         4  (recorded in triage-memory)
  ⓧ false-positive:   3  (recorded in triage-memory)
  ⏸ snoozed:          2  (will appear next tournament)
  ↳ skipped:          2  (left open)

Run /fix --all-accepted to apply remediations.
```
