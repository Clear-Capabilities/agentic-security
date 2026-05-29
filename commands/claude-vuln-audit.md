---
description: Analyze patterns in Claude-introduced findings + suggest CLAUDE.md stanzas that pre-empt them.
argument-hint: "[--accept] [--limit <n>]"
---

# /claude-vuln-audit

Closes the prompt-engineering loop. Analyzes the current scan's findings to identify patterns where Claude-authored work (commits with `Co-Authored-By: Claude` trailer) ships specific vulnerability families at a higher rate than human-authored work — then drafts CLAUDE.md additions that would pre-empt the pattern.

## What it does

1. Reads `.agentic-security/last-scan.json` and uses the git-history annotations from item #7 to split findings by AI-authored vs human-authored
2. Computes per-family lift: `(AI share of family) / (overall AI share)`
3. For families with lift ≥ 1.2 and at least 2 AI findings, drafts a CLAUDE.md stanza
4. Optionally appends accepted suggestions to `CLAUDE.md` via `--accept`

## Example output

```
Authorship audit — 47 findings traced to commits
  AI-authored: 18 (38%)
  Human-authored: 29 (62%)

Patterns where Claude ships more vulns than baseline:

  sqli         12 AI vs 4 human   share 75%   lift 1.97×   max severity: critical
  auth-missing  4 AI vs 1 human   share 80%   lift 2.11×   max severity: high

## Security default — sqli

Past Claude-authored work in this repo has introduced 12 sqli finding(s)
(1.97× the rate of human-authored work). To pre-empt:

> when asked to add a database query, always use parameterized queries via
> the existing helper rather than string interpolation. If no helper exists,
> use the driver's prepared-statement API directly (db.prepare(sql).run(params)).

Consider this a hard default unless the user explicitly asks for an exception.

[append to CLAUDE.md with /claude-vuln-audit --accept]
```

## Implementation

```js
import { analyzeAuthorshipPatterns, suggestClaudeMdEvolution, extractOriginatingPromptCluster } from '@clear-capabilities/agentic-security-scanner/posture/claude-authorship.js';

const scan = readLastScan(scanRoot);
const analysis = analyzeAuthorshipPatterns(scan.findings);
const suggestions = suggestClaudeMdEvolution(analysis);
const clusters = extractOriginatingPromptCluster(scan.findings);

// Display the suggestions + cluster summary, optionally write to CLAUDE.md
```

## Prompt-cluster mode

Findings that carry `originatingPrompt` (set by git-history.js when the commit message includes `Prompt:` / `User asked:` markers) get clustered by Jaccard token similarity. Surfaces patterns like:

```
Cluster (4 findings) — sample prompt:
  "add an endpoint for users to update their profile"
Families: authz, csrf

→ Add a CLAUDE.md note: "When asked to add user-edit endpoints, default to
   authz check + CSRF middleware before writing the route handler."
```

## Safety

Pure local analysis — no API calls. The suggestions are drafts; nothing is written to `CLAUDE.md` without `--accept`.
