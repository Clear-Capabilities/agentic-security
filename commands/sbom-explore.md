---
description: Conversational SBOM exploration — query dependencies, drift, license, transitive paths in natural language.
argument-hint: "<question>"
---

# /sbom-explore

Conversational exploration of the project's Software Bill of Materials. Ask in natural language; Claude reads `.agentic-security/sbom-history/<sha>.json` + `last-scan.json` and answers.

## Example queries

```bash
/sbom-explore "show me every transitive dep added this month"
/sbom-explore "which deps have any L1 CVE"
/sbom-explore "what changes if I drop lodash"
/sbom-explore "list every dep on a deprecated version"
/sbom-explore "show me the dependency path to the AGPL packages"
/sbom-explore "which deps were relicensed in the last 12 months"
/sbom-explore "compare the SBOM vs last week"
```

## Implementation

The command loads:
- `.agentic-security/last-scan.json` → current `components[]`
- `.agentic-security/sbom-history/*.json` → prior snapshots
- `.agentic-security/license-graph.json` (if present) → license-graph findings
- Online OSV cache for CVE annotations (`~/.claude/agentic-security/osv-cache/`)

Then routes the question via Claude:

```js
import { _internals as _sbom } from '@clear-capabilities/agentic-security-scanner/posture/sbom-diff.js';
import { analyzeLicenseGraph } from '@clear-capabilities/agentic-security-scanner/posture/license-graph.js';

const cur = readJson('.agentic-security/last-scan.json');
const history = listSbomHistory(scanRoot);
const license = analyzeLicenseGraph(cur.components || []);
// Answer the user's question with this context.
```

## Output

Plain Markdown response. Examples:

For "transitive deps added this month":
```
12 transitive deps added since 2026-05-01:

| Package | Version | First seen | Direct dep that pulled it in |
|---|---|---|---|
| color-name | 1.1.4 | 2026-05-04 | tailwindcss@3.4 |
| balanced-match | 1.0.2 | 2026-05-04 | tailwindcss@3.4 |
| ...
```

For "show me the dependency path to AGPL":
```
1 AGPL dependency in tree:

  your-app
    └─ @some-ai/sdk@0.2.0  (MIT — direct)
       └─ vector-store-client@1.5.0  (MIT — transitive)
          └─ pg-binding@4.0.0  (AGPL-3.0 — TRANSITIVE COPYLEFT)

Recommendation: switch vector-store-client to a permissive alternative,
or scope your distribution as SaaS (AGPL is OK under SaaS mode per
.agentic-security/license-policy.yml).
```

## Why a chat surface

Same data as `/security-show-sbom`, but you don't have to remember the flag matrix. Just ask.
