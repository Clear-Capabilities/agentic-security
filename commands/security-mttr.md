---
description: Track finding age and surface findings exceeding SLA thresholds.
argument-hint: "[--sla-days '{\"critical\":7,\"high\":30,\"medium\":60,\"low\":90}']"
---

Run the finding-age / SLA report against the current scan.

```bash
node -e "
const fs = await import('node:fs/promises');
const { findingsExceedingSLA } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/mttr.js');
const current = JSON.parse(await fs.readFile('.agentic-security/last-scan.json', 'utf8'));
const findings = [...(current.findings||[]), ...(current.secrets||[]), ...(current.supplyChain||[]).filter(s => s.type==='vulnerable_dep')];
const overSla = findingsExceedingSLA(findings);
console.log('SLA breaches:', overSla.length);
for (const f of overSla.slice(0, 20)) console.log('  ' + f.severity + '\t' + f.ageDays + 'd\t' + (f.file||'') + ':' + (f.line||0) + '\t' + (f.vuln||''));
"
```

The report shows **SLA breaches** — findings older than the per-severity threshold (default: critical=7d, high=30d, medium=60d, low=90d).

Finding age is measured from the scan timestamp in `.agentic-security/last-scan.json`. For MTTR tracking across multiple scans, compare successive scan JSON files using `/security-drift`.
