---
description: List dependency CVEs that appear in the CISA Known Exploited Vulnerabilities (KEV) catalog — vulnerabilities observed exploited in the wild. Highest-priority triage: weaponized findings.
---

Surface the SCA findings whose CVEs are listed in the CISA KEV catalog.

```bash
node -e "
const fs = await import('node:fs/promises');
const scan = JSON.parse(await fs.readFile('.agentic-security/last-scan.json', 'utf8'));
const findings = (scan.findings||[]).filter(f => f.kev === true);
console.log('CISA KEV findings:', findings.length);
for (const f of findings.slice(0, 50)) {
  const ransom = f.kevRansomware ? ' [ransomware]' : '';
  const cve = (f.cveAliases||[])[0] || '';
  console.log('  ' + f.severity.toUpperCase().padEnd(8) + ' ' + cve.padEnd(18) + ' ' + (f.package||'') + '@' + (f.version||'') + '  added ' + (f.kevDateAdded||'') + ransom);
}
"
```

KEV (Known Exploited Vulnerabilities) is CISA's authoritative list of CVEs being actively exploited in the wild. Unlike EPSS (a probability score), KEV is ground truth: a CVE on this list has been used in real attacks.

## Triage priority

Findings flagged `kev: true` get +20 toxicity score automatically — they sort to the top of the standard `/security-scan-all` report. This command is for when you want a focused, KEV-only view (e.g., "what do I have to fix this week per CISA BOD 22-01").

The `kevRansomware: true` flag means CISA has linked the CVE to known ransomware campaigns. Those should be treated as the highest priority.

The catalog is cached locally with a 24-hour TTL; runs offline if you've fetched it once. To refresh, re-run with the cache cleared.
