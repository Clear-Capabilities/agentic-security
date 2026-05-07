---
description: Render a STRIDE coverage table from the last scan.
---

Read `.agentic-security/last-scan.json`, group findings by their `stride` field (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), and render:

```
| STRIDE category | Count | Top vulnerabilities |
```

Then call out:
- Categories with zero findings — these may be under-covered or genuinely absent
- The single highest-exploitability finding per category

Use the `security-triager` subagent for the analysis — it has the exploitability scoring and dedup logic.
