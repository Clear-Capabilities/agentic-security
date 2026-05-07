---
description: Dependency vulnerability audit only (SCA, OSV.dev-backed).
argument-hint: "[path]"
---

Run only the SCA pillar against `${1:-.}`. Calls `api.osv.dev` for CVE lookup unless `--no-network` is set.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --only sca --format cli
```

If suspicious packages appear in the output, invoke the `sca-malware-analyst` subagent to get a CLEAN/SUSPICIOUS/MALICIOUS verdict per component.
