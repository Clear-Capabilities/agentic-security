---
description: One-screen verdict — "safe to deploy?" — with up to 3 actionable fixes and copy-paste patches. The vibecoder default.
argument-hint: "[path]"
---

Run the agentic-security scanner in `ship` mode against `${1:-.}` and render the
one-screen verdict. This is the vibecoder default: high-confidence findings only,
no CWE/CVSS jargon, every actionable item gets a copy-paste fix snippet.

```bash
node $CLAUDE_PLUGIN_ROOT/scanner/dist/agentic-security.mjs ship ${1:-.}
ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

If the output says ❌, run `/fix <n>` to apply the patch for finding number n.
If the output says ✅, you're safe to deploy.

Power user? Run `/security-scan-all --firehose` for the full per-finding list
with full taxonomy (CWE / CVSS / OWASP / MITRE ATT&CK).

🛡  agentic-security · created by ClearCapabilities.Com
