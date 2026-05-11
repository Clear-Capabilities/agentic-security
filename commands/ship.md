---
description: One-screen verdict — "safe to deploy?" — and if not, asks which severity tier to fix. The vibecoder default.
argument-hint: "[path]"
---

Run the agentic-security scanner in `ship` mode against `${1:-.}` and render the
one-screen verdict. This is the vibecoder default: high-confidence findings only,
no CWE/CVSS jargon.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship ${1:-.}; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

## How to respond to the user

The scanner's output already includes the right call-to-action. After it
runs, **do not list individual findings.** Instead:

- If the verdict is ✅: tell the user they're safe to deploy, in one short line.
- If the verdict is ❌: relay the severity-tier prompt the scanner printed,
  and **ask the user which level they want to fix first** (critical, high,
  medium, low). Wait for their answer before doing anything else.

Once the user picks a severity, run `/security-fix-all --severity <their choice>`.

If they ask to see specifics first, run `/security-scan-all --firehose` for
the full per-finding list. Don't volunteer that list unprompted — the whole
point of `/ship` is the one-screen summary.

🛡  agentic-security · created by ClearCapabilities.Com
