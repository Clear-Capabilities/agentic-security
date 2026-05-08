---
description: Secret-only sweep (60+ provider patterns + entropy detection).
argument-hint: "[path]"
---

Run only the Secret-scanning pillar against `${1:-.}`. Values are masked in output by default; pass `--unmask` only when you need to verify a specific finding.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --only secrets --format cli; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

For any genuine hit:
1. Treat the credential as compromised — rotate it immediately at the provider.
2. Move the value into a secrets manager or environment variable.
3. Audit git history (`git log -p -S "<masked-value>"`) for prior exposure.
