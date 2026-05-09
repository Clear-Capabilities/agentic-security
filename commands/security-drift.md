---
description: Diff two scans for posture changes — new/removed endpoints, new/removed deps, lost auth boundaries, newly exposed data classes, severity deltas.
argument-hint: "[--from <scan-a.json>] [--to <scan-b.json>]"
---

Compute posture drift between two scan JSON files.

1. Resolve `--from` and `--to`:
   - Both must be paths to JSON files produced by `agentic-security scan --format json`.
   - If `--from` is omitted, use `.agentic-security/last-scan.json` from the previous commit's worktree (ask the user which ref to compare against, then scan it).
   - `--to` defaults to `.agentic-security/last-scan.json` (the most recent scan of the current working tree).

2. Run the diff:

```bash
node -e "
const { driftBetween, driftToMarkdown } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/drift.js');
const fs = await import('node:fs/promises');
const a = JSON.parse(await fs.readFile('${FROM:-.agentic-security/last-scan.json}', 'utf8'));
const b = JSON.parse(await fs.readFile('${TO:-.agentic-security/last-scan.json}', 'utf8'));
process.stdout.write(driftToMarkdown(driftBetween(a, b)));
"
```

3. Print the Markdown output verbatim. The report contains:
   - **Headline tier** (info / low / medium / high / critical)
   - **Auth boundaries lost** — every previously-authenticated route now exposed
   - **New endpoints** — flagged with 🔒 (auth) or ⚠️ (unauth)
   - **New dependencies** and **new CVEs introduced**
   - **New findings** + severity delta
   - **Newly exposed data classes** (PII / PHI / PCI / Confidential)

4. Suggest follow-ups based on the headline tier:
   - `critical` (auth boundary lost or new critical finding) → recommend `/security-poc <id>` for the new finding and `/security-fix` to restore the boundary.
   - `high` (new unauth endpoints, new high-tier CVE) → recommend `/security-chain` to check whether the new surface combines with existing findings into an attack chain.
   - `medium`/`low`/`info` → no follow-up needed; safe to merge.

## Why this exists

Drift shows exactly what changed between any two scan snapshots — new bugs can't sneak in unnoticed, and lost auth boundaries are flagged before merge.
