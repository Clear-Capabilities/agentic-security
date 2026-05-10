---
description: Install short-form /security-* command shortcuts into this project so you can type /security-scan-all instead of /agentic-security:security-scan-all.
---

Install project-level command shortcuts for agentic-security so the short forms work in this project.

```bash
mkdir -p .claude/commands

# Locate the installed plugin bundle
BUNDLE=""
for f in ~/.claude/plugins/cache/clearcapabilities/agentic-security/*/scanner/dist/agentic-security.mjs; do
  [ -f "$f" ] && BUNDLE="$f"
done
if [ -z "$BUNDLE" ]; then
  echo "ERROR: agentic-security plugin bundle not found. Ensure the plugin is installed."
  exit 1
fi

cat > .claude/commands/security-scan-all.md << CMDEOF
---
description: Run a full security scan (SAST + SCA + Secrets) on this project or a given path.
argument-hint: "[path]"
---
\`\`\`bash
node $BUNDLE scan \${1:-.} --format cli --verbose
\`\`\`
After the scan, the JSON report is written to \`.agentic-security/last-scan.json\`.
If you see critical findings, run \`/security-fix-all --severity critical\` to remediate.
CMDEOF

cat > .claude/commands/security-fix.md << CMDEOF
---
description: Apply a remediation patch for a single finding from the last scan.
argument-hint: "<finding-id>"
---
\`\`\`bash
node $BUNDLE fix --finding \${1}
\`\`\`
Hand the finding off to the security-fixer subagent: read the affected file, apply the fix template adapted to the surrounding code, and run the project's test command if one is configured. Do not declare the fix complete until the finding no longer reproduces on re-scan.
CMDEOF

cat > .claude/commands/security-fix-all.md << CMDEOF
---
description: Remediate every finding at or above a severity threshold (default critical).
argument-hint: "[--severity critical|high|medium]"
---
Read \`.agentic-security/last-scan.json\`. For every finding whose severity is at or above \`\${1:-critical}\`, dispatch the security-fixer subagent in sequence (not in parallel — each fix may invalidate later findings). After each batch, re-run \`/security-scan\` to confirm fixes landed. Stop and report if a fix's tests fail.
CMDEOF

cat > .claude/commands/security-report.md << CMDEOF
---
description: Generate an HTML security report (or JSON/Markdown/SARIF).
argument-hint: "[--format html|json|md|sarif] [--output <file>]"
---
\`\`\`bash
node $BUNDLE scan . --format \${1:-html} --output \${2:-security-report.html}
\`\`\`
CMDEOF

cat > .claude/commands/security-sca.md << CMDEOF
---
description: Run a dependency vulnerability scan (SCA only) against this project.
argument-hint: "[path]"
---
\`\`\`bash
node $BUNDLE scan \${1:-.} --only sca --format cli
\`\`\`
CMDEOF

cat > .claude/commands/security-secrets.md << CMDEOF
---
description: Scan for leaked credentials and hardcoded secrets.
argument-hint: "[path]"
---
\`\`\`bash
node $BUNDLE scan \${1:-.} --only secrets --format cli
\`\`\`
CMDEOF

cat > .claude/commands/security-mcp-audit.md << CMDEOF
---
description: Audit MCP server configurations for agent-host risks (untrusted install, hardcoded creds, prompt injection in descriptions, dangerous capabilities).
argument-hint: "[path]"
---
\`\`\`bash
node $BUNDLE scan \${1:-.} --format cli
\`\`\`
The audit fires on \`.mcp.json\`, \`claude_desktop_config.json\`, and \`mcp_servers.json\` files. Rerun after adding any new MCP server.
CMDEOF

cat > .claude/commands/security-authz.md << CMDEOF
---
description: Deep auth/authZ audit — JWT alg confusion, hardcoded JWT secret, OAuth2 PKCE/redirect_uri validation, multi-tenant scope, session fixation.
argument-hint: "[path]"
---
\`\`\`bash
node $BUNDLE scan \${1:-.} --format cli
\`\`\`
Covers OWASP A01 (Broken Access Control). Findings appear with kind:authz in the JSON report.
CMDEOF

cat > .claude/commands/security-kev.md << CMDEOF
---
description: List dependency CVEs in the CISA Known Exploited Vulnerabilities catalog (weaponized in the wild).
---
\`\`\`bash
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
\`\`\`
CMDEOF

cat > .claude/commands/security-help.md << CMDEOF
---
description: List every agentic-security command organized by category, with one-line descriptions.
---
Run \`/agentic-security:security-help\` for the full command catalog.
CMDEOF

cat > .claude/commands/security-status.md << CMDEOF
---
description: Print a one-screen project & plugin health snapshot — version, last scan time + counts, cache size, hook activation, suppression rules.
---
Run \`/agentic-security:security-status\` for the project health snapshot.
CMDEOF

cat > .claude/commands/security-explain.md << CMDEOF
---
description: Explain a finding in plain English — what it means, how an attacker exploits it, the worst case, and how to fix it.
argument-hint: "<finding-id-or-CWE-or-vuln-name>"
---
Run \`/agentic-security:security-explain \${1}\` for a plain-English explanation card.
CMDEOF

cat > .claude/commands/security-grade.md << CMDEOF
---
description: One letter-grade snapshot (A–F) of the project's security posture.
---
Run \`/agentic-security:security-grade\` for the project's security letter grade.
CMDEOF

cat > .claude/commands/security-launch-check.md << CMDEOF
---
description: Pre-deploy 10-item checklist — the things beginners typically miss before going live.
---
Run \`/agentic-security:security-launch-check\` for the pre-launch checklist.
CMDEOF

cat > .claude/commands/security-aibom.md << CMDEOF
---
description: Generate an AI/ML Bill of Materials — every model, prompt template, framework, and vector store your project uses.
argument-hint: "[--format aibom|aibom-md]"
---
\`\`\`bash
node $BUNDLE scan . --format \${1:-aibom-md}
\`\`\`
CMDEOF

cat > .claude/commands/security-llm-threat-model.md << CMDEOF
---
description: Map findings to OWASP LLM Top 10 (2025) — Prompt Injection, Sensitive Disclosure, Supply Chain, Poisoning, Improper Output, Excessive Agency, System Prompt Leakage, Vector Weaknesses, Misinformation, Unbounded Consumption.
---
Run \`/agentic-security:security-llm-threat-model\` for the OWASP LLM Top 10 coverage map.
CMDEOF

cat > .claude/commands/security-badge.md << CMDEOF
---
description: Print a markdown badge of your current security grade for your project's README.
---
Run \`/agentic-security:security-badge\` for the badge markdown.
CMDEOF

cat > .claude/commands/security-share.md << CMDEOF
---
description: Generate copy-paste posts (Twitter/X, LinkedIn, Discord/Slack) about your security progress.
argument-hint: "[twitter|linkedin|discord|all]"
---
Run \`/agentic-security:security-share \${1:-all}\` for shareable posts.
CMDEOF

cat > .claude/commands/security-recap.md << CMDEOF
---
description: Year-in-Security recap card — days active, scans run, fixes shipped, longest streak, top achievements.
---
Run \`/agentic-security:security-recap\` for the recap card.
CMDEOF

echo "✓ Installed shortcuts in .claude/commands/:"
echo "  /security-scan-all, /security-fix, /security-fix-all"
echo "  /security-report, /security-sca, /security-secrets"
echo "  /security-mcp-audit, /security-authz, /security-kev"
echo "  /security-help, /security-status"
echo "  /security-explain, /security-grade, /security-launch-check"
echo "  /security-aibom, /security-llm-threat-model"
echo "  /security-badge, /security-share, /security-recap"
echo ""
echo "These work in this project. Re-run /agentic-security:security-setup in other projects."
```
