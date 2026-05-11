---
description: Install short-form command shortcuts into this project so you can type /scan-all instead of /agentic-security:scan-all.
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

cat > .claude/commands/fix.md << CMDEOF
---
description: Fix findings. Use --one <id> for a single finding, --all [--critical|--high|--medium|--low] for batch, or --pr to bundle into a pull request.
argument-hint: "[--one <finding-id>] | [--all [--critical|--high|--medium|--low]] | [--pr [--apply] [--branch <name>]]"
---
Run \`/agentic-security:fix \$@\` to fix findings.
CMDEOF

cat > .claude/commands/scan.md << CMDEOF
---
description: Run the scanner. Default is full sweep; use --sca-only or --secrets-only for focused scans.
argument-hint: "[path] [--all|--sca-only|--secrets-only]"
---
Run \`/agentic-security:scan \$@\` to scan this project.
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

cat > .claude/commands/security-threat-model.md << CMDEOF
---
description: Threat model from the last scan — STRIDE (default) or OWASP LLM Top 10 (--llm).
argument-hint: "[--stride|--llm]"
---
Run \`/agentic-security:security-threat-model \${1:---stride}\` for the threat model.
CMDEOF

cat > .claude/commands/produce-compliance-report.md << CMDEOF
---
description: Auditor-ready compliance attestation for NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, or SOC 2.
argument-hint: "[nist|asvs|pci|soc2]"
---
Run \`/agentic-security:produce-compliance-report \${1}\` for the compliance attestation.
CMDEOF

cat > .claude/commands/security-share.md << CMDEOF
---
description: Posts (Twitter/LinkedIn/Discord/recap) about your security progress.
argument-hint: "[twitter|linkedin|discord|recap|all]"
---
Run \`/agentic-security:security-share \${1:-all}\` for shareable posts and recap.
CMDEOF

echo "✓ Installed shortcuts in .claude/commands/:"
echo "  /scan, /show-findings, /fix"
echo "  /security-mcp-audit, /security-authz, /security-kev"
echo "  /security-help, /security-status"
echo "  /security-explain, /security-grade, /security-launch-check"
echo "  /security-aibom, /security-threat-model [--stride|--llm]"
echo "  /security-share [twitter|linkedin|discord|recap|all]"
echo "  /produce-compliance-report [nist|asvs|pci|soc2]"
echo ""
echo "These work in this project. Re-run /agentic-security:security-setup in other projects."
```
