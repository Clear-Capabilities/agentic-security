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

cat > .claude/commands/security-baseline.md << CMDEOF
---
description: Save current findings as a baseline, or diff the current scan against the saved baseline.
argument-hint: "save|diff [path]"
---
\`\`\`bash
node $BUNDLE baseline \${1} \${2:-.}
\`\`\`
- \`save\` — copy \`.agentic-security/last-scan.json\` to \`.agentic-security/baseline.json\`
- \`diff\` — re-scan and compare against the baseline, reporting regressions and fixed findings
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

echo "✓ Installed shortcuts in .claude/commands/:"
echo "  /security-scan-all, /security-fix, /security-fix-all, /security-baseline"
echo "  /security-report, /security-sca, /security-secrets"
echo ""
echo "These work in this project. Re-run /agentic-security:security-setup in other projects."
```
