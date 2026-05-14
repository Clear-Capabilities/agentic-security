---
description: Generate a security grade badge for your README and an investor-ready security summary — one command, copy-paste ready.
---

Generate two artifacts from your last scan:
1. A Shields.io badge URL for your README showing your current security grade.
2. An investor/client-ready security summary paragraph you can paste into a pitch deck or SOC 2 prep doc.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first, then /security-badge.');
  process.exit(0);
}

const findings = scan.findings || [];
const components = scan.components || [];

const crit = findings.filter(f => f.severity === 'critical').length;
const high = findings.filter(f => f.severity === 'high').length;
const med  = findings.filter(f => f.severity === 'medium').length;
const low  = findings.filter(f => f.severity === 'low').length;
const kev  = findings.filter(f => f.kev).length;
const total = findings.length;
const vulnDeps = components.filter(c => c.vulnerabilities && c.vulnerabilities.length > 0).length;

// Compute grade
function computeGrade() {
  if (crit > 0 || kev > 0) return { grade: 'F', color: 'critical', label: 'red' };
  if (high > 2) return { grade: 'D', color: 'red', label: 'red' };
  if (high > 0) return { grade: 'C', color: 'orange', label: 'orange' };
  if (med > 5) return { grade: 'C', color: 'orange', label: 'orange' };
  if (med > 0) return { grade: 'B', color: 'yellow', label: 'yellow' };
  if (low > 5) return { grade: 'B', color: 'yellow', label: 'yellow' };
  return { grade: 'A', color: 'brightgreen', label: 'brightgreen' };
}

const { grade, color } = computeGrade();
const encodedGrade = encodeURIComponent('Security%3A ' + grade);
const badgeUrl = \`https://img.shields.io/badge/security-\${grade}-\${color}\`;
const badgeMd = \`[![Security: \${grade}](\${badgeUrl})](https://github.com/Clear-Capabilities/agentic-security)\`;

const scanDate = scan.scannedAt ? new Date(scan.scannedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

console.log('');
console.log(W('Security Badge & Investor Summary', '1'));
console.log('');
console.log(W('── README Badge ─────────────────────────────────────────', '36'));
console.log('');
console.log('  Grade: ' + W(grade, grade === 'A' ? '32;1' : grade === 'B' ? '33;1' : '31;1'));
console.log('');
console.log('  Paste into your README.md:');
console.log('');
console.log('  ' + badgeMd);
console.log('');
console.log('  Shield URL only:');
console.log('  ' + badgeUrl);
console.log('');
console.log(W('── Investor / Client Summary ────────────────────────────', '36'));
console.log('');

// Output structured data for Claude to write the summary paragraph
console.log(JSON.stringify({
  grade,
  scan_date: scanDate,
  total_findings: total,
  critical: crit,
  high,
  medium: med,
  low,
  kev_weaponized_cves: kev,
  vulnerable_dependencies: vulnDeps,
  total_dependencies: components.length,
  checks_performed: [
    'SAST (static analysis across all source files)',
    'SCA (dependency vulnerability scan via OSV + CISA KEV)',
    'Secrets detection (entropy + pattern-based)',
    'Auth/AuthZ analysis',
    'Business logic review',
    'IaC security audit',
  ],
}, null, 2));
console.log('');
"
```

Using the JSON above, write two things:

**1. Investor paragraph** (3–4 sentences): A professional security posture statement suitable for a due-diligence questionnaire or pitch deck security section. Mention the grade, what was checked, what was found (or "no critical findings"), and that automated scanning is integrated into the development workflow. Tone: factual, confident, not marketing-speak.

**2. SOC 2 prep note** (2 sentences): State which controls this scan addresses (CC6.1, CC6.6, CC7.1, CC7.2) and what evidence it provides for auditors.

Format the output as plain text the user can copy-paste. Include the badge Markdown above each section header.
