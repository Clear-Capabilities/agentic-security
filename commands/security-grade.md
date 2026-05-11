---
description: Single letter-grade snapshot (A–F) of your project's security posture, with one sentence explaining why and one concrete next action. For non-technical builders.
---

Compute and print a project-wide security letter grade from the last scan.

```bash
node -e "
const fs = require('fs');
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

if (!scan) {
  console.log('No scan yet. Run /scan --all first to take a baseline.');
  process.exit(0);
}

const findings = scan.findings || [];
const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;

// Compute grade.
//
// The grade composes three signals:
//   - Critical findings dominate. ANY critical → C or worse.
//   - KEV (weaponized) findings escalate further. ANY KEV → D minimum.
//   - High count contributes linearly above the critical floor.
//
// Floor table:
//   0 critical, 0 KEV, ≤2 high   → A
//   0 critical, 0 KEV, ≤5 high   → A-
//   0 critical, ≤10 high          → B
//   0 critical, >10 high          → B-
//   1-2 critical                  → C
//   3-5 critical                  → C-
//   6-10 critical                 → D
//   any KEV-listed                → D minimum
//   >10 critical                  → F
//   >5 critical AND any KEV       → F

const kevCount = findings.filter(f => f.kev === true).length;
const c = counts.critical, h = counts.high;

let grade, reason, action;

if (c > 10 || (c > 5 && kevCount > 0)) {
  grade = 'F';
  reason = c + ' critical finding(s)' + (kevCount ? ' including ' + kevCount + ' actively-exploited CVE(s)' : '') + '. Your project would not pass any security review in this state.';
  action = 'Run /fix --all --critical to start triaging the worst.';
} else if (c >= 6) {
  grade = 'D';
  reason = c + ' critical finding(s) — too many to ship safely. Each one is a potential breach.';
  action = 'Run /fix --all --critical to fix the worst, then /security-grade again.';
} else if (kevCount > 0) {
  grade = 'D';
  reason = kevCount + ' CVE(s) on the CISA Known Exploited Vulnerabilities list — these are being weaponized in real attacks right now.';
  action = 'Run /security-kev to see them, then update the affected packages.';
} else if (c >= 3) {
  grade = 'C-';
  reason = c + ' critical finding(s). A working app, but with serious holes an attacker would target.';
  action = 'Run /fix --all --critical.';
} else if (c >= 1) {
  grade = 'C';
  reason = c + ' critical finding(s). Most things look OK, but the criticals must be fixed before launch.';
  action = 'Run /fix --all --critical (just ' + c + ' fix' + (c>1?'es':'') + ').';
} else if (h > 10) {
  grade = 'B-';
  reason = '0 critical, but ' + h + ' high-severity findings — the volume itself is a risk.';
  action = 'Run /security-triage to walk through the high-severity findings and validate them.';
} else if (h >= 3) {
  grade = 'B';
  reason = '0 critical and only ' + h + ' high-severity findings. You are in OK shape.';
  action = 'Run /fix --all --high to clean up the remaining issues.';
} else if (h > 0) {
  grade = 'A-';
  reason = '0 critical and ' + h + ' high-severity finding(s). Very close to clean.';
  action = 'Run /security-explain on the high finding(s) and decide whether to fix or accept.';
} else if (counts.medium > 0) {
  grade = 'A';
  reason = '0 critical and 0 high. ' + counts.medium + ' medium finding(s) remain — typically hardening, not breach risks.';
  action = 'Optional: review medium findings with /show-findings.';
} else {
  grade = 'A+';
  reason = 'No critical, high, or medium findings. Clean across the board.';
  action = 'Keep scanning on every PR. Save the current scan as a baseline: cp .agentic-security/last-scan.json scan-clean.json';
}

// Render
const W = (s, code) => process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s;
const COLOR = { 'A+': '92', 'A': '92', 'A-': '92', 'B': '32', 'B-': '32', 'C': '33', 'C-': '33', 'D': '31', 'F': '91' };

// 0.14.0 — show grade-delta vs. previous scan if streak.json exists
let delta = '';
try {
  const streak = JSON.parse(fs.readFileSync('.agentic-security/streak.json', 'utf8'));
  if (streak.previousGrade && streak.previousGrade !== grade) {
    const RANK = { 'F': 0, 'D': 1, 'C-': 2, 'C': 3, 'B-': 4, 'B': 5, 'A-': 6, 'A': 7, 'A+': 8 };
    const prev = RANK[streak.previousGrade] ?? -1;
    const now = RANK[grade] ?? -1;
    if (now > prev) delta = '  📈 ' + W('Grade up: ' + streak.previousGrade + ' → ' + grade, '92');
    else if (now < prev) delta = '  📉 ' + W('Grade down: ' + streak.previousGrade + ' → ' + grade, '91');
  }
} catch {}

console.log('');
console.log('  Security grade:  ' + W(grade, COLOR[grade] || '0'));
if (delta) console.log(delta);
console.log('');
console.log('  ' + reason);
console.log('');
console.log('  Next: ' + action);
console.log('');
console.log('  Detail: critical=' + c + '  high=' + h + '  medium=' + counts.medium + '  low=' + counts.low + '  KEV=' + kevCount);
console.log('');
if (grade === 'A+') {
  console.log('  ' + W('🎉 Perfect score. Save this scan as your baseline so you know if anything regresses.', '92'));
  console.log('');
}

// Badge — inline so users get the README snippet without a separate command
const colors = { 'A+': 'brightgreen', 'A': 'brightgreen', 'A-': 'green', 'B': 'green', 'B-': 'yellowgreen', 'C': 'yellow', 'C-': 'orange', 'D': 'orange', 'F': 'red' };
const params = new URLSearchParams({ label: 'agentic-security', message: grade, color: colors[grade] || 'lightgrey', logo: 'shield', logoColor: 'white' });
const badgeUrl = 'https://img.shields.io/static/v1?' + params.toString();
const repo = 'https://github.com/clearcapabilities/agentic-security';
console.log('  README badge:');
console.log('  [![agentic-security: ' + grade + '](' + badgeUrl + ')](' + repo + ')');
console.log('');
"
```

Print the output verbatim. The user wants a one-glance posture summary with a README badge snippet.
