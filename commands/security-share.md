---
description: Generate copy-paste-ready posts (Twitter/X, LinkedIn, Discord/Slack) about your security progress — current grade, streak, achievements. One command, three formats.
argument-hint: "[twitter|linkedin|discord|all]"
---

Print copy-paste posts about your project's current security state.

```bash
node -e "
const fs = require('fs');

let scan, streak;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /security-scan-all first, then /security-share.'); process.exit(0); }
try { streak = JSON.parse(fs.readFileSync('.agentic-security/streak.json', 'utf8')); }
catch { streak = {}; }

const findings = scan.findings || [];
const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
const counts = { critical: 0, high: 0, medium: 0, low: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
for (const s of supplyChain) counts[s.severity || 'high'] = (counts[s.severity || 'high']||0) + 1;
const kev = [...findings, ...supplyChain].filter(f => f.kev === true).length;
const c = counts.critical, h = counts.high;

let grade;
if (c > 10 || (c > 5 && kev > 0)) grade = 'F';
else if (c >= 6) grade = 'D';
else if (kev > 0) grade = 'D';
else if (c >= 3) grade = 'C-';
else if (c >= 1) grade = 'C';
else if (h > 10) grade = 'B-';
else if (h >= 3) grade = 'B';
else if (h > 0) grade = 'A-';
else if (counts.medium > 0) grade = 'A';
else grade = 'A+';

const days = streak.daysCleanCritical || 0;
const fixes = streak.totalFixesInferred || 0;
const totalScans = streak.totalScans || 1;
const repo = 'https://github.com/clearcapabilities/agentic-security';

// Highest-tier achievement to brag about
const TIER_ORDER = ['streak-365', 'streak-180', 'streak-90', 'streak-30', 'streak-7', 'triage-gold', 'triage-silver', 'triage-master', 'grade-a-plus', 'launch-ready', 'clean-sweep', 'first-fix', 'first-scan'];
const TIER_LABELS = {
  'streak-365': 'Diamond Streak 💠', 'streak-180': 'Platinum Streak 💎', 'streak-90': 'Gold Streak 🥇',
  'streak-30': 'Silver Streak 🥈',  'streak-7': 'Bronze Streak 🥉',
  'triage-gold': 'Gold Fixer 🥇',   'triage-silver': 'Silver Fixer 🥈',  'triage-master': 'Bronze Fixer 🎯',
  'grade-a-plus': 'Grade A+ 🌟',     'launch-ready': 'Launch Ready 🚀',    'clean-sweep': 'Clean Sweep 🧹',
};
const earned = new Set(streak.achievements || []);
const topAch = TIER_ORDER.find(id => earned.has(id));
const topLabel = topAch ? TIER_LABELS[topAch] : null;

const target = (process.argv[1] || 'all').toLowerCase();

const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const BOLD = '1', DIM = '2', CYAN = '36';

function header(name, chars) {
  console.log('');
  console.log(W('━━ ' + name + ' ' + (chars ? '(' + chars + ' chars) ' : '') + '━'.repeat(Math.max(2, 60 - name.length - String(chars||'').length)), BOLD));
  console.log('');
}

function out(text) {
  console.log(text);
  console.log('');
  console.log(W('  Length: ' + text.length + ' chars', DIM));
}

if (target === 'twitter' || target === 'x' || target === 'all') {
  header('Twitter / X', '≤280');
  let tweet;
  if (days >= 7) {
    tweet = '🔒 ' + days + '-day clean security streak on my project with @AnthropicAI Claude Code · agentic-security plugin\\n\\nGrade ' + grade + (topLabel ? ' · ' + topLabel : '') + '\\n\\nAuto-scans every file edit. Open source: ' + repo;
  } else if (grade === 'A+' || grade === 'A') {
    tweet = '🔒 Just got grade ' + grade + ' on my codebase with the agentic-security plugin for @AnthropicAI Claude Code\\n\\nIt scans every file the moment AI writes it. Catches SQLi, XSS, CVEs, hardcoded secrets, prompt injection, and more.\\n\\n' + repo;
  } else if (fixes > 0) {
    tweet = '🔒 Just shipped ' + fixes + ' security fix' + (fixes === 1 ? '' : 'es') + ' with the agentic-security plugin for @AnthropicAI Claude Code · grade ' + grade + ' and climbing\\n\\nAuto-fixes vulnerabilities the same session AI introduces them.\\n\\n' + repo;
  } else {
    tweet = '🔒 Trying out agentic-security — security scanner for AI-written code that runs inside @AnthropicAI Claude Code · current grade ' + grade + '\\n\\nSAST, SCA, secrets, IaC, prompt-injection · all in one plugin · ' + repo;
  }
  out(tweet);
}

if (target === 'linkedin' || target === 'all') {
  header('LinkedIn', '');
  const lines = [];
  lines.push('Tracking the security posture of my work with the agentic-security plugin for Claude Code.');
  lines.push('');
  lines.push('Current snapshot:');
  lines.push('• Grade: ' + grade);
  if (days >= 1) lines.push('• Clean of critical findings: ' + days + ' day' + (days === 1 ? '' : 's'));
  if (fixes > 0) lines.push('• Fixes applied across ' + totalScans + ' scans: ' + fixes);
  if (topLabel) lines.push('• Latest achievement: ' + topLabel);
  lines.push('');
  lines.push('What I like about it: it runs inside Claude Code, scans every file the moment AI generates it, and ranks findings by real-world risk (function-level reachability + CISA KEV signal) instead of just CVSS scores.');
  lines.push('');
  lines.push('Free for any internal use, including for-profit teams. ' + repo);
  out(lines.join('\\n'));
}

if (target === 'discord' || target === 'slack' || target === 'all') {
  header('Discord / Slack', '');
  const params = new URLSearchParams({ label: 'agentic-security', message: grade, color: { 'A+': 'brightgreen', 'A': 'brightgreen', 'A-': 'green', 'B': 'green', 'B-': 'yellowgreen', 'C': 'yellow', 'C-': 'orange', 'D': 'orange', 'F': 'red' }[grade] || 'lightgrey', logo: 'shield', logoColor: 'white' });
  const badge = 'https://img.shields.io/static/v1?' + params.toString();
  const lines = [];
  lines.push(':closed_lock_with_key: Security check on my project — **grade ' + grade + '**');
  if (days >= 1) lines.push(':fire: ' + days + '-day clean streak of critical findings');
  if (fixes > 0) lines.push(':wrench: ' + fixes + ' fix' + (fixes === 1 ? '' : 'es') + ' shipped');
  if (topLabel) lines.push(':trophy: ' + topLabel);
  lines.push('');
  lines.push('Powered by agentic-security: ' + repo);
  lines.push('Badge: ' + badge);
  out(lines.join('\\n'));
}

if (!['twitter', 'x', 'linkedin', 'discord', 'slack', 'all'].includes(target)) {
  console.error('Unknown target: ' + target);
  console.error('Usage: /security-share [twitter|linkedin|discord|all]');
  process.exit(1);
}
" -- "$1"
```

Print verbatim. The user wants the post text to copy.

## Why this exists

Sharing security progress publicly is unusual right now — building a brag-worthy moment is half the battle. `/security-share` turns the celebration moments (streak hit, grade up, fix shipped) into a one-command copy-paste post. Pick the target platform — `twitter`, `linkedin`, `discord`/`slack`, or `all` — and paste the result wherever your audience is.

The post is generated from your local `streak.json` and `last-scan.json` — nothing leaves your machine until you decide to publish.
