---
description: Year-in-Security recap — Spotify-Wrapped-style summary of your project's security journey. Days active, scans run, fixes shipped, grade journey, longest streak, top achievements.
---

Generate a shareable recap card from `.agentic-security/streak.json`.

```bash
node -e "
const fs = require('fs');

let streak;
try { streak = JSON.parse(fs.readFileSync('.agentic-security/streak.json', 'utf8')); }
catch { console.log('No streak history yet. Run /security-scan-all a few times to build one, then /security-recap.'); process.exit(0); }

if (!streak.totalScans) {
  console.log('No scan history yet. /security-recap needs at least one scan to summarize.');
  process.exit(0);
}

function daysSince(iso) {
  if (!iso) return 0;
  return Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 86_400_000));
}

const daysActive = daysSince(streak.firstScanDate);
const totalScans = streak.totalScans || 0;
const fixes = streak.totalFixesInferred || 0;
const longestStreak = streak.bestDaysCleanCritical || streak.daysCleanCritical || 0;
const currentStreak = streak.daysCleanCritical || 0;
const firstFindings = streak.totalFindingsAtFirstScan ?? 0;
const lastFindings = streak.totalFindingsAtLastScan ?? 0;
const findingsResolved = Math.max(0, firstFindings - lastFindings);

const TIER_ORDER = ['streak-365', 'streak-180', 'streak-90', 'streak-30', 'streak-7', 'triage-gold', 'triage-silver', 'triage-master', 'grade-a-plus', 'grade-a', 'launch-ready', 'clean-sweep', 'first-fix', 'first-scan'];
const TIER_LABELS = {
  'streak-365': '💠 Diamond Streak', 'streak-180': '💎 Platinum Streak', 'streak-90': '🥇 Gold Streak',
  'streak-30': '🥈 Silver Streak',  'streak-7': '🥉 Bronze Streak',
  'triage-gold': '🥇 Gold Fixer',   'triage-silver': '🥈 Silver Fixer',  'triage-master': '🎯 Bronze Fixer',
  'grade-a-plus': '🌟 Grade A+',     'grade-a': '🏆 Grade A',
  'launch-ready': '🚀 Launch Ready', 'clean-sweep': '🧹 Clean Sweep',
  'first-fix': '🔧 First Fix',       'first-scan': '🛡️ First Scan',
};
const earned = streak.achievements || [];
const topThree = TIER_ORDER.filter(id => earned.includes(id)).slice(0, 3);

const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const BOLD = '1', DIM = '2', GREEN = '92', YELLOW = '93', CYAN = '96';

console.log('');
console.log(W('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', BOLD));
console.log(W('       Your Year in Security 🔒', BOLD));
console.log(W('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', BOLD));
console.log('');
console.log('  ' + W(daysActive + ' days', BOLD + ';' + CYAN) + ' protected · ' + W(totalScans, BOLD) + ' scans run');
console.log('');

if (fixes > 0) {
  console.log('  🔧  You shipped ' + W(fixes + ' fix' + (fixes === 1 ? '' : 'es'), BOLD + ';' + GREEN));
}
if (findingsResolved > 0 && firstFindings > 0) {
  const pct = Math.round(100 * findingsResolved / firstFindings);
  console.log('  📉  Resolved ' + W(findingsResolved + ' finding' + (findingsResolved === 1 ? '' : 's'), BOLD) + ' since day one (' + pct + '% of where you started)');
}
if (longestStreak > 0) {
  console.log('  🔥  Longest clean run: ' + W(longestStreak + ' day' + (longestStreak === 1 ? '' : 's') + ' without a critical', BOLD + ';' + YELLOW));
}
if (currentStreak > 0 && currentStreak !== longestStreak) {
  console.log('  ⏱️   Current streak: ' + W(currentStreak + ' day' + (currentStreak === 1 ? '' : 's'), BOLD));
}
if (streak.lastGrade) {
  let line = '  🏷️   Grade: ';
  if (streak.previousGrade && streak.previousGrade !== streak.lastGrade) {
    line += W(streak.previousGrade, DIM) + ' → ' + W(streak.lastGrade, BOLD);
  } else {
    line += W(streak.lastGrade, BOLD);
  }
  if (streak.bestGrade && streak.bestGrade !== streak.lastGrade) line += '   (best: ' + streak.bestGrade + ')';
  console.log(line);
}

if (topThree.length) {
  console.log('');
  console.log(W('  Top achievements:', BOLD));
  for (const id of topThree) console.log('    ' + (TIER_LABELS[id] || id));
  if (earned.length > topThree.length) console.log('    ' + W('+ ' + (earned.length - topThree.length) + ' more (run /security-status)', DIM));
}

console.log('');
console.log(W('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', BOLD));
console.log('');
console.log('  Share your recap: ' + W('/security-share', CYAN));
console.log('  Get a badge:      ' + W('/security-badge', CYAN));
console.log('');
"
```

Print verbatim. The user wants the recap card.

## Why this exists

Spotify Wrapped is one of the most-shared marketing artifacts in tech every December. The same psychology applies to security — once a project has 6+ months of history in `.agentic-security/streak.json`, that data adds up to a personal narrative worth sharing. `/security-recap` produces a one-screen summary card with the highlights: days active, scans run, fixes shipped, grade journey, longest streak, top achievements.

Best paired with `/security-share` immediately after, to turn the recap into a tweet, LinkedIn post, or Discord drop.
