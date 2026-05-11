#!/usr/bin/env node
// SessionStart hook.
//
// First session per project: print full welcome + commands list.
// Subsequent sessions: print a one-line streak greeting if there's a streak
// (e.g., "🔥 14 days clean of critical findings · grade A · 12 fixes applied").
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const marker = path.join(stateDir, '.welcomed');
const streakPath = path.join(stateDir, 'streak.json');

function loadStreak() {
  try { return JSON.parse(fs.readFileSync(streakPath, 'utf8')); }
  catch { return null; }
}

function formatStreakLine(s) {
  if (!s || !s.totalScans) return null;
  const parts = [];
  if (s.daysCleanCritical >= 1) {
    const flame = s.daysCleanCritical >= 7 ? '🔥 ' : '';
    parts.push(`${flame}${s.daysCleanCritical} day${s.daysCleanCritical === 1 ? '' : 's'} clean of critical findings`);
  }
  if (s.lastGrade) parts.push(`grade ${s.lastGrade}`);
  if (s.totalFixesInferred > 0) parts.push(`${s.totalFixesInferred} fix${s.totalFixesInferred === 1 ? '' : 'es'} applied`);
  return parts.length ? parts.join(' · ') : null;
}

const isFirstTime = !fs.existsSync(marker);

if (isFirstTime) {
  const lines = [
    '',
    '🛡  agentic-security is active in this project.',
    '   Created by ClearCapabilities.Com — https://clearcapabilities.com',
    '',
    '   Building an app?            → /ship',
    '   AppSec / security work?     → /security-scan-all',
    '   Not sure which you are?     → /security-onboard',
    '',
    '  Hooks: every Edit/Write scans the changed file in <5s.',
    '  This welcome shows once per project.',
    '',
  ];
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(marker, new Date().toISOString());
  } catch {}
  console.error(lines.join('\n'));
  process.exit(0);
}

// Returning session: print streak-at-risk warning if applicable, otherwise the
// regular streak greeting.
const streak = loadStreak();

// Streak-at-risk: only nag when there's something worth losing (≥7 days clean)
// and the last scan was ≥2 days ago. Don't-break-the-chain psychology.
function _daysSince(iso) {
  if (!iso) return null;
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
}
const daysSinceScan = _daysSince(streak?.lastScanDate);
const atRisk = streak
  && (streak.daysCleanCritical || 0) >= 7
  && daysSinceScan !== null && daysSinceScan >= 2;

if (atRisk) {
  console.error('⚠️  agentic-security: ' + streak.daysCleanCritical + '-day clean streak at risk — last scan was ' + daysSinceScan + ' days ago.');
  console.error('    Run /security-scan-all to keep the streak going. Best ever: ' + (streak.bestDaysCleanCritical || streak.daysCleanCritical) + ' days.');
} else {
  const line = formatStreakLine(streak);
  if (line) console.error('🛡️  ' + line);
}
process.exit(0);
