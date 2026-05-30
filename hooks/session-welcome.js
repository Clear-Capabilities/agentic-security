#!/usr/bin/env node
// SessionStart hook.
//
// First session per project: print full welcome + commands list.
// Subsequent sessions: print a one-line streak greeting if there's a streak
// (e.g., "🔥 14 days clean of critical findings · grade A · 12 fixes applied").
'use strict';
const fs = require('fs');
const path = require('path');
const { lockup } = require('./mascot.js');

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
  // First-use welcome — lead with the brand line, then the frog lockup,
  // then the three onboarding paths. The product name and creator MUST be
  // unambiguous: this is the moment the user learns what they just installed.
  const useColor = !!process.stderr.isTTY && !process.env.NO_COLOR;
  const C = useColor ? {
    BOLD: '\x1b[1m', DIM: '\x1b[2m', RESET: '\x1b[0m',
    FROG: '\x1b[38;2;255;107;44m', CREAM: '\x1b[38;2;244;239;230m',
  } : { BOLD:'', DIM:'', RESET:'', FROG:'', CREAM:'' };
  const lines = [
    '',
    `   ${C.BOLD}Welcome to agentic-security${C.RESET}  ${C.DIM}— by Clear Capabilities Inc.${C.RESET}`,
    `   ${C.DIM}Full ASPM + LLMSecOps for Claude Code · https://clearcapabilities.com${C.RESET}`,
    '',
    lockup(),
    `   ${C.BOLD}Meet Patch.${C.RESET}  Tiny. ${C.FROG}${C.BOLD}Bright.${C.RESET}  Watching every Edit, Write, and Bash.`,
    '',
    '   ┌─ How to start ─────────────────────────────────────────────┐',
    '   │  Building an app?            → /find-and-fix-everything    │',
    '   │  AppSec / security work?     → /scan --all                 │',
    '   │  Not sure where to start?    → /secure                     │',
    '   │  See every command           → /secure --help              │',
    '   └────────────────────────────────────────────────────────────┘',
    '',
    `   ${C.DIM}Hooks: every Edit/Write scans the changed file in <5s.${C.RESET}`,
    `   ${C.DIM}This welcome shows once per project.${C.RESET}`,
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

// Harness-anatomy #2: surface AGENTS.md continual-learning notes (most-recent
// tail) so subagents can pick up where the last session left off.
try {
  const agentsMd = path.join(stateDir, 'AGENTS.md');
  if (fs.existsSync(agentsMd)) {
    const body = fs.readFileSync(agentsMd, 'utf8');
    const limit = 4 * 1024;
    let slice = body.length <= limit ? body : body.slice(-limit);
    if (body.length > limit) {
      const firstSection = slice.indexOf('\n## ');
      if (firstSection >= 0) slice = slice.slice(firstSection);
    }
    if (slice && slice.trim().length) {
      console.error('');
      console.error('agentic-security: AGENTS.md (continual-learning notes from prior sessions):');
      for (const line of slice.split('\n').slice(0, 40)) console.error('  ' + line);
      if (slice.split('\n').length > 40) console.error('  …(more in .agentic-security/AGENTS.md)');
    }
  }
} catch { /* surface failure is non-fatal */ }
process.exit(0);
