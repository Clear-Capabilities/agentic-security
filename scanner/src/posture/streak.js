// Streaks + achievements state module.
//
// Persists `.agentic-security/streak.json` so the user can see progress
// across sessions: days clean of critical findings, total scans, total
// fixes applied, achievements earned. Pure transform — recordScan reads
// the latest scan + previous streak file and writes the updated state.
//
// Achievement design: every achievement is derived from the streak state
// itself, so we never have to detect "a fix happened" — we just compare
// counters between scans.

import * as fs from 'node:fs';
import * as path from 'node:path';

function _streakPath(stateDir) {
  return path.join(stateDir, 'streak.json');
}

const _DEFAULT_STREAK = {
  firstScanDate: null,
  lastScanDate: null,
  totalScans: 0,
  daysCleanCritical: 0,
  lastCleanDate: null,
  lastCriticalDate: null,
  hasEverHadCritical: false,
  bestDaysCleanCritical: 0,
  totalFindingsAtFirstScan: null,
  totalFindingsAtLastScan: null,
  totalFixesInferred: 0,
  lastGrade: null,
  bestGrade: null,
  launchCheckPassedAt: null,
  achievements: [],
};

export function loadStreak(stateDir) {
  try {
    const raw = fs.readFileSync(_streakPath(stateDir), 'utf8');
    return { ..._DEFAULT_STREAK, ...JSON.parse(raw) };
  } catch {
    return { ..._DEFAULT_STREAK };
  }
}

function _todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function _daysBetween(aIso, bIso) {
  if (!aIso || !bIso) return 0;
  const a = new Date(aIso + 'T00:00:00Z').getTime();
  const b = new Date(bIso + 'T00:00:00Z').getTime();
  return Math.round((b - a) / 86_400_000);
}

// Compute a letter grade from severity counts. Mirrors /security-grade so
// we can track grade-delta in the streak.
function _computeGrade(scan) {
  const findings = scan?.findings || [];
  const supplyChain = scan?.supplyChain || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  for (const s of supplyChain.filter(s => s.type === 'vulnerable_dep')) {
    counts[s.severity || 'high'] = (counts[s.severity || 'high'] || 0) + 1;
  }
  const kev = [...findings, ...supplyChain].filter(f => f.kev === true).length;
  const c = counts.critical, h = counts.high;
  if (c > 10 || (c > 5 && kev > 0)) return 'F';
  if (c >= 6) return 'D';
  if (kev > 0) return 'D';
  if (c >= 3) return 'C-';
  if (c >= 1) return 'C';
  if (h > 10) return 'B-';
  if (h >= 3) return 'B';
  if (h > 0) return 'A-';
  if (counts.medium > 0) return 'A';
  return 'A+';
}

const _GRADE_RANK = { 'F': 0, 'D': 1, 'C-': 2, 'C': 3, 'B-': 4, 'B': 5, 'A-': 6, 'A': 7, 'A+': 8 };

function _gradeRank(g) { return _GRADE_RANK[g] ?? -1; }

function _computeAchievements(streak, scan) {
  const earned = new Set(streak.achievements || []);
  const findings = scan?.findings || [];
  const counts = { critical: 0, high: 0, medium: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  // Lifetime achievements (unlock once, never expire). Tiers escalate
  // Bronze → Silver → Gold → Platinum → Diamond. Old IDs preserved for
  // backward compatibility with persisted streak.json files.
  if (streak.totalScans >= 1) earned.add('first-scan');
  if (streak.hasEverHadCritical && counts.critical === 0) earned.add('clean-sweep');
  if (streak.totalFixesInferred >= 1) earned.add('first-fix');
  // Triage tiers (was: triage-master at 10)
  if (streak.totalFixesInferred >= 10) earned.add('triage-master');
  if (streak.totalFixesInferred >= 50) earned.add('triage-silver');
  if (streak.totalFixesInferred >= 200) earned.add('triage-gold');
  // Streak tiers (Bronze/Silver/Gold/Platinum/Diamond)
  if (streak.daysCleanCritical >= 7) earned.add('streak-7');         // Bronze
  if (streak.daysCleanCritical >= 30) earned.add('streak-30');       // Silver
  if (streak.daysCleanCritical >= 90) earned.add('streak-90');       // Gold
  if (streak.daysCleanCritical >= 180) earned.add('streak-180');     // Platinum
  if (streak.daysCleanCritical >= 365) earned.add('streak-365');     // Diamond
  if (_gradeRank(streak.lastGrade) >= _gradeRank('A')) earned.add('grade-a');
  if (streak.lastGrade === 'A+') earned.add('grade-a-plus');
  if (streak.launchCheckPassedAt) earned.add('launch-ready');
  if (streak.totalScans >= 25) earned.add('scan-veteran-25');
  if (streak.totalScans >= 100) earned.add('scan-veteran-100');

  return [...earned].sort();
}

// Public — invoked by the CLI after every full scan.
export function recordScan(stateDir, scan) {
  try { fs.mkdirSync(stateDir, { recursive: true }); } catch {}
  const prev = loadStreak(stateDir);
  const today = _todayUTC();

  const findings = scan?.findings || [];
  const supplyChain = scan?.supplyChain || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  for (const s of supplyChain.filter(s => s.type === 'vulnerable_dep')) {
    counts[s.severity || 'high'] = (counts[s.severity || 'high'] || 0) + 1;
  }

  const totalNow = findings.length + supplyChain.filter(s => s.type === 'vulnerable_dep').length;
  const grade = _computeGrade(scan);

  // Streak math: increment days-clean only when we're clean today AND today is a new date
  let daysCleanCritical = prev.daysCleanCritical || 0;
  let lastCleanDate = prev.lastCleanDate;
  let lastCriticalDate = prev.lastCriticalDate;
  let hasEverHadCritical = prev.hasEverHadCritical;

  if (counts.critical === 0) {
    if (lastCleanDate !== today) {
      // If yesterday was the last clean, +1; otherwise reset to 1 (new clean run)
      const gap = _daysBetween(lastCleanDate, today);
      daysCleanCritical = gap === 1 ? daysCleanCritical + 1 : 1;
      lastCleanDate = today;
    }
  } else {
    daysCleanCritical = 0;
    lastCriticalDate = today;
    hasEverHadCritical = true;
  }

  const bestDaysCleanCritical = Math.max(prev.bestDaysCleanCritical || 0, daysCleanCritical);

  // Infer "fixes applied" from finding count drops between consecutive scans
  let totalFixesInferred = prev.totalFixesInferred || 0;
  if (prev.totalFindingsAtLastScan != null && totalNow < prev.totalFindingsAtLastScan) {
    totalFixesInferred += (prev.totalFindingsAtLastScan - totalNow);
  }

  const next = {
    ...prev,
    firstScanDate: prev.firstScanDate || new Date().toISOString(),
    lastScanDate: new Date().toISOString(),
    totalScans: (prev.totalScans || 0) + 1,
    daysCleanCritical,
    lastCleanDate,
    lastCriticalDate,
    hasEverHadCritical,
    bestDaysCleanCritical,
    totalFindingsAtFirstScan: prev.totalFindingsAtFirstScan ?? totalNow,
    totalFindingsAtLastScan: totalNow,
    totalFixesInferred,
    previousGrade: prev.lastGrade,
    lastGrade: grade,
    bestGrade: prev.bestGrade && _gradeRank(prev.bestGrade) >= _gradeRank(grade) ? prev.bestGrade : grade,
  };
  next.achievements = _computeAchievements(next, scan);

  try { fs.writeFileSync(_streakPath(stateDir), JSON.stringify(next, null, 2)); } catch {}
  return next;
}

// Mark "launch check passed 10/10" — called from /security-launch-check
export function markLaunchCheckPassed(stateDir) {
  const prev = loadStreak(stateDir);
  const next = { ...prev, launchCheckPassedAt: new Date().toISOString() };
  next.achievements = _computeAchievements(next, { findings: [] });
  try { fs.mkdirSync(stateDir, { recursive: true }); fs.writeFileSync(_streakPath(stateDir), JSON.stringify(next, null, 2)); } catch {}
  return next;
}

export function formatStreakLine(streak) {
  if (!streak || !streak.totalScans) return null;
  const parts = [];
  if (streak.daysCleanCritical >= 1) {
    const flame = streak.daysCleanCritical >= 7 ? '🔥 ' : '';
    parts.push(`${flame}${streak.daysCleanCritical} day${streak.daysCleanCritical === 1 ? '' : 's'} clean of critical findings`);
  }
  if (streak.lastGrade) {
    parts.push(`grade ${streak.lastGrade}`);
  }
  if (streak.totalFixesInferred > 0) {
    parts.push(`${streak.totalFixesInferred} fix${streak.totalFixesInferred === 1 ? '' : 'es'} applied`);
  }
  return parts.length ? parts.join(' · ') : null;
}

export function formatGradeDelta(streak) {
  if (!streak || !streak.previousGrade || !streak.lastGrade) return null;
  if (streak.previousGrade === streak.lastGrade) return null;
  const prev = _gradeRank(streak.previousGrade);
  const now = _gradeRank(streak.lastGrade);
  if (now > prev) return `📈 Grade up: ${streak.previousGrade} → ${streak.lastGrade}`;
  if (now < prev) return `📉 Grade down: ${streak.previousGrade} → ${streak.lastGrade}`;
  return null;
}

const ACHIEVEMENT_LABELS = {
  'first-scan':      { icon: '🛡️', label: 'First Scan', desc: 'Ran your first security scan' },
  'first-fix':       { icon: '🔧', label: 'First Fix', desc: 'Applied at least one fix' },
  'clean-sweep':     { icon: '🧹', label: 'Clean Sweep', desc: 'Took your project from criticals to zero' },
  // Triage tiers
  'triage-master':   { icon: '🎯', label: 'Bronze Fixer', desc: '10+ findings remediated' },
  'triage-silver':   { icon: '🥈', label: 'Silver Fixer', desc: '50+ findings remediated' },
  'triage-gold':     { icon: '🥇', label: 'Gold Fixer', desc: '200+ findings remediated' },
  // Streak tiers (Bronze → Diamond)
  'streak-7':        { icon: '🥉', label: 'Bronze Streak', desc: '7 days clean of critical findings' },
  'streak-30':       { icon: '🥈', label: 'Silver Streak', desc: '30 days clean of critical findings' },
  'streak-90':       { icon: '🥇', label: 'Gold Streak', desc: '90 days clean of critical findings' },
  'streak-180':      { icon: '💎', label: 'Platinum Streak', desc: '180 days clean of critical findings' },
  'streak-365':      { icon: '💠', label: 'Diamond Streak', desc: '365 days clean of critical findings' },
  // Grade
  'grade-a':         { icon: '🏆', label: 'Grade A', desc: 'Reached an A-tier security grade' },
  'grade-a-plus':    { icon: '🌟', label: 'Grade A+', desc: 'Reached the perfect grade — zero findings' },
  'launch-ready':    { icon: '🚀', label: 'Launch Ready', desc: 'Passed all 10 launch-check items' },
  // Scan veteran
  'scan-veteran-25': { icon: '⭐', label: 'Scan Veteran (25)', desc: '25 scans completed' },
  'scan-veteran-100':{ icon: '🎖️', label: 'Scan Centurion (100)', desc: '100 scans completed' },
};

export function formatAchievements(streak) {
  if (!streak?.achievements?.length) return [];
  return streak.achievements.map(id => ({
    id,
    ...ACHIEVEMENT_LABELS[id] || { icon: '🏅', label: id, desc: '' },
  }));
}

export const _internal = { _computeGrade, _GRADE_RANK, _DEFAULT_STREAK, ACHIEVEMENT_LABELS };
