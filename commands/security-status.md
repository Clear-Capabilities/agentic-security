---
description: Print a one-screen project & plugin health snapshot — version, last scan time + counts, cache size, hook activation, suppression rules.
---

Print the agentic-security project health snapshot.

```bash
node -e "
const fs = require('fs');
const os = require('os');
const path = require('path');

const cwd = process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cacheDir = path.join(os.homedir(), '.claude', 'agentic-security', 'osv-cache');

function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }
function readJSON(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }
function dirSize(p) {
  if (!exists(p)) return 0;
  let total = 0;
  try {
    for (const f of fs.readdirSync(p)) {
      const s = fs.statSync(path.join(p, f));
      if (s.isFile()) total += s.size;
    }
  } catch {}
  return total;
}
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(1) + ' MB';
}
function fmtAge(iso) {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return Math.floor(ms/1000) + 's ago';
  if (ms < 3_600_000) return Math.floor(ms/60_000) + 'm ago';
  if (ms < 86_400_000) return Math.floor(ms/3_600_000) + 'h ago';
  return Math.floor(ms/86_400_000) + 'd ago';
}

// Plugin version
let version = 'unknown';
try {
  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || '';
  const pkg = readJSON(path.join(pluginRoot, '.claude-plugin', 'plugin.json'));
  if (pkg) version = pkg.version;
} catch {}

// Last scan
const lastScan = readJSON(path.join(stateDir, 'last-scan.json'));
const findings = lastScan?.findings || [];
const counts = { critical:0, high:0, medium:0, low:0, info:0 };
for (const f of findings) counts[f.severity] = (counts[f.severity]||0)+1;
const startedAt = lastScan?.startedAt || lastScan?.meta?.startedAt || null;

// Suppression rules
const rulesPath = path.join(stateDir, 'rules.yml');
let suppressionCount = 0;
try {
  const text = fs.readFileSync(rulesPath, 'utf8');
  suppressionCount = (text.match(/^\s*-\s*rule:/gm) || []).length;
} catch {}

// License policy
const licensePolicyExists = exists(path.join(stateDir, 'license-policy.yml'));

// Cache
const cacheSize = dirSize(cacheDir);
const cacheCount = exists(cacheDir) ? fs.readdirSync(cacheDir).length : 0;

// Hooks
const hooksJson = readJSON(path.join(process.env.CLAUDE_PLUGIN_ROOT || '', 'hooks', 'hooks.json'));
const hookKinds = hooksJson?.hooks ? Object.keys(hooksJson.hooks) : [];

// KEV cache freshness
let kevAge = 'not fetched';
try {
  const crypto = require('crypto');
  const kevKey = crypto.createHash('sha256').update('osv_kev:catalog').digest('hex') + '.json';
  const kevPath = path.join(cacheDir, kevKey);
  if (exists(kevPath)) {
    const blob = JSON.parse(fs.readFileSync(kevPath, 'utf8'));
    if (blob?.ts) kevAge = fmtAge(new Date(blob.ts).toISOString());
  }
} catch {}

console.log('agentic-security status');
console.log('');
console.log('  Version:        ' + version);
console.log('  Hooks active:   ' + (hookKinds.length ? hookKinds.join(', ') : 'none'));
console.log('  Offline mode:   ' + (process.env.AGENTIC_SECURITY_OFFLINE === '1' ? 'ON' : 'OFF'));
console.log('  Quiet mode:     ' + (process.env.AGENTIC_SECURITY_QUIET === '1' ? 'ON' : 'OFF'));
console.log('');
console.log('Last scan');
if (startedAt) {
  console.log('  When:           ' + fmtAge(startedAt) + '  (' + startedAt + ')');
  const filesCount = (typeof lastScan.scanned === 'object' ? lastScan.scanned?.files : lastScan.scanned) ?? lastScan.filesScanned ?? '?';
  console.log('  Files scanned:  ' + filesCount);
  console.log('  Findings:       ' + findings.length + '  (critical=' + counts.critical + ' high=' + counts.high + ' medium=' + counts.medium + ' low=' + counts.low + ' info=' + counts.info + ')');
  if (lastScan.routes) console.log('  Routes:         ' + lastScan.routes.length);
  if (lastScan.components) console.log('  Components:     ' + lastScan.components.length);
} else {
  console.log('  When:           never — run /scan --all to bootstrap');
}
console.log('');
console.log('Configuration');
console.log('  Suppressions:   ' + suppressionCount + ' rules in .agentic-security/rules.yml');
console.log('  License policy: ' + (licensePolicyExists ? 'configured' : 'not configured (.agentic-security/license-policy.yml)'));
console.log('');
console.log('Cache (' + cacheDir + ')');
console.log('  Size:           ' + fmtBytes(cacheSize) + '  (' + cacheCount + ' entries)');
console.log('  CISA KEV:       refreshed ' + kevAge + '  (24h TTL)');
console.log('');

// 0.14.0 — Streaks + achievements
const streak = readJSON(path.join(stateDir, 'streak.json'));
if (streak && streak.totalScans) {
  console.log('Streak');
  if (streak.daysCleanCritical >= 1) {
    const flame = streak.daysCleanCritical >= 7 ? '🔥 ' : '';
    console.log('  Clean run:      ' + flame + streak.daysCleanCritical + ' day' + (streak.daysCleanCritical === 1 ? '' : 's') + ' clean of critical findings (best: ' + (streak.bestDaysCleanCritical || streak.daysCleanCritical) + ')');
  } else if (streak.lastCriticalDate) {
    console.log('  Clean run:      0 days (last critical: ' + streak.lastCriticalDate + ')');
  }
  console.log('  Total scans:    ' + streak.totalScans);
  if (streak.totalFixesInferred > 0) console.log('  Fixes applied:  ' + streak.totalFixesInferred);
  if (streak.lastGrade) console.log('  Current grade:  ' + streak.lastGrade + (streak.bestGrade && streak.bestGrade !== streak.lastGrade ? '  (best: ' + streak.bestGrade + ')' : ''));
  console.log('');
  if (streak.achievements && streak.achievements.length) {
    const LABELS = {
      'first-scan':      ['🛡️', 'First Scan'],
      'first-fix':       ['🔧', 'First Fix'],
      'clean-sweep':     ['🧹', 'Clean Sweep'],
      'triage-master':   ['🎯', 'Bronze Fixer (10 fixes)'],
      'triage-silver':   ['🥈', 'Silver Fixer (50 fixes)'],
      'triage-gold':     ['🥇', 'Gold Fixer (200 fixes)'],
      'streak-7':        ['🥉', 'Bronze Streak (7 days)'],
      'streak-30':       ['🥈', 'Silver Streak (30 days)'],
      'streak-90':       ['🥇', 'Gold Streak (90 days)'],
      'streak-180':      ['💎', 'Platinum Streak (180 days)'],
      'streak-365':      ['💠', 'Diamond Streak (365 days)'],
      'grade-a':         ['🏆', 'Grade A'],
      'grade-a-plus':    ['🌟', 'Grade A+'],
      'launch-ready':    ['🚀', 'Launch Ready'],
      'scan-veteran-25': ['⭐', 'Scan Veteran (25)'],
      'scan-veteran-100':['🎖️', 'Scan Centurion (100)'],
    };
    console.log('Achievements (' + streak.achievements.length + ')');
    for (const a of streak.achievements) {
      const [icon, label] = LABELS[a] || ['🏅', a];
      console.log('  ' + icon + '  ' + label);
    }
    console.log('');
  }
}
if (counts.critical > 0) {
  console.log('Action: ' + counts.critical + ' critical finding(s). Run /fix --all --critical');
} else if (counts.high > 0) {
  console.log('Action: ' + counts.high + ' high finding(s). Run /fix --all --high');
} else if (!startedAt) {
  console.log('Action: run /scan --all to take a first inventory');
} else {
  console.log('Status: clean ✓');
}
"
```

Print the output verbatim. The user wants a one-screen health snapshot of the plugin and the project's security state.
