// Smart router — `agentic-security secure`.
//
// One entry point that inspects project state and tells the user the single
// best next action. The vibecoder doesn't have to choose between /scan,
// /fix, /launch-check, /report-card, /find-and-fix-everything, etc.
//
// Decision tree (cheap, no scan):
//   - No prior scan?              → run /scan first
//   - Prior scan, criticals open? → run /fix --all --critical
//   - Prior scan, highs open?     → /fix --all --high  OR  /triage --show
//   - Prior scan, only mediums?   → /posture --report-card
//   - All clean?                  → /security-badge   (celebrate + share)
//   - Pre-deploy intent (--launch flag, or no scan in 7 days)? → /launch-check
//
// Returns { action, command, reason }.

import * as fs from 'node:fs';
import * as path from 'node:path';

import { stateDir, statePath } from './state-dir.js';
function readJson(fp) {
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function ageHours(fp) {
  if (!fs.existsSync(fp)) return Infinity;
  return (Date.now() - fs.statSync(fp).mtimeMs) / 3_600_000;
}

// Compare the two most-recent scan-history entries to tell the user whether
// they're trending safer or more exposed. Returns {} when there isn't enough
// history to say anything honest. (premortem: never invent a trend from one
// data point.)
export function computeScanTrend(scanRoot) {
  const hist = readJson(statePath(scanRoot, 'scan-history.json'));
  if (!Array.isArray(hist) || hist.length < 2) return {};
  const cur = hist[hist.length - 1];
  const prev = hist[hist.length - 2];
  const sevOf = (e) => (e?.critical || 0) + (e?.high || 0);
  const delta = sevOf(cur) - sevOf(prev);
  let trend = 'flat';
  if (delta < 0) trend = 'improving';
  else if (delta > 0) trend = 'regressing';
  const n = Math.abs(delta);
  const whatChanged =
    trend === 'improving' ? `${n} fewer critical+high than last scan — keep going.`
    : trend === 'regressing' ? `${n} more critical+high than last scan — new risk crept in.`
    : 'No change in critical+high since last scan.';
  return { trend, whatChanged };
}

export function decide(opts) {
  const base = baseDecision(opts);
  return { ...base, ...computeScanTrend(opts.scanRoot) };
}

function baseDecision({ scanRoot, intent }) {
  const stateDirPath = stateDir(scanRoot);
  const lastScan = readJson(path.join(stateDirPath, 'last-scan.json'));
  const scanAge = ageHours(path.join(stateDirPath, 'last-scan.json'));

  if (!lastScan) {
    return {
      action: 'first-scan',
      command: 'agentic-security scan .',
      reason: 'No prior scan found. Start with a full sweep.',
    };
  }

  const findings = [
    ...(lastScan.findings || []),
    ...(lastScan.secrets || []),
    ...(lastScan.supplyChain || []),
  ];
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;

  if (intent === 'launch' || intent === 'deploy') {
    if (sev.critical > 0) return {
      action: 'block-launch',
      command: 'agentic-security fix --finding <id> --apply',
      reason: `${sev.critical} critical finding(s) — do NOT deploy. Fix first.`,
    };
    return {
      action: 'launch-check',
      command: 'claude /launch-check',
      reason: 'Pre-deploy checklist (HTTPS, headers, env hygiene, rate limits).',
    };
  }

  if (sev.critical > 0) {
    return {
      action: 'fix-critical',
      command: 'agentic-security fix --finding <id> --preview',
      reason: `${sev.critical} critical finding(s) open. Preview each fix, then --apply.`,
    };
  }
  if (sev.high > 0) {
    return {
      action: 'review-high',
      command: 'claude /triage --show',
      reason: `${sev.high} high finding(s). Review and triage before fixing.`,
    };
  }
  if (scanAge > 24 * 7) {
    return {
      action: 'rescan',
      command: 'agentic-security scan .',
      reason: `Last scan was ${Math.round(scanAge / 24)} days ago. Re-scan for fresh CVEs.`,
    };
  }
  if (sev.medium > 0) {
    return {
      action: 'report-card',
      command: 'claude /posture --report-card',
      reason: `Only mediums remain. Get a letter-grade snapshot and pick what's worth fixing.`,
    };
  }
  return {
    action: 'celebrate',
    command: 'claude /security-badge',
    reason: 'Clean scan. Generate a badge for your README and share the win.',
  };
}

export function explain(decision) {
  const lines = [
    `🛡  agentic-security · next step`,
    ``,
    `  Action:  ${decision.action}`,
    `  Why:     ${decision.reason}`,
  ];
  if (decision.trend) {
    const arrow = decision.trend === 'improving' ? '↓' : decision.trend === 'regressing' ? '↑' : '→';
    lines.push(`  Trend:   ${arrow} ${decision.whatChanged}`);
  }
  lines.push(`  Run:     ${decision.command}`, ``);
  return lines.join('\n');
}
