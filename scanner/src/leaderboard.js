// Leaderboard backend (v0.72).
//
// Generates the data shape that powers the future public leaderboard at
// agentic-security.dev/leaderboard. The leaderboard ranks repos by their
// security posture under our scanner — F1-on-CVE-history when we can
// compute it, otherwise just last-scan severity counts.
//
// Public hosting of the site is deferred — we ship the data side now so
// the future site is a thin frontend over this JSON.
//
// One leaderboard row per repo:
//
//   {
//     repo: 'owner/name',
//     score: { critical, high, medium, low, info, total },
//     postureGrade: 'A' | 'B' | 'C' | 'D' | 'F',
//     lastScanAge: '4h',
//     topCwe: 'CWE-89',
//     deltaTrend: 'improving' | 'flat' | 'regressing',
//     badgeUrl: 'https://agentic-security.dev/badge?repo=…',
//   }
//
// The grader is intentionally coarse — single letter — so the leaderboard
// stays scannable. Tie-break by lowest critical-count, then by recency.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { summarizeForBadge } from './badge.js';

import { statePath } from './posture/state-dir.js';
// Grade thresholds. Critical findings dominate; high/medium contribute
// secondarily. These numbers are heuristic — calibrate against the
// public leaderboard corpus once data lands.
function _postureGrade(counts) {
  if (!counts) return 'F';
  const c = counts.critical || 0;
  const h = counts.high || 0;
  const m = counts.medium || 0;
  if (c === 0 && h === 0 && m === 0) return 'A';
  if (c === 0 && h === 0 && m <= 5)  return 'B';
  if (c === 0 && h <= 2)             return 'C';
  if (c <= 1 && h <= 5)              return 'D';
  return 'F';
}

function _ageString(ts) {
  if (!ts) return null;
  const ageMs = Date.now() - new Date(ts).getTime();
  if (isNaN(ageMs) || ageMs < 0) return null;
  const min = Math.floor(ageMs / 60_000);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const day = Math.floor(hr / 24);
  return `${day}d`;
}

function _topCwe(scan) {
  if (!scan || !Array.isArray(scan.findings)) return null;
  const counts = new Map();
  for (const f of scan.findings) {
    if (!f.cwe) continue;
    counts.set(f.cwe, (counts.get(f.cwe) || 0) + 1);
  }
  let topCwe = null, topN = 0;
  for (const [cwe, n] of counts) {
    if (n > topN) { topCwe = cwe; topN = n; }
  }
  return topCwe;
}

function _deltaTrend(history) {
  // history: array of past scan summaries with `.timestamp` + `.severityCounts.critical`
  if (!Array.isArray(history) || history.length < 2) return 'flat';
  const recent = history.slice(-3);
  const first = recent[0].severityCounts || {};
  const last = recent[recent.length - 1].severityCounts || {};
  const fScore = (first.critical || 0) * 4 + (first.high || 0);
  const lScore = (last.critical || 0) * 4 + (last.high || 0);
  if (lScore < fScore - 1) return 'improving';
  if (lScore > fScore + 1) return 'regressing';
  return 'flat';
}

/**
 * Build a single leaderboard row for a repo. Reads the latest scan from
 * `<scanRoot>/.agentic-security/last-scan.json` and (optionally) history
 * from `<scanRoot>/.agentic-security/scan-history.jsonl`.
 *
 * `repo` is the GitHub slug ('owner/name'); used to drive the badge URL.
 */
export function leaderboardRowFor({ scanRoot, repo, badgeBase = 'https://agentic-security.dev/badge' } = {}) {
  if (!repo) throw new Error('leaderboardRowFor: repo slug is required');
  const lastScanPath = statePath(scanRoot || '.', 'last-scan.json');
  let scan = null;
  try { scan = JSON.parse(fs.readFileSync(lastScanPath, 'utf8')); } catch {}
  const summary = summarizeForBadge(scan);
  const grade = _postureGrade(summary.counts);
  const topCwe = _topCwe(scan);

  // Optional scan history for the trend signal.
  const historyPath = statePath(scanRoot || '.', 'scan-history.jsonl');
  let history = [];
  if (fs.existsSync(historyPath)) {
    try {
      history = fs.readFileSync(historyPath, 'utf8').split('\n')
        .map(l => l.trim()).filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean);
    } catch {}
  }
  const deltaTrend = _deltaTrend(history);

  return {
    repo,
    score: { ...summary.counts, total: summary.total },
    postureGrade: grade,
    lastScanAge: _ageString(scan?.timestamp || scan?.when),
    topCwe,
    deltaTrend,
    badgeUrl: `${badgeBase}?repo=${encodeURIComponent(repo)}`,
    badgeMarkdown: `![agentic-security](${badgeBase}?repo=${encodeURIComponent(repo)})`,
  };
}

/**
 * Rank a list of rows for the leaderboard. Sort by:
 *   1. lower critical count
 *   2. lower high count
 *   3. higher postureGrade (A > F)
 *   4. fresher lastScanAge
 *
 * Returns the input rows annotated with `rank` (1-indexed).
 */
export function rankRows(rows) {
  if (!Array.isArray(rows)) return [];
  const gradeOrder = { A: 0, B: 1, C: 2, D: 3, F: 4 };
  const sorted = [...rows].sort((a, b) => {
    const ac = a.score?.critical || 0;
    const bc = b.score?.critical || 0;
    if (ac !== bc) return ac - bc;
    const ah = a.score?.high || 0;
    const bh = b.score?.high || 0;
    if (ah !== bh) return ah - bh;
    const ag = gradeOrder[a.postureGrade] ?? 5;
    const bg = gradeOrder[b.postureGrade] ?? 5;
    if (ag !== bg) return ag - bg;
    return 0;
  });
  return sorted.map((r, i) => ({ ...r, rank: i + 1 }));
}

export const _internal = { _postureGrade, _ageString, _topCwe, _deltaTrend };
