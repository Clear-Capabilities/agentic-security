// Security regression scorecard — trend tracking across scans.
//
// Reads .agentic-security/scan-history.json (appended to by the post-edit hook
// and runScan) and returns a delta summary: findings added, findings fixed,
// net change, and which files regressed.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath, safeWriteState } from './state-dir.js';

const MAX_HISTORY = 30; // rolling window

function _readHistory(scanRoot) {
  const histPath = statePath(scanRoot, 'scan-history.json');
  try {
    return JSON.parse(fs.readFileSync(histPath, 'utf8'));
  } catch {
    return [];
  }
}

function _writeHistory(scanRoot, history) {
  const histPath = statePath(scanRoot, 'scan-history.json');
  safeWriteState(histPath, JSON.stringify(history.slice(-MAX_HISTORY), null, 2));
}

function _snapshotFromScan(scan, label) {
  const findings = scan.findings || [];
  return {
    timestamp: new Date().toISOString(),
    label: label || 'scan',
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    kev: findings.filter(f => f.kev).length,
    ids: new Set(findings.map(f => f.id).filter(Boolean)),
  };
}

function appendScanSnapshot(scan, scanRoot, label) {
  const history = _readHistory(scanRoot);
  const snap = _snapshotFromScan(scan, label);
  // Don't store the full id Set in JSON — store sorted array
  const entry = { ...snap, ids: [...snap.ids].sort() };
  history.push(entry);
  _writeHistory(scanRoot, history);
}

function computeTrend(scanRoot) {
  const history = _readHistory(scanRoot);
  if (history.length < 2) {
    return { hasTrend: false, snapshots: history, message: 'Need at least 2 scans to show a trend.' };
  }

  const prev = history[history.length - 2];
  const curr = history[history.length - 1];

  const prevIds = new Set(prev.ids || []);
  const currIds = new Set(curr.ids || []);

  const introduced = [...currIds].filter(id => !prevIds.has(id));
  const fixed = [...prevIds].filter(id => !currIds.has(id));

  const delta = curr.total - prev.total;
  const critDelta = curr.critical - prev.critical;

  return {
    hasTrend: true,
    snapshots: history,
    prev: { timestamp: prev.timestamp, total: prev.total, critical: prev.critical, high: prev.high },
    curr: { timestamp: curr.timestamp, total: curr.total, critical: curr.critical, high: curr.high },
    introduced: introduced.length,
    fixed: fixed.length,
    delta,
    critDelta,
    improving: delta <= 0 && critDelta <= 0,
    introducedIds: introduced.slice(0, 10),
    fixedCount: fixed.length,
  };
}

export { appendScanSnapshot, computeTrend };
