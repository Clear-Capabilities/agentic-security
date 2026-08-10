// Time-to-fix estimator.
//
// Estimates engineering hours to remediate each finding from:
//
//   - family base difficulty (regex auth-missing ≠ deserialization)
//   - patch shape (single-line vs cross-file refactor) from fix.code if present
//   - prior fix-history for the same family in this project (learned base)
//   - reachability tier (tests + verify cost adjusts)
//
// Output: f.estimatedFixHours, rolled-up totals + a per-family rollup so
// the PM/PR view can show "this PR ships ~6 hours of security debt."

import * as fs from 'node:fs';
import * as path from 'node:path';


import { statePath } from './state-dir.js';
const HISTORY_FILE = 'fix-history/log.json';

// Family base estimates (hours). Tuned from typical patch shapes.
const FAMILY_BASE_HOURS = {
  'sqli': 0.5, 'sql-injection': 0.5,           // parameterize one query
  'xss': 0.5, 'mutation-xss': 1.0,
  'command-injection': 0.5,
  'code-injection': 2.0,                        // usually needs refactor
  'deserialization': 4.0,                       // protocol/serializer swap
  'auth-missing': 0.5,                          // add middleware
  'authz': 2.0, 'idor': 2.0,                    // ownership checks across handlers
  'csrf': 1.0,
  'ssrf': 1.5, 'ssrf-cloud-metadata': 1.0,
  'xxe': 0.5,
  'open-redirect': 0.5,
  'path-traversal': 1.0,
  'crypto-weak-cipher': 2.0,                    // algorithm swap + key plumbing
  'crypto-weak-hash': 1.0,
  'crypto-tls-no-verify': 0.5,
  'crypto-tls-version': 1.0,
  'crypto-jwt-none': 0.5,
  'crypto-jwt-key-confusion': 0.5,
  'hardcoded-secret': 1.0,                       // env-var plumbing + rotation
  'vulnerable-dependency': 0.5,                  // npm install bump
  'dependency-confusion': 1.0,
  'iam-overpermissive': 1.5,
  'k8s-rbac-cluster-admin': 1.0,
  'k8s-pod-security-privileged': 1.0,
  'prompt-injection': 3.0,                       // architectural — prompt isolation
  'agent-tool-exec': 4.0,                        // narrow the tool surface
  'reentrancy': 4.0,                             // Solidity refactor + tests
  'pqc-migration': 8.0,                          // multi-quarter project
  'license-graph': 2.0,                          // dep swap or policy negotiation
};

function _loadFixHistory(scanRoot) {
  const fp = statePath(scanRoot, HISTORY_FILE);
  if (!fs.existsSync(fp)) return [];
  try {
    const arr = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}

function _historicalAvg(history, family) {
  const matches = history.filter(h => h.family === family && typeof h.elapsedHours === 'number');
  if (!matches.length) return null;
  const sum = matches.reduce((a, b) => a + b.elapsedHours, 0);
  return sum / matches.length;
}

function _patchShapeAdjust(finding) {
  // If we have the synthesized fix code, estimate complexity from size.
  const code = finding.fix?.code || finding.fix?.replacement || '';
  if (!code) return 1.0;
  const lines = code.split('\n').length;
  if (lines <= 3)  return 1.0;
  if (lines <= 10) return 1.4;
  if (lines <= 30) return 2.0;
  return 3.0;
}

function _reachAdjust(finding) {
  // Higher reachability → more careful testing → slightly higher cost.
  const tier = finding.reachabilityTier;
  if (tier === 'reachable-public' || tier === 'public-unauthed') return 1.3;
  if (tier === 'route-reachable')                                return 1.15;
  if (tier === 'unreachable')                                    return 0.7;
  return 1.0;
}

/**
 * Annotate findings with estimatedFixHours. Returns
 *   { perFinding: count, totalHours, perFamily: { fam: hours, ... } }
 */
export function annotateTimeToFix(scanRoot, findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return { perFinding: 0, totalHours: 0, perFamily: {} };
  }
  const history = _loadFixHistory(scanRoot);
  let total = 0;
  const perFamily = {};
  for (const f of findings) {
    const base = _historicalAvg(history, f.family) ?? FAMILY_BASE_HOURS[f.family] ?? 1.5;
    const patchAdj = _patchShapeAdjust(f);
    const reachAdj = _reachAdjust(f);
    const hours = Number((base * patchAdj * reachAdj).toFixed(2));
    f.estimatedFixHours = hours;
    f.estimatedFixHoursSource = _historicalAvg(history, f.family) != null ? 'history' : 'family-base';
    total += hours;
    perFamily[f.family || 'unknown'] = (perFamily[f.family || 'unknown'] || 0) + hours;
  }
  return {
    perFinding: findings.length,
    totalHours: Number(total.toFixed(1)),
    perFamily: Object.fromEntries(
      Object.entries(perFamily)
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => [k, Number(v.toFixed(1))]),
    ),
  };
}

/**
 * Render a one-paragraph PM summary.
 */
export function renderTimeSummary(roll) {
  if (!roll || roll.perFinding === 0) return 'No findings — 0 hours of security debt.';
  const top = Object.entries(roll.perFamily).slice(0, 3).map(([k, v]) => `${k} (${v}h)`).join(', ');
  return `${roll.perFinding} finding(s) — ~${roll.totalHours} engineering hours of security debt. Top families: ${top}.`;
}

export const _internals = { FAMILY_BASE_HOURS, _patchShapeAdjust, _reachAdjust, _historicalAvg };
